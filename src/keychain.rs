//! ed25519 keychain: load-or-generate the `auth` key file, sign tokens and
//! pin hub keys.
//!
//! Hub-pro auth parity with the TS reference (hub-service/keychain.ts) and
//! `Docs/Devices/protocol.md` section 2:
//!
//! - The key file (`auth` in the working directory, matching the TS keychain;
//!   `$HUBKEY` overrides the path) is the base64 encoding of the 48-byte
//!   PKCS8 DER ed25519 private key followed by the 44-byte SPKI DER public
//!   key (92 bytes total, 124 base64 chars).
//! - A signed token has the shape `key.<pub>.<sig>.<expiry>` where:
//!     pub     = base64 of the 44-byte SPKI public key (bytes 48..92 of the
//!               file)
//!     sig     = base64 ed25519 signature over
//!                 v0: `<expiry>`
//!                 v1: `hub1:<hub SPKI>:<expiry>` (only valid on that hub)
//!     expiry  = DECIMAL epoch-seconds string of now + 60; hub-pro rejects
//!               it once 30 s past or more than 330 s ahead
//! - The hub verifies the signature against the embedded public key and
//!   treats the key as the connection identity (owner/host/group).
//! - Hub key pins live in `hubs.json` beside the key file:
//!   `{"<address>": "<hub SPKI>"}`.
//!
//! Usage:
//!
//! ```no_run
//! use hub_service_rs::{Keychain, auth_header_block};
//!
//! let keychain = Keychain::new(); // loads or generates `auth` in the cwd
//! let token = keychain.sign_default()?; // fresh v0 token for a connect
//! let headers = auth_header_block(&token); // raw "auth: ...\r\nv: 0\r\n"
//! # Ok::<(), hub_service_rs::KeychainError>(())
//! ```

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::{Map, Value};
use std::env;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds a fresh token stays valid (protocol.md: SDK default now + 60).
pub const AUTH_EXPIRY: u64 = 60;

/// TS keychain layout: PKCS8 DER private key (48 bytes for ed25519) followed
/// by the SPKI DER public key (44 bytes for ed25519).
const PRIVATE_DER_LENGTH: usize = 48;
const PUBLIC_DER_LENGTH: usize = 44;

/// Fixed DER prefixes for ed25519 keys (RFC 8410):
/// PKCS8: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 },
///                    OCTET STRING { OCTET STRING { 32-byte seed } } }
/// SPKI:  SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { pub } }
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Keychain failures: I/O, malformed auth files, crypto errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainError {
    /// Reading or writing the auth file failed.
    Io(String),
    /// The auth file is not a valid keychain blob.
    BadAuthFile(String),
    /// ed25519 key parsing or signing failed.
    Key(String),
}

impl fmt::Display for KeychainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeychainError::Io(error) => write!(f, "keychain io error: {error}"),
            KeychainError::BadAuthFile(error) => write!(f, "bad auth file: {error}"),
            KeychainError::Key(error) => write!(f, "keychain crypto error: {error}"),
        }
    }
}

impl std::error::Error for KeychainError {}

/// The loaded key material: the raw 32-byte seed and the 44-byte SPKI DER
/// public key (bytes 48..92 of the key file, TS parity).
#[derive(Clone)]
pub(crate) struct KeyData {
    pub(crate) seed: [u8; 32],
    pub(crate) public_der: Vec<u8>,
}

impl KeyData {
    /// base64 of the SPKI DER.
    pub(crate) fn public_key(&self) -> String {
        B64.encode(&self.public_der)
    }

    /// base64 ed25519 signature over `data`.
    pub(crate) fn sign(&self, data: &str) -> String {
        let signature: Signature = SigningKey::from_bytes(&self.seed).sign(data.as_bytes());
        B64.encode(signature.to_bytes())
    }

    fn token(&self, hub_key: Option<&str>, expiry: u64) -> String {
        let data = match hub_key {
            Some(hub_key) => format!("hub1:{hub_key}:{expiry}"),
            None => expiry.to_string(),
        };
        format!("key.{}.{}.{expiry}", self.public_key(), self.sign(&data))
    }
}

/// An auth token for an explicit key file text and expiry (for tests and
/// tools): `hub_key` `None` signs v0, otherwise v1.
pub fn auth_token(
    key_file: &str,
    hub_key: Option<&str>,
    expiry: u64,
) -> Result<String, KeychainError> {
    Ok(parse(key_file, Path::new("<text>"))?.token(hub_key, expiry))
}

pub(crate) fn now_seconds() -> Result<u64, KeychainError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| KeychainError::Key(format!("system clock before epoch: {error}")))?
        .as_secs())
}

/// ed25519 keychain (TS `keychain.ts` parity): load-or-generate the `auth`
/// key file, sign `key.<pub>.<sig>.<expiry>` tokens and keep hub key pins.
///
/// The key material is loaded lazily on first use and cached; safe to share
/// across threads (the service re-signs on every reconnect).
pub struct Keychain {
    path: PathBuf,
    cached: Mutex<Option<KeyData>>,
}

impl Keychain {
    /// The default keychain: `auth` in the current working directory
    /// (or `$HUBKEY` when set, TS parity).
    pub fn new() -> Self {
        let path = env::var("HUBKEY").unwrap_or_else(|_| "auth".to_string());
        Self::with_path(path)
    }

    /// A keychain reading (or writing on first use) `path`.
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cached: Mutex::new(None),
        }
    }

    /// The key file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The service's public key: base64 of the 44-byte SPKI DER.
    pub fn public_key(&self) -> Result<String, KeychainError> {
        Ok(self.data()?.public_key())
    }

    /// A fresh v0 auth token: `key.<pub>.<sig>.<expiry>` with
    /// `expiry = now_epoch_seconds + expires` (decimal string, TS parity).
    pub fn sign(&self, expires: u64) -> Result<String, KeychainError> {
        self.sign_for_hub(None, expires)
    }

    /// A fresh token bound to `hub_key` (v1: the signature covers
    /// `hub1:<hub key>:<expiry>`); `None` signs v0.
    pub fn sign_for_hub(
        &self,
        hub_key: Option<&str>,
        expires: u64,
    ) -> Result<String, KeychainError> {
        let data = self.data()?;
        Ok(data.token(hub_key, now_seconds()? + expires))
    }

    /// `sign(AUTH_EXPIRY)`.
    pub fn sign_default(&self) -> Result<String, KeychainError> {
        self.sign(AUTH_EXPIRY)
    }

    /// The hub key pinned for `address`, if any.
    pub fn hub_key(&self, address: &str) -> Option<String> {
        self.read_pins().get(address)?.as_str().map(str::to_string)
    }

    /// Pins `hub_key` for `address` (replaces an earlier pin).
    pub fn pin_hub_key(&self, address: &str, hub_key: &str) -> Result<(), KeychainError> {
        let mut pins = self.read_pins();
        pins.insert(address.to_string(), Value::String(hub_key.to_string()));
        self.write_pins(&pins)
    }

    /// Removes the pin for `address`: connects use v0 again until hub/info
    /// pins the key again. Use it when the hub's key changed on purpose.
    pub fn forget_hub_key(&self, address: &str) -> Result<(), KeychainError> {
        let mut pins = self.read_pins();
        if pins.remove(address).is_none() {
            return Ok(());
        }
        self.write_pins(&pins)
    }

    fn pins_path(&self) -> PathBuf {
        match self.path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join("hubs.json"),
            _ => PathBuf::from("hubs.json"),
        }
    }

    /// The pins (empty when the file is missing or corrupt).
    fn read_pins(&self) -> Map<String, Value> {
        fs::read_to_string(self.pins_path())
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|value| match value {
                Value::Object(map) => Some(map),
                _ => None,
            })
            .unwrap_or_default()
    }

    fn write_pins(&self, pins: &Map<String, Value>) -> Result<(), KeychainError> {
        let text =
            serde_json::to_string(pins).map_err(|error| KeychainError::Io(error.to_string()))?;
        write_atomic(&self.pins_path(), text.as_bytes())
    }

    pub(crate) fn data(&self) -> Result<KeyData, KeychainError> {
        let mut guard = self
            .cached
            .lock()
            .map_err(|_| KeychainError::Key("keychain lock poisoned".to_string()))?;
        if let Some(data) = guard.as_ref() {
            return Ok(data.clone());
        }
        let data = load_or_generate(&self.path, false)?;
        *guard = Some(data.clone());
        Ok(data)
    }
}

impl Default for Keychain {
    fn default() -> Self {
        Self::new()
    }
}

/// Loads the key file at `path`, generating it when missing (parent
/// directories are created 0700 when `private_dirs` is set).
pub(crate) fn load_or_generate(path: &Path, private_dirs: bool) -> Result<KeyData, KeychainError> {
    if path.exists() {
        load(path)
    } else {
        generate(path, private_dirs)
    }
}

/// Loads an existing key file: base64 of 48-byte PKCS8 DER + 44-byte SPKI
/// DER. The PKCS8 blob is validated with ed25519-dalek; the public key is
/// taken verbatim from bytes 48..92 (TS parity).
fn load(path: &Path) -> Result<KeyData, KeychainError> {
    let text = fs::read_to_string(path)
        .map_err(|error| KeychainError::Io(format!("read {}: {error}", path.display())))?;
    parse(&text, path)
}

pub(crate) fn parse(text: &str, path: &Path) -> Result<KeyData, KeychainError> {
    let bytes = B64.decode(text.trim()).map_err(|error| {
        KeychainError::BadAuthFile(format!("base64 decode {}: {error}", path.display()))
    })?;
    let expected = PRIVATE_DER_LENGTH + PUBLIC_DER_LENGTH;
    if bytes.len() != expected {
        return Err(KeychainError::BadAuthFile(format!(
            "bad auth file {}: expected {expected} bytes, got {}",
            path.display(),
            bytes.len()
        )));
    }
    let signing_key =
        SigningKey::from_pkcs8_der(&bytes[..PRIVATE_DER_LENGTH]).map_err(|error| {
            KeychainError::Key(format!(
                "invalid PKCS8 private key in {}: {error}",
                path.display()
            ))
        })?;
    Ok(KeyData {
        seed: signing_key.to_bytes(),
        public_der: bytes[PRIVATE_DER_LENGTH..].to_vec(),
    })
}

/// Generates a fresh keypair and writes the key file atomically with mode
/// 0600 (92 bytes: 48-byte PKCS8 DER + 44-byte SPKI DER, base64, no
/// trailing newline).
fn generate(path: &Path, private_dirs: bool) -> Result<KeyData, KeychainError> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let seed = signing_key.to_bytes();
    let public_raw = VerifyingKey::from(&signing_key).to_bytes();
    let mut bytes = Vec::with_capacity(PRIVATE_DER_LENGTH + PUBLIC_DER_LENGTH);
    bytes.extend_from_slice(&PKCS8_PREFIX);
    bytes.extend_from_slice(&seed);
    bytes.extend_from_slice(&SPKI_PREFIX);
    bytes.extend_from_slice(&public_raw);
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        create_dirs(dir, private_dirs)?;
    }
    write_atomic(path, B64.encode(&bytes).as_bytes())?;
    Ok(KeyData {
        seed,
        public_der: bytes[PRIVATE_DER_LENGTH..].to_vec(),
    })
}

fn create_dirs(dir: &Path, private: bool) -> Result<(), KeychainError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(if private { 0o700 } else { 0o755 });
    }
    #[cfg(not(unix))]
    let _ = private;
    builder
        .create(dir)
        .map_err(|error| KeychainError::Io(format!("create {}: {error}", dir.display())))
}

/// Writes `data` to a temp file beside `path` (mode 0600) and renames it.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<(), KeychainError> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let io =
        |error: std::io::Error| KeychainError::Io(format!("write {}: {error}", path.display()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = options
        .open(&tmp)
        .and_then(|mut file| file.write_all(data))
        .and_then(|_| fs::rename(&tmp, path));
    if let Err(error) = result {
        let _ = fs::remove_file(&tmp);
        return Err(io(error));
    }
    Ok(())
}
