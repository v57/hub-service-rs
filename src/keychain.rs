//! ed25519 keychain: load-or-generate the `auth` key file and sign tokens.
//!
//! Hub-pro auth parity with the TS reference (hub-service/keychain.ts):
//!
//! - The key file (`auth` in the working directory, matching the TS keychain;
//!   `$HUBKEY` overrides the path) is the base64 encoding of the 48-byte
//!   PKCS8 DER ed25519 private key followed by the 44-byte SPKI DER public
//!   key (92 bytes total, 124 base64 chars).
//! - A signed token has the shape `key.<pub>.<sig>.<expiry>` where:
//!     pub     = base64 of the 44-byte SPKI public key (bytes 48..92 of the
//!               file)
//!     sig     = base64 ed25519 signature over the expiry string
//!     expiry  = DECIMAL epoch-seconds string of now + 10 (TS parity;
//!               hub-pro reads it as base-36, so the decimal form never
//!               trips the expiry check)
//! - The hub verifies the signature against the embedded public key and
//!   treats the key as the connection identity (owner/host/group).
//!
//! Usage:
//!
//! ```no_run
//! use hub_service_rs::{Keychain, auth_header_block};
//!
//! let keychain = Keychain::new(); // loads or generates `auth` in the cwd
//! let token = keychain.sign_default()?; // fresh token for a connect
//! let headers = auth_header_block(&token); // raw "auth: ...\r\nv: 0\r\n"
//! # Ok::<(), hub_service_rs::KeychainError>(())
//! ```

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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
/// public key (bytes 48..92 of the auth file, TS parity).
#[derive(Clone)]
struct KeyData {
    seed: [u8; 32],
    public_der: Vec<u8>,
}

/// ed25519 keychain (TS `keychain.ts` parity): load-or-generate the `auth`
/// key file and sign `key.<pub>.<sig>.<expiry>` tokens.
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

    /// The service's public key: base64 of the 44-byte SPKI DER.
    pub fn public_key(&self) -> Result<String, KeychainError> {
        Ok(B64.encode(self.data()?.public_der))
    }

    /// A fresh auth token: `key.<pub>.<sig>.<expiry>` with
    /// `expiry = now_epoch_seconds + expires` (decimal string, TS parity).
    pub fn sign(&self, expires: u64) -> Result<String, KeychainError> {
        let data = self.data()?;
        let signing_key = SigningKey::from_bytes(&data.seed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| KeychainError::Key(format!("system clock before epoch: {error}")))?
            .as_secs();
        let expiry = (now + expires).to_string();
        let signature: Signature = signing_key.sign(expiry.as_bytes());
        Ok(format!(
            "key.{}.{}.{expiry}",
            B64.encode(&data.public_der),
            B64.encode(signature.to_bytes()),
        ))
    }

    /// `sign(10)` — the TS default expiry.
    pub fn sign_default(&self) -> Result<String, KeychainError> {
        self.sign(10)
    }

    fn data(&self) -> Result<KeyData, KeychainError> {
        let mut guard = self
            .cached
            .lock()
            .map_err(|_| KeychainError::Key("keychain lock poisoned".to_string()))?;
        if let Some(data) = guard.as_ref() {
            return Ok(data.clone());
        }
        let data = if self.path.exists() {
            load(&self.path)?
        } else {
            generate(&self.path)?
        };
        *guard = Some(data.clone());
        Ok(data)
    }
}

impl Default for Keychain {
    fn default() -> Self {
        Self::new()
    }
}

/// Loads an existing auth file: base64 of 48-byte PKCS8 DER + 44-byte SPKI
/// DER. The PKCS8 blob is validated with ed25519-dalek; the public key is
/// taken verbatim from bytes 48..92 (TS parity).
fn load(path: &Path) -> Result<KeyData, KeychainError> {
    let text = fs::read_to_string(path)
        .map_err(|error| KeychainError::Io(format!("read {}: {error}", path.display())))?;
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

/// Generates a fresh keypair and writes the auth file (92 bytes: 48-byte
/// PKCS8 DER + 44-byte SPKI DER, base64, no trailing newline).
fn generate(path: &Path) -> Result<KeyData, KeychainError> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let seed = signing_key.to_bytes();
    let public_raw = VerifyingKey::from(&signing_key).to_bytes();
    let mut bytes = Vec::with_capacity(PRIVATE_DER_LENGTH + PUBLIC_DER_LENGTH);
    bytes.extend_from_slice(&PKCS8_PREFIX);
    bytes.extend_from_slice(&seed);
    bytes.extend_from_slice(&SPKI_PREFIX);
    bytes.extend_from_slice(&public_raw);
    let text = B64.encode(&bytes);
    fs::write(path, text.as_bytes())
        .map_err(|error| KeychainError::Io(format!("write {}: {error}", path.display())))?;
    Ok(KeyData {
        seed,
        public_der: bytes[PRIVATE_DER_LENGTH..].to_vec(),
    })
}
