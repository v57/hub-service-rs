//! Device key and service certificates (`Docs/Devices/protocol.md`
//! sections 1 and 3).
//!
//! - The device key is one ed25519 key per OS instance, in the same file
//!   format as the `auth` key. It lives in `~/.hub/device.key` (directory
//!   0700, file 0600), `/var/lib/hub/device.key` for root, or
//!   `$HUB_DEVICE_KEY`, and is created atomically on first use.
//! - The device signs a certificate for each service key it runs, sent in
//!   the `device` handshake header as `<payload>.<signature>`: payload is the
//!   base64url (no padding) of the certificate JSON, and the signature is the
//!   device key's base64 ed25519 signature over the payload characters.
//! - The service renews its certificate at connect when less than a day of
//!   its 7 days is left.

use crate::keychain::{self, KeyData, KeychainError};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Default certificate lifetime: 7 days.
pub const CERTIFICATE_LIFETIME: u64 = 604_800;
/// A certificate with less than this left is renewed at connect: 1 day.
pub const CERTIFICATE_RENEW: u64 = 86_400;

/// The certificate fields, serialized in this order (protocol.md section 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Certificate {
    /// Always 1.
    pub v: u8,
    /// Device SPKI.
    pub device: String,
    /// Service SPKI, the key in `auth`.
    pub service: String,
    /// 1-128 bytes, unique per device by convention.
    pub instance: String,
    /// Suggested device name, at most 64 bytes.
    #[serde(rename = "deviceName", skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// `macos`, `ios`, `linux`, `windows`, `android`, `other`...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Declared parent device name for containers and VMs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Reserved: hub SPKI for per-hub device keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub: Option<String>,
    pub iat: u64,
    pub exp: u64,
}

impl Certificate {
    /// The certificate JSON with no whitespace.
    pub fn json(&self) -> String {
        serde_json::to_string(self).expect("certificate serializes")
    }
}

fn encode(key: &KeyData, certificate: &Certificate) -> String {
    let payload = B64URL.encode(certificate.json());
    let signature = key.sign(&payload);
    format!("{payload}.{signature}")
}

/// The `device` header value for `certificate`, signed with the key file
/// text `device_key_file` (for tests and tools).
pub fn encode_certificate(
    device_key_file: &str,
    certificate: &Certificate,
) -> Result<String, KeychainError> {
    Ok(encode(
        &keychain::parse(device_key_file, Path::new("<text>"))?,
        certificate,
    ))
}

fn spki_digest(spki: &str) -> Option<String> {
    let der = B64.decode(spki).ok()?;
    Some(
        Sha256::digest(der)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

/// Device id: the first 32 lowercase hex characters of SHA-256(SPKI DER).
pub fn device_id(spki: &str) -> Option<String> {
    Some(spki_digest(spki)?[..32].to_string())
}

/// The safety code shown when approving a device: `"ddd ddd"`.
pub fn safety_code(spki: &str) -> Option<String> {
    let n = u64::from_str_radix(&spki_digest(spki)?[..8], 16).ok()? % 1_000_000;
    Some(format!("{:03} {:03}", n / 1000, n % 1000))
}

/// This OS as a certificate platform.
pub fn platform() -> &'static str {
    match env::consts::OS {
        "macos" => "macos",
        "ios" => "ios",
        "linux" => "linux",
        "windows" => "windows",
        "android" => "android",
        "tvos" => "tvos",
        "watchos" => "watchos",
        "visionos" => "visionos",
        _ => "other",
    }
}

/// The host name without a trailing `.local` (the default device name).
pub fn host_name() -> Option<String> {
    #[cfg(unix)]
    {
        let mut buffer = [0_u8; 256];
        // SAFETY: the buffer is valid for its length; gethostname writes a
        // NUL-terminated name (truncated to the buffer).
        let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
        if result != 0 {
            return None;
        }
        let end = buffer
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(buffer.len());
        let name = String::from_utf8_lossy(&buffer[..end]).into_owned();
        let name = name.strip_suffix(".local").unwrap_or(&name).to_string();
        (!name.is_empty()).then_some(name)
    }
    #[cfg(not(unix))]
    {
        env::var("COMPUTERNAME")
            .ok()
            .filter(|name| !name.is_empty())
    }
}

/// Cuts `text` to at most `max` bytes without splitting a character.
fn truncate(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// The device key file (created on first use, cached once loaded).
pub struct DeviceKey {
    path: PathBuf,
    cached: Mutex<Option<KeyData>>,
}

impl DeviceKey {
    /// The default device key: `$HUB_DEVICE_KEY`, `/var/lib/hub/device.key`
    /// for root, else `~/.hub/device.key`.
    pub fn new() -> Option<Self> {
        Some(Self::with_path(Self::default_path()?))
    }

    /// A device key reading (or creating on first use) `path`.
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cached: Mutex::new(None),
        }
    }

    /// `$HUB_DEVICE_KEY`, `/var/lib/hub/device.key` for root, else
    /// `~/.hub/device.key`.
    pub fn default_path() -> Option<PathBuf> {
        if let Ok(path) = env::var("HUB_DEVICE_KEY") {
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
        #[cfg(unix)]
        // SAFETY: getuid has no preconditions.
        if unsafe { libc::getuid() } == 0 {
            return Some(PathBuf::from("/var/lib/hub/device.key"));
        }
        let home = env::var("HOME").ok().filter(|home| !home.is_empty())?;
        Some(Path::new(&home).join(".hub").join("device.key"))
    }

    /// The key file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The device public key (SPKI base64), creating the key file when missing.
    pub fn public_key(&self) -> Result<String, KeychainError> {
        Ok(self.data()?.public_key())
    }

    /// The `device` header value for `certificate`.
    pub fn sign(&self, certificate: &Certificate) -> Result<String, KeychainError> {
        Ok(encode(&self.data()?, certificate))
    }

    fn data(&self) -> Result<KeyData, KeychainError> {
        let mut guard = self
            .cached
            .lock()
            .map_err(|_| KeychainError::Key("device key lock poisoned".to_string()))?;
        if let Some(data) = guard.as_ref() {
            return Ok(data.clone());
        }
        let data = keychain::load_or_generate(&self.path, true)?;
        *guard = Some(data.clone());
        Ok(data)
    }
}

/// Issues and renews the certificate a service sends at connect.
pub struct Certifier {
    device_key: Arc<DeviceKey>,
    instance: String,
    device_name: Option<String>,
    parent: Option<String>,
    current: Option<(String, u64)>,
}

impl Certifier {
    /// `device_name` `None` uses the host name. `instance` is cut to 128
    /// bytes, the names to 64.
    pub fn new(
        device_key: Arc<DeviceKey>,
        instance: &str,
        device_name: Option<&str>,
        parent: Option<&str>,
    ) -> Self {
        Self {
            device_key,
            instance: truncate(instance, 128),
            device_name: device_name
                .map(str::to_string)
                .or_else(host_name)
                .map(|name| truncate(&name, 64)),
            parent: parent
                .filter(|parent| !parent.is_empty())
                .map(|parent| truncate(parent, 64)),
            current: None,
        }
    }

    /// The `device` header for a connect at `now`: the current certificate,
    /// or a new one when there is none or less than [`CERTIFICATE_RENEW`] is
    /// left.
    pub fn header(&mut self, service_key: &str, now: u64) -> Result<String, KeychainError> {
        if let Some((header, exp)) = &self.current {
            if exp.saturating_sub(now) >= CERTIFICATE_RENEW {
                return Ok(header.clone());
            }
        }
        let certificate = Certificate {
            v: 1,
            device: self.device_key.public_key()?,
            service: service_key.to_string(),
            instance: self.instance.clone(),
            device_name: self.device_name.clone(),
            platform: Some(platform().to_string()),
            parent: self.parent.clone(),
            hub: None,
            iat: now,
            exp: now + CERTIFICATE_LIFETIME,
        };
        let header = self.device_key.sign(&certificate)?;
        self.current = Some((header.clone(), certificate.exp));
        Ok(header)
    }
}
