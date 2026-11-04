//! Auth v2's client side (`Docs/Devices/protocol.md` section 2): before every
//! connect the SDK asks `hub/info` on an anonymous connection with a fresh
//! nonce, and sends its token only if the hub proved the key it claims, over
//! that nonce.

use crate::Address;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use channel_rs::{CallResult, Channel, ConnectOptions};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use std::time::Duration;

/// How a connection to an address travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubTransport {
    Encrypted,
    Loopback,
    Overlay,
    LocalNetwork,
    /// Plain `ws://` beyond loopback, the overlay and the LAN: it isn't dialed
    /// unless `allow_plaintext` says so.
    Refused,
}

impl HubTransport {
    /// The protocol's name of this class (`localNetwork`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            HubTransport::Encrypted => "encrypted",
            HubTransport::Loopback => "loopback",
            HubTransport::Overlay => "overlay",
            HubTransport::LocalNetwork => "localNetwork",
            HubTransport::Refused => "refused",
        }
    }
}

fn ipv4(host: &str) -> Option<[u8; 4]> {
    let mut bytes = [0_u8; 4];
    let mut parts = host.split('.');
    for byte in &mut bytes {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        *byte = part.parse().ok()?;
    }
    parts.next().is_none().then_some(bytes)
}

/// Classifies an address before anything is dialed. A bare port is loopback,
/// and a `host:port` without a scheme reads as `ws://`.
pub fn hub_transport_of(address: &str) -> HubTransport {
    let address = address.trim();
    if !address.is_empty() && address.bytes().all(|byte| byte.is_ascii_digit()) {
        return HubTransport::Loopback;
    }
    let (scheme, rest) = address.split_once("://").unwrap_or(("ws", address));
    let scheme = scheme.to_ascii_lowercase();
    match scheme.as_str() {
        "wss" | "https" | "quic" => return HubTransport::Encrypted,
        "ws" | "http" => {}
        _ => return HubTransport::Refused,
    }
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let authority = authority.split_once('@').map_or(authority, |(_, host)| host);
    if let Some(bracketed) = authority.strip_prefix('[') {
        let v6 = bracketed.split(']').next().unwrap_or_default().to_ascii_lowercase();
        return match v6.as_str() {
            "::1" => HubTransport::Loopback,
            _ if ["fc", "fd", "fe8", "fe9", "fea", "feb"].iter().any(|prefix| v6.starts_with(prefix)) => {
                HubTransport::LocalNetwork
            }
            _ => HubTransport::Refused,
        };
    }
    let host = authority.split(':').next().unwrap_or_default().to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    if let Some([a, b, _, _]) = ipv4(host) {
        return match (a, b) {
            (127, _) => HubTransport::Loopback,
            (100, 64..=127) => HubTransport::Overlay,
            (10, _) | (172, 16..=31) | (192, 168) | (169, 254) => HubTransport::LocalNetwork,
            _ => HubTransport::Refused,
        };
    }
    if host == "localhost" || host.ends_with(".localhost") {
        HubTransport::Loopback
    } else if host.ends_with(".hub.invalid") {
        HubTransport::Overlay
    } else if host.ends_with(".local") {
        HubTransport::LocalNetwork
    } else {
        HubTransport::Refused
    }
}

/// The nonce for one `hub/info`: 32 fresh random bytes in base64url.
pub fn make_client_nonce() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The string a `hub/info` proof signs.
pub fn hub_info_signed_data(hub_key: &str, nonce: &str) -> String {
    format!("hubinfo1:{hub_key}:{nonce}")
}

/// An answer to `hub/info` with a nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubInfo {
    pub key: String,
    pub proof: String,
    pub challenge: String,
}

impl HubInfo {
    /// `key`, `proof` and `challenge` when all three are strings, and the
    /// challenge is what the protocol allows: it goes into a raw header line.
    pub fn from_value(value: &Value) -> Option<HubInfo> {
        let text = |name: &str| value.get(name)?.as_str().filter(|text| !text.is_empty()).map(str::to_string);
        let info = HubInfo { key: text("key")?, proof: text("proof")?, challenge: text("challenge")? };
        let valid = info.challenge.len() <= 128
            && info.challenge.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
        valid.then_some(info)
    }

    /// Whether the answer proves its key over `nonce`. A relayed answer passes
    /// too, so it never decides which credentials a hub gets.
    pub fn proves(&self, nonce: &str) -> bool {
        let Ok(spki) = B64.decode(&self.key) else { return false };
        let Ok(signature) = B64.decode(&self.proof) else { return false };
        let Some(raw) = spki.strip_prefix(&crate::keychain::SPKI_PREFIX[..]) else { return false };
        let Ok(raw) = <[u8; 32]>::try_from(raw) else { return false };
        let Ok(signature) = <[u8; 64]>::try_from(signature.as_slice()) else { return false };
        let Ok(key) = VerifyingKey::from_bytes(&raw) else { return false };
        key.verify(hub_info_signed_data(&self.key, nonce).as_bytes(), &Signature::from_bytes(&signature)).is_ok()
    }
}

/// Asks the hub at `address` for its key and a challenge on a short anonymous
/// connection, with a channel of its own so it serves none of the service's
/// handlers, and returns the answer only with a valid proof.
pub(crate) fn ask_hub(address: &Address, timeout: Duration) -> Result<HubInfo, String> {
    let channel = Channel::<()>::new();
    let options = ConnectOptions {
        handshake_timeout: timeout,
        timeout: Some(timeout),
        ..ConnectOptions::default()
    };
    let connected = match address {
        Address::Port(port) => channel.connect(*port, options),
        Address::Url(url) => channel.connect(url.clone(), options),
    };
    let mut client = connected.map_err(|error| error.to_string())?;
    let nonce = make_client_nonce();
    let answer = client
        .sender()
        .send::<Value, Value>("hub/info", json!({ "nonce": nonce }))
        .map_err(|error| error.to_string())?;
    client.stop();
    let CallResult::Ok(Some(value)) = answer else {
        return Err("hub didn't prove its key".to_string());
    };
    HubInfo::from_value(&value)
        .filter(|info| info.proves(&nonce))
        .ok_or_else(|| "hub didn't prove its key".to_string())
}
