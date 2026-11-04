//! What the tests' fake hubs need to answer `hub/info`: the vectors' keys and
//! their proofs (`Docs/Devices/vectors.json`).
#![allow(dead_code)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use hub_service_rs::hub_info_signed_data;
use serde_json::{Value, json};

pub const HUB_KEY: &str = "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
pub const OTHER_KEY: &str = "MCowBQYDK2VwAyEAgTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";
/// The seeds behind those two keys.
pub const HUB_SEED: [u8; 32] = [1; 32];
pub const OTHER_SEED: [u8; 32] = [2; 32];

/// What `seed` signs for `hub/info`, claiming `key`.
pub fn proof(seed: &[u8; 32], key: &str, nonce: &str) -> String {
    let signature = SigningKey::from_bytes(seed).sign(hub_info_signed_data(key, nonce).as_bytes());
    B64.encode(signature.to_bytes())
}

/// The nonce in a `hub/info` request body.
pub fn nonce(body: &Value) -> &str {
    body.get("nonce").and_then(Value::as_str).unwrap_or_default()
}

/// A hub's whole answer: `seed` signs for `key`.
pub fn answer(seed: &[u8; 32], key: &str, body: &Value, challenge: &str) -> Value {
    json!({
        "key": key, "protocol": 2, "pro": true, "mode": "default-allow",
        "proof": proof(seed, key, nonce(body)), "challenge": challenge,
    })
}
