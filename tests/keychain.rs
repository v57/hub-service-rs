//! Keychain unit tests (hub-pro-support contract): token shape, signature
//! verification, auth file round-trip, TS-generated auth file parity and
//! the raw connect header block.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hub_service_rs::{
    Keychain, KeychainError, auth_header_block, auth_token, connect_header_block,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// TS-generated test key (owner key from the hub-pro test env) and its public
// key (hub-service/keychain.ts parity).
const TS_TEST_AUTH: &str = "MC4CAQAwBQYDK2VwBCIEINguo0cc0FACJ0oRV3V/+ZqIyj04ON5wdMJGH4a/do8CMCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ=";
const TS_TEST_PUB: &str = "MCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ=";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique temp dir per test (tests run in parallel).
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hubkey-rs-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// The raw 32-byte ed25519 public key is the trailing 32 bytes of the
/// 44-byte SPKI DER (12-byte SPKI prefix, RFC 8410).
fn raw_public_key(pub_b64: &str) -> [u8; 32] {
    let spki = B64.decode(pub_b64).expect("pub is base64");
    assert_eq!(spki.len(), 44, "pub is the 44-byte SPKI DER");
    let mut raw = [0_u8; 32];
    raw.copy_from_slice(&spki[12..44]);
    raw
}

#[test]
fn generates_auth_file_and_round_trips() {
    let dir = temp_dir("roundtrip");
    let path = dir.join("auth");
    let keychain = Keychain::with_path(&path);
    let pub1 = keychain.public_key().expect("public key");

    assert!(path.exists(), "auth file should be generated on first use");
    // 92 bytes (48 PKCS8 + 44 SPKI) -> 124 base64 chars.
    let text = fs::read_to_string(&path).expect("read auth file");
    assert_eq!(text.trim().len(), 124, "auth file is 124 base64 chars");
    assert_eq!(B64.decode(text.trim()).expect("base64").len(), 92);

    // Reload from disk (fresh instance): same public key (file round-trip).
    let reloaded = Keychain::with_path(&path);
    assert_eq!(reloaded.public_key().expect("public key"), pub1);
    let token = reloaded.sign_default().expect("sign");
    assert_eq!(token.split('.').nth(1).unwrap(), pub1);
}

#[test]
fn token_shape_is_key_pub_sig_decimal() {
    let dir = temp_dir("shape");
    let keychain = Keychain::with_path(dir.join("auth"));
    let token = keychain.sign_default().expect("sign");

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        parts.len(),
        4,
        "token should be key.<pub>.<sig>.<expiry>: {token}"
    );
    assert_eq!(parts[0], "key");
    assert!(
        parts[1]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
        "pub must be base64"
    );
    assert_eq!(parts[1].len(), 60, "pub is base64 of the 44-byte SPKI DER");
    assert!(
        parts[2]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
        "sig must be base64"
    );
    assert_eq!(
        parts[2].len(),
        88,
        "sig is base64 of the 64-byte ed25519 signature"
    );
    assert!(
        parts[3].chars().all(|c| c.is_ascii_digit()),
        "expiry must be a decimal string"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry: u64 = parts[3].parse().expect("expiry parses");
    assert!(
        (now + 58..=now + 62).contains(&expiry),
        "expiry is now + 60"
    );
}

#[test]
fn signature_verifies_against_embedded_public_key() {
    let dir = temp_dir("verify");
    let keychain = Keychain::with_path(dir.join("auth"));
    let token = keychain.sign_default().expect("sign");

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(keychain.public_key().expect("public key"), parts[1]);

    let verify_key = VerifyingKey::from_bytes(&raw_public_key(parts[1])).expect("verify key");
    let signature = Signature::from_bytes(
        &B64.decode(parts[2]).expect("sig base64")[..]
            .try_into()
            .expect("64 bytes"),
    );
    // Signature is over the expiry STRING (not the token).
    assert!(
        verify_key.verify(parts[3].as_bytes(), &signature).is_ok(),
        "signature must verify over the expiry string with the token pub"
    );
    assert!(
        verify_key
            .verify(format!("{}x", parts[3]).as_bytes(), &signature)
            .is_err(),
        "signature must not verify over a different message"
    );
}

#[test]
fn ts_generated_auth_file_reproduces_public_key() {
    let dir = temp_dir("tskey");
    let path = dir.join("auth");
    fs::write(&path, TS_TEST_AUTH).expect("write TS auth file");

    let keychain = Keychain::with_path(&path);
    assert_eq!(
        keychain.public_key().expect("public key"),
        TS_TEST_PUB,
        "must reproduce the TS keychain public key from its auth file"
    );

    let token = keychain.sign_default().expect("sign");
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts[1], TS_TEST_PUB);
    let verify_key = VerifyingKey::from_bytes(&raw_public_key(parts[1])).expect("verify key");
    let signature = Signature::from_bytes(
        &B64.decode(parts[2]).expect("sig base64")[..]
            .try_into()
            .expect("64 bytes"),
    );
    assert!(
        verify_key.verify(parts[3].as_bytes(), &signature).is_ok(),
        "token signed with the TS key must verify against the TS public key"
    );
}

#[test]
fn sign_accepts_custom_expiry() {
    let dir = temp_dir("expiry");
    let keychain = Keychain::with_path(dir.join("auth"));
    let token = keychain.sign(120).expect("sign(120)");
    let expiry: u64 = token
        .split('.')
        .nth(3)
        .unwrap()
        .parse()
        .expect("expiry parses");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((now + 118..=now + 122).contains(&expiry));
}

#[test]
fn bad_auth_file_errors() {
    let dir = temp_dir("bad");
    let path = dir.join("auth");
    fs::write(&path, "bm90LWEta2V5").expect("write junk"); // "not-a-key"
    let keychain = Keychain::with_path(&path);
    assert!(matches!(
        keychain.public_key(),
        Err(KeychainError::BadAuthFile(_))
    ));
    assert!(matches!(
        keychain.sign_default(),
        Err(KeychainError::BadAuthFile(_))
    ));
}

#[test]
fn auth_header_block_is_raw_auth_and_v() {
    assert_eq!(
        auth_header_block("key.a.b.123"),
        "auth: key.a.b.123\r\nv: 0\r\n"
    );
    // channel-rs appends a final CRLF itself, so the block yields exactly
    // the two header lines followed by the blank line.
    assert!(auth_header_block("key.a.b.123").ends_with("v: 0\r\n"));
}

#[test]
fn hub_key_pins_live_beside_the_key_file() {
    let dir = temp_dir("pins");
    let keychain = Keychain::with_path(dir.join("auth"));
    assert_eq!(keychain.hub_key("ws://127.0.0.1:1997"), None);

    keychain
        .pin_hub_key("ws://127.0.0.1:1997", "HUBKEY1")
        .expect("pin");
    keychain
        .pin_hub_key("ws://example:1997", "HUBKEY2")
        .expect("pin");
    assert_eq!(
        keychain.hub_key("ws://127.0.0.1:1997").as_deref(),
        Some("HUBKEY1")
    );
    assert!(dir.join("hubs.json").exists());

    // A fresh keychain on the same file sees the pins.
    let reloaded = Keychain::with_path(dir.join("auth"));
    keychain
        .forget_hub_key("ws://127.0.0.1:1997")
        .expect("forget");
    assert_eq!(reloaded.hub_key("ws://127.0.0.1:1997"), None);
    assert_eq!(
        reloaded.hub_key("ws://example:1997").as_deref(),
        Some("HUBKEY2")
    );
}

#[test]
fn sign_for_hub_binds_the_hub_key() {
    let dir = temp_dir("v1");
    let path = dir.join("auth");
    fs::write(&path, TS_TEST_AUTH).expect("write TS auth file");
    let keychain = Keychain::with_path(&path);

    let token = keychain.sign_for_hub(Some("HUBKEY"), 60).expect("sign");
    let expiry: u64 = token.rsplit('.').next().unwrap().parse().unwrap();
    assert_eq!(
        token,
        auth_token(TS_TEST_AUTH, Some("HUBKEY"), expiry).unwrap()
    );
    assert_ne!(token, auth_token(TS_TEST_AUTH, None, expiry).unwrap());

    let parts: Vec<&str> = token.split('.').collect();
    let verify_key = VerifyingKey::from_bytes(&raw_public_key(parts[1])).expect("verify key");
    let signature = Signature::from_bytes(&B64.decode(parts[2]).unwrap()[..].try_into().unwrap());
    assert!(
        verify_key
            .verify(format!("hub1:HUBKEY:{expiry}").as_bytes(), &signature)
            .is_ok()
    );
}

#[test]
fn connect_header_block_adds_version_and_device() {
    assert_eq!(connect_header_block("t", 1, None), "auth: t\r\nv: 1\r\n");
    assert_eq!(
        connect_header_block("t", 1, Some("p.s")),
        "auth: t\r\nv: 1\r\ndevice: p.s\r\n"
    );
}

#[cfg(unix)]
#[test]
fn generated_key_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("mode");
    let keychain = Keychain::with_path(dir.join("auth"));
    keychain.public_key().expect("public key");
    let mode = fs::metadata(dir.join("auth")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}
