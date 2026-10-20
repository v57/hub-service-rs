//! Device layer test vectors (`Docs/Devices/vectors.json`): every SDK must
//! reproduce these strings exactly.

use hub_service_rs::{Certificate, auth_token, device_id, encode_certificate, safety_code};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../Docs/Devices/vectors.json"
    );
    let text = std::fs::read_to_string(path).expect("read Docs/Devices/vectors.json");
    serde_json::from_str(&text).expect("vectors.json parses")
}

fn text<'a>(vectors: &'a Value, pointer: &str) -> &'a str {
    vectors
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing vector {pointer}"))
}

#[test]
fn auth_v0() {
    let v = vectors();
    let expiry = v.pointer("/auth/expiry").and_then(Value::as_u64).unwrap();
    let token = auth_token(text(&v, "/keys/service/keyFile"), None, expiry).unwrap();
    assert_eq!(token, text(&v, "/auth/v0/header"));
}

#[test]
fn auth_v1() {
    let v = vectors();
    let expiry = v.pointer("/auth/expiry").and_then(Value::as_u64).unwrap();
    let token = auth_token(
        text(&v, "/keys/service/keyFile"),
        Some(text(&v, "/keys/hub/publicKey")),
        expiry,
    )
    .unwrap();
    assert_eq!(token, text(&v, "/auth/v1/header"));
}

fn check_certificate(
    name: &str,
    instance: &str,
    device_name: &str,
    platform: &str,
    parent: Option<&str>,
) {
    let v = vectors();
    let certificate = Certificate {
        v: 1,
        device: text(&v, "/keys/device/publicKey").to_string(),
        service: text(&v, "/keys/service/publicKey").to_string(),
        instance: instance.to_string(),
        device_name: Some(device_name.to_string()),
        platform: Some(platform.to_string()),
        parent: parent.map(str::to_string),
        hub: None,
        iat: 1792500000,
        exp: 1793104800,
    };
    assert_eq!(certificate.json(), text(&v, &format!("/{name}/json")));
    let header = encode_certificate(text(&v, "/keys/device/keyFile"), &certificate).unwrap();
    assert_eq!(header, text(&v, &format!("/{name}/header")));
}

#[test]
fn certificate() {
    check_certificate(
        "certificate",
        "s3-local/Backup Disk",
        "Mac Studio",
        "macos",
        None,
    );
}

#[test]
fn child_certificate() {
    check_certificate(
        "childCertificate",
        "builder",
        "builder",
        "linux",
        Some("Mac Studio"),
    );
}

#[test]
fn device_id_and_safety_code() {
    let v = vectors();
    let key = text(&v, "/keys/device/publicKey");
    assert_eq!(
        device_id(key).as_deref(),
        Some(text(&v, "/keys/device/deviceId"))
    );
    assert_eq!(
        safety_code(key).as_deref(),
        Some(text(&v, "/keys/device/safetyCode"))
    );
}
