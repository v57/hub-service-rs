//! Device layer test vectors (`Docs/Devices/vectors.json`): every SDK must
//! reproduce these strings exactly.

use hub_service_rs::auth_token;
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
