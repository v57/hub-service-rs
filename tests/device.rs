//! Device key file, certificate renewal and the instance default.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hub_service_rs::{
    Address, CERTIFICATE_LIFETIME, Certifier, DeviceKey, Keychain, Service, ServiceOptions,
    normalize_hub_address, platform,
};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hubdevice-rs-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn payload(header: &str) -> Value {
    let (payload, _) = header.split_once('.').expect("payload.signature");
    serde_json::from_slice(&B64URL.decode(payload).expect("base64url")).expect("json")
}

#[cfg(unix)]
#[test]
fn key_file_is_created_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("mode");
    let key = DeviceKey::with_path(dir.join("hub").join("device.key"));
    let first = key.public_key().unwrap();
    let file = fs::metadata(dir.join("hub/device.key"))
        .unwrap()
        .permissions()
        .mode();
    let parent = fs::metadata(dir.join("hub")).unwrap().permissions().mode();
    assert_eq!(file & 0o777, 0o600);
    assert_eq!(parent & 0o777, 0o700);
    // A fresh handle reads the same key.
    assert_eq!(
        DeviceKey::with_path(dir.join("hub/device.key"))
            .public_key()
            .unwrap(),
        first
    );
}

#[test]
fn certificate_renews_with_a_day_left() {
    let dir = temp_dir("renew");
    let key = Arc::new(DeviceKey::with_path(dir.join("device.key")));
    let mut certifier = Certifier::new(
        key.clone(),
        "s3-local/Backup Disk",
        Some("Mac Studio"),
        Some("Host"),
    );
    let now = 1_792_500_000;

    let first = certifier.header("SERVICE", now).unwrap();
    // 2 days left: kept.
    assert_eq!(
        certifier.header("SERVICE", now + 5 * 86_400).unwrap(),
        first
    );
    // 12 hours left: renewed, issued at the new time.
    let later = now + 6 * 86_400 + 43_200;
    let renewed = certifier.header("SERVICE", later).unwrap();
    assert_ne!(renewed, first);
    assert_eq!(payload(&renewed)["iat"], later);

    let fields = payload(&first);
    assert_eq!(fields["v"], 1);
    assert_eq!(fields["device"], key.public_key().unwrap());
    assert_eq!(fields["service"], "SERVICE");
    assert_eq!(fields["instance"], "s3-local/Backup Disk");
    assert_eq!(fields["deviceName"], "Mac Studio");
    assert_eq!(fields["platform"], platform());
    assert_eq!(fields["parent"], "Host");
    assert_eq!(fields["exp"], now + CERTIFICATE_LIFETIME);
}

#[test]
fn instance_is_cut_to_128_bytes_on_a_character_boundary() {
    let dir = temp_dir("cut");
    let key = Arc::new(DeviceKey::with_path(dir.join("device.key")));
    let long = "é".repeat(100); // 200 bytes
    let mut certifier = Certifier::new(key, &long, Some("n"), None);
    let instance = payload(&certifier.header("S", 1).unwrap())["instance"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(instance.len(), 128);
    assert!(
        payload(&certifier.header("S", 1).unwrap())
            .get("parent")
            .is_none()
    );
}

#[test]
fn instance_defaults() {
    let keychain = Arc::new(Keychain::with_path(temp_dir("instance").join("auth")));
    let options = || ServiceOptions {
        keychain: Some(keychain.clone()),
        disable_device: true,
        ..ServiceOptions::default()
    };
    // cargo runs tests in the package directory; $HUB_INSTANCE is unset here.
    if std::env::var("HUB_INSTANCE").is_err() {
        let mut service = Service::new(options());
        service.post("s3/read", Ok);
        assert_eq!(service.instance(), "hub-service-rs");

        let service = Service::new(ServiceOptions {
            name: Some("Backup Disk".into()),
            ..options()
        });
        assert_eq!(service.instance(), "Backup Disk");
    }

    let service = Service::new(ServiceOptions {
        name: Some("Backup Disk".into()),
        instance: Some("s3-local/Backup Disk".into()),
        ..options()
    });
    assert_eq!(service.instance(), "s3-local/Backup Disk");
}

#[test]
fn caller_provided_device_key_reads_no_file() {
    const KEY_FILE: &str = "MC4CAQAwBQYDK2VwBCIEIAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDMCowBQYDK2VwAyEA7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=";
    let key = Arc::new(DeviceKey::from_key_file(KEY_FILE).unwrap());
    assert_eq!(
        key.public_key().unwrap(),
        "MCowBQYDK2VwAyEA7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E="
    );
    let mut certifier = Certifier::new(key, "x", Some("n"), None);
    let header = certifier.header("S", 1).unwrap();
    assert_eq!(
        payload(&header)["device"],
        "MCowBQYDK2VwAyEA7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E="
    );
    assert!(DeviceKey::from_key_file("bm90LWEta2V5").is_err());
}

#[test]
fn pin_addresses_are_normalized() {
    assert_eq!(normalize_hub_address("1997"), "ws://localhost:1997");
    assert_eq!(
        normalize_hub_address("WSS://Hub.Example.COM/"),
        "wss://hub.example.com"
    );
    assert_eq!(
        normalize_hub_address("ws://Host:80/Path/"),
        "ws://host:80/Path"
    );
    assert_eq!(Address::Port(1997).pin_address(), "ws://localhost:1997");
    assert_eq!(
        Address::Url("ws://Example:2000/".into()).pin_address(),
        "ws://example:2000"
    );
}
