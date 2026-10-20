//! Hub Network share publishing against a fake hub-net agent (HTTP on a Unix
//! socket, in a thread) and an in-process fake hub (a channel-rs server).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use channel_rs::{Channel, ListenOptions, PostRequest, Server};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hub_service_rs::{
    Address, DeviceKey, Keychain, NetworkPolicy, NetworkShare, Protocol, Service, ServiceError,
    ServiceOptions, parse_iso_ms,
};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    // Short: Unix socket paths are limited to ~104 bytes.
    let dir = PathBuf::from("/tmp").join(format!(
        "hsrs-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

// --- fake agent -------------------------------------------------------------

#[derive(Default)]
struct AgentControl {
    attest_status: AtomicU16,
    ttl: AtomicI64,
    chunked: AtomicBool,
    bad_signatures: AtomicUsize,
    stop: AtomicBool,
}

fn iso(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.123456789Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn verify(spki: &str, data: &str, signature: &str) -> bool {
    let Ok(spki) = B64.decode(spki) else {
        return false;
    };
    let Ok(signature) = B64.decode(signature) else {
        return false;
    };
    let (Ok(raw), Ok(signature)) = (
        <[u8; 32]>::try_from(&spki[12..]),
        <[u8; 64]>::try_from(&signature[..]),
    ) else {
        return false;
    };
    VerifyingKey::from_bytes(&raw)
        .map(|key| {
            key.verify(data.as_bytes(), &Signature::from_bytes(&signature))
                .is_ok()
        })
        .unwrap_or(false)
}

fn start_agent(path: PathBuf) -> Arc<AgentControl> {
    let control = Arc::new(AgentControl::default());
    control.attest_status.store(200, Ordering::Relaxed);
    control.ttl.store(300, Ordering::Relaxed);
    let listener = UnixListener::bind(&path).expect("bind agent socket");
    listener.set_nonblocking(true).unwrap();
    let agent = control.clone();
    thread::spawn(move || {
        while !agent.stop.load(Ordering::Relaxed) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(2));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let body = loop {
                let n = stream.read(&mut buffer).unwrap_or(0);
                if n == 0 {
                    break None;
                }
                request.extend_from_slice(&buffer[..n]);
                let text = String::from_utf8_lossy(&request).to_string();
                if let Some(split) = text.find("\r\n\r\n") {
                    let length: usize = text[..split]
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    if text.len() >= split + 4 + length {
                        break Some((text[..split].to_string(), text[split + 4..].to_string()));
                    }
                }
            };
            let Some((head, body)) = body else { continue };
            let request: Value = serde_json::from_str(&body).unwrap();
            let (status, reply) = if head.starts_with("POST /challenge ") {
                (
                    200,
                    json!({"version": 1, "nonce": "bm9uY2U", "key": "agent-key"}).to_string(),
                )
            } else if head.starts_with("POST /attest ") {
                let key = request["serviceKey"].as_str().unwrap_or_default();
                let signature = request["signature"].as_str().unwrap_or_default();
                if !verify(key, "bm9uY2U", signature) {
                    agent.bad_signatures.fetch_add(1, Ordering::Relaxed);
                    (401, "{\"error\":\"bad signature\"}\n".to_string())
                } else if agent.attest_status.load(Ordering::Relaxed) != 200 {
                    (
                        agent.attest_status.load(Ordering::Relaxed),
                        "{\"error\":\"denied\"}\n".to_string(),
                    )
                } else {
                    let attestation = json!({
                        "version": 1, "attestationId": "att", "serviceKey": key, "key": "agent-key",
                        "shareName": request["shareName"], "protocol": request["protocol"], "target": request["target"],
                        "issuedAt": iso(now() - 1), "expiresAt": iso(now() + agent.ttl.load(Ordering::Relaxed)),
                        "signature": "c2ln", "extra": "kept"
                    });
                    (200, attestation.to_string())
                }
            } else {
                (404, "not found".to_string())
            };
            let response = if agent.chunked.load(Ordering::Relaxed) {
                format!(
                    "HTTP/1.1 {status} X\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{reply}\r\n0\r\n\r\n",
                    reply.len()
                )
            } else {
                format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n{reply}",
                    reply.len()
                )
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    control
}

// --- fake hub ---------------------------------------------------------------

#[derive(Default)]
struct HubState;

type Replaces = Arc<Mutex<Vec<Value>>>;

struct FakeHub {
    _channel: Channel<HubState>,
    server: Server<HubState>,
    replaces: Replaces,
}

impl FakeHub {
    fn start() -> Self {
        let replaces: Replaces = Arc::default();
        let log = replaces.clone();
        let mut channel = Channel::<HubState>::new();
        channel
            .post::<Value, Value, (), _>("hub/service/update", |_| Ok(None))
            .unwrap()
            .post::<Value, Value, (), _>(
                "network/shares/replace",
                move |request: PostRequest<'_, HubState, Value, ()>| {
                    log.lock().unwrap().push(request.body.clone());
                    let publications: Vec<Value> = request.body["shares"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .enumerate()
                        .map(|(index, share)| {
                            json!({
                                "version": 1, "resourceId": format!("hnr1_{}", share["name"].as_str().unwrap()),
                                "authority": "share.hub.invalid", "providerId": "provider",
                                "protocol": share["protocol"], "overlayAddress": "100.96.0.2", "port": 4000 + index
                            })
                        })
                        .collect();
                    Ok(Some(json!({ "shares": publications })))
                },
            )
            .unwrap();
        let server = channel
            .listen(0_u16, ListenOptions::default())
            .expect("listen");
        Self {
            _channel: channel,
            server,
            replaces,
        }
    }

    /// Polls the hub while `work` runs on another thread (the service's
    /// calls block until the hub answers).
    fn run<T: Send + 'static>(&mut self, work: impl FnOnce() -> T + Send + 'static) -> T {
        let handle = thread::spawn(work);
        while !handle.is_finished() {
            let _ = self.server.poll();
            thread::sleep(Duration::from_millis(1));
        }
        handle.join().unwrap()
    }

    fn pump(&mut self, ms: u64) {
        let deadline = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < deadline {
            let _ = self.server.poll();
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn last(&self) -> Value {
        self.replaces
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a shares/replace call")
    }

    fn count(&self) -> usize {
        self.replaces.lock().unwrap().len()
    }
}

fn service(hub: &FakeHub, dir: &PathBuf) -> (Arc<Mutex<Service>>, Arc<Keychain>) {
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let service = Service::new(ServiceOptions {
        address: Some(Address::Port(hub.server.port())),
        keychain: Some(keychain.clone()),
        device_key: Some(Arc::new(DeviceKey::with_path(dir.join("device.key")))),
        agent_socket: Some(dir.join("agent.sock")),
        ..ServiceOptions::default()
    });
    (Arc::new(Mutex::new(service)), keychain)
}

#[test]
fn declared_shares_are_published_on_connect() {
    let dir = temp_dir("declared");
    let agent = start_agent(dir.join("agent.sock"));
    let mut hub = FakeHub::start();
    let (service, keychain) = service(&hub, &dir);
    service
        .lock()
        .unwrap()
        .share(
            NetworkShare::new("s3", Protocol::Tcp, "127.0.0.1", 9001).policy(
                NetworkPolicy::Group {
                    group: "editors".into(),
                },
            ),
        )
        .unwrap()
        .start();
    let deadline = Instant::now() + Duration::from_secs(5);
    while hub.count() == 0 && Instant::now() < deadline {
        hub.pump(10);
    }
    hub.pump(100);

    assert_eq!(hub.count(), 1);
    assert_eq!(agent.bad_signatures.load(Ordering::Relaxed), 0);
    let wire = &hub.last()["shares"][0];
    assert_eq!(wire["name"], "s3");
    assert_eq!(wire["version"], 1);
    assert_eq!(wire["policy"], json!({"mode": "group", "group": "editors"}));
    assert_eq!(
        wire["attestation"]["serviceKey"],
        keychain.public_key().unwrap()
    );
    // Forwarded verbatim, unknown fields included.
    assert_eq!(wire["attestation"]["extra"], "kept");
    let publications = service.lock().unwrap().share_publications();
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0].resource_id, "hnr1_s3");
    assert_eq!(publications[0].overlay_address, "100.96.0.2");
    agent.stop.store(true, Ordering::Relaxed);
}

#[test]
fn publish_update_and_remove() {
    let dir = temp_dir("publish");
    let agent = start_agent(dir.join("agent.sock"));
    agent.chunked.store(true, Ordering::Relaxed);
    let mut hub = FakeHub::start();
    let (service, _) = service(&hub, &dir);
    let web = NetworkShare::new("web", Protocol::Tcp, "localhost", 8080).policy(NetworkPolicy::Hub);
    assert_eq!(
        service.lock().unwrap().publish_share(web.clone()),
        Err(ServiceError::NotStarted)
    );
    service.lock().unwrap().start();
    hub.pump(200);
    assert_eq!(hub.count(), 0, "nothing declared");

    let s = service.clone();
    let w = web.clone();
    let published = hub.run(move || {
        let service = s.lock().unwrap();
        service.publish_share(w)?;
        service.publish_share(NetworkShare::new("api", Protocol::Udp, "localhost", 9090))
    });
    let published = published.unwrap();
    assert_eq!(published.len(), 2);
    assert_eq!(published[0].resource_id, "hnr1_api");
    let shares = hub.last()["shares"].clone();
    assert_eq!(shares[0]["name"], "api");
    assert_eq!(shares[0]["policy"], json!({"mode": "private"}));

    // Update the port.
    let s = service.clone();
    let mut updated = web.clone();
    updated.target.port = 8081;
    hub.run(move || s.lock().unwrap().publish_share(updated))
        .unwrap();
    assert_eq!(hub.last()["shares"][1]["target"]["port"], 8081);

    let s = service.clone();
    let remaining = hub
        .run(move || s.lock().unwrap().remove_share("web"))
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(hub.last()["shares"].as_array().unwrap().len(), 1);
    assert_eq!(
        service.lock().unwrap().share_publications()[0].resource_id,
        "hnr1_api"
    );

    let s = service.clone();
    let missing = hub.run(move || s.lock().unwrap().remove_share("web"));
    assert_eq!(
        missing,
        Err(ServiceError::Network("Share 'web' not found".into()))
    );
    agent.stop.store(true, Ordering::Relaxed);
}

#[test]
fn agent_failures_roll_back() {
    let dir = temp_dir("rollback");
    let mut hub = FakeHub::start();
    let (service, _) = service(&hub, &dir);
    service.lock().unwrap().start();
    hub.pump(200);
    let web = NetworkShare::new("web", Protocol::Tcp, "localhost", 8080);

    // No agent.
    let (s, w) = (service.clone(), web.clone());
    match hub.run(move || s.lock().unwrap().publish_share(w)) {
        Err(ServiceError::Network(error)) => assert!(error.contains("unavailable"), "{error}"),
        other => panic!("{other:?}"),
    }

    // The agent refuses.
    let agent = start_agent(dir.join("agent.sock"));
    agent.attest_status.store(403, Ordering::Relaxed);
    let (s, w) = (service.clone(), web.clone());
    assert_eq!(
        hub.run(move || s.lock().unwrap().publish_share(w)),
        Err(ServiceError::Network(
            "Hub Network agent rejected attestation (403): {\"error\":\"denied\"}".into()
        ))
    );

    // An attestation that is already expired.
    agent.attest_status.store(200, Ordering::Relaxed);
    agent.ttl.store(-5, Ordering::Relaxed);
    let (s, w) = (service.clone(), web.clone());
    assert_eq!(
        hub.run(move || s.lock().unwrap().publish_share(w)),
        Err(ServiceError::Network(
            "Local-agent attestation is expired".into()
        ))
    );
    assert_eq!(hub.count(), 0);

    // Nothing above stayed declared.
    agent.ttl.store(300, Ordering::Relaxed);
    let s = service.clone();
    let published = hub
        .run(move || {
            s.lock().unwrap().publish_share(NetworkShare::new(
                "api",
                Protocol::Tcp,
                "localhost",
                9090,
            ))
        })
        .unwrap();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].resource_id, "hnr1_api");
    agent.stop.store(true, Ordering::Relaxed);
}

#[test]
fn invalid_shares() {
    let mut service = Service::new(ServiceOptions {
        disable_device: true,
        ..ServiceOptions::default()
    });
    let mut invalid =
        |share: NetworkShare| service.share(share).err().map(|error| error.to_string());
    assert_eq!(
        invalid(NetworkShare::new("a\nb", Protocol::Tcp, "localhost", 1)),
        Some("network error: Invalid Hub Network share name".into())
    );
    assert!(invalid(NetworkShare::new("x", Protocol::Tcp, "localhost", 0)).is_some());
    assert_eq!(
        invalid(
            NetworkShare::new("x", Protocol::Tcp, "localhost", 1)
                .policy(NetworkPolicy::Keys { keys: vec![] })
        ),
        Some("network error: Invalid Hub Network policy".into())
    );
}

#[test]
fn iso_times() {
    assert_eq!(parse_iso_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(
        parse_iso_ms("2026-10-20T20:12:00.5Z"),
        Some(1_792_527_120_500)
    );
    assert_eq!(
        parse_iso_ms("2026-10-20T23:12:00.500123+03:00"),
        Some(1_792_527_120_500)
    );
    assert_eq!(parse_iso_ms("2026-10-20T20:12:00"), None);
    assert_eq!(parse_iso_ms("yesterday"), None);
    assert_eq!(parse_iso_ms(&iso(1_792_527_120)), Some(1_792_527_120_123));
}
