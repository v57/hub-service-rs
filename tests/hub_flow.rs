//! Connect flow against an in-process fake hub (a channel-rs server): v0
//! connect, hub/info, hub key pin, v1 reconnect; hub-lite stays on v0.

use channel_rs::{Channel, ListenOptions, PostRequest, Server};
use hub_service_rs::{Address, Keychain, Service, ServiceOptions, auth_token};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HUB_KEY: &str = "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hubflow-rs-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

type Connects = Arc<Mutex<Vec<HashMap<String, String>>>>;

#[derive(Default)]
struct HubState;

/// A fake hub recording each connection's handshake headers.
struct FakeHub {
    _channel: Channel<HubState>,
    server: Server<HubState>,
    connects: Connects,
}

impl FakeHub {
    fn start(answers_info: bool) -> Self {
        let connects: Connects = Arc::default();
        let mut channel = Channel::<HubState>::new();
        channel
            .post::<Value, Value, (), _>("hub/service/update", |_| Ok(None))
            .unwrap()
            .post::<Value, Value, (), _>("hub/profile/update", |_| Ok(None))
            .unwrap();
        if answers_info {
            channel
                .post::<Value, Value, (), _>("hub/info", |_: PostRequest<'_, HubState, Value, ()>| {
                    Ok(Some(json!({"key": HUB_KEY, "protocol": 1, "pro": true, "mode": "default-allow"})))
                })
                .unwrap();
        }
        let log = connects.clone();
        let server = channel
            .listen(
                0_u16,
                ListenOptions {
                    state: Some(Rc::new(move |headers: &HashMap<String, String>| {
                        log.lock().unwrap().push(headers.clone());
                        Ok(HubState)
                    })),
                    ..ListenOptions::default()
                },
            )
            .expect("listen");
        Self {
            _channel: channel,
            server,
            connects,
        }
    }

    /// Polls until `count` connections arrived (or `limit` passes), then a
    /// little longer so the service finishes its updates.
    fn pump(&mut self, count: usize, limit: Duration) {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline && self.connects.lock().unwrap().len() < count {
            let _ = self.server.poll();
            std::thread::sleep(Duration::from_millis(1));
        }
        let settle = Instant::now() + Duration::from_millis(300);
        while Instant::now() < settle {
            let _ = self.server.poll();
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn connects(&self) -> Vec<HashMap<String, String>> {
        self.connects.lock().unwrap().clone()
    }
}

fn service_for(hub: &FakeHub, keychain: &Arc<Keychain>) -> Service {
    Service::new(ServiceOptions {
        address: Some(Address::Port(hub.server.port())),
        keychain: Some(keychain.clone()),
        ..ServiceOptions::default()
    })
}

#[test]
fn learns_and_pins_the_hub_key_then_connects_with_v1() {
    let dir = temp_dir("pin");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(true);
    let mut service = service_for(&hub, &keychain);
    service.start();
    hub.pump(2, Duration::from_secs(5));

    let connects = hub.connects();
    assert_eq!(connects.len(), 2, "v0 connect, then a v1 reconnect");
    assert_eq!(connects[0]["v"], "0");
    assert_eq!(connects[1]["v"], "1");
    let address = format!("ws://127.0.0.1:{}", hub.server.port());
    assert_eq!(keychain.hub_key(&address).as_deref(), Some(HUB_KEY));

    // The v1 token signs hub1:<hub key>:<expiry> with the service key.
    let token = &connects[1]["auth"];
    let expiry: u64 = token.rsplit('.').next().unwrap().parse().unwrap();
    let key_file = fs::read_to_string(dir.join("auth")).unwrap();
    assert_eq!(
        token,
        &auth_token(&key_file, Some(HUB_KEY), expiry).unwrap()
    );
}

#[test]
fn pinned_hub_connects_once_with_v1() {
    let dir = temp_dir("pinned");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(true);
    keychain
        .pin_hub_key(&format!("ws://127.0.0.1:{}", hub.server.port()), HUB_KEY)
        .unwrap();
    let mut service = service_for(&hub, &keychain);
    service.start();
    hub.pump(2, Duration::from_millis(500));

    let connects = hub.connects();
    assert_eq!(connects.len(), 1);
    assert_eq!(connects[0]["v"], "1");
}

#[test]
fn hub_lite_stays_on_v0() {
    let dir = temp_dir("lite");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(false);
    let mut service = service_for(&hub, &keychain);
    service.start();
    hub.pump(2, Duration::from_millis(500));

    let connects = hub.connects();
    assert_eq!(connects.len(), 1);
    assert_eq!(connects[0]["v"], "0");
    assert!(!dir.join("hubs.json").exists());
}
