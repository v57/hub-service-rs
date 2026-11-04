//! Connect flow against an in-process fake hub (a channel-rs server): the proof
//! of the hub's key, the pin, a token for that answer's challenge alone, and
//! nothing at all for a hub that doesn't prove its key.

mod common;

use channel_rs::{CallResult, Channel, ListenOptions, PostRequest, Sender, Server};
use common::{HUB_KEY, HUB_SEED, OTHER_KEY, OTHER_SEED, answer, nonce, proof};
use hub_service_rs::{Address, DeviceKey, Keychain, Service, ServiceError, ServiceOptions, auth_token};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// How the fake hub answers `hub/info`.
#[derive(Clone, Copy)]
enum Info {
    /// Proves the real hub key.
    Proving,
    /// Proves its own key (another than `HUB_KEY`).
    ProvingOther,
    /// The real key, with no proof.
    NoProof,
    /// Claims the real key, signs with its own.
    ForgedProof,
    /// Proves the real key, but with no challenge.
    NoChallenge,
    /// Proves the real key, with a challenge that would add a header line.
    BadChallenge,
}

/// A fake hub recording each connection's handshake headers.
struct FakeHub {
    _channel: Channel<HubState>,
    server: Server<HubState>,
    connects: Connects,
    nonces: Rc<RefCell<Vec<String>>>,
    updates: Rc<Cell<usize>>,
    sender: Rc<RefCell<Option<Sender<HubState>>>>,
}

impl FakeHub {
    fn start(info: Info) -> Self {
        let connects: Connects = Arc::default();
        let nonces: Rc<RefCell<Vec<String>>> = Rc::default();
        let updates: Rc<Cell<usize>> = Rc::default();
        let mut channel = Channel::<HubState>::new();
        let asked = nonces.clone();
        let registered = updates.clone();
        channel
            .post::<Value, Value, (), _>("hub/service/update", move |_| {
                registered.set(registered.get() + 1);
                Ok(None)
            })
            .unwrap()
            .post::<Value, Value, (), _>("hub/profile/update", |_| Ok(None))
            .unwrap()
            .post::<Value, Value, (), _>("hub/info", move |request: PostRequest<'_, HubState, Value, ()>| {
                let body = &request.body;
                asked.borrow_mut().push(nonce(body).to_string());
                let challenge = format!("challenge-{}", asked.borrow().len());
                let mut reply = match info {
                    Info::Proving | Info::NoProof | Info::NoChallenge | Info::BadChallenge => {
                        answer(&HUB_SEED, HUB_KEY, body, &challenge)
                    }
                    Info::ProvingOther => answer(&OTHER_SEED, OTHER_KEY, body, &challenge),
                    Info::ForgedProof => answer(&HUB_SEED, HUB_KEY, body, &challenge),
                };
                match info {
                    Info::NoProof => {
                        reply.as_object_mut().unwrap().remove("proof");
                    }
                    Info::ForgedProof => reply["proof"] = json!(proof(&OTHER_SEED, HUB_KEY, nonce(body))),
                    Info::NoChallenge => {
                        reply.as_object_mut().unwrap().remove("challenge");
                    }
                    Info::BadChallenge => reply["challenge"] = json!("c\r\nx: y"),
                    _ => {}
                }
                Ok(Some(reply))
            })
            .unwrap();
        let log = connects.clone();
        let sender: Rc<RefCell<Option<Sender<HubState>>>> = Rc::default();
        let latest = sender.clone();
        let server = channel
            .listen(
                0_u16,
                ListenOptions {
                    state: Some(Rc::new(move |headers: &HashMap<String, String>| {
                        log.lock().unwrap().push(headers.clone());
                        Ok(HubState)
                    })),
                    on_connect: Some(Rc::new(move |_state: &mut HubState, sender| {
                        *latest.borrow_mut() = Some(sender);
                    })),
                    ..ListenOptions::default()
                },
            )
            .expect("listen");
        Self {
            _channel: channel,
            server,
            connects,
            nonces,
            updates,
            sender,
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

    /// No connection so far carried credentials, and nothing registered.
    fn assert_got_nothing(&self) {
        let connects = self.connects();
        assert!(!connects.is_empty(), "the service asked");
        for headers in &connects {
            assert!(!headers.contains_key("auth"), "sent auth: {headers:?}");
            assert!(!headers.contains_key("device"), "sent device: {headers:?}");
            assert!(!headers.contains_key("v"), "sent v: {headers:?}");
        }
        assert_eq!(self.updates.get(), 0, "registered on an anonymous connection");
    }
}

fn service_for(hub: &FakeHub, keychain: &Arc<Keychain>) -> Service {
    // The device key sits beside the temp key file, never in ~/.hub.
    let device_key = keychain.path().with_file_name("device.key");
    Service::new(ServiceOptions {
        address: Some(Address::Port(hub.server.port())),
        keychain: Some(keychain.clone()),
        device_key: Some(Arc::new(DeviceKey::with_path(device_key))),
        ..ServiceOptions::default()
    })
}

fn pin_address(hub: &FakeHub) -> String {
    format!("ws://localhost:{}", hub.server.port())
}

#[test]
fn sends_a_token_only_after_the_proof_and_pins_the_key() {
    let dir = temp_dir("pin");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(Info::Proving);
    let mut service = service_for(&hub, &keychain);
    service.start();
    hub.pump(2, Duration::from_secs(5));

    let connects = hub.connects();
    assert_eq!(connects.len(), 2, "the anonymous question, then the connect");
    assert!(!connects[0].contains_key("auth") && !connects[0].contains_key("device"));
    assert_eq!(connects[1]["v"], "1");
    assert_eq!(keychain.hub_key(&pin_address(&hub)).as_deref(), Some(HUB_KEY));
    assert_eq!(service.hub_key().as_deref(), Some(HUB_KEY));
    assert_eq!(hub.updates.get(), 1);

    // The token signs hub1:<hub key>:<challenge>:<expiry> with the service key.
    let token = &connects[1]["auth"];
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts[4], "challenge-1");
    let expiry: u64 = parts[3].parse().unwrap();
    let key_file = fs::read_to_string(dir.join("auth")).unwrap();
    assert_eq!(
        token,
        &auth_token(&key_file, HUB_KEY, "challenge-1", expiry).unwrap()
    );
    let nonce = hub.nonces.borrow()[0].clone();
    assert_eq!(nonce.len(), 43, "32 bytes in base64url, no padding");
}

#[test]
fn every_connect_asks_again_with_its_own_nonce_and_challenge() {
    let dir = temp_dir("again");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(Info::Proving);
    let mut first = service_for(&hub, &keychain);
    first.start();
    hub.pump(2, Duration::from_secs(5));
    // The same pin, a new connect: it asks again.
    let mut second = service_for(&hub, &keychain);
    second.start();
    hub.pump(4, Duration::from_secs(5));

    let connects = hub.connects();
    assert_eq!(connects.len(), 4);
    let tokens: Vec<&String> = connects.iter().filter_map(|headers| headers.get("auth")).collect();
    assert_eq!(tokens.len(), 2);
    assert_ne!(tokens[0].split('.').nth(4), tokens[1].split('.').nth(4));
    let nonces = hub.nonces.borrow();
    assert_eq!(nonces.len(), 2);
    assert_ne!(nonces[0], nonces[1]);
}

fn gets_nothing(info: Info) {
    let dir = temp_dir("noproof");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(info);
    let mut service = service_for(&hub, &keychain);
    service.start();
    // Long enough for a retry: the first one comes after a second.
    hub.pump(2, Duration::from_millis(2500));
    assert!(hub.connects().len() >= 2, "retries");
    hub.assert_got_nothing();
    assert_eq!(keychain.hub_key(&pin_address(&hub)), None);
    assert!(!dir.join("hubs.json").exists());
}

#[test]
fn hub_with_no_proof_gets_nothing() {
    gets_nothing(Info::NoProof);
}

#[test]
fn hub_claiming_the_real_key_with_its_own_signature_gets_nothing() {
    gets_nothing(Info::ForgedProof);
}

#[test]
fn hub_with_no_challenge_gets_nothing() {
    gets_nothing(Info::NoChallenge);
}

#[test]
fn hub_with_a_challenge_that_is_no_token_part_gets_nothing() {
    gets_nothing(Info::BadChallenge);
}

#[test]
fn pinned_address_answering_with_another_proven_key_gets_nothing() {
    let dir = temp_dir("otherkey");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(Info::ProvingOther);
    keychain.pin_hub_key(&pin_address(&hub), HUB_KEY).unwrap();
    let mut service = service_for(&hub, &keychain);
    service.start();
    hub.pump(2, Duration::from_millis(1500));

    hub.assert_got_nothing();
    assert_eq!(keychain.hub_key(&pin_address(&hub)).as_deref(), Some(HUB_KEY));
}

#[test]
fn a_refused_address_is_not_dialed() {
    let dir = temp_dir("refused");
    let options = || ServiceOptions {
        address: Some(Address::Url("ws://hub.example.com:1997".into())),
        keychain: Some(Arc::new(Keychain::with_path(dir.join("auth")))),
        disable_device: true,
        ..ServiceOptions::default()
    };
    let mut service = Service::new(options());
    service.start();
    let error = service.send("x", json!(1)).unwrap_err();
    assert!(matches!(error, ServiceError::PlaintextRefused(_)), "{error:?}");
    assert!(error.to_string().contains("unencrypted"), "{error}");
    assert!(service.values("x", json!(1)).is_err());
    assert!(!dir.join("auth").exists(), "signed nothing");

    let allowed = Service::new(ServiceOptions { allow_plaintext: true, ..options() });
    assert_eq!(allowed.plaintext_refusal(), None);
}

#[test]
fn a_call_made_right_away_waits_for_the_connection() {
    let dir = temp_dir("wait");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(Info::Proving);
    let mut service = service_for(&hub, &keychain);
    service.start();
    let service = &service;
    std::thread::scope(|scope| {
        let call = scope.spawn(move || service.send("hub/profile/update", json!({})));
        hub.pump(2, Duration::from_secs(5));
        while !call.is_finished() {
            hub.pump(0, Duration::from_millis(1));
        }
        assert_eq!(call.join().unwrap(), Ok(Value::Null));
    });
    assert_eq!(hub.updates.get(), 1, "the call went out after the registration");
}

#[test]
fn a_custom_signer_gets_the_proven_key_and_the_challenge() {
    let dir = temp_dir("sign");
    let calls: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let log = calls.clone();
    let mut hub = FakeHub::start(Info::Proving);
    let mut service = Service::new(ServiceOptions {
        address: Some(Address::Port(hub.server.port())),
        keychain: Some(Arc::new(Keychain::with_path(dir.join("auth")))),
        disable_device: true,
        sign: Some(Arc::new(move |hub_key: &str, nonce: &str| {
            log.lock().unwrap().push((hub_key.to_string(), nonce.to_string()));
            "custom-token".to_string()
        })),
        ..ServiceOptions::default()
    });
    service.start();
    hub.pump(2, Duration::from_secs(5));
    assert_eq!(calls.lock().unwrap()[0], (HUB_KEY.to_string(), "challenge-1".to_string()));
    let connects = hub.connects();
    assert_eq!(connects[1]["auth"], "custom-token");
    assert_eq!(connects[1]["v"], "1");
    assert!(!connects[1].contains_key("device"));
    assert!(!dir.join("auth").exists(), "the keychain signed nothing");

    // A hub with no proof never reaches it.
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    let mut unproven = FakeHub::start(Info::NoProof);
    let mut service = Service::new(ServiceOptions {
        address: Some(Address::Port(unproven.server.port())),
        keychain: Some(Arc::new(Keychain::with_path(dir.join("auth2")))),
        disable_device: true,
        sign: Some(Arc::new(move |_: &str, _: &str| {
            counted.fetch_add(1, Ordering::Relaxed);
            "custom-token".to_string()
        })),
        ..ServiceOptions::default()
    });
    service.start();
    unproven.pump(1, Duration::from_secs(5));
    assert_eq!(count.load(Ordering::Relaxed), 0);
    unproven.assert_got_nothing();
}

#[test]
fn every_connect_carries_the_device_certificate() {
    let dir = temp_dir("device");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(Info::Proving);
    let mut service = service_for(&hub, &keychain);
    service.start();
    hub.pump(2, Duration::from_secs(5));

    let connects = hub.connects();
    assert_eq!(connects.len(), 2);
    // Only on the connection after the proof.
    assert!(!connects[0].contains_key("device"));
    let device_key = DeviceKey::with_path(dir.join("device.key"));
    let (payload, _) = connects[1]["device"].split_once('.').unwrap();
    use base64::Engine;
    let json: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(json["device"], device_key.public_key().unwrap());
    assert_eq!(json["service"], keychain.public_key().unwrap());
}

#[test]
fn disabled_device_mode_sends_no_certificate() {
    let dir = temp_dir("nodevice");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(Info::Proving);
    let mut service = Service::new(ServiceOptions {
        address: Some(Address::Port(hub.server.port())),
        keychain: Some(keychain.clone()),
        disable_device: true,
        ..ServiceOptions::default()
    });
    service.start();
    hub.pump(2, Duration::from_secs(5));

    let connects = hub.connects();
    assert_eq!(connects.len(), 2);
    assert_eq!(connects[1]["v"], "1");
    assert!(!connects[1].contains_key("device"));
    assert!(!dir.join("device.key").exists());
}

#[test]
fn handlers_see_the_caller() {
    let dir = temp_dir("caller");
    let keychain = Arc::new(Keychain::with_path(dir.join("auth")));
    let mut hub = FakeHub::start(Info::Proving);
    let mut service = service_for(&hub, &keychain);
    service.post_request("who", |request| {
        Ok(match request.caller {
            Some(caller) => json!({
                "key": caller.key,
                "device": caller.device.map(|device| device.name),
                "owner": caller.owner,
                "body": request.body,
            }),
            None => Value::Null,
        })
    });
    service.start();
    hub.pump(2, Duration::from_secs(5));

    let sender = hub.sender.borrow_mut().take().expect("service connected");
    let context = json!({"hub": {"caller": {
        "key": "K", "device": {"id": "d", "name": "Mac Studio"}, "groups": ["owners"], "owner": true
    }, "hubKey": HUB_KEY}});
    let reply = sender
        .send_with_context::<Value, Value, Value>("who", json!(7), context)
        .unwrap();
    assert!(
        matches!(&reply, CallResult::Ok(Some(value)) if *value == json!({"key": "K", "device": "Mac Studio", "owner": true, "body": 7}))
    );

    let reply = sender.send::<Value, Value>("who", json!(7)).unwrap();
    assert!(matches!(
        reply,
        CallResult::Ok(None) | CallResult::Ok(Some(Value::Null))
    ));
}
