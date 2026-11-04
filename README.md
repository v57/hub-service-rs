<h1>
  <img alt="Hub Service logo" src="./icon.png" width="70" valign="middle">
  &nbsp;hub-service-rs
</h1>

Rust port of [hub-service](https://github.com/v57/hub-service) — connect to a
[hub](https://github.com/v57/hub-lite) (default `ws://127.0.0.1:1997`), host
your own post/stream API endpoints, register apps, and call API through the hub.

hub-server auth (TS keychain parity, `Hub/Docs/Devices/protocol.md` section 2): the
service loads-or-generates the ed25519 `auth` key file in the working
directory. Every (re)connect asks the hub to prove its key on a short anonymous
connection, then attaches a fresh `key.<pub>.<sig>.<expiry>.<nonce>` token as the
raw `auth`/`v` header block. The first proven key is pinned in `hubs.json` beside
the key file (keyed by the address, a bare port as `ws://localhost:<port>`). A hub
that doesn't prove its key, or proves another than the pinned one, gets nothing and
is reported while the service keeps trying, so calls wait instead of failing. Plain
`ws://` beyond loopback, the overlay and the LAN isn't dialed unless `allow_plaintext`
or `HUB_ALLOW_PLAINTEXT=1` says so. Unless
`disable_device` is set, every connect also sends a `device` header: a
certificate for the service key signed by the device key (`~/.hub/device.key`,
`/var/lib/hub/device.key` for root, or `$HUB_DEVICE_KEY`; created on first
use), renewed when less than a day of its 7 days is left. The wire contract matches the TS reference
(`hub/profile/update`, `hub/service/update`, AppInterface + element DSL).

## Install

```bash
cargo add hub-service-rs --git https://github.com/v57/hub-service-rs
```

Requires [channel-rs](https://github.com/v57/channel-rs) and a tokio runtime
(the channel client is driven by a poll thread owned by `Service::start`).

## Usage

Start a hub first (hub-server, listens on 1997), then:

```rust
use hub_service_rs::{Action, App, AppHeader, Service, ServiceOptions};
use serde_json::json;

#[tokio::main]
async fn main() {
    let mut service = Service::new(ServiceOptions {
        name: Some("Echo".into()),
        icon: Some(json!({"symbol": "speaker.wave.2", "text": "E"})),
        ..Default::default()
    });
    service
        .post("echo", |body| Ok(body))
        .post("echo/upper", |body| {
            Ok(json!(body.as_str().unwrap_or_default().to_uppercase()))
        })
        .app(
            App::new(AppHeader::new("Echo", "echo/ui"))
                .body(vec![
                    json!("Hello from Rust"),
                    text_field("echo", Some("Text to echo"),
                        Some(Action::new("echo/upper").body(json!("value")).output(json!("value")))),
                    cell(Some(json!("$Echo")), Some(json!("value"))),
                ]),
        )
        .start();
    // Service::start spawns the poll thread; keep the runtime alive.
    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
}
```

Call it through the hub (any language):

```rust
let response = service.send("echo/upper", json!("hello"))?; // "HELLO"
```

## API

- `Service::new(ServiceOptions)` — `address` (port or ws:// URL; default
  `1997` or `$HUB`), `name`, `icon`, `keychain` (default: `Keychain` reading
  `auth` in the cwd, or `$HUBKEY`), `sign` (optional token factory given the
  proven hub key and the challenge; turns off device mode), `allow_plaintext`
  (dial plain `ws://` beyond loopback, the overlay and the LAN; also
  `HUB_ALLOW_PLAINTEXT=1`)
- `Keychain` / `KeychainError` — `sign_for_hub(hub_key, nonce, expires)` and
  `sign_default(hub_key, nonce)` → `key.<pub>.<sig>.<expiry>.<nonce>` for one
  connection (30 s), `public_key()`, `hub_key` / `pin_hub_key` /
  `forget_hub_key(address)`; `auth_token(key_file, hub_key, nonce, expiry)`,
  `connect_header_block(token, device)`
- `hub_transport_of(address)`, `HubInfo`, `hub_info_signed_data`,
  `make_client_nonce` — the transport classes and the hub's proof
  Device options: `instance` (default: `$HUB_INSTANCE`, else `name`, else the
  working directory's name), `device_name` (default: `$HUB_DEVICE_NAME`, else
  the computer name), `parent` (`$HUB_DEVICE_PARENT`), `device_key`
  (`DeviceKey::from_key_file` for a key kept elsewhere), `disable_device`
  (`$HUB_DEVICE=0`)
- `hub_key()` / `forget_hub_key()` — this service's pin; drop it after the hub's
  key changed
- `DeviceKey`, `Certifier`, `Certificate`, `encode_certificate`, `device_id`,
  `safety_code` — the device key file and service certificates
- `share(NetworkShare)` before `start()`, `publish_share(share)`,
  `remove_share(name)`, `share_publications()` — Hub Network shares (TS
  `publishShare` parity): the local hub-net agent (`agent_socket`, default
  `/var/run/hub-net/agent.sock` on macOS, `/run/hub-net/agent.sock` on Linux)
  attests each local target and the hub publishes the declared set, again on
  every reconnect
- `post(path, handler)` / `post_with_settings(path, handler, ApiSettings)` /
  `stream(...)` — fluent; handlers take `serde_json::Value`
- `post_request(path, handler)` / `stream_request(...)` (and `_with_settings`)
  — handlers take a `Request { body, caller, context }`; `caller` is the hub's
  `Caller { key, device, groups, owner, via, claimed, hub_key }`, `None` when
  the call carries no hub caller
- `app(App)` — register app header + `AppInterface` stream at `header.path`
- `send(path, body)` / `values(path, body)` — client calls through the hub
- `start()` — connect + poll thread; detects `is_connected` false→true per
  connection and re-sends `hub/profile/update` then `hub/service/update`

`ApiSettings` carries `Permissions` (group auto-filled from the first path
segment, TS parity) and `Limit`.

Note: channel-rs's client `ConnectOptions` has no `on_connect` callback, so
`start()` spawns a poll thread (`Client::poll()`) and sends the update messages
on each `is_connected()` transition. Its client has no TLS and this crate builds
it without QUIC, so `wss://` and `quic://` addresses pass the transport check but
fail to connect (reported, and retried). There is no `stop`: the poll thread runs
for the life of the process.

## Test

```bash
./scripts/test             # cargo test
cargo run --example echo   # example service (needs a hub on 1997)
# cross-language check (TS):
bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
```
