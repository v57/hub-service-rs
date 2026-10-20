<h1>
  <img alt="Hub Service logo" src="./icon.png" width="70" valign="middle">
  &nbsp;hub-service-rs
</h1>

Rust port of [hub-service](https://github.com/v57/hub-service) — connect to a
[hub](https://github.com/v57/hub-lite) (default `ws://127.0.0.1:1997`), host
your own post/stream API endpoints, register apps, and call API through the hub.

Hub-pro auth (TS keychain parity, `Hub/Docs/Devices/protocol.md`): the
service loads-or-generates the ed25519 `auth` key file in the working
directory and attaches a freshly signed `key.<pub>.<sig>.<expiry>` token as the
raw `auth`/`v` header block on EVERY (re)connect — hub-lite ignores the headers
entirely, so the port stays regression-safe. On the first connection to a hub
it asks `hub/info` for the hub key, pins it in `hubs.json` beside the key file
(keyed by the address, a bare port as `ws://localhost:<port>`) and reconnects
with a v1 token that only that hub accepts. Unless
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

Start a hub first (`new Hub()` from hub-lite, listens on 1997), then:

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
  `auth` in the cwd, or `$HUBKEY`), `sign` (optional v0 token factory that
  replaces the keychain)
- `Keychain` / `KeychainError` — `sign(expires)` (v0) and
  `sign_for_hub(hub_key, expires)` (v1) → `key.<pub>.<sig>.<expiry>`,
  `public_key()`, `hub_key` / `pin_hub_key` / `forget_hub_key(address)`;
  `auth_token(key_file, hub_key, expiry)`, `connect_header_block(token, v, device)`
  Device options: `instance` (default: `$HUB_INSTANCE`, else `name`, else the
  working directory's name), `device_name` (default: `$HUB_DEVICE_NAME`, else
  the computer name), `parent` (`$HUB_DEVICE_PARENT`), `device_key`
  (`DeviceKey::from_key_file` for a key kept elsewhere), `disable_device`
  (`$HUB_DEVICE=0`)
- `forget_hub_key()` — drop this service's pin after the hub's key changed
- `DeviceKey`, `Certifier`, `Certificate`, `encode_certificate`, `device_id`,
  `safety_code` — the device key file and service certificates
- `post(path, handler)` / `post_with_settings(path, handler, ApiSettings)` /
  `stream(...)` — fluent; handlers take `serde_json::Value`
- `post_request(path, handler)` / `stream_request(...)` (and `_with_settings`)
  — handlers take a `Request { body, caller, context }`; `caller` is the hub's
  `Caller { key, device, groups, owner, via, claimed, hub_key }`, `None` when
  the call carries no hub caller (hub-lite)
- `app(App)` — register app header + `AppInterface` stream at `header.path`
- `send(path, body)` / `values(path, body)` — client calls through the hub
- `start()` — connect + poll thread; detects `is_connected` false→true per
  connection and re-sends `hub/profile/update` then `hub/service/update`

`ApiSettings` carries `Permissions` (group auto-filled from the first path
segment, TS parity) and `Limit` — wire-parity fields that hub-lite ignores.

Note: channel-rs's client `ConnectOptions` has no `on_connect` callback, so
`start()` spawns a poll thread (`Client::poll()`) and sends the update messages
on each `is_connected()` transition.

## Test

```bash
./scripts/test             # cargo test
cargo run --example echo   # example service (needs a hub on 1997)
# cross-language check (TS):
bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
```
