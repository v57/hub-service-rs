<h1>
  <img alt="Hub Service logo" src="./icon.png" width="70" valign="middle">
  &nbsp;hub-service-rs
</h1>

Rust port of [hub-service](https://github.com/v57/hub-service) — connect to a
[hub](https://github.com/v57/hub-lite) (default `ws://127.0.0.1:1997`), host
your own post/stream API endpoints, register apps, and call API through the hub.

Hub-pro auth (TS keychain parity): the service loads-or-generates the ed25519
`auth` key file in the working directory and attaches a freshly signed
`key.<pub>.<sig>.<expiry>` token as the raw `auth: ...\r\nv: 0\r\n` header
block on EVERY (re)connect — hub-lite ignores the headers entirely, so the
port stays regression-safe. The wire contract matches the TS reference
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
  `1997` or `$HUB`), `name`, `icon`, `sign` (optional token factory; default:
  `Keychain` reading `auth` in the cwd, or `$HUBKEY`)
- `Keychain` / `KeychainError` — `sign(expires)` → `key.<pub>.<sig>.<expiry>`,
  `public_key()`, `auth_header_block(token)` → the raw `auth`+`v` headers
- `post(path, handler)` / `post_with_settings(path, handler, ApiSettings)` /
  `stream(...)` — fluent; handlers take `serde_json::Value`
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
