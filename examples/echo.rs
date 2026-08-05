//! Echo example service — mirrors hub-service-go/example.
//!
//! Registers `echo` (returns the body), `echo/upper` (uppercases a string)
//! and the `echo/ui` app, then connects to the hub (default 127.0.0.1:1997)
//! and stays alive forever.
//!
//! Run: `cargo run --example echo`
//! Verify (from the TS repo): `bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'`

use hub_service_rs::{Action, App, AppHeader, Service, ServiceOptions, button, cell, text_field};
use serde_json::{json, Value};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let mut service = Service::new(ServiceOptions {
        name: Some("Echo".to_string()),
        icon: Some(json!({"symbol": "speaker.wave.2", "text": "E"})),
        ..Default::default()
    });
    service
        .post("echo", |body| Ok(body))
        .post("echo/upper", |body: Value| {
            let text = body.as_str().unwrap_or_default();
            Ok(json!(text.to_uppercase()))
        })
        .app(
            App::new(AppHeader::new("Echo", "echo/ui"))
                .body(vec![
                    json!("Hello from Rust"),
                    text_field(
                        "echo",
                        Some("Text to echo"),
                        Some(
                            Action::new("echo/upper")
                                .body(json!("value"))
                                .output(json!("value")),
                        ),
                    ),
                    cell(Some(json!("$Echo")), Some(json!("value"))),
                    button(
                        "Upper",
                        Action::new("echo/upper")
                            .body(json!("value"))
                            .output(json!("value")),
                    ),
                ])
                .data(json!({"hello": "world"})),
        )
        .start();
    println!("echo service started (hub-lite :1997)");
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
