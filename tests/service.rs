//! Unit tests for hub-service-rs: registration, settings/group auto-fill,
//! exact wire JSON, send-before-start errors, profile gating and the
//! AppInterface shape.

use channel_rs::ChannelError;
use hub_service_rs::{
    ApiSettings, App, AppHeader, Caller, Request, Service, ServiceOptions, ServicePermissions,
};
use serde_json::{json, Value};

fn echo(body: Value) -> Result<Value, ChannelError> {
    Ok(body)
}

#[test]
fn services_list_includes_registered_paths() {
    let mut service = Service::new(ServiceOptions::default());
    service
        .post("echo", echo)
        .stream("echo/values", |_body| Ok(Vec::new()))
        .app(App::new(AppHeader::new("Echo", "echo/ui")));
    let update = service.update_payload();
    // post + stream + app path, sorted by path
    let paths: Vec<&str> = update.services.iter().map(|s| s.path.as_str()).collect();
    assert_eq!(paths, vec!["echo", "echo/ui", "echo/values"]);
    assert_eq!(update.apps.len(), 1);
    assert_eq!(update.apps[0].path, "echo/ui");
    assert_eq!(update.apps[0].type_, "app");
    assert_eq!(update.apps[0].name, "Echo");
}

#[test]
fn settings_apply_to_update_payload() {
    let mut service = Service::new(ServiceOptions::default());
    service.post_with_settings(
        "echo",
        echo,
        ApiSettings {
            permissions: Some(ServicePermissions {
                group: String::new(),
                name: "Echo".to_string(),
                allows: Some(true),
            }),
            limit: Some(5),
        },
    );
    let update = service.update_payload();
    assert_eq!(update.services.len(), 1);
    let entry = &update.services[0];
    assert_eq!(entry.limit, Some(5));
    let permissions = entry.permissions.as_ref().expect("permissions set");
    // group auto-filled from the first path segment
    assert_eq!(permissions.group, "echo");
    assert_eq!(permissions.name, "Echo");
    assert_eq!(permissions.allows, Some(true));
}

#[test]
fn profile_only_when_set() {
    let plain = Service::new(ServiceOptions::default());
    assert!(plain.profile().is_none(), "no profile expected");

    let named = Service::new(ServiceOptions {
        name: Some("Echo".to_string()),
        ..Default::default()
    });
    let profile = named.profile().expect("profile expected with name");
    assert_eq!(profile.name.as_deref(), Some("Echo"));
    assert!(profile.icon.is_none());

    let icon_only = Service::new(ServiceOptions {
        icon: Some(json!({"symbol": "speaker.wave.2", "text": "E"})),
        ..Default::default()
    });
    assert!(icon_only.profile().is_some(), "icon alone sets a profile");
}

#[test]
fn update_json_matches_wire_contract() {
    let mut service = Service::new(ServiceOptions::default());
    service.post_with_settings(
        "echo",
        echo,
        ApiSettings {
            permissions: Some(ServicePermissions {
                group: String::new(),
                name: "Echo".to_string(),
                allows: Some(true),
            }),
            limit: Some(5),
        },
    );
    let raw = serde_json::to_string(&service.update_payload()).expect("serialize update");
    let want = r#"{"services":[{"path":"echo","permissions":{"group":"echo","name":"Echo","allows":true},"limit":5}],"apps":[]}"#;
    assert_eq!(raw, want, "update payload must match the wire contract exactly");
}

#[test]
fn send_before_start_errors() {
    let service = Service::new(ServiceOptions::default());
    assert!(service.send("echo", json!("x")).is_err(), "send must error before start");
    assert!(service.values("echo", json!("x")).is_err(), "values must error before start");
}

#[test]
fn app_interface_shape() {
    let app = App::new(AppHeader::new("Echo", "echo/ui")).body(vec![json!("hi")]);
    let interface = app.interface();
    let object = interface.as_object().expect("interface is an object");
    // all 5 keys always present
    for key in ["header", "body", "top", "bottom", "data"] {
        assert!(object.contains_key(key), "missing key {key}");
    }
    assert_eq!(object["top"], Value::Null);
    assert_eq!(object["bottom"], Value::Null);
    assert_eq!(object["data"], json!({}));
    assert_eq!(object["header"]["type"], "app");
    assert_eq!(object["header"]["name"], "Echo");
    assert_eq!(object["header"]["path"], "echo/ui");
    assert_eq!(object["body"], json!(["hi"]));
}

#[test]
fn caller_is_absent_without_hub_context() {
    assert_eq!(Caller::from_context(&json!({})), None);
    assert_eq!(Caller::from_context(&json!({"service": "abc"})), None);
    assert!(Request::new(json!(1), json!({})).caller.is_none());
}

#[test]
fn caller_anonymous_and_through_a_merged_hub() {
    let anonymous = Caller::from_context(&json!({
        "hub": {"caller": {"groups": [], "owner": false}, "hubKey": "H"}
    }))
    .expect("caller");
    assert_eq!(anonymous.key, None);
    assert_eq!(anonymous.device, None);
    assert!(!anonymous.owner);
    assert_eq!(anonymous.hub_key.as_deref(), Some("H"));

    let merged = Request::new(
        json!("body"),
        json!({"service": "s", "hub": {"caller": {
            "key": "M", "groups": ["g1", "g2"], "owner": false,
            "via": "V", "claimed": {"key": "K", "owner": true}
        }, "hubKey": "H"}}),
    );
    let caller = merged.caller.expect("caller");
    assert_eq!(caller.key.as_deref(), Some("M"));
    assert_eq!(caller.groups, vec!["g1", "g2"]);
    assert_eq!(caller.via.as_deref(), Some("V"));
    assert_eq!(caller.claimed, Some(json!({"key": "K", "owner": true})));
    assert_eq!(merged.context["service"], "s");
}
