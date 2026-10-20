//! hub-service-rs — Rust port of [hub-service](https://github.com/v57/hub-service).
//!
//! Connect to a hub (hub-lite / hub-pro), host post/stream API endpoints,
//! register apps, and call API through the hub.
//!
//! Hub-pro auth (TS keychain parity, `Docs/Devices/protocol.md`): the
//! service loads-or-generates the ed25519 `auth` key file in the cwd and
//! attaches a freshly signed `key.<pub>.<sig>.<expiry>` token as the raw
//! `auth`/`v` header block on EVERY (re)connect (hub-lite ignores the headers
//! entirely, so the port stays regression-safe). With no hub key pinned for
//! the address it connects with v0, asks `hub/info` for the hub key, pins it
//! in `hubs.json` and reconnects with a v1 token bound to that hub. Unless
//! disabled, every connect also sends a certificate for the service key
//! signed by the device key (see [`DeviceKey`]), renewed when less than a day
//! is left. The wire
//! contract matches the TS reference: `hub/profile/update`,
//! `hub/service/update` on every (re)connect, AppInterface + element DSL.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fmt;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

pub use channel_rs::*;

mod device;
mod keychain;
pub use device::{
    CERTIFICATE_LIFETIME, CERTIFICATE_RENEW, Certificate, Certifier, DeviceKey, default_device_name,
    device_id, device_mode_enabled, encode_certificate, host_name, platform, safety_code,
};
pub use keychain::{AUTH_EXPIRY, Keychain, KeychainError, auth_token};

const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const POLL_SLEEP: Duration = Duration::from_millis(1);

/// The v0 raw header block for the WebSocket upgrade request:
/// `auth: <fresh token>` + `v: 0` (channel-rs appends the final CRLF itself;
/// keeping ours makes the block self-contained).
pub fn auth_header_block(token: &str) -> String {
    connect_header_block(token, 0, None)
}

/// The raw handshake header block: `auth`, `v` (0 or 1) and, when given,
/// the `device` certificate.
pub fn connect_header_block(token: &str, version: u8, device: Option<&str>) -> String {
    let mut block = format!("auth: {token}\r\nv: {version}\r\n");
    if let Some(device) = device {
        block.push_str(&format!("device: {device}\r\n"));
    }
    block
}

// ---------------------------------------------------------------------------
// Options & address
// ---------------------------------------------------------------------------

/// Where to connect: a port on 127.0.0.1 or a full `ws://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Port(u16),
    Url(String),
}

/// Options for [`Service::new`]. All fields optional.
#[derive(Default)]
pub struct ServiceOptions {
    /// Port (u16) or `ws://` URL. Default: `1997`, or `$HUB` when set.
    pub address: Option<Address>,
    /// Profile name shown in the hub.
    pub name: Option<String>,
    /// Profile icon: a string or `{"symbol": ..., "text": ...}`.
    pub icon: Option<Value>,
    /// Optional v0 token factory for hub-pro auth, replacing the keychain.
    /// The returned token is attached as the raw `auth` header on every
    /// (re)connect; an empty string connects without auth headers. No hub
    /// key is learned or pinned with a custom factory.
    pub sign: Option<Arc<dyn Fn() -> String + Send + Sync>>,
    /// The keychain to sign with and keep hub key pins in (default:
    /// [`Keychain::new`], the `auth` file in the cwd or `$HUBKEY`).
    pub keychain: Option<Arc<Keychain>>,
    /// Instance name in the device certificate, unique per device
    /// (`s3-local/Backup Disk`). Default: `$HUB_INSTANCE`, else `name`, else
    /// the basename of the working directory, else `service`.
    pub instance: Option<String>,
    /// Suggested device name in the certificate. Default: `$HUB_DEVICE_NAME`,
    /// else the macOS computer name, else the host name.
    pub device_name: Option<String>,
    /// Declared parent device name, for containers and VMs. Default:
    /// `$HUB_DEVICE_PARENT`.
    pub parent: Option<String>,
    /// The device key (default: [`DeviceKey::new`], `~/.hub/device.key` or
    /// `$HUB_DEVICE_KEY`). Apps that keep it in their own store pass
    /// [`DeviceKey::from_key_file`].
    pub device_key: Option<Arc<DeviceKey>>,
    /// No device key and no `device` header: a plain key connection.
    /// `$HUB_DEVICE=0` (or `off`, `false`, `no`) does the same.
    pub disable_device: bool,
}

impl fmt::Debug for ServiceOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceOptions")
            .field("address", &self.address)
            .field("name", &self.name)
            .field("icon", &self.icon)
            .field("sign", &self.sign.as_ref().map(|_| "<closure>"))
            .field("keychain", &self.keychain.as_ref().map(|keychain| keychain.path().to_path_buf()))
            .field("instance", &self.instance)
            .field("device_name", &self.device_name)
            .field("parent", &self.parent)
            .field("device_key", &self.device_key.as_ref().map(|key| key.path().to_path_buf()))
            .field("disable_device", &self.disable_device)
            .finish()
    }
}

impl Clone for ServiceOptions {
    fn clone(&self) -> Self {
        Self {
            address: self.address.clone(),
            name: self.name.clone(),
            icon: self.icon.clone(),
            sign: self.sign.clone(),
            keychain: self.keychain.clone(),
            instance: self.instance.clone(),
            device_name: self.device_name.clone(),
            parent: self.parent.clone(),
            device_key: self.device_key.clone(),
            disable_device: self.disable_device,
        }
    }
}

impl Address {
    /// The key of this address's hub key pin (see [`normalize_hub_address`]).
    pub fn pin_address(&self) -> String {
        match self {
            Address::Port(port) => normalize_hub_address(&port.to_string()),
            Address::Url(url) => normalize_hub_address(url),
        }
    }
}

/// A hub address normalized for hub key pins (protocol.md section 2): a bare
/// port `1997` becomes `ws://localhost:1997`; otherwise the URL as given with
/// the scheme and host lowercased and no trailing slash.
pub fn normalize_hub_address(address: &str) -> String {
    if !address.is_empty() && address.bytes().all(|byte| byte.is_ascii_digit()) {
        return format!("ws://localhost:{address}");
    }
    let trimmed = address.trim_end_matches('/');
    match trimmed.find("://") {
        Some(scheme_end) => {
            let rest = &trimmed[scheme_end + 3..];
            let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            format!(
                "{}://{}{}",
                trimmed[..scheme_end].to_ascii_lowercase(),
                rest[..authority_end].to_ascii_lowercase(),
                &rest[authority_end..]
            )
        }
        None => trimmed.to_string(),
    }
}

fn resolve_address(options: &ServiceOptions) -> Address {
    if let Some(address) = &options.address {
        return address.clone();
    }
    if let Ok(env) = env::var("HUB") {
        if !env.is_empty() {
            return if env.starts_with("ws://") || env.starts_with("wss://") {
                Address::Url(env)
            } else if let Ok(port) = env.parse::<u16>() {
                Address::Port(port)
            } else {
                Address::Url(env)
            };
        }
    }
    Address::Port(1997)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Profile sent as `hub/profile/update` on connect (only when set).
#[derive(Debug, Clone, Serialize)]
pub struct Profile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<Value>,
}

/// Pro-only wire-parity permissions; hub-lite ignores it.
#[derive(Debug, Clone, Serialize)]
pub struct ServicePermissions {
    /// Auto-filled with the first path segment when empty (TS parity).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub group: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allows: Option<bool>,
}

/// Settings for a registered API path (pro-only fields, wire parity).
#[derive(Debug, Clone, Default)]
pub struct ApiSettings {
    pub permissions: Option<ServicePermissions>,
    pub limit: Option<u32>,
}

/// One entry of the `hub/service/update` services array.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceHeader {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<ServicePermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One entry of the `hub/service/update` apps array (`type` is always "app").
#[derive(Debug, Clone, Serialize)]
pub struct AppHeader {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub path: String,
}

impl AppHeader {
    /// Builds an app header with `type: "app"`.
    pub fn new(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            type_: "app".to_string(),
            name: name.into(),
            path: path.into(),
        }
    }
}

/// The `hub/service/update` payload.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceUpdate {
    pub services: Vec<ServiceHeader>,
    pub apps: Vec<AppHeader>,
}

/// Action reference from a UI element to an API call.
#[derive(Debug, Clone, Serialize)]
pub struct Action {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
}

impl Action {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            body: None,
            output: None,
        }
    }

    pub fn body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    pub fn output(mut self, output: Value) -> Self {
        self.output = Some(output);
        self
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

/// A hub app: a header plus a UI body of elements (TS app.ts parity).
/// Body entries are plain strings (shorthand text) or element maps built
/// with the helpers below.
#[derive(Debug, Clone)]
pub struct App {
    pub header: AppHeader,
    pub body: Vec<Value>,
    pub top: Option<Value>,
    pub bottom: Option<Value>,
    pub data: Value,
}

impl App {
    pub fn new(header: AppHeader) -> Self {
        Self {
            header,
            body: Vec::new(),
            top: None,
            bottom: None,
            data: json!({}),
        }
    }

    pub fn body(mut self, body: Vec<Value>) -> Self {
        self.body = body;
        self
    }

    pub fn top(mut self, top: Value) -> Self {
        self.top = Some(top);
        self
    }

    pub fn bottom(mut self, bottom: Value) -> Self {
        self.bottom = Some(bottom);
        self
    }

    pub fn data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }

    /// The AppInterface map streamed at the app path: all five keys always
    /// present (`top`/`bottom` are null when unset).
    pub fn interface(&self) -> Value {
        json!({
            "header": self.header.clone(),
            "body": self.body.clone(),
            "top": self.top.clone(),
            "bottom": self.bottom.clone(),
            "data": self.data.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Element helpers (TS app.ts wire shapes)
// ---------------------------------------------------------------------------

fn element(entries: Vec<(&str, Value)>) -> Value {
    let mut map = serde_json::Map::new();
    for (key, value) in entries {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

/// `{"type":"text","value":...}` (plain strings are the shorthand form).
pub fn text(value: impl Into<String>) -> Value {
    element(vec![("type", json!("text")), ("value", json!(value.into()))])
}

pub fn progress(value: impl Into<String>, min: Option<f64>, max: Option<f64>) -> Value {
    let mut entries = vec![("type", json!("progress")), ("value", json!(value.into()))];
    if let Some(min) = min {
        entries.push(("min", json!(min)));
    }
    if let Some(max) = max {
        entries.push(("max", json!(max)));
    }
    element(entries)
}

pub fn text_field(value: impl Into<String>, placeholder: Option<&str>, action: Option<Action>) -> Value {
    let mut entries = vec![("type", json!("textField")), ("value", json!(value.into()))];
    if let Some(placeholder) = placeholder {
        entries.push(("placeholder", json!(placeholder)));
    }
    if let Some(action) = action {
        entries.push(("action", json!(action)));
    }
    element(entries)
}

pub fn button(title: impl Into<String>, action: Action) -> Value {
    element(vec![
        ("type", json!("button")),
        ("title", json!(title.into())),
        ("action", json!(action)),
    ])
}

pub fn slider(
    value: impl Into<String>,
    default_value: Option<f64>,
    min: Option<f64>,
    max: Option<f64>,
    step: Option<f64>,
    action: Option<Action>,
) -> Value {
    let mut entries = vec![("type", json!("slider")), ("value", json!(value.into()))];
    if let Some(default_value) = default_value {
        entries.push(("defaultValue", json!(default_value)));
    }
    if let Some(min) = min {
        entries.push(("min", json!(min)));
    }
    if let Some(max) = max {
        entries.push(("max", json!(max)));
    }
    if let Some(step) = step {
        entries.push(("step", json!(step)));
    }
    if let Some(action) = action {
        entries.push(("action", json!(action)));
    }
    element(entries)
}

pub fn list(data: impl Into<String>, content: Value) -> Value {
    element(vec![
        ("type", json!("list")),
        ("data", json!(data.into())),
        ("content", content),
    ])
}

pub fn picker(options: Vec<String>, selected: impl Into<String>) -> Value {
    element(vec![
        ("type", json!("picker")),
        ("options", json!(options)),
        ("selected", json!(selected.into())),
    ])
}

pub fn cell(title: Option<Value>, subtitle: Option<Value>) -> Value {
    let mut entries = vec![("type", json!("cell"))];
    if let Some(title) = title {
        entries.push(("title", title));
    }
    if let Some(subtitle) = subtitle {
        entries.push(("subtitle", subtitle));
    }
    element(entries)
}

pub fn files(value: impl Into<String>, title: Option<Value>, action: Action) -> Value {
    let mut entries = vec![
        ("type", json!("files")),
        ("value", json!(value.into())),
        ("action", json!(action)),
    ];
    if let Some(title) = title {
        entries.push(("title", title));
    }
    element(entries)
}

pub fn file_operation(format: Option<&str>, title: Option<Value>, action: Action) -> Value {
    let mut entries = vec![("type", json!("fileOperation")), ("action", json!(action))];
    if let Some(format) = format {
        entries.push(("format", json!(format)));
    }
    if let Some(title) = title {
        entries.push(("title", title));
    }
    element(entries)
}

pub fn hstack(content: Vec<Value>, spacing: Option<f64>) -> Value {
    let mut entries = vec![("type", json!("hstack")), ("content", json!(content))];
    if let Some(spacing) = spacing {
        entries.push(("spacing", json!(spacing)));
    }
    element(entries)
}

pub fn vstack(content: Vec<Value>, spacing: Option<f64>) -> Value {
    let mut entries = vec![("type", json!("vstack")), ("content", json!(content))];
    if let Some(spacing) = spacing {
        entries.push(("spacing", json!(spacing)));
    }
    element(entries)
}

pub fn zstack(content: Vec<Value>) -> Value {
    element(vec![("type", json!("zstack")), ("content", json!(content))])
}

pub fn spacer() -> Value {
    element(vec![("type", json!("spacer"))])
}

// ---------------------------------------------------------------------------
// Caller identity
// ---------------------------------------------------------------------------

/// The caller's device, when its connection is device-attached.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct CallerDevice {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

/// Who is calling (`Docs/Devices/protocol.md` section 4), from
/// `context.hub.caller`. The hub replaces any client-supplied `context.hub`,
/// so handlers can trust it.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct Caller {
    /// Caller SPKI; `None` for anonymous callers.
    #[serde(default)]
    pub key: Option<String>,
    /// `None` unless the caller's connection is device-attached.
    #[serde(default)]
    pub device: Option<CallerDevice>,
    /// Groups of the key or its device.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Member of the owners group.
    #[serde(default)]
    pub owner: bool,
    /// Merged hub SPKI when the call came through a merged hub.
    #[serde(default)]
    pub via: Option<String>,
    /// The merged hub's own caller (unverified).
    #[serde(default)]
    pub claimed: Option<Value>,
    /// The forwarding hub's key (`context.hub.hubKey`).
    #[serde(skip)]
    pub hub_key: Option<String>,
}

impl Caller {
    /// The caller in a request context; `None` when it has no hub caller
    /// (hub-lite, or a call that didn't come through a hub).
    pub fn from_context(context: &Value) -> Option<Caller> {
        let hub = context.get("hub")?;
        let mut caller: Caller = serde_json::from_value(hub.get("caller")?.clone()).ok()?;
        caller.hub_key = hub.get("hubKey").and_then(Value::as_str).map(str::to_string);
        Some(caller)
    }
}

/// A request handed to [`Service::post_request`] and
/// [`Service::stream_request`] handlers.
#[derive(Debug, Clone)]
pub struct Request {
    pub body: Value,
    /// Who is calling; `None` when the call carries no hub caller.
    pub caller: Option<Caller>,
    /// The whole request context (`service`/`device` selection, `hub`).
    pub context: Value,
}

impl Request {
    pub fn new(body: Value, context: Value) -> Self {
        Self {
            body,
            caller: Caller::from_context(&context),
            context,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// `send`/`values` called before `start()`.
    NotStarted,
    /// The service thread went away (should not happen while running).
    Disconnected,
    /// The remote endpoint replied with an error.
    Remote(String),
    /// A channel-rs level failure.
    Channel(String),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::NotStarted => write!(f, "Service not started"),
            ServiceError::Disconnected => write!(f, "Service disconnected"),
            ServiceError::Remote(error) => write!(f, "remote error: {error}"),
            ServiceError::Channel(error) => write!(f, "channel error: {error}"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<ChannelError> for ServiceError {
    fn from(value: ChannelError) -> Self {
        ServiceError::Channel(value.to_string())
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

type PostHandler = Box<dyn Fn(Request) -> Result<Value, ChannelError> + Send + Sync>;
type StreamHandler = Box<dyn Fn(Request) -> Result<Vec<Value>, ChannelError> + Send + Sync>;

/// Requests routed from [`Service::send`]/[`Service::values`] to the poll
/// thread. Everything touching the channel-rs client happens on that one
/// thread (channel-rs is single-threaded per client).
enum Command {
    Send {
        path: String,
        body: Value,
        resp: mpsc::Sender<Result<CallResult<Value>, ChannelError>>,
    },
    Values {
        path: String,
        body: Value,
        resp: mpsc::Sender<Result<u64, ChannelError>>,
    },
    ValuesNext {
        id: u64,
        resp: mpsc::Sender<Result<StreamNext<Value>, ChannelError>>,
    },
    ValuesClose {
        id: u64,
    },
}

/// Registers API endpoints on a hub and serves calls forwarded by it.
///
/// Register handlers (post/stream/app) before calling [`Service::start`].
pub struct Service {
    address: Address,
    profile: Option<Profile>,
    sign: Option<Arc<dyn Fn() -> String + Send + Sync>>,
    keychain: Option<Arc<Keychain>>,
    instance: Option<String>,
    device_name: Option<String>,
    parent: Option<String>,
    device_key: Option<Arc<DeviceKey>>,
    apps: Vec<AppHeader>,
    paths: BTreeSet<String>,
    settings: HashMap<String, ApiSettings>,
    posts: Vec<(String, PostHandler)>,
    streams: Vec<(String, StreamHandler)>,
    app_interfaces: Vec<(String, Value)>,
    requests: OnceLock<mpsc::Sender<Command>>,
}

impl Service {
    /// Creates a Service. Options are optional.
    pub fn new(options: ServiceOptions) -> Self {
        let address = resolve_address(&options);
        let profile = if options.name.is_some() || options.icon.is_some() {
            Some(Profile {
                name: options.name,
                icon: options.icon,
            })
        } else {
            None
        };
        // Default auth source: the keychain `auth` file in the cwd (TS
        // parity), generated on first use. A custom `sign` factory replaces it.
        let keychain = match options.sign {
            Some(_) => None,
            None => Some(options.keychain.clone().unwrap_or_else(|| Arc::new(Keychain::new()))),
        };
        let device_key = match options.disable_device || !device_mode_enabled() {
            true => None,
            false => options.device_key.clone().or_else(|| DeviceKey::new().map(Arc::new)),
        };
        Self {
            address,
            sign: options.sign.clone(),
            keychain,
            instance: options.instance.clone(),
            device_name: options.device_name.clone(),
            parent: options.parent.clone(),
            device_key,
            profile,
            apps: Vec::new(),
            paths: BTreeSet::new(),
            settings: HashMap::new(),
            posts: Vec::new(),
            streams: Vec::new(),
            app_interfaces: Vec::new(),
            requests: OnceLock::new(),
        }
    }

    /// Registers a request/response API endpoint.
    pub fn post<F>(&mut self, path: impl Into<String>, handler: F) -> &mut Self
    where
        F: Fn(Value) -> Result<Value, ChannelError> + Send + Sync + 'static,
    {
        self.post_with_settings(path, handler, ApiSettings::default())
    }

    /// Registers a request/response API endpoint with wire-parity settings.
    pub fn post_with_settings<F>(
        &mut self,
        path: impl Into<String>,
        handler: F,
        settings: ApiSettings,
    ) -> &mut Self
    where
        F: Fn(Value) -> Result<Value, ChannelError> + Send + Sync + 'static,
    {
        self.post_request_with_settings(path, move |request| handler(request.body), settings)
    }

    /// Registers a request/response API endpoint whose handler also gets the
    /// caller and the request context.
    pub fn post_request<F>(&mut self, path: impl Into<String>, handler: F) -> &mut Self
    where
        F: Fn(Request) -> Result<Value, ChannelError> + Send + Sync + 'static,
    {
        self.post_request_with_settings(path, handler, ApiSettings::default())
    }

    /// [`Service::post_request`] with wire-parity settings.
    pub fn post_request_with_settings<F>(
        &mut self,
        path: impl Into<String>,
        handler: F,
        settings: ApiSettings,
    ) -> &mut Self
    where
        F: Fn(Request) -> Result<Value, ChannelError> + Send + Sync + 'static,
    {
        let path = path.into();
        self.add_path(&path, settings);
        self.posts.push((path, Box::new(handler)));
        self
    }

    /// Registers a streaming API endpoint. The handler receives the decoded
    /// body and returns the values to yield.
    pub fn stream<F>(&mut self, path: impl Into<String>, handler: F) -> &mut Self
    where
        F: Fn(Value) -> Result<Vec<Value>, ChannelError> + Send + Sync + 'static,
    {
        self.stream_with_settings(path, handler, ApiSettings::default())
    }

    /// Registers a streaming API endpoint with wire-parity settings.
    pub fn stream_with_settings<F>(
        &mut self,
        path: impl Into<String>,
        handler: F,
        settings: ApiSettings,
    ) -> &mut Self
    where
        F: Fn(Value) -> Result<Vec<Value>, ChannelError> + Send + Sync + 'static,
    {
        self.stream_request_with_settings(path, move |request| handler(request.body), settings)
    }

    /// Registers a streaming API endpoint whose handler also gets the caller
    /// and the request context.
    pub fn stream_request<F>(&mut self, path: impl Into<String>, handler: F) -> &mut Self
    where
        F: Fn(Request) -> Result<Vec<Value>, ChannelError> + Send + Sync + 'static,
    {
        self.stream_request_with_settings(path, handler, ApiSettings::default())
    }

    /// [`Service::stream_request`] with wire-parity settings.
    pub fn stream_request_with_settings<F>(
        &mut self,
        path: impl Into<String>,
        handler: F,
        settings: ApiSettings,
    ) -> &mut Self
    where
        F: Fn(Request) -> Result<Vec<Value>, ChannelError> + Send + Sync + 'static,
    {
        let path = path.into();
        self.add_path(&path, settings);
        self.streams.push((path, Box::new(handler)));
        self
    }

    /// Registers an app: its header goes to the hub apps list and its path
    /// serves the AppInterface as a stream (TS parity: the path is also
    /// callable and listed among the services).
    pub fn app(&mut self, app: App) -> &mut Self {
        let path = app.header.path.clone();
        let interface = app.interface();
        self.apps.push(app.header);
        self.add_path(&path, ApiSettings::default());
        self.app_interfaces.push((path, interface));
        self
    }

    /// The current `hub/service/update` payload (services sorted by path).
    pub fn update_payload(&self) -> ServiceUpdate {
        ServiceUpdate {
            services: self
                .paths
                .iter()
                .map(|path| ServiceHeader {
                    path: path.clone(),
                    permissions: self.settings.get(path).and_then(|s| s.permissions.clone()),
                    limit: self.settings.get(path).and_then(|s| s.limit),
                })
                .collect(),
            apps: self.apps.clone(),
        }
    }

    /// The instance name in the device certificate: the `instance` option,
    /// else `$HUB_INSTANCE`, else the profile name, else the basename of the
    /// working directory, else `service`.
    pub fn instance(&self) -> String {
        let name = self.profile.as_ref().and_then(|profile| profile.name.clone());
        let directory = env::current_dir()
            .ok()
            .and_then(|dir| dir.file_name().map(|name| name.to_string_lossy().into_owned()));
        [self.instance.clone(), env::var("HUB_INSTANCE").ok(), name, directory]
            .into_iter()
            .flatten()
            .find(|instance| !instance.is_empty())
            .unwrap_or_else(|| "service".to_string())
    }

    /// Forgets the hub key pinned for this service's address. Use it when a
    /// v1 connect keeps failing with `invalid signature` because the hub's
    /// key changed on purpose; the next connect learns it again.
    pub fn forget_hub_key(&self) -> Result<(), KeychainError> {
        match &self.keychain {
            Some(keychain) => keychain.forget_hub_key(&self.address.pin_address()),
            None => Ok(()),
        }
    }

    /// The profile sent as `hub/profile/update`, if name/icon were set.
    pub fn profile(&self) -> Option<&Profile> {
        self.profile.as_ref()
    }

    /// Connects to the hub and spawns the poll thread. On every (re)connect
    /// it sends `hub/profile/update` (if a profile is set) and
    /// `hub/service/update` with the current services+apps. Idempotent.
    pub fn start(&mut self) -> &mut Self {
        if self.requests.get().is_some() {
            return self;
        }
        let (tx, rx) = mpsc::channel();
        let certifier = self.device_key.as_ref().map(|device_key| {
            Certifier::new(
                device_key.clone(),
                &self.instance(),
                self.device_name.as_deref(),
                self.parent.as_deref(),
            )
        });
        let core = Core {
            certifier,
            address: self.address.clone(),
            profile: self.profile.take(),
            sign: self.sign.take(),
            keychain: self.keychain.clone(),
            hub_key_known: false,
            apps: std::mem::take(&mut self.apps),
            paths: std::mem::take(&mut self.paths),
            settings: std::mem::take(&mut self.settings),
            posts: std::mem::take(&mut self.posts),
            streams: std::mem::take(&mut self.streams),
            app_interfaces: std::mem::take(&mut self.app_interfaces),
            rx,
        };
        let _ = self.requests.set(tx);
        thread::spawn(move || core.run());
        self
    }

    /// Calls an API through the hub. Errors if the service is not started.
    pub fn send(&self, path: &str, body: Value) -> Result<Value, ServiceError> {
        let tx = self.requests.get().ok_or(ServiceError::NotStarted)?;
        let (rtx, rrx) = mpsc::channel();
        tx.send(Command::Send {
            path: path.to_string(),
            body,
            resp: rtx,
        })
        .map_err(|_| ServiceError::Disconnected)?;
        match rrx.recv().map_err(|_| ServiceError::Disconnected)?? {
            CallResult::Ok(Some(value)) => Ok(value),
            CallResult::Ok(None) => Ok(Value::Null),
            CallResult::RemoteErr(error) => Err(ServiceError::Remote(error)),
        }
    }

    /// Opens a stream call through the hub. Errors if not started.
    pub fn values(&self, path: &str, body: Value) -> Result<ServiceValues, ServiceError> {
        let tx = self.requests.get().ok_or(ServiceError::NotStarted)?;
        let (rtx, rrx) = mpsc::channel();
        tx.send(Command::Values {
            path: path.to_string(),
            body,
            resp: rtx,
        })
        .map_err(|_| ServiceError::Disconnected)?;
        let id = rrx.recv().map_err(|_| ServiceError::Disconnected)??;
        Ok(ServiceValues {
            id,
            tx: tx.clone(),
            done: false,
        })
    }

    fn add_path(&mut self, path: &str, mut settings: ApiSettings) {
        self.paths.insert(path.to_string());
        if let Some(permissions) = settings.permissions.as_mut() {
            if permissions.group.is_empty() {
                permissions.group = path.split('/').next().unwrap_or_default().to_string();
            }
        }
        self.settings.insert(path.to_string(), settings);
    }
}

/// A client-side stream call through the hub. Iterate with [`next`]
/// (`None` = stream ended).
///
/// [`next`]: ServiceValues::next
pub struct ServiceValues {
    id: u64,
    tx: mpsc::Sender<Command>,
    done: bool,
}

impl ServiceValues {
    /// Waits for the next stream value; `Ok(None)` when the stream ends.
    pub fn next(&mut self) -> Result<Option<Value>, ServiceError> {
        if self.done {
            return Ok(None);
        }
        let (rtx, rrx) = mpsc::channel();
        self.tx
            .send(Command::ValuesNext {
                id: self.id,
                resp: rtx,
            })
            .map_err(|_| ServiceError::Disconnected)?;
        match rrx.recv().map_err(|_| ServiceError::Disconnected)?? {
            StreamNext::Item(value) => Ok(Some(value)),
            StreamNext::Done => {
                self.done = true;
                Ok(None)
            }
            StreamNext::RemoteErr(error) => Err(ServiceError::Remote(error)),
        }
    }
}

impl Drop for ServiceValues {
    fn drop(&mut self) {
        let _ = self.tx.send(Command::ValuesClose { id: self.id });
    }
}

// ---------------------------------------------------------------------------
// Poll thread
// ---------------------------------------------------------------------------

struct Core {
    address: Address,
    profile: Option<Profile>,
    sign: Option<Arc<dyn Fn() -> String + Send + Sync>>,
    keychain: Option<Arc<Keychain>>,
    /// The current connection used a pinned hub key (v1).
    hub_key_known: bool,
    /// Issues the `device` header; `None` when device mode is off.
    certifier: Option<Certifier>,
    apps: Vec<AppHeader>,
    paths: BTreeSet<String>,
    settings: HashMap<String, ApiSettings>,
    posts: Vec<(String, PostHandler)>,
    streams: Vec<(String, StreamHandler)>,
    app_interfaces: Vec<(String, Value)>,
    rx: mpsc::Receiver<Command>,
}

impl Core {
    fn build_update(&self) -> ServiceUpdate {
        ServiceUpdate {
            services: self
                .paths
                .iter()
                .map(|path| ServiceHeader {
                    path: path.clone(),
                    permissions: self.settings.get(path).and_then(|s| s.permissions.clone()),
                    limit: self.settings.get(path).and_then(|s| s.limit),
                })
                .collect(),
            apps: self.apps.clone(),
        }
    }

    /// The service loop: owns the Channel, the Client and every `Values`
    /// handle; reconnects forever, re-announcing the profile + service update
    /// on each fresh connection.
    fn run(mut self) {
        let mut channel = Channel::new();

        for (path, handler) in self.posts.drain(..) {
            channel
                .post::<Value, Value, Value, _>(path, move |request| {
                    handler(Request::new(request.body, request.context)).map(Some)
                })
                .expect("register post handler");
        }
        for (path, handler) in self.streams.drain(..) {
            channel
                .stream::<Value, Value, Value, _>(path, move |request| {
                    let mut emitter = request.emitter;
                    for item in handler(Request::new(request.body, request.context))? {
                        emitter.emit(item)?;
                    }
                    Ok(())
                })
                .expect("register stream handler");
        }
        for (path, interface) in self.app_interfaces.drain(..) {
            channel
                .stream::<(), Value, (), _>(path, move |mut request| {
                    request.emitter.emit(interface.clone())?;
                    Ok(())
                })
                .expect("register app stream");
        }

        let mut client: Option<Client<()>> = None;
        let mut connected = false;
        let mut values: Vec<(u64, Values<Value>)> = Vec::new();
        let mut next_values_id: u64 = 0;

        loop {
            // Serve client calls (send / values) on this thread.
            while let Ok(command) = self.rx.try_recv() {
                match command {
                    Command::Send { path, body, resp } => {
                        let result = match client.as_mut() {
                            Some(client) => client.sender().send::<Value, Value>(&path, body),
                            None => Err(ChannelError::new("not connected")),
                        };
                        let _ = resp.send(result);
                    }
                    Command::Values { path, body, resp } => {
                        let result = match client.as_mut() {
                            Some(client) => {
                                client.sender().values::<Value, Value, ()>(&path, body, ())
                            }
                            None => Err(ChannelError::new("not connected")),
                        };
                        let _ = resp.send(result.map(|stream| {
                            let id = next_values_id;
                            next_values_id += 1;
                            values.push((id, stream));
                            id
                        }));
                    }
                    Command::ValuesNext { id, resp } => {
                        let result = match values.iter_mut().find(|(i, _)| *i == id) {
                            Some((_, stream)) => stream.next(),
                            None => Ok(StreamNext::Done),
                        };
                        let _ = resp.send(result);
                    }
                    Command::ValuesClose { id } => {
                        if let Some(index) = values.iter().position(|(i, _)| *i == id) {
                            let (_, mut stream) = values.remove(index);
                            stream.close();
                        }
                    }
                }
            }

            // Connection maintenance: poll, detect the is_connected
            // false->true transition per connection, send the updates.
            let mut dropped = false;
            if let Some(c) = client.as_mut() {
                let _ = c.poll();
                if c.is_connected() {
                    if !connected {
                        self.send_updates(c);
                        connected = true;
                        if !self.hub_key_known && self.learn_hub_key(c) {
                            // Reconnect at once with the hub-bound v1 token.
                            client = None;
                            values.clear();
                            connected = false;
                            continue;
                        }
                    }
                } else {
                    dropped = true;
                }
            }
            if dropped {
                client = None;
                values.clear();
                connected = false;
                thread::sleep(RECONNECT_DELAY);
                continue;
            }
            if client.is_none() {
                // Fresh hub-pro auth token per connect (expiry changes): the
                // raw header block is attached to the HTTP upgrade request.
                let headers = self.connect_headers();
                let options = ConnectOptions {
                    headers,
                    ..ConnectOptions::default()
                };
                let result = match &self.address {
                    Address::Port(port) => channel.connect(*port, options),
                    Address::Url(url) => channel.connect(url.clone(), options),
                };
                match result {
                    Ok(c) => {
                        client = Some(c);
                        connected = false;
                    }
                    Err(_) => thread::sleep(RECONNECT_DELAY),
                }
            }
            thread::sleep(POLL_SLEEP);
        }
    }

    /// The handshake header block for the next connect: a v1 token when a
    /// hub key is pinned for the address, else v0.
    fn connect_headers(&mut self) -> Option<String> {
        if let Some(sign) = &self.sign {
            let token = sign();
            return (!token.is_empty()).then(|| auth_header_block(&token));
        }
        let keychain = self.keychain.as_ref()?;
        let hub_key = keychain.hub_key(&self.address.pin_address());
        self.hub_key_known = hub_key.is_some();
        // A keychain failure logs and connects without auth headers rather
        // than killing the service thread.
        let token = match keychain.sign_for_hub(hub_key.as_deref(), AUTH_EXPIRY) {
            Ok(token) => token,
            Err(error) => {
                eprintln!("hub-service-rs: keychain error: {error}");
                return None;
            }
        };
        // A device key that can't be read or created leaves a plain key
        // connection.
        let device = match (&mut self.certifier, keychain.public_key(), keychain::now_seconds()) {
            (Some(certifier), Ok(service_key), Ok(now)) => match certifier.header(&service_key, now) {
                Ok(header) => Some(header),
                Err(error) => {
                    eprintln!("hub-service-rs: device certificate error: {error}");
                    None
                }
            },
            _ => None,
        };
        Some(connect_header_block(
            &token,
            if hub_key.is_some() { 1 } else { 0 },
            device.as_deref(),
        ))
    }

    /// Asks `hub/info` for the hub key and pins it. True when a key was
    /// pinned (the caller reconnects with v1); hub-lite answers with an error.
    fn learn_hub_key(&self, client: &mut Client<()>) -> bool {
        let Some(keychain) = &self.keychain else {
            return false;
        };
        let Ok(CallResult::Ok(Some(info))) = client.sender().send::<Value, ()>("hub/info", ()) else {
            return false;
        };
        match info.get("key").and_then(Value::as_str) {
            Some(key) if !key.is_empty() => keychain.pin_hub_key(&self.address.pin_address(), key).is_ok(),
            _ => false,
        }
    }

    fn send_updates(&self, client: &mut Client<()>) {
        let sender = client.sender();
        if let Some(profile) = &self.profile {
            let _ = sender.request::<Value, Profile>("hub/profile/update", profile.clone());
        }
        let _ = sender.request::<Value, ServiceUpdate>("hub/service/update", self.build_update());
    }
}
