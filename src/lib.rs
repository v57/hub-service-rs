//! hub-service-rs — Rust port of [hub-service](https://github.com/v57/hub-service).
//!
//! Connect to a hub (hub-lite / hub-pro), host post/stream API endpoints,
//! register apps, and call API through the hub.
//!
//! Lite port: no auth, no keychain, no crypto. The wire contract matches the
//! TS reference: `hub/profile/update`, `hub/service/update` on every
//! (re)connect, AppInterface + element DSL.

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fmt;
use std::sync::mpsc;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

pub use channel_rs::*;

const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const POLL_SLEEP: Duration = Duration::from_millis(1);

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
#[derive(Debug, Clone, Default)]
pub struct ServiceOptions {
    /// Port (u16) or `ws://` URL. Default: `1997`, or `$HUB` when set.
    pub address: Option<Address>,
    /// Profile name shown in the hub.
    pub name: Option<String>,
    /// Profile icon: a string or `{"symbol": ..., "text": ...}`.
    pub icon: Option<Value>,
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

type PostHandler = Box<dyn Fn(Value) -> Result<Value, ChannelError> + Send + Sync>;
type StreamHandler = Box<dyn Fn(Value) -> Result<Vec<Value>, ChannelError> + Send + Sync>;

/// Requests routed from [`Service::send`]/[`Service::values`] to the poll
/// thread. Everything touching the channel-rs client happens on that one
/// thread (channel-rs is single-threaded per client).
enum Request {
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
    apps: Vec<AppHeader>,
    paths: BTreeSet<String>,
    settings: HashMap<String, ApiSettings>,
    posts: Vec<(String, PostHandler)>,
    streams: Vec<(String, StreamHandler)>,
    app_interfaces: Vec<(String, Value)>,
    requests: OnceLock<mpsc::Sender<Request>>,
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
        Self {
            address,
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
        let core = Core {
            address: self.address.clone(),
            profile: self.profile.take(),
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
        tx.send(Request::Send {
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
        tx.send(Request::Values {
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
    tx: mpsc::Sender<Request>,
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
            .send(Request::ValuesNext {
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
        let _ = self.tx.send(Request::ValuesClose { id: self.id });
    }
}

// ---------------------------------------------------------------------------
// Poll thread
// ---------------------------------------------------------------------------

struct Core {
    address: Address,
    profile: Option<Profile>,
    apps: Vec<AppHeader>,
    paths: BTreeSet<String>,
    settings: HashMap<String, ApiSettings>,
    posts: Vec<(String, PostHandler)>,
    streams: Vec<(String, StreamHandler)>,
    app_interfaces: Vec<(String, Value)>,
    rx: mpsc::Receiver<Request>,
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
                .post::<Value, Value, (), _>(path, move |request| handler(request.body).map(Some))
                .expect("register post handler");
        }
        for (path, handler) in self.streams.drain(..) {
            channel
                .stream::<Value, Value, (), _>(path, move |request| {
                    let mut emitter = request.emitter;
                    for item in handler(request.body)? {
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
            while let Ok(request) = self.rx.try_recv() {
                match request {
                    Request::Send { path, body, resp } => {
                        let result = match client.as_mut() {
                            Some(client) => client.sender().send::<Value, Value>(&path, body),
                            None => Err(ChannelError::new("not connected")),
                        };
                        let _ = resp.send(result);
                    }
                    Request::Values { path, body, resp } => {
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
                    Request::ValuesNext { id, resp } => {
                        let result = match values.iter_mut().find(|(i, _)| *i == id) {
                            Some((_, stream)) => stream.next(),
                            None => Ok(StreamNext::Done),
                        };
                        let _ = resp.send(result);
                    }
                    Request::ValuesClose { id } => {
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
                let result = match &self.address {
                    Address::Port(port) => channel.connect(*port, ConnectOptions::default()),
                    Address::Url(url) => channel.connect(url.clone(), ConnectOptions::default()),
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

    fn send_updates(&self, client: &mut Client<()>) {
        let sender = client.sender();
        if let Some(profile) = &self.profile {
            let _ = sender.request::<Value, Profile>("hub/profile/update", profile.clone());
        }
        let _ = sender.request::<Value, ServiceUpdate>("hub/service/update", self.build_update());
    }
}
