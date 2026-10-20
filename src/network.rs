//! Hub Network share publishing (TS hub-service/network.ts parity): make a
//! local TCP/UDP port reachable through Hub Network.
//!
//! For each share the service asks the local hub-net agent (HTTP over its
//! Unix socket) for a challenge, signs the nonce with the service key, gets
//! an attestation of the local target, and sends the whole declared set to
//! the hub with `network/shares/replace`. Attestations are forwarded
//! verbatim; the hub answers with one publication per share, in request
//! order. Declared shares are published again on every (re)connect.

use crate::keychain::{Keychain, KeychainError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const WIRE_VERSION: u64 = 1;
const MAX_SHARE_NAME_LENGTH: usize = 255;

/// `tcp` or `udp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Who may reach a share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum NetworkPolicy {
    /// Every member of the hub's network.
    Hub,
    Group {
        group: String,
    },
    Keys {
        keys: Vec<String>,
    },
    /// Owners only (the default).
    Private,
    Disabled,
}

/// The local listener behind a share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalTarget {
    pub host: String,
    pub port: u16,
}

/// A share: a stable name for a local TCP/UDP port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkShare {
    pub name: String,
    pub protocol: Protocol,
    pub target: LocalTarget,
    pub policy: NetworkPolicy,
}

impl NetworkShare {
    /// A share with the default (private) policy.
    pub fn new(
        name: impl Into<String>,
        protocol: Protocol,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            name: name.into(),
            protocol,
            target: LocalTarget {
                host: host.into(),
                port,
            },
            policy: NetworkPolicy::Private,
        }
    }

    pub fn policy(mut self, policy: NetworkPolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// Where the hub published a share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharePublication {
    pub version: u64,
    pub resource_id: String,
    pub authority: String,
    pub provider_id: String,
    pub protocol: Protocol,
    pub overlay_address: String,
    pub port: u16,
}

/// The default hub-net agent socket.
pub fn default_agent_socket() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/var/run/hub-net/agent.sock")
    } else {
        PathBuf::from("/run/hub-net/agent.sock")
    }
}

/// Non-empty after trimming, no control characters.
fn valid_text(text: &str) -> bool {
    !text.trim().is_empty() && !text.chars().any(|c| c < '\u{20}' || c == '\u{7f}')
}

fn validate_share(share: &NetworkShare) -> Result<(), String> {
    if !valid_text(&share.name) || share.name.chars().count() > MAX_SHARE_NAME_LENGTH {
        return Err("Invalid Hub Network share name".into());
    }
    if !valid_text(&share.target.host) {
        return Err("Invalid Hub Network target host".into());
    }
    if share.target.port == 0 {
        return Err("Invalid Hub Network target port".into());
    }
    let policy_ok = match &share.policy {
        NetworkPolicy::Group { group } => valid_text(group),
        NetworkPolicy::Keys { keys } => !keys.is_empty() && keys.iter().all(|key| valid_text(key)),
        _ => true,
    };
    if !policy_ok {
        return Err("Invalid Hub Network policy".into());
    }
    Ok(())
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// RFC 3339 time (`2026-10-20T20:12:00.5Z`, `...+03:00`) to Unix milliseconds.
pub fn parse_iso_ms(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = &text[19..];
    let mut ms = 0;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let padded = format!("{:0<3}", &fraction[..digits.min(3)]);
        ms = padded.parse::<i64>().ok()?;
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6 && rest.as_bytes()[3] == b':' => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            sign * (rest[1..3].parse::<i64>().ok()? * 3600 + rest[4..6].parse::<i64>().ok()? * 60)
        }
        _ => return None,
    };
    let seconds =
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    Some(seconds * 1000 + ms)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

/// The declared shares and their publications.
pub(crate) struct NetworkPublisher {
    shares: BTreeMap<String, NetworkShare>,
    publications: Vec<SharePublication>,
    socket: PathBuf,
    timeout: Duration,
}

impl NetworkPublisher {
    pub(crate) fn new(socket: Option<PathBuf>) -> Self {
        Self {
            shares: BTreeMap::new(),
            publications: Vec::new(),
            socket: socket.unwrap_or_else(default_agent_socket),
            timeout: Duration::from_secs(5),
        }
    }

    pub(crate) fn has_shares(&self) -> bool {
        !self.shares.is_empty()
    }

    pub(crate) fn publications(&self) -> Vec<SharePublication> {
        self.publications.clone()
    }

    pub(crate) fn declare(&mut self, share: NetworkShare) -> Result<(), String> {
        validate_share(&share)?;
        self.shares.insert(share.name.clone(), share);
        Ok(())
    }

    /// Publishes `share` with the rest of the set; on failure the set is
    /// left as it was.
    pub(crate) fn publish(
        &mut self,
        share: NetworkShare,
        keychain: &Keychain,
        send: &mut dyn FnMut(Value) -> Result<Value, String>,
    ) -> Result<Vec<SharePublication>, String> {
        validate_share(&share)?;
        let previous = self.shares.insert(share.name.clone(), share.clone());
        let result = self.synchronize(keychain, send);
        if result.is_err() {
            match previous {
                Some(previous) => self.shares.insert(share.name.clone(), previous),
                None => self.shares.remove(&share.name),
            };
        }
        result
    }

    pub(crate) fn remove(
        &mut self,
        name: &str,
        keychain: &Keychain,
        send: &mut dyn FnMut(Value) -> Result<Value, String>,
    ) -> Result<Vec<SharePublication>, String> {
        let removed = self
            .shares
            .remove(name)
            .ok_or_else(|| format!("Share '{name}' not found"))?;
        let result = self.synchronize(keychain, send);
        if result.is_err() {
            self.shares.insert(name.to_string(), removed);
        }
        result
    }

    /// Attests every declared share and sends the set with
    /// `network/shares/replace`.
    pub(crate) fn synchronize(
        &mut self,
        keychain: &Keychain,
        send: &mut dyn FnMut(Value) -> Result<Value, String>,
    ) -> Result<Vec<SharePublication>, String> {
        let service_key = keychain.public_key().map_err(|error| error.to_string())?;
        let shares: Vec<NetworkShare> = self.shares.values().cloned().collect();
        let mut wire = Vec::with_capacity(shares.len());
        for share in &shares {
            let attestation = self.attest(share, &service_key, keychain)?;
            let mut entry = serde_json::to_value(share).map_err(|error| error.to_string())?;
            entry["version"] = json!(WIRE_VERSION);
            // Forwarded verbatim: the agent signed it.
            entry["attestation"] = attestation;
            wire.push(entry);
        }
        let reply = send(json!({ "shares": wire }))?;
        let publications = reply
            .get("shares")
            .and_then(Value::as_array)
            .ok_or("Hub returned an invalid shares/replace response")?;
        if publications.len() != shares.len() {
            return Err(format!(
                "Hub returned {} publications for {} shares",
                publications.len(),
                shares.len()
            ));
        }
        // v1 publications carry no share name: the hub keeps request order.
        let mut resource_ids = HashSet::new();
        let mut checked = Vec::with_capacity(shares.len());
        for (index, (share, publication)) in shares.iter().zip(publications).enumerate() {
            let publication = check_publication(publication, share, index)?;
            if !resource_ids.insert(publication.resource_id.clone()) {
                return Err(format!(
                    "Hub returned duplicate resourceId at share index {index}"
                ));
            }
            checked.push(publication);
        }
        self.publications = checked.clone();
        Ok(checked)
    }

    /// Challenge, sign, attest.
    fn attest(
        &self,
        share: &NetworkShare,
        service_key: &str,
        keychain: &Keychain,
    ) -> Result<Value, String> {
        let mut request = json!({
            "serviceKey": service_key,
            "shareName": share.name,
            "protocol": share.protocol,
            "target": share.target,
        });
        let challenge = self.agent_json("/challenge", &request, "challenge")?;
        let nonce = challenge
            .get("nonce")
            .and_then(Value::as_str)
            .filter(|nonce| !nonce.is_empty())
            .ok_or("Hub Network agent returned an invalid challenge")?;
        let signature = keychain
            .data()
            .map_err(|error: KeychainError| error.to_string())?
            .sign(nonce);
        request["signature"] = json!(signature);
        let attestation = self.agent_json("/attest", &request, "attestation")?;
        check_attestation(&attestation, share, service_key)?;
        Ok(attestation)
    }

    /// POSTs JSON to the agent and parses a JSON object reply.
    fn agent_json(&self, path: &str, body: &Value, operation: &str) -> Result<Value, String> {
        let unavailable = |_| {
            format!(
                "Hub Network agent is unavailable at {}",
                self.socket.display()
            )
        };
        let mut stream = UnixStream::connect(&self.socket).map_err(unavailable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(unavailable)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(unavailable)?;
        let body = body.to_string();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).map_err(unavailable)?;
        let mut response = Vec::new();
        if let Err(error) = stream.read_to_end(&mut response) {
            return Err(match error.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => format!(
                    "Hub Network agent timed out after {} ms",
                    self.timeout.as_millis()
                ),
                _ => format!(
                    "Hub Network agent is unavailable at {}",
                    self.socket.display()
                ),
            });
        }
        let invalid = || "Hub Network agent returned an invalid response".to_string();
        let split = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(invalid)?;
        let head = String::from_utf8_lossy(&response[..split]).to_string();
        let mut body = response[split + 4..].to_vec();
        let status: u16 = head
            .split(' ')
            .nth(1)
            .and_then(|status| status.parse().ok())
            .ok_or_else(invalid)?;
        let chunked = head.lines().any(|line| {
            let line = line.to_ascii_lowercase();
            line.starts_with("transfer-encoding:") && line.contains("chunked")
        });
        if chunked {
            body = dechunk(&body);
        }
        let text = String::from_utf8_lossy(&body).trim().to_string();
        if !(200..300).contains(&status) {
            let detail = if text.is_empty() {
                String::new()
            } else {
                format!(": {text}")
            };
            return Err(format!(
                "Hub Network agent rejected {operation} ({status}){detail}"
            ));
        }
        match serde_json::from_str::<Value>(&text) {
            Ok(value) if value.is_object() => Ok(value),
            _ => Err("Hub Network agent returned invalid JSON".into()),
        }
    }
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(line_end) = rest.windows(2).position(|window| window == b"\r\n") {
        let size = std::str::from_utf8(&rest[..line_end])
            .ok()
            .and_then(|line| usize::from_str_radix(line.split(';').next()?.trim(), 16).ok());
        let Some(size) = size.filter(|&size| size > 0) else {
            break;
        };
        let start = line_end + 2;
        if start + size > rest.len() {
            break;
        }
        out.extend_from_slice(&rest[start..start + size]);
        rest = &rest[(start + size + 2).min(rest.len())..];
    }
    out
}

fn check_attestation(
    attestation: &Value,
    share: &NetworkShare,
    service_key: &str,
) -> Result<(), String> {
    let text = |field: &str| attestation.get(field).and_then(Value::as_str);
    let target = attestation.get("target");
    let matches = attestation.get("version").and_then(Value::as_u64) == Some(WIRE_VERSION)
        && text("serviceKey") == Some(service_key)
        && text("shareName") == Some(share.name.as_str())
        && attestation.get("protocol") == Some(&json!(share.protocol))
        && target
            .and_then(|target| target.get("host"))
            .and_then(Value::as_str)
            == Some(share.target.host.as_str())
        && target
            .and_then(|target| target.get("port"))
            .and_then(Value::as_u64)
            == Some(share.target.port as u64);
    if !matches {
        return Err("Local-agent attestation does not match the share".into());
    }
    let issued = text("issuedAt").and_then(parse_iso_ms);
    let expires = text("expiresAt").and_then(parse_iso_ms);
    let now = now_ms();
    match (issued, expires) {
        (Some(issued), Some(expires))
            if expires > issued && issued <= now + 30_000 && expires > now =>
        {
            Ok(())
        }
        _ => Err("Local-agent attestation is expired".into()),
    }
}

fn check_publication(
    value: &Value,
    share: &NetworkShare,
    index: usize,
) -> Result<SharePublication, String> {
    if value.get("version").and_then(Value::as_u64) != Some(WIRE_VERSION) {
        return Err(format!(
            "Invalid Hub publication version at share index {index}"
        ));
    }
    let resource = value
        .get("resourceId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !resource.starts_with("hnr1_") || resource.len() == 5 {
        return Err(format!(
            "Invalid Hub publication resourceId at share index {index}"
        ));
    }
    for field in ["authority", "providerId", "overlayAddress"] {
        if !value
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(valid_text)
        {
            return Err(format!(
                "Invalid Hub publication {field} at share index {index}"
            ));
        }
    }
    if value.get("protocol") != Some(&json!(share.protocol)) {
        return Err(format!(
            "Hub publication protocol mismatch at share index {index}"
        ));
    }
    if !value
        .get("port")
        .and_then(Value::as_u64)
        .is_some_and(|port| (1..=65_535).contains(&port))
    {
        return Err(format!(
            "Invalid Hub publication port at share index {index}"
        ));
    }
    serde_json::from_value(value.clone())
        .map_err(|_| format!("Invalid Hub publication at share index {index}"))
}
