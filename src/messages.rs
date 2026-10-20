//! Typed construction and parsing of the core JSON messages.

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::codec::payload_of;

pub const PROTOCOL_VERSION: u64 = 1;
pub const SUITE: &str = "25519_ChaChaPoly_SHA256";

/// Render a `{type, payload}` envelope as a JSON text message.
pub fn envelope(message_type: &str, payload: Value) -> String {
    json!({ "type": message_type, "payload": payload }).to_string()
}

// ---- outgoing messages ----------------------------------------------------

pub fn client_init(client_id: &str) -> String {
    envelope(
        "client/init",
        json!({ "client_id": client_id, "version": PROTOCOL_VERSION, "suite": SUITE }),
    )
}

/// `client/hello` advertising the source role and the Pairing PSK method.
pub fn client_hello(
    name: &str,
    software_version: &str,
    line_sense: bool,
    mac_address: Option<&str>,
) -> String {
    let mut device_info = json!({
        "product_name": "Sendspin Sender",
        "manufacturer": "sendspin-sender",
        "software_version": software_version,
    });
    if let Some(mac) = mac_address {
        device_info["mac_address"] = json!(mac);
    }

    let mut source_support = json!({});
    if line_sense {
        source_support["features"] = json!({ "line_sense": true });
    }

    envelope(
        "client/hello",
        json!({
            "name": name,
            "device_info": device_info,
            "supported_roles": ["source@v1"],
            "source@v1_support": source_support,
            "supported_pair_methods": {
                "pairing_psk": { "locations": ["device", "operator"] },
            },
            "unpaired_access": { "enabled": false },
        }),
    )
}

pub fn client_time(client_transmitted: i64) -> String {
    envelope(
        "client/time",
        json!({ "client_transmitted": client_transmitted }),
    )
}

/// `client/state` with the client-level `available` flag and the source object.
pub fn client_state(available: bool, signal: Option<&str>) -> String {
    let mut payload = json!({ "available": available });
    if let Some(signal) = signal {
        payload["source"] = json!({ "signal": signal });
    }
    envelope("client/state", payload)
}

pub fn client_stream_start(codec: &str, channels: u32, sample_rate: u32, bit_depth: u32) -> String {
    envelope(
        "client-stream/start",
        json!({
            "source": {
                "codec": codec,
                "channels": channels,
                "sample_rate": sample_rate,
                "bit_depth": bit_depth,
            }
        }),
    )
}

pub fn client_stream_end() -> String {
    envelope("client-stream/end", json!({}))
}

pub fn client_goodbye(reason: &str) -> String {
    envelope("client/goodbye", json!({ "reason": reason }))
}

pub fn pair_init(pairing_index: u64) -> String {
    envelope(
        "client/pair-init",
        json!({ "pairing_index": pairing_index }),
    )
}

pub fn pair_finalize(long_term_psk: &str) -> String {
    envelope(
        "client/pair-finalize",
        json!({ "long_term_psk": long_term_psk }),
    )
}

pub fn pair_abort(reason: &str) -> String {
    envelope("pair/abort", json!({ "reason": reason }))
}

// ---- incoming messages ----------------------------------------------------

/// The cleartext `server/init` reply.
pub struct ServerInit {
    pub server_id: String,
    pub version: u64,
}

pub fn parse_server_init(text: &str) -> Result<ServerInit> {
    let (message_type, payload) = payload_of(text)?;
    if message_type != "server/init" {
        bail!("expected server/init, got {message_type}");
    }
    Ok(ServerInit {
        server_id: field_str(&payload, "server_id")?,
        version: payload.get("version").and_then(Value::as_u64).unwrap_or(0),
    })
}

/// The `server/error` reply that replaces `server/init` on rejection.
pub struct ServerError {
    pub reason: String,
}

pub fn parse_server_error(text: &str) -> Result<ServerError> {
    let (message_type, payload) = payload_of(text)?;
    if message_type != "server/error" {
        bail!("expected server/error, got {message_type}");
    }
    Ok(ServerError {
        reason: payload
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("malformed")
            .to_string(),
    })
}

pub struct ServerHello {
    pub name: String,
    pub source_codecs: Vec<String>,
}

pub fn parse_server_hello(payload: &Value) -> Result<ServerHello> {
    let name = payload
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("Sendspin server")
        .to_string();
    let source_codecs = payload
        .get("source@v1_support")
        .and_then(|support| support.get("supported_codecs"))
        .and_then(Value::as_array)
        .map(|codecs| {
            codecs
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(ServerHello {
        name,
        source_codecs,
    })
}

/// The parameters of a `server/activate`.
pub struct ServerActivate {
    pub activities: Vec<String>,
    pub active_roles: Option<Vec<String>>,
    pub pairing_method: Option<String>,
    pub pairing_format: Option<String>,
}

pub fn parse_server_activate(payload: &Value) -> Result<ServerActivate> {
    let activities = payload
        .get("activities")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let active_roles = payload
        .get("active_roles")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        });
    let pairing = payload.get("pairing");
    Ok(ServerActivate {
        activities,
        active_roles,
        pairing_method: pairing
            .and_then(|value| value.get("method"))
            .and_then(Value::as_str)
            .map(str::to_string),
        pairing_format: pairing
            .and_then(|value| value.get("format"))
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// A `server/command` with its optional source sub-object.
pub struct ServerCommand {
    pub source_command: Option<String>,
}

pub fn parse_server_command(payload: &Value) -> Result<ServerCommand> {
    Ok(ServerCommand {
        source_command: payload
            .get("source")
            .and_then(|source| source.get("command"))
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// A `server/time` JSON payload.
pub struct ServerTimePayload {
    pub client_transmitted: i64,
    pub server_received: i64,
    pub server_transmitted: i64,
}

pub fn parse_server_time_json(payload: &Value) -> Result<ServerTimePayload> {
    Ok(ServerTimePayload {
        client_transmitted: field_i64(payload, "client_transmitted")?,
        server_received: field_i64(payload, "server_received")?,
        server_transmitted: field_i64(payload, "server_transmitted")?,
    })
}

/// The `pair/abort` a server sends when it ends a pairing attempt.
pub fn parse_pair_abort(payload: &Value) -> Option<String> {
    payload
        .get("reason")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn field_str(payload: &Value, key: &str) -> Result<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("payload is missing the string field {key}"))
}

fn field_i64(payload: &Value, key: &str) -> Result<i64> {
    payload
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow::anyhow!("payload is missing the integer field {key}"))
}
