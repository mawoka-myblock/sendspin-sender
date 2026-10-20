//! Small byte-cursor helpers shared by the binary message parsers.

use anyhow::{bail, Result};

/// Parse a `type`/`payload` JSON envelope into its payload value.
pub fn payload_of(text: &str) -> Result<(String, serde_json::Value)> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    let message_type = value
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("message is missing its type"))?
        .to_string();
    let payload = value
        .get("payload")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("message {message_type} is missing its payload"))?;
    if !payload.is_object() {
        bail!("message {message_type} payload is not an object");
    }
    Ok((message_type, payload))
}
