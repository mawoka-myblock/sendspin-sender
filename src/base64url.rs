//! Unpadded base64url helpers, as used throughout the Sendspin wire format.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub fn encode(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data.as_ref())
}

pub fn decode(text: &str) -> anyhow::Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(text)?)
}

pub fn decode_32(text: &str) -> anyhow::Result<[u8; 32]> {
    let raw = decode(text)?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", raw.len()))?;
    Ok(arr)
}
