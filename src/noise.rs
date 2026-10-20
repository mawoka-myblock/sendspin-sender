//! Noise KKpsk2 handshake and encrypted transport, per the Sendspin specification.
//!
//! The server is always the Noise **initiator**, the client the **responder**. The PSK
//! lands at location 2, which is mixed *after* message 1, so the responder can read
//! `psk_id`/`psk_category` from message 1 before choosing which PSK to mix in.

use anyhow::{Context, Result};
use snow::{params::NoiseParams, Builder, HandshakeState};

use crate::base64url;

pub const HANDSHAKE_TYPE: &str = "noise/handshake";
const MAX_MESSAGE: usize = 65535;

/// The PSK categories a handshake can be keyed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PskCategory {
    LongTerm,
    Pairing,
    Sentinel,
}

impl PskCategory {
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "lt" | "long_term" => Some(Self::LongTerm),
            "pr" | "pairing" => Some(Self::Pairing),
            "sn" | "sentinel" => Some(Self::Sentinel),
            _ => None,
        }
    }

    pub fn as_code(self) -> &'static str {
        match self {
            Self::LongTerm => "lt",
            Self::Pairing => "pr",
            Self::Sentinel => "sn",
        }
    }
}

pub fn noise_params() -> Result<NoiseParams> {
    "Noise_KKpsk2_25519_ChaChaPoly_SHA256"
        .parse()
        .context("parsing the Sendspin Noise parameters")
}

/// The `psk_id` / `psk_category` payload carried in cleartext inside Noise message 1.
#[derive(serde::Deserialize)]
pub struct Msg1Payload {
    pub psk_id: String,
    pub psk_category: String,
}

/// A resolved handshake candidate: the PSK bytes and the category it was matched under.
#[derive(Clone)]
pub struct Candidate {
    pub psk_id: String,
    pub psk: Vec<u8>,
    pub category: PskCategory,
}

impl Candidate {
    /// A human-readable summary for logs.
    pub fn describe(&self) -> String {
        format!("{} ({})", self.psk_id, self.category.as_code())
    }
}

/// Read Noise message 1 as the responder and return the cleartext payload it carries.
/// The returned state still needs `set_psk` before it can produce message 2.
pub fn read_message_1(handshake: &mut HandshakeState, message: &[u8]) -> Result<Msg1Payload> {
    let mut buf = vec![0u8; MAX_MESSAGE];
    let len = handshake
        .read_message(message, &mut buf)
        .context("reading Noise message 1")?;
    serde_json::from_slice(&buf[..len]).context("parsing the Noise message 1 payload")
}

/// Build the responder (client) handshake state, keyed to the server's static key.
pub fn responder_handshake(
    local_private: &[u8],
    remote_public: &[u8],
    prologue: &[u8],
) -> Result<HandshakeState> {
    let params = noise_params()?;
    Builder::new(params)
        .prologue(prologue)?
        .local_private_key(local_private)?
        .remote_public_key(remote_public)?
        .build_responder()
        .context("building the responder handshake")
}

/// Build the initiator (server) handshake state, keyed to the client's static key.
/// The sender is always the responder; this exists to drive the interop tests
/// and to model the server side of a handshake.
#[allow(dead_code)]
pub fn initiator_handshake(
    local_private: &[u8],
    remote_public: &[u8],
    prologue: &[u8],
    psk: &[u8; 32],
) -> Result<HandshakeState> {
    let params = noise_params()?;
    Builder::new(params)
        .prologue(prologue)?
        .local_private_key(local_private)?
        .remote_public_key(remote_public)?
        .psk(2, psk)?
        .build_initiator()
        .context("building the initiator handshake")
}

/// Wrap a Noise handshake message into the `noise/handshake` JSON envelope.
pub fn pack_handshake(ciphertext: &[u8]) -> String {
    serde_json::json!({
        "type": HANDSHAKE_TYPE,
        "payload": { "data": base64url::encode(ciphertext) },
    })
    .to_string()
}

/// Extract the `data` field from a `noise/handshake` envelope.
pub fn unpack_handshake(text: &str) -> Result<Vec<u8>> {
    let value: serde_json::Value =
        serde_json::from_str(text).context("parsing a noise/handshake message")?;
    if value.get("type").and_then(|v| v.as_str()) != Some(HANDSHAKE_TYPE) {
        anyhow::bail!("expected a noise/handshake message");
    }
    let data = value
        .get("payload")
        .and_then(|payload| payload.get("data"))
        .and_then(|data| data.as_str())
        .context("noise/handshake is missing payload.data")?;
    base64url::decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full KKpsk2 handshake where the responder learns the PSK only after message 1.
    #[test]
    fn responder_selects_the_psk_after_reading_message_one() {
        let generator = Builder::new(noise_params().unwrap());
        let server = generator.generate_keypair().unwrap();
        let client = generator.generate_keypair().unwrap();
        let psk: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
        let prologue = b"client-init || server-init";

        let mut initiator =
            initiator_handshake(&server.private, &client.public, prologue, &psk).unwrap();
        let mut responder = responder_handshake(&client.private, &server.public, prologue).unwrap();

        let mut buf = vec![0u8; MAX_MESSAGE];
        let payload_in = format!(
            r#"{{"psk_id":"{}","psk_category":"lt"}}"#,
            base64url::encode([7u8; 32])
        );
        let len = initiator
            .write_message(payload_in.as_bytes(), &mut buf)
            .unwrap();
        let msg1 = buf[..len].to_vec();

        let parsed = read_message_1(&mut responder, &msg1).unwrap();
        assert_eq!(parsed.psk_category, "lt");

        responder.set_psk(2, &psk).unwrap();
        let hash_before_msg2 = responder.get_handshake_hash().to_vec();
        let len = responder.write_message(b"{}", &mut buf).unwrap();
        let msg2 = buf[..len].to_vec();
        // The handshake hash is only final once message 2 has been written.
        assert_ne!(hash_before_msg2, responder.get_handshake_hash());
        let payload_len = initiator.read_message(&msg2, &mut buf).unwrap();
        assert_eq!(&buf[..payload_len], b"{}");

        assert_eq!(
            initiator.get_handshake_hash(),
            responder.get_handshake_hash()
        );

        let mut i = initiator.into_transport_mode().unwrap();
        let mut r = responder.into_transport_mode().unwrap();
        let len = i.write_message(b"hello", &mut buf).unwrap();
        let plain = r.read_message(&buf[..len], &mut buf.clone()).unwrap();
        assert_eq!(plain, b"hello".len());
    }

    /// The envelope helpers round-trip a handshake message.
    #[test]
    fn handshake_envelope_round_trips() {
        let packed = pack_handshake(&[1, 2, 3, 4]);
        assert!(packed.contains(HANDSHAKE_TYPE));
        assert_eq!(unpack_handshake(&packed).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn category_codes_are_the_short_forms() {
        assert_eq!(PskCategory::from_code("lt"), Some(PskCategory::LongTerm));
        assert_eq!(PskCategory::from_code("pr"), Some(PskCategory::Pairing));
        assert_eq!(PskCategory::from_code("sn"), Some(PskCategory::Sentinel));
        assert_eq!(PskCategory::from_code("xx"), None);
        assert_eq!(PskCategory::LongTerm.as_code(), "lt");
    }
}
