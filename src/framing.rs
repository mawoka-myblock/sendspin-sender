//! Binary message framing: message type IDs, fragmentation, and clock sync payloads.

use anyhow::{bail, Result};

/// Binary message IDs from the Sendspin specification.
pub const TYPE_JSON: u8 = 0;
pub const TYPE_FRAGMENT: u8 = 1;
pub const TYPE_SOURCE_AUDIO_CHUNK: u8 = 12;

const FLAG_FIRST: u8 = 0b0000_0010;
const FLAG_LAST: u8 = 0b0000_0001;

/// A decrypted binary message: a typed role payload (the JSON type is handled by the caller).
pub enum BinaryMessage {
    Typed { message_type: u8, payload: Vec<u8> },
}

/// Reassembles fragmented binary messages arriving from the server.
#[derive(Default)]
pub struct Reassembler {
    buffer: Option<(u8, Vec<u8>)>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self { buffer: None }
    }

    /// Feed one decrypted binary message. Returns a complete message when one is available.
    pub fn push(&mut self, plaintext: &[u8]) -> Result<Option<BinaryMessage>> {
        let Some((&message_type, rest)) = plaintext.split_first() else {
            bail!("empty binary message");
        };
        if message_type != TYPE_FRAGMENT {
            if self.buffer.is_some() {
                bail!("non-fragment binary message while a fragmented message is in flight");
            }
            return Ok(Some(BinaryMessage::Typed {
                message_type,
                payload: rest.to_vec(),
            }));
        }

        let Some((&flags, rest)) = rest.split_first() else {
            bail!("fragment message is missing its flags byte");
        };
        if flags & !(FLAG_FIRST | FLAG_LAST) != 0 {
            bail!("fragment has reserved flag bits set");
        }
        let first = flags & FLAG_FIRST != 0;
        let last = flags & FLAG_LAST != 0;

        if first {
            if self.buffer.is_some() {
                bail!("first fragment while a fragmented message is in flight");
            }
            let Some((&orig_type, data)) = rest.split_first() else {
                bail!("first fragment is missing its orig_type byte");
            };
            if orig_type == TYPE_FRAGMENT {
                bail!("fragment orig_type must not be the fragment type");
            }
            if last {
                return Ok(Some(BinaryMessage::Typed {
                    message_type: orig_type,
                    payload: data.to_vec(),
                }));
            }
            self.buffer = Some((orig_type, data.to_vec()));
            return Ok(None);
        }

        let Some((orig_type, data)) = self.buffer.as_mut() else {
            bail!("non-first fragment with no fragmented message in flight");
        };
        if last {
            data.extend_from_slice(rest);
            let orig_type = *orig_type;
            let payload = std::mem::take(data);
            self.buffer = None;
            return Ok(Some(BinaryMessage::Typed {
                message_type: orig_type,
                payload,
            }));
        }
        data.extend_from_slice(rest);
        Ok(None)
    }
}

/// Build a source audio chunk (binary message type 12).
///
/// Layout: `[type][timestamp:8 big-endian][audio:...]`; the timestamp is the server
/// clock time in microseconds at which the chunk's first sample was captured.
pub fn source_audio_chunk(timestamp_us: u64, audio: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + audio.len());
    out.push(TYPE_SOURCE_AUDIO_CHUNK);
    out.extend_from_slice(&timestamp_us.to_be_bytes());
    out.extend_from_slice(audio);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfragmented_message_passes_through() {
        let mut r = Reassembler::new();
        let message = source_audio_chunk(42, &[1, 2, 3]);
        let out = r.push(&message).unwrap().unwrap();
        match out {
            BinaryMessage::Typed {
                message_type,
                payload,
            } => {
                assert_eq!(message_type, TYPE_SOURCE_AUDIO_CHUNK);
                assert_eq!(&payload[0..8], &42u64.to_be_bytes());
                assert_eq!(&payload[8..], &[1, 2, 3]);
            }
        }
    }

    #[test]
    fn fragmented_message_is_reassembled() {
        let mut r = Reassembler::new();
        // First fragment: [1][FIRST][orig_type][data].
        let first = [TYPE_FRAGMENT, 0b10, 7, 10, 11];
        assert!(r.push(&first).unwrap().is_none());
        // Last fragment: [1][LAST][data].
        let last = [TYPE_FRAGMENT, 0b01, 12];
        let out = r.push(&last).unwrap().unwrap();
        match out {
            BinaryMessage::Typed {
                message_type,
                payload,
            } => {
                assert_eq!(message_type, 7);
                assert_eq!(payload, vec![10, 11, 12]);
            }
        }
    }

    #[test]
    fn out_of_order_fragments_are_rejected() {
        let mut r = Reassembler::new();
        let orphan = [TYPE_FRAGMENT, 0b01, 1];
        assert!(r.push(&orphan).is_err());
    }

    #[test]
    fn nested_fragment_first_parts_are_rejected() {
        let mut r = Reassembler::new();
        assert!(r.push(&[TYPE_FRAGMENT, 0b10, 5, 1]).unwrap().is_none());
        assert!(r.push(&[TYPE_FRAGMENT, 0b10, 6, 1]).is_err());
    }

    #[test]
    fn fragment_orig_type_may_not_be_the_fragment_type() {
        let mut r = Reassembler::new();
        assert!(r.push(&[TYPE_FRAGMENT, 0b10, TYPE_FRAGMENT, 9]).is_err());
    }

    #[test]
    fn reserved_flag_bits_are_rejected() {
        let mut r = Reassembler::new();
        assert!(r.push(&[TYPE_FRAGMENT, 0b100, 7, 1]).is_err());
    }

    #[test]
    fn non_fragment_while_fragment_in_flight_is_rejected() {
        let mut r = Reassembler::new();
        assert!(r.push(&[TYPE_FRAGMENT, 0b10, 7, 1]).unwrap().is_none());
        assert!(r.push(&[TYPE_JSON, 1, 2]).is_err());
    }
}
