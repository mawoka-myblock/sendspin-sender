//! Client identity, pairing token, and persisted pairing records.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::base64url;

/// Domain separation labels from the Sendspin spec.
const PSK_ID_LABEL: &[u8] = b"sendspin-psk-id-v1";
const SENTINEL_LABEL: &[u8] = b"sendspin-sentinel-psk-v1";

/// `psk_id = base64url(SHA-256("sendspin-psk-id-v1" || PSK))`.
pub fn psk_id_for(psk: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PSK_ID_LABEL);
    hasher.update(psk);
    base64url::encode(hasher.finalize())
}

/// The Sentinel PSK: `SHA-256("sendspin-sentinel-psk-v1")`.
pub fn sentinel_psk() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SENTINEL_LABEL);
    hasher.finalize().into()
}

/// The static identity of this sender: a long-lived X25519 keypair.
#[derive(Clone)]
pub struct Identity {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    private_key: String,
    public_key: String,
}

impl Identity {
    /// Load the identity from `path`, generating and persisting one on first use.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        if path.exists() {
            let text = fs::read_to_string(path)
                .with_context(|| format!("reading identity {}", path.display()))?;
            let file: IdentityFile = toml::from_str(&text)
                .with_context(|| format!("parsing identity {}", path.display()))?;
            let private: [u8; 32] = base64url::decode(&file.private_key)
                .context("identity private_key is not valid base64url")?
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("identity private_key must be 32 bytes"))?;
            let public: [u8; 32] = base64url::decode(&file.public_key)
                .context("identity public_key is not valid base64url")?
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("identity public_key must be 32 bytes"))?;
            return Ok(Self {
                private_key: private,
                public_key: public,
            });
        }

        let keypair = snow::Builder::new(crate::noise::noise_params()?).generate_keypair()?;
        let private: [u8; 32] = keypair.private.as_slice().try_into().unwrap();
        let public: [u8; 32] = keypair.public.as_slice().try_into().unwrap();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let file = IdentityFile {
            version: 1,
            private_key: base64url::encode(private),
            public_key: base64url::encode(public),
        };
        let text = toml::to_string_pretty(&file)?;
        fs::write(path, text).with_context(|| format!("writing identity {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        tracing::info!("generated a new client identity at {}", path.display());
        Ok(Self {
            private_key: private,
            public_key: public,
        })
    }

    /// The `client_id`: base64url of the raw public key.
    pub fn client_id(&self) -> String {
        base64url::encode(self.public_key)
    }
}

/// A long-term record binding this client to one server.
#[derive(Clone, Serialize, Deserialize)]
pub struct PairingRecord {
    pub psk_id: String,
    pub psk: String,
    pub server_id: String,
}

/// The accepted pairing PSK, kept as a permanent handshake candidate.
#[derive(Clone)]
pub struct PairingPsk {
    pub psk_id: String,
    pub psk: [u8; 32],
}

/// Client-side pairing state persisted between runs.
#[derive(Default, Serialize, Deserialize)]
pub struct PairingState {
    #[serde(default)]
    pub pairing_psk: Option<StoredPairingPsk>,
    #[serde(default)]
    pub records: Vec<PairingRecord>,
    #[serde(default)]
    pub last_playback_server_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredPairingPsk {
    pub psk_id: String,
    pub psk: String,
}

/// Generate a fresh 32-byte PSK.
pub fn generate_psk() -> [u8; 32] {
    use rand::RngCore;
    let mut psk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut psk);
    psk
}

/// Generate a fresh pairing PSK together with its id.
pub fn generate_pairing_psk() -> PairingPsk {
    let psk = generate_psk();
    PairingPsk {
        psk_id: psk_id_for(&psk),
        psk,
    }
}

impl PairingState {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading pairing state {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing pairing state {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        fs::write(path, text)
            .with_context(|| format!("writing pairing state {}", path.display()))?;
        Ok(())
    }

    pub fn pairing_psk(&self) -> Option<PairingPsk> {
        let stored = self.pairing_psk.as_ref()?;
        let psk: [u8; 32] = base64url::decode(&stored.psk)
            .ok()?
            .as_slice()
            .try_into()
            .ok()?;
        Some(PairingPsk {
            psk_id: stored.psk_id.clone(),
            psk,
        })
    }

    pub fn set_pairing_psk(&mut self, pairing: &PairingPsk) {
        self.pairing_psk = Some(StoredPairingPsk {
            psk_id: pairing.psk_id.clone(),
            psk: base64url::encode(pairing.psk),
        });
    }

    /// Resolve a `psk_id` to a handshake candidate.
    pub fn resolve(
        &self,
        psk_id: &str,
        category: crate::noise::PskCategory,
    ) -> Option<(Vec<u8>, crate::noise::PskCategory)> {
        match category {
            crate::noise::PskCategory::Sentinel => {
                let sentinel = sentinel_psk();
                if psk_id_for(&sentinel) == psk_id {
                    Some((sentinel.to_vec(), category))
                } else {
                    None
                }
            }
            crate::noise::PskCategory::LongTerm => self
                .records
                .iter()
                .find(|record| record.psk_id == psk_id)
                .and_then(|record| base64url::decode(&record.psk).ok())
                .map(|psk| (psk, category)),
            crate::noise::PskCategory::Pairing => {
                let pairing = self.pairing_psk()?;
                if pairing.psk_id == psk_id {
                    Some((pairing.psk.to_vec(), category))
                } else {
                    None
                }
            }
        }
    }

    /// Store a new long-term record for `server_id`, replacing any prior one.
    pub fn store_record(&mut self, server_id: &str, psk: &[u8; 32]) {
        let psk_id = psk_id_for(psk);
        self.records.retain(|record| record.server_id != server_id);
        self.records.push(PairingRecord {
            psk_id,
            psk: base64url::encode(psk),
            server_id: server_id.to_string(),
        });
    }
}

/// Encode a version-0 pairing token: `SP:0` + base32(client_key || pairing_psk) with `2`->`9`.
pub fn encode_pairing_token(client_key: &[u8; 32], pairing_psk: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(client_key);
    payload.extend_from_slice(pairing_psk);
    let encoded = data_encoding::BASE32_NOPAD.encode(&payload);
    let body: String = encoded
        .chars()
        .map(|ch| if ch == '2' { '9' } else { ch })
        .collect();
    format!("SP:0{body}")
}

/// Decode a pairing token, reversing the `2`<->`9` transliteration.
pub fn decode_pairing_token(token: &str) -> Result<Vec<u8>> {
    let trimmed = token.trim().to_ascii_uppercase();
    let rest = trimmed
        .strip_prefix("SP:")
        .context("pairing token must start with SP:")?;
    let mut chars = rest.chars();
    let version = chars
        .next()
        .context("pairing token is missing its version")?;
    if version != '0' {
        anyhow::bail!("unsupported pairing token version {version}");
    }
    let body: String = chars.collect();
    if body.len() % 8 == 1 {
        anyhow::bail!("pairing token body has an invalid length");
    }
    let mut padded = body;
    while !padded.len().is_multiple_of(8) {
        padded.push('=');
    }
    let normalized: String = padded
        .chars()
        .map(|ch| if ch == '9' { '2' } else { ch })
        .collect();
    data_encoding::BASE32
        .decode(normalized.as_bytes())
        .context("pairing token body is not valid base32")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference vector from `pairing.md`.
    #[test]
    fn pairing_token_matches_the_spec_vector() {
        let client_key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let pairing_psk: [u8; 32] = std::array::from_fn(|i| 0xe0 + i as u8);
        let token = encode_pairing_token(&client_key, &pairing_psk);
        assert_eq!(
            token,
            "SP:0AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYP6BYPC4PSOLZXH5DU6V97M5XXO74HR6LZ7J5PW674PT6X37T6757Y"
        );

        // Decoding round-trips, including the lenient `9`<->`2` handling.
        let decoded = decode_pairing_token(&token).unwrap();
        assert_eq!(decoded.len(), 64);
        assert_eq!(&decoded[..32], &client_key);
        assert_eq!(&decoded[32..], &pairing_psk);

        let lowered = token.to_ascii_lowercase();
        assert_eq!(decode_pairing_token(&lowered).unwrap(), decoded);
    }

    /// `psk_id` is the base64url SHA-256 of the labelled PSK.
    #[test]
    fn psk_id_uses_the_expected_label() {
        let psk = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"sendspin-psk-id-v1");
        hasher.update(psk);
        assert_eq!(psk_id_for(&psk), base64url::encode(hasher.finalize()));
    }

    /// The Sentinel PSK is `SHA-256("sendspin-sentinel-psk-v1")`.
    #[test]
    fn sentinel_psk_matches_the_spec_value() {
        let mut hasher = Sha256::new();
        hasher.update(b"sendspin-sentinel-psk-v1");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(sentinel_psk(), expected);
    }
}
