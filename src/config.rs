//! Configuration: the `~/.config/sendspin-sender/config.toml` file and CLI overrides.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::connection::{ConnectionConfig, SourceCodec};

/// The on-disk configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// WebSocket URL of the server, e.g. `ws://192.168.1.10:8927/sendspin`.
    pub server_url: String,
    /// Browse for the server over mDNS when `server_url` is empty.
    pub discover: bool,
    /// Friendly device name shown by the server and desktop UIs.
    pub name: String,
    /// Codec for the outgoing stream: `pcm` or `flac`.
    pub codec: String,
    /// Capture sample rate in Hz.
    pub sample_rate: u32,
    /// Capture channel count.
    pub channels: u32,
    /// Bits per sample.
    pub bit_depth: u32,
    /// Chunk duration in milliseconds.
    pub chunk_millis: u32,
    /// Report line-in signal presence so the server can trigger autostart.
    pub line_sense: bool,
    /// Name of the virtual sink node.
    pub sink_name: String,
    /// Description of the virtual sink node.
    pub sink_description: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            discover: true,
            name: "Sendspin Sender".to_string(),
            codec: "pcm".to_string(),
            sample_rate: 48_000,
            channels: 2,
            bit_depth: 16,
            chunk_millis: 10,
            line_sense: false,
            sink_name: "sendspin-sender.sink".to_string(),
            sink_description: "Sendspin".to_string(),
        }
    }
}

impl Config {
    /// The default configuration path.
    pub fn default_path() -> PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("sendspin-sender").join("config.toml")
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }

    pub fn state_dir(&self) -> PathBuf {
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
            })
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("sendspin-sender")
    }

    pub fn codec(&self) -> Result<SourceCodec> {
        match self.codec.to_ascii_lowercase().as_str() {
            "pcm" => Ok(SourceCodec::Pcm),
            "flac" => Ok(SourceCodec::Flac),
            other => anyhow::bail!("unsupported codec {other:?}; expected pcm or flac"),
        }
    }

    /// The PipeWire scheduling quantum, in frames: one chunk's worth of audio.
    ///
    /// Aligning the graph quantum with the chunk size keeps capture latency at the chunk
    /// duration instead of the graph default (typically 1024 frames, ~21 ms at 48 kHz).
    pub fn quantum_frames(&self) -> u32 {
        let frames = self.sample_rate as u64 * self.chunk_millis as u64 / 1000;
        frames.clamp(1, u32::MAX as u64) as u32
    }

    /// Build the connection settings, resolving the server URL if discovery is enabled.
    pub fn to_connection(&self, url: String, software_version: &str) -> Result<ConnectionConfig> {
        let state_dir = self.state_dir();
        Ok(ConnectionConfig {
            url,
            name: self.name.clone(),
            software_version: software_version.to_string(),
            codec: self.codec()?,
            sample_rate: self.sample_rate,
            channels: self.channels,
            bit_depth: self.bit_depth,
            chunk_millis: self.chunk_millis,
            quantum_frames: self.quantum_frames(),
            line_sense: self.line_sense,
            mac_address: None,
            identity_path: state_dir.join("identity.toml"),
            pairing_path: state_dir.join("pairings.toml"),
            sink_node_name: self.sink_name.clone(),
        })
    }
}
