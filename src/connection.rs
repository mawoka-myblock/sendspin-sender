//! The connection state machine: dial, handshake, activation, time sync, and streaming.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::base64url;
use crate::framing::{self, BinaryMessage, TYPE_JSON, TYPE_SOURCE_AUDIO_CHUNK};
use crate::identity::{self, Identity, PairingState};
use crate::messages::{self, ServerActivate};
use crate::noise::{self, PskCategory};
use crate::pipewire::capture::{Capture, CaptureConfig};
use crate::timefilter::TimeFilter;
use crate::timesync;

/// Settings for one connection attempt.
#[derive(Clone)]
pub struct ConnectionConfig {
    pub url: String,
    pub name: String,
    pub software_version: String,
    pub codec: SourceCodec,
    pub sample_rate: u32,
    pub channels: u32,
    pub bit_depth: u32,
    pub chunk_millis: u32,
    /// Requested PipeWire scheduling quantum in frames.
    pub quantum_frames: u32,
    pub line_sense: bool,
    pub mac_address: Option<String>,
    pub identity_path: std::path::PathBuf,
    pub pairing_path: std::path::PathBuf,
    pub sink_node_name: String,
}

/// The codec used for the outgoing source stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceCodec {
    Pcm,
    Flac,
}

impl SourceCodec {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pcm => "pcm",
            Self::Flac => "flac",
        }
    }
}

/// Monotonic time in microseconds, matching the wire's clock domain.
pub fn now_us() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec * 1_000_000 + ts.tv_nsec / 1_000
}

/// A running sender connection.
pub struct Connection {
    stop: Arc<AtomicBool>,
}

impl Connection {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Spawn the connection task. It reconnects on its own until `stop` is set.
pub fn spawn(config: ConnectionConfig) -> Result<Connection> {
    let stop = Arc::new(AtomicBool::new(false));
    let task_stop = stop.clone();
    tokio::spawn(async move {
        run_supervisor(config, task_stop).await;
    });
    Ok(Connection { stop })
}

async fn run_supervisor(config: ConnectionConfig, stop: Arc<AtomicBool>) {
    let mut backoff = Duration::from_millis(500);
    while !stop.load(Ordering::SeqCst) {
        match run_once(&config, &stop).await {
            Ok(()) => {
                backoff = Duration::from_millis(500);
            }
            Err(err) => {
                tracing::warn!("connection ended: {err:#}");
            }
        }
        if stop.load(Ordering::SeqCst) {
            break;
        }
        tracing::info!("reconnecting in {:?}", backoff);
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
    tracing::info!("sender stopped");
}

/// The shared, mutable state of one live connection.
struct Session {
    config: ConnectionConfig,
    pairing: PairingState,
    /// The PSK that keyed the current Noise session.
    matched: noise::Candidate,
    /// The handshake hash, the prologue for any in-band re-handshake.
    handshake_hash: Vec<u8>,
    /// Our long-term static private key, reused by every handshake.
    local_private: Vec<u8>,
    /// The server's static public key, used to bind pairing records and re-handshakes.
    server_public: Vec<u8>,
    /// The server's static public key, in base64url form, as it appears in `server_id`.
    server_id: String,
    /// Pairing activations seen since the last handshake.
    pairing_index: u64,
    /// Roles the server last declared active.
    active_roles: Vec<String>,
    available: bool,
    time_filter: TimeFilter,
    /// Local timestamps of the outstanding `client/time` probes.
    pending_time: VecDeque<i64>,
    capture: Option<Capture>,
    capture_rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    streaming: bool,
    /// PCM captured but not yet framed into a chunk, with its first-sample local time.
    backlog: Vec<u8>,
    backlog_started_us: i64,
    /// Frame size in bytes, derived from the negotiated format.
    frame_bytes: usize,
    /// Bytes of PCM per outgoing chunk.
    chunk_bytes: usize,
    /// Chunks emitted since the stream started, for periodic progress logging.
    sent_chunks: u64,
}

impl Session {
    fn source_active(&self) -> bool {
        self.active_roles.iter().any(|role| role == "source@v1")
    }
}

struct Wire {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    transport: snow::TransportState,
    reassembler: framing::Reassembler,
}

impl Wire {
    /// Send an encrypted JSON message as a binary WebSocket message.
    async fn send_json(&mut self, text: &str) -> Result<()> {
        let mut plaintext = Vec::with_capacity(text.len() + 1);
        plaintext.push(TYPE_JSON);
        plaintext.extend_from_slice(text.as_bytes());
        self.send_binary(&plaintext).await
    }

    /// Send an already-framed binary payload (message type byte included).
    async fn send_binary(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; 65535];
        let len = self
            .transport
            .write_message(plaintext, &mut buf)
            .context("encrypting an outgoing message")?;
        self.ws
            .send(Message::Binary(buf[..len].to_vec().into()))
            .await
            .context("sending a WebSocket message")
    }

    /// Send an outgoing message, fragmenting it when it exceeds one Noise message.
    async fn send_framed(&mut self, message_type: u8, payload: &[u8]) -> Result<()> {
        const MAX_PAYLOAD: usize = 65518 - 2;
        let mut framed = Vec::with_capacity(payload.len() + 1);
        framed.push(message_type);
        framed.extend_from_slice(payload);

        if framed.len() <= 65518 {
            return self.send_binary(&framed).await;
        }

        let body = payload;
        let mut offset = 0usize;
        let mut first = true;
        while offset < body.len() {
            let take = MAX_PAYLOAD.min(body.len() - offset);
            let last = offset + take >= body.len();
            let mut fragment = Vec::with_capacity(take + 3);
            fragment.push(framing::TYPE_FRAGMENT);
            let mut flags = 0u8;
            if first {
                flags |= 0b0000_0010;
            }
            if last {
                flags |= 0b0000_0001;
            }
            fragment.push(flags);
            if first {
                fragment.push(message_type);
            }
            fragment.extend_from_slice(&body[offset..offset + take]);
            self.send_binary(&fragment).await?;
            offset += take;
            first = false;
        }
        Ok(())
    }

    /// Swap in a new transport after a re-handshake, resetting fragment state.
    fn replace_transport(&mut self, transport: snow::TransportState) {
        self.transport = transport;
        self.reassembler = framing::Reassembler::new();
    }

    /// Receive the next decrypted message from the server.
    async fn recv(&mut self) -> Result<Received> {
        loop {
            let message = match self.ws.next().await {
                Some(Ok(message)) => message,
                Some(Err(err)) => return Err(err).context("reading from the WebSocket"),
                None => bail!("the server closed the connection"),
            };
            let data = match message {
                Message::Text(text) => text.as_bytes().to_vec(),
                Message::Binary(data) => data.to_vec(),
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                Message::Close(_) => bail!("the server closed the connection"),
            };
            let received_us = now_us();
            let mut plaintext = vec![0u8; 65535];
            let len = self
                .transport
                .read_message(&data, &mut plaintext)
                .context("decrypting a message from the server")?;
            plaintext.truncate(len);
            if plaintext.is_empty() {
                continue;
            }
            let Some(message) = self.reassembler.push(&plaintext)? else {
                continue;
            };
            match message {
                BinaryMessage::Typed {
                    message_type: TYPE_JSON,
                    payload,
                } => {
                    let text =
                        String::from_utf8(payload).context("a JSON message was not valid UTF-8")?;
                    return Ok(Received::Json { text, received_us });
                }
                BinaryMessage::Typed {
                    message_type,
                    payload: _,
                } => {
                    return Ok(Received::Binary { message_type });
                }
            }
        }
    }
}

enum Received {
    Json { text: String, received_us: i64 },
    Binary { message_type: u8 },
}

async fn run_once(config: &ConnectionConfig, stop: &Arc<AtomicBool>) -> Result<()> {
    tracing::info!("dialing {}", config.url);
    let identity = Identity::load_or_generate(&config.identity_path)?;
    let pairing = PairingState::load(&config.pairing_path)?;

    let (ws, _response) = tokio_tungstenite::connect_async(&config.url)
        .await
        .with_context(|| format!("connecting to {}", config.url))?;

    // ---- cleartext phase -------------------------------------------------
    let mut ws = ws;
    let our_init = messages::client_init(&identity.client_id());
    ws.send(Message::Text(our_init.clone().into())).await?;

    let first_text = expect_text(&mut ws, "server/init").await?;
    if first_text.contains("\"server/error\"") || first_text.contains("server/error") {
        let err = messages::parse_server_error(&first_text)?;
        bail!("the server rejected client/init: {}", err.reason);
    }
    let server_init = messages::parse_server_init(&first_text)?;
    if server_init.version != messages::PROTOCOL_VERSION {
        bail!(
            "the server speaks core message version {}; this client implements {}",
            server_init.version,
            messages::PROTOCOL_VERSION
        );
    }
    tracing::info!("server {} accepted the connection", server_init.server_id);

    let msg1_text = expect_text(&mut ws, "noise/handshake").await?;
    let msg1 = noise::unpack_handshake(&msg1_text)?;

    // The prologue is the raw bytes of `client/init` followed by `server/init`.
    let mut prologue = our_init.into_bytes();
    prologue.extend_from_slice(first_text.as_bytes());

    let server_public = base64url::decode_32(&server_init.server_id)
        .context("the server_id is not a 32-byte base64url key")?;

    // Read message 1 without a PSK to learn which credential the server wants.
    let mut responder =
        noise::responder_handshake(&identity.private_key, &server_public, &prologue)?;
    let payload = noise::read_message_1(&mut responder, &msg1)?;
    let category = PskCategory::from_code(&payload.psk_category)
        .context("the server sent an unknown psk_category")?;
    let matched = select_psk(&pairing, &payload.psk_id, category)?;
    tracing::info!(
        "Noise message 1 asks for psk_id={} category={:?}",
        payload.psk_id,
        matched.category
    );
    tracing::debug!("handshake keyed with {}", matched.describe());

    responder.set_psk(2, &matched.psk)?;
    let mut buf = vec![0u8; 65535];
    let len = responder.write_message(b"{}", &mut buf)?;
    ws.send(Message::Text(noise::pack_handshake(&buf[..len]).into()))
        .await?;

    // `h` is only final once message 2 has been written; it is the prologue for any
    // in-band re-handshake.
    let handshake_hash = responder.get_handshake_hash().to_vec();
    tracing::debug!("handshake hash {}", base64url::encode(&handshake_hash));
    let transport = responder.into_transport_mode()?;
    let mut wire = Wire {
        ws,
        transport,
        reassembler: framing::Reassembler::new(),
    };

    // ---- encrypted phase -------------------------------------------------
    let mut session = Session {
        config: config.clone(),
        pairing,
        matched,
        handshake_hash,
        local_private: identity.private_key.to_vec(),
        server_public: server_public.to_vec(),
        server_id: server_init.server_id.clone(),
        pairing_index: 0,
        active_roles: Vec::new(),
        available: false,
        time_filter: TimeFilter::default(),
        pending_time: VecDeque::new(),
        capture: None,
        capture_rx: None,
        streaming: false,
        backlog: Vec::new(),
        backlog_started_us: 0,
        frame_bytes: (config.channels as usize * (config.bit_depth as usize / 8)).max(1),
        chunk_bytes: chunk_bytes_for(config),
        sent_chunks: 0,
    };

    let hello = wait_for_json(&mut wire, "server/hello").await?;
    let server_hello = messages::parse_server_hello(&hello)?;
    tracing::info!(
        "connected to {:?}; server source codecs: {:?}",
        server_hello.name,
        server_hello.source_codecs
    );
    if !server_hello.source_codecs.is_empty() {
        let wanted = session.config.codec.as_str();
        if !server_hello
            .source_codecs
            .iter()
            .any(|codec| codec == wanted)
        {
            tracing::warn!(
                "server does not list the {wanted} codec; it may reject client-stream/start"
            );
        }
    }

    wire.send_json(&messages::client_hello(
        &session.config.name,
        &session.config.software_version,
        session.config.line_sense,
        session.config.mac_address.as_deref(),
    ))
    .await?;

    // Start time sync immediately so the filter converges before `available: true`.
    let probe = now_us();
    session.pending_time.push_back(probe);
    wire.send_json(&messages::client_time(probe)).await?;

    let mut time_sync_timer = tokio::time::interval(Duration::from_millis(50));
    time_sync_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut next_probe = Instant::now() + timesync::sync_interval(&session.time_filter);

    let mut stats_timer = tokio::time::interval(Duration::from_secs(10));
    stats_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_sent_chunks = 0u64;

    loop {
        if stop.load(Ordering::SeqCst) {
            let _ = wire.send_json(&messages::client_goodbye("shutdown")).await;
            return Ok(());
        }

        session.pump_capture(&mut wire).await?;

        tokio::select! {
            biased;
            _ = stats_timer.tick() => {
                if session.streaming {
                    let delta = session.sent_chunks - last_sent_chunks;
                    tracing::debug!(
                        "streaming: {} chunks sent in the last 10 s ({} total)",
                        delta,
                        session.sent_chunks
                    );
                    last_sent_chunks = session.sent_chunks;
                }
            }
            _ = time_sync_timer.tick() => {
                if Instant::now() >= next_probe {
                    let probe = now_us();
                    session.pending_time.push_back(probe);
                    wire.send_json(&messages::client_time(probe)).await?;
                    next_probe = Instant::now() + timesync::sync_interval(&session.time_filter);
                }
            }
            received = wire.recv() => {
                let received = received?;
                session.handle_message(&mut wire, received).await?;
            }
        }
    }
}

async fn expect_text(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    what: &str,
) -> Result<String> {
    loop {
        let message = match ws.next().await {
            Some(Ok(message)) => message,
            Some(Err(err)) => return Err(err).context("reading from the WebSocket"),
            None => bail!("the server closed the connection while awaiting {what}"),
        };
        match message {
            Message::Text(text) => return Ok(text.to_string()),
            Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                continue
            }
            Message::Close(_) => bail!("the server closed the connection while awaiting {what}"),
        }
    }
}

async fn wait_for_json(wire: &mut Wire, what: &str) -> Result<serde_json::Value> {
    loop {
        match wire.recv().await? {
            Received::Json { text, .. } => {
                let (_, payload) = crate::codec::payload_of(&text)?;
                return Ok(payload);
            }
            Received::Binary { .. } => {
                tracing::debug!("ignoring a binary message while awaiting {what}");
                continue;
            }
        }
    }
}

/// Pick the handshake candidate matching `psk_id`.
///
/// The pairing PSK is always a candidate so the server can re-handshake onto it. An unknown
/// long-term id falls back to the Sentinel only during the initial handshake, so the server
/// can carry a re-pairing instead of the connection dying.
fn select_psk(
    pairing: &PairingState,
    psk_id: &str,
    category: PskCategory,
) -> Result<noise::Candidate> {
    if let Some((psk, category)) = pairing.resolve(psk_id, category) {
        return Ok(noise::Candidate {
            psk_id: psk_id.to_string(),
            psk,
            category,
        });
    }
    if category == PskCategory::LongTerm {
        let sentinel = identity::sentinel_psk();
        tracing::warn!(
            "no stored credential matches psk_id={psk_id}; answering under the Sentinel PSK so \
             the server can re-pair"
        );
        return Ok(noise::Candidate {
            psk_id: identity::psk_id_for(&sentinel),
            psk: sentinel.to_vec(),
            category: PskCategory::Sentinel,
        });
    }
    bail!("no PSK matches psk_id={psk_id} for category {category:?}")
}

impl Session {
    /// Drain captured PCM into the backlog, dropping stale audio past the backlog bound.
    async fn pump_capture(&mut self, wire: &mut Wire) -> Result<()> {
        if !self.streaming {
            return Ok(());
        }
        let Some(rx) = self.capture_rx.as_mut() else {
            return Ok(());
        };
        while let Ok(pcm) = rx.try_recv() {
            if self.backlog.is_empty() {
                self.backlog_started_us = now_us();
            }
            self.backlog.extend_from_slice(&pcm);
        }

        // Keep a small bound so a stall resumes from live capture rather than bursting stale
        // audio. ~60 ms of stereo s16 at 48 kHz; enough to ride out a scheduling hiccup
        // without adding perceptible delay.
        const MAX_BACKLOG: usize = 90_000;
        if self.backlog.len() > MAX_BACKLOG {
            let excess = self.backlog.len() - MAX_BACKLOG;
            let aligned = excess - (excess % self.frame_bytes);
            self.backlog.drain(..aligned);
            self.backlog_started_us += frame_duration_us(aligned, self.frame_bytes, &self.config);
        }

        while self.backlog.len() >= self.chunk_bytes {
            let chunk: Vec<u8> = self.backlog.drain(..self.chunk_bytes).collect();
            let start_us = self.backlog_started_us;
            self.backlog_started_us +=
                frame_duration_us(chunk.len(), self.frame_bytes, &self.config);
            let server_ts = self.time_filter.compute_server_time(start_us);
            let payload = framing::source_audio_chunk(server_ts.max(0) as u64, &chunk);
            wire.send_framed(TYPE_SOURCE_AUDIO_CHUNK, &payload[1..])
                .await?;
            self.sent_chunks += 1;
        }
        Ok(())
    }

    async fn handle_message(&mut self, wire: &mut Wire, received: Received) -> Result<()> {
        match received {
            Received::Json { text, received_us } => {
                let (message_type, payload) = crate::codec::payload_of(&text)?;
                match message_type.as_str() {
                    "server/time" => {
                        let time = messages::parse_server_time_json(&payload)?;
                        let was = self.time_filter.is_synchronized();
                        timesync::apply_server_time(
                            &mut self.time_filter,
                            time.client_transmitted,
                            time.server_received,
                            time.server_transmitted,
                            received_us,
                        );
                        if !was && self.time_filter.is_synchronized() {
                            tracing::info!(
                                "clock synchronized (error {} us)",
                                self.time_filter.error()
                            );
                            self.maybe_report_available(wire).await?;
                        }
                    }
                    "server/activate" => {
                        let activate = messages::parse_server_activate(&payload)?;
                        self.handle_activate(wire, activate).await?;
                    }
                    "server/command" => {
                        let command = messages::parse_server_command(&payload)?;
                        if let Some(command) = command.source_command {
                            self.handle_source_command(wire, &command).await?;
                        }
                    }
                    "server/hello" => {
                        tracing::debug!("ignoring a repeated server/hello");
                    }
                    "pair/abort" => {
                        let reason = messages::parse_pair_abort(&payload).unwrap_or_default();
                        tracing::warn!("the server aborted a pairing attempt: {reason}");
                    }
                    "noise/handshake" => {
                        // An in-band re-handshake: swap session keys without closing the socket.
                        let data = payload
                            .get("data")
                            .and_then(serde_json::Value::as_str)
                            .context("a re-handshake carried no data field")?;
                        let msg1 = base64url::decode(data)
                            .context("a re-handshake data field was not base64url")?;
                        self.handle_rehandshake(wire, &msg1).await?;
                    }
                    other => {
                        tracing::debug!("ignoring a server message of type {other}");
                    }
                }
            }
            Received::Binary { message_type } => match message_type {
                TYPE_SOURCE_AUDIO_CHUNK => {
                    tracing::trace!("ignoring an inbound source audio chunk");
                }
                _ => {
                    tracing::debug!("ignoring a binary message of type {message_type}");
                }
            },
        }
        Ok(())
    }

    /// Answer an in-band re-handshake (Noise message 1 inside the current channel).
    ///
    /// The prologue is the prior handshake hash; message 2 is sent under the *old* keys,
    /// then both sides switch to the new transport.
    async fn handle_rehandshake(&mut self, wire: &mut Wire, msg1: &[u8]) -> Result<()> {
        tracing::info!("the server started an in-band re-handshake");
        let mut responder = noise::responder_handshake(
            &self.local_private,
            &self.server_public,
            &self.handshake_hash,
        )?;
        let payload = noise::read_message_1(&mut responder, msg1)?;
        let category = PskCategory::from_code(&payload.psk_category)
            .context("the server sent an unknown psk_category in a re-handshake")?;
        let matched = select_psk(&self.pairing, &payload.psk_id, category)?;
        tracing::info!(
            "re-handshake asks for psk_id={} category={:?}",
            payload.psk_id,
            matched.category
        );

        responder.set_psk(2, &matched.psk)?;
        let mut buf = vec![0u8; 65535];
        let len = responder.write_message(b"{}", &mut buf)?;
        // Message 2 travels inside the current (old-key) channel.
        wire.send_json(&noise::pack_handshake(&buf[..len])).await?;

        // `h` is only final once message 2 has been written.
        let new_hash = responder.get_handshake_hash().to_vec();
        let transport = responder.into_transport_mode()?;
        wire.replace_transport(transport);

        self.handshake_hash = new_hash;
        self.matched = matched;
        // `server/activate` is the server's first message under the new keys; the
        // session-level state (time filter, streams) persists across the swap.
        self.pairing_index = 0;
        Ok(())
    }

    async fn maybe_report_available(&mut self, wire: &mut Wire) -> Result<()> {
        if self.available || !self.time_filter.is_synchronized() || !self.source_active() {
            return Ok(());
        }
        let signal = if self.config.line_sense {
            Some("present")
        } else {
            None
        };
        wire.send_json(&messages::client_state(true, signal))
            .await?;
        self.available = true;
        tracing::info!("reported available: true; awaiting a server start command");
        Ok(())
    }

    async fn handle_activate(&mut self, wire: &mut Wire, activate: ServerActivate) -> Result<()> {
        if let Some(roles) = &activate.active_roles {
            self.active_roles = roles.clone();
        }
        self.pairing_index += 1;

        if activate.activities.iter().any(|a| a == "pairing") {
            tracing::info!(
                "the server requested pairing (method {:?}, format {:?})",
                activate.pairing_method,
                activate.pairing_format
            );
            return self.run_pairing(wire, &activate).await;
        }

        tracing::info!(
            "server/activate: activities={:?} active_roles={:?}",
            activate.activities,
            self.active_roles
        );

        if !self.source_active() {
            self.stop_streaming(wire).await?;
            return Ok(());
        }

        self.maybe_report_available(wire).await?;
        Ok(())
    }

    async fn run_pairing(&mut self, wire: &mut Wire, activate: &ServerActivate) -> Result<()> {
        let method = activate.pairing_method.as_deref().unwrap_or_default();
        if method != "pairing_psk" {
            tracing::error!("unsupported pairing method {method:?}");
            wire.send_json(&messages::pair_abort("method_not_supported"))
                .await?;
            return Ok(());
        }
        if self.matched.category != PskCategory::Pairing {
            tracing::error!(
                "pairing was requested but the session is not keyed with the pairing PSK"
            );
            wire.send_json(&messages::pair_abort("method_not_supported"))
                .await?;
            return Ok(());
        }

        let new_psk = identity::generate_psk();
        wire.send_json(&messages::pair_init(self.pairing_index))
            .await?;
        wire.send_json(&messages::pair_finalize(&base64url::encode(new_psk)))
            .await?;

        let ack = wait_for_json(wire, "server/pair-finalize").await?;
        let _ = ack;
        // The record is persisted on the server's acknowledgement.
        self.pairing.store_record(&self.server_id, &new_psk);
        self.pairing.save(&self.config.pairing_path)?;
        tracing::info!("pairing completed and persisted");
        Ok(())
    }

    async fn handle_source_command(&mut self, wire: &mut Wire, command: &str) -> Result<()> {
        match command {
            "start" => {
                if self.streaming {
                    return Ok(());
                }
                if !self.source_active() || !self.available {
                    tracing::debug!("ignoring a start command while not available or not active");
                    return Ok(());
                }
                self.start_streaming(wire).await?;
            }
            "stop" => {
                self.stop_streaming(wire).await?;
            }
            other => tracing::debug!("ignoring an unknown source command {other:?}"),
        }
        Ok(())
    }

    async fn start_streaming(&mut self, wire: &mut Wire) -> Result<()> {
        let (tx, rx) = mpsc::unbounded_channel();
        let (chunk_tx, chunk_rx) = crossbeam_channel::unbounded();
        // Bridge the PipeWire thread's channel into the async task.
        std::thread::spawn(move || {
            while let Ok(chunk) = chunk_rx.recv() {
                if tx.send(chunk).is_err() {
                    break;
                }
            }
        });

        let capture = crate::pipewire::capture::start(
            CaptureConfig {
                target: self.config.sink_node_name.clone(),
                sample_rate: self.config.sample_rate,
                channels: self.config.channels,
                quantum_frames: self.config.quantum_frames,
            },
            chunk_tx,
        )?;

        wire.send_json(&messages::client_stream_start(
            self.config.codec.as_str(),
            self.config.channels,
            self.config.sample_rate,
            self.config.bit_depth,
        ))
        .await?;

        self.capture = Some(capture);
        self.capture_rx = Some(rx);
        self.streaming = true;
        self.backlog.clear();
        self.backlog_started_us = now_us();
        self.sent_chunks = 0;
        tracing::info!(
            "streaming the virtual sink to the server ({}, {} Hz, {} ch, {} bit)",
            self.config.codec.as_str(),
            self.config.sample_rate,
            self.config.channels,
            self.config.bit_depth
        );
        Ok(())
    }

    async fn stop_streaming(&mut self, wire: &mut Wire) -> Result<()> {
        if !self.streaming {
            return Ok(());
        }
        if let Some(capture) = self.capture.take() {
            capture.stop();
        }
        self.capture_rx = None;
        self.streaming = false;
        self.backlog.clear();
        wire.send_json(&messages::client_stream_end()).await?;
        tracing::info!("stopped streaming");
        Ok(())
    }
}

/// Bytes of PCM per outgoing chunk, derived from the configured chunk duration.
fn chunk_bytes_for(config: &ConnectionConfig) -> usize {
    let frames = (config.sample_rate as u64 * config.chunk_millis as u64 / 1000).max(1);
    let bytes = frames as usize * config.channels.max(1) as usize * (config.bit_depth as usize / 8);
    // Chunks must keep the audio sample stream continuous, so round down to whole frames.
    let frame_bytes = config.channels.max(1) as usize * (config.bit_depth as usize / 8);
    (bytes / frame_bytes).max(1) * frame_bytes
}

/// The duration of `bytes` of PCM, in microseconds.
fn frame_duration_us(bytes: usize, frame_bytes: usize, config: &ConnectionConfig) -> i64 {
    let frames = (bytes / frame_bytes.max(1)) as i64;
    frames * 1_000_000 / config.sample_rate.max(1) as i64
}
