//! Capture of the virtual sink's monitor ports, delivering raw PCM to the network side.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use pipewire as pw;
use pw::{properties::properties, spa};

use spa::param::audio::{AudioFormat, AudioInfoRaw};
use spa::param::format::{MediaSubtype, MediaType};
use spa::param::format_utils;
use spa::pod::Pod;

/// Captured PCM, multichannel interleaved signed 16-bit little-endian, sent raw.
pub type CapturedChunk = Vec<u8>;
/// Configuration for the capture stream.
#[derive(Clone, Debug)]
pub struct CaptureConfig {
    /// Node name of the sink whose monitor ports are captured.
    pub target: String,
    /// Requested sample rate; 0 accepts the graph's native rate.
    pub sample_rate: u32,
    /// Requested channels; 0 accepts the graph's native count.
    pub channels: u32,
    /// Requested scheduling quantum in frames, e.g. one chunk's worth.
    pub quantum_frames: u32,
}

/// A running capture stream. Dropping it stops the stream.
pub struct Capture {
    stop: Arc<AtomicBool>,
}

impl Capture {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Spawn the PipeWire main loop on its own thread and start capturing.
///
/// Captured chunks are pushed into `tx`; the thread exits when the receiver is dropped or
/// [`Capture::stop`] is called.
pub fn start(config: CaptureConfig, tx: Sender<CapturedChunk>) -> Result<Capture> {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();

    std::thread::Builder::new()
        .name("pipewire-capture".to_string())
        .spawn(move || {
            if let Err(err) = run(config, tx, thread_stop) {
                tracing::error!("PipeWire capture thread stopped: {err:#}");
            }
        })
        .context("spawning the PipeWire capture thread")?;

    Ok(Capture { stop })
}

struct CaptureState {
    format: AudioInfoRaw,
    tx: Sender<CapturedChunk>,
}

fn run(config: CaptureConfig, tx: Sender<CapturedChunk>, stop: Arc<AtomicBool>) -> Result<()> {
    pw::init();

    let mainloop = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&mainloop, None)?;
    let core = context.connect_rc(None)?;

    let state = CaptureState {
        format: AudioInfoRaw::new(),
        tx,
    };

    let props = properties! {
        *pw::keys::MEDIA_TYPE => "Audio",
        *pw::keys::MEDIA_CATEGORY => "Capture",
        *pw::keys::MEDIA_ROLE => "Music",
        *pw::keys::STREAM_CAPTURE_SINK => "true",
        *pw::keys::TARGET_OBJECT => config.target.as_str(),
        *pw::keys::NODE_NAME => "sendspin-sender.capture",
        "node.description" => "Sendspin source capture",
        // Ask PipeWire to schedule this stream at our chunk size rather than the graph
        // default (typically 1024 frames, ~21 ms at 48 kHz), trimming capture latency.
        *pw::keys::NODE_LATENCY => latency_fraction(config.quantum_frames, config.sample_rate),
    };

    let stream = pw::stream::StreamBox::new(&core, "sendspin-capture", props)
        .context("creating the capture stream")?;

    let sample_rate = config.sample_rate;
    let channels = config.channels;

    let _listener = stream
        .add_local_listener_with_user_data(state)
        .param_changed(move |_, state, id, param| {
            let Some(param) = param else {
                return;
            };
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            let Ok((media_type, media_subtype)) = format_utils::parse_format(param) else {
                return;
            };
            if media_type != MediaType::Audio || media_subtype != MediaSubtype::Raw {
                return;
            }
            let _ = state.format.parse(param);
            tracing::info!(
                "capture format negotiated: rate={} channels={}",
                state.format.rate(),
                state.format.channels()
            );
            let _ = (sample_rate, channels);
        })
        .process(|stream, state| {
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let datas = buffer.datas_mut();
            if datas.is_empty() {
                return;
            }
            let data = &mut datas[0];
            let size = data.chunk().size() as usize;
            if size == 0 {
                return;
            }
            let Some(raw) = data.data() else {
                return;
            };
            if size > raw.len() {
                return;
            }
            let pcm = raw[..size].to_vec();
            if state.tx.send(pcm).is_err() {
                tracing::debug!("capture receiver gone; dropping chunk");
            }
        })
        .register()
        .context("registering the capture stream listener")?;

    // Accept any native rate/channel count, converting to signed 16-bit PCM.
    let mut audio_info = AudioInfoRaw::new();
    audio_info.set_format(AudioFormat::S16LE);
    if config.sample_rate != 0 {
        audio_info.set_rate(config.sample_rate);
    }
    if config.channels != 0 {
        audio_info.set_channels(config.channels);
    }

    let obj = pw::spa::pod::Object {
        type_: pw::spa::utils::SpaTypes::ObjectParamFormat.as_raw(),
        id: spa::param::ParamType::EnumFormat.as_raw(),
        properties: audio_info.into(),
    };
    let values: Vec<u8> = pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(obj),
    )
    .context("serializing the capture format pod")?
    .0
    .into_inner();
    let mut params = [Pod::from_bytes(&values).context("building the capture format pod")?];

    stream
        .connect(
            spa::utils::Direction::Input,
            None,
            pw::stream::StreamFlags::AUTOCONNECT
                | pw::stream::StreamFlags::MAP_BUFFERS
                | pw::stream::StreamFlags::RT_PROCESS,
            &mut params,
        )
        .context("connecting the capture stream")?;

    // Poll for the stop flag so the loop can exit cleanly.
    let poll_loop = mainloop.clone();
    let interval = std::time::Duration::from_millis(200);
    let timer = mainloop.loop_().add_timer(move |_| {
        if stop.load(Ordering::SeqCst) {
            poll_loop.quit();
        }
    });
    timer.update_timer(Some(interval), Some(interval));

    mainloop.run();
    Ok(())
}

/// Render a `node.latency` value as the `frames/rate` fraction PipeWire expects.
fn latency_fraction(quantum_frames: u32, sample_rate: u32) -> String {
    let rate = sample_rate.max(1);
    let frames = quantum_frames.max(1);
    format!("{frames}/{rate}")
}
