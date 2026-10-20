//! The virtual sink that appears in the desktop's audio control center.
//!
//! A null-audio-sink adapter node is created on the PipeWire graph; it shows up like any
//! other output device. Applications routed into it are captured from its monitor ports
//! by [`crate::pipewire::capture`].

use anyhow::{Context, Result};
use pipewire as pw;

use pw::properties::properties;

/// Configuration for the virtual sink node.
#[derive(Clone, Debug)]
pub struct SinkConfig {
    /// Stable node name, e.g. `sendspin-sender.sink`.
    pub node_name: String,
    /// Human-readable description shown by desktop UIs.
    pub node_description: String,
    /// Channel layout, e.g. `FL,FR`.
    pub channel_positions: String,
    /// Sample rate the sink advertises.
    pub sample_rate: u32,
    /// Number of channels.
    pub channels: u32,
    /// Requested scheduling quantum in frames, e.g. one chunk's worth.
    pub quantum_frames: u32,
}

impl Default for SinkConfig {
    fn default() -> Self {
        Self {
            node_name: "sendspin-sender.sink".to_string(),
            node_description: "Sendspin".to_string(),
            channel_positions: "FL,FR".to_string(),
            sample_rate: 48_000,
            channels: 2,
            quantum_frames: 480,
        }
    }
}

/// A live virtual sink node in the PipeWire graph.
pub struct VirtualSink {
    node_name: String,
}

impl VirtualSink {
    /// The node name of the sink, used as the capture target.
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    /// Rebuild a handle from a node name, for passing across threads.
    pub fn from_name(node_name: String) -> Self {
        Self { node_name }
    }
}

/// The null-audio-sink adapter node hangs off this key when it is not the factory itself.
const AUDIO_POSITION_KEY: &str = "audio.position";

/// Render a `node.latency` value as the `frames/rate` fraction PipeWire expects.
fn latency_fraction(quantum_frames: u32, sample_rate: u32) -> String {
    let rate = sample_rate.max(1);
    let frames = quantum_frames.max(1);
    format!("{frames}/{rate}")
}

/// One `core.sync` roundtrip: run the loop until the server has answered.
///
/// Any registry facts already delivered before the sync are visible to listeners by the time
/// this returns.
fn roundtrip(mainloop: &pw::main_loop::MainLoopRc, core: &pw::core::Core) -> Result<()> {
    use std::cell::Cell;
    use std::rc::Rc;

    let done = Rc::new(Cell::new(false));
    let done_clone = done.clone();
    let loop_clone = mainloop.clone();

    let pending = core.sync(0).context("starting a PipeWire roundtrip")?;
    let _listener = core
        .add_listener_local()
        .done(move |id, seq| {
            if id == pw::core::PW_ID_CORE && seq == pending {
                done_clone.set(true);
                loop_clone.quit();
            }
        })
        .register();

    while !done.get() {
        mainloop.run();
    }
    Ok(())
}

/// Destroy any lingering nodes left behind by a previous run under the same name.
///
/// `object.linger` keeps the sink in the graph after the creating client disconnects, which is
/// what we want mid-session but means a killed process leaves its node behind. Without this, a
/// restart would add a second node with the same name instead of replacing it.
fn remove_lingering_sinks(
    mainloop: &pw::main_loop::MainLoopRc,
    core: &pw::core::Core,
    node_name: &str,
) -> Result<()> {
    use std::cell::RefCell;
    use std::rc::Rc;

    let registry = core
        .get_registry()
        .context("opening the PipeWire registry")?;
    let stale: Rc<RefCell<Vec<u32>>> = Rc::new(RefCell::new(Vec::new()));
    let stale_clone = stale.clone();
    let wanted = node_name.to_string();
    let _listener = registry
        .add_listener_local()
        .global(move |global| {
            if global.type_ != pw::types::ObjectType::Node {
                return;
            }
            if let Some(props) = global.props {
                if props.get(*pw::keys::NODE_NAME) == Some(wanted.as_str()) {
                    stale_clone.borrow_mut().push(global.id);
                }
            }
        })
        .register();

    roundtrip(mainloop, core)?;

    let ids = stale.borrow().clone();
    let mut removed = false;
    for id in ids {
        match registry.destroy_global(id).into_result() {
            Ok(_) => {
                tracing::info!("removed a lingering sink node (global {id})");
                removed = true;
            }
            Err(err) => tracing::warn!("could not remove a lingering sink node {id}: {err}"),
        }
    }
    if removed {
        // Let the destroy take effect before we create the replacement.
        roundtrip(mainloop, core)?;
    }
    Ok(())
}

/// Create the virtual sink and return the node proxy that must be kept alive.
///
/// The caller owns the PipeWire main loop; it must keep iterating it and must not drop the
/// returned proxy, or the node leaves the graph.
pub fn create_sink(
    mainloop: &pw::main_loop::MainLoopRc,
    core: &pw::core::Core,
    config: &SinkConfig,
) -> Result<(VirtualSink, pw::node::Node)> {
    // Replace, rather than shadow, a node a previous run left behind.
    remove_lingering_sinks(mainloop, core, &config.node_name)?;

    let props = properties! {
        *pw::keys::FACTORY_NAME => "support.null-audio-sink",
        *pw::keys::NODE_NAME => config.node_name.as_str(),
        *pw::keys::NODE_DESCRIPTION => config.node_description.as_str(),
        *pw::keys::MEDIA_CLASS => "Audio/Sink",
        AUDIO_POSITION_KEY => config.channel_positions.as_str(),
        "audio.rate" => config.sample_rate.to_string(),
        "audio.channels" => config.channels.to_string(),
        "monitor.channel-volumes" => "true",
        "object.linger" => "1",
        "device.description" => config.node_description.as_str(),
        "device.icon-name" => "audio-card-analog",
        "priority.driver" => "1000",
        "priority.session" => "1000",
        "node.pause-on-idle" => "false",
        // Schedule at the chunk size so upstream apps are woken in small blocks and the
        // monitor capture has little to drain. Without this the graph default (usually
        // 1024 frames, ~21 ms at 48 kHz) sets the floor on capture latency.
        *pw::keys::NODE_LATENCY => latency_fraction(config.quantum_frames, config.sample_rate),
    };

    let node: pw::node::Node = core
        .create_object::<pw::node::Node>("adapter", &props)
        .with_context(|| format!("creating the virtual sink {}", config.node_name))?;

    tracing::info!(
        "created virtual sink {:?} ({})",
        config.node_name,
        config.node_description
    );
    Ok((
        VirtualSink {
            node_name: config.node_name.clone(),
        },
        node,
    ))
}
