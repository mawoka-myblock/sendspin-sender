//! `sendspin-sender`: stream a PipeWire virtual sink to a Sendspin server as a `source@v1`
//! client.

mod base64url;
mod codec;
mod config;
mod connection;
mod discovery;
mod framing;
mod identity;
mod messages;
mod noise;
mod pipewire;
mod timefilter;
mod timesync;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::config::Config;

const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "sendspin-sender",
    about = "Stream a PipeWire virtual sink to a Sendspin server",
    version
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Override the server URL (skips mDNS discovery).
    #[arg(long, global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the sender: create the virtual sink and connect to the server.
    Run,
    /// Print the pairing token to paste into the server's operator interface.
    PrintToken,
    /// Decode a pairing token and show the client id and PSK it carries.
    VerifyToken {
        /// The token to decode, e.g. `SP:0...`.
        token: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let config_path = cli.config.clone().unwrap_or_else(Config::default_path);
    let config = Config::load(&config_path)?;

    match cli.command.unwrap_or(Command::Run) {
        Command::PrintToken => print_token(&config),
        Command::VerifyToken { token } => verify_token(&token),
        Command::Run => run_sender(config, cli.server),
    }
}

/// Decode a version-0 pairing token for inspection.
fn verify_token(token: &str) -> Result<()> {
    let payload = identity::decode_pairing_token(token)?;
    if payload.len() != 64 {
        anyhow::bail!(
            "expected a 64-byte version-0 payload, got {} bytes",
            payload.len()
        );
    }
    let client_key: [u8; 32] = payload[..32].try_into().unwrap();
    let pairing_psk: [u8; 32] = payload[32..].try_into().unwrap();
    println!("client_id:   {}", base64url::encode(client_key));
    println!("pairing_psk: {}", base64url::encode(pairing_psk));
    println!("psk_id:      {}", identity::psk_id_for(&pairing_psk));
    Ok(())
}

/// Print (generating on first use) the version-0 pairing token for this client.
fn print_token(config: &Config) -> Result<()> {
    let state_dir = config.state_dir();
    let identity = identity::Identity::load_or_generate(&state_dir.join("identity.toml"))?;

    let pairing_path = state_dir.join("pairings.toml");
    let mut pairing = identity::PairingState::load(&pairing_path)?;
    let pairing_psk = match pairing.pairing_psk() {
        Some(psk) => psk,
        None => {
            let psk = identity::generate_pairing_psk();
            pairing.set_pairing_psk(&psk);
            pairing.save(&pairing_path)?;
            psk
        }
    };

    let token = identity::encode_pairing_token(&identity.public_key, &pairing_psk.psk);
    println!("client_id: {}", identity.client_id());
    println!("pairing token:");
    println!("{token}");
    Ok(())
}

fn run_sender(config: Config, server_override: Option<String>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the Tokio runtime")?;

    runtime.block_on(async move {
        let url = resolve_server_url(&config, server_override)?;
        tracing::info!("using server {url}");

        // Create the virtual sink, then run for as long as the process lives.
        let sink_config = pipewire::sink::SinkConfig {
            node_name: config.sink_name.clone(),
            node_description: config.sink_description.clone(),
            channel_positions: channel_positions(config.channels),
            sample_rate: config.sample_rate,
            channels: config.channels,
            quantum_frames: config.quantum_frames(),
        };
        let sink = start_sink(sink_config)?;
        tracing::info!("virtual sink {:?} is available", sink.node_name());

        let connection = connection::spawn(config.to_connection(url, SOFTWARE_VERSION)?)?;

        wait_for_shutdown().await;
        tracing::info!("shutting down");
        connection.stop();
        // Give the goodbye a moment to reach the server.
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    })
}

/// Resolve the target URL from the override, the config file, or mDNS discovery.
fn resolve_server_url(config: &Config, server_override: Option<String>) -> Result<String> {
    if let Some(server) = server_override {
        return Ok(server);
    }
    if !config.server_url.is_empty() {
        return Ok(config.server_url.clone());
    }
    if !config.discover {
        anyhow::bail!("no server configured and discovery is disabled");
    }
    tracing::info!("browsing for a Sendspin server over mDNS");
    let servers = discovery::browse(Duration::from_secs(3))?;
    Ok(servers[0].clone())
}

/// Create the PipeWire sink on a dedicated thread that keeps iterating its main loop.
fn start_sink(config: pipewire::sink::SinkConfig) -> Result<pipewire::sink::VirtualSink> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("pipewire-sink".to_string())
        .spawn(move || {
            if let Err(err) = run_sink(config, tx) {
                tracing::error!("PipeWire sink thread stopped: {err:#}");
            }
        })
        .context("spawning the PipeWire sink thread")?;

    let node_name = rx
        .recv_timeout(Duration::from_secs(5))
        .context("the PipeWire sink thread did not report back")??;
    Ok(pipewire::sink::VirtualSink::from_name(node_name))
}

/// Run the sink's main loop until the process exits.
///
/// The node proxy is held for the lifetime of the loop: dropping it would remove the node
/// from the graph even with `object.linger`.
fn run_sink(
    config: pipewire::sink::SinkConfig,
    ready: std::sync::mpsc::Sender<Result<String>>,
) -> Result<()> {
    ::pipewire::init();
    let mainloop = ::pipewire::main_loop::MainLoopRc::new(None)?;
    let context = ::pipewire::context::ContextRc::new(&mainloop, None)?;
    let core = context.connect_rc(None)?;
    let (sink, _node) = pipewire::sink::create_sink(&mainloop, &core, &config)?;
    let _ = ready.send(Ok(sink.node_name().to_string()));
    // Iterate the loop so the create request is flushed and the node is announced.
    mainloop.run();
    Ok(())
}

fn channel_positions(channels: u32) -> String {
    match channels {
        1 => "MONO".to_string(),
        2 => "FL,FR".to_string(),
        _ => "FL,FR".to_string(),
    }
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(sigint) => sigint,
            Err(_) => return std::future::pending().await,
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(sigterm) => sigterm,
            Err(_) => return std::future::pending().await,
        };
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sendspin_sender=info,warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
