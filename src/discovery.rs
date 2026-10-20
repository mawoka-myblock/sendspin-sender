//! Server discovery over mDNS (`_sendspin-server._tcp`).
//!
//! The spec forbids a client from *advertising* `_sendspin._tcp` while using a
//! client-initiated connection, but browsing the server's service is how a client finds a
//! server to dial.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};

const SERVICE_TYPE: &str = "_sendspin-server._tcp.local.";

/// Browse for servers for up to `timeout`, returning `ws://host:port/sendspin` URLs.
pub fn browse(timeout: Duration) -> Result<Vec<String>> {
    let daemon = ServiceDaemon::new().context("starting the mDNS daemon")?;
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .with_context(|| format!("browsing {SERVICE_TYPE}"))?;

    let mut found = Vec::new();
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match receiver.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let port = info.get_port();
                let addresses = info.get_addresses();
                for address in addresses {
                    let host = if address.is_ipv6() {
                        format!("[{address}]")
                    } else {
                        address.to_string()
                    };
                    found.push(format!("ws://{host}:{port}/sendspin"));
                }
                if addresses.is_empty() {
                    let hostname = info.get_hostname().trim_end_matches('.');
                    found.push(format!("ws://{hostname}:{port}/sendspin"));
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.shutdown();

    if found.is_empty() {
        bail!("no Sendspin server answered on {SERVICE_TYPE}");
    }
    Ok(found)
}
