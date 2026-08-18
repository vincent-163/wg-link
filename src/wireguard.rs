use anyhow::{Context, Result, bail};
use std::{collections::HashMap, process::Command};

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub public_key: String,
    pub listen_port: u16,
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub latest_handshake: u64,
}

fn output(interface: &str, field: &str) -> Result<String> {
    let result = Command::new("wg")
        .args(["show", interface, field])
        .output()
        .with_context(|| format!("failed to run wg show {interface} {field}"))?;
    if !result.status.success() {
        bail!(
            "wg show {interface} {field} failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&result.stdout).trim().to_string())
}

fn pairs(interface: &str, field: &str) -> Result<HashMap<String, String>> {
    Ok(output(interface, field)?
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((fields.next()?.to_string(), fields.next()?.to_string()))
        })
        .collect())
}

pub fn snapshot(interface: &str) -> Result<Snapshot> {
    let public_key = output(interface, "public-key")?;
    if public_key.is_empty() {
        bail!("wireguard interface {interface} has no public key");
    }
    let listen_port = output(interface, "listen-port")?
        .parse::<u16>()
        .with_context(|| format!("invalid listen port on {interface}"))?;
    if listen_port == 0 {
        bail!("wireguard interface {interface} has no listen port");
    }

    let endpoint_map = pairs(interface, "endpoints")?;
    let handshake_map = pairs(interface, "latest-handshakes")?;
    let peers = output(interface, "peers")?
        .lines()
        .filter(|line| !line.is_empty())
        .map(|public_key| Peer {
            public_key: public_key.to_string(),
            endpoint: endpoint_map
                .get(public_key)
                .filter(|value| value.as_str() != "(none)")
                .cloned(),
            latest_handshake: handshake_map
                .get(public_key)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        })
        .collect();

    Ok(Snapshot {
        public_key,
        listen_port,
        peers,
    })
}

pub fn set_endpoint(interface: &str, peer: &str, port: u16) -> Result<()> {
    let endpoint = format!("127.0.0.1:{port}");
    let result = Command::new("wg")
        .args(["set", interface, "peer", peer, "endpoint", &endpoint])
        .output()
        .with_context(|| format!("failed to set endpoint for {peer}"))?;
    if !result.status.success() {
        bail!(
            "wg set endpoint failed for {peer}: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    Ok(())
}
