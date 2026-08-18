use anyhow::{Context, Result};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::UdpSocket,
    sync::{RwLock, mpsc},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct RelayPacket {
    pub peer_key: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PathTarget {
    pub provider: String,
    pub sender: mpsc::Sender<RelayPacket>,
}

pub async fn run_peer(
    peer_key: String,
    bind_port: u16,
    wireguard_port: u16,
    paths: Arc<RwLock<Vec<PathTarget>>>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
) -> Result<()> {
    let socket = UdpSocket::bind(("127.0.0.1", bind_port))
        .await
        .with_context(|| format!("failed to bind peer broker port {bind_port}"))?;
    let wireguard_addr: SocketAddr = format!("127.0.0.1:{wireguard_port}").parse()?;
    let mut buffer = vec![0u8; 65_535];
    info!(peer = %short(&peer_key), bind_port, wireguard_port, "peer UDP broker listening");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            packet = inbound.recv() => {
                let Some(packet) = packet else { return Ok(()); };
                socket.send_to(&packet, wireguard_addr).await?;
                debug!(peer = %short(&peer_key), bytes = packet.len(), "forwarded EasyTier packet to WireGuard");
            }
            received = socket.recv_from(&mut buffer) => {
                let (length, source) = received?;
                if source != wireguard_addr {
                    warn!(peer = %short(&peer_key), %source, "dropping packet from unknown local source");
                    continue;
                }

                let targets = paths.read().await.clone();
                let Some(target) = targets.first() else {
                    warn!(peer = %short(&peer_key), "dropping WireGuard packet because no relay path is configured");
                    continue;
                };
                target.sender.send(RelayPacket {
                    peer_key: peer_key.clone(),
                    payload: buffer[..length].to_vec(),
                }).await.with_context(|| format!("relay path {} stopped", target.provider))?;
                debug!(peer = %short(&peer_key), provider = %target.provider, bytes = length, "forwarded WireGuard packet by EasyTier peer_id");
            }
        }
    }
}

fn short(key: &str) -> &str {
    key.get(..8).unwrap_or(key)
}
