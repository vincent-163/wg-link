use anyhow::{Context, Result};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    net::UdpSocket,
    sync::{RwLock, mpsc},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::metrics::MetricsRegistry;
use crate::shortcut::state::SessionKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayChannel {
    BaseWireGuard,
    ShortcutWireGuard {
        session: SessionKey,
    },
    PathProbe {
        nonce: u64,
        sent_micros: u64,
        reply: bool,
    },
}

#[derive(Debug, Clone)]
pub struct RelayPacket {
    pub peer_key: String,
    pub channel: RelayChannel,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InboundRelayPacket {
    pub source_key: String,
    pub channel: RelayChannel,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PathTarget {
    pub id: String,
    pub label: String,
    pub protocol: String,
    pub sender: mpsc::Sender<RelayPacket>,
}

#[derive(Debug, Default)]
pub struct PathSet {
    pub targets: Vec<PathTarget>,
    pub selected: Option<String>,
}

impl PathSet {
    pub fn ordered_targets(&self) -> Vec<PathTarget> {
        let mut targets = self.targets.clone();
        if let Some(selected) = &self.selected
            && let Some(index) = targets.iter().position(|target| &target.id == selected)
        {
            targets.swap(0, index);
        }
        targets
    }

    pub fn select(&mut self, path_id: Option<&str>) -> bool {
        match path_id {
            None => {
                self.selected = None;
                true
            }
            Some(path_id) if self.targets.iter().any(|target| target.id == path_id) => {
                self.selected = Some(path_id.to_string());
                true
            }
            Some(_) => false,
        }
    }
}

pub async fn run_peer(
    peer_key: String,
    bind_port: u16,
    wireguard_port: u16,
    paths: Arc<RwLock<PathSet>>,
    metrics: MetricsRegistry,
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

                let targets = ordered_healthy_targets(&peer_key, &paths, &metrics).await;
                if targets.is_empty() {
                    warn!(peer = %short(&peer_key), "dropping WireGuard packet because no relay path is configured");
                    continue;
                }
                let payload = buffer[..length].to_vec();
                let mut forwarded = false;
                for target in targets {
                    if target.sender.send(RelayPacket {
                        peer_key: peer_key.clone(),
                        channel: RelayChannel::BaseWireGuard,
                        payload: payload.clone(),
                    }).await.is_ok() {
                        debug!(peer = %short(&peer_key), path = %target.id, bytes = length, "forwarded WireGuard packet by EasyTier peer_id");
                        forwarded = true;
                        break;
                    }
                    warn!(peer = %short(&peer_key), path = %target.id, "relay path stopped; trying fallback");
                }
                if !forwarded {
                    anyhow::bail!("all relay paths stopped for peer {}", short(&peer_key));
                }
            }
        }
    }
}

pub async fn run_dispatcher(
    paths: HashMap<String, Arc<RwLock<PathSet>>>,
    dynamic_targets: Vec<PathTarget>,
    metrics: MetricsRegistry,
    mut inbound: mpsc::Receiver<RelayPacket>,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            packet = inbound.recv() => {
                let Some(packet) = packet else { return Ok(()); };
                let targets = match paths.get(&packet.peer_key) {
                    Some(path_set) => ordered_healthy_targets(&packet.peer_key, path_set, &metrics).await,
                    None => dynamic_targets.clone(),
                };
                if targets.is_empty() {
                    warn!(peer = %short(&packet.peer_key), "dropping dispatched packet because no dynamic EasyTier path is configured");
                    continue;
                }
                let mut forwarded = false;
                for target in targets {
                    if target.sender.send(packet.clone()).await.is_ok() {
                        forwarded = true;
                        break;
                    }
                    warn!(peer = %short(&packet.peer_key), path = %target.id, "dispatched relay path stopped; trying fallback");
                }
                if !forwarded {
                    anyhow::bail!("all dispatched relay paths stopped for peer {}", short(&packet.peer_key));
                }
            }
        }
    }
}

async fn ordered_healthy_targets(
    peer_key: &str,
    paths: &Arc<RwLock<PathSet>>,
    metrics: &MetricsRegistry,
) -> Vec<PathTarget> {
    let (selected, mut targets) = {
        let paths = paths.read().await;
        (paths.selected.clone(), paths.ordered_targets())
    };
    targets.sort_by_key(|target| {
        let available = metrics.is_available(peer_key, &target.id);
        match (selected.as_deref() == Some(target.id.as_str()), available) {
            (true, true) => 0,
            (false, true) => 1,
            (true, false) => 2,
            (false, false) => 3,
        }
    });
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(id: &str) -> PathTarget {
        let (sender, _) = mpsc::channel(1);
        PathTarget {
            id: id.into(),
            label: id.into(),
            protocol: "udp".into(),
            sender,
        }
    }

    #[test]
    fn selected_path_is_ordered_first() {
        let mut paths = PathSet {
            targets: vec![target("one"), target("two")],
            selected: None,
        };
        assert!(paths.select(Some("two")));
        assert_eq!(paths.ordered_targets()[0].id, "two");
        assert!(!paths.select(Some("missing")));
        assert!(paths.select(None));
        assert_eq!(paths.ordered_targets()[0].id, "one");
    }

    #[tokio::test]
    async fn dynamic_peer_uses_shared_easytier_target() {
        let (target_sender, mut target_receiver) = mpsc::channel(1);
        let target = PathTarget {
            id: "dynamic".into(),
            label: "dynamic".into(),
            protocol: "udp".into(),
            sender: target_sender,
        };
        let (sender, receiver) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_dispatcher(
            HashMap::new(),
            vec![target],
            MetricsRegistry::default(),
            receiver,
            cancel.clone(),
        ));
        sender
            .send(RelayPacket {
                peer_key: "dynamic-peer".into(),
                channel: RelayChannel::ShortcutWireGuard {
                    session: SessionKey {
                        shortcut_id: crate::shortcut::control::ShortcutId([1; 16]),
                        epoch: 1,
                    },
                },
                payload: vec![1, 2, 3],
            })
            .await
            .unwrap();
        assert_eq!(
            target_receiver.recv().await.unwrap().peer_key,
            "dynamic-peer"
        );
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
}

fn short(key: &str) -> &str {
    key.get(..8).unwrap_or(key)
}
