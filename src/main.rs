mod broker;
mod config;
mod discovery;
mod easytier;
mod identity;
mod shortcut;
mod wireguard;

use anyhow::Result;
use broker::PathTarget;
use clap::Parser;
use config::Config;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    sync::{RwLock, mpsc},
    task::JoinHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GenerationKey {
    public_key: String,
    listen_port: u16,
    peers: Vec<(String, Vec<String>)>,
}

struct Generation {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "wg_linkd=info".into()),
        )
        .init();
    let config = Config::parse().normalize();

    match discovery::stun::public_address(&config.stun).await {
        Ok(address) => info!(server = %config.stun, %address, "STUN public endpoint"),
        Err(error) => warn!(server = %config.stun, %error, "STUN query failed"),
    }

    let mut active_key: Option<GenerationKey> = None;
    let mut generation: Option<Generation> = None;

    loop {
        match wireguard::snapshot(&config.interface) {
            Ok(snapshot) => {
                let mut peers: Vec<(String, Vec<String>)> = snapshot
                    .peers
                    .iter()
                    .map(|peer| {
                        let mut allowed_ips: Vec<String> =
                            peer.allowed_ips.iter().map(ToString::to_string).collect();
                        allowed_ips.sort();
                        (peer.public_key.clone(), allowed_ips)
                    })
                    .collect();
                peers.sort();
                let key = GenerationKey {
                    public_key: snapshot.public_key.clone(),
                    listen_port: snapshot.listen_port,
                    peers,
                };
                if active_key.as_ref() != Some(&key) {
                    if let Some(old) = generation.take() {
                        old.cancel.cancel();
                        let _ = old.task.await;
                    }
                    let cancel = CancellationToken::new();
                    let task =
                        tokio::spawn(run_generation(config.clone(), snapshot, cancel.clone()));
                    generation = Some(Generation { cancel, task });
                    active_key = Some(key);
                }
            }
            Err(error) => {
                warn!(interface = %config.interface, %error, "failed to read WireGuard state")
            }
        }
        if generation
            .as_ref()
            .is_some_and(|generation| generation.task.is_finished())
        {
            if let Some(finished) = generation.take() {
                match finished.task.await {
                    Ok(()) => warn!("wg-link generation stopped; it will be restarted"),
                    Err(error) => error!(%error, "wg-link generation task failed"),
                }
            }
            active_key = None;
        }
        sleep(config.poll_interval()).await;
    }
}

async fn run_generation(config: Config, snapshot: wireguard::Snapshot, cancel: CancellationToken) {
    if let Err(error) = run_generation_inner(config, snapshot, cancel).await {
        error!(%error, "wg-link generation failed");
    }
}

async fn run_generation_inner(
    config: Config,
    snapshot: wireguard::Snapshot,
    cancel: CancellationToken,
) -> Result<()> {
    info!(
        interface = %config.interface,
        public_key = %short(&snapshot.public_key),
        listen_port = snapshot.listen_port,
        peer_count = snapshot.peers.len(),
        relay_count = config.relays.len(),
        "starting embedded wg-link generation"
    );

    let mut path_maps = HashMap::<String, Arc<RwLock<Vec<PathTarget>>>>::new();
    let mut inbound_senders = HashMap::<String, mpsc::Sender<Vec<u8>>>::new();
    let mut broker_tasks = Vec::new();
    let mut baselines = HashMap::<String, u64>::new();
    let mut managed_ports = HashMap::<String, u16>::new();

    for peer in &snapshot.peers {
        let peer_port = identity::derive_port(
            config.peer_port_base,
            7_000,
            "peer-broker",
            &[&snapshot.public_key, &peer.public_key],
        );
        wireguard::set_endpoint(&config.interface, &peer.public_key, peer_port)?;
        let paths = Arc::new(RwLock::new(Vec::new()));
        let (inbound_sender, inbound_receiver) = mpsc::channel(256);
        broker_tasks.push(tokio::spawn(broker::run_peer(
            peer.public_key.clone(),
            peer_port,
            snapshot.listen_port,
            paths.clone(),
            inbound_receiver,
            cancel.child_token(),
        )));
        path_maps.insert(peer.public_key.clone(), paths);
        inbound_senders.insert(peer.public_key.clone(), inbound_sender);
        baselines.insert(peer.public_key.clone(), peer.latest_handshake);
        managed_ports.insert(peer.public_key.clone(), peer_port);
    }

    let mut relay_tasks = Vec::new();
    for relay in &config.relays {
        let provider = format!("easytier|{relay}");
        let listener_port = identity::derive_port(
            config.listener_port_base,
            3_500,
            "easytier-listener",
            &[&snapshot.public_key, relay],
        );
        let (relay_sender, relay_receiver) = mpsc::channel(256);
        let mut peer_routes = Vec::new();
        for peer in &snapshot.peers {
            peer_routes.push(easytier::PeerRoute {
                public_key: peer.public_key.clone(),
                inbound: inbound_senders
                    .get(&peer.public_key)
                    .expect("peer broker sender must exist")
                    .clone(),
            });
            if let Some(paths) = path_maps.get(&peer.public_key) {
                paths.write().await.push(PathTarget {
                    provider: provider.clone(),
                    sender: relay_sender.clone(),
                });
            }
        }
        relay_tasks.push(tokio::spawn(easytier::run_relay(
            config.clone(),
            easytier::RelaySpec {
                local_public_key: snapshot.public_key.clone(),
                relay: relay.clone(),
                listener_port,
                peers: peer_routes,
                outbound: relay_receiver,
            },
            cancel.child_token(),
        )));
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = sleep(config.poll_interval()) => {
                let current = wireguard::snapshot(&config.interface)?;
                for peer in &current.peers {
                    let Some(port) = managed_ports.get(&peer.public_key) else { continue; };
                    let endpoint = format!("127.0.0.1:{port}");
                    if peer.endpoint.as_deref() != Some(endpoint.as_str()) {
                        wireguard::set_endpoint(&config.interface, &peer.public_key, *port)?;
                    }
                    let baseline = baselines.entry(peer.public_key.clone()).or_default();
                    if peer.latest_handshake > *baseline {
                        *baseline = peer.latest_handshake;
                        info!(
                            peer = %short(&peer.public_key),
                            latest_handshake = peer.latest_handshake,
                            "WireGuard authenticated wg-link path"
                        );
                    }
                }
            }
        }
    }

    cancel.cancel();
    for task in broker_tasks {
        let _ = task.await;
    }
    for task in relay_tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "embedded EasyTier relay stopped with error"),
            Err(error) => warn!(%error, "embedded EasyTier relay task failed"),
        }
    }
    Ok(())
}

fn short(key: &str) -> &str {
    key.get(..8).unwrap_or(key)
}
