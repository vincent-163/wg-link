mod broker;
mod config;
mod discovery;
mod easytier;
mod identity;
mod shortcut;
mod wireguard;

use anyhow::Result;
use broker::{PathTarget, RelayChannel};
use clap::Parser;
use config::Config;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
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

    const SHORTCUT_TUN: &str = "wgls0";
    let interface_addresses = wireguard::interface_addresses(&config.interface)?;
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
    let (shortcut_inbound_sender, mut shortcut_inbound_receiver) = mpsc::channel(256);
    let mut shortcut_outbound = None;
    for relay in &config.relays {
        let provider = format!("easytier|{relay}");
        let listener_port = identity::derive_port(
            config.listener_port_base,
            3_500,
            "easytier-listener",
            &[&snapshot.public_key, relay],
        );
        let (relay_sender, relay_receiver) = mpsc::channel(256);
        shortcut_outbound.get_or_insert_with(|| relay_sender.clone());
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
                shortcut_inbound: shortcut_inbound_sender.clone(),
                outbound: relay_receiver,
            },
            cancel.child_token(),
        )));
    }

    let shortcut_outbound = shortcut_outbound.expect("at least one relay is required");
    let device_runtime = shortcut::device::start(SHORTCUT_TUN, cancel.child_token())?;
    let shortcut::device::DeviceRuntime {
        handle: device,
        routes,
        mut events,
        task: device_task,
    } = device_runtime;
    let route_manager = shortcut::policy::AtomicRouteManager::new(
        routes,
        shortcut::policy::SystemPolicy::new_with_source(
            SHORTCUT_TUN,
            interface_addresses
                .first()
                .copied()
                .ok_or_else(|| anyhow::anyhow!("missing local WireGuard source address"))?,
        ),
    );
    let manager = shortcut::state::ShortcutManager::new(route_manager);
    let mut controller = shortcut::controller::ShortcutController::new(
        snapshot.public_key.clone(),
        manager,
        device.clone(),
    );
    let control_runtime = shortcut::base_control::start(
        &interface_addresses,
        &config.interface,
        cancel.child_token(),
    )
    .await?;
    let mut control_receiver = control_runtime.receiver;
    let control_tasks = control_runtime.tasks;
    let mut current_snapshot = snapshot.clone();
    let mut next_issue = HashMap::<String, u64>::new();
    let mut session_peers = HashMap::new();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            control = control_receiver.recv() => {
                let Some(control) = control else {
                    std::future::pending::<()>().await;
                    continue;
                };
                tracing::debug!(source = %control.source, "received shortcut control datagram");
                if let shortcut::control::ControlMessage::Ticket { ticket } = control.message {
                    let now = unix_now();
                    let Some(sender) = current_snapshot.route_peer(control.source, None) else {
                        tracing::debug!(source = %control.source, "shortcut control source is not an AllowedIP");
                        continue;
                    };
                    if sender.latest_handshake == 0 || now.saturating_sub(sender.latest_handshake) > 180 {
                        tracing::debug!(peer = %short(&sender.public_key), latest_handshake = sender.latest_handshake, now, "shortcut control base handshake is stale");
                        continue;
                    }
                    let sender_key = sender.public_key.clone();
                    match controller.receive_ticket(ticket, &sender_key, now, shortcut_outbound.clone()).await {
                        Ok(session) => { session_peers.insert(session, sender_key); }
                        Err(error) => debug_error("shortcut ticket rejected", &error),
                    }
                }
            }
            inbound = shortcut_inbound_receiver.recv() => {
                let Some(inbound) = inbound else {
                    std::future::pending::<()>().await;
                    continue;
                };
                if let RelayChannel::ShortcutWireGuard { session } = inbound.channel
                    && let Err(error) = device.receive(session, inbound.source_key, inbound.payload).await
                {
                    debug_error("shortcut packet rejected", &error);
                }
            }
            event = events.recv() => {
                let Some(event) = event else { break; };
                let now = unix_now();
                if controller.handle_device_event(&event, now)? {
                    if let shortcut::device::DeviceEvent::AuthenticatedHandshake { session } = event {
                        if let Some(peer) = session_peers.get(&session) {
                            next_issue.insert(peer.clone(), now.saturating_add(120));
                            info!(peer = %short(peer), ?session, "authenticated shortcut route activated");
                        }
                    }
                }
            }
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
                current_snapshot = current;
                let now = unix_now();
                for peer in &current_snapshot.peers {
                    if snapshot.public_key >= peer.public_key
                        || peer.latest_handshake == 0
                        || now.saturating_sub(peer.latest_handshake) > 180
                        || next_issue.get(&peer.public_key).is_some_and(|next| now < *next)
                    {
                        continue;
                    }
                    tracing::debug!(peer = %short(&peer.public_key), "attempting direct shortcut issue");
                    match issue_direct_shortcut(
                        &snapshot.public_key,
                        &interface_addresses,
                        peer,
                        now,
                        &mut controller,
                        shortcut_outbound.clone(),
                    ).await {
                        Ok(session) => {
                            session_peers.insert(session, peer.public_key.clone());
                            next_issue.insert(peer.public_key.clone(), now.saturating_add(10));
                        }
                        Err(error) => debug_error("direct shortcut issue failed", &error),
                    }
                }
                for session in controller.expire(now)? {
                    device.remove(session).await?;
                    session_peers.remove(&session);
                }
            }
        }
    }

    cancel.cancel();
    for session in controller.expire(u64::MAX)? {
        let _ = device.remove(session).await;
    }
    let _ = device_task.await;
    for task in control_tasks {
        let _ = task.await;
    }
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

async fn issue_direct_shortcut<R: shortcut::state::RouteManager>(
    local_public_key: &str,
    local_addresses: &[IpAddr],
    peer: &wireguard::Peer,
    now: u64,
    controller: &mut shortcut::controller::ShortcutController<R>,
    outbound: mpsc::Sender<broker::RelayPacket>,
) -> Result<shortcut::state::SessionKey> {
    let remote_address = peer
        .allowed_ips
        .iter()
        .find_map(|network| {
            ((network.addr().is_ipv4() && network.prefix_len() == 32)
                || (network.addr().is_ipv6() && network.prefix_len() == 128))
                .then_some(network.addr())
        })
        .ok_or_else(|| anyhow::anyhow!("peer has no host AllowedIP for in-band control"))?;
    let local_address = local_addresses
        .iter()
        .copied()
        .find(|address| address.is_ipv4() == remote_address.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("no matching local WireGuard address family"))?;
    let local = shortcut::cascade::CascadePeer {
        public_key: local_public_key.to_string(),
        peer_id: local_public_key.to_string(),
        endpoint_candidates: vec![],
    };
    let remote = shortcut::cascade::CascadePeer {
        public_key: peer.public_key.clone(),
        peer_id: peer.public_key.clone(),
        endpoint_candidates: vec![],
    };
    let pair = shortcut::cascade::plan(shortcut::cascade::CascadeRequest {
        issuer_public_key: local_public_key,
        upstream: &local,
        downstream: &remote,
        upstream_selector: host_selector(remote_address),
        downstream_selector: host_selector(local_address),
        parent: None,
        now,
    })?;
    shortcut::base_control::send(
        local_address,
        remote_address,
        &shortcut::control::ControlMessage::Ticket {
            ticket: pair.downstream,
        },
    )
    .await?;
    controller
        .receive_ticket(pair.upstream, local_public_key, now, outbound)
        .await
}

fn host_selector(address: IpAddr) -> ipnet::IpNet {
    match address {
        IpAddr::V4(address) => ipnet::Ipv4Net::new(address, 32).unwrap().into(),
        IpAddr::V6(address) => ipnet::Ipv6Net::new(address, 128).unwrap().into(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn debug_error(message: &str, error: &anyhow::Error) {
    tracing::debug!(%error, "{message}");
}

fn short(key: &str) -> &str {
    key.get(..8).unwrap_or(key)
}
