mod broker;
mod config;
mod discovery;
mod easytier;
mod identity;
mod management;
mod metrics;
mod shortcut;
mod wireguard;

use anyhow::Result;
use broker::{PathSet, PathTarget, RelayChannel};
use clap::Parser;
use config::Config;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{RwLock, mpsc},
    task::JoinHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const BASE_HANDSHAKE_LIFETIME_SECONDS: u64 = 180;
const HUB_SHORTCUT_RENEWAL_LEAD_SECONDS: u64 = 30;

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
    let management = management::ManagementState::default();
    let management_task = tokio::spawn(management::run(
        config.management_listen,
        management.clone(),
    ));
    if !config.management_listen.ip().is_loopback() {
        warn!(listen = %config.management_listen, "management interface is exposed beyond loopback");
    }
    if !config.disable_public_relay {
        tokio::spawn(easytier::run_public_relay_service(config.public_relay_port));
    }

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
                    let task = tokio::spawn(run_generation(
                        config.clone(),
                        snapshot,
                        management.clone(),
                        cancel.clone(),
                    ));
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
        if management_task.is_finished() {
            return management_task.await?;
        }
    }
}

async fn run_generation(
    config: Config,
    snapshot: wireguard::Snapshot,
    management: management::ManagementState,
    cancel: CancellationToken,
) {
    let generation_cancel = cancel.child_token();
    let result =
        run_generation_inner(config, snapshot, management, generation_cancel.clone()).await;
    generation_cancel.cancel();
    sleep(Duration::from_millis(1_200)).await;
    if let Err(error) = result {
        error!(%error, "wg-link generation failed");
    }
}

async fn run_generation_inner(
    config: Config,
    snapshot: wireguard::Snapshot,
    management: management::ManagementState,
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
    let mut path_maps = HashMap::<String, Arc<RwLock<PathSet>>>::new();
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
        let paths = Arc::new(RwLock::new(PathSet::default()));
        let (inbound_sender, inbound_receiver) = mpsc::channel(256);
        broker_tasks.push(tokio::spawn(broker::run_peer(
            peer.public_key.clone(),
            peer_port,
            snapshot.listen_port,
            paths.clone(),
            management.metrics.clone(),
            inbound_receiver,
            cancel.child_token(),
        )));
        path_maps.insert(peer.public_key.clone(), paths);
        inbound_senders.insert(peer.public_key.clone(), inbound_sender);
        baselines.insert(peer.public_key.clone(), peer.latest_handshake);
        managed_ports.insert(peer.public_key.clone(), peer_port);
    }

    let mut relay_tasks = Vec::new();
    let mut dynamic_targets = Vec::new();
    let (shortcut_inbound_sender, mut shortcut_inbound_receiver) = mpsc::channel(256);
    for (relay_index, relay) in config.relays.iter().enumerate() {
        let path_id = format!("et-{}", &blake3::hash(relay.as_bytes()).to_hex()[..12]);
        let protocol = url::Url::parse(relay)
            .ok()
            .map(|url| url.scheme().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let listener_port = identity::derive_port(
            config.listener_port_base,
            3_500,
            "easytier-listener",
            &[&snapshot.public_key, relay],
        );
        let (relay_sender, relay_receiver) = mpsc::channel(256);
        dynamic_targets.push(PathTarget {
            id: path_id.clone(),
            label: format!("relay-{}", relay_index + 1),
            protocol: protocol.clone(),
            sender: relay_sender.clone(),
        });
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
                management.metrics.register_path(&peer.public_key, &path_id);
                paths.write().await.targets.push(PathTarget {
                    id: path_id.clone(),
                    label: format!("relay-{}", relay_index + 1),
                    protocol: protocol.clone(),
                    sender: relay_sender.clone(),
                });
            }
        }
        relay_tasks.push(tokio::spawn(easytier::run_relay(
            config.clone(),
            easytier::RelaySpec {
                local_public_key: snapshot.public_key.clone(),
                path_id: path_id.clone(),
                relay: relay.clone(),
                listener_port,
                peers: peer_routes,
                shortcut_inbound: shortcut_inbound_sender.clone(),
                outbound: relay_receiver,
                metrics: management.metrics.clone(),
            },
            cancel.child_token(),
        )));
    }

    management
        .replace_generation(
            &config.interface,
            path_maps
                .iter()
                .map(|(peer_key, paths)| (peer_key.clone(), paths.clone()))
                .collect(),
        )
        .await;

    let policy = shortcut::policy::SystemPolicy::new_with_source(
        SHORTCUT_TUN,
        interface_addresses
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("missing local WireGuard source address"))?,
    );
    policy.cleanup_stale()?;
    policy.ensure_control_bypass()?;

    let (shortcut_outbound, shortcut_dispatch_receiver) = mpsc::channel(256);
    let shortcut_dispatch_task = tokio::spawn(broker::run_dispatcher(
        path_maps.clone(),
        dynamic_targets,
        management.metrics.clone(),
        shortcut_dispatch_receiver,
        cancel.child_token(),
    ));
    let device_runtime = shortcut::device::start(SHORTCUT_TUN, cancel.child_token())?;
    let shortcut::device::DeviceRuntime {
        handle: device,
        routes,
        mut events,
        task: device_task,
    } = device_runtime;
    let route_manager = shortcut::policy::AtomicRouteManager::new(routes, policy);
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
    let mut hub_issues = HashMap::<HubIssueKey, u64>::new();
    let mut poll = tokio::time::interval(config.poll_interval());
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = poll.tick() => {
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
                issue_hub_shortcuts(
                    &snapshot.public_key,
                    &interface_addresses,
                    &current_snapshot,
                    now,
                    &mut hub_issues,
                ).await;
                for session in controller.expire(now)? {
                    device.remove(session).await?;
                }
            }
            control = control_receiver.recv() => {
                let Some(control) = control else {
                    std::future::pending::<()>().await;
                    continue;
                };
                tracing::debug!(source = %control.source, "received shortcut control datagram");
                match control.message {
                    shortcut::control::ControlMessage::Keepalive {
                        reply_requested: true,
                    } => {
                        let Some(local_address) = interface_addresses
                            .iter()
                            .copied()
                            .find(|address| address.is_ipv4() == control.source.is_ipv4())
                        else {
                            continue;
                        };
                        if let Err(error) = shortcut::base_control::send(
                            local_address,
                            control.source,
                            &shortcut::control::ControlMessage::Keepalive {
                                reply_requested: false,
                            },
                        )
                        .await
                        {
                            debug_error("shortcut control keepalive response failed", &error);
                        }
                    }
                    shortcut::control::ControlMessage::Keepalive {
                        reply_requested: false,
                    } => {}
                    shortcut::control::ControlMessage::Ticket { ticket } => {
                        let now = unix_now();
                        let Some(sender) = current_snapshot.route_peer(control.source, None) else {
                            tracing::debug!(source = %control.source, "shortcut control source is not an AllowedIP");
                            continue;
                        };
                        if !fresh_handshake(sender.latest_handshake, now) {
                            tracing::debug!(peer = %short(&sender.public_key), latest_handshake = sender.latest_handshake, now, "shortcut control base handshake is stale");
                            continue;
                        }
                        let sender_key = sender.public_key.clone();
                        match controller.receive_ticket(ticket, &sender_key, now, shortcut_outbound.clone()).await {
                            Ok(_) => {}
                            Err(error) => debug_error("shortcut ticket rejected", &error),
                        }
                    }
                    shortcut::control::ControlMessage::Revoke { .. }
                    | shortcut::control::ControlMessage::Status { .. } => {}
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
                if let shortcut::device::DeviceEvent::SessionFailed { session } = event {
                    match controller.fail(session) {
                        Ok(true) => {
                            info!(?session, "removed failed shortcut session");
                        }
                        Ok(false) => {}
                        Err(error) => debug_error("failed to remove shortcut session", &error),
                    }
                    continue;
                }
                let authenticated_session = match event {
                    shortcut::device::DeviceEvent::AuthenticatedHandshake { session } => Some(session),
                    _ => None,
                };
                match controller.handle_device_event(&event, now) {
                    Ok(outcome) => {
                        if outcome.activated && let Some(session) = authenticated_session {
                            info!(?session, "authenticated received shortcut route");
                        }
                        for session in outcome.retired {
                            device.remove(session).await?;
                            info!(?session, "retired replaced shortcut session");
                        }
                    }
                    Err(error) => {
                        debug_error("shortcut device event rejected", &error);
                        if let Some(session) = authenticated_session {
                            if let Err(remove_error) = controller.fail(session) {
                                debug_error("failed to discard rejected shortcut session", &remove_error);
                            }
                            if let Err(remove_error) = device.remove(session).await {
                                debug_error("failed to remove rejected shortcut device session", &remove_error);
                            }
                        }
                    }
                }
            }
        }
    }

    cancel.cancel();
    for session in controller.expire(u64::MAX)? {
        let _ = device.remove(session).await;
    }
    match device_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(%error, "shortcut device stopped with error"),
        Err(error) => warn!(%error, "shortcut device task failed"),
    }
    for task in control_tasks {
        let _ = task.await;
    }
    for task in broker_tasks {
        let _ = task.await;
    }
    match shortcut_dispatch_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(%error, "shortcut path dispatcher stopped with error"),
        Err(error) => warn!(%error, "shortcut path dispatcher task failed"),
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HubIssueKey {
    left_public_key: String,
    right_public_key: String,
}

async fn issue_hub_shortcuts(
    issuer_public_key: &str,
    interface_addresses: &[IpAddr],
    snapshot: &wireguard::Snapshot,
    now: u64,
    issues: &mut HashMap<HubIssueKey, u64>,
) {
    if snapshot.peers.len() < 2 {
        return;
    }
    for left_index in 0..snapshot.peers.len() {
        for right_index in left_index + 1..snapshot.peers.len() {
            let left = &snapshot.peers[left_index];
            let right = &snapshot.peers[right_index];
            let (Some(left_address), Some(right_address)) =
                (host_allowed_address(left), host_allowed_address(right))
            else {
                continue;
            };
            if left_address.is_ipv4() != right_address.is_ipv4() {
                continue;
            }
            let Some(local_address) = interface_addresses
                .iter()
                .copied()
                .find(|address| address.is_ipv4() == left_address.is_ipv4())
            else {
                continue;
            };
            let key = ordered_hub_issue_key(&left.public_key, &right.public_key);
            if now < issues.get(&key).copied().unwrap_or_default() {
                continue;
            }
            if !renewable_handshake(left.latest_handshake, now)
                || !renewable_handshake(right.latest_handshake, now)
            {
                match refresh_hub_handshakes(local_address, left_address, right_address).await {
                    Ok(()) => {
                        issues.insert(key, now.saturating_add(1));
                        tracing::debug!(
                            left = %short(&left.public_key),
                            right = %short(&right.public_key),
                            "refreshed Hub base handshakes before shortcut renewal"
                        );
                    }
                    Err(error) => {
                        issues.insert(key, now.saturating_add(5));
                        debug_error("Hub base handshake refresh failed", &error);
                    }
                }
                continue;
            }
            match issue_peer_pair(
                issuer_public_key,
                local_address,
                left,
                left_address,
                right,
                right_address,
                now,
            )
            .await
            {
                Ok(next_issue) => {
                    issues.insert(key, next_issue);
                }
                Err(error) => {
                    issues.insert(key, now.saturating_add(5));
                    debug_error("peer shortcut issue failed", &error);
                }
            }
        }
    }
}

async fn refresh_hub_handshakes(
    local_address: IpAddr,
    left_address: IpAddr,
    right_address: IpAddr,
) -> Result<()> {
    let keepalive = shortcut::control::ControlMessage::Keepalive {
        reply_requested: true,
    };
    shortcut::base_control::send(local_address, left_address, &keepalive).await?;
    shortcut::base_control::send(local_address, right_address, &keepalive).await?;
    Ok(())
}

async fn issue_peer_pair(
    issuer_public_key: &str,
    local_address: IpAddr,
    left: &wireguard::Peer,
    left_address: IpAddr,
    right: &wireguard::Peer,
    right_address: IpAddr,
    now: u64,
) -> Result<u64> {
    let (pair, next_issue) = plan_peer_pair(
        issuer_public_key,
        left,
        left_address,
        right,
        right_address,
        now,
    )?;
    shortcut::base_control::send(
        local_address,
        left_address,
        &shortcut::control::ControlMessage::Ticket {
            ticket: pair.upstream,
        },
    )
    .await?;
    shortcut::base_control::send(
        local_address,
        right_address,
        &shortcut::control::ControlMessage::Ticket {
            ticket: pair.downstream,
        },
    )
    .await?;
    info!(
        left = %short(&left.public_key),
        right = %short(&right.public_key),
        next_issue,
        "issued endpoint-to-endpoint shortcut tickets"
    );
    Ok(next_issue)
}

fn plan_peer_pair(
    issuer_public_key: &str,
    left: &wireguard::Peer,
    left_address: IpAddr,
    right: &wireguard::Peer,
    right_address: IpAddr,
    now: u64,
) -> Result<(shortcut::cascade::ShortcutTicketPair, u64)> {
    let period = identity::peer_id_period(now);
    let left_peer = shortcut::cascade::CascadePeer {
        public_key: left.public_key.clone(),
        peer_id: identity::rotating_node_name(&left.public_key, period),
        endpoint_candidates: vec![],
    };
    let right_peer = shortcut::cascade::CascadePeer {
        public_key: right.public_key.clone(),
        peer_id: identity::rotating_node_name(&right.public_key, period),
        endpoint_candidates: vec![],
    };
    let handshake_deadline = [left.latest_handshake, right.latest_handshake]
        .into_iter()
        .map(|handshake| handshake.saturating_add(BASE_HANDSHAKE_LIFETIME_SECONDS))
        .min()
        .unwrap_or(now);
    let pair = shortcut::cascade::plan(shortcut::cascade::CascadeRequest {
        issuer_public_key,
        upstream: &left_peer,
        downstream: &right_peer,
        upstream_selector: host_selector(right_address),
        downstream_selector: host_selector(left_address),
        parent: None,
        expires_at_limit: Some(handshake_deadline),
        renew_after_seconds: None,
        now,
    })?;
    let next_issue = pair
        .upstream
        .renew_at
        .saturating_sub(HUB_SHORTCUT_RENEWAL_LEAD_SECONDS)
        .max(now + 1);
    Ok((pair, next_issue))
}

fn ordered_hub_issue_key(left: &str, right: &str) -> HubIssueKey {
    if left <= right {
        HubIssueKey {
            left_public_key: left.to_string(),
            right_public_key: right.to_string(),
        }
    } else {
        HubIssueKey {
            left_public_key: right.to_string(),
            right_public_key: left.to_string(),
        }
    }
}

fn fresh_handshake(latest_handshake: u64, now: u64) -> bool {
    latest_handshake != 0 && now.saturating_sub(latest_handshake) <= BASE_HANDSHAKE_LIFETIME_SECONDS
}

fn renewable_handshake(latest_handshake: u64, now: u64) -> bool {
    fresh_handshake(latest_handshake, now)
        && now.saturating_add(shortcut::control::DEFAULT_RENEW_AFTER_SECONDS + 1)
            <= latest_handshake.saturating_add(BASE_HANDSHAKE_LIFETIME_SECONDS)
}

fn host_allowed_address(peer: &wireguard::Peer) -> Option<IpAddr> {
    peer.allowed_ips.iter().find_map(|network| {
        ((network.addr().is_ipv4() && network.prefix_len() == 32)
            || (network.addr().is_ipv6() && network.prefix_len() == 128))
            .then_some(network.addr())
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    fn peer(public_key: &str, address: &str) -> wireguard::Peer {
        wireguard::Peer {
            public_key: public_key.into(),
            endpoint: None,
            allowed_ips: vec![address.parse::<IpNet>().unwrap()],
            latest_handshake: 7_200,
            receive_bytes: 0,
            transmit_bytes: 0,
        }
    }

    #[test]
    fn hub_pair_tickets_connect_endpoints_without_hub_as_remote() {
        let left = peer("left-public-key", "192.168.38.2/32");
        let right = peer("right-public-key", "192.168.38.3/32");
        let (pair, next_issue) = plan_peer_pair(
            "hub-public-key",
            &left,
            "192.168.38.2".parse().unwrap(),
            &right,
            "192.168.38.3".parse().unwrap(),
            7_200,
        )
        .unwrap();
        assert_eq!(pair.upstream.shortcut_id, pair.downstream.shortcut_id);
        assert_eq!(pair.upstream.issuer_public_key, "hub-public-key");
        assert_eq!(pair.upstream.recipient_public_key, "left-public-key");
        assert_eq!(pair.upstream.remote_public_key, "right-public-key");
        assert_eq!(pair.upstream.selector.to_string(), "192.168.38.3/32");
        assert_eq!(pair.downstream.recipient_public_key, "right-public-key");
        assert_eq!(pair.downstream.remote_public_key, "left-public-key");
        assert_eq!(pair.downstream.selector.to_string(), "192.168.38.2/32");
        assert!(!pair.upstream.remote_peer_id.contains("hub"));
        assert_eq!(pair.upstream.renew_at, 7_320);
        assert_eq!(pair.upstream.expires_at, 7_380);
        assert_eq!(next_issue, 7_290);
    }

    #[test]
    fn hub_issue_key_is_order_independent() {
        assert_eq!(
            ordered_hub_issue_key("left", "right"),
            ordered_hub_issue_key("right", "left")
        );
    }

    #[test]
    fn hub_does_not_reissue_near_handshake_deadline() {
        assert!(renewable_handshake(7_200, 7_200));
        assert!(!renewable_handshake(7_200, 7_260));
        assert!(fresh_handshake(7_200, 7_350));
    }
}
