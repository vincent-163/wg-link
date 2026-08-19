use crate::{
    broker::{InboundRelayPacket, RelayChannel, RelayPacket},
    config::Config,
    discovery, identity,
    metrics::MetricsRegistry,
    shortcut::{control::ShortcutId, state::SessionKey},
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use easytier::{
    common::config::TomlConfigLoader,
    instance::instance::Instance,
    peers::{PeerPacketFilter, peer_manager::PeerManager},
    tunnel::packet_def::{PacketType, ZCPacket},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use url::Url;

const LEGACY_FRAME_MAGIC: &[u8; 8] = b"WGLINK01";
const TYPED_FRAME_MAGIC: &[u8; 8] = b"WGLINK02";
const MAX_KEY_LEN: usize = 128;
const SHORTCUT_CHANNEL: u8 = 1;
const PROBE_REQUEST_CHANNEL: u8 = 2;
const PROBE_RESPONSE_CHANNEL: u8 = 3;
const MAX_IN_FLIGHT_PROBE_SENDS: usize = 8;

#[derive(Debug)]
struct ProbeSendResult {
    request: Option<(u64, String)>,
    error: Option<String>,
}

#[derive(Debug)]
pub struct PeerRoute {
    pub public_key: String,
    pub inbound: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug)]
pub struct RelaySpec {
    pub local_public_key: String,
    pub path_id: String,
    pub relay: String,
    pub listener_port: u16,
    pub peers: Vec<PeerRoute>,
    pub shortcut_inbound: mpsc::Sender<InboundRelayPacket>,
    pub outbound: mpsc::Receiver<RelayPacket>,
    pub metrics: MetricsRegistry,
}

#[derive(Debug, Clone)]
struct DiscoveryContext {
    local_public_key: String,
    listener_port: u16,
    peer_public_keys: Vec<String>,
}

struct WgPacketFilter {
    local_public_key: String,
    peers: HashMap<String, mpsc::Sender<Vec<u8>>>,
    shortcut_inbound: mpsc::Sender<InboundRelayPacket>,
    probe_inbound: mpsc::Sender<InboundRelayPacket>,
    path_id: String,
    metrics: MetricsRegistry,
}

#[async_trait]
impl PeerPacketFilter for WgPacketFilter {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let Some(header) = packet.peer_manager_header() else {
            return Some(packet);
        };
        if header.packet_type != PacketType::Data as u8 {
            return Some(packet);
        }
        let Some(frame) = decode_frame(packet.payload()) else {
            return Some(packet);
        };
        if frame.target != self.local_public_key {
            return Some(packet);
        }
        match frame.channel {
            RelayChannel::BaseWireGuard => {
                let Some(sender) = self.peers.get(frame.source) else {
                    return Some(packet);
                };
                self.metrics
                    .record_rx(frame.source, &self.path_id, frame.payload.len());
                if sender.try_send(frame.payload.to_vec()).is_err() {
                    debug!(peer = %short(frame.source), "dropping received WireGuard packet because broker is busy");
                }
            }
            RelayChannel::ShortcutWireGuard { session } => {
                if self
                    .shortcut_inbound
                    .try_send(InboundRelayPacket {
                        source_key: frame.source.to_string(),
                        channel: RelayChannel::ShortcutWireGuard { session },
                        payload: frame.payload.to_vec(),
                    })
                    .is_err()
                {
                    debug!(peer = %short(frame.source), ?session, "dropping received shortcut packet because device is busy");
                }
            }
            RelayChannel::PathProbe { .. } => {
                if self
                    .probe_inbound
                    .try_send(InboundRelayPacket {
                        source_key: frame.source.to_string(),
                        channel: frame.channel,
                        payload: frame.payload.to_vec(),
                    })
                    .is_err()
                {
                    debug!(peer = %short(frame.source), path = %self.path_id, "dropping path probe because receiver is busy");
                }
            }
        }
        None
    }
}

pub async fn run_relay(config: Config, spec: RelaySpec, cancel: CancellationToken) -> Result<()> {
    let network_name = identity::transport_network();
    let mut advertised_period = identity::current_peer_id_period();
    let discovery_context = DiscoveryContext {
        local_public_key: spec.local_public_key.clone(),
        listener_port: spec.listener_port,
        peer_public_keys: spec
            .peers
            .iter()
            .map(|peer| peer.public_key.clone())
            .collect(),
    };
    let config_text = build_config(&config, &spec, &network_name, advertised_period, &[]);
    let inbound = spec
        .peers
        .iter()
        .map(|peer| (peer.public_key.clone(), peer.inbound.clone()))
        .collect::<HashMap<_, _>>();
    let mut outbound = spec.outbound;
    let (probe_tx, mut probe_rx) = mpsc::channel(256);

    let loader = TomlConfigLoader::new_from_str(&config_text)
        .context("failed to parse generated EasyTier config")?;
    let mut instance = Instance::new(loader);
    instance
        .run()
        .await
        .context("embedded EasyTier failed to start")?;
    let peer_manager = instance.get_peer_manager();
    let global_ctx = peer_manager.get_global_ctx();
    peer_manager
        .add_peer_packet_filter(WgPacketFilter {
            local_public_key: spec.local_public_key.clone(),
            peers: inbound,
            shortcut_inbound: spec.shortcut_inbound.clone(),
            probe_inbound: probe_tx,
            path_id: spec.path_id.clone(),
            metrics: spec.metrics.clone(),
        })
        .await;

    info!(
        relay = %spec.relay,
        network = %network_name,
        peer_id_period = advertised_period,
        easytier_peer_id = peer_manager.my_peer_id(),
        listener_port = spec.listener_port,
        "embedded EasyTier peer_id transport started"
    );

    let (candidate_tx, mut candidate_rx) = mpsc::channel(8);
    let discovery_cancel = cancel.child_token();
    let discovery_task = tokio::spawn(run_discovery_loop(
        config.clone(),
        discovery_context,
        config.discovery_interval(),
        candidate_tx.clone(),
        discovery_cancel.clone(),
    ));
    let lan_discovery_task = tokio::spawn(discovery::lan::run_loop(
        spec.local_public_key.clone(),
        network_name.clone(),
        spec.listener_port,
        candidate_tx,
        cancel.child_token(),
    ));
    let conn_manager = instance.get_conn_manager();
    let mut candidate_urls = HashSet::new();

    let mut peer_ids_by_hostname = HashMap::<String, u32>::new();
    let mut pending_probes = HashMap::<u64, (String, Instant)>::new();
    let mut probe_sends = JoinSet::new();
    let mut next_probe_nonce = 1u64;
    let mut refresh = tokio::time::interval(Duration::from_secs(1));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            candidates = candidate_rx.recv() => {
                let Some(candidates) = candidates else { break; };
                for candidate in candidates {
                    let url = Url::parse(&format!("udp://{candidate}"))?;
                    if candidate_urls.insert(url.clone()) {
                        if let Err(error) = conn_manager.add_connector_by_url(url.clone()).await {
                            warn!(relay = %spec.relay, %url, %error, "failed to add discovered EasyTier candidate");
                        } else {
                            info!(relay = %spec.relay, %url, "added discovered EasyTier candidate");
                        }
                    }
                }
            }
            _ = refresh.tick() => {
                let current_period = identity::current_peer_id_period();
                if current_period != advertised_period {
                    advertised_period = current_period;
                    let hostname = identity::rotating_node_name(
                        &spec.local_public_key,
                        advertised_period,
                    );
                    global_ctx.set_hostname(hostname.clone());
                    info!(
                        relay = %spec.relay,
                        peer_id_period = advertised_period,
                        %hostname,
                        "rotated hourly EasyTier peer identity"
                    );
                }
                let mut discovered = HashMap::new();
                let mut discovered_latencies = HashMap::new();
                for route in peer_manager.list_routes().await {
                    if peer_ids_by_hostname.get(&route.hostname) != Some(&route.peer_id) {
                        debug!(relay = %spec.relay, peer_id = route.peer_id, hostname = %route.hostname, "resolved EasyTier hostname to peer_id");
                    }
                    discovered_latencies.insert(route.hostname.clone(), route.path_latency as f64);
                    discovered.insert(route.hostname, route.peer_id);
                }
                peer_ids_by_hostname = discovered;

                let now = Instant::now();
                let expired = pending_probes
                    .iter()
                    .filter(|(_, (_, sent))| now.saturating_duration_since(*sent) > Duration::from_secs(3))
                    .map(|(nonce, _)| *nonce)
                    .collect::<Vec<_>>();
                for nonce in expired {
                    if let Some((peer_key, _)) = pending_probes.remove(&nonce) {
                        spec.metrics.record_probe(&peer_key, &spec.path_id, None);
                    }
                }

                for peer in &spec.peers {
                    let resolved = resolve_peer_id(&peer_ids_by_hostname, &peer.public_key, unix_now());
                    spec.metrics.set_available(&peer.public_key, &spec.path_id, resolved.is_some());
                    let Some((_, hostname, dst_peer_id)) = resolved else {
                        spec.metrics.set_route_latency(&peer.public_key, &spec.path_id, None);
                        continue;
                    };
                    spec.metrics.set_route_latency(
                        &peer.public_key,
                        &spec.path_id,
                        discovered_latencies.get(&hostname).copied(),
                    );
                    let nonce = next_probe_nonce;
                    next_probe_nonce = next_probe_nonce.wrapping_add(1).max(1);
                    let frame = encode_frame(
                        &spec.local_public_key,
                        &peer.public_key,
                        RelayChannel::PathProbe {
                            nonce,
                            sent_micros: unix_micros(),
                            reply: false,
                        },
                        b"p",
                    );
                    let mut packet = ZCPacket::new_with_payload(&frame);
                    packet.fill_peer_manager_hdr(peer_manager.my_peer_id(), dst_peer_id, PacketType::Data as u8);
                    if queue_probe_send(
                        &mut probe_sends,
                        peer_manager.clone(),
                        packet,
                        dst_peer_id,
                        Some((nonce, peer.public_key.clone())),
                    ) {
                        pending_probes.insert(nonce, (peer.public_key.clone(), now));
                    } else {
                        spec.metrics.record_probe(&peer.public_key, &spec.path_id, None);
                        debug!(
                            relay = %spec.relay,
                            peer = %short(&peer.public_key),
                            "dropping path probe because the bounded sender set is busy"
                        );
                    }
                }
            }
            result = probe_sends.join_next(), if !probe_sends.is_empty() => {
                match result {
                    Some(Ok(ProbeSendResult { request: Some((nonce, peer_key)), error: Some(error) })) => {
                        if pending_probes.remove(&nonce).is_some() {
                            spec.metrics.record_probe(&peer_key, &spec.path_id, None);
                        }
                        debug!(relay = %spec.relay, peer = %short(&peer_key), %error, "EasyTier path probe send failed");
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        warn!(relay = %spec.relay, %error, "EasyTier path probe sender task failed");
                    }
                    None => {}
                }
            }
            probe = probe_rx.recv() => {
                let Some(probe) = probe else { break; };
                let RelayChannel::PathProbe { nonce, sent_micros, reply } = probe.channel else {
                    continue;
                };
                if reply {
                    if let Some((peer_key, sent)) = pending_probes.remove(&nonce) {
                        if peer_key == probe.source_key {
                            spec.metrics.record_probe(&peer_key, &spec.path_id, Some(sent.elapsed()));
                        }
                    }
                    continue;
                }
                let Some((_, _, dst_peer_id)) = resolve_peer_id(
                    &peer_ids_by_hostname,
                    &probe.source_key,
                    unix_now(),
                ) else {
                    continue;
                };
                let frame = encode_frame(
                    &spec.local_public_key,
                    &probe.source_key,
                    RelayChannel::PathProbe { nonce, sent_micros, reply: true },
                    b"p",
                );
                let mut packet = ZCPacket::new_with_payload(&frame);
                packet.fill_peer_manager_hdr(peer_manager.my_peer_id(), dst_peer_id, PacketType::Data as u8);
                if !queue_probe_send(
                    &mut probe_sends,
                    peer_manager.clone(),
                    packet,
                    dst_peer_id,
                    None,
                ) {
                    debug!(
                        relay = %spec.relay,
                        peer = %short(&probe.source_key),
                        "dropping path probe response because the bounded sender set is busy"
                    );
                }
            }
            packet = outbound.recv() => {
                let Some(packet) = packet else { break; };
                let Some((target_period, target_hostname, dst_peer_id)) = resolve_peer_id(
                    &peer_ids_by_hostname,
                    &packet.peer_key,
                    unix_now(),
                ) else {
                    debug!(relay = %spec.relay, peer = %short(&packet.peer_key), "dropping WireGuard packet until EasyTier peer_id is resolved");
                    continue;
                };
                let frame = encode_frame(
                    &spec.local_public_key,
                    &packet.peer_key,
                    packet.channel,
                    &packet.payload,
                );
                let mut zc_packet = ZCPacket::new_with_payload(&frame);
                zc_packet.fill_peer_manager_hdr(
                    peer_manager.my_peer_id(),
                    dst_peer_id,
                    PacketType::Data as u8,
                );
                if let Err(error) = peer_manager.send_msg_for_proxy(zc_packet, dst_peer_id).await {
                    spec.metrics.set_available(&packet.peer_key, &spec.path_id, false);
                    warn!(relay = %spec.relay, peer = %short(&packet.peer_key), dst_peer_id, %error, "EasyTier peer_id send failed");
                } else {
                    spec.metrics.record_tx(&packet.peer_key, &spec.path_id, packet.payload.len());
                    debug!(relay = %spec.relay, peer = %short(&packet.peer_key), target_period, %target_hostname, dst_peer_id, bytes = packet.payload.len(), "sent WireGuard packet by EasyTier peer_id");
                }
            }
        }
    }
    discovery_cancel.cancel();
    let _ = discovery_task.await;
    lan_discovery_task.abort();
    let _ = lan_discovery_task.await;
    probe_sends.abort_all();
    while probe_sends.join_next().await.is_some() {}
    instance.clear_resources().await;
    Ok(())
}

fn queue_probe_send(
    sends: &mut JoinSet<ProbeSendResult>,
    peer_manager: Arc<PeerManager>,
    packet: ZCPacket,
    dst_peer_id: u32,
    request: Option<(u64, String)>,
) -> bool {
    if sends.len() >= MAX_IN_FLIGHT_PROBE_SENDS {
        return false;
    }
    sends.spawn(async move {
        let error = peer_manager
            .send_msg_for_proxy(packet, dst_peer_id)
            .await
            .err()
            .map(|error| error.to_string());
        ProbeSendResult { request, error }
    });
    true
}

pub async fn run_public_relay_service(port: u16) -> Result<()> {
    let relay_network = format!("__wg_link_relay_{:032x}", rand::random::<u128>());
    let relay_secret = format!("{:032x}", rand::random::<u128>());
    let allowed_network = identity::transport_network();
    loop {
        let config_text =
            build_public_relay_config(port, &relay_network, &relay_secret, &allowed_network);
        let loader = TomlConfigLoader::new_from_str(&config_text)
            .context("failed to parse generated EasyTier public relay config")?;
        let mut instance = Instance::new(loader);
        match instance.run().await {
            Ok(()) => {
                info!(
                    port,
                    protocols = "udp,tcp",
                    "embedded EasyTier pure relay listening"
                );
                instance.get_peer_manager().wait().await;
                instance.clear_resources().await;
            }
            Err(error) => {
                warn!(port, %error, "embedded EasyTier pure relay failed; retrying");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run_discovery_loop(
    config: Config,
    context: DiscoveryContext,
    interval: Duration,
    sender: mpsc::Sender<Vec<SocketAddr>>,
    cancel: CancellationToken,
) {
    let mut first_announce = true;
    let mut local_public_ips = HashSet::new();
    loop {
        let candidates =
            discover_candidates(&config, &context, first_announce, &mut local_public_ips).await;
        first_announce = false;
        info!(
            peer_id_periods = ?identity::active_peer_id_periods(unix_now()),
            candidate_count = candidates.len(),
            "peer discovery refresh completed"
        );
        if sender.send(candidates).await.is_err() {
            break;
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

async fn discover_candidates(
    config: &Config,
    context: &DiscoveryContext,
    first_announce: bool,
    local_public_ips: &mut HashSet<IpAddr>,
) -> Vec<SocketAddr> {
    let mut candidates = Vec::new();
    match discovery::stun::public_addresses(&config.stun).await {
        Ok(addresses) => {
            for address in &addresses {
                info!(server = %config.stun, %address, "refreshed STUN public endpoint");
                local_public_ips.insert(address.ip());
            }
        }
        Err(error) => {
            warn!(server = %config.stun, %error, "STUN refresh failed");
        }
    };
    let tracker_event = if first_announce {
        discovery::tracker::AnnounceEvent::Started
    } else {
        discovery::tracker::AnnounceEvent::Update
    };
    let active_periods = identity::active_peer_id_periods(unix_now());
    for tracker in config
        .http_trackers
        .iter()
        .chain(config.udp_trackers.iter())
    {
        for period in active_periods {
            let tracker_provider =
                format!("{}|tracker|{tracker}", identity::discovery_scope(period));
            let own_peer_id = identity::peer_id(&context.local_public_key, &tracker_provider);
            let own_hash = identity::info_hash(&context.local_public_key, &tracker_provider);
            match discovery::tracker::query(
                tracker,
                own_hash,
                own_peer_id,
                context.listener_port,
                tracker_event,
            )
            .await
            {
                Ok(found) => candidates.extend(found),
                Err(error) => warn!(tracker, period, %error, "tracker self announce failed"),
            }
            for peer_key in &context.peer_public_keys {
                let peer_hash = identity::info_hash(peer_key, &tracker_provider);
                match discovery::tracker::query(
                    tracker,
                    peer_hash,
                    own_peer_id,
                    context.listener_port,
                    discovery::tracker::AnnounceEvent::Stopped,
                )
                .await
                {
                    Ok(found) => candidates.extend(found),
                    Err(error) => {
                        warn!(tracker, period, peer = %short(peer_key), %error, "tracker peer lookup failed")
                    }
                }
            }
        }
    }

    if config.dht {
        for period in active_periods {
            let dht_provider = format!("{}|dht-mainline", identity::discovery_scope(period));
            for peer_key in &context.peer_public_keys {
                match discovery::dht::announce_and_discover(
                    identity::info_hash(&context.local_public_key, &dht_provider),
                    identity::info_hash(peer_key, &dht_provider),
                    context.listener_port,
                )
                .await
                {
                    Ok(found) => candidates.extend(found),
                    Err(error) => warn!(period, %error, "DHT discovery failed"),
                }
            }
        }
    }

    candidates.retain(|candidate| {
        !is_local_candidate(candidate, local_public_ips, context.listener_port)
    });

    let mut unique = HashSet::new();
    discovery::retain_public_candidates(&mut candidates);
    candidates.retain(|candidate| unique.insert(*candidate));
    candidates
}

fn is_local_candidate(
    candidate: &SocketAddr,
    local_public_ips: &HashSet<IpAddr>,
    listener_port: u16,
) -> bool {
    candidate.port() == listener_port && local_public_ips.contains(&candidate.ip())
}

fn build_config(
    config: &Config,
    spec: &RelaySpec,
    network_name: &str,
    peer_id_period: u64,
    candidates: &[SocketAddr],
) -> String {
    let node_name = identity::rotating_node_name(&spec.local_public_key, peer_id_period);
    let instance_id = identity::rotating_instance_id(&spec.local_public_key, peer_id_period);
    let mut text = format!(
        "instance_id = {}\ninstance_name = {}\nhostname = {}\ndhcp = false\nlisteners = [{}]\nstun_servers = [{}]\n\n[network_identity]\nnetwork_name = {}\nnetwork_secret = \"\"\n\n",
        toml_string(&instance_id),
        toml_string(&node_name),
        toml_string(&node_name),
        toml_string(&format!("udp://0.0.0.0:{}", spec.listener_port)),
        toml_string(&config.stun),
        toml_string(network_name),
    );
    text.push_str(&format!("[[peer]]\nuri = {}\n\n", toml_string(&spec.relay)));
    for candidate in candidates {
        text.push_str(&format!(
            "[[peer]]\nuri = {}\n\n",
            toml_string(&format!("udp://{candidate}"))
        ));
    }
    text.push_str(
        "[flags]\nno_tun = true\nuse_smoltcp = true\nlatency_first = true\nprivate_mode = false\nrelay_network_whitelist = \"*\"\ndisable_p2p = false\ndisable_udp_hole_punching = false\nmulti_thread = false\n",
    );
    text
}

fn build_public_relay_config(
    port: u16,
    network_name: &str,
    network_secret: &str,
    allowed_network: &str,
) -> String {
    format!(
        "instance_name = \"wg-link-public-relay\"\nhostname = \"wg-link-public-relay\"\ndhcp = false\nlisteners = [\"udp://0.0.0.0:{port}\", \"tcp://0.0.0.0:{port}\"]\n\n[network_identity]\nnetwork_name = {}\nnetwork_secret = {}\n\n[flags]\nno_tun = true\nuse_smoltcp = true\nprivate_mode = false\nrelay_all_peer_rpc = true\nrelay_network_whitelist = {}\ndisable_p2p = true\ndisable_udp_hole_punching = true\ndisable_tcp_hole_punching = true\nmulti_thread = false\n",
        toml_string(network_name),
        toml_string(network_secret),
        toml_string(allowed_network),
    )
}

fn resolve_peer_id(
    peer_ids_by_hostname: &HashMap<String, u32>,
    peer_key: &str,
    unix_seconds: u64,
) -> Option<(u64, String, u32)> {
    for period in identity::active_peer_id_periods(unix_seconds) {
        let hostname = identity::rotating_node_name(peer_key, period);
        if let Some(&peer_id) = peer_ids_by_hostname.get(&hostname) {
            return Some((period, hostname, peer_id));
        }
    }
    None
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

struct DecodedFrame<'a> {
    source: &'a str,
    target: &'a str,
    channel: RelayChannel,
    payload: &'a [u8],
}

fn encode_frame(source: &str, target: &str, channel: RelayChannel, payload: &[u8]) -> Vec<u8> {
    if channel == RelayChannel::BaseWireGuard {
        return encode_legacy_frame(source, target, payload);
    }
    let mut frame = Vec::with_capacity(37 + source.len() + target.len() + payload.len());
    frame.extend_from_slice(TYPED_FRAME_MAGIC);
    match channel {
        RelayChannel::BaseWireGuard => unreachable!(),
        RelayChannel::ShortcutWireGuard { session } => {
            frame.push(SHORTCUT_CHANNEL);
            frame.extend_from_slice(&session.shortcut_id.0);
            frame.extend_from_slice(&session.epoch.to_be_bytes());
        }
        RelayChannel::PathProbe {
            nonce,
            sent_micros,
            reply,
        } => {
            frame.push(if reply {
                PROBE_RESPONSE_CHANNEL
            } else {
                PROBE_REQUEST_CHANNEL
            });
            frame.extend_from_slice(&nonce.to_be_bytes());
            frame.extend_from_slice(&sent_micros.to_be_bytes());
        }
    }
    frame.extend_from_slice(&(source.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(target.len() as u16).to_be_bytes());
    frame.extend_from_slice(source.as_bytes());
    frame.extend_from_slice(target.as_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn encode_legacy_frame(source: &str, target: &str, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(12 + source.len() + target.len() + payload.len());
    frame.extend_from_slice(LEGACY_FRAME_MAGIC);
    frame.extend_from_slice(&(source.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(target.len() as u16).to_be_bytes());
    frame.extend_from_slice(source.as_bytes());
    frame.extend_from_slice(target.as_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn decode_frame(frame: &[u8]) -> Option<DecodedFrame<'_>> {
    if frame.starts_with(LEGACY_FRAME_MAGIC) {
        let (source, target, payload) = decode_keys_and_payload(frame, LEGACY_FRAME_MAGIC.len())?;
        return Some(DecodedFrame {
            source,
            target,
            channel: RelayChannel::BaseWireGuard,
            payload,
        });
    }
    if frame.len() < TYPED_FRAME_MAGIC.len() + 21 || !frame.starts_with(TYPED_FRAME_MAGIC) {
        return None;
    }
    let channel_id = frame[TYPED_FRAME_MAGIC.len()];
    let metadata_offset = TYPED_FRAME_MAGIC.len() + 1;
    let (channel, lengths_offset) = match channel_id {
        SHORTCUT_CHANNEL => {
            if frame.len() < metadata_offset + 24 + 4 {
                return None;
            }
            let shortcut_id = ShortcutId(
                frame[metadata_offset..metadata_offset + 16]
                    .try_into()
                    .ok()?,
            );
            let epoch = u64::from_be_bytes(
                frame[metadata_offset + 16..metadata_offset + 24]
                    .try_into()
                    .ok()?,
            );
            (
                RelayChannel::ShortcutWireGuard {
                    session: SessionKey { shortcut_id, epoch },
                },
                metadata_offset + 24,
            )
        }
        PROBE_REQUEST_CHANNEL | PROBE_RESPONSE_CHANNEL => {
            if frame.len() < metadata_offset + 16 + 4 {
                return None;
            }
            let nonce = u64::from_be_bytes(
                frame[metadata_offset..metadata_offset + 8]
                    .try_into()
                    .ok()?,
            );
            let sent_micros = u64::from_be_bytes(
                frame[metadata_offset + 8..metadata_offset + 16]
                    .try_into()
                    .ok()?,
            );
            (
                RelayChannel::PathProbe {
                    nonce,
                    sent_micros,
                    reply: channel_id == PROBE_RESPONSE_CHANNEL,
                },
                metadata_offset + 16,
            )
        }
        _ => return None,
    };
    let (source, target, payload) = decode_keys_and_payload(frame, lengths_offset)?;
    Some(DecodedFrame {
        source,
        target,
        channel,
        payload,
    })
}

fn decode_keys_and_payload(frame: &[u8], lengths_offset: usize) -> Option<(&str, &str, &[u8])> {
    if frame.len() < lengths_offset + 4 {
        return None;
    }
    let source_len =
        u16::from_be_bytes([frame[lengths_offset], frame[lengths_offset + 1]]) as usize;
    let target_len =
        u16::from_be_bytes([frame[lengths_offset + 2], frame[lengths_offset + 3]]) as usize;
    if source_len == 0 || target_len == 0 || source_len > MAX_KEY_LEN || target_len > MAX_KEY_LEN {
        return None;
    }
    let offset = lengths_offset + 4;
    let source_end = offset.checked_add(source_len)?;
    let target_end = source_end.checked_add(target_len)?;
    if target_end >= frame.len() {
        return None;
    }
    let source = std::str::from_utf8(&frame[offset..source_end]).ok()?;
    let target = std::str::from_utf8(&frame[source_end..target_end]).ok()?;
    Some((source, target, &frame[target_end..]))
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

fn short(key: &str) -> &str {
    key.get(..8).unwrap_or(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_self_candidate_across_stun_address_families() {
        let local_public_ips = [
            "203.0.113.44".parse().unwrap(),
            "2001:4860::1".parse().unwrap(),
        ]
        .into_iter()
        .collect();

        assert!(is_local_candidate(
            &"203.0.113.44:42413".parse().unwrap(),
            &local_public_ips,
            42413,
        ));
        assert!(is_local_candidate(
            &"[2001:4860::1]:42413".parse().unwrap(),
            &local_public_ips,
            42413,
        ));
        assert!(!is_local_candidate(
            &"203.0.113.44:42414".parse().unwrap(),
            &local_public_ips,
            42413,
        ));
        assert!(!is_local_candidate(
            &"8.8.8.8:42413".parse().unwrap(),
            &local_public_ips,
            42413,
        ));
    }

    #[test]
    fn frame_round_trip() {
        let frame = encode_frame(
            "source",
            "target",
            RelayChannel::BaseWireGuard,
            b"wireguard",
        );
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.source, "source");
        assert_eq!(decoded.target, "target");
        assert_eq!(decoded.channel, RelayChannel::BaseWireGuard);
        assert_eq!(decoded.payload, b"wireguard");
    }

    #[test]
    fn shortcut_frame_round_trip() {
        let session = SessionKey {
            shortcut_id: ShortcutId([7; 16]),
            epoch: 9,
        };
        let frame = encode_frame(
            "source",
            "target",
            RelayChannel::ShortcutWireGuard { session },
            b"shortcut",
        );
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.source, "source");
        assert_eq!(decoded.target, "target");
        assert_eq!(decoded.channel, RelayChannel::ShortcutWireGuard { session });
        assert_eq!(decoded.payload, b"shortcut");
    }

    #[test]
    fn probe_frame_round_trip() {
        let channel = RelayChannel::PathProbe {
            nonce: 42,
            sent_micros: 123_456,
            reply: true,
        };
        let frame = encode_frame("source", "target", channel, b"p");
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.source, "source");
        assert_eq!(decoded.target, "target");
        assert_eq!(decoded.channel, channel);
        assert_eq!(decoded.payload, b"p");
    }

    #[test]
    fn truncated_typed_frames_are_rejected() {
        for channel in [
            SHORTCUT_CHANNEL,
            PROBE_REQUEST_CHANNEL,
            PROBE_RESPONSE_CHANNEL,
        ] {
            let mut frame = TYPED_FRAME_MAGIC.to_vec();
            frame.push(channel);
            frame.resize(28, 0);
            assert!(decode_frame(&frame).is_none());
        }
    }

    #[test]
    fn public_relay_config_is_valid_and_isolated() {
        let text =
            build_public_relay_config(11_020, "isolated-network", "secret", "allowed-network");
        TomlConfigLoader::new_from_str(&text).unwrap();
        assert!(!text.contains("[[peer]]"));
        assert!(text.contains("no_tun = true"));
        assert!(text.contains("relay_all_peer_rpc = true"));
        assert!(text.contains("relay_network_whitelist = \"allowed-network\""));
    }

    #[test]
    fn invalid_frame_is_not_consumed() {
        assert!(decode_frame(b"not wg-link").is_none());
        assert!(
            decode_frame(&encode_frame(
                "source",
                "target",
                RelayChannel::BaseWireGuard,
                &[]
            ))
            .is_none()
        );
    }

    #[test]
    fn peer_resolution_prefers_current_hour() {
        let peer_key = "peer-public-key";
        let current = identity::rotating_node_name(peer_key, 2);
        let previous = identity::rotating_node_name(peer_key, 1);
        let routes = HashMap::from([(previous, 11), (current.clone(), 22)]);

        assert_eq!(
            resolve_peer_id(&routes, peer_key, 7_200),
            Some((2, current, 22))
        );
    }

    #[test]
    fn peer_resolution_accepts_previous_hour_only() {
        let peer_key = "peer-public-key";
        let previous = identity::rotating_node_name(peer_key, 1);
        let expired = identity::rotating_node_name(peer_key, 0);
        let routes = HashMap::from([(previous.clone(), 11), (expired, 33)]);

        assert_eq!(
            resolve_peer_id(&routes, peer_key, 7_200),
            Some((1, previous, 11))
        );
    }

    #[test]
    fn peer_resolution_rejects_expired_hour() {
        let peer_key = "peer-public-key";
        let expired = identity::rotating_node_name(peer_key, 0);
        let routes = HashMap::from([(expired, 33)]);

        assert_eq!(resolve_peer_id(&routes, peer_key, 7_200), None);
    }
}
