use crate::{
    broker::{InboundRelayPacket, RelayChannel, RelayPacket},
    config::Config,
    discovery, identity,
    shortcut::{control::ShortcutId, state::SessionKey},
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use easytier::{
    common::config::TomlConfigLoader,
    instance::instance::Instance,
    peers::PeerPacketFilter,
    tunnel::packet_def::{PacketType, ZCPacket},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use url::Url;

const LEGACY_FRAME_MAGIC: &[u8; 8] = b"WGLINK01";
const TYPED_FRAME_MAGIC: &[u8; 8] = b"WGLINK02";
const MAX_KEY_LEN: usize = 128;
const SHORTCUT_CHANNEL: u8 = 1;

#[derive(Debug)]
pub struct PeerRoute {
    pub public_key: String,
    pub inbound: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug)]
pub struct RelaySpec {
    pub local_public_key: String,
    pub relay: String,
    pub listener_port: u16,
    pub peers: Vec<PeerRoute>,
    pub shortcut_inbound: mpsc::Sender<InboundRelayPacket>,
    pub outbound: mpsc::Receiver<RelayPacket>,
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
        candidate_tx,
        discovery_cancel.clone(),
    ));
    let conn_manager = instance.get_conn_manager();
    let mut candidate_urls = HashSet::new();

    let mut peer_ids_by_hostname = HashMap::<String, u32>::new();
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
                for route in peer_manager.list_routes().await {
                    if peer_ids_by_hostname.get(&route.hostname) != Some(&route.peer_id) {
                        debug!(relay = %spec.relay, peer_id = route.peer_id, hostname = %route.hostname, "resolved EasyTier hostname to peer_id");
                    }
                    discovered.insert(route.hostname, route.peer_id);
                }
                peer_ids_by_hostname = discovered;
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
                    warn!(relay = %spec.relay, peer = %short(&packet.peer_key), dst_peer_id, %error, "EasyTier peer_id send failed");
                } else {
                    debug!(relay = %spec.relay, peer = %short(&packet.peer_key), target_period, %target_hostname, dst_peer_id, bytes = packet.payload.len(), "sent WireGuard packet by EasyTier peer_id");
                }
            }
        }
    }
    discovery_cancel.cancel();
    let _ = discovery_task.await;
    instance.clear_resources().await;
    Ok(())
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
    let mut text = format!(
        "instance_name = {}\nhostname = {}\ndhcp = false\nlisteners = [{}]\nstun_servers = [{}]\n\n[network_identity]\nnetwork_name = {}\nnetwork_secret = \"\"\n\n",
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
    if frame.len() < TYPED_FRAME_MAGIC.len() + 29
        || !frame.starts_with(TYPED_FRAME_MAGIC)
        || frame[TYPED_FRAME_MAGIC.len()] != SHORTCUT_CHANNEL
    {
        return None;
    }
    let session_offset = TYPED_FRAME_MAGIC.len() + 1;
    let shortcut_id = ShortcutId(frame[session_offset..session_offset + 16].try_into().ok()?);
    let epoch = u64::from_be_bytes(
        frame[session_offset + 16..session_offset + 24]
            .try_into()
            .ok()?,
    );
    let (source, target, payload) = decode_keys_and_payload(frame, session_offset + 24)?;
    Some(DecodedFrame {
        source,
        target,
        channel: RelayChannel::ShortcutWireGuard {
            session: SessionKey { shortcut_id, epoch },
        },
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
