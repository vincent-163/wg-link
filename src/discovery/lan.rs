use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use pnet::datalink;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};
use tokio::{net::UdpSocket, sync::mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub const DISCOVERY_PORT: u16 = 38_391;
const DISCOVERY_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 38, 9);
const MAGIC: &[u8; 8] = b"WGLAN01\0";
const VERSION: u8 = 1;
const MAX_KEY_LEN: usize = 128;
const MAX_NETWORK_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Announcement {
    node_id: String,
    network: String,
    period: u64,
    listener_port: u16,
}

pub async fn run_loop(
    local_public_key: String,
    network: String,
    listener_port: u16,
    sender: mpsc::Sender<Vec<SocketAddr>>,
    cancel: CancellationToken,
) {
    let interfaces = local_lan_interfaces();
    if interfaces.is_empty() {
        warn!("LAN discovery disabled because no IPv4 interface was found");
        return;
    }
    let socket = match bind_socket(&interfaces) {
        Ok(socket) => socket,
        Err(error) => {
            warn!(%error, "LAN discovery socket setup failed");
            return;
        }
    };
    info!(
        port = DISCOVERY_PORT,
        interfaces = ?interfaces,
        "LAN EasyTier discovery started"
    );

    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                let announcement = encode_announcement(&Announcement {
                    node_id: crate::identity::rotating_node_id(
                        &local_public_key,
                        crate::identity::current_peer_id_period(),
                    ),
                    network: network.clone(),
                    period: crate::identity::current_peer_id_period(),
                    listener_port,
                });
                announce(&socket, &interfaces, &announcement).await;
                let candidates = receive_candidates(
                    &socket,
                    &interfaces,
                    &network,
                    &local_public_key,
                ).await;
                if !candidates.is_empty() && sender.send(candidates).await.is_err() {
                    break;
                }
            }
        }
    }
}

fn bind_socket(interfaces: &[(Ipv4Addr, Ipv4Net)]) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("create LAN discovery socket")?;
    socket
        .set_reuse_address(true)
        .context("enable LAN discovery address reuse")?;
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .context("enable LAN discovery port reuse")?;
    socket
        .set_broadcast(true)
        .context("enable LAN discovery broadcast")?;
    socket
        .bind(&SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            DISCOVERY_PORT,
        )))
        .context("bind LAN discovery socket")?;
    for (address, _) in interfaces {
        socket
            .join_multicast_v4(&DISCOVERY_GROUP, address)
            .with_context(|| format!("join LAN discovery multicast on {address}"))?;
    }
    socket
        .set_multicast_loop_v4(true)
        .context("enable LAN discovery multicast loopback")?;
    socket
        .set_nonblocking(true)
        .context("set LAN discovery nonblocking")?;
    Ok(UdpSocket::from_std(socket.into())?)
}

async fn announce(socket: &UdpSocket, interfaces: &[(Ipv4Addr, Ipv4Net)], packet: &[u8]) {
    let mut destinations = HashSet::new();
    destinations.insert(SocketAddr::V4(SocketAddrV4::new(
        DISCOVERY_GROUP,
        DISCOVERY_PORT,
    )));
    for (_, network) in interfaces {
        destinations.insert(SocketAddr::V4(SocketAddrV4::new(
            network.broadcast(),
            DISCOVERY_PORT,
        )));
    }
    for destination in destinations {
        if let Err(error) = socket.send_to(packet, destination).await {
            debug!(%destination, %error, "LAN discovery announcement send failed");
        }
    }
}

async fn receive_candidates(
    socket: &UdpSocket,
    interfaces: &[(Ipv4Addr, Ipv4Net)],
    network: &str,
    local_public_key: &str,
) -> Vec<SocketAddr> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let active_periods = crate::identity::active_peer_id_periods(unix_now());
    let mut candidates = HashSet::new();
    let mut buffer = [0u8; 512];
    loop {
        let received = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await;
        let Ok(Ok((length, source))) = received else {
            break;
        };
        let IpAddr::V4(source_ip) = source.ip() else {
            continue;
        };
        if !interfaces
            .iter()
            .any(|(_, subnet)| subnet.contains(&source_ip))
        {
            continue;
        }
        let Some(announcement) = decode_announcement(&buffer[..length]) else {
            continue;
        };
        if announcement.network != network
            || !active_periods.contains(&announcement.period)
            || announcement.node_id
                == crate::identity::rotating_node_id(local_public_key, announcement.period)
            || announcement.listener_port == 0
        {
            continue;
        }
        candidates.insert(SocketAddr::V4(SocketAddrV4::new(
            source_ip,
            announcement.listener_port,
        )));
    }
    candidates.into_iter().collect()
}

fn local_lan_interfaces() -> Vec<(Ipv4Addr, Ipv4Net)> {
    datalink::interfaces()
        .into_iter()
        .filter(|interface| {
            interface.is_up()
                && interface.is_broadcast()
                && !interface.is_loopback()
                && !interface.is_point_to_point()
                && !is_virtual_interface(&interface.name)
        })
        .flat_map(|interface| {
            interface
                .ips
                .into_iter()
                .filter_map(|network| match network.ip() {
                    IpAddr::V4(address)
                        if address.is_private()
                            && !address.is_loopback()
                            && !address.is_unspecified() =>
                    {
                        Some((address, Ipv4Net::new(address, network.prefix()).ok()?))
                    }
                    _ => None,
                })
        })
        .collect()
}

fn is_virtual_interface(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "wg",
        "wgl",
        "tun",
        "tap",
        "easy",
        "docker",
        "br-",
        "veth",
        "virbr",
        "podman",
        "cni",
        "tailscale",
        "zerotier",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn encode_announcement(announcement: &Announcement) -> Vec<u8> {
    let key = announcement.node_id.as_bytes();
    let network = announcement.network.as_bytes();
    assert!(key.len() <= MAX_KEY_LEN);
    assert!(network.len() <= MAX_NETWORK_LEN);
    let mut packet = Vec::with_capacity(32 + key.len() + network.len());
    packet.extend_from_slice(MAGIC);
    packet.push(VERSION);
    packet.extend_from_slice(&(key.len() as u16).to_be_bytes());
    packet.extend_from_slice(key);
    packet.extend_from_slice(&announcement.period.to_be_bytes());
    packet.extend_from_slice(&announcement.listener_port.to_be_bytes());
    packet.push(network.len() as u8);
    packet.extend_from_slice(network);
    packet
}

fn decode_announcement(packet: &[u8]) -> Option<Announcement> {
    if packet.len() < MAGIC.len() + 1 + 2 + 8 + 2 + 1 || &packet[..MAGIC.len()] != MAGIC {
        return None;
    }
    let mut cursor = MAGIC.len();
    if packet[cursor] != VERSION {
        return None;
    }
    cursor += 1;
    let key_len = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]) as usize;
    cursor += 2;
    if key_len == 0 || key_len > MAX_KEY_LEN || cursor + key_len + 8 + 2 + 1 > packet.len() {
        return None;
    }
    let node_id = String::from_utf8(packet[cursor..cursor + key_len].to_vec()).ok()?;
    cursor += key_len;
    let period = u64::from_be_bytes(packet[cursor..cursor + 8].try_into().ok()?);
    cursor += 8;
    let listener_port = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
    cursor += 2;
    let network_len = packet[cursor] as usize;
    cursor += 1;
    if network_len == 0 || network_len > MAX_NETWORK_LEN || cursor + network_len != packet.len() {
        return None;
    }
    let network = String::from_utf8(packet[cursor..].to_vec()).ok()?;
    Some(Announcement {
        node_id,
        network,
        period,
        listener_port,
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_round_trips_without_relay_address() {
        let announcement = Announcement {
            node_id: "0123456789abcdef".to_string(),
            network: "wglr-test".to_string(),
            period: 42,
            listener_port: 43_210,
        };
        assert_eq!(
            decode_announcement(&encode_announcement(&announcement)),
            Some(announcement)
        );
    }

    #[test]
    fn malformed_announcement_is_rejected() {
        assert!(decode_announcement(b"bad").is_none());
        let mut packet = encode_announcement(&Announcement {
            node_id: "0123456789abcdef".to_string(),
            network: "network".to_string(),
            period: 1,
            listener_port: 1,
        });
        packet[8] = 99;
        assert!(decode_announcement(&packet).is_none());
    }

    #[test]
    fn announcement_uses_rotating_node_id_instead_of_relay_or_public_key() {
        let public_key = "wg-peer-public-key";
        let period = 42;
        let announcement = Announcement {
            node_id: crate::identity::rotating_node_id(public_key, period),
            network: "wglr-test".to_string(),
            period,
            listener_port: 43_210,
        };
        let encoded = encode_announcement(&announcement);
        assert!(
            !encoded
                .windows(public_key.len())
                .any(|window| window == public_key.as_bytes())
        );
        assert!(
            !encoded
                .windows("59.110.138.44".len())
                .any(|window| window == b"59.110.138.44")
        );
    }

    #[test]
    fn virtual_interfaces_are_not_lan_discovery_sources() {
        assert!(is_virtual_interface("wg-link0"));
        assert!(is_virtual_interface("tun0"));
        assert!(is_virtual_interface("wgls0"));
        assert!(is_virtual_interface("docker0"));
        assert!(is_virtual_interface("br-deadbeef"));
        assert!(!is_virtual_interface("eno1"));
        assert!(!is_virtual_interface("eth0"));
    }

    #[test]
    fn rotating_id_does_not_require_a_preconfigured_wireguard_peer() {
        let public_key = "shortcut-peer-learned-after-ticket";
        let period = 42;
        let announcement = Announcement {
            node_id: crate::identity::rotating_node_id(public_key, period),
            network: "wglr-test".to_string(),
            period,
            listener_port: 43_210,
        };
        assert_ne!(announcement.node_id, public_key);
        assert_ne!(announcement.listener_port, DISCOVERY_PORT);
    }
}
