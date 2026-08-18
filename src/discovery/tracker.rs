use anyhow::{Context, Result, bail};
use rand::Rng;
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceEvent {
    Update,
    Started,
    Stopped,
}

impl AnnounceEvent {
    fn http_value(self) -> Option<&'static str> {
        match self {
            Self::Update => None,
            Self::Started => Some("started"),
            Self::Stopped => Some("stopped"),
        }
    }

    fn udp_value(self) -> u32 {
        match self {
            Self::Update => 0,
            Self::Started => 2,
            Self::Stopped => 3,
        }
    }
}

#[derive(Debug, Deserialize)]
struct HttpTrackerResponse {
    #[serde(default, with = "serde_bytes")]
    peers: Vec<u8>,
    #[serde(default, with = "serde_bytes")]
    peers6: Vec<u8>,
    #[serde(rename = "failure reason")]
    failure_reason: Option<String>,
}

pub async fn query_http(
    tracker: &str,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    event: AnnounceEvent,
) -> Result<Vec<SocketAddr>> {
    let separator = if tracker.contains('?') { '&' } else { '?' };
    let mut request_url = format!(
        "{tracker}{separator}info_hash={}&peer_id={}&port={port}&uploaded=0&downloaded=0&left=0&compact=1&numwant=50",
        percent_bytes(&info_hash),
        percent_bytes(&peer_id),
    );
    if let Some(event) = event.http_value() {
        request_url.push_str("&event=");
        request_url.push_str(event);
    }
    let body = reqwest::Client::new()
        .get(request_url)
        .timeout(Duration::from_secs(15))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let response: HttpTrackerResponse = serde_bencode::from_bytes(&body)?;
    if let Some(reason) = response.failure_reason {
        bail!("HTTP tracker rejected announce: {reason}");
    }
    let mut peers = compact_peers_v4(&response.peers);
    peers.extend(compact_peers_v6(&response.peers6));
    Ok(peers)
}

pub async fn query_udp(
    tracker: &str,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    event: AnnounceEvent,
) -> Result<Vec<SocketAddr>> {
    let url = Url::parse(tracker)?;
    let host = url.host_str().context("UDP tracker URL has no host")?;
    let tracker_port = url.port().unwrap_or(80);
    let address = tokio::net::lookup_host((host, tracker_port))
        .await?
        .next()
        .context("UDP tracker did not resolve")?;
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(address).await?;

    let connect_tx = rand::rng().random::<u32>();
    let mut connect = [0u8; 16];
    connect[..8].copy_from_slice(&0x4172_7101_980u64.to_be_bytes());
    connect[12..].copy_from_slice(&connect_tx.to_be_bytes());
    socket.send(&connect).await?;
    let mut response = [0u8; 4096];
    let length = timeout(Duration::from_secs(8), socket.recv(&mut response)).await??;
    if length < 16
        || u32::from_be_bytes(response[0..4].try_into()?) != 0
        || u32::from_be_bytes(response[4..8].try_into()?) != connect_tx
    {
        bail!("invalid UDP tracker connect response");
    }
    let connection_id = u64::from_be_bytes(response[8..16].try_into()?);

    let announce_tx = rand::rng().random::<u32>();
    let mut announce = [0u8; 98];
    announce[..8].copy_from_slice(&connection_id.to_be_bytes());
    announce[8..12].copy_from_slice(&1u32.to_be_bytes());
    announce[12..16].copy_from_slice(&announce_tx.to_be_bytes());
    announce[16..36].copy_from_slice(&info_hash);
    announce[36..56].copy_from_slice(&peer_id);
    announce[80..84].copy_from_slice(&event.udp_value().to_be_bytes());
    announce[88..92].copy_from_slice(&rand::rng().random::<u32>().to_be_bytes());
    announce[92..96].copy_from_slice(&(-1i32).to_be_bytes());
    announce[96..98].copy_from_slice(&port.to_be_bytes());
    socket.send(&announce).await?;
    let length = timeout(Duration::from_secs(8), socket.recv(&mut response)).await??;
    if length < 20
        || u32::from_be_bytes(response[0..4].try_into()?) != 1
        || u32::from_be_bytes(response[4..8].try_into()?) != announce_tx
    {
        bail!("invalid UDP tracker announce response");
    }
    if address.is_ipv4() {
        Ok(compact_peers_v4(&response[20..length]))
    } else {
        Ok(compact_peers_v6(&response[20..length]))
    }
}

pub async fn query(
    tracker: &str,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    event: AnnounceEvent,
) -> Result<Vec<SocketAddr>> {
    match Url::parse(tracker)?.scheme() {
        "udp" => query_udp(tracker, info_hash, peer_id, port, event).await,
        "http" | "https" => query_http(tracker, info_hash, peer_id, port, event).await,
        scheme => bail!("unsupported tracker scheme {scheme}"),
    }
}

fn compact_peers_v4(bytes: &[u8]) -> Vec<SocketAddr> {
    bytes
        .chunks_exact(6)
        .map(|chunk| {
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]),
                u16::from_be_bytes([chunk[4], chunk[5]]),
            ))
        })
        .collect()
}

fn compact_peers_v6(bytes: &[u8]) -> Vec<SocketAddr> {
    bytes
        .chunks_exact(18)
        .map(|chunk| {
            let mut address = [0u8; 16];
            address.copy_from_slice(&chunk[..16]);
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address),
                u16::from_be_bytes([chunk[16], chunk[17]]),
                0,
                0,
            ))
        })
        .collect()
}

fn percent_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("%{byte:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_peers_ignores_incomplete_tail() {
        let peers = compact_peers_v4(&[8, 8, 8, 8, 0x01, 0xbb, 1, 2]);
        assert_eq!(peers, vec!["8.8.8.8:443".parse().unwrap()]);
    }

    #[test]
    fn compact_ipv6_peers_ignore_incomplete_tail() {
        let mut encoded = Ipv6Addr::LOCALHOST.octets().to_vec();
        encoded.extend_from_slice(&443u16.to_be_bytes());
        encoded.push(1);
        assert_eq!(
            compact_peers_v6(&encoded),
            vec!["[::1]:443".parse().unwrap()]
        );
    }

    #[test]
    fn percent_encoding_is_byte_safe() {
        assert_eq!(percent_bytes(&[0, 0xab, 0xff]), "%00%AB%FF");
    }

    #[test]
    fn tracker_event_values_match_bep_15() {
        assert_eq!(AnnounceEvent::Update.udp_value(), 0);
        assert_eq!(AnnounceEvent::Started.udp_value(), 2);
        assert_eq!(AnnounceEvent::Stopped.udp_value(), 3);
    }
}
