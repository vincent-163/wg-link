use crate::shortcut::control::ControlMessage;
use anyhow::{Context, Result, bail};
use pnet::datalink::{self, Channel, Config as DataLinkConfig};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

pub const CONTROL_PORT: u16 = 51_821;

pub struct ReceivedControl {
    pub source: IpAddr,
    pub message: ControlMessage,
}

pub struct ControlRuntime {
    pub receiver: mpsc::Receiver<ReceivedControl>,
    pub tasks: Vec<JoinHandle<Result<()>>>,
}

pub async fn start(
    addresses: &[IpAddr],
    interface_name: &str,
    cancel: CancellationToken,
) -> Result<ControlRuntime> {
    if addresses.is_empty() {
        bail!("WireGuard interface has no usable address for shortcut control");
    }
    let (sender, receiver) = mpsc::channel(256);
    let mut tasks = Vec::new();
    let interface = interface_name.to_string();
    let network_sender = sender.clone();
    let network_cancel = cancel.child_token();
    tasks.push(tokio::task::spawn_blocking(move || {
        capture_interface(&interface, network_sender, network_cancel)
    }));
    for address in addresses {
        let socket = UdpSocket::bind(SocketAddr::new(*address, CONTROL_PORT))
            .await
            .with_context(|| format!("failed to bind shortcut control on {address}"))?;
        let sender = sender.clone();
        let cancel = cancel.child_token();
        tasks.push(tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    received = socket.recv_from(&mut buffer) => {
                        let (length, source) = match received {
                            Ok(received) => received,
                            Err(error) => {
                                warn!(%error, "shortcut control socket receive failed; retrying");
                                continue;
                            }
                        };
                        let message = match ControlMessage::decode(&buffer[..length]) {
                            Ok(message) => message,
                            Err(error) => {
                                warn!(%source, %error, "ignored invalid shortcut control datagram");
                                continue;
                            }
                        };
                        sender.send(ReceivedControl { source: source.ip(), message }).await
                            .context("shortcut control receiver stopped")?;
                    }
                }
            }
        }));
    }
    Ok(ControlRuntime { receiver, tasks })
}

fn capture_interface(
    interface_name: &str,
    sender: mpsc::Sender<ReceivedControl>,
    cancel: CancellationToken,
) -> Result<()> {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == interface_name)
        .ok_or_else(|| {
            anyhow::anyhow!("WireGuard interface {interface_name} is not visible to packet capture")
        })?;
    let config = DataLinkConfig {
        read_timeout: Some(Duration::from_secs(1)),
        ..Default::default()
    };
    let (_, mut receiver) = match datalink::channel(&interface, config)? {
        Channel::Ethernet(sender, receiver) => (sender, receiver),
        _ => bail!("unsupported packet capture channel for {interface_name}"),
    };
    while !cancel.is_cancelled() {
        let packet = match receiver.next() {
            Ok(packet) => packet,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::TimedOut {
                    continue;
                }
                if !cancel.is_cancelled() {
                    warn!(%error, "WireGuard packet capture failed; retrying");
                }
                continue;
            }
        };
        let Some((source, payload)) = ipv4_udp_payload(packet) else {
            continue;
        };
        if payload.len() < 8 || u16::from_be_bytes([payload[2], payload[3]]) != CONTROL_PORT {
            continue;
        }
        let body = &payload[8..];
        let message = match ControlMessage::decode(body) {
            Ok(message) => message,
            Err(error) => {
                debug!(%error, "ignored invalid captured shortcut control datagram");
                continue;
            }
        };
        if sender
            .blocking_send(ReceivedControl { source, message })
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

fn ipv4_udp_payload(packet: &[u8]) -> Option<(IpAddr, &[u8])> {
    let offset = if packet.first().is_some_and(|byte| byte >> 4 == 4) {
        0
    } else if packet.len() >= 14 && packet[14] >> 4 == 4 {
        14
    } else {
        return None;
    };
    let packet = &packet[offset..];
    if packet.len() < 20 || packet[9] != 17 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }
    let source = IpAddr::V4(std::net::Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    Some((source, &packet[header_len..]))
}

pub async fn send(local: IpAddr, target: IpAddr, message: &ControlMessage) -> Result<()> {
    if local.is_ipv4() != target.is_ipv4() {
        bail!("shortcut control address families do not match");
    }
    let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await?;
    if local.is_ipv4() {
        socket.set_ttl(1)?;
    }
    let frame = message.encode()?;
    socket
        .send_to(&frame, SocketAddr::new(target, CONTROL_PORT))
        .await
        .context("failed to send in-band shortcut ticket")?;
    Ok(())
}
