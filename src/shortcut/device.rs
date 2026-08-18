use crate::{
    broker::{RelayChannel, RelayPacket},
    shortcut::{
        control::DerivedKeys,
        engine::{ShortcutTunnel, TunnelOutput},
        policy::UserspaceRoutes,
        state::{RouteTarget, SessionKey},
    },
};
use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, RwLock},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Duration, interval},
};
use tokio_tun::Tun;
use tokio_util::sync::CancellationToken;
use tracing::debug;

const DEFAULT_MTU: i32 = 1_380;
const PACKET_BUFFER_SIZE: usize = 65_535;

#[derive(Debug)]
pub enum DeviceEvent {
    HandshakeStarted {
        session: SessionKey,
    },
    AuthenticatedHandshake {
        session: SessionKey,
    },
    InnerPacket {
        session: SessionKey,
        source: IpAddr,
        destination: IpAddr,
    },
    MissingRoute {
        destination: IpAddr,
    },
}

#[derive(Clone)]
pub struct DeviceHandle {
    commands: mpsc::Sender<DeviceCommand>,
}

impl DeviceHandle {
    pub async fn prepare(
        &self,
        session: SessionKey,
        keys: DerivedKeys,
        remote_public_key: String,
        outbound: mpsc::Sender<RelayPacket>,
    ) -> Result<()> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(DeviceCommand::Prepare {
                session,
                keys,
                remote_public_key,
                outbound,
                reply,
            })
            .await
            .context("shortcut device stopped before session preparation")?;
        response
            .await
            .context("shortcut device dropped session preparation response")?
    }

    pub async fn receive(
        &self,
        session: SessionKey,
        source_public_key: String,
        datagram: Vec<u8>,
    ) -> Result<()> {
        self.commands
            .send(DeviceCommand::Receive {
                session,
                source_public_key,
                datagram,
            })
            .await
            .context("shortcut device stopped before receiving datagram")
    }

    pub async fn remove(&self, session: SessionKey) -> Result<()> {
        self.commands
            .send(DeviceCommand::Remove { session })
            .await
            .context("shortcut device stopped before session removal")
    }
}

#[derive(Clone, Default)]
pub struct DeviceRoutes {
    routes: Arc<RwLock<HashMap<IpNet, RouteTarget>>>,
}

impl DeviceRoutes {
    fn lookup(&self, destination: IpAddr) -> Option<RouteTarget> {
        self.routes
            .read()
            .ok()?
            .iter()
            .filter(|(network, _)| network.contains(&destination))
            .max_by_key(|(network, _)| network.prefix_len())
            .map(|(_, target)| *target)
    }
}

impl UserspaceRoutes for DeviceRoutes {
    fn replace(&mut self, selector: IpNet, target: RouteTarget) -> Result<()> {
        self.routes
            .write()
            .map_err(|_| anyhow!("shortcut userspace route lock is poisoned"))?
            .insert(selector, target);
        Ok(())
    }

    fn remove(&mut self, selector: IpNet) -> Result<()> {
        self.routes
            .write()
            .map_err(|_| anyhow!("shortcut userspace route lock is poisoned"))?
            .remove(&selector);
        Ok(())
    }
}

pub struct DeviceRuntime {
    pub handle: DeviceHandle,
    pub routes: DeviceRoutes,
    pub events: mpsc::Receiver<DeviceEvent>,
    pub task: JoinHandle<Result<()>>,
}

pub fn start(name: &str, cancel: CancellationToken) -> Result<DeviceRuntime> {
    let mut devices = Tun::builder()
        .name(name)
        .mtu(DEFAULT_MTU)
        .up()
        .build()
        .with_context(|| format!("failed to create non-persistent shortcut TUN {name}"))?;
    let tun = devices
        .pop()
        .ok_or_else(|| anyhow!("shortcut TUN builder returned no device"))?;
    let routes = DeviceRoutes::default();
    let (command_sender, command_receiver) = mpsc::channel(256);
    let (event_sender, event_receiver) = mpsc::channel(256);
    let task_routes = routes.clone();
    let task = tokio::spawn(run(
        tun,
        task_routes,
        command_receiver,
        event_sender,
        cancel,
    ));
    Ok(DeviceRuntime {
        handle: DeviceHandle {
            commands: command_sender,
        },
        routes,
        events: event_receiver,
        task,
    })
}

enum DeviceCommand {
    Prepare {
        session: SessionKey,
        keys: DerivedKeys,
        remote_public_key: String,
        outbound: mpsc::Sender<RelayPacket>,
        reply: oneshot::Sender<Result<()>>,
    },
    Receive {
        session: SessionKey,
        source_public_key: String,
        datagram: Vec<u8>,
    },
    Remove {
        session: SessionKey,
    },
}

struct SessionRuntime {
    session: SessionKey,
    tunnel: ShortcutTunnel,
    remote_public_key: String,
    outbound: mpsc::Sender<RelayPacket>,
}

async fn run(
    tun: Tun,
    routes: DeviceRoutes,
    mut commands: mpsc::Receiver<DeviceCommand>,
    events: mpsc::Sender<DeviceEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut sessions = HashMap::<SessionKey, SessionRuntime>::new();
    let mut packet = vec![0u8; PACKET_BUFFER_SIZE];
    let mut timer = interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            received = tun.recv(&mut packet) => {
                let length = received.context("failed reading shortcut TUN")?;
                let inner = &packet[..length];
                let Some((_, destination)) = packet_addresses(inner) else {
                    continue;
                };
                let Some(target) = routes.lookup(destination) else {
                    let _ = events.send(DeviceEvent::MissingRoute { destination }).await;
                    continue;
                };
                let runtime = sessions
                    .get_mut(&target.session)
                    .ok_or_else(|| anyhow!("active shortcut route points to a missing session"))?;
                let output = runtime.tunnel.encapsulate(inner)?;
                send_network(runtime, output).await?;
            }
            command = commands.recv() => {
                let Some(command) = command else { break; };
                match command {
                    DeviceCommand::Prepare { session, keys, remote_public_key, outbound, reply } => {
                        let result = prepare_session(session, keys, remote_public_key, outbound, &mut sessions, &events).await;
                        let _ = reply.send(result);
                    }
                    DeviceCommand::Receive { session, source_public_key, datagram } => {
                        let Some(runtime) = sessions.get_mut(&session) else {
                            debug!(?session, "dropping shortcut datagram for unknown session");
                            continue;
                        };
                        if runtime.remote_public_key != source_public_key {
                            debug!(?session, "dropping shortcut datagram from unexpected peer");
                            continue;
                        }
                        let output = match runtime.tunnel.receive(None, &datagram) {
                            Ok(output) => output,
                            Err(error) => {
                                debug!(?session, %error, "dropping invalid shortcut datagram");
                                continue;
                            }
                        };
                        if output.authenticated_handshake {
                            events.send(DeviceEvent::AuthenticatedHandshake { session }).await
                                .context("shortcut event receiver stopped")?;
                        }
                        let TunnelOutput { network_packets, tunnel_packets, .. } = output;
                        for packet in tunnel_packets {
                            if let Some((source, destination)) = packet_addresses(&packet) {
                                events.send(DeviceEvent::InnerPacket { session, source, destination }).await
                                    .context("shortcut event receiver stopped")?;
                            }
                            tun.send_all(&packet).await.context("failed writing shortcut TUN")?;
                        }
                        send_packets(runtime, network_packets).await?;
                    }
                    DeviceCommand::Remove { session } => {
                        sessions.remove(&session);
                    }
                }
            }
            _ = timer.tick() => {
                for runtime in sessions.values_mut() {
                    let output = runtime.tunnel.update_timers()?;
                    send_network(runtime, output).await?;
                }
            }
        }
    }
    Ok(())
}

async fn prepare_session(
    session: SessionKey,
    keys: DerivedKeys,
    remote_public_key: String,
    outbound: mpsc::Sender<RelayPacket>,
    sessions: &mut HashMap<SessionKey, SessionRuntime>,
    events: &mpsc::Sender<DeviceEvent>,
) -> Result<()> {
    let mut runtime = SessionRuntime {
        session,
        tunnel: ShortcutTunnel::new(keys, session_index(session)),
        remote_public_key,
        outbound,
    };
    let output = runtime.tunnel.encapsulate(&[])?;
    send_network(&runtime, output).await?;
    sessions.insert(session, runtime);
    events
        .send(DeviceEvent::HandshakeStarted { session })
        .await
        .context("shortcut event receiver stopped")?;
    Ok(())
}

async fn send_network(runtime: &SessionRuntime, output: TunnelOutput) -> Result<()> {
    send_packets(runtime, output.network_packets).await
}

async fn send_packets(runtime: &SessionRuntime, packets: Vec<Vec<u8>>) -> Result<()> {
    for packet in packets {
        runtime
            .outbound
            .send(RelayPacket {
                peer_key: runtime.remote_public_key.clone(),
                channel: RelayChannel::ShortcutWireGuard {
                    session: runtime.session,
                },
                payload: packet,
            })
            .await
            .context("shortcut outer transport stopped")?;
    }
    Ok(())
}

fn session_index(session: SessionKey) -> u32 {
    let digest = blake3::hash(
        &[
            session.shortcut_id.0.as_slice(),
            session.epoch.to_le_bytes().as_slice(),
        ]
        .concat(),
    );
    u32::from_le_bytes(digest.as_bytes()[..4].try_into().expect("four-byte digest")) & 0x00ff_ffff
}

fn packet_addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some((
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?)),
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?)),
        )),
        6 if packet.len() >= 40 => Some((
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?)),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortcut::control::ShortcutId;
    use std::str::FromStr;

    fn target(epoch: u64) -> RouteTarget {
        RouteTarget {
            session: SessionKey {
                shortcut_id: ShortcutId([2; 16]),
                epoch,
            },
        }
    }

    #[test]
    fn userspace_routes_use_longest_prefix_match() {
        let mut routes = DeviceRoutes::default();
        routes
            .replace(IpNet::from_str("198.51.100.0/24").unwrap(), target(1))
            .unwrap();
        routes
            .replace(IpNet::from_str("198.51.100.7/32").unwrap(), target(2))
            .unwrap();
        assert_eq!(
            routes.lookup("198.51.100.7".parse().unwrap()),
            Some(target(2))
        );
    }

    #[test]
    fn parses_ipv4_and_ipv6_addresses() {
        let mut ipv4 = [0u8; 20];
        ipv4[0] = 0x45;
        ipv4[12..16].copy_from_slice(&[198, 51, 100, 1]);
        ipv4[16..20].copy_from_slice(&[198, 51, 100, 7]);
        assert_eq!(
            packet_addresses(&ipv4),
            Some((
                "198.51.100.1".parse().unwrap(),
                "198.51.100.7".parse().unwrap()
            ))
        );

        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60;
        ipv6[23] = 1;
        ipv6[39] = 7;
        assert!(packet_addresses(&ipv6).is_some());
    }

    #[test]
    fn session_index_is_stable_and_uses_twenty_four_bits() {
        let index = session_index(SessionKey {
            shortcut_id: ShortcutId([3; 16]),
            epoch: 4,
        });
        assert_eq!(
            index,
            session_index(SessionKey {
                shortcut_id: ShortcutId([3; 16]),
                epoch: 4,
            })
        );
        assert_eq!(index & 0xff00_0000, 0);
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN"]
    async fn nonpersistent_tun_disappears_after_runtime_stops() {
        let name = format!("wgl{:x}", std::process::id());
        let cancel = CancellationToken::new();
        let runtime = start(&name, cancel.clone()).unwrap();
        assert!(std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
        cancel.cancel();
        runtime.task.await.unwrap().unwrap();
        assert!(!std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
    }
}
