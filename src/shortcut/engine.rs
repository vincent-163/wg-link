use crate::shortcut::control::DerivedKeys;
use anyhow::{Result, bail};
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use std::net::IpAddr;

const MAX_PACKET_SIZE: usize = 65_535 + 256;
const HANDSHAKE_INITIATION: u32 = 1;
const HANDSHAKE_RESPONSE: u32 = 2;
const COOKIE_REPLY: u32 = 3;
const TRANSPORT_DATA: u32 = 4;

#[derive(Debug, Default)]
pub struct TunnelOutput {
    pub network_packets: Vec<Vec<u8>>,
    pub tunnel_packets: Vec<Vec<u8>>,
    pub authenticated_handshake: bool,
}

pub struct ShortcutTunnel {
    tunnel: Tunn,
}

impl ShortcutTunnel {
    pub fn new(keys: DerivedKeys, index: u32) -> Self {
        let tunnel = Tunn::new(
            StaticSecret::from(keys.local_private),
            PublicKey::from(keys.remote_public),
            Some(keys.preshared_key),
            Some(25),
            index,
            None,
        );
        Self { tunnel }
    }

    pub fn encapsulate(&mut self, packet: &[u8]) -> Result<TunnelOutput> {
        let mut destination = vec![0; MAX_PACKET_SIZE];
        let mut output = TunnelOutput::default();
        collect_result(
            self.tunnel.encapsulate(packet, &mut destination),
            &mut output,
        )?;
        Ok(output)
    }

    pub fn receive(&mut self, source: Option<IpAddr>, datagram: &[u8]) -> Result<TunnelOutput> {
        let message_type = wireguard_message_type(datagram);
        let mut output = TunnelOutput::default();
        let mut destination = vec![0; MAX_PACKET_SIZE];
        let mut first = true;

        loop {
            let result = self.tunnel.decapsulate(
                source,
                if first { datagram } else { &[] },
                &mut destination,
            );
            let delivered = !matches!(result, TunnResult::Done);
            collect_result(result, &mut output)?;
            first = false;
            if !delivered {
                break;
            }
        }
        output.authenticated_handshake = match message_type {
            Some(HANDSHAKE_INITIATION) => output
                .network_packets
                .iter()
                .any(|packet| wireguard_message_type(packet) == Some(HANDSHAKE_RESPONSE)),
            Some(HANDSHAKE_RESPONSE) => output
                .network_packets
                .iter()
                .any(|packet| wireguard_message_type(packet) == Some(TRANSPORT_DATA)),
            Some(COOKIE_REPLY | TRANSPORT_DATA) | None | Some(_) => false,
        };
        Ok(output)
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.stats().0
    }

    pub fn update_timers(&mut self) -> Result<TunnelOutput> {
        let mut destination = vec![0; MAX_PACKET_SIZE];
        let mut output = TunnelOutput::default();
        collect_result(self.tunnel.update_timers(&mut destination), &mut output)?;
        Ok(output)
    }
}

fn collect_result(result: TunnResult<'_>, output: &mut TunnelOutput) -> Result<()> {
    match result {
        TunnResult::Done => {}
        TunnResult::Err(error) => bail!("shortcut WireGuard packet failed: {error:?}"),
        TunnResult::WriteToNetwork(packet) => output.network_packets.push(packet.to_vec()),
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            output.tunnel_packets.push(packet.to_vec())
        }
    }
    Ok(())
}

fn wireguard_message_type(datagram: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(datagram.get(..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortcut::control::{CONTROL_VERSION, ShortcutId, ShortcutRole, ShortcutTicket};
    use ipnet::IpNet;
    use std::str::FromStr;

    fn ticket(role: ShortcutRole) -> ShortcutTicket {
        ShortcutTicket {
            version: CONTROL_VERSION,
            shortcut_id: ShortcutId([3; 16]),
            epoch: 8,
            role,
            issued_at: 1_000,
            renew_at: 1_120,
            expires_at: 1_180,
            selector: IpNet::from_str("198.51.100.7/32").unwrap(),
            issuer_public_key: "issuer".into(),
            recipient_public_key: "recipient".into(),
            remote_public_key: "remote".into(),
            remote_peer_id: "peer-id".into(),
            endpoint_candidates: vec![],
            delegation: None,
            master_secret: [4; 32],
        }
    }

    fn ipv4_packet() -> [u8; 20] {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[198, 51, 100, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
        packet
    }

    #[test]
    fn reports_authentication_only_after_valid_handshake_packets() {
        let mut left = ShortcutTunnel::new(ticket(ShortcutRole::Left).derive_keys(), 1);
        let mut right = ShortcutTunnel::new(ticket(ShortcutRole::Right).derive_keys(), 2);

        let initiation = left.encapsulate(&ipv4_packet()).unwrap();
        assert!(!initiation.authenticated_handshake);
        assert_eq!(initiation.network_packets.len(), 1);

        let response = right.receive(None, &initiation.network_packets[0]).unwrap();
        assert!(response.authenticated_handshake);
        assert_eq!(response.network_packets.len(), 1);

        let established = left.receive(None, &response.network_packets[0]).unwrap();
        assert!(established.authenticated_handshake);
        assert!(established.network_packets.len() >= 2);
        assert!(left.time_since_last_handshake().is_some());

        let mut decrypted = Vec::new();
        for packet in &established.network_packets {
            decrypted.extend(right.receive(None, packet).unwrap().tunnel_packets);
        }
        assert_eq!(decrypted, vec![ipv4_packet().to_vec()]);
    }
}
