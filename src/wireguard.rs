use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use std::{collections::HashMap, net::IpAddr, process::Command};

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub public_key: String,
    pub listen_port: u16,
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<IpNet>,
    pub latest_handshake: u64,
    pub receive_bytes: u64,
    pub transmit_bytes: u64,
}

impl Snapshot {
    pub fn peer(&self, public_key: &str) -> Option<&Peer> {
        self.peers.iter().find(|peer| peer.public_key == public_key)
    }

    pub fn route_peer(
        &self,
        destination: IpAddr,
        exclude_public_key: Option<&str>,
    ) -> Option<&Peer> {
        longest_matching_prefix(&self.peers, destination, exclude_public_key)
    }
}

fn output(interface: &str, field: &str) -> Result<String> {
    let result = Command::new("wg")
        .args(["show", interface, field])
        .output()
        .with_context(|| format!("failed to run wg show {interface} {field}"))?;
    if !result.status.success() {
        bail!(
            "wg show {interface} {field} failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&result.stdout).trim().to_string())
}

fn pairs(interface: &str, field: &str) -> Result<HashMap<String, String>> {
    Ok(output(interface, field)?
        .lines()
        .filter_map(|line| line.split_once(char::is_whitespace))
        .map(|(key, value)| (key.to_string(), value.trim().to_string()))
        .collect())
}

fn triples(interface: &str, field: &str) -> Result<HashMap<String, (u64, u64)>> {
    Ok(output(interface, field)?
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((
                fields.next()?.to_string(),
                (fields.next()?.parse().ok()?, fields.next()?.parse().ok()?),
            ))
        })
        .collect())
}

fn parse_allowed_ips(value: Option<&String>) -> Vec<IpNet> {
    value
        .into_iter()
        .flat_map(|value| value.split([',', ' ', '\t']))
        .filter(|value| !value.is_empty() && *value != "(none)")
        .filter_map(|value| value.parse().ok())
        .collect()
}

fn longest_matching_prefix<'a>(
    peers: &'a [Peer],
    destination: IpAddr,
    exclude_public_key: Option<&str>,
) -> Option<&'a Peer> {
    peers
        .iter()
        .filter(|peer| Some(peer.public_key.as_str()) != exclude_public_key)
        .filter_map(|peer| {
            peer.allowed_ips
                .iter()
                .filter(|network| network.contains(&destination))
                .max_by_key(|network| network.prefix_len())
                .map(|network| (network.prefix_len(), peer))
        })
        .max_by_key(|(prefix_len, _)| *prefix_len)
        .map(|(_, peer)| peer)
}

pub fn snapshot(interface: &str) -> Result<Snapshot> {
    let public_key = output(interface, "public-key")?;
    if public_key.is_empty() {
        bail!("wireguard interface {interface} has no public key");
    }
    let listen_port = output(interface, "listen-port")?
        .parse::<u16>()
        .with_context(|| format!("invalid listen port on {interface}"))?;
    if listen_port == 0 {
        bail!("wireguard interface {interface} has no listen port");
    }

    let endpoint_map = pairs(interface, "endpoints")?;
    let handshake_map = pairs(interface, "latest-handshakes")?;
    let allowed_ips_map = pairs(interface, "allowed-ips")?;
    let transfer_map = triples(interface, "transfer")?;
    let peers = output(interface, "peers")?
        .lines()
        .filter(|line| !line.is_empty())
        .map(|public_key| Peer {
            public_key: public_key.to_string(),
            endpoint: endpoint_map
                .get(public_key)
                .filter(|value| value.as_str() != "(none)")
                .cloned(),
            allowed_ips: parse_allowed_ips(allowed_ips_map.get(public_key)),
            latest_handshake: handshake_map
                .get(public_key)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            receive_bytes: transfer_map.get(public_key).map_or(0, |value| value.0),
            transmit_bytes: transfer_map.get(public_key).map_or(0, |value| value.1),
        })
        .collect();

    Ok(Snapshot {
        public_key,
        listen_port,
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn peer(public_key: &str, allowed_ips: &[&str]) -> Peer {
        Peer {
            public_key: public_key.into(),
            endpoint: None,
            allowed_ips: allowed_ips
                .iter()
                .map(|value| IpNet::from_str(value).unwrap())
                .collect(),
            latest_handshake: 0,
            receive_bytes: 0,
            transmit_bytes: 0,
        }
    }

    #[test]
    fn longest_allowed_prefix_selects_more_specific_peer() {
        let peers = vec![
            peer("broad", &["198.51.100.0/24"]),
            peer("specific", &["198.51.100.7/32"]),
        ];
        assert_eq!(
            longest_matching_prefix(&peers, "198.51.100.7".parse().unwrap(), None)
                .unwrap()
                .public_key,
            "specific"
        );
    }

    #[test]
    fn route_lookup_can_exclude_ingress_peer() {
        let peers = vec![
            peer("ingress", &["198.51.100.0/24"]),
            peer("next", &["198.51.100.7/32"]),
        ];
        assert_eq!(
            longest_matching_prefix(&peers, "198.51.100.7".parse().unwrap(), Some("ingress"))
                .unwrap()
                .public_key,
            "next"
        );
    }

    #[test]
    fn parses_comma_separated_allowed_ips() {
        let value = "198.51.100.7/32, 2001:db8::7/128".to_string();
        let parsed = parse_allowed_ips(Some(&value));
        assert_eq!(parsed.len(), 2);
    }
}

pub fn set_endpoint(interface: &str, peer: &str, port: u16) -> Result<()> {
    let endpoint = format!("127.0.0.1:{port}");
    let result = Command::new("wg")
        .args(["set", interface, "peer", peer, "endpoint", &endpoint])
        .output()
        .with_context(|| format!("failed to set endpoint for {peer}"))?;
    if !result.status.success() {
        bail!(
            "wg set endpoint failed for {peer}: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    Ok(())
}
