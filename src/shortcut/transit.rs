use crate::{shortcut::state::SessionKey, wireguard};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::{collections::HashMap, net::IpAddr};

const AUTHENTICATED_PATH_SECONDS: u64 = 180;
const SUPPRESSION_SECONDS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressPath<'a> {
    Base {
        public_key: &'a str,
    },
    Shortcut {
        public_key: &'a str,
        session: SessionKey,
    },
}

impl<'a> IngressPath<'a> {
    fn public_key(self) -> &'a str {
        match self {
            Self::Base { public_key } | Self::Shortcut { public_key, .. } => public_key,
        }
    }

    fn parent_session(self) -> Option<SessionKey> {
        match self {
            Self::Base { .. } => None,
            Self::Shortcut { session, .. } => Some(session),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitOpportunity {
    pub upstream_public_key: String,
    pub downstream_public_key: String,
    pub upstream_selector: IpNet,
    pub downstream_selector: IpNet,
    pub parent_session: Option<SessionKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    upstream_public_key: String,
    downstream_public_key: String,
    source: IpAddr,
    destination: IpAddr,
}

#[derive(Default)]
pub struct TransitDetector {
    observed: HashMap<FlowKey, u64>,
}

impl TransitDetector {
    pub fn observe(
        &mut self,
        snapshot: &wireguard::Snapshot,
        ingress: IngressPath<'_>,
        source: IpAddr,
        destination: IpAddr,
        now: u64,
    ) -> Option<TransitOpportunity> {
        let upstream_public_key = ingress.public_key();
        if let IngressPath::Base { .. } = ingress {
            let upstream = snapshot.peer(upstream_public_key)?;
            if !handshake_is_fresh(upstream.latest_handshake, now) {
                return None;
            }
        }
        let downstream = snapshot.route_peer(destination, Some(upstream_public_key))?;
        if downstream.public_key == upstream_public_key
            || !handshake_is_fresh(downstream.latest_handshake, now)
        {
            return None;
        }

        let flow = FlowKey {
            upstream_public_key: upstream_public_key.to_string(),
            downstream_public_key: downstream.public_key.clone(),
            source,
            destination,
        };
        if self
            .observed
            .get(&flow)
            .is_some_and(|last| now.saturating_sub(*last) < SUPPRESSION_SECONDS)
        {
            return None;
        }
        self.observed.insert(flow, now);
        self.observed
            .retain(|_, last| now.saturating_sub(*last) < SUPPRESSION_SECONDS);

        Some(TransitOpportunity {
            upstream_public_key: upstream_public_key.to_string(),
            downstream_public_key: downstream.public_key.clone(),
            upstream_selector: host_selector(destination),
            downstream_selector: host_selector(source),
            parent_session: ingress.parent_session(),
        })
    }
}

fn handshake_is_fresh(latest_handshake: u64, now: u64) -> bool {
    latest_handshake != 0 && now.saturating_sub(latest_handshake) <= AUTHENTICATED_PATH_SECONDS
}

fn host_selector(address: IpAddr) -> IpNet {
    match address {
        IpAddr::V4(address) => IpNet::V4(Ipv4Net::new(address, 32).expect("valid IPv4 prefix")),
        IpAddr::V6(address) => IpNet::V6(Ipv6Net::new(address, 128).expect("valid IPv6 prefix")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{shortcut::control::ShortcutId, wireguard::Peer};
    use std::str::FromStr;

    fn peer(public_key: &str, allowed_ip: &str, latest_handshake: u64) -> Peer {
        Peer {
            public_key: public_key.into(),
            endpoint: None,
            allowed_ips: vec![IpNet::from_str(allowed_ip).unwrap()],
            latest_handshake,
            receive_bytes: 1,
            transmit_bytes: 1,
        }
    }

    fn snapshot() -> wireguard::Snapshot {
        wireguard::Snapshot {
            public_key: "middle".into(),
            listen_port: 51_820,
            peers: vec![
                peer("upstream", "203.0.113.0/24", 950),
                peer("downstream", "198.51.100.0/24", 990),
            ],
        }
    }

    #[test]
    fn shortcut_ingress_can_trigger_next_cascade_segment() {
        let mut detector = TransitDetector::default();
        let parent = SessionKey {
            shortcut_id: ShortcutId([4; 16]),
            epoch: 2,
        };
        let opportunity = detector
            .observe(
                &snapshot(),
                IngressPath::Shortcut {
                    public_key: "left",
                    session: parent,
                },
                "203.0.113.9".parse().unwrap(),
                "198.51.100.7".parse().unwrap(),
                1_000,
            )
            .unwrap();
        assert_eq!(opportunity.upstream_public_key, "left");
        assert_eq!(opportunity.downstream_public_key, "downstream");
        assert_eq!(opportunity.upstream_selector.to_string(), "198.51.100.7/32");
        assert_eq!(
            opportunity.downstream_selector.to_string(),
            "203.0.113.9/32"
        );
        assert_eq!(opportunity.parent_session, Some(parent));
    }

    #[test]
    fn repeated_flow_is_suppressed_without_blocking_forwarding() {
        let mut detector = TransitDetector::default();
        let source = "203.0.113.9".parse().unwrap();
        let destination = "198.51.100.7".parse().unwrap();
        assert!(
            detector
                .observe(
                    &snapshot(),
                    IngressPath::Base {
                        public_key: "upstream"
                    },
                    source,
                    destination,
                    1_000,
                )
                .is_some()
        );
        assert!(
            detector
                .observe(
                    &snapshot(),
                    IngressPath::Base {
                        public_key: "upstream"
                    },
                    source,
                    destination,
                    1_005,
                )
                .is_none()
        );
    }

    #[test]
    fn stale_base_handshake_does_not_authorize_ticket() {
        let mut stale = snapshot();
        stale.peers[1].latest_handshake = 700;
        assert!(
            TransitDetector::default()
                .observe(
                    &stale,
                    IngressPath::Base {
                        public_key: "upstream"
                    },
                    "203.0.113.9".parse().unwrap(),
                    "198.51.100.7".parse().unwrap(),
                    1_000,
                )
                .is_none()
        );
    }
}
