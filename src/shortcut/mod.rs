pub mod base_control;
pub mod cascade;
pub mod control;
pub mod controller;
pub mod device;
pub mod engine;
pub mod policy;
pub mod state;
pub mod transit;

#[cfg(test)]
mod tests {
    use super::{
        cascade::{CascadePeer, CascadeRequest, plan},
        control::ShortcutId,
        engine::ShortcutTunnel,
        state::{RouteManager, RouteTarget, ShortcutManager},
        transit::{IngressPath, TransitDetector},
    };
    use crate::wireguard::{Peer, Snapshot};
    use anyhow::Result;
    use ipnet::IpNet;
    use std::str::FromStr;

    #[derive(Default)]
    struct Routes {
        active: Vec<(IpNet, RouteTarget)>,
    }

    impl RouteManager for Routes {
        fn activate(&mut self, selector: IpNet, target: RouteTarget) -> Result<()> {
            self.active.push((selector, target));
            Ok(())
        }

        fn deactivate(&mut self, _selector: IpNet) -> Result<()> {
            Ok(())
        }
    }

    fn peer(public_key: &str, peer_id: &str) -> CascadePeer {
        CascadePeer {
            public_key: public_key.into(),
            peer_id: peer_id.into(),
            endpoint_candidates: vec![],
        }
    }

    fn packet() -> [u8; 20] {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[203, 0, 113, 9]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
        packet
    }

    fn authenticate(left: &mut ShortcutTunnel, right: &mut ShortcutTunnel) -> (bool, bool) {
        let initiation = left.encapsulate(&packet()).unwrap();
        let response = right.receive(None, &initiation.network_packets[0]).unwrap();
        let established = left.receive(None, &response.network_packets[0]).unwrap();
        (
            established.authenticated_handshake,
            response.authenticated_handshake,
        )
    }

    #[test]
    fn chained_shortcut_converges_only_after_each_authenticated_handshake() {
        let left = peer("left", "left-peer");
        let middle = peer("middle", "middle-peer");
        let right = peer("right", "right-peer");
        let first = plan(CascadeRequest {
            issuer_public_key: "first-router",
            upstream: &left,
            downstream: &middle,
            upstream_selector: IpNet::from_str("198.51.100.7/32").unwrap(),
            downstream_selector: IpNet::from_str("203.0.113.9/32").unwrap(),
            parent: None,
            now: 1_000,
        })
        .unwrap();

        let mut left_manager = ShortcutManager::new(Routes::default());
        let mut middle_manager = ShortcutManager::new(Routes::default());
        let left_prepared = left_manager
            .receive_ticket(first.upstream, "first-router", "left", 1_001)
            .unwrap();
        let middle_prepared = middle_manager
            .receive_ticket(first.downstream, "first-router", "middle", 1_001)
            .unwrap();
        left_manager
            .mark_handshaking(left_prepared.session)
            .unwrap();
        middle_manager
            .mark_handshaking(middle_prepared.session)
            .unwrap();
        assert!(left_manager.routes().active.is_empty());
        assert!(middle_manager.routes().active.is_empty());

        let mut left_tunnel = ShortcutTunnel::new(left_prepared.keys, 1);
        let mut middle_tunnel = ShortcutTunnel::new(middle_prepared.keys, 2);
        let (left_authenticated, middle_authenticated) =
            authenticate(&mut left_tunnel, &mut middle_tunnel);
        assert!(left_authenticated && middle_authenticated);
        left_manager
            .authenticated_handshake(left_prepared.session, 1_002)
            .unwrap();
        middle_manager
            .authenticated_handshake(middle_prepared.session, 1_002)
            .unwrap();
        assert_eq!(left_manager.routes().active.len(), 1);
        assert_eq!(middle_manager.routes().active.len(), 1);

        let snapshot = Snapshot {
            public_key: "middle".into(),
            listen_port: 51_820,
            peers: vec![Peer {
                public_key: "right".into(),
                endpoint: None,
                allowed_ips: vec![IpNet::from_str("198.51.100.0/24").unwrap()],
                latest_handshake: 1_001,
                receive_bytes: 1,
                transmit_bytes: 1,
            }],
        };
        let opportunity = TransitDetector::default()
            .observe(
                &snapshot,
                IngressPath::Shortcut {
                    public_key: "left",
                    session: middle_prepared.session,
                },
                "203.0.113.9".parse().unwrap(),
                "198.51.100.7".parse().unwrap(),
                1_003,
            )
            .unwrap();
        let parent = middle_manager
            .active_lease(middle_prepared.session)
            .unwrap();
        let child = plan(CascadeRequest {
            issuer_public_key: "middle",
            upstream: &left,
            downstream: &right,
            upstream_selector: opportunity.upstream_selector,
            downstream_selector: opportunity.downstream_selector,
            parent: Some(&parent),
            now: 1_003,
        })
        .unwrap();
        assert_eq!(
            child
                .upstream
                .delegation
                .as_ref()
                .unwrap()
                .parent_shortcut_id,
            middle_prepared.session.shortcut_id
        );

        let left_child = left_manager
            .receive_ticket(child.upstream, "middle", "left", 1_004)
            .unwrap();
        let mut right_manager = ShortcutManager::new(Routes::default());
        let right_child = right_manager
            .receive_ticket(child.downstream, "middle", "right", 1_004)
            .unwrap();
        left_manager.mark_handshaking(left_child.session).unwrap();
        right_manager.mark_handshaking(right_child.session).unwrap();
        assert_eq!(left_manager.routes().active.len(), 1);
        assert!(right_manager.routes().active.is_empty());

        let mut left_child_tunnel = ShortcutTunnel::new(left_child.keys, 3);
        let mut right_child_tunnel = ShortcutTunnel::new(right_child.keys, 4);
        let (left_child_authenticated, right_child_authenticated) =
            authenticate(&mut left_child_tunnel, &mut right_child_tunnel);
        assert!(left_child_authenticated && right_child_authenticated);
        left_manager
            .authenticated_handshake(left_child.session, 1_005)
            .unwrap();
        right_manager
            .authenticated_handshake(right_child.session, 1_005)
            .unwrap();
        assert_eq!(left_manager.routes().active.len(), 2);
        assert_eq!(right_manager.routes().active.len(), 1);
        assert_ne!(left_child.session.shortcut_id, ShortcutId([0; 16]));
    }
}
