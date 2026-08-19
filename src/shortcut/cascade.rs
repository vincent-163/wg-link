use crate::shortcut::{
    control::{
        CONTROL_VERSION, DEFAULT_EXPIRES_AFTER_SECONDS, DEFAULT_RENEW_AFTER_SECONDS,
        MAX_DELEGATION_DEPTH, ShortcutDelegation, ShortcutId, ShortcutRole, ShortcutTicket,
    },
    state::ActiveLease,
};
use anyhow::{Result, bail};
use ipnet::IpNet;
use rand::RngCore;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct CascadePeer {
    pub public_key: String,
    pub peer_id: String,
    pub endpoint_candidates: Vec<SocketAddr>,
}

#[derive(Debug)]
pub struct CascadeRequest<'a> {
    pub issuer_public_key: &'a str,
    pub upstream: &'a CascadePeer,
    pub downstream: &'a CascadePeer,
    pub upstream_selector: IpNet,
    pub downstream_selector: IpNet,
    pub parent: Option<&'a ActiveLease>,
    pub expires_at_limit: Option<u64>,
    pub renew_after_seconds: Option<u64>,
    pub now: u64,
}

#[derive(Debug)]
pub struct ShortcutTicketPair {
    pub upstream: ShortcutTicket,
    pub downstream: ShortcutTicket,
}

pub fn plan(request: CascadeRequest<'_>) -> Result<ShortcutTicketPair> {
    if request.issuer_public_key.is_empty() {
        bail!("cascade issuer public key is empty");
    }
    if request.upstream.public_key == request.downstream.public_key {
        bail!("cascade cannot connect a peer to itself");
    }
    if request.upstream.peer_id.is_empty() || request.downstream.peer_id.is_empty() {
        bail!("cascade peer id is empty");
    }

    let shortcut_id = random_shortcut_id();
    let mut master_secret = [0u8; 32];
    rand::rng().fill_bytes(&mut master_secret);
    let delegation = delegation(request.issuer_public_key, request.parent)?;
    let expires_at = request
        .now
        .saturating_add(DEFAULT_EXPIRES_AFTER_SECONDS)
        .min(request.parent.map_or(u64::MAX, |parent| parent.expires_at))
        .min(request.expires_at_limit.unwrap_or(u64::MAX));
    if expires_at <= request.now.saturating_add(1) {
        bail!("parent shortcut lease is too close to expiry for delegation");
    }
    let renew_after_seconds = request
        .renew_after_seconds
        .unwrap_or(DEFAULT_RENEW_AFTER_SECONDS);
    let renew_at = request
        .now
        .saturating_add(renew_after_seconds)
        .min(expires_at - 1);

    let common =
        |role, selector, recipient: &CascadePeer, remote: &CascadePeer| -> ShortcutTicket {
            ShortcutTicket {
                version: CONTROL_VERSION,
                shortcut_id,
                epoch: 1,
                role,
                issued_at: request.now,
                renew_at,
                expires_at,
                selector,
                issuer_public_key: request.issuer_public_key.to_string(),
                recipient_public_key: recipient.public_key.clone(),
                remote_public_key: remote.public_key.clone(),
                remote_peer_id: remote.peer_id.clone(),
                endpoint_candidates: remote.endpoint_candidates.clone(),
                delegation: delegation.clone(),
                master_secret,
            }
        };

    Ok(ShortcutTicketPair {
        upstream: common(
            ShortcutRole::Left,
            request.upstream_selector,
            request.upstream,
            request.downstream,
        ),
        downstream: common(
            ShortcutRole::Right,
            request.downstream_selector,
            request.downstream,
            request.upstream,
        ),
    })
}

fn delegation(
    issuer_public_key: &str,
    parent: Option<&ActiveLease>,
) -> Result<Option<ShortcutDelegation>> {
    let Some(parent) = parent else {
        return Ok(None);
    };
    let issuer = peer_fingerprint(issuer_public_key);
    let (root_shortcut_id, depth, remaining_delegations, mut visited_issuers) =
        match &parent.delegation {
            Some(lineage) => {
                if lineage.remaining_delegations == 0 {
                    bail!("shortcut delegation budget is exhausted");
                }
                (
                    lineage.root_shortcut_id,
                    lineage.depth.saturating_add(1),
                    lineage.remaining_delegations - 1,
                    lineage.visited_issuers.clone(),
                )
            }
            None => (
                parent.session.shortcut_id,
                1,
                MAX_DELEGATION_DEPTH - 1,
                Vec::new(),
            ),
        };
    if depth > MAX_DELEGATION_DEPTH || visited_issuers.contains(&issuer) {
        bail!("shortcut delegation would create a loop");
    }
    visited_issuers.push(issuer);
    Ok(Some(ShortcutDelegation {
        root_shortcut_id,
        parent_shortcut_id: parent.session.shortcut_id,
        depth,
        remaining_delegations,
        visited_issuers,
    }))
}

fn random_shortcut_id() -> ShortcutId {
    let mut id = [0u8; 16];
    rand::rng().fill_bytes(&mut id);
    ShortcutId(id)
}

fn peer_fingerprint(public_key: &str) -> [u8; 16] {
    let digest = blake3::hash(public_key.as_bytes());
    let mut fingerprint = [0u8; 16];
    fingerprint.copy_from_slice(&digest.as_bytes()[..16]);
    fingerprint
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortcut::state::SessionKey;
    use std::str::FromStr;

    fn peer(public_key: &str, peer_id: &str) -> CascadePeer {
        CascadePeer {
            public_key: public_key.into(),
            peer_id: peer_id.into(),
            endpoint_candidates: vec![],
        }
    }

    #[test]
    fn delegated_pair_shares_secret_and_is_bounded_by_parent_lease() {
        let parent = ActiveLease {
            session: SessionKey {
                shortcut_id: ShortcutId([1; 16]),
                epoch: 4,
            },
            expires_at: 1_150,
            delegation: None,
        };
        let upstream = peer("left", "left-peer");
        let downstream = peer("right", "right-peer");
        let pair = plan(CascadeRequest {
            issuer_public_key: "middle",
            upstream: &upstream,
            downstream: &downstream,
            upstream_selector: IpNet::from_str("198.51.100.7/32").unwrap(),
            downstream_selector: IpNet::from_str("203.0.113.1/32").unwrap(),
            parent: Some(&parent),
            expires_at_limit: None,
            renew_after_seconds: None,
            now: 1_000,
        })
        .unwrap();

        assert_eq!(pair.upstream.master_secret, pair.downstream.master_secret);
        assert_eq!(pair.upstream.shortcut_id, pair.downstream.shortcut_id);
        assert_eq!(pair.upstream.expires_at, parent.expires_at);
        assert_eq!(pair.downstream.expires_at, parent.expires_at);
        assert_eq!(pair.upstream.role, ShortcutRole::Left);
        assert_eq!(pair.downstream.role, ShortcutRole::Right);
        assert_eq!(pair.upstream.delegation.as_ref().unwrap().depth, 1);
    }

    #[test]
    fn repeated_issuer_is_rejected_as_a_loop() {
        let issuer = peer_fingerprint("middle");
        let parent = ActiveLease {
            session: SessionKey {
                shortcut_id: ShortcutId([1; 16]),
                epoch: 4,
            },
            expires_at: 1_180,
            delegation: Some(ShortcutDelegation {
                root_shortcut_id: ShortcutId([9; 16]),
                parent_shortcut_id: ShortcutId([8; 16]),
                depth: 1,
                remaining_delegations: 7,
                visited_issuers: vec![issuer],
            }),
        };
        let upstream = peer("left", "left-peer");
        let downstream = peer("right", "right-peer");
        assert!(
            plan(CascadeRequest {
                issuer_public_key: "middle",
                upstream: &upstream,
                downstream: &downstream,
                upstream_selector: IpNet::from_str("198.51.100.7/32").unwrap(),
                downstream_selector: IpNet::from_str("203.0.113.1/32").unwrap(),
                parent: Some(&parent),
                expires_at_limit: None,
                renew_after_seconds: None,
                now: 1_000,
            })
            .is_err()
        );
    }
}
