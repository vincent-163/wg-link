use crate::shortcut::control::{DerivedKeys, ShortcutDelegation, ShortcutId, ShortcutTicket};
use anyhow::{Result, bail};
use ipnet::IpNet;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub shortcut_id: ShortcutId,
    pub epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteTarget {
    pub session: SessionKey,
}

pub trait RouteManager {
    fn activate(&mut self, selector: IpNet, target: RouteTarget) -> Result<()>;
    fn deactivate(&mut self, selector: IpNet) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    Prepared,
    Handshaking,
    Active,
    Draining,
}

#[derive(Debug)]
struct ManagedSession {
    ticket: ShortcutTicket,
    phase: SessionPhase,
}

pub struct PreparedShortcut {
    pub session: SessionKey,
    pub keys: DerivedKeys,
    pub already_present: bool,
}

#[derive(Debug, Clone)]
pub struct ActiveLease {
    pub session: SessionKey,
    pub expires_at: u64,
    pub delegation: Option<ShortcutDelegation>,
}

pub struct ShortcutManager<R> {
    routes: R,
    sessions: HashMap<SessionKey, ManagedSession>,
    active_routes: HashMap<IpNet, SessionKey>,
}

impl<R: RouteManager> ShortcutManager<R> {
    pub fn new(routes: R) -> Self {
        Self {
            routes,
            sessions: HashMap::new(),
            active_routes: HashMap::new(),
        }
    }

    pub fn receive_ticket(
        &mut self,
        ticket: ShortcutTicket,
        authenticated_sender: &str,
        local_public_key: &str,
        now: u64,
    ) -> Result<PreparedShortcut> {
        ticket.validate(now)?;
        if ticket.issuer_public_key != authenticated_sender {
            bail!("shortcut ticket issuer does not match authenticated control channel");
        }
        if ticket.recipient_public_key != local_public_key {
            bail!("shortcut ticket was not addressed to this node");
        }
        let session = SessionKey {
            shortcut_id: ticket.shortcut_id,
            epoch: ticket.epoch,
        };
        if let Some(existing) = self.sessions.get(&session) {
            if existing.ticket.selector != ticket.selector
                || existing.ticket.remote_public_key != ticket.remote_public_key
            {
                bail!("conflicting shortcut ticket for an existing epoch");
            }
            return Ok(PreparedShortcut {
                session,
                keys: existing.ticket.derive_keys(),
                already_present: true,
            });
        }
        let keys = ticket.derive_keys();
        self.sessions.insert(
            session,
            ManagedSession {
                ticket,
                phase: SessionPhase::Prepared,
            },
        );
        Ok(PreparedShortcut {
            session,
            keys,
            already_present: false,
        })
    }

    pub fn mark_handshaking(&mut self, session: SessionKey) -> Result<()> {
        let managed = self
            .sessions
            .get_mut(&session)
            .ok_or_else(|| anyhow::anyhow!("unknown shortcut session"))?;
        if managed.phase == SessionPhase::Prepared {
            managed.phase = SessionPhase::Handshaking;
        }
        Ok(())
    }

    pub fn authenticated_handshake(&mut self, session: SessionKey, now: u64) -> Result<bool> {
        let managed = self
            .sessions
            .get(&session)
            .ok_or_else(|| anyhow::anyhow!("unknown shortcut session"))?;
        if now >= managed.ticket.expires_at {
            bail!("shortcut session authenticated after expiry");
        }
        if managed.phase == SessionPhase::Active {
            return Ok(false);
        }
        let selector = managed.ticket.selector;
        let previous = self.active_routes.get(&selector).copied();

        self.routes.activate(selector, RouteTarget { session })?;

        if let Some(previous) = previous.filter(|previous| *previous != session)
            && let Some(old) = self.sessions.get_mut(&previous)
        {
            old.phase = SessionPhase::Draining;
        }
        self.sessions
            .get_mut(&session)
            .expect("session must still exist")
            .phase = SessionPhase::Active;
        self.active_routes.insert(selector, session);
        Ok(true)
    }

    pub fn expire(&mut self, now: u64) -> Result<Vec<SessionKey>> {
        let expired: Vec<SessionKey> = self
            .sessions
            .iter()
            .filter_map(|(key, managed)| (now >= managed.ticket.expires_at).then_some(*key))
            .collect();

        for session in &expired {
            let Some(managed) = self.sessions.get(session) else {
                continue;
            };
            if self.active_routes.get(&managed.ticket.selector) == Some(session) {
                self.routes.deactivate(managed.ticket.selector)?;
                self.active_routes.remove(&managed.ticket.selector);
            }
        }
        for session in &expired {
            self.sessions.remove(session);
        }
        Ok(expired)
    }

    pub fn retire_draining(&mut self) -> Vec<SessionKey> {
        let draining = self
            .sessions
            .iter()
            .filter_map(|(session, managed)| {
                (managed.phase == SessionPhase::Draining).then_some(*session)
            })
            .collect::<Vec<_>>();
        for session in &draining {
            self.sessions.remove(session);
        }
        draining
    }

    pub fn fail(&mut self, session: SessionKey) -> Result<bool> {
        let Some(managed) = self.sessions.remove(&session) else {
            return Ok(false);
        };
        if self.active_routes.get(&managed.ticket.selector) == Some(&session) {
            self.routes.deactivate(managed.ticket.selector)?;
            self.active_routes.remove(&managed.ticket.selector);
        }
        Ok(true)
    }

    pub fn phase(&self, session: SessionKey) -> Option<SessionPhase> {
        self.sessions.get(&session).map(|managed| managed.phase)
    }

    pub fn active_lease(&self, session: SessionKey) -> Option<ActiveLease> {
        let managed = self.sessions.get(&session)?;
        (managed.phase == SessionPhase::Active).then(|| ActiveLease {
            session,
            expires_at: managed.ticket.expires_at,
            delegation: managed.ticket.delegation.clone(),
        })
    }

    pub fn routes(&self) -> &R {
        &self.routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortcut::control::{CONTROL_VERSION, ShortcutRole};
    use std::str::FromStr;

    #[derive(Default)]
    struct MockRoutes {
        activations: Vec<(IpNet, RouteTarget)>,
        deactivations: Vec<IpNet>,
    }

    impl RouteManager for MockRoutes {
        fn activate(&mut self, selector: IpNet, target: RouteTarget) -> Result<()> {
            self.activations.push((selector, target));
            Ok(())
        }

        fn deactivate(&mut self, selector: IpNet) -> Result<()> {
            self.deactivations.push(selector);
            Ok(())
        }
    }

    fn ticket(epoch: u64) -> ShortcutTicket {
        ShortcutTicket {
            version: CONTROL_VERSION,
            shortcut_id: ShortcutId([5; 16]),
            epoch,
            role: ShortcutRole::Left,
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
            master_secret: [epoch as u8; 32],
        }
    }

    #[test]
    fn route_is_not_installed_before_authenticated_handshake() {
        let mut manager = ShortcutManager::new(MockRoutes::default());
        let prepared = manager
            .receive_ticket(ticket(1), "issuer", "recipient", 1_001)
            .unwrap();
        assert!(manager.routes().activations.is_empty());

        manager.mark_handshaking(prepared.session).unwrap();
        assert!(manager.routes().activations.is_empty());
        assert_eq!(
            manager.phase(prepared.session),
            Some(SessionPhase::Handshaking)
        );

        assert!(
            manager
                .authenticated_handshake(prepared.session, 1_002)
                .unwrap()
        );
        assert_eq!(manager.routes().activations.len(), 1);
        assert_eq!(manager.phase(prepared.session), Some(SessionPhase::Active));
    }

    #[test]
    fn renewal_does_not_replace_route_until_new_epoch_authenticates() {
        let mut manager = ShortcutManager::new(MockRoutes::default());
        let first = manager
            .receive_ticket(ticket(1), "issuer", "recipient", 1_001)
            .unwrap();
        manager
            .authenticated_handshake(first.session, 1_002)
            .unwrap();

        let second = manager
            .receive_ticket(ticket(2), "issuer", "recipient", 1_003)
            .unwrap();
        manager.mark_handshaking(second.session).unwrap();
        assert_eq!(manager.routes().activations.len(), 1);
        assert_eq!(manager.phase(first.session), Some(SessionPhase::Active));

        manager
            .authenticated_handshake(second.session, 1_004)
            .unwrap();
        assert_eq!(manager.routes().activations.len(), 2);
        assert_eq!(manager.phase(first.session), Some(SessionPhase::Draining));
        assert_eq!(manager.phase(second.session), Some(SessionPhase::Active));

        assert_eq!(manager.retire_draining(), vec![first.session]);
        assert_eq!(manager.phase(first.session), None);
        assert_eq!(manager.phase(second.session), Some(SessionPhase::Active));
    }

    #[test]
    fn duplicate_ticket_does_not_reset_active_session() {
        let mut manager = ShortcutManager::new(MockRoutes::default());
        let first = manager
            .receive_ticket(ticket(1), "issuer", "recipient", 1_001)
            .unwrap();
        manager
            .authenticated_handshake(first.session, 1_002)
            .unwrap();

        let duplicate = manager
            .receive_ticket(ticket(1), "issuer", "recipient", 1_003)
            .unwrap();

        assert!(duplicate.already_present);
        assert_eq!(manager.phase(first.session), Some(SessionPhase::Active));
        assert_eq!(manager.routes().activations.len(), 1);
    }

    #[test]
    fn failing_active_session_removes_its_route() {
        let mut manager = ShortcutManager::new(MockRoutes::default());
        let prepared = manager
            .receive_ticket(ticket(1), "issuer", "recipient", 1_001)
            .unwrap();
        manager
            .authenticated_handshake(prepared.session, 1_002)
            .unwrap();

        assert!(manager.fail(prepared.session).unwrap());
        assert_eq!(manager.routes().deactivations.len(), 1);
        assert_eq!(manager.phase(prepared.session), None);
    }

    #[test]
    fn failing_old_session_keeps_new_active_route() {
        let mut manager = ShortcutManager::new(MockRoutes::default());
        let first = manager
            .receive_ticket(ticket(1), "issuer", "recipient", 1_001)
            .unwrap();
        manager
            .authenticated_handshake(first.session, 1_002)
            .unwrap();
        let second = manager
            .receive_ticket(ticket(2), "issuer", "recipient", 1_003)
            .unwrap();
        manager
            .authenticated_handshake(second.session, 1_004)
            .unwrap();

        assert!(manager.fail(first.session).unwrap());
        assert!(manager.routes().deactivations.is_empty());
        assert_eq!(manager.phase(second.session), Some(SessionPhase::Active));
    }

    #[test]
    fn expiry_removes_only_the_current_active_route() {
        let mut manager = ShortcutManager::new(MockRoutes::default());
        let prepared = manager
            .receive_ticket(ticket(1), "issuer", "recipient", 1_001)
            .unwrap();
        manager
            .authenticated_handshake(prepared.session, 1_002)
            .unwrap();
        manager.expire(1_180).unwrap();
        assert_eq!(manager.routes().deactivations.len(), 1);
    }

    #[test]
    fn rejects_ticket_from_wrong_authenticated_sender() {
        let mut manager = ShortcutManager::new(MockRoutes::default());
        assert!(
            manager
                .receive_ticket(ticket(1), "different-issuer", "recipient", 1_001)
                .is_err()
        );
        assert!(manager.routes().activations.is_empty());
    }

    #[test]
    fn rejects_ticket_for_another_recipient() {
        let mut manager = ShortcutManager::new(MockRoutes::default());
        assert!(
            manager
                .receive_ticket(ticket(1), "issuer", "another-node", 1_001)
                .is_err()
        );
        assert!(manager.routes().activations.is_empty());
    }
}
