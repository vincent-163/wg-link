use crate::shortcut::state::SessionKey;
use ipnet::IpNet;
use std::collections::HashMap;

const ISSUE_RETRY_SECONDS: u64 = 5;
const HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;
const RENEWAL_LEAD_SECONDS: u64 = 90;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IssueKey {
    pub peer_public_key: String,
    pub downstream_selector: IpNet,
}

#[derive(Debug, Default)]
struct IssueState {
    active: Option<SessionKey>,
    pending: Option<SessionKey>,
    next_issue: u64,
}

#[derive(Debug)]
struct SessionLease {
    issue: IssueKey,
    renew_at: u64,
}

#[derive(Default)]
pub struct RenewalScheduler {
    issues: HashMap<IssueKey, IssueState>,
    sessions: HashMap<SessionKey, SessionLease>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssueAttempt {
    pub stale_pending: Option<SessionKey>,
}

impl RenewalScheduler {
    pub fn has_active(&self, issue: &IssueKey) -> bool {
        self.issues
            .get(issue)
            .is_some_and(|state| state.active.is_some())
    }

    pub fn begin_issue(&mut self, issue: &IssueKey, now: u64) -> Option<IssueAttempt> {
        let state = self.issues.entry(issue.clone()).or_default();
        if now < state.next_issue {
            return None;
        }
        state.next_issue = now.saturating_add(ISSUE_RETRY_SECONDS);
        Some(IssueAttempt {
            stale_pending: state.pending.take(),
        })
    }

    pub fn issued(&mut self, issue: IssueKey, session: SessionKey, renew_at: u64, now: u64) {
        let state = self.issues.entry(issue.clone()).or_default();
        state.pending = Some(session);
        state.next_issue = now.saturating_add(HANDSHAKE_TIMEOUT_SECONDS);
        self.sessions
            .insert(session, SessionLease { issue, renew_at });
    }

    pub fn authenticated(&mut self, session: SessionKey, now: u64) -> Option<u64> {
        let lease = self.sessions.get(&session)?;
        let state = self.issues.get_mut(&lease.issue)?;
        if state.pending != Some(session) {
            return None;
        }
        state.active = Some(session);
        state.pending = None;
        state.next_issue = lease
            .renew_at
            .saturating_sub(RENEWAL_LEAD_SECONDS)
            .max(now.saturating_add(1));
        Some(state.next_issue)
    }

    pub fn removed(&mut self, session: SessionKey, now: u64) {
        let Some(lease) = self.sessions.remove(&session) else {
            return;
        };
        let Some(state) = self.issues.get_mut(&lease.issue) else {
            return;
        };
        let was_pending = state.pending == Some(session);
        let was_active = state.active == Some(session);
        if was_pending {
            state.pending = None;
        }
        if was_active {
            state.active = None;
        }
        if was_pending || (was_active && state.pending.is_none()) {
            state.next_issue = state
                .next_issue
                .min(now.saturating_add(ISSUE_RETRY_SECONDS));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortcut::control::ShortcutId;
    use std::str::FromStr;

    fn issue(peer: &str, selector: &str) -> IssueKey {
        IssueKey {
            peer_public_key: peer.into(),
            downstream_selector: IpNet::from_str(selector).unwrap(),
        }
    }

    fn session(value: u8) -> SessionKey {
        SessionKey {
            shortcut_id: ShortcutId([value; 16]),
            epoch: 1,
        }
    }

    #[test]
    fn selectors_for_one_peer_have_independent_renewals() {
        let mut scheduler = RenewalScheduler::default();
        let first = issue("peer", "192.0.2.2/32");
        let second = issue("peer", "192.0.2.3/32");

        assert_eq!(
            scheduler.begin_issue(&first, 1_000),
            Some(IssueAttempt {
                stale_pending: None
            })
        );
        scheduler.issued(first.clone(), session(1), 1_120, 1_000);
        assert_eq!(
            scheduler.begin_issue(&second, 1_000),
            Some(IssueAttempt {
                stale_pending: None
            })
        );
        scheduler.issued(second.clone(), session(2), 1_120, 1_000);

        assert_eq!(scheduler.authenticated(session(1), 1_002), Some(1_030));
        assert_eq!(
            scheduler.begin_issue(&second, 1_011),
            Some(IssueAttempt {
                stale_pending: Some(session(2))
            })
        );
        assert_eq!(scheduler.begin_issue(&first, 1_029), None);
        assert_eq!(
            scheduler.begin_issue(&first, 1_030),
            Some(IssueAttempt {
                stale_pending: None
            })
        );
    }

    #[test]
    fn renewal_is_scheduled_from_ticket_time_not_authentication_time() {
        let mut scheduler = RenewalScheduler::default();
        let key = issue("peer", "192.0.2.2/32");
        scheduler.begin_issue(&key, 1_000);
        scheduler.issued(key.clone(), session(1), 1_120, 1_000);

        assert_eq!(scheduler.authenticated(session(1), 1_015), Some(1_030));
        assert_eq!(scheduler.begin_issue(&key, 1_029), None);
        assert_eq!(
            scheduler.begin_issue(&key, 1_030),
            Some(IssueAttempt {
                stale_pending: None
            })
        );
    }

    #[test]
    fn old_session_removal_does_not_interrupt_authenticated_replacement() {
        let mut scheduler = RenewalScheduler::default();
        let key = issue("peer", "192.0.2.2/32");
        scheduler.begin_issue(&key, 1_000);
        scheduler.issued(key.clone(), session(1), 1_120, 1_000);
        scheduler.authenticated(session(1), 1_002);
        scheduler.begin_issue(&key, 1_030);
        scheduler.issued(key.clone(), session(2), 1_240, 1_030);
        scheduler.authenticated(session(2), 1_122);

        scheduler.removed(session(1), 1_180);
        assert_eq!(scheduler.begin_issue(&key, 1_149), None);
        assert_eq!(
            scheduler.begin_issue(&key, 1_150),
            Some(IssueAttempt {
                stale_pending: None
            })
        );
    }

    #[test]
    fn failed_pending_replacement_retries_without_waiting_for_old_expiry() {
        let mut scheduler = RenewalScheduler::default();
        let key = issue("peer", "192.0.2.2/32");
        scheduler.begin_issue(&key, 1_000);
        scheduler.issued(key.clone(), session(1), 1_120, 1_000);
        scheduler.authenticated(session(1), 1_002);
        scheduler.begin_issue(&key, 1_030);
        scheduler.issued(key.clone(), session(2), 1_240, 1_030);

        scheduler.removed(session(2), 1_123);
        assert_eq!(
            scheduler.begin_issue(&key, 1_127),
            Some(IssueAttempt {
                stale_pending: None
            })
        );
        assert_eq!(scheduler.begin_issue(&key, 1_128), None);
    }

    #[test]
    fn only_an_active_lease_can_renew_after_base_handshake_goes_stale() {
        let mut scheduler = RenewalScheduler::default();
        let key = issue("peer", "192.0.2.2/32");
        assert!(!scheduler.has_active(&key));
        scheduler.begin_issue(&key, 1_000);
        scheduler.issued(key.clone(), session(1), 1_120, 1_000);
        assert!(!scheduler.has_active(&key));
        scheduler.authenticated(session(1), 1_002);
        assert!(scheduler.has_active(&key));
    }
}
