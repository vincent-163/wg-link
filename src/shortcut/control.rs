use anyhow::{Result, bail};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{fmt, net::SocketAddr};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const CONTROL_VERSION: u8 = 1;
pub const DEFAULT_RENEW_AFTER_SECONDS: u64 = 120;
pub const DEFAULT_EXPIRES_AFTER_SECONDS: u64 = 180;
pub const MAX_DELEGATION_DEPTH: u8 = 8;
const MAX_CLOCK_SKEW_SECONDS: u64 = 30;
const MAX_LEASE_SECONDS: u64 = 300;
const MAX_CONTROL_FRAME_SIZE: usize = 64 * 1024;
const CONTROL_MAGIC: &[u8; 8] = b"WGLINKC1";

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShortcutId(pub [u8; 16]);

impl fmt::Debug for ShortcutId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShortcutRole {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortcutDelegation {
    pub root_shortcut_id: ShortcutId,
    pub parent_shortcut_id: ShortcutId,
    pub depth: u8,
    pub remaining_delegations: u8,
    pub visited_issuers: Vec<[u8; 16]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShortcutStatus {
    Authenticated,
    Expired,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Ticket {
        ticket: ShortcutTicket,
    },
    Revoke {
        shortcut_id: ShortcutId,
        epoch: u64,
    },
    Status {
        shortcut_id: ShortcutId,
        epoch: u64,
        status: ShortcutStatus,
    },
}

impl ControlMessage {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = serde_json::to_vec(self)?;
        if body.len() > MAX_CONTROL_FRAME_SIZE {
            bail!("shortcut control frame is too large");
        }
        let mut frame = Vec::with_capacity(CONTROL_MAGIC.len() + body.len());
        frame.extend_from_slice(CONTROL_MAGIC);
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    pub fn decode(frame: &[u8]) -> Result<Self> {
        if frame.len() <= CONTROL_MAGIC.len()
            || frame.len() > CONTROL_MAGIC.len() + MAX_CONTROL_FRAME_SIZE
            || !frame.starts_with(CONTROL_MAGIC)
        {
            bail!("invalid shortcut control frame");
        }
        Ok(serde_json::from_slice(&frame[CONTROL_MAGIC.len()..])?)
    }
}

impl ShortcutRole {
    fn local_label(self) -> &'static str {
        match self {
            Self::Left => "left-static",
            Self::Right => "right-static",
        }
    }

    fn remote_label(self) -> &'static str {
        match self {
            Self::Left => "right-static",
            Self::Right => "left-static",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ShortcutTicket {
    pub version: u8,
    pub shortcut_id: ShortcutId,
    pub epoch: u64,
    pub role: ShortcutRole,
    pub issued_at: u64,
    pub renew_at: u64,
    pub expires_at: u64,
    pub selector: IpNet,
    pub issuer_public_key: String,
    pub recipient_public_key: String,
    pub remote_public_key: String,
    pub remote_peer_id: String,
    pub endpoint_candidates: Vec<SocketAddr>,
    #[serde(default)]
    pub delegation: Option<ShortcutDelegation>,
    pub master_secret: [u8; 32],
}

impl Drop for ShortcutTicket {
    fn drop(&mut self) {
        self.master_secret.zeroize();
    }
}

impl fmt::Debug for ShortcutTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShortcutTicket")
            .field("version", &self.version)
            .field("shortcut_id", &self.shortcut_id)
            .field("epoch", &self.epoch)
            .field("role", &self.role)
            .field("issued_at", &self.issued_at)
            .field("renew_at", &self.renew_at)
            .field("expires_at", &self.expires_at)
            .field("selector", &self.selector)
            .field("issuer_public_key", &self.issuer_public_key)
            .field("recipient_public_key", &self.recipient_public_key)
            .field("remote_public_key", &self.remote_public_key)
            .field("remote_peer_id", &self.remote_peer_id)
            .field("endpoint_candidates", &self.endpoint_candidates)
            .field("delegation", &self.delegation)
            .field("master_secret", &"[redacted]")
            .finish()
    }
}

impl ShortcutTicket {
    pub fn validate(&self, now: u64) -> Result<()> {
        if self.version != CONTROL_VERSION {
            bail!("unsupported shortcut ticket version {}", self.version);
        }
        if self.epoch == 0 {
            bail!("shortcut epoch must be non-zero");
        }
        if self.issuer_public_key.is_empty()
            || self.recipient_public_key.is_empty()
            || self.remote_public_key.is_empty()
        {
            bail!("shortcut ticket is missing a stable public key");
        }
        if self.remote_peer_id.is_empty() {
            bail!("shortcut ticket is missing the remote EasyTier peer id");
        }
        if self.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECONDS) {
            bail!("shortcut ticket was issued too far in the future");
        }
        if self.renew_at <= self.issued_at || self.expires_at <= self.renew_at {
            bail!("shortcut ticket has an invalid renewal window");
        }
        if self.expires_at.saturating_sub(self.issued_at) > MAX_LEASE_SECONDS {
            bail!("shortcut ticket lease is too long");
        }
        if now >= self.expires_at {
            bail!("shortcut ticket has expired");
        }
        if let Some(delegation) = &self.delegation {
            if delegation.depth == 0 || delegation.depth > MAX_DELEGATION_DEPTH {
                bail!("shortcut delegation depth is invalid");
            }
            if delegation.remaining_delegations
                > MAX_DELEGATION_DEPTH.saturating_sub(delegation.depth)
            {
                bail!("shortcut delegation budget is invalid");
            }
            if delegation.visited_issuers.len() > MAX_DELEGATION_DEPTH as usize {
                bail!("shortcut delegation lineage is too long");
            }
        }
        Ok(())
    }

    pub fn derive_keys(&self) -> DerivedKeys {
        let local_private = derive_private(
            &self.master_secret,
            self.shortcut_id,
            self.epoch,
            self.role.local_label(),
        );
        let remote_private = derive_private(
            &self.master_secret,
            self.shortcut_id,
            self.epoch,
            self.role.remote_label(),
        );
        let local_public = PublicKey::from(&StaticSecret::from(local_private)).to_bytes();
        let remote_public = PublicKey::from(&StaticSecret::from(remote_private)).to_bytes();
        let preshared_key = derive_bytes(
            &self.master_secret,
            self.shortcut_id,
            self.epoch,
            "preshared-key",
        );

        DerivedKeys {
            local_private,
            local_public,
            remote_public,
            preshared_key,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub local_private: [u8; 32],
    pub local_public: [u8; 32],
    pub remote_public: [u8; 32],
    pub preshared_key: [u8; 32],
}

fn derive_private(
    master_secret: &[u8; 32],
    shortcut_id: ShortcutId,
    epoch: u64,
    label: &str,
) -> [u8; 32] {
    let mut private = derive_bytes(master_secret, shortcut_id, epoch, label);
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    private
}

fn derive_bytes(
    master_secret: &[u8; 32],
    shortcut_id: ShortcutId,
    epoch: u64,
    label: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(master_secret);
    hasher.update(b"wg-link shortcut v1\0");
    hasher.update(&shortcut_id.0);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(label.as_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ticket(role: ShortcutRole) -> ShortcutTicket {
        ShortcutTicket {
            version: CONTROL_VERSION,
            shortcut_id: ShortcutId([7; 16]),
            epoch: 1,
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
            master_secret: [9; 32],
        }
    }

    #[test]
    fn opposite_roles_derive_matching_key_pair() {
        let left = ticket(ShortcutRole::Left).derive_keys();
        let right = ticket(ShortcutRole::Right).derive_keys();
        assert_eq!(left.local_public, right.remote_public);
        assert_eq!(right.local_public, left.remote_public);
        assert_eq!(left.preshared_key, right.preshared_key);
        assert_ne!(left.local_private, right.local_private);
    }

    #[test]
    fn rejects_expired_ticket() {
        assert!(ticket(ShortcutRole::Left).validate(1_180).is_err());
    }

    #[test]
    fn control_frame_round_trip() {
        let message = ControlMessage::Ticket {
            ticket: ticket(ShortcutRole::Left),
        };
        let encoded = message.encode().unwrap();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        match decoded {
            ControlMessage::Ticket { ticket } => {
                assert_eq!(ticket.shortcut_id, ShortcutId([7; 16]));
                assert_eq!(ticket.master_secret, [9; 32]);
            }
            _ => panic!("wrong control message type"),
        }
    }

    #[test]
    fn rejects_frame_without_magic() {
        assert!(ControlMessage::decode(b"not-wg-link").is_err());
    }
}
