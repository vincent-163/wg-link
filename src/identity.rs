use sha1::{Digest, Sha1};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PEER_ID_PERIOD_SECONDS: u64 = 60 * 60;
pub const PEER_ID_VALID_PERIODS: u64 = 2;

pub fn digest(parts: &[&[u8]]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&((*part).len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize()
}

pub fn peer_id_period(unix_seconds: u64) -> u64 {
    unix_seconds / PEER_ID_PERIOD_SECONDS
}

pub fn current_peer_id_period() -> u64 {
    peer_id_period(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

pub fn active_peer_id_periods(unix_seconds: u64) -> [u64; PEER_ID_VALID_PERIODS as usize] {
    let current = peer_id_period(unix_seconds);
    [current, current.saturating_sub(1)]
}

pub fn rotating_node_id(public_key: &str, period: u64) -> String {
    let period = period.to_be_bytes();
    let hash = digest(&[b"wg-link/hourly-node/v2", public_key.as_bytes(), &period]);
    hash.to_hex()[..16].to_string()
}

pub fn rotating_node_name(public_key: &str, period: u64) -> String {
    format!("wgl-{}", rotating_node_id(public_key, period))
}

pub fn rotating_instance_id(public_key: &str, period: u64) -> String {
    let period = period.to_be_bytes();
    let hex = digest(&[
        b"wg-link/hourly-instance/v1",
        public_key.as_bytes(),
        &period,
    ])
    .to_hex()
    .to_string();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

pub fn transport_network() -> String {
    let hash = digest(&[b"wg-link/easytier-network/v2"]);
    format!("wglr-{}", &hash.to_hex()[..20])
}

pub fn discovery_scope(period: u64) -> String {
    format!("wg-link/hourly-discovery/v2/{period}")
}

pub fn derive_port(base: u16, span: u16, label: &str, parts: &[&str]) -> u16 {
    let mut values: Vec<&[u8]> = vec![b"wg-link/port/v1", label.as_bytes()];
    values.extend(parts.iter().map(|value| value.as_bytes()));
    let bytes = digest(&values);
    let offset = u16::from_be_bytes([bytes.as_bytes()[0], bytes.as_bytes()[1]]) % span;
    base.saturating_add(offset)
}

pub fn info_hash(public_key: &str, provider: &str) -> [u8; 20] {
    let mut sha1 = Sha1::new();
    sha1.update(b"wg-link/discovery/v1");
    sha1.update((public_key.len() as u64).to_be_bytes());
    sha1.update(public_key.as_bytes());
    sha1.update((provider.len() as u64).to_be_bytes());
    sha1.update(provider.as_bytes());
    sha1.finalize().into()
}

pub fn peer_id(public_key: &str, provider: &str) -> [u8; 20] {
    info_hash(public_key, &format!("peer-id|{provider}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotating_identity_changes_each_hour() {
        let first = rotating_node_id("wg-public-key", 10);
        assert_ne!(first, rotating_node_id("wg-public-key", 11));
        assert_ne!(first, rotating_node_id("other-key", 10));
        assert_eq!(first, rotating_node_id("wg-public-key", 10));
    }

    #[test]
    fn rotating_instance_ids_are_stable_per_node_and_hour() {
        let first = rotating_instance_id("wg-public-key", 10);
        assert_eq!(first, rotating_instance_id("wg-public-key", 10));
        assert_ne!(first, rotating_instance_id("wg-public-key", 11));
        assert_ne!(first, rotating_instance_id("other-key", 10));
    }

    #[test]
    fn peer_ids_have_a_two_hour_sliding_window() {
        assert_eq!(peer_id_period(0), 0);
        assert_eq!(peer_id_period(3_599), 0);
        assert_eq!(peer_id_period(3_600), 1);
        assert_eq!(active_peer_id_periods(7_200), [2, 1]);
        assert_eq!(active_peer_id_periods(0), [0, 0]);
    }

    #[test]
    fn transport_network_is_not_relay_scoped() {
        assert_eq!(transport_network(), transport_network());
        assert!(transport_network().starts_with("wglr-"));
    }

    #[test]
    fn tracker_hashes_are_stable_and_scope_specific() {
        let first = info_hash("wg-public-key", "hour-10|tracker-a");
        assert_eq!(first, info_hash("wg-public-key", "hour-10|tracker-a"));
        assert_ne!(first, info_hash("wg-public-key", "hour-10|tracker-b"));
        assert_ne!(first, peer_id("wg-public-key", "hour-10|tracker-a"));
    }
}
