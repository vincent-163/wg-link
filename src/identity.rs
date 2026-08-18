use sha1::{Digest, Sha1};

pub fn digest(parts: &[&[u8]]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&((*part).len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize()
}

pub fn provider_node_id(public_key: &str, provider: &str) -> String {
    let hash = digest(&[
        b"wg-link/provider-node/v1",
        public_key.as_bytes(),
        provider.as_bytes(),
    ]);
    hash.to_hex()[..16].to_string()
}

pub fn relay_network(provider: &str) -> String {
    let hash = digest(&[b"wg-link/easytier-relay-network/v1", provider.as_bytes()]);
    format!("wglr-{}", &hash.to_hex()[..20])
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
    fn provider_identity_is_domain_separated() {
        assert_ne!(
            provider_node_id("wg-public-key", "easytier|relay-a"),
            provider_node_id("wg-public-key", "easytier|relay-b")
        );
        assert_ne!(
            provider_node_id("wg-public-key", "easytier|relay-a"),
            provider_node_id("other-key", "easytier|relay-a")
        );
    }

    #[test]
    fn tracker_hashes_are_stable_and_provider_specific() {
        let first = info_hash("wg-public-key", "easytier|relay|tracker-a");
        assert_eq!(
            first,
            info_hash("wg-public-key", "easytier|relay|tracker-a")
        );
        assert_ne!(
            first,
            info_hash("wg-public-key", "easytier|relay|tracker-b")
        );
        assert_ne!(first, peer_id("wg-public-key", "easytier|relay|tracker-a"));
    }
}
