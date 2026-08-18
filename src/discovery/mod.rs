pub mod dht;
pub mod stun;
pub mod tracker;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub fn retain_public_candidates(candidates: &mut Vec<SocketAddr>) {
    candidates.retain(|candidate| is_public_candidate(candidate));
}

pub fn is_public_candidate(candidate: &SocketAddr) -> bool {
    match candidate.ip() {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_private()
        && !address.is_link_local()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
        && !address.is_documentation()
        && !(address.octets()[0] == 100 && (64..=127).contains(&address.octets()[1]))
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_unicast_link_local()
        && !(segments[0] & 0xfe00 == 0xfc00)
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_non_public_candidates() {
        let mut candidates = vec![
            "8.8.8.8:443".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
            "100.64.0.1:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            "[fc00::1]:443".parse().unwrap(),
        ];

        retain_public_candidates(&mut candidates);

        assert_eq!(candidates, vec!["8.8.8.8:443".parse().unwrap()]);
    }
}
