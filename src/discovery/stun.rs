use anyhow::{Context, Result, bail};
use rand::RngCore;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::{
    net::UdpSocket,
    task::JoinSet,
    time::{Duration, timeout},
};

const MAGIC_COOKIE: u32 = 0x2112_A442;

pub async fn public_address(server: &str) -> Result<SocketAddr> {
    Ok(public_addresses(server)
        .await?
        .into_iter()
        .next()
        .context(format!("STUN server {server} returned no public address"))?)
}

pub async fn public_addresses(server: &str) -> Result<Vec<SocketAddr>> {
    let servers = tokio::net::lookup_host(server)
        .await?
        .collect::<HashSet<_>>();
    if servers.is_empty() {
        bail!("STUN server {server} did not resolve");
    }

    let mut requests = JoinSet::new();
    for address in servers {
        requests.spawn(public_address_at(address));
    }

    let mut public = HashSet::new();
    let mut last_error = None;
    while let Some(result) = requests.join_next().await {
        match result {
            Ok(Ok(address)) => {
                public.insert(address);
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(error) => last_error = Some(error.into()),
        }
    }

    if public.is_empty() {
        return Err(last_error
            .unwrap()
            .context(format!("STUN server {server} did not respond")));
    }
    let mut public = public.into_iter().collect::<Vec<_>>();
    public.sort_unstable();
    Ok(public)
}

async fn public_address_at(server: SocketAddr) -> Result<SocketAddr> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    let mut transaction = [0u8; 12];
    rand::rng().fill_bytes(&mut transaction);
    let mut request = [0u8; 20];
    request[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    request[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction);
    socket.send(&request).await?;

    let mut response = [0u8; 2048];
    let length = timeout(Duration::from_secs(5), socket.recv(&mut response)).await??;
    if length < 20 || response[0..2] != 0x0101u16.to_be_bytes() || response[8..20] != transaction {
        bail!("invalid STUN binding response");
    }
    parse_xor_mapped(&response[..length])
}

fn parse_xor_mapped(message: &[u8]) -> Result<SocketAddr> {
    let mut offset = 20;
    while offset + 4 <= message.len() {
        let kind = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let length = u16::from_be_bytes([message[offset + 2], message[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + length;
        if value_end > message.len() {
            break;
        }
        if kind == 0x0020 && length >= 8 {
            let family = message[value_start + 1];
            let port = u16::from_be_bytes([message[value_start + 2], message[value_start + 3]])
                ^ (MAGIC_COOKIE >> 16) as u16;
            if family == 0x01 && length >= 8 {
                let cookie = MAGIC_COOKIE.to_be_bytes();
                let ip = Ipv4Addr::new(
                    message[value_start + 4] ^ cookie[0],
                    message[value_start + 5] ^ cookie[1],
                    message[value_start + 6] ^ cookie[2],
                    message[value_start + 7] ^ cookie[3],
                );
                return Ok(SocketAddr::new(IpAddr::V4(ip), port));
            }
            if family == 0x02 && length >= 20 {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(&message[8..20]);
                let mut address = [0u8; 16];
                for index in 0..16 {
                    address[index] = message[value_start + 4 + index] ^ mask[index];
                }
                return Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), port));
            }
        }
        offset = value_end.div_ceil(4) * 4;
    }
    bail!("STUN response has no XOR-MAPPED-ADDRESS")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(attribute: &[u8]) -> Vec<u8> {
        let mut message = vec![0u8; 20 + 4 + attribute.len()];
        message[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        message[8..20].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        message[20..22].copy_from_slice(&0x0020u16.to_be_bytes());
        message[22..24].copy_from_slice(&(attribute.len() as u16).to_be_bytes());
        message[24..].copy_from_slice(attribute);
        message
    }

    #[test]
    fn parses_xor_mapped_ipv4() {
        let port = 51820u16 ^ (MAGIC_COOKIE >> 16) as u16;
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let attribute = [
            0x00,
            0x01,
            (port >> 8) as u8,
            port as u8,
            1 ^ cookie[0],
            2 ^ cookie[1],
            3 ^ cookie[2],
            4 ^ cookie[3],
        ];
        assert_eq!(
            parse_xor_mapped(&response(&attribute)).unwrap(),
            "1.2.3.4:51820".parse().unwrap()
        );
    }

    #[test]
    fn rejects_missing_xor_mapped_address() {
        assert!(parse_xor_mapped(&[0; 20]).is_err());
    }
}
