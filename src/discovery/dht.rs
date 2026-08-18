use anyhow::Result;
use futures_lite::StreamExt;
use mainline::{Dht, Id};
use std::{collections::HashSet, net::SocketAddr, time::Duration};
use tracing::warn;

pub async fn announce_and_discover(
    local_hash: [u8; 20],
    peer_hash: [u8; 20],
    listener_port: u16,
) -> Result<Vec<SocketAddr>> {
    let dht = Dht::client()?;
    let dht = dht.as_async();
    let local_id = Id::from_bytes(local_hash)?;
    let peer_id = Id::from_bytes(peer_hash)?;
    if let Err(error) = dht.announce_peer(local_id, Some(listener_port)).await {
        warn!(%error, "DHT announce failed");
    }

    let mut stream = dht.get_peers(peer_id);
    let mut seen = HashSet::<SocketAddr>::new();
    let lookup = async {
        while let Some(batch) = stream.next().await {
            for address in batch {
                let address = SocketAddr::V4(address);
                seen.insert(address);
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let _ = tokio::time::timeout(Duration::from_secs(25), lookup).await;
    Ok(seen.into_iter().collect())
}
