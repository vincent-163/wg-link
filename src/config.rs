use clap::Parser;
use std::{net::SocketAddr, time::Duration};

#[derive(Debug, Clone, Parser)]
#[command(version, about = "WireGuard endpoint manager backed by EasyTier")]
pub struct Config {
    #[arg(long, short = 'i')]
    pub interface: String,

    #[arg(long = "relay", required = true)]
    pub relays: Vec<String>,

    #[arg(long = "http-tracker")]
    pub http_trackers: Vec<String>,

    #[arg(long = "udp-tracker")]
    pub udp_trackers: Vec<String>,

    #[arg(long)]
    pub dht: bool,

    #[arg(long, default_value = "stun.cloudflare.com:3478")]
    pub stun: String,

    #[arg(long, default_value_t = 2)]
    pub poll_seconds: u64,

    #[arg(long, default_value_t = 300)]
    pub discovery_interval_seconds: u64,

    #[arg(long, default_value_t = 30_000)]
    pub peer_port_base: u16,

    #[arg(long, default_value_t = 42_000)]
    pub listener_port_base: u16,

    #[arg(long, default_value = "127.0.0.1:51821")]
    pub management_listen: SocketAddr,

    #[arg(long, default_value_t = 11_020)]
    pub public_relay_port: u16,

    #[arg(long)]
    pub disable_public_relay: bool,
}

impl Config {
    pub fn normalize(self) -> Self {
        self
    }

    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_seconds.max(1))
    }

    pub fn discovery_interval(&self) -> Duration {
        Duration::from_secs(self.discovery_interval_seconds.max(30))
    }
}
