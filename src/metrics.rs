use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Default)]
pub struct MetricsRegistry {
    inner: Arc<Mutex<HashMap<(String, String), PathMetrics>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathMetricsSnapshot {
    pub available: bool,
    pub rtt_ms: Option<f64>,
    pub route_latency_ms: Option<f64>,
    pub loss_percent: Option<f64>,
    pub probe_samples: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_bps_5s: f64,
    pub tx_bps_1m: f64,
    pub tx_bps_1h: f64,
    pub rx_bps_5s: f64,
    pub rx_bps_1m: f64,
    pub rx_bps_1h: f64,
}

#[derive(Debug)]
struct PathMetrics {
    available: bool,
    rtt_ms: Option<f64>,
    route_latency_ms: Option<f64>,
    probes: VecDeque<ProbeSample>,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_rates: RateSet,
    rx_rates: RateSet,
}

#[derive(Debug)]
struct ProbeSample {
    at: Instant,
    success: bool,
}

#[derive(Debug)]
struct RateSet {
    five_seconds: EwmaRate,
    one_minute: EwmaRate,
    one_hour: EwmaRate,
}

#[derive(Debug)]
struct EwmaRate {
    tau: Duration,
    last: Instant,
    bytes_per_second: f64,
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self {
            available: false,
            rtt_ms: None,
            route_latency_ms: None,
            probes: VecDeque::new(),
            tx_bytes: 0,
            rx_bytes: 0,
            tx_rates: RateSet::new(),
            rx_rates: RateSet::new(),
        }
    }
}

impl RateSet {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            five_seconds: EwmaRate::new(Duration::from_secs(5), now),
            one_minute: EwmaRate::new(Duration::from_secs(60), now),
            one_hour: EwmaRate::new(Duration::from_secs(3_600), now),
        }
    }

    fn add(&mut self, bytes: usize, now: Instant) {
        self.five_seconds.add(bytes, now);
        self.one_minute.add(bytes, now);
        self.one_hour.add(bytes, now);
    }

    fn snapshot(&mut self, now: Instant) -> [f64; 3] {
        [
            self.five_seconds.value(now),
            self.one_minute.value(now),
            self.one_hour.value(now),
        ]
    }
}

impl EwmaRate {
    fn new(tau: Duration, now: Instant) -> Self {
        Self {
            tau,
            last: now,
            bytes_per_second: 0.0,
        }
    }

    fn decay(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.bytes_per_second *= (-elapsed / self.tau.as_secs_f64()).exp();
            self.last = now;
        }
    }

    fn add(&mut self, bytes: usize, now: Instant) {
        self.decay(now);
        self.bytes_per_second += bytes as f64 / self.tau.as_secs_f64();
    }

    fn value(&mut self, now: Instant) -> f64 {
        self.decay(now);
        self.bytes_per_second * 8.0
    }
}

impl MetricsRegistry {
    pub fn register_path(&self, peer_key: &str, path_id: &str) {
        self.inner
            .lock()
            .expect("metrics lock poisoned")
            .entry((peer_key.to_string(), path_id.to_string()))
            .or_default();
    }

    pub fn remove_peers_except(&self, peer_keys: &[String]) {
        self.inner
            .lock()
            .expect("metrics lock poisoned")
            .retain(|(peer_key, _), _| peer_keys.contains(peer_key));
    }

    pub fn set_available(&self, peer_key: &str, path_id: &str, available: bool) {
        self.with_path(peer_key, path_id, |metrics| metrics.available = available);
    }

    pub fn is_available(&self, peer_key: &str, path_id: &str) -> bool {
        self.inner
            .lock()
            .expect("metrics lock poisoned")
            .get(&(peer_key.to_string(), path_id.to_string()))
            .is_some_and(|metrics| metrics.available)
    }

    pub fn set_route_latency(&self, peer_key: &str, path_id: &str, latency_ms: Option<f64>) {
        self.with_path(peer_key, path_id, |metrics| {
            metrics.route_latency_ms = latency_ms
        });
    }

    pub fn record_probe(&self, peer_key: &str, path_id: &str, rtt: Option<Duration>) {
        let now = Instant::now();
        self.with_path(peer_key, path_id, |metrics| {
            metrics.probes.push_back(ProbeSample {
                at: now,
                success: rtt.is_some(),
            });
            if let Some(rtt) = rtt {
                metrics.rtt_ms = Some(rtt.as_secs_f64() * 1_000.0);
                metrics.available = true;
            }
            trim_probes(&mut metrics.probes, now);
        });
    }

    pub fn record_tx(&self, peer_key: &str, path_id: &str, bytes: usize) {
        let now = Instant::now();
        self.with_path(peer_key, path_id, |metrics| {
            metrics.tx_bytes = metrics.tx_bytes.saturating_add(bytes as u64);
            metrics.tx_rates.add(bytes, now);
        });
    }

    pub fn record_rx(&self, peer_key: &str, path_id: &str, bytes: usize) {
        let now = Instant::now();
        self.with_path(peer_key, path_id, |metrics| {
            metrics.rx_bytes = metrics.rx_bytes.saturating_add(bytes as u64);
            metrics.rx_rates.add(bytes, now);
        });
    }

    pub fn snapshot(&self, peer_key: &str, path_id: &str) -> PathMetricsSnapshot {
        let now = Instant::now();
        let mut guard = self.inner.lock().expect("metrics lock poisoned");
        let metrics = guard
            .entry((peer_key.to_string(), path_id.to_string()))
            .or_default();
        trim_probes(&mut metrics.probes, now);
        let probe_samples = metrics.probes.len();
        let loss_percent = (probe_samples > 0).then(|| {
            let lost = metrics
                .probes
                .iter()
                .filter(|sample| !sample.success)
                .count();
            lost as f64 * 100.0 / probe_samples as f64
        });
        let tx = metrics.tx_rates.snapshot(now);
        let rx = metrics.rx_rates.snapshot(now);
        PathMetricsSnapshot {
            available: metrics.available,
            rtt_ms: metrics.rtt_ms,
            route_latency_ms: metrics.route_latency_ms,
            loss_percent,
            probe_samples,
            tx_bytes: metrics.tx_bytes,
            rx_bytes: metrics.rx_bytes,
            tx_bps_5s: tx[0],
            tx_bps_1m: tx[1],
            tx_bps_1h: tx[2],
            rx_bps_5s: rx[0],
            rx_bps_1m: rx[1],
            rx_bps_1h: rx[2],
        }
    }

    fn with_path(&self, peer_key: &str, path_id: &str, update: impl FnOnce(&mut PathMetrics)) {
        let mut guard = self.inner.lock().expect("metrics lock poisoned");
        update(
            guard
                .entry((peer_key.to_string(), path_id.to_string()))
                .or_default(),
        );
    }
}

fn trim_probes(probes: &mut VecDeque<ProbeSample>, now: Instant) {
    while probes.len() > 100
        || probes.front().is_some_and(|sample| {
            now.saturating_duration_since(sample.at) > Duration::from_secs(60)
        })
    {
        probes.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_window_is_bounded_to_one_hundred_samples() {
        let registry = MetricsRegistry::default();
        for index in 0..120 {
            registry.record_probe(
                "peer",
                "path",
                (index % 2 == 0).then_some(Duration::from_millis(5)),
            );
        }
        let snapshot = registry.snapshot("peer", "path");
        assert_eq!(snapshot.probe_samples, 100);
        assert_eq!(snapshot.loss_percent, Some(50.0));
    }

    #[test]
    fn traffic_updates_all_ewma_windows() {
        let registry = MetricsRegistry::default();
        registry.record_tx("peer", "path", 1_000);
        let snapshot = registry.snapshot("peer", "path");
        assert!(snapshot.tx_bps_5s > snapshot.tx_bps_1m);
        assert!(snapshot.tx_bps_1m > snapshot.tx_bps_1h);
        assert_eq!(snapshot.tx_bytes, 1_000);
    }
}
