use crate::{broker::PathSet, metrics::MetricsRegistry};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tracing::{info, warn};

const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Clone, Default)]
pub struct ManagementState {
    inner: Arc<RwLock<ManagementInner>>,
    pub metrics: MetricsRegistry,
}

#[derive(Default)]
struct ManagementInner {
    interface: String,
    peers: HashMap<String, ManagedPeer>,
}

#[derive(Clone)]
struct ManagedPeer {
    peer_key: String,
    key_hint: String,
    paths: Arc<RwLock<PathSet>>,
}

#[derive(Serialize)]
struct StateResponse {
    interface: String,
    peers: Vec<PeerResponse>,
}

#[derive(Serialize)]
struct PeerResponse {
    id: String,
    key_hint: String,
    selected_path: Option<String>,
    active_path: Option<String>,
    paths: Vec<PathResponse>,
}

#[derive(Serialize)]
struct PathResponse {
    id: String,
    label: String,
    protocol: String,
    selected: bool,
    active: bool,
    metrics: crate::metrics::PathMetricsSnapshot,
}

#[derive(Deserialize)]
struct SelectPathRequest {
    path_id: Option<String>,
}

impl ManagementState {
    pub async fn replace_generation(
        &self,
        interface: &str,
        peers: Vec<(String, Arc<RwLock<PathSet>>)>,
    ) {
        let peer_keys = peers
            .iter()
            .map(|(peer_key, _)| peer_key.clone())
            .collect::<Vec<_>>();
        self.metrics.remove_peers_except(&peer_keys);
        let previous_selections = {
            let inner = self.inner.read().await;
            inner
                .peers
                .values()
                .filter_map(|peer| {
                    peer.paths
                        .try_read()
                        .ok()
                        .and_then(|paths| paths.selected.clone())
                        .map(|selected| (peer.peer_key.clone(), selected))
                })
                .collect::<HashMap<_, _>>()
        };
        let mut managed = HashMap::new();
        for (peer_key, paths) in peers {
            if let Some(selected) = previous_selections.get(&peer_key) {
                paths.write().await.select(Some(selected));
            }
            let id = peer_id(&peer_key);
            managed.insert(
                id,
                ManagedPeer {
                    key_hint: peer_key.chars().take(12).collect(),
                    peer_key,
                    paths,
                },
            );
        }
        let mut inner = self.inner.write().await;
        inner.interface = interface.to_string();
        inner.peers = managed;
    }

    async fn snapshot(&self) -> StateResponse {
        let (interface, peers) = {
            let inner = self.inner.read().await;
            (
                inner.interface.clone(),
                inner
                    .peers
                    .iter()
                    .map(|(id, peer)| (id.clone(), peer.clone()))
                    .collect::<Vec<_>>(),
            )
        };
        let mut response = Vec::with_capacity(peers.len());
        for (id, peer) in peers {
            let paths = peer.paths.read().await;
            let snapshots = paths
                .targets
                .iter()
                .map(|target| (target, self.metrics.snapshot(&peer.peer_key, &target.id)))
                .collect::<Vec<_>>();
            let active_path = paths
                .selected
                .as_ref()
                .filter(|selected| {
                    snapshots
                        .iter()
                        .any(|(target, metrics)| &target.id == *selected && metrics.available)
                })
                .cloned()
                .or_else(|| {
                    snapshots
                        .iter()
                        .find(|(_, metrics)| metrics.available)
                        .map(|(target, _)| target.id.clone())
                });
            let mut path_responses = Vec::with_capacity(paths.targets.len());
            for (target, metrics) in snapshots {
                let selected = paths.selected.as_deref() == Some(target.id.as_str());
                let active = active_path.as_deref() == Some(target.id.as_str());
                path_responses.push(PathResponse {
                    id: target.id.clone(),
                    label: target.label.clone(),
                    protocol: target.protocol.clone(),
                    selected,
                    active,
                    metrics,
                });
            }
            response.push(PeerResponse {
                id,
                key_hint: peer.key_hint,
                selected_path: paths.selected.clone(),
                active_path,
                paths: path_responses,
            });
        }
        response.sort_by(|left, right| left.key_hint.cmp(&right.key_hint));
        StateResponse {
            interface,
            peers: response,
        }
    }

    async fn select_path(&self, peer_id: &str, path_id: Option<&str>) -> Result<(), SelectError> {
        let peer = self
            .inner
            .read()
            .await
            .peers
            .get(peer_id)
            .cloned()
            .ok_or(SelectError::PeerNotFound)?;
        if let Some(path_id) = path_id {
            let paths = peer.paths.read().await;
            if !paths.targets.iter().any(|target| target.id == path_id) {
                return Err(SelectError::PathNotFound);
            }
            if !self.metrics.snapshot(&peer.peer_key, path_id).available {
                return Err(SelectError::PathUnavailable);
            }
        }
        let mut paths = peer.paths.write().await;
        if paths.select(path_id) {
            Ok(())
        } else {
            Err(SelectError::PathNotFound)
        }
    }
}

#[derive(Debug)]
enum SelectError {
    PeerNotFound,
    PathNotFound,
    PathUnavailable,
}

pub async fn run(listen: SocketAddr, state: ManagementState) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind management interface at {listen}"))?;
    info!(%listen, "management interface listening");
    loop {
        let (stream, address) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(stream, state).await {
                warn!(%address, %error, "management request failed");
            }
        });
    }
}

async fn handle(mut stream: TcpStream, state: ManagementState) -> Result<()> {
    let request = read_request(&mut stream).await?;
    let (status, content_type, body) = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => (200, "text/html; charset=utf-8", UI.to_string()),
        ("GET", "/api/state") => (
            200,
            "application/json",
            serde_json::to_string(&state.snapshot().await)?,
        ),
        ("POST", path) if path.starts_with("/api/peers/") && path.ends_with("/path") => {
            let peer_id = path
                .trim_start_matches("/api/peers/")
                .trim_end_matches("/path")
                .trim_end_matches('/');
            let selection: SelectPathRequest =
                serde_json::from_slice(&request.body).context("invalid path selection JSON")?;
            match state
                .select_path(peer_id, selection.path_id.as_deref())
                .await
            {
                Ok(()) => (200, "application/json", "{\"ok\":true}".to_string()),
                Err(SelectError::PeerNotFound | SelectError::PathNotFound) => (
                    404,
                    "application/json",
                    "{\"error\":\"not found\"}".to_string(),
                ),
                Err(SelectError::PathUnavailable) => (
                    409,
                    "application/json",
                    "{\"error\":\"path is not healthy\"}".to_string(),
                ),
            }
        }
        _ => (404, "text/plain; charset=utf-8", "not found".to_string()),
    };
    write_response(&mut stream, status, content_type, &body).await
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

async fn read_request(stream: &mut TcpStream) -> Result<Request> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let length = stream.read(&mut buffer).await?;
        anyhow::ensure!(length > 0, "empty HTTP request");
        data.extend_from_slice(&buffer[..length]);
        anyhow::ensure!(data.len() <= MAX_REQUEST_BYTES, "HTTP request too large");
        if let Some(index) = find_header_end(&data) {
            break index;
        }
    };
    let headers = std::str::from_utf8(&data[..header_end]).context("invalid HTTP headers")?;
    let mut lines = headers.lines();
    let mut request_line = lines
        .next()
        .context("missing HTTP request line")?
        .split_whitespace();
    let method = request_line
        .next()
        .context("missing HTTP method")?
        .to_string();
    let path = request_line
        .next()
        .context("missing HTTP path")?
        .to_string();
    let content_length = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let body_start = header_end + 4;
    while data.len() < body_start + content_length {
        let length = stream.read(&mut buffer).await?;
        anyhow::ensure!(length > 0, "truncated HTTP request body");
        data.extend_from_slice(&buffer[..length]);
        anyhow::ensure!(data.len() <= MAX_REQUEST_BYTES, "HTTP request too large");
    }
    Ok(Request {
        method,
        path,
        body: data[body_start..body_start + content_length].to_vec(),
    })
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

fn peer_id(peer_key: &str) -> String {
    blake3::hash(peer_key.as_bytes()).to_hex()[..16].to_string()
}

const UI: &str = r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>wg-link 管理</title><style>
:root{color-scheme:dark;background:#07111f;color:#dbeafe;font:14px system-ui,sans-serif}body{margin:0;padding:24px;background:radial-gradient(circle at top,#12345a 0,#07111f 42%)}main{max-width:1280px;margin:auto}h1{margin:0;font-size:28px}.sub{color:#8fb5d9;margin:6px 0 22px}.peer{background:#0d1b2d;border:1px solid #1f3b5a;border-radius:14px;margin:14px 0;padding:16px;box-shadow:0 12px 35px #0005}.peer-head{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:12px}.key{font:600 15px ui-monospace,monospace}.badge{padding:4px 8px;border-radius:99px;background:#183a5c;color:#9ed3ff}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 8px;border-top:1px solid #19334f;white-space:nowrap}th{color:#7ea8cc;font-weight:600}.active{color:#5ee6a8}.down{color:#fda4af}select{background:#112a44;color:#dbeafe;border:1px solid #31587b;border-radius:8px;padding:7px}.empty{padding:28px;border:1px dashed #31587b;border-radius:12px;color:#8fb5d9}.error{color:#fda4af} @media(max-width:900px){body{padding:12px}.scroll{overflow:auto}}
</style></head><body><main><h1>wg-link 路径控制台</h1><div class="sub" id="status">正在加载…</div><div id="peers"></div></main>
<script>
const fmtRate=v=>v<1e3?v.toFixed(0)+' bps':v<1e6?(v/1e3).toFixed(1)+' Kbps':v<1e9?(v/1e6).toFixed(1)+' Mbps':(v/1e9).toFixed(2)+' Gbps';
const fmt=v=>v==null?'—':Number(v).toFixed(1); const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function choose(peer,path){const r=await fetch(`/api/peers/${peer}/path`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({path_id:path||null})});if(!r.ok)alert((await r.json()).error||'切换失败');await load()}
async function load(){try{const s=await (await fetch('/api/state',{cache:'no-store'})).json();document.getElementById('status').textContent=`接口 ${s.interface||'—'} · ${s.peers.length} 个 peer · 每 2 秒刷新`;const root=document.getElementById('peers');if(!s.peers.length){root.innerHTML='<div class="empty">当前没有 WireGuard peer。</div>';return}root.innerHTML=s.peers.map(p=>`<section class="peer"><div class="peer-head"><div><div class="key">${esc(p.key_hint)}…</div><div class="badge">当前：${esc(p.active_path||'等待健康路径')}</div></div><select onchange="choose('${p.id}',this.value)"><option value="" ${p.selected_path==null?'selected':''}>自动选择</option>${p.paths.map(x=>`<option value="${x.id}" ${p.selected_path===x.id?'selected':''} ${!x.metrics.available?'disabled':''}>${esc(x.label)} · ${esc(x.protocol)}</option>`).join('')}</select></div><div class="scroll"><table><thead><tr><th>路径</th><th>状态</th><th>RTT</th><th>EasyTier 路由</th><th>丢包</th><th>发送 5s / 1m / 1h</th><th>接收 5s / 1m / 1h</th></tr></thead><tbody>${p.paths.map(x=>`<tr><td>${esc(x.label)} <span class="badge">${esc(x.protocol)}</span></td><td class="${x.metrics.available?'active':'down'}">${x.active?'● 使用中':x.metrics.available?'● 可用':'○ 不可用'}</td><td>${fmt(x.metrics.rtt_ms)} ms</td><td>${fmt(x.metrics.route_latency_ms)} ms</td><td>${fmt(x.metrics.loss_percent)}% / ${x.metrics.probe_samples}</td><td>${fmtRate(x.metrics.tx_bps_5s)} / ${fmtRate(x.metrics.tx_bps_1m)} / ${fmtRate(x.metrics.tx_bps_1h)}</td><td>${fmtRate(x.metrics.rx_bps_5s)} / ${fmtRate(x.metrics.rx_bps_1m)} / ${fmtRate(x.metrics.rx_bps_1h)}</td></tr>`).join('')}</tbody></table></div></section>`).join('')}catch(e){document.getElementById('status').innerHTML='<span class="error">管理接口读取失败：'+esc(e)+'</span>'}}
load();setInterval(load,2000);
</script></body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::{PathSet, PathTarget};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn unavailable_path_cannot_be_selected() {
        let state = ManagementState::default();
        let (sender, _) = mpsc::channel(1);
        let paths = Arc::new(RwLock::new(PathSet {
            targets: vec![PathTarget {
                id: "path".into(),
                label: "relay-1".into(),
                protocol: "udp".into(),
                sender,
            }],
            selected: None,
        }));
        state
            .replace_generation("wg0", vec![("peer-key".into(), paths.clone())])
            .await;
        let id = peer_id("peer-key");
        assert!(matches!(
            state.select_path(&id, Some("path")).await,
            Err(SelectError::PathUnavailable)
        ));
        state.metrics.set_available("peer-key", "path", true);
        state.select_path(&id, Some("path")).await.unwrap();
        assert_eq!(paths.read().await.selected.as_deref(), Some("path"));
    }
}
