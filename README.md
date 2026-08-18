# wg-link

> Experimental: the peer-id data path is functional, but configuration and
> wire framing may still change before a stable release.

`wg-linkd` takes over WireGuard peer endpoints without storing private keys or
network configuration. It only needs a WireGuard interface name and reads the
interface's live public key, listen port, peers, endpoints, and handshake state
through `wg show`.

For each peer it:

- assigns a loopback UDP endpoint and listens on one UDP port;
- embeds one no-TUN EasyTier instance per configured relay in the `wg-linkd`
  process, without spawning `easytier-core` or `easytier-cli`;
- joins the relay's open EasyTier network and participates in unrestricted peer
  discovery and packet relaying;
- derives an hourly EasyTier hostname from the WireGuard public key and the
  current UTC Unix-hour period, then resolves both the current and previous
  period to EasyTier's routed `peer_id`; relay addresses do not participate in
  the identity hash, each ID is created hourly, and each remains usable for a
  two-hour sliding window;
- exposes only the wg-link EasyTier listener endpoint; the real WireGuard
  listen port remains local and is never placed in EasyTier hostnames, tracker
  records, or DHT records;
- wraps WireGuard UDP datagrams in a small public-key-addressed frame and sends
  them directly with EasyTier's `send_msg_for_proxy` peer routing API; no
  EasyTier virtual IP, TUN route, or UDP port-forward is involved;
- treats a newer WireGuard `latest_handshake` value as authenticated success;
- continuously restores the managed endpoint if WireGuard roaming changes it.

The daemon exposes a loopback-only management console at
`http://127.0.0.1:51821/` by default. It shows the selected and active path for
every peer, per-path EasyTier route latency, active-probe RTT and packet loss
over at most the latest 100 probes/60 seconds, plus transmit and receive EWMA
rates over 5 seconds, 1 minute, and 1 hour. A healthy relay/protocol path can be
selected manually, or selection can be returned to automatic fallback. Change
the bind address with `--management-listen`; binding a non-loopback address is
explicitly warned because the console intentionally omits relay URLs and full
WireGuard public keys.

Every process also starts an embedded EasyTier relay listener on UDP and TCP
port `11020`. It has no TUN device and no configured peers, uses a random
isolated local network identity, and accepts only the wg-link transport network
as a foreign network. This keeps it out of the virtual overlay while allowing
other wg-link nodes to use it as a pure in-process relay. Use
`--public-relay-port` to change the port or `--disable-public-relay` when
another service already owns it.

Discovery providers are optional. STUN defaults to
`stun.cloudflare.com:3478`; HTTP trackers, UDP trackers, and Mainline DHT can
feed additional public UDP candidates into the running EasyTier connector.
Discovery is refreshed every five minutes by default and can be adjusted with
`--discovery-interval-seconds` (minimum 30 seconds).

The hourly periods use UTC Unix time. Nodes should have working clock
synchronization; accepting the current and previous periods tolerates normal
hour-boundary propagation delays but is not a substitute for NTP.

Tracker and DHT keys are derived from the WireGuard public key, the tracker or
DHT identity domain, and the same hourly period. The daemon announces and
queries both currently valid periods, so relay address changes do not alter
discovery identities and an hour-boundary update does not interrupt discovery.
Each tracker has its own identity domain, so registrations on different
trackers are not directly linkable. A tracker registers the local endpoint only
under the local public-key hash; peer hashes are queried with a `stopped`
announce so the lookup does not leave a persistent registration under the
remote identity. Mainline DHT similarly announces only the local key and
queries each configured peer key. HTTP and UDP compact peer responses support
both IPv4 and IPv6.

STUN is also refreshed periodically, and the same server is passed into the
embedded EasyTier instance for NAT classification and hole punching. Private,
loopback, link-local, documentation, and CGNAT candidates returned by discovery
providers are discarded.

The daemon does not publish interface addresses, routes, internal subnets,
WireGuard configuration, or private keys. Its only advertised identity is the
hourly EasyTier hostname derived from the WireGuard public key and UTC period;
the vendored EasyTier collector is patched not to advertise physical-interface
addresses. WireGuard itself remains the authentication boundary:
unauthenticated or impersonated EasyTier peers cannot produce a successful
WireGuard handshake.

## Build

```bash
PROTOC=/path/to/recent/protoc cargo build --release
```

EasyTier's protobuf definitions require a recent `protoc` with proto3 optional
support. Rust `1.85` or newer is required for edition 2024; the validated build
uses Rust `1.97.1` and `protoc 27.3`.

## Run

Run as root or with the capabilities required to call `wg set`:

```bash
RUST_LOG=wg_linkd=info ./target/release/wg-linkd \
  --interface wg-link0 \
  --relay tcp://relay.example.com:11010
```

Optional discovery:

```bash
./target/release/wg-linkd \
  --interface wg-link0 \
  --relay tcp://relay.example.com:11010 \
  --dht \
  --http-tracker https://tracker.example/announce \
  --udp-tracker udp://tracker.example:6969/announce
```

The tracker and DHT options may be repeated. Newly discovered endpoints are
added to EasyTier at runtime; restarting `wg-linkd` is not required.

The daemon deliberately does not create WireGuard interfaces, assign tunnel
addresses, install routes, or persist keys. Those remain owned by the system's
normal WireGuard configuration.

## Shortcut routing design

The proposed route-delegation protocol for replacing an authenticated
two-hop WireGuard path with a direct peer relationship is documented in
[`docs/shortcut-routing.md`](docs/shortcut-routing.md). It uses first-packet
transit detection, two in-band tickets sent through the existing WireGuard
paths, and a separate non-persistent TUN backed by an in-process userspace
WireGuard engine. The main interface and its `AllowedIPs` remain unchanged;
active destinations enter a dedicated policy table whose default device is the
shortcut TUN.
