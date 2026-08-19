# First-packet shortcut routing design

## Goal

Assume traffic currently follows a valid two-hop WireGuard route:

```text
L --main WireGuard--> A --main WireGuard--> B
```

`L` has authorized `A` for a destination such as a documentation address
inside `198.51.100.0/24`. `A` does not own that destination; its own live
WireGuard `AllowedIPs` table selects `B` as the next hop.

The first packet must continue through `A` without waiting. At the same time,
`A` sends one authenticated shortcut ticket to `L` and one to `B` through the
already established main WireGuard tunnels. The tickets contain the same
ephemeral shortcut master secret, the opposite endpoint's stable public key,
EasyTier peer ID, endpoint candidates, route selector, and lease epoch.

`L` and `B` then derive a dedicated ephemeral WireGuard session, establish it
through direct UDP when possible or EasyTier peer-ID transport otherwise, and
move the delegated traffic to a separate non-persistent shortcut TUN:

```text
L --shortcut TUN + userspace WireGuard--> B
```

The operator-configured main WireGuard interface and its `AllowedIPs` remain
unchanged. If the shortcut disappears or expires, policy routing immediately
falls back to the original path through `A`.

## Why a second TUN is required

WireGuard uses `AllowedIPs` as both an outbound peer selector and an inbound
source authorization table. Installing the same `/32` on a new peer removes it
from the old peer, and deleting the new peer does not restore the original
mapping.

A separate shortcut TUN avoids that conflict:

- the main WireGuard interface keeps the immutable base route through `A`;
- the shortcut userspace WireGuard engine has its own route-to-peer table;
- a policy rule diverts only active shortcut destinations into the shortcut
  routing table;
- removing that rule restores the base route without reconstructing any
  WireGuard configuration.

This supports both strict subprefixes and an identical host `/32` safely.

## Components

### Main WireGuard interface

The existing operator-owned interface remains responsible for:

- authenticating the configured `L`/`A` and `A`/`B` relationships;
- carrying the first packet through `A`;
- carrying shortcut tickets and renewals from `A`;
- providing the fallback data path.

`wg-linkd` continues to manage only peer endpoints on this interface.

### Transit detector on A

`A` attaches a TC ingress eBPF program to the main WireGuard interface. For
each decrypted IPv4 or IPv6 data packet it:

1. maps the source address to upstream peer `L` using a read-only LPM trie
   populated from the live peer `AllowedIPs` table;
2. maps the destination address to downstream peer `B` using the same
   longest-prefix lookup;
3. ignores local delivery, same-peer traffic, control packets, multicast, and
   already active shortcut tuples;
4. emits one ring-buffer event for the first `(L, B, route selector)` packet;
5. returns `TC_ACT_OK`, so the original packet is forwarded to `B` normally.

An LRU hold-down map suppresses repeated events while a shortcut is preparing,
active, or recently failed. Packet payloads are never copied to userspace; the
event contains only address family, source/destination selectors, peer IDs,
packet length, and a timestamp.

An AF_PACKET observer can provide an initial prototype, but TC eBPF is the
target implementation because it can identify and suppress control packets
without copying every forwarded packet.

### In-band shortcut control

Shortcut control uses a dedicated UDP destination port and a fixed magic value
inside the already encrypted main WireGuard tunnels. ICMP is not the default
because rate limiting, middlebox handling, and payload rewriting make it less
predictable.

The same TC program recognizes the shortcut magic before normal forwarding,
redirects the control payload to a BPF ring buffer, and consumes the packet.
The ticket therefore works even when the selected destination is routed behind
the receiving WireGuard node rather than assigned to the node itself.

No daemon-specific tunnel IP is required.

## Zero-wait dual-ticket exchange

When `A` receives a first-packet event, it creates:

- a random 32-byte shortcut master secret;
- a random 128-bit epoch ID;
- a deterministic shortcut ID;
- a route selector, initially the most-specific `B` prefix containing the
  packet destination;
- a lease issue time, renewal time, and expiry time;
- endpoint hints for both nodes.

It sends two tickets concurrently while the original packet continues through
the base route.

### Ticket to L

The packet is injected into `A`'s main WireGuard interface with the observed
flow direction reversed:

```text
source      = original destination
destination = original source
```

`L` already authorizes the original destination behind peer `A`, so WireGuard
accepts the ticket as authenticated traffic from `A`.

### Ticket to B

The packet uses the original direction:

```text
source      = original source
destination = original destination
```

`B` already authorizes the original source behind peer `A`, so it likewise
accepts the ticket as authenticated traffic from `A`.

Both tickets use hop limit 1. If a receiver does not run wg-link, the packet is
dropped instead of being forwarded to the destination host.

The packets are injected with an L3 raw or packet socket bound to the main
WireGuard interface. `CAP_NET_RAW` is required. The kernel WireGuard path, not
an out-of-band public-key claim, authenticates `A` as the delegator.

## Ticket contents

Each endpoint receives the same immutable shortcut data plus a different role:

```text
protocol version
message kind: CREATE or RENEW
shortcut ID
epoch ID
shortcut master secret
issued-at
renew-after
expires-at
route selector
original source selector
delegator stable WireGuard public key
left stable WireGuard public key
right stable WireGuard public key
recipient role: LEFT or RIGHT
opposite EasyTier peer ID
opposite provider-scoped hostname
opposite public UDP endpoint candidates
opposite deterministic broker port
flags and feature version
```

The receiver validates:

1. the packet arrived on the configured main WireGuard interface;
2. its source address maps to the configured delegator peer `A`;
3. the selected prefix is already authorized through `A` in the main
   `AllowedIPs` table;
4. issue, renewal, and expiry times are within bounded clock skew;
5. the epoch is newer than the accepted epoch for the shortcut ID;
6. the opposite stable key and peer ID are not local or the delegator;
7. the route does not overlap a higher-priority operator policy rule;
8. the shortcut count, prefix count, and ticket size stay within limits.

Tickets never enter trackers or DHT. They travel only inside the existing
authenticated WireGuard relationships.

## Ephemeral shortcut keys

The two endpoints do not reuse or read the main WireGuard private key. Both
derive all shortcut secrets from the master secret delivered by `A`:

```text
left_private  = clamp(KDF(master, shortcut_id, epoch, "left-static"))
right_private = clamp(KDF(master, shortcut_id, epoch, "right-static"))
shortcut_psk  = KDF(master, shortcut_id, epoch, "preshared-key")
```

Each endpoint knows the master secret and both roles, so it can derive its own
ephemeral private key and the opposite ephemeral public key without another
message exchange. The stable WireGuard public keys remain identity labels for
wg-link/EasyTier discovery; they are not used as shortcut encryption keys.

This removes an extra key-exchange RTT. The tradeoff is deliberate: `A` knows
the shortcut master secret and could derive both ephemeral keys. `A` is already
the authenticated router carrying the original plaintext flow. A future mode
can add one direct ephemeral-DH RTT when cryptographic secrecy from `A` is more
important than minimum setup latency.

Secrets exist only in locked, zeroizing memory and are never persisted.

## Shortcut transport

Each endpoint immediately creates the ephemeral userspace WireGuard peer and
starts a handshake. No route is installed yet.

The outer transport has two candidates:

1. **EasyTier peer-ID bootstrap**: shortcut WireGuard UDP datagrams are sent to
   a deterministic local broker, wrapped in the existing wg-link frame, and
   routed to the opposite EasyTier peer ID. This always provides the relay
   fallback.
2. **Direct UDP**: both nodes send from their deterministic shortcut UDP ports
   to the endpoint candidates included in the ticket. STUN and simultaneous
   send perform hole punching. A successful direct path replaces the relay
   path without changing the inner WireGuard session.

Both sides initiate immediately. WireGuard handles simultaneous initiation.
The process generates a keepalive/probe through the userspace engine so the
handshake does not wait for a packet from the TUN.

The shortcut becomes eligible for activation only after the userspace engine
authenticates the opposite ephemeral key and completes a fresh handshake.

## Dedicated TUN and policy routing

`wg-linkd` creates one non-persistent TUN, for example `wgls0`, shared by all
shortcut leases. It is created without `TUNSETPERSIST`, so a process crash
closes the file descriptor and removes the device.

The main routing table is never given a new global default route. Instead,
wg-link installs a dedicated policy table:

```text
table wg-link-shortcut:
    default dev wgls0
```

Each active lease installs only a destination policy rule:

```text
ip rule to <delegated-prefix> lookup wg-link-shortcut
```

This implements the requested default-to-TUN behavior inside a dedicated
table, while leaving the host's main default route unchanged.

Outer UDP sockets for EasyTier, STUN, trackers, and direct shortcut endpoints
receive a dedicated firewall mark. A higher-priority rule sends that mark to
the main routing table so encrypted outer traffic never re-enters `wgls0`.

The in-band control socket has its own dedicated mark and uses the same
higher-priority main-table bypass. CREATE and renewal tickets therefore keep
traversing the authenticated base WireGuard path even while their destination
has an active shortcut selector. Reverse-path filtering remains enabled.

The userspace engine reads original IP packets from `wgls0`, selects the
shortcut peer with its own longest-prefix table, encrypts them, and sends the
result through the best outer transport. Decrypted packets are written back to
the TUN with their original inner addresses.

The policy rule is installed only after the shortcut WireGuard handshake
succeeds. Therefore the first packet and all setup-time traffic continue
through `A`; there is no preparation black hole.

## Lifetime and automatic renewal

Shortcut authority follows WireGuard's handshake timing model:

- `renew-after`: 120 seconds;
- `expires-at`: 180 seconds after the ticket epoch begins;
- replacement preparation lead: 90 seconds before `renew-after`.

Ninety seconds before renewal time, `A` sends a new one-way `RENEW` ticket with
a fresh master secret and epoch to `L` and `B` through their base WireGuard
paths. Sending the renewal itself keeps the base path active and triggers
normal WireGuard rekeying when needed.

Each endpoint prepares the new ephemeral shortcut session beside the old one.
After the new handshake succeeds, it atomically replaces the userspace route
entry while the policy rule remains installed. The old epoch remains available
until its lease expires, so a failed replacement can be retried without
withdrawing the active policy route.

No acknowledgement RTT is required. If one side misses renewal, its current
epoch expires at 180 seconds. Loss of direct authenticated handshakes, repeated
transmit without receive progress, or expiry removes the policy rule
immediately and returns traffic to `A`.

`A` stops renewal when either base peer is removed, its relevant `AllowedIPs`
change, or the route no longer selects the same downstream peer.

## Chained shortcut convergence

Shortcut sessions remain eligible as authenticated control paths. This lets a
long route converge one transit at a time without requiring the original first
hop to understand the complete topology.

For a path `L -> A -> B -> C`:

1. `A` observes the base-path packet and creates the `L <-> B` shortcut while
   still forwarding the packet normally.
2. Only after the `L <-> B` shortcut handshake authenticates may `L` route the
   delegated destination selector directly to `B`.
3. When `B` decrypts a packet from the authenticated `L` shortcut session, it
   already knows the stable identity bound to that ephemeral session. Before
   injecting the packet into `wgls0`, `B` performs a longest-prefix lookup in
   its current base-WireGuard `AllowedIPs` table. If the next hop is `C`, `B`
   forwards the packet normally and concurrently creates an `L <-> C` child
   shortcut.
4. `B` sends the upstream child ticket to `L` over the authenticated `L <-> B`
   shortcut control channel, and sends the downstream ticket to `C` over its
   authenticated base-WireGuard channel. The ordinary routed base path remains
   a fallback for control delivery.
5. `L` and `C` install their child routes only after their own `L <-> C`
   userspace-WireGuard handshake succeeds. The older `L <-> B` shortcut remains
   available for unrelated selectors and control renewal.
6. The same rule can repeat at `C`, progressively reducing `L -> A -> B -> C ->
   D` to `L <-> D` without creating a temporary forwarding black hole.

Each child ticket contains a bounded delegation lineage: root shortcut ID,
parent shortcut ID, depth, remaining delegation budget, and hashed issuer
fingerprints. A node refuses repeated issuers, exhausted budgets, self-links,
or children whose lifetime would exceed their authenticated parent control
lease. The maximum depth is eight by default. This prevents routing loops and
unbounded ticket amplification without publishing the original internal path.

The child uses two directional selectors: the upstream endpoint receives the
destination prefix behind the downstream node, while the downstream endpoint
receives the source prefix behind the upstream node. Both tickets share one
shortcut ID and master secret, but are accepted only when the declared issuer
matches the stable identity of the authenticated base or shortcut control
channel that delivered the ticket.

Shortcut decryption, rather than a kernel TUN address, supplies the upstream
identity for chained detection. The userspace engine associates every inner
packet with its authenticated shortcut session before writing it to `wgls0`,
so no virtual `/24`, packet-source guess, or leaked internal endpoint metadata
is required.

## Failure and crash behavior

| Failure | Result |
| --- | --- |
| Ticket lost to one endpoint | No shortcut handshake; traffic stays on A |
| Direct UDP fails | Shortcut WireGuard uses EasyTier peer-ID relay |

| Shortcut handshake fails | Policy rule is never installed |
| A stops or stops renewing | Lease expires and policy rule is removed |
| L or B process crashes | Non-persistent TUN disappears; main route through A remains |
| Main WG config changes | A revokes renewal; endpoints remove the lease |
| Endpoint candidate changes | Renewal carries new hints; peer-ID bootstrap remains available |
| One-sided renewal | Direct health check fails or epoch expires; both return to A |

EasyTier may now learn a physical-LAN UDP candidate through the authenticated
deployment's private-LAN discovery socket. That improves the transport between
nodes which are already EasyTier peers, but it does not by itself turn two
hosts that only share a WireGuard hub into direct WireGuard peers. Hub-mediated
multi-hop shortcut routing still requires a dynamic peer-key route in the
shortcut dispatcher; until that is present, the end-to-end shortcut remains
hub-mediated even when the underlying EasyTier nodes have a direct LAN path.

No base `AllowedIPs` entry is moved or deleted, so crash recovery requires no
persistent network-configuration journal.

## Privacy and exposure

- Trackers and DHT see only existing provider-scoped public-key hashes and
  public UDP candidates.
- Shortcut route selectors and the master secret travel only inside the main
  WireGuard tunnels.
- EasyTier sees stable endpoint public keys, peer IDs, frame sizes, and
  encrypted shortcut WireGuard datagrams, but not inner packet addresses.
- The shortcut TUN has no required public address and is never advertised.
- Logs show shortcut IDs, shortened public keys, prefix counts, timing, and
  state transitions; full prefixes require an explicit privacy-debug option.
- Shortcut secrets, epochs, and route selectors are not persisted.

## Implementation map

### `transit_bpf.rs` and eBPF object

- TC ingress parser for IPv4, IPv6, and shortcut control packets;
- upstream/downstream LPM maps derived from live `AllowedIPs`;
- first-packet LRU suppression;
- ring-buffer events without packet payloads;
- ticket consume/redirect path.

### `control.rs`

- ticket encoding and validation;
- raw L3 injection through the main WireGuard interface;
- epoch replay checks and bounded clock skew;
- role-specific key and PSK derivation;
- renewal and revocation generation on `A`.

### `shortcut_device.rs`

- non-persistent TUN creation;
- in-process userspace WireGuard peers and handshake state;
- userspace destination-to-peer route table;
- direct UDP and EasyTier peer-ID outer transports;
- endpoint racing, roaming, keepalive, and health counters.

### `policy.rs`

- dedicated route table with `default dev wgls0`;
- per-prefix destination rules;
- firewall-mark bypass for outer transport sockets;
- netlink-based atomic activation and removal;
- cleanup on normal shutdown.

### Existing modules

- `wireguard.rs`: add live `AllowedIPs`, transfer counters, and peer selection
  snapshots without reading the main private key;
- `easytier.rs`: expose dynamic peer-ID transport for shortcut encrypted UDP
  datagrams;
- `main.rs`: coordinate transit events, tickets, shortcut epochs, renewals,
  expiry, health, and hold-down state.

## Minimum RTT sequence

```text
L -> A -> B       first data packet, forwarded normally
A -> L            CREATE ticket over main WireGuard       (parallel)
A -> B            CREATE ticket over main WireGuard       (parallel)
L <-> B            direct shortcut WireGuard handshake    (one RTT)
L -> B             subsequent data through shortcut TUN
```

There is no offer/prepare/commit round trip through `A`. The only required
additional RTT is the direct WireGuard handshake between `L` and `B`.

## Initial implementation scope

- Linux only;
- TC eBPF transit detection and ticket interception;
- one shared non-persistent shortcut TUN;
- IPv4 and IPv6 destination selectors;
- one-hop `L -> A -> B` discovery;
- userspace shortcut WireGuard inside the existing Rust process;
- EasyTier peer-ID bootstrap plus direct UDP racing;
- 120-second renewal and 180-second expiry;
- one active downstream owner per selector;
- feature disabled by default behind `--shortcut-routing`;
- hold-down after failure to prevent repeated first-packet storms.

## Acceptance test

Use three network namespaces or hosts with documentation address ranges:

1. configure an identical destination `/32` through `A` on `L` and through `B`
   on `A`;
2. configure the symmetric return route through `A` on `B`;
3. verify the first packet reaches the destination through `A`;
4. verify `A` emits both tickets without delaying that packet;
5. verify `L` and `B` derive matching role-specific keys and authenticate a
   shortcut handshake in one direct RTT;
6. verify only then that the destination policy rule points to the shortcut
   table whose default device is `wgls0`;
7. verify subsequent traffic counters increase on `L` and `B` while forwarding
   counters on `A` stop increasing;
8. block direct UDP and verify the same shortcut WireGuard session continues
   through EasyTier peer-ID relay;
9. stop renewal and verify policy removal and fallback through `A` no later
   than the 180-second expiry;
10. kill `wg-linkd` and verify the non-persistent TUN disappears and the main
    WireGuard route remains unchanged.
