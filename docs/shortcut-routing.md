# Shortcut routing design

## Goal

Suppose local peer `L` sends a delegated prefix through configured WireGuard
peer `A`, while `A` routes that prefix through peer `B`:

```text
L --WireGuard--> A --WireGuard--> B
```

After `L` has authenticated `A` with a successful WireGuard handshake,
`wg-linkd` should let `A` introduce `B`. If both endpoints authorize the
delegation, they prepare a direct WireGuard peer relationship and switch the
delegated traffic to:

```text
L --WireGuard over wg-link/EasyTier--> B
```

The original route through `A` remains the authority and fallback. Trackers,
DHT nodes, relays, and unrelated EasyTier peers must not learn the delegated
prefixes.

This feature is called a **shortcut lease**. It is route delegation, not
forwarding WireGuard ciphertext addressed to `A` into `B`: a packet encrypted
for `A` cannot be authenticated or decrypted by `B`.

## Terminology

- **delegator**: configured peer `A`, already authorized for a prefix by the
  local WireGuard `AllowedIPs` table;
- **next hop**: peer `B`, advertised by `A` as the peer that owns or routes the
  delegated prefix;
- **base route**: the operator-provided WireGuard route through `A`;
- **shortcut route**: an in-memory, expiring route directly through `B`;
- **provider**: an EasyTier relay identity domain;
- **shortcut ID**: a hash of provider, delegator, both endpoint keys, the
  delegated prefixes, and the delegator's boot nonce.

## Required trust change

`latest_handshake` is sufficient to prove that a WireGuard data path worked,
but it cannot authenticate an independent EasyTier control message. EasyTier
peer names are derived from public keys, but knowledge of a public key is not
proof of possession of the corresponding WireGuard private key.

Shortcut control messages therefore require pairwise authenticated encryption:

1. `wg-linkd` reads the interface's live WireGuard private key into memory.
2. It computes static X25519 DH with the configured peer public key.
3. It derives a provider-scoped control key with a domain-separated KDF.
4. It encrypts each control message with XChaCha20-Poly1305.
5. The private key and derived keys are never written to disk and are zeroized
   when the generation stops.

If reading the live private key is forbidden, secure route delegation is not
possible with the current out-of-band EasyTier control plane. A handshake
timestamp alone does not provide a signing or encryption key to `wg-linkd`.

## Control frame

Data frames retain the existing `WGLINK01` format. Control frames use a
separate versioned envelope:

```text
magic          8 bytes  "WGLCTL01"
source key len 2 bytes
target key len 2 bytes
provider hash 16 bytes
nonce          24 bytes
source key     variable
target key     variable
ciphertext     variable, includes AEAD tag
```

The encrypted payload is canonical CBOR or a fixed binary structure. JSON is
not used for authenticated bytes because map ordering and number encoding must
be unambiguous.

Every payload contains:

```text
version
message kind
shortcut ID
issuer boot nonce
monotonic sequence
issued-at
expires-at
delegator public key
left endpoint public key
right endpoint public key
delegated prefixes
```

The provider identity is included in both the KDF and AEAD associated data, so
a control frame observed on one relay cannot be replayed on another relay.

## Route advertisement

After a recent successful handshake with each configured peer, `A` may send an
encrypted `ROUTE_OFFER` to that peer. For recipient `L`, the offer contains
routes from `A`'s live WireGuard table whose next hop is another peer such as
`B`.

`L` accepts an offered prefix only when all of these are true:

1. the message decrypts with the pairwise `L`/`A` control key;
2. `A` is an operator-configured base peer, not another shortcut peer;
3. `L` observed a new handshake with `A` during the current daemon lifetime;
4. the offer is unexpired and its sequence is newer than the last accepted
   sequence for the same boot nonce;
5. the offered prefix is contained by a base `AllowedIPs` prefix assigned to
   `A` on `L`;
6. `B` is neither `L` nor `A`, and its public key is structurally valid;
7. the offer has one-hop delegation depth and does not form a known loop;
8. no equal- or higher-priority active shortcut already owns the prefix.

This makes `A` capable only of delegating address space that `L` already
authorized `A` to route.

`A` sends a symmetric offer to `B` for the return prefixes routed through `L`.
A shortcut cannot commit until both directions have been prepared.

## Two-phase activation

Installing a direct route on only one endpoint can black-hole traffic. The
control protocol therefore uses a two-phase commit coordinated by `A`:

1. **Offer**: `A` sends `ROUTE_OFFER` independently to `L` and `B`.
2. **Prepare**: each endpoint creates the other WireGuard peer with a managed
   loopback endpoint, but installs no delegated `AllowedIPs` yet. It starts
   EasyTier peer discovery for the new public key and replies
   `SHORTCUT_PREPARED` to `A`.
3. **Commit**: after receiving both prepared messages, `A` sends
   `SHORTCUT_COMMIT` with an activation time and short lease.
4. **Activate**: `L` and `B` install the direct shortcut prefixes at the
   activation time and temporarily enable a short persistent keepalive.
5. **Authenticate**: both endpoints require `latest_handshake` for the new
   direct peer to advance before the commit timeout.
6. **Established**: each endpoint sends `SHORTCUT_ESTABLISHED` to `A`. `A`
   begins periodic lease renewal only after both confirmations.

Before commit, traffic continues through `A`. If either endpoint fails to
prepare, resolve the other peer, or complete a direct WireGuard handshake, `A`
sends `SHORTCUT_ABORT` and no route changes remain.

## Kernel WireGuard routing limit

Kernel WireGuard uses `AllowedIPs` both for outbound peer selection and inbound
source authorization. A more-specific prefix can safely override a covering
base route while preserving automatic fallback:

```text
base route through A: 198.51.100.0/24
shortcut through B:   198.51.100.7/32
```

Removing `B`'s `/32` exposes `A`'s unchanged `/24` again, so this mode needs no
persistent recovery journal.

An equal prefix is different. A local kernel experiment confirmed this
sequence:

1. assign `198.51.100.7/32` to `A`;
2. assign the same prefix to `B`;
3. WireGuard removes the prefix from `A` and assigns it to `B`;
4. remove `B`;
5. the prefix does not automatically return to `A`.

Consequently, the safe kernel implementation accepts only a **strictly more
specific** shortcut prefix. It must reject an equal prefix with
`exact-prefix-requires-userspace` rather than mutate operator configuration in
a way that cannot survive a daemon crash without persistent state.

Stock userspace WireGuard implementations use the same `AllowedIPs` model. To
support equal `/32` takeover while retaining `A` as an automatic fallback,
wg-link needs one of:

- a custom userspace WireGuard peer-selection layer that keeps an immutable
  base route and a separate expiring shortcut route table;
- a kernel/userspace WireGuard extension that supports multiple ordered peers
  for one prefix;
- an operator-approved persistent transaction journal that records and
  restores the original `AllowedIPs` configuration.

The third option conflicts with wg-link's current no-persistent-network-config
property. The recommended full implementation is therefore a custom userspace
route selector; simply replacing kernel WireGuard with unmodified
`wireguard-go` is insufficient.

## Lease and fallback

Each established shortcut is held only in memory and has a short renewable
lease. The endpoint removes the shortcut peer or its shortcut prefixes when:

- the delegator stops renewing the lease;
- the direct peer handshake becomes stale;
- receive counters stop advancing while transmit counters continue;
- the delegator revokes or replaces the route;
- a conflicting, more-specific operator route appears;
- the EasyTier peer identity changes unexpectedly;
- the daemon is shutting down cleanly.

For strict-subprefix kernel mode, removal immediately falls back to the
unchanged covering route through `A`. A short hold-down timer prevents repeated
direct-path failures from causing route flapping.

## Privacy

- Trackers and DHT contain only provider-scoped hashes and public UDP
  candidates, never route prefixes.
- EasyTier relays see only the existing endpoint public keys, provider domain,
  frame sizes, and encrypted control ciphertext.
- Route offers are encrypted separately for each recipient.
- No private key, derived control key, route offer, or lease is persisted.
- Logs contain shortened public keys and prefix counts by default; full
  prefixes require an explicit debug/privacy override.

## Implementation map

### `wireguard.rs`

- parse each peer's live `AllowedIPs`;
- read the live private key into a zeroizing secret type;
- add a peer without `AllowedIPs` during prepare;
- atomically install and remove strict-subprefix shortcut routes;
- expose handshake and transfer counters for health checks.

### `control.rs`

- canonical control message encoding;
- X25519 shared-secret derivation and provider-scoped KDF;
- XChaCha20-Poly1305 encryption/decryption;
- replay window, boot nonce, sequence, expiry, and shortcut-ID validation;
- prefix containment, overlap, and loop checks.

### `easytier.rs`

- separate data and control frame decoding;
- dynamically resolve next-hop public keys to EasyTier `peer_id` values;
- transport encrypted offers, prepare acknowledgements, commit, abort, and
  renewal messages without exposing prefixes.

### `main.rs`

- retain the operator/base peer set separately from dynamic shortcut peers;
- gate delegator authority on a handshake observed in the current process;
- coordinate prepare/commit/established state;
- manage leases, keepalives, health checks, hold-downs, and rollback;
- restart the static broker generation only after a prepared peer is added.

## Initial scope

The first implementation should deliberately be narrow:

- Linux kernel WireGuard only;
- one-hop delegation only;
- IPv4 and IPv6 strict-subprefix shortcuts;
- one shortcut owner per prefix;
- no aggregation or recursive route propagation;
- no equal-prefix takeover;
- feature disabled by default behind `--shortcut-routing`;
- default handshake authorization window of 180 seconds;
- default prepare timeout of 15 seconds;
- default lease of 90 seconds and renewal every 30 seconds;
- default failed-shortcut hold-down of 300 seconds.

## Acceptance test

Use three network namespaces or hosts:

1. `L` has a base route through `A` for a documentation `/24`.
2. `A` has a more-specific `/32` through `B`.
3. `B` has the symmetric return route through `A`.
4. Before authorization, packets traverse `A`.
5. Trigger fresh `L`/`A` and `A`/`B` WireGuard handshakes.
6. Verify both endpoints prepare, commit, and authenticate the direct peer.
7. Verify traffic counters increase on `L`/`B` while forwarding counters on
   `A` stop increasing.
8. Break the direct EasyTier path or stop renewals.
9. Verify the shortcut is removed and traffic returns through `A` without
   changing persistent WireGuard configuration.
10. Repeat with equal `/32` base and offered prefixes and verify that kernel
    mode rejects the shortcut without modifying `AllowedIPs`.
