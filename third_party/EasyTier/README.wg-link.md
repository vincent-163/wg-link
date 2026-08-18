# EasyTier vendoring note

This directory contains EasyTier `v2.6.4` at commit
`8428a89d2dabc94c97d370ec607c6ca142473626`.

`wg-link` carries a privacy patch in
`easytier/src/common/network.rs`: physical-interface addresses are not added to
EasyTier's peer candidate list. STUN-derived public addresses and the explicit
wg-link listener remain available for hole punching. The adjacent tracing
attribute change keeps that patched collector compatible with current tracing
macros.
