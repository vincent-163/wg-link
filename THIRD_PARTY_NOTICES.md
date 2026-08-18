# Third-party notices

## EasyTier

This repository vendors selected EasyTier 2.6.4 source code under
`third_party/EasyTier` and carries local changes needed by `wg-linkd`.
EasyTier is licensed under the GNU Lesser General Public License version 3.0.
The complete license text is retained at `third_party/EasyTier/LICENSE`.

The local changes include:

- suppressing publication of physical-interface addresses;
- exposing a typed peer packet-filter registration method;
- small compatibility fixes required by the embedded build.

The upstream source revision used by this repository is documented in
`third_party/EasyTier/README.wg-link.md`.
