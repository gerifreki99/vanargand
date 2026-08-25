<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

**English** · [Français](README.fr.md)

# Specification

Versioned and frozen. Code references specification sections by version, never
by a moving document.

- `v3/` — current frozen version
- `vectors/` — conformance test vectors (CC0-1.0)

## Test vectors come first

Vectors are written **before** the implementation, directly from the
specification. Writing them is how specification ambiguity is discovered, and it
is far cheaper to discover it here than in a consensus debugger.

The vectors are also the artefact that survives if the implementation does not:
a specification with conformance vectors is reimplementable by someone else. A
specification in prose is not.

Planned coverage: canonical serialisation, address derivation and Bech32m,
sparse Merkle tree hashing convention, transaction envelope, 2D nonce layout
(lane, sequence), state transition per transaction type.
