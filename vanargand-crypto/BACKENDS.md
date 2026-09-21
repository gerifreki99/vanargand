<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# Wiring a post-quantum backend

**Current state: no post-quantum library is a dependency of this crate.** The
algorithm registry, the traits and a behavioural conformance suite are here; the
library is not. This document is what a contributor needs to close that gap.

## Why it is empty rather than half-filled

An adapter written against an API nobody compiled is worse than no adapter. It
looks finished, it is discovered to be wrong by whoever next runs `cargo build`,
and the time it saves is smaller than the time it costs to find out which of its
assumptions were wrong. The parts that can be got right without a compiler — the
FIPS sizes, the algorithm identifiers, the determinism requirement, the
conformance suite — are done. The part that cannot is left undone and labelled.

## The bar

`vanargand_crypto::sign::conformance::check` is library code, not a test, so it
runs against a candidate wherever that candidate is defined. A backend that does
not pass it does not go in. It checks:

1. sign/verify round trip;
2. **deterministic signing** — the same key and message always give the same
   bytes;
3. **deterministic key generation** — the same seed always gives the same
   keypair, and different seeds give different ones;
4. rejection of the wrong message and the wrong key;
5. rejection of **every single-byte corruption** of the signature, at every
   position;
6. the empty message signs, verifies, and does not verify against a non-empty
   one.

None of this tests that the algorithm is secure. It tests that the backend
behaves the way the rest of Vanargand assumes.

## The three requirements a library must satisfy

### 1. Deterministic signing, not the hedged variant

FIPS 204 defines both a deterministic and a hedged (randomised) signing mode.
Vanargand requires the **deterministic** one for anything that enters state, and
this is not a preference:

- R2's account equivocation proof is "two signatures by the same device subkey
  on the same lane and sequence". Under randomised signing, an honest wallet
  that retries a send after a timeout produces exactly that evidence *against
  itself*, and the nomad credit's self-proving fraud property becomes a
  self-accusing bug.
- Two encodings of one transaction means two transaction ids, which is
  malleability.
- Conformance test vectors cannot exist for a randomised signer.

Many libraries default to hedged. Check, and pass the flag.

### 2. Deterministic key generation from a 32-byte seed

The trait takes the FIPS 204 ξ (or FIPS 203 *d*/*z*) directly. A library that
only exposes `keygen(rng)` needs its internal seeded entry point — often named
`key_gen_internal` or similar, sometimes only available behind a feature. If it
has none, it is the wrong library: without seeded key generation, a wallet
cannot be restored from a master seed, and [`crate::derive`] has nothing to
derive.

### 3. FIPS byte encodings, not the library's own

Key and signature lengths are asserted in `algorithm.rs` against FIPS 203 and
204. If a library's encoded lengths differ, it is using its own container
format, and the adapter must strip it — a Vanargand address is a hash of the
FIPS key bytes, and getting this wrong produces a chain whose addresses no
other implementation can reproduce.

## Steps

1. Add the dependency as `optional = true` and a feature that enables it, in the
   pattern already shown by the `test-backend` feature.
2. Implement `SignatureBackend` (and/or `KemBackend`) in a module gated on that
   feature.
3. Register it in the `match` inside `sign::backend` / `kem::backend`.
4. Add a test that calls `conformance::check` on it.
5. Add known-answer vectors from the NIST submission package to
   `spec/vectors/`, and a test that runs them. The conformance suite proves the
   backend is self-consistent; only KATs prove it implements the standard that
   everyone else implements.

## Candidate libraries

Two families exist as of this writing. Neither is endorsed here, and whoever
does the work should check maturity, audit status and licence at that time
rather than trusting a list written earlier:

- **RustCrypto** (`ml-dsa`, `ml-kem`) — pure Rust, no C, permissive licence,
  fits the reproducible-build requirement of G3 most easily. Younger.
- **PQClean bindings** (`pqcrypto-*`) — wraps the reference C implementations,
  which are the ones that have had the most eyes on them. Brings a C toolchain
  into the build, which costs something on the mobile and embedded targets that
  `docs/02-scope.pdf` cares about.

The R1.7 decision that constrains the choice is not about the library but about
the algorithm: **ML-DSA-44, not FALCON**, because a safe FALCON needs
constant-time floating-point arithmetic and Vanargand runs on whatever hardware
is in the room. A library offering an attractive FALCON does not change that.

## Until then

`test-backend` registers a deterministic stand-in at algorithm id `0x10` with no
security whatsoever — the verifying key and the signing key are the same bytes
and a signature is a hash of both. It exists so that the block, transaction and
state layers can be built and tested now.

The one thing standing between that convenience and a chain anyone could forge
blocks on is `AlgorithmId::valid_on_live_chain`, which returns `false` for it.
Consensus code calls it. If that check is ever removed, the finding is not "a
test broke".
