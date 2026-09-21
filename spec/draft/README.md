<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# Specification — working draft

**Status: draft. Nothing here is frozen.**

`spec/README.md` describes `v3/` as the current frozen version. A frozen version
is a promise that an encoding will never change again; this directory makes no
such promise. It holds the working draft from which a frozen version will
eventually be cut. When a section is judged stable it moves, unchanged, into a
numbered version directory, and only then does the freeze rule apply to it.

Read the numbering as the dependency order, not as chapters: each document may
only depend on the ones before it.

| Document | Covers | Depends on |
|---|---|---|
| [`01-canonical-encoding.md`](01-canonical-encoding.md) | Deterministic byte encoding of every protocol object | — |
| [`02-hashing.md`](02-hashing.md) | BLAKE3 usage, domain separation, hash chains | 01 |
| [`03-addresses.md`](03-addresses.md) | Key hierarchy, address derivation, Bech32m `van1…` | 01, 02 |
| [`04-transactions.md`](04-transactions.md) | Transaction envelope, 2D nonce, Tier 1 transaction types | 01–03 |
| [`05-blocks.md`](05-blocks.md) | Block header, finality rungs, provisional whitelist | 01–04 |

## Scope

This draft covers **Tier 1 ("La Meute")** only, per
[`docs/02-scope.pdf`](../../docs/02-scope.pdf). Tier 2 and Tier 3 objects
(private storage sealing, the WASM VM, bridges, cross-chain milestones) are
named where a Tier 1 object must reserve space for them, and specified nowhere.

## Conformance test vectors come first

Every normative statement in these documents that a machine can check has a
corresponding entry in [`../vectors/`](../vectors/). The vectors are generated
by an implementation written from the prose and independent of the Rust code
(see [`../../tools/vectorgen/`](../../tools/vectorgen/)), so that two
implementations agreeing is evidence and not a tautology.

Where prose and vector disagree, **the vector is the bug report**: one of the
two is wrong and the disagreement is the finding. Neither wins automatically.

## Conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in RFC 2119.

Byte strings are written in lowercase hex. Integers are decimal unless prefixed
`0x`. `‖` denotes concatenation of byte strings.

A statement marked **(frozen)** is one that cannot change after the genesis
block without a new specification version and a compatibility break. A
statement marked **(open)** records a decision that has not been made; it names
the choice rather than hiding it.
