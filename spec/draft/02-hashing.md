<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# 02 — Hashing and domain separation

**Status: draft.** The context strings in §3 are intended to be **(frozen)**.

## 1. The primitive

Vanargand uses **BLAKE3** as its only general-purpose hash. Output is 32 bytes
unless a section says otherwise. `H(x)` denotes BLAKE3 in plain hash mode over
the byte string `x`.

Why one hash and not two: every additional primitive is another implementation
to audit on every platform the wallet runs on, and BLAKE3's tree structure gives
the archive market (`docs/04-proof-of-service.pdf`, the timed-response
challenges) verified streaming for free — a slice of a large object can be
verified against the root without holding the whole object. That property is
load-bearing later, so the choice is made now.

BLAKE3 is not post-quantum-fragile in the way signatures are: Grover's algorithm
costs a square root, so a 256-bit digest retains roughly 128 bits of preimage
resistance against a quantum adversary. That is the accepted margin and it is
why the digest is 32 bytes and not 24.

## 2. Domain separation is mandatory

**No protocol object is ever hashed with bare `H(x)`.** Every hash in Vanargand
is computed in BLAKE3's *key derivation mode*, `derive_key(context, material)`,
with a context string from the table in §3.

Notation: `H[ctx](x)` := BLAKE3 `derive_key` with context string `ctx`, input
material `x`, 32 bytes of output.

The reason is the classic one, and Vanargand is unusually exposed to it because
so many of its objects are 32-byte digests that get re-hashed: a transaction id,
a Merkle node, a commitment-chain link and a PayWord token are all "32 bytes
that get hashed again". Without separation, a value produced as one can be
presented as another. With separation, a preimage in one domain is useless in
every other.

Context strings are ASCII, contain the protocol name and a version, and are
hardcoded constants — never assembled from runtime data. A context string built
by string concatenation from a user-controlled value is a domain-separation bug
wearing the costume of a fix.

## 3. Context string registry (frozen)

Every context string in the protocol, in one table. Adding a hash to Vanargand
means adding a line here first.

| Context string | Input material | Defined in |
|---|---|---|
| `vanargand v1 account id` | `algorithm_id` ‖ `public_key` | 03 |
| `vanargand v1 device id` | `algorithm_id` ‖ `public_key` | 03 |
| `vanargand v1 key derivation` | `path` ‖ `master_seed` | 03 |
| `vanargand v1 txid` | canonical encoding of `TxBody` | 04 |
| `vanargand v1 tx signing` | `chain_id` ‖ `txid` | 04 |
| `vanargand v1 name commitment` | canonical(`name`) ‖ `salt` ‖ `account_id` | 04 |
| `vanargand v1 asset id` | `creator_account_id` ‖ `creating_txid` | 04 |
| `vanargand v1 block id` | canonical encoding of `BlockHeader` | 05 |
| `vanargand v1 block signing` | `chain_id` ‖ `block_id` | 05 |
| `vanargand v1 smt leaf` | `key` ‖ `value_hash` | 06 |
| `vanargand v1 smt node` | `left` ‖ `right` | 06 |
| `vanargand v1 state value` | canonical encoding of a stored record | 06 |
| `vanargand v1 commitment chain` | previous link | 05 |
| `vanargand v1 payword` | previous token | (Tier 1, bourse) |
| `vanargand v1 epoch seed` | mixed reveals ‖ epoch number | 05 |

`algorithm_id` is a single byte, per `03-addresses.md` §2.

## 4. Hash chains

Two mechanisms in Vanargand are hash chains, and they are the same construction
read in opposite directions. Specifying them together is deliberate: the one
failure mode they share — reusing a chain, or reusing a link across domains — is
easier to see side by side.

A chain of length *n* over a 32-byte seed `s`:

```
link[n]   = s
link[i]   = H[ctx](link[i+1])     for i from n-1 down to 0
root      = link[0]
```

The holder commits to `root` publicly and keeps the seed. Revealing `link[1]`
proves knowledge without revealing `link[2]`; a verifier checks
`H[ctx](link[1]) == root` and advances its stored value to `link[1]`.

**Commitment chain (A4 randomness).** `ctx` = `vanargand v1 commitment chain`.
The root is sealed at bond time. Proposing a block reveals the next link. The
proposer cannot choose the value (the chain is sealed in advance) and cannot
withhold it without forfeiting the proposal, which is why R2 removed the slashing
penalty for non-revelation: silence is now indistinguishable from, and treated
as, a missed turn.

**PayWord (micro-payments).** `ctx` = `vanargand v1 payword`. The payer seals a
chain at channel-open time; spending the *i*-th tranche means sending
`link[i]`, 32 bytes, verified in one hash. This is Rivest and Shamir's 1997
construction, adopted unchanged by R2.

Both MUST use their own context string, and a chain MUST NOT be reused across
two channels, two bond periods, or two chains. The seed is derived per use from
the key hierarchy of `03-addresses.md`, which makes reuse a bug that has to be
written on purpose.

### 4.1 Chain length and the cost of a reveal

Verifying a reveal is one hash. Verifying a reveal that skips *k* links is *k*
hashes, which is what happens after a gap — a missed epoch, an unsent tranche.
Implementations MUST bound the catch-up work they will perform for an untrusted
peer; an unbounded "walk forward until it matches" is a CPU exhaustion vector
(A6). The bound is a parameter, not a constant, and is **(open)**.

## 5. Merkle structures

Vanargand uses two distinct Merkle constructions and they MUST NOT be confused:

- A **sparse Merkle tree** (`06-state.md`) for state, keyed by a 32-byte key,
  256 levels deep, with a defined empty-subtree value. It answers "what is the
  value at this key, and prove it" and also "there is no value at this key".
- A **binary Merkle tree over a list** for transaction roots, built over the
  transaction ids of a block in block order.

Both use `vanargand v1 smt leaf` / `vanargand v1 smt node`, distinguishing leaf
from internal node by context string. This is the standard defence against the
second-preimage attack in which an internal node is presented as a leaf.

The leaf context takes `key ‖ value_hash` in the sparse tree, where both exist,
and the 32-byte element alone in the list tree, where there is no key. The two
inputs have different lengths, so a leaf of one tree is never a leaf of the
other.

An empty list tree has root `00…00`. That is a sentinel rather than a digest:
no non-empty list can produce it without a preimage of zero under BLAKE3.

**Odd node count.** In the list tree, a level with an odd number of nodes
promotes the last node unchanged to the next level. It is NOT duplicated. Node
duplication is the CVE-2012-2459 bug: duplicating the last node makes two
different transaction lists produce the same root.

## 6. Test vectors

[`../vectors/02-hashing.json`](../vectors/02-hashing.json) covers the context
registry (each context string against a fixed input), hash chains of several
lengths, and Merkle roots for lists of 0, 1, 2, 3, 4 and 5 elements — 3 and 5
being the cases where the odd-count rule bites.

## 7. Open points

- **(open)** Catch-up bound for hash-chain reveals (§4.1).
- **(open)** Whether federal milestones (Tier 3) need a second hash for
  cross-chain verification by implementations that do not want a BLAKE3
  dependency. The honest answer is that this is a Tier 3 problem and naming it
  here is enough.
