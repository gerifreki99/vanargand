<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

**English** · [Français](README.fr.md)

# Vanargand

**A partition-tolerant ledger design for intermittently connected networks.**

> **Status: design stage, with an implementation of the foundation layer
> beginning.** This repository contains design documents, a threat model,
> revision logs, a working-draft specification, conformance vectors, and Rust
> crates implementing the encoding, primitives interface, canonical objects and
> ledger. **No chain has ever run.** Nothing here has been audited or reviewed
> by anyone. Several core problems are open — see
> [Open problems](#open-problems) — and the code has no post-quantum backend
> wired in, so it cannot verify a real signature today. See
> [What is implemented](#what-is-implemented) for the honest boundary.

---

## What this is

Vanargand is a design for a ledger in which **network partition is the normal
operating regime rather than a failure mode**. Most distributed ledger designs
assume connectivity and treat partition as an exception to be recovered from.
Vanargand inverts that assumption and asks what a payment and identity system looks
like when nodes are routinely offline for hours or days.

The design targets three settings: sites with deliberately degraded
connectivity (large events), areas with intermittent infrastructure, and — as a
generalisation — high-latency networks where round trips are measured in
minutes.

## Contributions

The parts of this design that may be of independent interest, regardless of
whether Vanargand itself is ever built:

1. **Channel fraud under partition.** Unilateral channel closure with a stale
   state, executed inside provisional (non-finalised) blocks while the
   counterparty and its watchtower are on the other side of a partition. The
   contest window elapses in a world where the contesting party cannot exist.
   The payment-channel literature assumes liveness; the partition literature
   ignores channels. Documented as **C9** in the threat model, with a proposed
   remedy (grammatical whitelist for provisional inclusion, contest clocks
   counted exclusively in finalised height).

2. **Bounded offline spending with self-proving account equivocation.** A
   publicly declared, on-ledger bound on a given account's offline exposure, so
   that merchant risk is known *ex ante* rather than repaired *ex post*.
   Double-spending across partitions necessarily produces two signatures
   sharing a (device subkey, lane, sequence) tuple — fraud carries its own
   proof. Per-device lane allocation ensures two honest devices belonging to
   the same account cannot produce a punishable equivocation.

3. **A finality ladder in which partition is nominal.** Provisional and
   finalised states as first-class, with deterministic reconciliation: two
   honest nodes holding the same provisional blocks compute the same final
   state independent of arrival order.

4. **Monetary inversion as a regulatory pattern.** The protocol token is used
   only between machines for infrastructure settlement; end users transact in
   their existing currency. This removes the consumer-facing token surface
   while preserving the operator's economics.

## Open problems

This section exists because the design is not finished, and pretending
otherwise would waste your time.

| ID | Problem | Status |
|----|---------|--------|
| C7 | Provenance-weighting leakage; reduces to proof-of-personhood | Open |
| B4 | Traffic correlation against the messaging layer | Open |
| D3 | Data availability for archived state | Open |
| G7 | Regulatory qualification | Open |
| A4 | Randomness beacon on the launch critical path | Under revision |
| A7 | Invalid finalised state and light-client exposure | Partial remedy |
| E1–E3 | Storage sealing (Proof of Replication) | To be designed |

The central economic claim — that attacking the network is structurally
unprofitable — currently **depends on C7** and should be read as a conjecture
pending measurement, not a result. See the revision log for how this claim was
weakened from its original form.

## What is implemented

| Area | State |
|---|---|
| Canonical encoding, with non-canonical input rejected | Implemented, vectors |
| BLAKE3 domain separation, hash chains (PayWord, commitment chain) | Implemented, vectors |
| Key hierarchy, account and device identifiers, Bech32m `van1…` | Implemented, vectors |
| Two-dimensional nonce, lane state | Implemented |
| Transaction envelope, 21 kinds, the provisional grammar (C9) | Implemented |
| Account equivocation evidence (R2) | Implemented |
| Block header, finality ladder, contestation clocks | Implemented |
| Sparse Merkle tree, inclusion **and non-inclusion** proofs | Implemented |
| Ledger: 6 of 21 transaction kinds, nomad credit enforcement | Partial |
| Post-quantum signature and KEM backends | **Interface only** |
| Consensus, networking, messaging, channels, storage, bridges | Not started |

The signature layer is worth singling out. `vanargand-crypto` has the algorithm
registry, the traits, and a behavioural conformance suite a backend must pass —
but **no post-quantum library is a dependency yet**, and that is a labelled
state rather than an oversight. An adapter written against an API nobody
compiled looks finished and is not. See
[`vanargand-crypto/BACKENDS.md`](vanargand-crypto/BACKENDS.md).

Two findings from writing the code are recorded in the draft specification
rather than quietly resolved: the offline ceiling does not cover local assets,
which is exactly the payment the Tier 1 pilot is built around
([`04-transactions.md`](spec/draft/04-transactions.md) §4.1), and R1.7's premium
name threshold contradicts its own `@marie` example (§6.1).

## Repository layout

```
docs/               Design documents, threat model, revision logs (R1, R2)
spec/draft/         Specification, working draft — not frozen
spec/vectors/       Conformance test vectors (CC0)
tools/vectorgen/    A second implementation, in Python, that generates them
vanargand-crypto/   Primitives interface: hashing, chains, key hierarchy, traits
vanargand-types/    Canonical encoding, identifiers, addresses, transactions, blocks
vanargand-state/    Sparse Merkle tree, account model, state transitions
vanargand-*/        Reserved, documented, not implemented
```

The vectors are generated by a Python implementation written from the prose in
`spec/draft/`, deliberately not from the Rust. Vectors generated by the
implementation they test prove only that the implementation agrees with itself.
CI runs both: one job asks whether the Rust matches the vectors, the other
whether the vectors still match the specification they came from.

## Revision logs

`docs/` contains the review rounds (R1, R2) as separate documents rather than
folding them silently into the design. They record decisions that were made,
found to be wrong, and replaced — including two corrections to the design's
central claims. They are published deliberately.

## AI assistance

This work was developed with AI assistance. Large language models were used for
drafting and revising the design documents, for adversarial review of the design,
and for literature search.

They are tools, not authors, and nothing here rests on a model's authority. Every
design decision, every claim, and every error is the author's. Where a claim is
weak it is marked open rather than smoothed over — see
[Open problems](#open-problems) and the revision logs above.

## Licensing

| Content | License |
|---------|---------|
| Code | `MIT OR Apache-2.0` |
| Documents and specifications | `CC-BY-4.0` |
| Conformance test vectors | `CC0-1.0` |

Machine-readable scope: [`.reuse/dep5`](.reuse/dep5).

Dual-licensing the code follows the Rust ecosystem convention. Test vectors are
placed in the public domain so that any implementation can use them without
considering licensing at all.

## Citing

See [`CITATION.cff`](CITATION.cff), or use the archived release DOI.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Contributions are accepted under the
Developer Certificate of Origin — a `Signed-off-by` line in each commit. There
is no CLA.

The most useful contribution at this stage is still not code. It is an argument
that one of the mechanisms described here does not work. If you find one, please
open an issue.

The second most useful is a disagreement between the two implementations. Where
`tools/vectorgen/generate.py` and the Rust crates differ, one of them is wrong —
or the specification is ambiguous enough that two readers of it diverged, which
is the most valuable of the three outcomes.

After that: a post-quantum backend that passes
`vanargand_crypto::sign::conformance::check`, and the fifteen transaction kinds
the ledger does not yet apply.

## Security

See [`SECURITY.md`](SECURITY.md).

## Language

Design documents are currently in French; specifications and papers are being
written in English. Translation is in progress.
