<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

**English** · [Français](README.fr.md)

# Vanargand

**A partition-tolerant ledger design for intermittently connected networks.**

> **Status: design stage. There is no implementation yet.**
> This repository contains design documents, a threat model, and revision logs.
> Nothing here has been audited, reviewed, or run in production. Several core
> problems are open — see [Open problems](#open-problems) below.

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

## Repository layout

```
docs/          Design documents, threat model, revision logs (R1, R2)
spec/          Frozen specification, versioned
spec/vectors/  Conformance test vectors (CC0)
```

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
| Code (when it exists) | `MIT OR Apache-2.0` |
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

The most useful contribution at this stage is not code. It is an argument that
one of the mechanisms described here does not work. If you find one, please open
an issue.

## Security

See [`SECURITY.md`](SECURITY.md).

## Language

Design documents are currently in French; specifications and papers are being
written in English. Translation is in progress.
