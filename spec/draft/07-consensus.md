<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# 07 — Proof of Service

**Status: draft.** The sampling algorithm of §4 is normative in the strongest
sense: two implementations that differ here draw different committees and the
chain splits. It is written as pseudocode rather than prose for that reason.

## 1. Weight without floating point

```
weight = bond × multiplier ÷ 1000
```

`multiplier` is an integer in thousandths, from 1000 (×1.0) to 2000 (×2.0). The
division is by 1000, truncating, computed with a 128-bit intermediate so that
the product cannot overflow.

There is no floating point, here or anywhere. A multiplier of "1.8" is the
integer 1800, and two nodes that compute `10_000 × 1800 ÷ 1000` get the same
answer on every platform for ever, which is not true of `10_000.0 × 1.8`.

**At launch the multiplier is frozen at 1000** (`docs/04-proof-of-service.pdf`
§8, phase 1). The service score is accumulated and published but does not affect
weight until validators vote to activate it, on the evidence of months of real
data and a bounty campaign specifically aimed at breaking the diversity metric.

The honest framing R2 requires: with a ×2 cap, **merit makes domination more
expensive, it does not prevent it**. Money alone still suffices — with twice as
much money.

### 1.1 What may feed the multiplier

Only physically provable service (R1.1): sealed-storage challenges and
participation in consensus. **Relay and gateway volumes never feed it**, because
their counterparties are forgeable and the security of consensus must not rest
on a measurement of identities. That measurement is C7, the diversity oracle,
and it is open.

The design rule that follows, and that applies to every future metric:

> A diversity metric MUST fail by **under**-estimating the score, never by
> over-estimating it.

## 2. The epoch

An epoch is 720 blocks. `epoch = height ÷ 720`. The committee for epoch *e+1* is
drawn at the **last block of epoch *e***, seconds before it takes office rather
than hours (R1.4).

## 3. The seed

Each validator seals a hash-chain root when it bonds (`02-hashing.md` §4).
Proposing a block reveals the next link, which the proposer can neither choose —
the chain was fixed before it knew anything — nor withhold without forfeiting
its turn.

```
mixed = H[vanargand v1 epoch seed]( reveal₁ ‖ reveal₂ ‖ … ‖ reveal_n ‖ epoch_be64 )
```

where the reveals are those of the closing epoch, ordered by **ascending
proposer account identifier** — not by the order they arrived, which differs
between nodes.

`mixed` is then passed through a verifiable delay function whose evaluation is
longer than the window in which the last proposer could act, so that even the
last player cannot test which variant suits it. The VDF output, proved in STARK
by paid provers, is the epoch seed.

Two things must be said plainly:

- **The VDF is the single unproven component on the launch path** (R2). The
  documented fallback is hardened commit-reveal, without slashing.
- Because revealing and proposing are one act, R2 **withdrew the R1 penalty for
  non-revelation**. A crash and a deliberate withholding produce the same
  silence, and Vanargand slashes only faults that carry their own proof.
  Silence costs a missed turn and score erosion.

### 3.1 The delay, and the proof that is not a STARK

The delay itself is deliberately dull: `H[vanargand v1 delay function]` iterated
a fixed number of times. Inherently sequential, post-quantum for the same reason
every hash here is, and trivial to agree on.

The hard part is proving it was performed without making every verifier repeat
it. R2 requires a STARK. Short of one, this specification defines a
**checkpointed proof of sequential work**: the prover publishes `s` checkpoints,
one per segment, and a verifier recomputes a sampled subset.

```
c[0]   = input
c[i+1] = H^(iterations/s)( c[i] )
output = c[s]
```

`iterations` MUST be a multiple of `s`. A ragged final segment is an off-by-one
that two implementations can read differently, and a consensus rule readable two
ways is worse than an inconvenient one.

**Soundness, stated rather than assumed.** A prover that skips a fraction *f* of
the work has at least that fraction of its segments wrong. Checking *k* segments
chosen uniformly catches it with probability **1 − (1 − f)ᵏ**. With ten samples:
half the work skipped is caught 99.9 % of the time; one segment in a thousand
skipped is caught about 1 % of the time — and has saved one part in a thousand
of the delay, which attacks nothing.

The guarantee therefore weakens exactly as the cheating becomes pointless. That
is what makes it usable as an interim mechanism, and it remains strictly weaker
than a STARK, which catches any deviation and verifies in constant time.

**The challenge that selects the samples MUST NOT be chosen by the prover.**
Otherwise it picks one that samples only the segments it computed honestly. It
comes from the block that publishes the proof.

An implementation that performs no delay at all MUST use `mixed` directly and
MUST label the chain as a test network. The interface is the same; the security
is not.

## 4. Sampling the committee (normative)

192 members are drawn, weighted, without replacement. Then 64 of them are on
duty at any one block.

### 4.1 The draw

```
candidates ← eligible validators, sorted ascending by account_id
committee  ← empty list
total      ← Σ weight(candidates)

for round from 0 while committee has fewer than 192 members:
    if candidates is empty or total = 0: stop
    x ← H[vanargand v1 committee draw](seed ‖ round_be64)
    r ← (first 16 bytes of x, big-endian, as u128) mod total
    scan candidates in order, accumulating weight,
        take the first whose running total is strictly greater than r
    append it to committee; remove it from candidates; total ← total − its weight
```

Sorting by account identifier, and not by weight or by arrival, is what makes
two nodes agree. Removing the chosen candidate is what makes it *without*
replacement: a validator holding forty per cent of the weight occupies one seat,
not forty per cent of them.

**Modulo bias.** `r` is reduced from a 128-bit value, while `total` is bounded by
the supply, below 2⁶⁴. The resulting bias is smaller than 2⁻⁶⁴ and is accepted
rather than corrected: rejection sampling would make the number of hashes depend
on the draw, and a variable-time consensus rule is a worse problem than a bias
no one can observe in the lifetime of the universe.

### 4.2 The activation schedule

One permutation per epoch, by Fisher–Yates driven by the seed:

```
π ← [0 … 191]
for i from 191 down to 1:
    j ← H[vanargand v1 committee draw](seed ‖ "activate" ‖ i_be64) mod (i+1)
    swap π[i], π[j]
```

Let `n` be the committee's size — 192 when there are at least that many eligible
candidates, fewer otherwise. The members on duty at block `b` of the epoch are a
sliding window over the permutation:

```
count  ← min(64, n)
offset ← b mod n
active(b) = { committee[π[(offset + i) mod n]] : i ∈ [0, count) }
```

A stride of one, deliberately. A larger stride would shuffle the committee
faster between consecutive blocks, and an earlier draft used 65 because it is
coprime with 192 — but the committee is only 192 members when the network is
large enough, and with `n = 65` a stride of 65 leaves the window stationary and
one member never serves at all. A stride of one is coprime with every `n`, needs
no condition, and visits every offset within `n` blocks, which is at most 192 of
the epoch's 720.

The cost is that consecutive blocks share 63 of their 64 members. That is
accepted: it is good for connection reuse, and targeting resistance was never
supposed to come from committee churn.

**This schedule is known an hour in advance, and the specification says so.**
R2 requires the claim of unpredictability to be dropped: what protects a
validator from being targeted is not an unpredictability it does not have, it is
the sentinel architecture — rotating relays in front of the validator, so that
knowing an identity does not give an address.

## 5. Certificates and the threshold

A vote is a signature by a member of the active set over the block's signing
digest (`05-blocks.md` §2). A certificate is a set of votes.

Finality at rung 2 requires **strictly more than two thirds of the active
weight**:

```
3 × Σ weight(signers)  >  2 × Σ weight(active set)
```

Compared by cross-multiplication, never by division. `>` and not `≥`: the
classical BFT bound is strict, and an implementation that accepts exactly two
thirds has a safety bug that only appears when the weights happen to divide
evenly.

A certificate MUST NOT contain two votes from the same member, and each vote
MUST be from a member of the active set for that block.

## 6. The inactivity leak

When rung 2 cannot be reached because too many members are unreachable, the
chain does not stop: it drops to rung 1 and the effective weight of silent
members decays until those present are again above two thirds of what remains.

```
missed_beyond_grace = max(0, consecutive_missed_blocks − grace)
remaining           = max(0, leak_period − missed_beyond_grace)
effective_weight    = weight × remaining ÷ leak_period
```

Linear rather than geometric, because linear is exact in integers.

The decay is **graduated**, and the order matters (R2): the service score first,
then rewards, and the bond itself only after weeks. The point is to restore
liveness without ruining the minority side of a partition at the very moment it
reconnects. Only the effective-weight decay above belongs to this document; the
reward and bond schedules belong to emission.

A member that signs again resets its counter immediately. The leak is a
liveness mechanism, not a punishment, and it must be trivially reversible —
being unreachable is the normal condition this protocol was built for.

## 7. Slashing

**Exactly one fault is slashed: equivocation**, which carries its own proof —
two blocks at one height, one chain, one validator, two different block
identifiers, two valid signatures (`05-blocks.md` §7).

Absence is never slashed. This was R2's first acknowledged error: the R1 penalty
for non-revelation punished a fault nobody can attribute, in a protocol that
claims partition as its normal regime and whose C9 parade rests on the principle
that silence under partition is not guilt. The contradiction was internal, and
the rule restored is:

> Only faults that produce their own proof are seized. Unavailability costs
> graduated penalties and score erosion.

## 8. Parameters

Every one is a point of departure to be fixed by simulation, not a constant.

| Parameter | Value | Constrained by |
|---|---|---|
| block time | 5 s | worldwide network latency |
| epoch | 720 blocks | challenge and draw frequency |
| committee sampled | 192 | R1 oversampling, ×3 |
| committee active | 64 | vote latency, certificate size |
| multiplier range | 1000–2000 | service amplifies, does not replace |
| time to the cap | ~6 months | make attacks slow, not merely expensive |
| erosion to 1000 | ~3 months | merit must be re-earned |
| unbonding delay | ~504 epochs (3 weeks) | the window to denounce a fraud |
| leak grace | 2 epochs | tolerate an ordinary restart |
| leak period | 12 epochs | restore liveness within half a day |

## 9. Open points

- **(open)** The VDF itself: parameters, the STARK prover, and who pays for it.
- **(open)** How the service score is computed from storage challenges and
  consensus participation, and how it erodes. Only its effect on weight is
  specified here.
- **(open)** Proposer selection within the active set. Round-robin over the
  active set by index is the assumption elsewhere in this draft, and it has not
  been checked against A5 (censorship), which wants rotation *and* eventually
  mandatory inclusion lists.
- **(open)** The certificate's wire format, and the succinct STARK certificate
  that R1.7 puts at "trial" status and that Tier 3's federal milestones need.
