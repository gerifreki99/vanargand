<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# 05 — Blocks, finality and clocks

**Status: draft.** The header layout in §2 is intended to be **(frozen)**.

## 1. There is no timestamp

A Vanargand block header carries no wall-clock time. This is the most visible
consequence of CONTRIBUTING.md's rule that the only clock is block height, and
it is worth stating as a positive design decision rather than as an omission.

Every other chain carries a timestamp, and every other chain then has to decide
what to do when a proposer lies about it: accept a window, reject outliers,
median-of-committee, and a small body of consensus rules that exist only to
police a field nothing needed.

Nothing here needs one:

- epochs are `height / 720`;
- contestation windows are counted in finalised height (§4);
- the archive market's timed-response challenges measure latency between two
  parties at the transport layer, and never enter state.

A timestamp would be an input a proposer controls, honest nodes cannot check,
and nothing reads.

## 2. The header (frozen)

```
BlockHeader := version             u16
               chain               ChainId   (32)
               height              varint
               parent              BlockId   (32)
               rung                varint    (1 = provisional, 2 = chain)
               finalized_height    varint
               state_root          Hash      (32)
               tx_root             Hash      (32)
               proposer            AccountId (32)
               randomness_reveal   Hash      (32)
               archive_commitment  Hash      (32)
               emitted_supply      Amount    (varint)
               security_budget     Amount    (varint)
               fee_emission_ratio  Ratio     (two varints)
```

`block_id = H[vanargand v1 block id](canonical(BlockHeader))`; the proposer
signs `H[vanargand v1 block signing](chain_id ‖ block_id)`.

Four of these fields exist because a document demanded them, and each is worth
a line:

- **`emitted_supply`** — `docs/05-emission.pdf` §5. One number, comparable in an
  instant against what the formula permits at this height. It is what lets one
  chain audit another from a few kilobytes, and therefore what makes the VAN
  zone possible at all.
- **`security_budget`** — a third of bonded stake: what attacking finality
  actually costs. Published per `docs/05-emission.pdf` §4.
- **`fee_emission_ratio`** — how much of the network lives on its use rather
  than on subsidy, and a gate for opening Tier 2. It is a fraction, and there is
  no floating point in this protocol, so it travels as the two integers it was
  computed from. A verifier recomputes the comparison by cross-multiplication,
  which is exact.
- **`archive_commitment`** — the slice of history archived at this height.
  History leaves the validators' machines and stays verifiable forever.

## 3. The finality ladder

`docs/04-proof-of-service.pdf` §5 replaces all-or-nothing finality with a public
scale, because a protocol whose normal operating condition is partition cannot
afford a consensus that stops when a third of its validators are unreachable.

| Rung | Name | What it means |
|---|---|---|
| 1 | provisional | A cut-off group is producing blocks with the validators it has. A cheque: almost always honoured, guaranteed on presentation. |
| 2 | chain | More than two thirds of the committee's weight has signed. Seconds, and permanent. |
| 3 | federal | The chain's milestone is anchored with its neighbours. Even collusion of every one of its validators cannot rewrite that past. |

**Rung 3 is never a value in a header.** Federal finality is conferred by other
chains after the fact; a block cannot claim it about itself.

A header's `rung` is what the proposer *claims*, and the claim changes which
transactions are grammatically legal (`04-transactions.md` §4). A block claiming
rung 2 that never collects two thirds is simply not final. A block claiming
rung 1 can never become final without being replayed.

A block claiming rung 2 MUST have `finalized_height == height`: it *is* the
finalised tip it refers to. Letting the two differ would give a proposer a
second number to lie about, and every contestation clock in the protocol reads
that number.

## 4. Clocks, and why they are all the same clock

> Every contestation window in Vanargand is counted in **finalised height**.

This is the C9 parade, and it is a single rule rather than a list of special
cases. A partition raises `height` freely and cannot move `finalized_height` at
all. So during an outage, every window that protects an absent party — a channel
closure, a recovery, a bridge exit, a transaction's own validity — stands still.

The implementation makes this structural rather than remembered: the window type
takes a finalised height and there is no overload that takes an ordinary one, so
writing the C9 bug requires writing it on purpose.

A window whose deadline overflows never elapses. That is the safe direction: it
protects the absent party forever rather than expiring immediately.

## 5. Randomness (A4)

Each validator seals a hash-chain root when it bonds. Proposing a block reveals
the next link, which the proposer can neither choose — the chain was fixed
before it knew anything — nor withhold without forfeiting its turn. The epoch
seed mixes the last reveals and passes them through a verifiable delay function,
so that even the last player of an epoch cannot test which variant suits it.

Because revealing and proposing are one act, R2 was able to **withdraw the
slashing penalty for non-revelation** it had introduced in R1. A crash and a
deliberate withholding produce the same silence, and Vanargand slashes only
faults that carry their own proof. Silence costs a missed turn and score
erosion, never a seizure.

The VDF-STARK is, by R2's own account, the single unproven component on the
launch path, with hardened commit-reveal as the documented fallback.

## 6. Committee (parameters, not constants)

| Parameter | Value | Constrained by |
|---|---|---|
| block time | 5 s | worldwide network latency |
| epoch | 720 blocks (~1 h) | challenge and draw frequency |
| committee, active | 64 | vote latency, certificate size |
| committee, sampled | 192 (×3) | R1 oversampling |
| finality threshold | > 2/3 of committee weight | classical BFT |
| unbonding delay | ~504 epochs (~3 weeks) | the window to denounce a fraud |

Every one of these is a point of departure to be fixed by simulation.

Which 64 of the 192 activate follows a schedule derived from the epoch seed and
is therefore **known an hour in advance**. R2 requires this to be said plainly:
what protects a validator from being targeted is not an unpredictability it does
not have, it is the sentinel architecture — rotating relays in front of the
validator, so that knowing an identity does not give an address.

## 7. Validator equivocation (A2)

Two blocks at one height, signed by one validator, on one chain, with different
block identifiers, and two valid signatures. A few hundred bytes, publishable by
anyone on any chain, convicting automatically.

This is the **only** shape of validator misbehaviour that is slashed. See §5.

A "proof" that presents the same block twice, or two blocks at different
heights, or blocks by someone other than the accused, is not evidence, and an
implementation MUST check all three.

## 8. Open points

- **(open)** Validator set representation, committee sampling from the service
  weight, and the certificate format. These belong to `vanargand-consensus` and
  are not specified here.
- **(open)** The inactivity leak's exact schedule: R2 fixes the shape (score
  first, then rewards, and bond only after weeks, so as never to ruin the
  minority side of a partition at the moment of reconnection) but not the rates.
- **(open)** How a light client obtains its first milestone through several
  independent channels (A3's stated precondition).
