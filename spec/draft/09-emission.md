<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# 09 — Emission

**Status: draft.** The figures are points of departure to be tested by
simulation, per `docs/05-emission.pdf` itself. What is **(frozen)** is the
*shape*: a cap, a halving schedule, a burn, and a counter anyone can audit.

## 1. The rule that matters is the auditable one

A monetary policy can be argued about. What cannot be argued about, and what
this chapter exists for, is that **one chain can check another's honesty from a
few hundred bytes**:

> Chaque en-tête de bloc porte la masse totale de VAN émise par la chaîne depuis
> sa naissance […]. Un seul nombre, comparable en un instant à ce que la formule
> autorise à cette hauteur de chaîne.

That is the whole federation in one sentence. A chain whose counter exceeds its
formula is demoted out of the VAN zone by arithmetic; nobody votes.

## 2. The schedule

| Constant | Value |
|---|---|
| epoch | 720 blocks ≈ 1 hour |
| epochs per year | 8 766 (365.25 days) |
| halving period | 4 years = 35 064 epochs |
| first period's total | 50 000 000 VAN |
| cap | 100 000 000 VAN |

```
period(epoch)          = epoch ÷ 35064
period_total(p)        = 50_000_000 VAN >> p        (0 once p ≥ 64)
per_epoch(epoch)       = period_total(period(epoch)) ÷ 35064
permitted_through(e)   = Σ over complete periods + per_epoch × epochs elapsed
```

All in ulf, all truncating **down**. The first period therefore emits
49 999 999 999 989 384 ulf rather than exactly fifty million VAN — a shortfall
of 10 616 ulf, about a hundred-millionth of one VAN. That direction is
deliberate: a chain one ulf *over* its formula fails the border check and is
demoted; a chain one ulf under it is simply a chain.

Since `Σ 1/2ᵖ = 2`, the schedule's limit is exactly twice the first period, which
is the cap. It is not approached asymptotically for ever: once a period's total
has been halved below 35 064 ulf there is nothing left to divide by the epochs,
and **emission stops** — at period 41, year 164.

R2 moved the halving from two years to four. Two concentrated half of all the
money that will ever exist into the first twenty-four months of a network nobody
had heard of, which is a distribution shape rather than a schedule.

## 3. The three envelopes

60 % validators, 25 % bootstrap, 15 % treasury — `vanargand_types::amount::EmissionSplit`.

Each is rounded down and **the remainder is not emitted at all**, which is the
opposite convention from a fee split. A fee already exists and must be fully
accounted for; emission is being *created*, and the rule governing creation is
that a chain may never mint more than the formula allows. Two ulf an hour is not
a price worth arguing about; a demotion is.

## 4. Secondary emission: regeneration

Primary emission exists **only on the founding chain**. Every other chain in the
VAN zone is born with a minting right of zero and fills up through bridges, as a
country without a gold mine fills up through trade.

What every conforming chain may do is **regenerate**: re-mint at most half of
what it burned in the previous epoch.

```
max_regeneration(burned) = burned ÷ 2
```

The arithmetic consequence is the point. No chain can create more than it
destroys, so the total mass can only erode with use — and manufacturing traffic
to farm regeneration burns a hundred to re-mint fifty, which is structurally a
machine for losing money.

## 5. The border check (normative)

A verifier holding a header and its parent checks three things. None needs the
chain's history, its state, or its cooperation.

1. `emitted_supply ≥ parent.emitted_supply` — the counter is cumulative since
   genesis. **A counter that can decrease is a counter that can be reset**, and
   the whole audit rests on it never being.
2. `emitted_supply ≤ MAX_SUPPLY`.
3. `emitted_supply ≤ permitted_through(height ÷ 720)`.

Failing any of the three is not a rejected block on a foreign chain — it is
evidence, publishable by any scout, that demotes the chain out of the VAN zone
and burns the bonds behind it.

## 6. The fee, and the fire

Every fee splits 70 / 20 / 10 — provider, context pot, fire — with the
remainder to the fire (`04-transactions.md` §7).

The burn is the keystone and deserves restating here, because it is what makes
C1 hold: **every closed loop loses the burn on every turn.** A robot cycling its
own money through its own chains pays 100 to recover at most 90, whatever the
arrangement, whatever the number of chains, whichever way it turns. The
destroyed share is also what lets regeneration exist without inflating the mass,
and what makes each real use of the network a small gift to everyone holding
VAN.

R1.2's transversal invariant belongs here and is **not implemented**: for any
identity and any epoch, total subsidies captured must not exceed α times the
fees burned by payers of diverse provenance. It is the single inequality that
caps a multi-channel attacker globally rather than mechanism by mechanism, and
it depends on C7 — the diversity oracle — which is open. **(open)**

## 7. What is implemented, and what is carried without being checked

Implemented: §2, §4 and §5, as `vanargand_consensus::emission`, checked by
`vanargand-node` on every block.

Carried but **not** checked: `fee_emission_ratio`, the health metric R1.5 makes
a go/no-go criterion for opening Tier 2. Verifying it needs the epoch's total
real fees, and no crate accumulates them — the ledger tracks the burn and the
context pot but not the providers' share. **(open)**

Not implemented at all: the three envelopes' *distribution*, the missions and
usage credits of the bootstrap fund, the self-constituting bond of R2 (rewards
locked as bond until the minimum is reached), and validator reward vesting.
Every one of those is a way of *paying* emission out; this chapter only
constrains how much may exist.
