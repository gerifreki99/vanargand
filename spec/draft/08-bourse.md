<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# 08 — Channels

**Status: draft.** The PayWord construction of §2 is intended to be **(frozen)**;
the penalty and window sizes in §4 are parameters.

## 1. What a channel is for

Two parties lock a sum, exchange acknowledgements off-chain for free, and write
only the final balance. A thousand micro-payments cost two entries in the
register.

Without this, "buy a megabyte of connectivity from the passenger next to you"
is a slide rather than a product: a ledger entry per megabyte is neither cheap
enough nor fast enough, and it is the feature that gives the VAN its first real
use (`docs/02-scope.pdf`, Tier 1).

**Strictly two parties** (R1.6). Multi-party channels are a research topic;
groups go through a hub or through unanimous locking, and tree-shaped channels
mature on the test network first.

## 2. PayWord (frozen)

The payer seals a hash chain when the channel opens and publishes its root. The
*i*-th tranche is paid by revealing the *i*-th link.

```
link[n]  = seed
link[i]  = H[vanargand v1 payword](link[i+1])
root     = link[0]
```

A token is `(index, link)`. The index is not redundant: a verifier walking from
the root learns only the distance, and must check that the distance equals the
claimed index — otherwise a payer presents the link for tranche 400 while
claiming tranche 5.

Verification is `index` hashes. `MAX_TRANCHES` is 65 536, and the bound is not
tidiness: without it a claim of four billion tranches is a denial of service
against every node that validates the closing transaction (A6).

One token settles every tranche below it, so a payee that misses messages loses
nothing and a payer that owes forty tranches sends one 32-byte value.

**A chain is never reused.** Two channels sharing one would let the second payee
spend the first payee's tokens. Seeds come from the key hierarchy at
`[4, channel_index]`, which makes reuse something someone has to write on
purpose.

### 2.1 What it costs, against the alternative

| Per micro-payment | Signature scheme | PayWord |
|---|---|---|
| Bytes on the wire | 2420 | 32 |
| Verification | one ML-DSA verify | one hash |

R2's note on adopting a 1997 construction unchanged is a design principle worth
keeping: *la solution éprouvée est si bien adaptée que l'innovation est
inutile.*

## 3. Closing

### 3.1 Cooperatively

Both parties sign a final split. It must sum **exactly** to the deposit — a
cooperative closure that created or destroyed value would be a mint or a burn
that two parties signed and nobody audited.

There is no contestation window, because there is no absent victim. That is why
R2 whitelists this transaction in provisional blocks, and why the application
prompts a user to close their channels before a planned outage.

### 3.2 Unilaterally

One party publishes a claim of *n* tranches with the token that proves it, and a
window opens. A claim of zero needs no token; the payee's remedy against a false
zero is to dispute, which is the whole mechanism.

### 3.3 Only the payer can lie

A claim is believed only with the token that proves it, so **over**-claiming
would require a preimage. The payee therefore cannot inflate what it is owed,
and the payer's only attack is to *under*-claim.

That asymmetry is what makes disputes a single rule: present a **strictly
larger** token. Equal is not fraud; smaller is the disputer arguing against
itself.

## 4. The window, and C9

> Every contestation window is counted in **finalised height**.

This is the entry the whole chapter exists for, and it is documented as **C9**
in the threat model, credited to the external review.

The attack: publish a stale unilateral closure into provisional blocks while the
counterparty and its watchtower are on the far side of a partition. The window
elapses in a world where the objector cannot exist. Neither literature covers
it — payment channels assume liveness, partitions ignore channels.

The parade has two halves, and both live outside the channel logic:

1. `purse_close_unilateral` and `purse_dispute` are **grammatically illegal** in
   a provisional block (`04-transactions.md` §4). `purse_close_cooperative` is
   whitelisted.
2. Deadlines are counted in finalised height only. A partition raises the
   ordinary height freely and cannot move the finalised tip at all, so the
   window stands still for exactly as long as the objector cannot speak
   (`05-blocks.md` §4).

The implementation makes the second half structural: the window type takes a
finalised height and there is no overload taking an ordinary one, so writing the
C9 bug requires writing it on purpose.

| Parameter | Value | Constrained by |
|---|---|---|
| dispute window | 24 epochs of **finalised** height (~1 day) | a domestic watchtower's chances to notice |
| penalty for a proved stale claim | the payer's whole remaining share | a watchtower that is not paid is not watching |

The penalty's size is a parameter. What is not a parameter is that it exists and
that it goes to the party that was cheated.

## 5. Watchtowers

A window is worth nothing unless somebody is awake for it. R1.6 makes that
structural rather than a service you remember to buy: **every device of an owner
is automatically a watchtower for that owner's channels**. The ordinary case is
that the victim's own laptop objects.

A watchtower holds the best token per channel — 32 bytes and an index — and
**no secret**. That is what makes the design work: a watchtower needing a
signing key would mean the key living on every device, which is precisely what
the root-key hierarchy exists to avoid. The worst a dishonest watchtower can do
is fail to act; it can never steal.

A watchtower holding *less* than a pending claim should say so rather than stay
silent. It may simply have missed the newest tokens, and its operator should
hear about that.

## 6. Expiry is hygiene, not liveness

A channel carries an expiry in finalised height. It is **not** a liveness
mechanism: a payee that vanishes never strands the deposit, because the payer
can close unilaterally with the true count and the window runs out unopposed.

Expiry exists so that a forgotten channel eventually stops occupying state,
which is `docs/01-concept.pdf`'s requirement that settled obligations leave the
ledger the moment they close.

## 7. Open points

- **(open)** Batched cooperative closure through an HTLC hub, which R2 schedules
  for Tier 2.
- **(open)** Tree-shaped channels — group state as bilateral sub-balances with
  contestation localised to an edge. R1.6 status: trial, on the test network.
- **(open)** What a watchtower is paid, and by whom. "Guetteurs rémunérés"
  appears throughout the design documents and the payment has no mechanism yet.
  Until it does, the only watchtowers with an incentive are the owner's own
  devices — which is most of them, but not the single-device user.
- **(open, residual)** A channel with a gateway remains a partial location
  trace, acknowledged in R2 and not solved.
