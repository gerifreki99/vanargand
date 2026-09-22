<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# 04 — Transactions

**Status: draft.** The discriminants in §3 and the envelope layout in §2 are
intended to be **(frozen)**.

## 1. Every kind is provable

R2's answer to A7 — a two-thirds-corrupt committee finalising an invalid state
that no light client can detect — is a fraud proof over state transitions. That
only works if the transitions are few, fixed and strictly deterministic, so the
constraint lands on every transaction kind defined here:

> A transaction kind MUST NOT depend on anything but its own bytes and the state
> it names. No wall-clock time, no randomness the protocol did not derive, no
> iteration over an unordered collection, no virtual machine.

The practical consequence is that a full node can produce a compact refutation —
the Merkle branches the transition touched — that a phone verifies in
milliseconds.

## 2. The envelope

```
TxBody := version      u16
          chain        ChainId        (32 bytes)
          account      AccountId      (32 bytes)
          device       DeviceId       (32 bytes)
          nonce        Nonce          (lane varint, sequence varint)
          fee          Amount         (varint)
          valid_until  Option<varint>
          kind         TxKind

Transaction := TxBody ‖ Signature
```

`txid = H[vanargand v1 txid](canonical(TxBody))`, over the **body**, so the
identifier does not depend on the signature. It is therefore stable while a
transaction is being assembled, and a third party cannot change it by
re-wrapping.

The signature covers
`H[vanargand v1 tx signing](chain_id ‖ txid)`.

`chain` appears both in the body and in the signing domain. That redundancy is
deliberate: thirty-two bytes beside a 2420-byte ML-DSA signature costs nothing,
it makes a transaction identifier globally meaningful rather than meaningful
only next to the signature that binds it, and it is a second lock on D4.

`valid_until` is a **finalised** height. Every deadline in this protocol is. A
validity window measured in ordinary height would expire inside a partition, and
a transaction that expires while nobody can include it is a transaction the
partition has silently cancelled.

### 2.1 Who may sign

The signing key MUST be a device subkey registered to `account`, and its
`device_id` MUST equal `body.device`. A verifier that checks only "this
signature is valid" and not "this key is the device the body names" has left
every nonce lane, nomad share and equivocation proof hanging off nothing.

## 3. Kinds (frozen discriminants)

Zero is reserved and always invalid, so that a zeroed buffer fails rather than
selecting something. A removed variant keeps its number reserved forever.

| # | Kind | Provisional? |
|---|---|---|
| 1 | `transfer` | **yes** |
| 2 | `nomad_set` | no |
| 3 | `device_add` | no |
| 4 | `device_revoke` | no |
| 5 | `name_commit` | no |
| 6 | `name_reveal` | no |
| 7 | `guardian_set` | no |
| 8 | `recovery_start` | no |
| 9 | `recovery_cancel` | no |
| 10 | `recovery_finalise` | no |
| 11 | `bond` | no |
| 12 | `unbond` | no |
| 13 | `purse_open` | **yes** |
| 14 | `purse_close_cooperative` | **yes** |
| 15 | `purse_close_unilateral` | no |
| 16 | `purse_dispute` | no |
| 17 | `asset_create` | no |
| 18 | `asset_mint` | no |
| 19 | `asset_burn` | no |
| 20 | `account_equivocation` | no |
| 21 | `validator_equivocation` | no |

## 4. The partition grammar (C9)

The third column above is not advice. A transaction kind marked "no" is
**grammatically invalid** in a provisional block, and a provisional block
containing one is invalid in its entirety — not "invalid minus that
transaction", which would make two honest nodes disagree about what the block
was.

The reasoning, kind by kind:

- **`purse_close_unilateral` and `purse_dispute`.** C9 itself. Publishing a
  stale unilateral closure while the counterparty and its watchtower are on the
  far side of a partition would let the contestation window run out in a world
  where the objector cannot exist. Forbidding the transaction offline, *and*
  counting every window in finalised height only, closes it from both
  directions. R2 whitelisted the cooperative closure: both parties signed it, so
  there is no absent victim.
- **`nomad_set`, `device_add`, `device_revoke`.** The offline credit is worth
  something only because the merchant knew the ceiling before the outage.
  Raising it, or minting a new device with a new share, inside the partition
  destroys exactly that property.
- **`recovery_*`, `guardian_set`.** Identity changes need a contestation window,
  and a window cannot run here.
- **`bond`, `unbond`.** Consensus membership is a global fact; one side of a
  split must not change it. `unbond` is named explicitly in R1.3.
- **`name_*`, `asset_create`.** Uniqueness of a name or a ticker is global.
- **`asset_mint`, `asset_burn`.** Issuance changes a supply both sides will have
  to agree on. The Tier 1 pilot's actual need is *transfers* of already-issued
  tokens, which are permitted.
- **Evidence.** Seizure is irreversible; a provisional block is not. Evidence
  keeps — it is replayed on reconnection, and the clocks it feeds were frozen
  the whole time anyway.

### 4.1 Open: the offline ceiling does not cover local assets

R2's monetary inversion puts the Tier 1 consumer's payments in the organiser's
closed token, while the nomad credit of `docs/01-concept.pdf` is denominated in
VAN. So the exact payment the pilot is built around — a human paying in a local
asset, offline — is bounded by nothing.

Three ways out, none chosen:

1. denominate the credit per asset, and let `nomad_set` carry a map;
2. forbid local assets in provisional blocks, which deletes the pilot's use
   case;
3. price local assets into the VAN ceiling at some rate, which needs an oracle
   and is worse than both.

Status: **(open)**. Pinned by a test so that resolving it has to be deliberate.

## 5. Equivocation as evidence

Both evidence kinds carry two signed objects and prove the same shape of fact:
the accused signed two contradictory things in one slot.

For an account (kind 20), the requirements are: same chain, same account, the
same accused device on both, **colliding nonces** — same lane *and* same
sequence — two different transaction identifiers, and two valid signatures.

This is R2's extension of "fraud produces its own evidence" from validators to
ordinary accounts, and it is not a detection mechanism. Because a nomad spend
travels on a single sequenced lane belonging to one device, spending the same
offline credit in two partitions *necessarily* manufactures this object. The
fraud writes its own indictment.

Two rules make it safe:

- **The lane belongs to the device, not the account.** R2's correction. Two
  honest devices of one account, isolated in two partitions, would otherwise
  collide and be punished for being in two places at once — which is this
  protocol's normal operating condition.
- **Evidence about evidence is invalid.** It is a recursion bomb dressed as a
  denunciation, and it proves nothing the inner evidence does not already prove.
  Decoders MUST additionally bound nesting depth, because the rejection happens
  after the parse.

## 6. Names

`name_commit` then `name_reveal`, per R1.7 — F4 front-running was an
acknowledged omission. The commitment is
`H[vanargand v1 name commitment](canonical(name) ‖ salt ‖ account_id)`.

The name is **length-prefixed** inside the commitment. Without that,
`("ab", salt)` and `("a", "b" ‖ salt)` could collide.

The grammar is ASCII lowercase, digits and hyphen; 1 to 32 characters; no
leading, trailing or doubled hyphen. **A decoder rejects, it never normalises**:
normalising would map two encodings to one state key.

This excludes every non-Latin script, which is a real cost for a protocol aimed
at "anywhere there are devices and people". It is taken deliberately: the
alternative is a Unicode confusable table baked into consensus, identical in
every implementation forever, tracking a moving external document. **(open)**
whether Tier 2 adds internationalised names in a separate, visually distinct
namespace, so that the confusable set is a property of that namespace rather
than of the protocol.

### 6.1 Open: the premium threshold contradicts its own example

R1.7 restricts the Harberger-style rent to names of "moins de six caractères",
and in the same sentence names `@marie` as the case the rent must never touch.
`marie` is five characters. Under the rule as written it is premium, rented, and
purchasable against its owner's will — precisely what the sentence forbids.

The implementation follows the rule as written, because moving a design
parameter to fit an example is how a specification stops describing what was
decided. Three ways out: lower the threshold to four; keep six and accept that
five-letter given names are premium; or separate the mechanisms, so that auction
applies to short names while rent applies only to names held by an account that
does not use them. Status: **(open)**.

## 7. Fees

Every fee splits 70 / 20 / 10 — provider, context pot, fire — per
`docs/05-emission.pdf` §4. Provider and pot round **down**; the fire takes the
remainder.

That is not arbitrary. Rounding dust has to go somewhere, and every other
destination is a party with an incentive to steer transaction sizes towards it.
The fire has none. It also guarantees the burn is never *under*-paid, which
keeps C1 sound: the invariant that makes every closed loop lose money is "a
fraction of fees is destroyed", and a rounding rule that could shave the burn to
zero on small fees would hand an attacker a fee size at which wash trading is
free.

## 8. Test vectors

`../vectors/` — and the property tests in `vanargand-types` and
`vanargand-state`, which cover the grammar table of §4 and the equivocation
requirements of §5 case by case.
