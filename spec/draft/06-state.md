<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# 06 — State

**Status: draft.** The tree construction in §2 is intended to be **(frozen)**.

## 1. State and history are different things

`docs/01-concept.pdf` §10 turns on one distinction, and this document is where
it becomes a data structure:

- **State** is what you must know to validate the next transaction: balances,
  open channels, declared offline credits, bonds, registered names.
- **History** is everything that has already happened: useful for audit, useless
  for moving forward.

State is committed to by `state_root` in every block header and is expected to
stay small for ever. History leaves the validators' machines entirely and
becomes the archive market's problem, leaving only a commitment behind
(`archive_commitment`).

The rule that keeps state small is the one that is easiest to forget while
writing code, so it is stated as a requirement:

> **A settled obligation leaves state at the moment it settles.** A balance that
> reaches zero is removed, not stored as zero. A closed channel is deleted, not
> flagged. The ledger holds current obligations, never the memory of paid debts.

An implementation that stores a zero rather than removing a key is not merely
wasteful: every account that ever touched a token keeps a row for ever, and the
"fifty-euro computer in ten years" claim quietly stops being true.

## 2. The sparse Merkle tree (frozen)

A map from 32-byte keys to 32-byte value digests, 256 levels deep, with a single
root that commits to the whole map **and to everything absent from it**.

```
leaf(key, value)   = H[vanargand v1 smt leaf](key ‖ value)
node(left, right)  = ZERO                                   if left = right = ZERO
                   = H[vanargand v1 smt node](left ‖ right)  otherwise
```

Two construction rules, both load-bearing:

**An empty subtree is `ZERO` at every depth.** Without it, proving anything in a
256-level tree would take 256 hashes. With it, the empty parts cost nothing and
a proof is as long as the tree is actually populated.

**A subtree holding exactly one key collapses to that key's leaf hash**, at any
depth. The leaf hash binds the key, so nothing is lost. This is what keeps
proofs proportional to `log₂(populated keys)` rather than to 256.

Keys are walked most-significant-bit first: bit 0 selects the child at the root.

### 2.1 Proofs

A proof is a list of sibling digests, root-downwards, plus a *terminal*:

| Terminal | Proves |
|---|---|
| a leaf whose key is the queried key | the key holds that value |
| a leaf whose key is **different** | the key is absent; this other leaf occupies the position |
| nothing | the key is absent; the subtree is empty |

**A verifier MUST check that a terminal leaf of a different key shares the
queried key's first *n* bits**, where *n* is the number of siblings supplied.
Without that check a prover can take any leaf from anywhere in the tree, attach
it to the queried key's path, recompute upwards with the queried key's bits, and
produce a valid-looking proof that an occupied key is empty. This is the single
subtlest requirement in the document and the implementation has a test named
after the attack.

A verifier MUST reject a proof with more than 256 siblings before doing any
work.

### 2.2 Non-inclusion is the point

An ordinary Merkle tree proves membership. Vanargand needs absence more:

- a name is unregistered, so the registration is legitimate;
- a device has been revoked, so its signature is worthless;
- a channel is closed, so there is nothing left to contest;
- **a state transition is invalid because the input it needed was not there** —
  half of A7's fraud proofs.

## 3. What the tree holds

Every key is **namespaced**:

```
key = H[vanargand v1 state value]( len(namespace) ‖ namespace ‖ payload )
```

| Namespace | Payload | Value |
|---|---|---|
| `account` | `account_id` | digest of the account record (§4) |
| `purse` | opening `txid` | digest of the channel record |
| `asset` | `asset_id` | digest of the asset record |
| `ticker` | the ticker's UTF-8 bytes | the `asset_id` holding it |
| `reserved` | `"burn and context pot"` | digest of the two counters |

An account identifier and a channel identifier are both 32 bytes. Storing them
raw would mean one key space shared by several kinds of record, and a proof
that "key *k* holds this value" would carry no statement about *what kind of
thing* lives there — leaving a verifier to decide from the value's shape, which
is how a parser confusion becomes a consensus bug.

Colliding would still require a preimage, so this is not the difference between
safe and broken. It is the difference between a rule that holds because nobody
can break BLAKE3 and a rule that holds because the namespaces differ, and only
the second survives a future record type whose identifier is not a hash.

The length byte makes the split unambiguous: without it, namespace `asset` with
a payload starting `x` and namespace `assetx` would hash the same bytes.

**The ticker namespace is where non-inclusion earns its keep.** A wallet
checking whether a name is free asks for a proof of absence at
`ticker(name)` — and gets an answer it can verify, rather than a node's word
for it.

Committing the burn counter to the state root is not bookkeeping. It is what
makes `docs/05-emission.pdf`'s invariant — every subsidy comes from fees already
paid, and a share of those fees is destroyed — **checkable by a phone** rather
than asserted by a validator.

A stored value is hashed as
`H[vanargand v1 state value](canonical(record))`, which is a different domain
from the tree's leaf hash. Sharing them would let a record whose encoding
happened to be 64 bytes long produce the same digest as a leaf.

## 4. The account record

```
Account := balances            Map<Option<AssetId>, Amount>
           nomad_credit        Amount
           nomad_margin        Amount
           devices             Map<DeviceId, Device>
           revoked_devices     Set<DeviceId>
           next_lane           Lane
           lanes               Map<Lane, u64>
           guardians           Set<AccountId>
           guardian_threshold  varint
           bonded              Amount
           name                Option<Name>

Device  := key ‖ lane ‖ nomad_share ‖ nomad_spent
```

Every map and set is canonical: strictly ascending keys, no duplicates. The
native asset is the key `None`, which sorts first — absence rather than a
reserved identifier, so there is no "the VAN asset id" to forge, and the common
case is also the smallest encoding.

`revoked_devices` is never emptied and a revoked `device_id` can never be added
again. Otherwise an attacker who once held a device key waits out the
contestation window and has it restored.

`next_lane` is a high-water mark, not a count. A lane below it may have belonged
to a revoked device, and reusing it would let an old signature and a new one
share a `(lane, sequence)` slot and look like equivocation by an account that
did nothing wrong.

## 5. The offline ceiling, as an operation

This is the mechanism `docs/01-concept.pdf` is built around, reduced to a
subtraction. In a **provisional** block only:

```
outflow  = fee + (native amount moved, if any)
remaining = device.nomad_share − device.nomad_spent
require    outflow ≤ remaining
then       device.nomad_spent += outflow
```

Three properties follow, and each is a decision rather than an accident:

**The fee counts.** An attacker able to pay unlimited fees offline would drain
the account past the ceiling by a route the merchant never saw.

**The share belongs to the device, not the account.** R2's correction. With an
account-wide credit, two honest devices isolated in two partitions would each
spend "the" credit and produce an equivocation between them — punishing an
account for being in two places, which is this protocol's normal operating
condition.

**The counters reset when rung-2 finality returns.** The credit is a per-outage
allowance, not a lifetime one, because the guarantee the merchant relies on is
about the partition she is standing in.

The sum of the device shares MUST NOT exceed `nomad_credit`. Otherwise the total
spendable offline is larger than the number published in advance, and the
published number is the only thing that makes the mechanism worth anything.

See `04-transactions.md` §4.1 for the **(open)** gap: local assets are not
covered by this ceiling, and local assets are what the Tier 1 pilot's users
actually spend.

## 6. Applying a transaction

The order is fixed, and it is not the obvious one:

1. envelope checks — version, chain, expiry in **finalised** height;
2. the provisional grammar, if this is a rung-1 block;
3. authority — the account exists, the device exists and is not revoked, the
   device owns the lane;
4. the nonce is exactly the one the lane expects;
5. the offline ceiling, if this is a rung-1 block;
6. the fee, split 70 / 20 / 10;
7. the kind's own effect;
8. the nonce is consumed **last**.

### 6.0 And once per block, before any of that

A block settles every channel whose contestation window has elapsed, in
ascending channel order, **before** it applies any transaction.

There is no `purse_settle` transaction and there should not be. If collecting
what you are already owed required one, a party would have to be online and
hold a fee — and the party most likely to be neither is the one that was
cheated and is waiting for a window to close. Ascending order, because two
nodes crediting the same accounts in different sequences compute different
state roots.

### 6.1 All or nothing

> A transaction that fails MUST leave state byte-for-byte as it was — including
> the fee, including the nonce.

There is no "the fee was taken but the transfer bounced" state. A protocol with
two kinds of failure has two kinds of bug, and a state root that depends on
which one happened. Consuming the nonce last means a rejected transaction can be
retried at the same sequence number rather than stranding the lane.

### 6.2 Determinism

No rule above reads anything but the transaction's bytes and the state they
name. No wall-clock time, no randomness the protocol did not derive, no
iteration over an unordered collection, no floating point.

This is what R2 means when it requires every transaction kind to be specified
"provable": a full node must be able to produce a compact refutation of a bad
transition — the Merkle branches it touched — that a phone verifies in
milliseconds (A7).

## 7. Open points

- **(open)** Rent for entries that claim to last for ever: registered names and
  abandoned dust. `docs/01-concept.pdf` requires "un loyer symbolique" so that
  what nobody claims eventually expires; the schedule, and what happens to a
  name whose owner simply stopped paying, are unspecified.
- **(open)** Incremental root computation. The reference implementation rebuilds
  the tree per block, which is correct and is not what a node should run: it
  needs persisted internal nodes so that a block touching ten accounts costs ten
  paths.
- **(open)** The refutation format for A7, which is the reason non-inclusion
  proofs exist and is not yet written down.
