<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# 03 — Keys, identity and addresses

**Status: draft.** §2, §4 and §5 are intended to be **(frozen)**.

## 1. What an identity is

An identity is created offline, for free, with no authority — this is a design
requirement of `docs/01-concept.pdf`, not an accident, and it is also the reason
C3 (Sybil on bootstrapping) is unsolvable by counting accounts. Everything in
this document follows from it.

An account has:

- one **root key**, which certifies device subkeys and nothing else;
- zero or more **device subkeys**, which sign transactions, each holding its own
  nonce lane and its own share of the nomad credit (R2);
- one **scan key**, an ML-KEM encapsulation key, used by the messaging layer;
- zero or more **guardians**, for social recovery.

The root key signs as rarely as possible. In normal operation it signs once, to
certify the first device, and then goes into cold storage or is split among
guardians. A key that signs every coffee is a key that lives in a hot process.

## 2. Algorithm identifiers (frozen)

Every key, signature and ciphertext in Vanargand carries a one-byte algorithm
identifier. There is no "the default algorithm" anywhere on the wire. This is
the version byte that `CONTRIBUTING.md` requires on every protocol object, and
it is what makes a future migration a protocol change rather than a hard fork of
every stored object.

| Id | Algorithm | Role | Public key | Signature / ciphertext |
|---|---|---|---|---|
| `0x00` | — | reserved, always invalid | — | — |
| `0x01` | ML-DSA-44 (FIPS 204) | signature | 1312 B | 2420 B |
| `0x02` | ML-KEM-768 (FIPS 203) | KEM | 1184 B | 1088 B |
| `0x03` | ML-DSA-65 (FIPS 204) | signature, high-stakes | 1952 B | 3309 B |
| `0x10`–`0x1f` | reserved | test vectors only, never valid on a live chain | — | — |

`0x00` is reserved as invalid on purpose: a zeroed buffer that is read as a key
must fail, not select something.

**ML-DSA-44 is the default** (R1.7). The choice is explicitly *not* the compact
one: FALCON's signatures are far smaller, but a safe FALCON implementation needs
constant-time floating-point arithmetic, and Vanargand runs on whatever hardware
a festival has. A few kilobytes beat a side channel. ML-DSA-65 is reserved for
the objects where size does not matter and compromise is unrecoverable —
cross-chain milestones and large bridge freezes (Tier 3) — where
`docs/01-concept.pdf` calls for "a door with two independent locks".

Implementations MUST use the **deterministic (hedged-free) variant** of ML-DSA
signing for any signature that enters state. Randomised signing means the same
transaction signed twice yields two distinct valid encodings, which is a
malleability source and makes test vectors impossible to write.

## 3. Key hierarchy and derivation

A wallet holds one 32-byte `master_seed`. Everything else is derived, so that a
recovered seed recovers the whole identity and no key material ever needs to be
backed up separately.

```
derive(path) = H[vanargand v1 key derivation](path ‖ master_seed)
```

where `path` is a sequence of at most 8 `u32` components, encoded as **one
length byte followed by each component as a little-endian `u32`**. The result is
a 32-byte seed, used directly as the FIPS 204 / FIPS 203 key-generation seed ξ,
which makes key generation deterministic and reproducible from the master seed
alone.

This encoding is deliberately *not* the canonical codec of
`01-canonical-encoding.md`, even though it would fit. A key hierarchy that
cannot be recomputed without the transaction encoder is a key hierarchy that a
recovery tool cannot reimplement in fifty lines, and the one piece of this
protocol that must stay reimplementable by a stranger, from the document alone,
in a hurry, is the one that gets someone's identity back.

Reserved paths:

| Path | Key |
|---|---|
| `[0]` | root signing key |
| `[1, i]` | device subkey *i* |
| `[2]` | scan key (ML-KEM) |
| `[3, i]` | one-time address *i* (§6) |
| `[4, i]` | PayWord chain seed for channel *i* |
| `[5, i]` | commitment chain seed for bond period *i* |

Note that `master_seed` is placed **after** the path in the hashed material.
This is not cosmetic: BLAKE3's `derive_key` is not a length-extension-vulnerable
construction, but putting the secret last keeps the habit correct for anyone who
later reaches for a different hash.

## 4. Account and device identifiers (frozen)

```
account_id = H[vanargand v1 account id](algorithm_id ‖ root_public_key)
device_id  = H[vanargand v1 device id](algorithm_id ‖ device_public_key)
```

Both are 32 bytes. Both commit to the algorithm id, so the same key bytes
interpreted under two algorithms yield two different identifiers.

The account id is the state key. It is **not** derived from any device key, so
rotating or revoking every device on an account does not change the account's
address — which is the whole point of the root-key layer, and what makes "lose
your phone" survivable.

## 5. Address text encoding (frozen)

Addresses are written in **Bech32m** (BIP-350), not Bech32 (BIP-173). Bech32's
checksum has a known weakness when the data part length changes; Bech32m fixes
it by changing the final constant from 1 to `0x2bc830a3`. Vanargand has no
legacy to preserve, so it uses only Bech32m and MUST reject Bech32.

```
hrp        = "van"          (mainnet)
             "tvan"         (public test network)
data       = [version] ‖ base32(payload)
version    = 0              for a 32-byte account id
```

`base32` is the Bech32 character set `qpzry9x8gf2tvdw0s3jn54khce6mua7l`,
five bits per character, over the 32-byte payload — 256 bits, which is 51.2
characters, so the payload is padded to 52 characters with zero bits in the
final character's low positions. The padding bits MUST be zero and a decoder
MUST reject non-zero padding.

A mainnet account address is therefore `van1` + 1 version char + 52 payload
chars + 6 checksum chars = **63 characters**.

Decoders MUST enforce every rule of BIP-350: the string is entirely lowercase or
entirely uppercase (mixed case is invalid), total length at most 90 characters,
HRP characters in `[33, 126]`, and at least one data character. An address whose
HRP does not match the network being addressed MUST be rejected rather than
reinterpreted — the separate `tvan` prefix exists so that a test-network address
pasted into a mainnet wallet fails loudly instead of burning funds.

Version values other than 0 are reserved. A decoder that does not recognise a
version MUST reject; it MUST NOT treat the payload as opaque and forward it.

## 6. One-time addresses

R2 adopts "generalised one-time addresses" to close C10 (mission proofs leaking
payer addresses) and to reduce the payment graph generally.

**What Tier 1 specifies.** A one-time address is an ordinary account address
derived at path `[3, i]`. The recipient generates them from its own seed and
hands them to the payer over the encrypted messaging layer, which already exists
in Tier 1 and already carries a session between the two parties. On-chain there
is no linkage and no special transaction type: a one-time address is
indistinguishable from any other new account.

**What Tier 1 does not specify, and why.** The attractive version is
non-interactive: the payer derives a fresh address for the recipient from the
recipient's published key alone, with no prior contact. Every deployed
construction for this — Monero's dual-key stealth addresses, EIP-5564 — relies
on the additive structure of an elliptic-curve group, which lets the payer tweak
a public key without the private key. **ML-DSA has no such structure**, and
neither does any lattice signature standardised so far.

A post-quantum substitute exists and is sketched here so that the cost is on the
record rather than discovered later: the payer encapsulates to the recipient's
scan key, obtaining `(ct, ss)`; both derive `seed = H[…](ss)`; the recipient
generates the one-time signing key from `seed`. This works, but scanning costs
one ML-KEM decapsulation *per announcement on the chain*, against one elliptic
curve multiplication in the classical schemes — and the announcement `ct` is
1088 bytes rather than 33.

Status: **(open)**. Interactive one-time addresses are enough for Tier 1's
actual privacy target, which is mission stamps between parties that already have
a session. Non-interactive PQ stealth addressing is a research item for the test
network, not a launch blocker.

## 7. Multi-device, guardianship and recovery

Per R1.6, every device of an owner is automatically a guardian of that owner's
identity and a watchtower for that owner's channels. Adding a device reuses the
recovery machinery: co-signature by an existing device plus one guardian, with a
short contestation window.

The transaction types are specified in `04-transactions.md`. Two rules belong
here because they are properties of the identity layer:

1. **Every recovery clock is counted in finalised block height only.** A
   recovery started during a partition does not mature inside that partition.
   This is the identity-layer instance of the C9 parade, and it is why
   `recovery_*` is on the provisional blacklist of `05-blocks.md`.
2. **A revoked device id is never reused.** Revocation is recorded permanently
   in the account's device set; a `device_add` naming a previously revoked
   `device_id` is invalid. Otherwise an attacker who once held a device key
   could wait out the contestation window and re-add it.

G4 (social attack on recovery) is not solved by these rules and is not claimed
to be. It is an attack on humans, and the parades — high thresholds, a
contestation window during which the old device can cancel, notification on
every channel — are product decisions that this document only constrains.

## 8. Test vectors

[`../vectors/03-addresses.json`](../vectors/03-addresses.json): derivation paths
to seeds, seeds to account ids, account ids to Bech32m strings, plus a
rejection set covering mixed case, bad checksum, Bech32-instead-of-Bech32m,
non-zero padding bits, wrong HRP, unknown version and over-length input.

Note that the vectors for §4 are computed from *given* public key bytes rather
than from a seed, so that they can be checked without an ML-DSA implementation.
Vectors that require real ML-DSA key generation are marked `requires: mldsa44`
and may be skipped by an implementation that has not wired a backend yet.
