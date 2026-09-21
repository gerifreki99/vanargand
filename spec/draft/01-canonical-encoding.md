<!--
SPDX-FileCopyrightText: 2026 Freki Geri
SPDX-License-Identifier: CC-BY-4.0
-->

# 01 — Canonical encoding

**Status: draft.** Everything in this document is intended to be **(frozen)** at
the genesis block.

## 1. Why this document exists first

Two honest nodes that encode the same object into different bytes compute
different hashes, and two different hashes are a consensus failure. Every other
document depends on this one, so this one depends on nothing.

The encoding has one property, and the property is not compactness:

> **Bijectivity.** Every valid object has exactly one valid encoding, and every
> valid encoding decodes to exactly one object.

The second half is the half that gets forgotten. An encoder that only ever
emits canonical bytes is not enough: a decoder that *accepts* a non-canonical
encoding of the same object lets an attacker produce two byte strings that a
node treats as the same transaction but that hash differently. Decoders
specified here MUST reject non-canonical input rather than normalise it.

## 2. Primitive types

### 2.1 `varint` (frozen)

Unsigned LEB128. Each byte carries seven payload bits in its low bits; the high
bit is set on every byte except the last. Payload is little-endian: the first
byte holds the least significant seven bits.

Encoding of *n*:

```
while n >= 0x80:
    emit (n & 0x7f) | 0x80
    n >>= 7
emit n
```

Decoders MUST enforce all three of:

1. **Shortest form.** The last byte MUST NOT be `0x00` unless the whole encoding
   is the single byte `0x00`. Encoding `1` as `81 00` is invalid.
2. **Bounded width.** At most ten bytes, the width of `u64::MAX`.
3. **No overflow.** The accumulated value MUST fit the declared target width.
   A `varint` in a `u32` field that decodes to `0x1_0000_0000` is invalid, not
   truncated.

Rationale for LEB128 over a fixed width: most integers in a transaction are
small (lane indices, sequence numbers early in an account's life, enum
discriminants), and the state is hashed, stored and gossiped far more often
than it is parsed.

| Value | Encoding |
|---|---|
| 0 | `00` |
| 1 | `01` |
| 127 | `7f` |
| 128 | `80 01` |
| 300 | `ac 02` |
| 2^32 − 1 | `ff ff ff ff 0f` |
| 2^64 − 1 | `ff ff ff ff ff ff ff ff ff 01` |

### 2.2 Fixed-width integers (frozen)

Used only where a field is semantically fixed-width — a version byte, a
discriminant reserved for future growth. Written little-endian. Notation:
`u8`, `u16le`, `u32le`, `u64le`.

`u8` is a single byte and is **not** a `varint`. Where this document says `u8`
it means one byte on the wire.

### 2.3 Byte strings (frozen)

`bytes` := `varint` length ‖ that many raw bytes.

`[u8; N]` (a fixed-length array, e.g. a 32-byte hash) := exactly N raw bytes,
**no length prefix**. The length is known from the schema; prefixing it would
give an attacker a second place to put a number.

### 2.4 Strings (frozen)

`string` := `bytes`, whose contents MUST be valid UTF-8.

Additionally, a `string` that appears in a field subject to a uniqueness
constraint in state — a registered name, an asset ticker — is subject to the
normalisation and confusable rules of `04-transactions.md`, and a value that is
not already in normal form is **invalid**, never normalised on the way in. A
decoder that normalises is a decoder that lets two distinct encodings map to one
state key.

### 2.5 Booleans (frozen)

`bool` := `u8`, exactly `0x00` (false) or `0x01` (true). Any other byte is
invalid. There is no "non-zero is true".

## 3. Composite types

### 3.1 Structs (frozen)

Fields are encoded back to back, in the order declared in the schema. There is
no field count, no tag, and no padding. Adding a field to a struct is a
compatibility break and requires a new specification version.

### 3.2 `Option<T>` (frozen)

`00` for absent, or `01` ‖ encoding of T for present. Absent MUST NOT be
encoded as a present zero value.

### 3.3 Sequences (frozen)

`Vec<T>` := `varint` count ‖ each element in order.

Where a sequence models a **set** — a guardian list, a validator set, a list of
revoked device ids — the schema says so, and the encoding is additionally
constrained: elements MUST appear in strictly ascending order by their encoded
byte string, compared lexicographically. Strictly ascending forbids duplicates
and fixes the order in one rule. A decoder MUST reject an out-of-order or
duplicated set.

This is the encoding-level half of the CONTRIBUTING rule against `HashMap` and
`HashSet`: unordered collections are not merely discouraged in memory, they have
no wire representation at all.

> **Encoded order is not numeric order.** For `varint` elements the two differ:
> 255 encodes as `ff 01` and 256 as `80 02`, so under this rule 255 sorts
> *after* 256. Comparing encoded bytes is what lets a verifier check the
> ordering without decoding, which is why the rule is written this way, but it
> means an implementation must not assume a numerically sorted list is a valid
> set. Every set in this specification holds fixed-width 32-byte identifiers,
> where encoded order and numeric order coincide; a future set over
> variable-width elements MUST state which order it means.

### 3.4 Maps (frozen)

`Map<K, V>` := `varint` count ‖ (K, V) pairs, ordered by the encoded byte string
of K, strictly ascending. Duplicate keys are invalid.

### 3.5 Enums (frozen)

`varint` discriminant ‖ encoding of the selected variant's payload.

Discriminants are assigned once and never reused, including after a variant is
removed. A removed variant's discriminant becomes permanently reserved: state
written under the old rules stays readable, and a future variant cannot
accidentally inherit the meaning of an old one.

## 4. What this encoding deliberately lacks

**No self-description.** The bytes do not say what they are. A decoder is always
invoked against a known schema. This removes an entire class of parser
confusion, and it is why there is no "skip unknown field" rule: there are no
unknown fields, only invalid input.

**No floating point.** There is no encoding for `f32` or `f64` and there will
not be one. Quantities that would naturally be fractional — the fee split, the
service multiplier, the fee/emission health ratio in the block header — are
specified as integers in fixed-point units in `05-blocks.md`, with their
rounding rule stated. See CONTRIBUTING.md.

**No timestamps.** There is no encoding for a wall-clock time. The only clock in
Vanargand is block height.

**No signature inside the signed object.** A signature never covers itself. The
split between a signable body and its envelope is specified in
`04-transactions.md`.

## 5. Limits (frozen)

A decoder MUST enforce these before allocating. They exist so that a node
parsing a hostile 40-byte message cannot be made to reserve a gigabyte.

| Limit | Value | Applies to |
|---|---|---|
| `MAX_OBJECT_SIZE` | 1 048 576 bytes | any single top-level encoded object |
| `MAX_SEQ_LEN` | 65 536 elements | any `Vec<T>`, set or `Map<K, V>` |
| `MAX_BYTES_LEN` | 1 048 576 bytes | any `bytes` or `string` field |
| `MAX_NESTING` | 32 | nested composite depth |

A length prefix that exceeds the remaining input is invalid, and MUST be
detected as invalid *before* the implementation allocates a buffer of the
declared size.

## 6. Test vectors

[`../vectors/01-canonical-encoding.json`](../vectors/01-canonical-encoding.json)

Each entry is one of:

- `encode`: an object and its unique valid encoding, checked in both directions.
- `reject`: a byte string that MUST fail to decode against a named schema, with
  the reason. These are the important ones — an implementation that passes every
  `encode` case and no `reject` case is exactly the malleable implementation
  this document exists to prevent.

## 7. Open points

- **(open)** Whether `MAX_SEQ_LEN` is per-field rather than global. A validator
  set and a guardian list have very different natural bounds, and one global
  limit is a limit that is wrong twice.
- **(open)** Whether the set ordering rule should compare by encoded bytes (as
  specified) or by a declared key. Encoded bytes is simpler to verify and harder
  to get subtly wrong; a declared key would read better in the few places where
  the encoding's leading bytes are a version tag shared by every element.
