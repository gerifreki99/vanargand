// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! BLAKE3 and domain separation.
//!
//! See `spec/draft/02-hashing.md`. The rule that governs this module in one
//! line: **no protocol object is ever hashed with a bare hash function.** Every
//! hash goes through a [`Context`] from [`domain`].
//!
//! The reason is that Vanargand is full of 32-byte values that get hashed
//! again — a transaction id, a Merkle node, a commitment-chain link, a PayWord
//! token. Without separation, a preimage produced in one role could be
//! presented in another. With it, each role has its own function.

use core::fmt;

use crate::error::CryptoError;

/// Length of every hash in the protocol, in bytes.
pub const HASH_LEN: usize = 32;

/// A domain separation context.
///
/// Wraps a `&'static str` rather than a `&str` on purpose: a context string
/// assembled at run time from caller-controlled data is a domain separation
/// bug dressed as a fix, and the type system can rule it out for free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Context(&'static str);

impl Context {
    /// Declares a context. Only [`domain`] should call this.
    #[must_use]
    pub const fn new(context: &'static str) -> Self {
        Self(context)
    }

    /// The context string, as hashed.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// The registry of every domain separation context in the protocol.
///
/// This module is the machine-readable copy of the table in
/// `spec/draft/02-hashing.md` §3. Adding a hash to Vanargand means adding a
/// line to both, and the test at the bottom of this file checks that no two
/// lines here collide.
pub mod domain {
    use super::Context;

    /// Account identifier, over `algorithm_id ‖ root_public_key`.
    pub const ACCOUNT_ID: Context = Context::new("vanargand v1 account id");
    /// Device identifier, over `algorithm_id ‖ device_public_key`.
    pub const DEVICE_ID: Context = Context::new("vanargand v1 device id");
    /// Key hierarchy, over `path ‖ master_seed`.
    pub const KEY_DERIVATION: Context = Context::new("vanargand v1 key derivation");
    /// Transaction identifier, over the canonical encoding of the body.
    pub const TXID: Context = Context::new("vanargand v1 txid");
    /// What a transaction signature actually covers: `chain_id ‖ txid`.
    pub const TX_SIGNING: Context = Context::new("vanargand v1 tx signing");
    /// Name registration commitment, over `canonical(name) ‖ salt ‖ account_id`.
    pub const NAME_COMMITMENT: Context = Context::new("vanargand v1 name commitment");
    /// Asset identifier, over `creator_account_id ‖ creating_txid`.
    pub const ASSET_ID: Context = Context::new("vanargand v1 asset id");
    /// Block identifier, over the canonical encoding of the header.
    pub const BLOCK_ID: Context = Context::new("vanargand v1 block id");
    /// What a block signature covers: `chain_id ‖ block_id`.
    pub const BLOCK_SIGNING: Context = Context::new("vanargand v1 block signing");
    /// Sparse Merkle tree leaf, over `key ‖ value_hash`.
    pub const SMT_LEAF: Context = Context::new("vanargand v1 smt leaf");
    /// Sparse Merkle tree internal node, over `left ‖ right`.
    pub const SMT_NODE: Context = Context::new("vanargand v1 smt node");
    /// A value stored in the state tree, over its canonical encoding.
    ///
    /// Distinct from [`SMT_LEAF`], which covers `key ‖ value_hash`. Sharing
    /// them would let a record whose encoding happened to be 64 bytes long
    /// produce the same digest as a leaf, which is the kind of coincidence this
    /// module exists to make impossible rather than improbable.
    pub const STATE_VALUE: Context = Context::new("vanargand v1 state value");
    /// Consensus randomness chain (A4): each link over the next.
    pub const COMMITMENT_CHAIN: Context = Context::new("vanargand v1 commitment chain");
    /// PayWord micro-payment chain: each token over the next.
    pub const PAYWORD: Context = Context::new("vanargand v1 payword");
    /// Epoch randomness seed, over the mixed reveals and the epoch number.
    pub const EPOCH_SEED: Context = Context::new("vanargand v1 epoch seed");

    /// Every context declared above.
    ///
    /// Used by the collision test, and by `tools/vectorgen` to generate the
    /// registry vectors. A context missing from this list is a context whose
    /// uniqueness nobody checked.
    pub const ALL: &[Context] = &[
        ACCOUNT_ID,
        DEVICE_ID,
        KEY_DERIVATION,
        TXID,
        TX_SIGNING,
        NAME_COMMITMENT,
        ASSET_ID,
        BLOCK_ID,
        BLOCK_SIGNING,
        SMT_LEAF,
        SMT_NODE,
        STATE_VALUE,
        COMMITMENT_CHAIN,
        PAYWORD,
        EPOCH_SEED,
    ];
}

/// A 32-byte BLAKE3 digest.
///
/// Ordering is lexicographic over the bytes, which is what makes this type
/// usable as a `BTreeMap` key and what the canonical set ordering rule of
/// `spec/draft/01-canonical-encoding.md` §3.3 relies on.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    /// The all-zero hash.
    ///
    /// Used as the parent of the genesis block and as the empty-subtree value
    /// at the bottom of the sparse Merkle tree. It is not the hash of anything:
    /// finding a preimage for it would be a break of BLAKE3, so using it as a
    /// sentinel is safe.
    pub const ZERO: Self = Self([0_u8; HASH_LEN]);

    /// Wraps 32 bytes that are already a digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Wraps a slice that must be exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let array: [u8; HASH_LEN] =
            bytes.try_into().map_err(|_| CryptoError::BadHashLength(bytes.len()))?;
        Ok(Self(array))
    }

    /// The digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Consumes the hash, returning its bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; HASH_LEN] {
        self.0
    }

    /// Lowercase hex, 64 characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(HASH_LEN * 2);
        for byte in self.0 {
            out.push(nibble_to_hex(byte >> 4));
            out.push(nibble_to_hex(byte & 0x0f));
        }
        out
    }

    /// Parses 64 hex characters, either case.
    pub fn from_hex(text: &str) -> Result<Self, CryptoError> {
        let bytes = decode_hex(text)?;
        Self::from_slice(&bytes)
    }

    /// Reads bit `index` of the digest, counting from the most significant bit
    /// of byte 0.
    ///
    /// This is the bit order the sparse Merkle tree walks: bit 0 selects the
    /// child at the root. Defining it here, once, keeps the tree and its test
    /// vectors from disagreeing about which end of the key is the top.
    ///
    /// Returns `false` for an index at or past 256 rather than panicking,
    /// because this runs on untrusted proofs.
    #[must_use]
    pub const fn bit(&self, index: usize) -> bool {
        if index >= HASH_LEN * 8 {
            return false;
        }
        let byte = self.0[index / 8];
        let shift = 7 - (index % 8);
        (byte >> shift) & 1 == 1
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Full hex, not truncated. A truncated hash in a log is a hash you
        // cannot grep for when you need it at three in the morning.
        write!(f, "Hash({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An incremental hasher bound to a domain.
///
/// There is no way to construct one without a [`Context`], which is the point.
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Hasher {
    /// Starts hashing in `context`.
    #[must_use]
    pub fn new(context: Context) -> Self {
        Self { inner: blake3::Hasher::new_derive_key(context.as_str()) }
    }

    /// Absorbs more input.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Finishes, producing 32 bytes.
    #[must_use]
    pub fn finalize(&self) -> Hash {
        Hash(*self.inner.finalize().as_bytes())
    }

    /// Finishes, filling `out` with as many bytes as it holds.
    ///
    /// BLAKE3's extendable output. Used where a caller needs more or less than
    /// 32 bytes of key material; the first 32 bytes are identical to
    /// [`Hasher::finalize`].
    pub fn finalize_into(&self, out: &mut [u8]) {
        self.inner.finalize_xof().fill(out);
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the absorbed state: this hasher sees master seeds.
        f.write_str("Hasher { .. }")
    }
}

/// Hashes `data` in `context`.
///
/// The one-shot form of [`Hasher`], and the function almost every caller wants.
#[must_use]
pub fn hash(context: Context, data: &[u8]) -> Hash {
    Hasher::new(context).update(data).finalize()
}

/// Hashes the concatenation of `parts` in `context`, without building the
/// concatenation.
///
/// Note that this is plain concatenation, with no length prefixes: it is for
/// callers whose parts are fixed-width (two hashes, an algorithm byte and a
/// key). A caller with variable-length parts must encode them canonically
/// first — otherwise `("ab", "c")` and `("a", "bc")` hash alike.
#[must_use]
pub fn hash_parts(context: Context, parts: &[&[u8]]) -> Hash {
    let mut hasher = Hasher::new(context);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

const fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + (nibble - 10)) as char,
    }
}

const fn hex_to_nibble(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character - b'0'),
        b'a'..=b'f' => Some(character - b'a' + 10),
        b'A'..=b'F' => Some(character - b'A' + 10),
        _ => None,
    }
}

/// Decodes a hex string of even length into bytes.
pub fn decode_hex(text: &str) -> Result<Vec<u8>, CryptoError> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(CryptoError::BadHex);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let (Some(&high), Some(&low)) = (pair.first(), pair.get(1)) else {
            return Err(CryptoError::BadHex);
        };
        let (Some(high), Some(low)) = (hex_to_nibble(high), hex_to_nibble(low)) else {
            return Err(CryptoError::BadHex);
        };
        out.push((high << 4) | low);
    }
    Ok(out)
}

/// Encodes bytes as lowercase hex.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{domain, encode_hex, hash, hash_parts, Context, Hash, Hasher, HASH_LEN};
    use std::collections::BTreeSet;

    #[test]
    fn domain_registry_has_no_duplicates() {
        let unique: BTreeSet<&str> = domain::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            unique.len(),
            domain::ALL.len(),
            "two domain contexts share a string; separation is void for both"
        );
    }

    #[test]
    fn domain_contexts_are_well_formed() {
        for context in domain::ALL {
            let text = context.as_str();
            assert!(text.starts_with("vanargand v1 "), "{text}: missing protocol and version");
            assert!(text.is_ascii(), "{text}: context strings must be ASCII");
            assert!(!text.ends_with(' '), "{text}: trailing space is a typo waiting to happen");
        }
    }

    #[test]
    fn different_domains_give_different_digests() {
        // The property the whole module exists for.
        let input = b"the same 32 bytes in two roles";
        let mut digests = BTreeSet::new();
        for context in domain::ALL {
            assert!(
                digests.insert(hash(*context, input)),
                "{context} collides with another domain on identical input"
            );
        }
    }

    #[test]
    fn hashing_is_deterministic() {
        let a = hash(domain::TXID, b"abc");
        let b = hash(domain::TXID, b"abc");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_parts_matches_concatenation() {
        let joined = hash(domain::SMT_NODE, b"leftright");
        let split = hash_parts(domain::SMT_NODE, &[b"left", b"right"]);
        assert_eq!(joined, split);
    }

    #[test]
    fn hash_parts_is_ambiguous_across_boundaries_as_documented() {
        // Asserted so that nobody "fixes" the documentation later: this really
        // is plain concatenation, and callers with variable-length parts must
        // encode canonically first.
        assert_eq!(
            hash_parts(domain::SMT_NODE, &[b"ab", b"c"]),
            hash_parts(domain::SMT_NODE, &[b"a", b"bc"])
        );
    }

    #[test]
    fn hex_round_trips() {
        let digest = hash(domain::BLOCK_ID, b"height 1");
        let text = digest.to_hex();
        assert_eq!(text.len(), HASH_LEN * 2);
        assert_eq!(Hash::from_hex(&text), Ok(digest));
        assert_eq!(Hash::from_hex(&text.to_uppercase()), Ok(digest));
    }

    #[test]
    fn hex_rejects_malformed_input() {
        assert!(Hash::from_hex("abc").is_err(), "odd length accepted");
        assert!(Hash::from_hex(&"g".repeat(64)).is_err(), "non-hex character accepted");
        assert!(Hash::from_hex(&"ab".repeat(31)).is_err(), "short digest accepted");
        assert!(Hash::from_hex(&"ab".repeat(33)).is_err(), "long digest accepted");
    }

    #[test]
    fn encode_hex_matches_hash_to_hex() {
        let digest = hash(domain::TXID, b"x");
        assert_eq!(encode_hex(digest.as_bytes()), digest.to_hex());
    }

    #[test]
    fn bit_reads_most_significant_first() {
        let mut bytes = [0_u8; HASH_LEN];
        bytes[0] = 0b1000_0001;
        bytes[31] = 0b0000_0001;
        let digest = Hash::from_bytes(bytes);

        assert!(digest.bit(0), "bit 0 must be the top bit of byte 0");
        assert!(!digest.bit(1));
        assert!(digest.bit(7), "bit 7 must be the bottom bit of byte 0");
        assert!(digest.bit(255), "bit 255 must be the bottom bit of byte 31");
        // Out of range is false rather than a panic: this runs on untrusted
        // Merkle proofs.
        assert!(!digest.bit(256));
        assert!(!digest.bit(usize::MAX));
    }

    #[test]
    fn zero_hash_is_not_a_digest_of_anything_we_produce() {
        // Not a proof, just a smoke test that ZERO is distinguishable.
        assert_ne!(hash(domain::SMT_LEAF, b""), Hash::ZERO);
        assert_eq!(Hash::ZERO.as_bytes(), &[0_u8; HASH_LEN]);
    }

    #[test]
    fn extendable_output_agrees_with_finalize_on_its_first_32_bytes() {
        let mut hasher = Hasher::new(domain::KEY_DERIVATION);
        hasher.update(b"seed material");
        let short = hasher.finalize();
        let mut long = [0_u8; 64];
        hasher.finalize_into(&mut long);
        assert_eq!(&long[..HASH_LEN], short.as_bytes());
    }

    #[test]
    fn ordering_is_lexicographic() {
        let low = Hash::from_bytes([0x00; HASH_LEN]);
        let mut middle_bytes = [0x00; HASH_LEN];
        middle_bytes[0] = 0x01;
        let middle = Hash::from_bytes(middle_bytes);
        let high = Hash::from_bytes([0xff; HASH_LEN]);
        assert!(low < middle && middle < high);
    }

    #[test]
    fn context_display_is_the_string_itself() {
        let context = Context::new("vanargand v1 example");
        assert_eq!(context.to_string(), "vanargand v1 example");
    }
}
