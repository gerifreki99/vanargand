// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The key hierarchy: one master seed, everything else derived.
//!
//! See `spec/draft/03-addresses.md` §3. A wallet holds a single 32-byte
//! [`MasterSeed`] and derives every other secret from it, so that recovering
//! the seed recovers the whole identity — the root key, every device subkey,
//! the scan key, every PayWord chain, every commitment chain. Nothing else ever
//! needs backing up, which is what makes `docs/01-concept.pdf`'s promise
//! ("personne n'a à recopier vingt-quatre mots sur un papier") mean something
//! more than a slogan.
//!
//! Derivation is deterministic and the output is used directly as the FIPS 203
//! / FIPS 204 key generation seed ξ. Key generation is therefore reproducible,
//! which is what makes test vectors for addresses possible at all.

use core::fmt;

use crate::error::CryptoError;
use crate::hash::{domain, Hash, Hasher, HASH_LEN};

/// Longest derivation path the protocol defines.
///
/// Every reserved path is one or two components. The bound exists so that an
/// encoded path has an obvious maximum size and a hostile one cannot be used to
/// make a wallet hash a megabyte.
pub const MAX_PATH_LEN: usize = 8;

/// Reserved purpose values — the first component of every path.
pub mod purpose {
    /// The account's root signing key. Certifies device subkeys and nothing
    /// else.
    pub const ROOT: u32 = 0;
    /// A device subkey, by index. Signs transactions; holds a nonce lane and a
    /// share of the nomad credit.
    pub const DEVICE: u32 = 1;
    /// The ML-KEM scan key used by the messaging layer.
    pub const SCAN: u32 = 2;
    /// A one-time address, by index. See `03-addresses.md` §6.
    pub const ONE_TIME: u32 = 3;
    /// A PayWord chain seed, by channel index.
    pub const PAYWORD: u32 = 4;
    /// A commitment chain seed, by bond period.
    pub const COMMITMENT: u32 = 5;
}

/// A path through the key hierarchy.
///
/// Encoded for hashing as one length byte followed by each component as a
/// little-endian `u32`. This deliberately does not reuse the canonical codec of
/// `vanargand-types`: that crate depends on this one, and a key hierarchy that
/// cannot be computed without the transaction encoder is a key hierarchy that
/// a recovery tool cannot reimplement in fifty lines.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DerivationPath(Vec<u32>);

impl DerivationPath {
    /// Builds a path, rejecting one that is too long.
    pub fn new(components: Vec<u32>) -> Result<Self, CryptoError> {
        if components.len() > MAX_PATH_LEN {
            return Err(CryptoError::PathTooLong(components.len()));
        }
        Ok(Self(components))
    }

    /// The account's root signing key: `[0]`.
    #[must_use]
    pub fn root() -> Self {
        Self(vec![purpose::ROOT])
    }

    /// Device subkey `index`: `[1, index]`.
    #[must_use]
    pub fn device(index: u32) -> Self {
        Self(vec![purpose::DEVICE, index])
    }

    /// The scan key: `[2]`.
    #[must_use]
    pub fn scan() -> Self {
        Self(vec![purpose::SCAN])
    }

    /// One-time address `index`: `[3, index]`.
    #[must_use]
    pub fn one_time(index: u32) -> Self {
        Self(vec![purpose::ONE_TIME, index])
    }

    /// PayWord chain seed for channel `index`: `[4, index]`.
    #[must_use]
    pub fn payword(index: u32) -> Self {
        Self(vec![purpose::PAYWORD, index])
    }

    /// Commitment chain seed for bond period `index`: `[5, index]`.
    #[must_use]
    pub fn commitment(index: u32) -> Self {
        Self(vec![purpose::COMMITMENT, index])
    }

    /// The path components.
    #[must_use]
    pub fn components(&self) -> &[u32] {
        &self.0
    }

    /// The bytes hashed for this path.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        // `len` is bounded by MAX_PATH_LEN, which is far below 255; the
        // fallback keeps the conversion total without a panic.
        let count = u8::try_from(self.0.len()).unwrap_or(u8::MAX);
        let mut out = Vec::with_capacity(1_usize.saturating_add(self.0.len().saturating_mul(4)));
        out.push(count);
        for component in &self.0 {
            out.extend_from_slice(&component.to_le_bytes());
        }
        out
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for component in &self.0 {
            write!(f, "/{component}")?;
        }
        Ok(())
    }
}

/// A wallet's root secret.
///
/// Zeroed on drop. That is a mitigation, not a guarantee: the value may have
/// been copied by the allocator, spilled to a register, or swapped to disk
/// before the destructor ran. It closes the easy window, which is worth doing,
/// and it does not close the hard ones, which is worth saying.
#[derive(Clone, PartialEq, Eq)]
pub struct MasterSeed([u8; HASH_LEN]);

impl MasterSeed {
    /// Wraps 32 bytes of entropy.
    ///
    /// Where those bytes come from is the wallet's problem, not this crate's:
    /// see the note on randomness in the crate documentation.
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

    /// The seed bytes. Handle accordingly.
    #[must_use]
    pub const fn expose(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl fmt::Debug for MasterSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A master seed that reaches a log file has ended someone's savings.
        f.write_str("MasterSeed(redacted)")
    }
}

impl Drop for MasterSeed {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            *byte = 0;
        }
        core::hint::black_box(&self.0);
    }
}

/// Derives the seed at `path`.
///
/// `H[vanargand v1 key derivation](path ‖ master_seed)`. Note the order: the
/// secret goes last. BLAKE3's key derivation mode is not vulnerable to length
/// extension, so this is not load-bearing here — it is the habit staying
/// correct for whoever reaches for a different hash later.
#[must_use]
pub fn derive_seed(master: &MasterSeed, path: &DerivationPath) -> Hash {
    Hasher::new(domain::KEY_DERIVATION)
        .update(&path.encode())
        .update(master.expose())
        .finalize()
}

#[cfg(test)]
mod tests {
    use super::{derive_seed, purpose, DerivationPath, MasterSeed, MAX_PATH_LEN};
    use std::collections::BTreeSet;

    fn master() -> MasterSeed {
        MasterSeed::from_bytes([0x42; 32])
    }

    #[test]
    fn reserved_paths_match_the_specification() {
        assert_eq!(DerivationPath::root().components(), &[0]);
        assert_eq!(DerivationPath::device(3).components(), &[1, 3]);
        assert_eq!(DerivationPath::scan().components(), &[2]);
        assert_eq!(DerivationPath::one_time(9).components(), &[3, 9]);
        assert_eq!(DerivationPath::payword(1).components(), &[4, 1]);
        assert_eq!(DerivationPath::commitment(0).components(), &[5, 0]);
    }

    #[test]
    fn purpose_constants_are_distinct() {
        let all =
            [purpose::ROOT, purpose::DEVICE, purpose::SCAN, purpose::ONE_TIME, purpose::PAYWORD,
             purpose::COMMITMENT];
        let unique: BTreeSet<u32> = all.iter().copied().collect();
        assert_eq!(unique.len(), all.len(), "two purposes share a number");
    }

    #[test]
    fn path_encoding_is_unambiguous() {
        // The property that matters: no two distinct paths encode alike, so no
        // two distinct paths derive the same secret.
        let paths = [
            DerivationPath::new(vec![]).unwrap(),
            DerivationPath::new(vec![0]).unwrap(),
            DerivationPath::new(vec![1]).unwrap(),
            DerivationPath::new(vec![0, 0]).unwrap(),
            DerivationPath::new(vec![1, 0]).unwrap(),
            DerivationPath::new(vec![0, 1]).unwrap(),
            DerivationPath::new(vec![1, 0, 0]).unwrap(),
            DerivationPath::new(vec![u32::MAX]).unwrap(),
        ];
        let encodings: BTreeSet<Vec<u8>> = paths.iter().map(DerivationPath::encode).collect();
        assert_eq!(encodings.len(), paths.len(), "two paths share an encoding");

        let seeds: BTreeSet<_> = paths.iter().map(|p| derive_seed(&master(), p)).collect();
        assert_eq!(seeds.len(), paths.len(), "two paths derive the same secret");
    }

    #[test]
    fn path_encoding_is_the_documented_layout() {
        assert_eq!(DerivationPath::new(vec![]).unwrap().encode(), vec![0]);
        assert_eq!(DerivationPath::root().encode(), vec![1, 0, 0, 0, 0]);
        assert_eq!(DerivationPath::device(1).encode(), vec![2, 1, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(
            DerivationPath::new(vec![u32::MAX]).unwrap().encode(),
            vec![1, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn overlong_paths_are_rejected() {
        assert!(DerivationPath::new(vec![0; MAX_PATH_LEN]).is_ok());
        assert!(DerivationPath::new(vec![0; MAX_PATH_LEN + 1]).is_err());
    }

    #[test]
    fn derivation_is_deterministic() {
        let path = DerivationPath::device(7);
        assert_eq!(derive_seed(&master(), &path), derive_seed(&master(), &path));
    }

    #[test]
    fn different_masters_give_different_secrets() {
        let path = DerivationPath::root();
        let other = MasterSeed::from_bytes([0x43; 32]);
        assert_ne!(derive_seed(&master(), &path), derive_seed(&other, &path));
    }

    #[test]
    fn display_reads_like_a_path() {
        assert_eq!(DerivationPath::device(12).to_string(), "m/1/12");
        assert_eq!(DerivationPath::new(vec![]).unwrap().to_string(), "m");
    }

    #[test]
    fn a_master_seed_never_prints_itself() {
        let text = format!("{:?}", master());
        assert!(!text.contains("42"), "Debug leaked seed bytes: {text}");
        assert_eq!(text, "MasterSeed(redacted)");
    }
}
