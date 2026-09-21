// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Algorithm identifiers.
//!
//! Every key, signature and ciphertext on the wire carries one of these bytes.
//! There is no "the default algorithm" anywhere in the encoding — see
//! `spec/draft/03-addresses.md` §2.

use core::fmt;

use crate::error::CryptoError;

/// A one-byte algorithm identifier, as it appears on the wire.
///
/// The numeric values are **frozen** at genesis. A value removed from the
/// protocol keeps its number reserved forever: reusing it would let an object
/// written under the old rules be reinterpreted under the new ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum AlgorithmId {
    /// ML-DSA-44 (FIPS 204). The protocol default for signatures.
    ///
    /// Chosen over the more compact FALCON because a safe FALCON needs
    /// constant-time floating-point arithmetic, and Vanargand runs on whatever
    /// hardware is in the room (R1.7).
    MlDsa44 = 0x01,

    /// ML-KEM-768 (FIPS 203). Key encapsulation for the messaging layer.
    ///
    /// Post-quantum from v1 rather than later, because G1's "harvest now,
    /// decrypt later" attack is already running against traffic sent today.
    MlKem768 = 0x02,

    /// ML-DSA-65 (FIPS 204). Reserved for objects where size does not matter
    /// and compromise is unrecoverable: cross-chain milestones and large bridge
    /// freezes (Tier 3).
    MlDsa65 = 0x03,

    /// A deterministic, **insecure** stand-in used only by test vectors and by
    /// the workspace's own tests.
    ///
    /// Sits in the reserved `0x10..=0x1f` test range, and
    /// [`AlgorithmId::valid_on_live_chain`] returns `false` for it. A chain
    /// that accepts a signature under this identifier has a consensus bug, and
    /// the test for that bug is in this crate.
    InsecureTest = 0x10,
}

impl AlgorithmId {
    /// Every identifier this version of the protocol defines, in ascending
    /// order.
    ///
    /// Exhaustive by construction: a new variant that is not added here fails
    /// the round-trip test below.
    pub const ALL: &'static [Self] =
        &[Self::MlDsa44, Self::MlKem768, Self::MlDsa65, Self::InsecureTest];

    /// Decodes an identifier byte.
    pub fn from_byte(byte: u8) -> Result<Self, CryptoError> {
        match byte {
            0x01 => Ok(Self::MlDsa44),
            0x02 => Ok(Self::MlKem768),
            0x03 => Ok(Self::MlDsa65),
            0x10 => Ok(Self::InsecureTest),
            other => Err(CryptoError::UnknownAlgorithm(other)),
        }
    }

    /// The identifier byte, as encoded.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Whether this algorithm produces signatures.
    #[must_use]
    pub const fn is_signature(self) -> bool {
        matches!(self, Self::MlDsa44 | Self::MlDsa65 | Self::InsecureTest)
    }

    /// Whether this algorithm is a key encapsulation mechanism.
    #[must_use]
    pub const fn is_kem(self) -> bool {
        matches!(self, Self::MlKem768)
    }

    /// Whether an object under this algorithm may appear on a production chain.
    ///
    /// Consensus code MUST call this before accepting any key or signature.
    /// The test algorithms exist so that the workspace can be tested without a
    /// post-quantum dependency, and the only thing standing between that
    /// convenience and a chain anyone can forge blocks on is this check.
    #[must_use]
    pub const fn valid_on_live_chain(self) -> bool {
        !matches!(self, Self::InsecureTest)
    }

    /// Public key length in bytes, fixed by the algorithm.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlKem768 => 1184,
            Self::MlDsa65 => 1952,
            Self::InsecureTest => 32,
        }
    }

    /// Secret key length in bytes, fixed by the algorithm.
    #[must_use]
    pub const fn secret_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlKem768 => 2400,
            Self::MlDsa65 => 4032,
            Self::InsecureTest => 32,
        }
    }

    /// Signature length for a signature algorithm, or ciphertext length for a
    /// KEM. Both are fixed-size in every algorithm defined here.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlKem768 => 1088,
            Self::MlDsa65 => 3309,
            Self::InsecureTest => 64,
        }
    }

    /// Human-readable name, used in error messages and in test vectors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlDsa65 => "ML-DSA-65",
            Self::InsecureTest => "INSECURE-TEST",
        }
    }

    /// Checks that this identifier denotes a signature algorithm.
    pub fn require_signature(self) -> Result<Self, CryptoError> {
        if self.is_signature() {
            Ok(self)
        } else {
            Err(CryptoError::WrongAlgorithmKind { got: self, expected: "signature" })
        }
    }

    /// Checks that this identifier denotes a key encapsulation mechanism.
    pub fn require_kem(self) -> Result<Self, CryptoError> {
        if self.is_kem() {
            Ok(self)
        } else {
            Err(CryptoError::WrongAlgorithmKind { got: self, expected: "kem" })
        }
    }
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::AlgorithmId;
    use crate::error::CryptoError;

    #[test]
    fn byte_round_trip_is_exhaustive() {
        // If a variant is added without being listed in ALL, this test fails
        // on the count check below rather than silently under-covering.
        let mut seen = 0_usize;
        for byte in 0_u8..=255 {
            if let Ok(algorithm) = AlgorithmId::from_byte(byte) {
                assert_eq!(algorithm.to_byte(), byte);
                assert!(
                    AlgorithmId::ALL.contains(&algorithm),
                    "{algorithm} decodes but is missing from AlgorithmId::ALL"
                );
                seen += 1;
            }
        }
        assert_eq!(seen, AlgorithmId::ALL.len(), "ALL does not match what from_byte accepts");
    }

    #[test]
    fn zero_is_reserved_and_invalid() {
        // A zeroed buffer read as a key must fail, not select something.
        assert_eq!(AlgorithmId::from_byte(0x00), Err(CryptoError::UnknownAlgorithm(0x00)));
    }

    #[test]
    fn every_algorithm_is_exactly_one_kind() {
        for &algorithm in AlgorithmId::ALL {
            assert_ne!(
                algorithm.is_signature(),
                algorithm.is_kem(),
                "{algorithm} is both or neither"
            );
        }
    }

    #[test]
    fn test_range_never_reaches_a_live_chain() {
        for &algorithm in AlgorithmId::ALL {
            let in_test_range = (0x10..=0x1f).contains(&algorithm.to_byte());
            assert_eq!(
                in_test_range,
                !algorithm.valid_on_live_chain(),
                "{algorithm}: test-range membership and live-chain validity disagree"
            );
        }
    }

    #[test]
    fn fips_sizes_are_the_standard_ones() {
        // Transcribed from FIPS 203 and FIPS 204. A typo here would be found
        // only by a failing interop test months later, so it is asserted.
        assert_eq!(AlgorithmId::MlDsa44.public_key_len(), 1312);
        assert_eq!(AlgorithmId::MlDsa44.secret_key_len(), 2560);
        assert_eq!(AlgorithmId::MlDsa44.output_len(), 2420);
        assert_eq!(AlgorithmId::MlDsa65.public_key_len(), 1952);
        assert_eq!(AlgorithmId::MlDsa65.secret_key_len(), 4032);
        assert_eq!(AlgorithmId::MlDsa65.output_len(), 3309);
        assert_eq!(AlgorithmId::MlKem768.public_key_len(), 1184);
        assert_eq!(AlgorithmId::MlKem768.secret_key_len(), 2400);
        assert_eq!(AlgorithmId::MlKem768.output_len(), 1088);
    }
}
