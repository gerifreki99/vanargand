// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Errors returned by this crate.
//!
//! Written by hand rather than derived. A cryptographic error type is read far
//! more often than it is written, and the derive macro would add a dependency
//! to the one crate in the workspace that should have as few as possible.

use core::fmt;

use crate::algorithm::AlgorithmId;

/// Anything that can go wrong in [`crate`].
///
/// # On what these variants say
///
/// Verification failure is a single opaque variant, [`CryptoError::BadSignature`].
/// It does not distinguish "malformed signature" from "well-formed signature
/// over the wrong message" from "wrong key", because an attacker who can tell
/// those apart learns which of their guesses was closer. Structural problems
/// that an honest caller can act on — a key of the wrong length, an algorithm
/// this build does not support — are reported precisely, because they are bugs
/// in the caller, not probes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The algorithm identifier byte is not one this version of the protocol
    /// defines.
    UnknownAlgorithm(u8),

    /// The algorithm is defined, but this build has no backend compiled in for
    /// it. Enable the corresponding cargo feature; see `BACKENDS.md`.
    NoBackend(AlgorithmId),

    /// The algorithm is defined and supported, but not for this operation — for
    /// example a KEM identifier where a signature identifier was required.
    WrongAlgorithmKind {
        /// What was supplied.
        got: AlgorithmId,
        /// What the operation needed, as a human-readable word: `"signature"`
        /// or `"kem"`.
        expected: &'static str,
    },

    /// A key, signature or ciphertext had the wrong length for its algorithm.
    BadLength {
        /// What the field was, for the error message: `"public key"`, and so on.
        field: &'static str,
        /// The algorithm whose fixed size was violated.
        algorithm: AlgorithmId,
        /// Length required by the algorithm.
        expected: usize,
        /// Length supplied.
        got: usize,
    },

    /// Signature verification failed. Deliberately opaque; see the type
    /// documentation.
    BadSignature,

    /// Key encapsulation or decapsulation failed.
    KemFailure,

    /// A hash chain reveal did not hash to the committed value, or required
    /// more catch-up steps than the caller allowed.
    BadChainLink {
        /// How many steps forward the verifier was willing to walk.
        max_steps: u32,
    },

    /// A hex string was not valid: odd length, or a character outside
    /// `[0-9a-fA-F]`.
    BadHex,

    /// A byte string that had to be exactly 32 bytes was not.
    BadHashLength(usize),

    /// A derivation path was longer than [`crate::derive::MAX_PATH_LEN`].
    PathTooLong(usize),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAlgorithm(byte) => {
                write!(f, "unknown algorithm identifier 0x{byte:02x}")
            }
            Self::NoBackend(algorithm) => write!(
                f,
                "no backend compiled in for {algorithm}; enable the corresponding cargo feature"
            ),
            Self::WrongAlgorithmKind { got, expected } => {
                write!(f, "{got} is not a {expected} algorithm")
            }
            Self::BadLength { field, algorithm, expected, got } => write!(
                f,
                "{field} for {algorithm} must be {expected} bytes, got {got}"
            ),
            Self::BadSignature => write!(f, "signature verification failed"),
            Self::KemFailure => write!(f, "key encapsulation failed"),
            Self::BadChainLink { max_steps } => {
                write!(f, "hash chain reveal did not verify within {max_steps} steps")
            }
            Self::BadHex => write!(f, "invalid hex"),
            Self::BadHashLength(got) => write!(f, "a hash must be 32 bytes, got {got}"),
            Self::PathTooLong(got) => write!(f, "derivation path has {got} components, too many"),
        }
    }
}

impl std::error::Error for CryptoError {}
