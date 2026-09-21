// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key encapsulation, independent of the algorithm that performs it.
//!
//! ML-KEM-768 (FIPS 203) from v1, not later. G1 in the threat model is the
//! "harvest now, decrypt later" attack: an adversary recording ciphertexts
//! today reads them in twenty years if the key exchange was classical. Post-
//! quantum *signatures* can in principle be adopted later, because a signature
//! only has to resist an adversary who is present while it still matters.
//! Post-quantum *encryption* cannot: every message sent before the switch stays
//! vulnerable forever. That asymmetry is why `docs/02-scope.pdf` calls this
//! non-deferrable, and why the interface exists before the messaging layer that
//! will use it.
//!
//! As with [`crate::sign`], no library is wired in yet; the traits and the
//! conformance suite come first.

use core::fmt;

use crate::algorithm::AlgorithmId;
use crate::error::CryptoError;
use crate::hash::{encode_hex, Hash, HASH_LEN};

/// A KEM public key — what a correspondent publishes so others can write to it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncapsulationKey {
    algorithm: AlgorithmId,
    bytes: Vec<u8>,
}

impl EncapsulationKey {
    /// Wraps key bytes, checking the length the algorithm requires.
    pub fn new(algorithm: AlgorithmId, bytes: Vec<u8>) -> Result<Self, CryptoError> {
        algorithm.require_kem()?;
        let expected = algorithm.public_key_len();
        if bytes.len() != expected {
            return Err(CryptoError::BadLength {
                field: "encapsulation key",
                algorithm,
                expected,
                got: bytes.len(),
            });
        }
        Ok(Self { algorithm, bytes })
    }

    /// The algorithm this key belongs to.
    #[must_use]
    pub const fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    /// The key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preview: &[u8] = self.bytes.get(..8).unwrap_or(&self.bytes);
        write!(f, "EncapsulationKey({}, {}…)", self.algorithm, encode_hex(preview))
    }
}

/// A KEM secret key. Zeroed on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct DecapsulationKey {
    algorithm: AlgorithmId,
    bytes: Vec<u8>,
}

impl DecapsulationKey {
    /// Wraps key bytes, checking the length the algorithm requires.
    pub fn new(algorithm: AlgorithmId, bytes: Vec<u8>) -> Result<Self, CryptoError> {
        algorithm.require_kem()?;
        let expected = algorithm.secret_key_len();
        if bytes.len() != expected {
            return Err(CryptoError::BadLength {
                field: "decapsulation key",
                algorithm,
                expected,
                got: bytes.len(),
            });
        }
        Ok(Self { algorithm, bytes })
    }

    /// The algorithm this key belongs to.
    #[must_use]
    pub const fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    /// The key bytes. Handle accordingly.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecapsulationKey({}, redacted)", self.algorithm)
    }
}

impl Drop for DecapsulationKey {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            *byte = 0;
        }
        core::hint::black_box(&self.bytes);
    }
}

/// An encapsulated key: the bytes a sender puts on the wire.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ciphertext {
    algorithm: AlgorithmId,
    bytes: Vec<u8>,
}

impl Ciphertext {
    /// Wraps ciphertext bytes, checking the length the algorithm requires.
    pub fn new(algorithm: AlgorithmId, bytes: Vec<u8>) -> Result<Self, CryptoError> {
        algorithm.require_kem()?;
        let expected = algorithm.output_len();
        if bytes.len() != expected {
            return Err(CryptoError::BadLength {
                field: "ciphertext",
                algorithm,
                expected,
                got: bytes.len(),
            });
        }
        Ok(Self { algorithm, bytes })
    }

    /// The algorithm this ciphertext belongs to.
    #[must_use]
    pub const fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    /// The ciphertext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preview: &[u8] = self.bytes.get(..8).unwrap_or(&self.bytes);
        write!(f, "Ciphertext({}, {}…)", self.algorithm, encode_hex(preview))
    }
}

/// A 32-byte shared secret. Zeroed on drop.
///
/// Never used directly as an encryption key: the messaging layer runs it
/// through a key schedule first. Exposed as raw bytes here because this crate
/// does not know what schedule the caller wants.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedSecret([u8; HASH_LEN]);

impl SharedSecret {
    /// Wraps 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// The secret bytes. Handle accordingly.
    #[must_use]
    pub const fn expose(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(redacted)")
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            *byte = 0;
        }
        core::hint::black_box(&self.0);
    }
}

/// A KEM keypair as produced by deterministic key generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemKeypair {
    /// The secret half.
    pub decapsulation: DecapsulationKey,
    /// The public half.
    pub encapsulation: EncapsulationKey,
}

/// What a key encapsulation library must provide.
pub trait KemBackend: Send + Sync {
    /// Which algorithm this backend implements.
    fn algorithm(&self) -> AlgorithmId;

    /// Deterministically generates a keypair from a 32-byte seed.
    fn keypair_from_seed(&self, seed: &Hash) -> Result<KemKeypair, CryptoError>;

    /// Encapsulates to `key`, deriving a shared secret.
    ///
    /// `randomness` is the 32 bytes of entropy FIPS 203 calls *m*. Passing it
    /// in rather than drawing it internally keeps this crate free of an RNG and
    /// makes the operation testable against known-answer vectors; a caller that
    /// reuses it across two encapsulations to the same key produces the same
    /// ciphertext, which is a caller bug and a serious one.
    fn encapsulate(
        &self,
        key: &EncapsulationKey,
        randomness: &Hash,
    ) -> Result<(Ciphertext, SharedSecret), CryptoError>;

    /// Decapsulates `ciphertext` with `key`.
    ///
    /// ML-KEM is designed so that a malformed ciphertext yields a
    /// pseudo-random secret rather than an error — *implicit rejection*. A
    /// backend MUST preserve that behaviour and MUST NOT report the difference,
    /// because reporting it is a decryption oracle.
    fn decapsulate(
        &self,
        key: &DecapsulationKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret, CryptoError>;
}

/// Looks up the KEM backend for an algorithm.
///
/// No backend is compiled in yet; see `BACKENDS.md`.
pub fn backend(algorithm: AlgorithmId) -> Result<&'static dyn KemBackend, CryptoError> {
    algorithm.require_kem()?;
    Err(CryptoError::NoBackend(algorithm))
}

#[cfg(test)]
mod tests {
    use super::{backend, Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret};
    use crate::algorithm::AlgorithmId;
    use crate::error::CryptoError;

    const KEM: AlgorithmId = AlgorithmId::MlKem768;

    #[test]
    fn lengths_are_checked_at_construction() {
        assert!(EncapsulationKey::new(KEM, vec![0; 1184]).is_ok());
        assert!(EncapsulationKey::new(KEM, vec![0; 1183]).is_err());
        assert!(DecapsulationKey::new(KEM, vec![0; 2400]).is_ok());
        assert!(Ciphertext::new(KEM, vec![0; 1088]).is_ok());
        assert!(Ciphertext::new(KEM, vec![0; 1089]).is_err());
    }

    #[test]
    fn a_signature_algorithm_is_not_a_kem() {
        assert!(matches!(
            EncapsulationKey::new(AlgorithmId::MlDsa44, vec![0; 1312]),
            Err(CryptoError::WrongAlgorithmKind { .. })
        ));
        assert!(matches!(
            backend(AlgorithmId::MlDsa44),
            Err(CryptoError::WrongAlgorithmKind { .. })
        ));
    }

    #[test]
    fn the_missing_backend_is_reported_as_missing() {
        assert_eq!(backend(KEM).err(), Some(CryptoError::NoBackend(KEM)));
    }

    #[test]
    fn secrets_never_print_themselves() {
        let secret = SharedSecret::from_bytes([0xab; 32]);
        assert_eq!(format!("{secret:?}"), "SharedSecret(redacted)");
        let key = DecapsulationKey::new(KEM, vec![0xcd; 2400]).unwrap();
        let text = format!("{key:?}");
        assert!(text.contains("redacted"), "{text}");
        assert!(!text.contains("cdcd"), "{text}");
    }
}
