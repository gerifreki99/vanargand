// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signatures, independent of the algorithm that produces them.
//!
//! Nothing outside this module names a signature library. A caller works with
//! [`VerifyingKey`], [`SigningKey`] and [`Signature`], each of which carries its
//! [`AlgorithmId`] on the wire, and asks [`backend`] for an implementation.
//!
//! # Determinism
//!
//! Signing MUST be deterministic. FIPS 204 permits a hedged variant that mixes
//! in fresh randomness; Vanargand does not use it for anything that enters
//! state. Randomised signing means the same transaction signed twice yields two
//! valid encodings with two different transaction ids, which is a malleability
//! source, breaks the equivocation proofs that the nomad credit depends on
//! (R2 — two signatures on the same lane and sequence are supposed to *be* the
//! evidence), and makes test vectors impossible to write.
//!
//! # No backend is compiled in by default
//!
//! Enable the `mldsa` feature for the real one, or `test-backend` for a
//! deterministic stand-in with no security whatsoever. See `BACKENDS.md`.

use core::fmt;

use crate::algorithm::AlgorithmId;
use crate::error::CryptoError;
use crate::hash::{domain, encode_hex, Hash, Hasher};

/// A public key, tagged with the algorithm that interprets it.
///
/// Deliberately not `std::hash::Hash`: the hash-based collections are banned by
/// `CONTRIBUTING.md`, so the trait would only enable the thing the rule
/// forbids. Ordering is derived, which makes `BTreeMap` and the canonical set
/// ordering of `01-canonical-encoding.md` §3.3 work.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerifyingKey {
    algorithm: AlgorithmId,
    bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Wraps key bytes, checking the length the algorithm requires.
    pub fn new(algorithm: AlgorithmId, bytes: Vec<u8>) -> Result<Self, CryptoError> {
        algorithm.require_signature()?;
        let expected = algorithm.public_key_len();
        if bytes.len() != expected {
            return Err(CryptoError::BadLength {
                field: "public key",
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

    /// The identifier derived from this key in `context`.
    ///
    /// `H[context](algorithm_id ‖ public_key)`. Used for both account ids and
    /// device ids, which differ only in their context string — see
    /// `spec/draft/03-addresses.md` §4.
    #[must_use]
    pub fn identifier(&self, context: crate::hash::Context) -> Hash {
        Hasher::new(context)
            .update(&[self.algorithm.to_byte()])
            .update(&self.bytes)
            .finalize()
    }

    /// The account identifier for this key, if it is used as an account root.
    #[must_use]
    pub fn account_id(&self) -> Hash {
        self.identifier(domain::ACCOUNT_ID)
    }

    /// The device identifier for this key, if it is used as a device subkey.
    #[must_use]
    pub fn device_id(&self) -> Hash {
        self.identifier(domain::DEVICE_ID)
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public keys are public, but 1312 bytes of hex in a log is not a
        // service to anyone. Show the identifier instead, which is what a
        // reader is actually looking for.
        write!(f, "VerifyingKey({}, id {})", self.algorithm, self.account_id())
    }
}

/// A secret key, tagged with its algorithm.
///
/// Zeroed on drop, with the same caveat as [`crate::derive::MasterSeed`]: this
/// closes the easy window, not the hard ones.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKey {
    algorithm: AlgorithmId,
    bytes: Vec<u8>,
}

impl SigningKey {
    /// Wraps key bytes, checking the length the algorithm requires.
    pub fn new(algorithm: AlgorithmId, bytes: Vec<u8>) -> Result<Self, CryptoError> {
        algorithm.require_signature()?;
        let expected = algorithm.secret_key_len();
        if bytes.len() != expected {
            return Err(CryptoError::BadLength {
                field: "secret key",
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

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({}, redacted)", self.algorithm)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            *byte = 0;
        }
        core::hint::black_box(&self.bytes);
    }
}

/// A signature, tagged with the algorithm that produced it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signature {
    algorithm: AlgorithmId,
    bytes: Vec<u8>,
}

impl Signature {
    /// Wraps signature bytes, checking the length the algorithm requires.
    pub fn new(algorithm: AlgorithmId, bytes: Vec<u8>) -> Result<Self, CryptoError> {
        algorithm.require_signature()?;
        let expected = algorithm.output_len();
        if bytes.len() != expected {
            return Err(CryptoError::BadLength {
                field: "signature",
                algorithm,
                expected,
                got: bytes.len(),
            });
        }
        Ok(Self { algorithm, bytes })
    }

    /// The algorithm this signature belongs to.
    #[must_use]
    pub const fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    /// The signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preview: &[u8] = self.bytes.get(..8).unwrap_or(&self.bytes);
        write!(f, "Signature({}, {}…)", self.algorithm, encode_hex(preview))
    }
}

/// A keypair as produced by deterministic key generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keypair {
    /// The secret half.
    pub signing: SigningKey,
    /// The public half.
    pub verifying: VerifyingKey,
}

/// What a signature library must provide to be usable by Vanargand.
///
/// Implementations live behind cargo features. The trait is deliberately
/// narrow: no streaming, no batch verification, no context strings. Everything
/// Vanargand signs is a 32-byte domain-separated digest, so a backend never
/// sees a large message and never has to make a choice about how to hash one.
pub trait SignatureBackend: Send + Sync {
    /// Which algorithm this backend implements.
    fn algorithm(&self) -> AlgorithmId;

    /// Deterministically generates a keypair from a 32-byte seed.
    ///
    /// The seed is the FIPS 204 ξ. Same seed, same keypair, on every platform
    /// and every version — a wallet restored from a seed phrase depends on it.
    fn keypair_from_seed(&self, seed: &Hash) -> Result<Keypair, CryptoError>;

    /// Signs a message deterministically.
    fn sign(&self, key: &SigningKey, message: &[u8]) -> Result<Signature, CryptoError>;

    /// Verifies a signature.
    ///
    /// Returns [`CryptoError::BadSignature`] for every failure, without
    /// distinguishing the cause.
    fn verify(
        &self,
        key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), CryptoError>;
}

/// Looks up the backend for an algorithm.
///
/// Returns [`CryptoError::NoBackend`] when the algorithm is defined by the
/// protocol but not compiled into this build. That distinction matters
/// operationally: "I do not know this algorithm" is a protocol version problem,
/// "I know it and cannot do it" is a build configuration problem, and an
/// operator staring at a log at midnight should not have to guess which.
pub fn backend(algorithm: AlgorithmId) -> Result<&'static dyn SignatureBackend, CryptoError> {
    algorithm.require_signature()?;
    match algorithm {
        #[cfg(any(test, feature = "test-backend"))]
        AlgorithmId::InsecureTest => Ok(&insecure_test::INSECURE_TEST),
        other => Err(CryptoError::NoBackend(other)),
    }
}

/// Generates a keypair for `algorithm` from `seed`.
pub fn keypair_from_seed(algorithm: AlgorithmId, seed: &Hash) -> Result<Keypair, CryptoError> {
    backend(algorithm)?.keypair_from_seed(seed)
}

/// Signs `message` with `key`.
pub fn sign(key: &SigningKey, message: &[u8]) -> Result<Signature, CryptoError> {
    backend(key.algorithm())?.sign(key, message)
}

/// Verifies `signature` over `message` under `key`.
///
/// Rejects a signature whose algorithm differs from the key's without
/// consulting a backend, so that a signature under a weak algorithm can never
/// be checked against a key registered under a strong one.
pub fn verify(
    key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    if key.algorithm() != signature.algorithm() {
        return Err(CryptoError::BadSignature);
    }
    backend(key.algorithm())?.verify(key, message, signature)
}

#[cfg(any(test, feature = "test-backend"))]
pub mod insecure_test {
    //! A deterministic stand-in with **no security at all**.
    //!
    //! It exists so that block, transaction and state tests can run without a
    //! post-quantum dependency, and so that the conformance vectors for
    //! everything above the signature layer can be computed by a generator that
    //! does not implement ML-DSA.
    //!
    //! # How insecure
    //!
    //! Completely. The verifying key and the signing key are the same 32 bytes,
    //! and a signature is `H(key ‖ message)`. Anyone holding a public key can
    //! forge every signature under it. This is a message authentication code
    //! wearing a signature's clothes.
    //!
    //! The one thing standing between this and a chain anyone could rewrite is
    //! [`AlgorithmId::valid_on_live_chain`], which returns `false` for
    //! [`AlgorithmId::InsecureTest`]. Consensus code calls it. There is a test
    //! for that in `vanargand-types`, and if it ever fails, the finding is not
    //! "a test broke".

    use super::{Keypair, Signature, SignatureBackend, SigningKey, VerifyingKey};
    use crate::algorithm::AlgorithmId;
    use crate::error::CryptoError;
    use crate::hash::{Context, Hash, Hasher};

    const SIGNATURE_DOMAIN: Context = Context::new("vanargand v1 INSECURE test signature");

    /// The backend instance returned by [`super::backend`].
    pub static INSECURE_TEST: InsecureTestBackend = InsecureTestBackend;

    /// See the module documentation. Not a signature scheme.
    #[derive(Debug, Clone, Copy)]
    pub struct InsecureTestBackend;

    impl InsecureTestBackend {
        fn raw_signature(key_bytes: &[u8], message: &[u8]) -> Vec<u8> {
            let mut hasher = Hasher::new(SIGNATURE_DOMAIN);
            hasher.update(key_bytes).update(message);
            let mut out = vec![0_u8; AlgorithmId::InsecureTest.output_len()];
            hasher.finalize_into(&mut out);
            out
        }
    }

    impl SignatureBackend for InsecureTestBackend {
        fn algorithm(&self) -> AlgorithmId {
            AlgorithmId::InsecureTest
        }

        fn keypair_from_seed(&self, seed: &Hash) -> Result<Keypair, CryptoError> {
            let bytes = seed.as_bytes().to_vec();
            Ok(Keypair {
                signing: SigningKey::new(AlgorithmId::InsecureTest, bytes.clone())?,
                verifying: VerifyingKey::new(AlgorithmId::InsecureTest, bytes)?,
            })
        }

        fn sign(&self, key: &SigningKey, message: &[u8]) -> Result<Signature, CryptoError> {
            if key.algorithm() != AlgorithmId::InsecureTest {
                return Err(CryptoError::WrongAlgorithmKind {
                    got: key.algorithm(),
                    expected: "signature",
                });
            }
            Signature::new(
                AlgorithmId::InsecureTest,
                Self::raw_signature(key.expose(), message),
            )
        }

        fn verify(
            &self,
            key: &VerifyingKey,
            message: &[u8],
            signature: &Signature,
        ) -> Result<(), CryptoError> {
            let expected = Self::raw_signature(key.as_bytes(), message);
            if crate::ct_eq(&expected, signature.as_bytes()) {
                Ok(())
            } else {
                Err(CryptoError::BadSignature)
            }
        }
    }
}

pub mod conformance {
    //! The bar a signature backend has to clear.
    //!
    //! Wiring a post-quantum library into [`super::SignatureBackend`] is a
    //! small piece of work with several ways to be subtly wrong: a library
    //! whose signing is randomised by default, an encoding that is not the FIPS
    //! one, a `verify` that returns `true` on a malformed signature rather than
    //! rejecting it. This module is the check, and it is shipped as library
    //! code rather than as a test so that it runs against a backend wherever
    //! that backend is defined — including out of tree.
    //!
    //! ```no_run
    //! # use vanargand_crypto::sign::{conformance, SignatureBackend};
    //! # fn demo(candidate: &dyn SignatureBackend) {
    //! conformance::check(candidate).expect("backend does not conform");
    //! # }
    //! ```

    use super::{sign_with, verify_with, Keypair, SignatureBackend};
    use crate::hash::Hash;

    /// A conformance failure, describing which property broke.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Failure(pub String);

    impl core::fmt::Display for Failure {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Failure {}

    fn fail<T>(message: impl Into<String>) -> Result<T, Failure> {
        Err(Failure(message.into()))
    }

    fn keypair(backend: &dyn SignatureBackend, byte: u8) -> Result<Keypair, Failure> {
        backend
            .keypair_from_seed(&Hash::from_bytes([byte; 32]))
            .map_err(|error| Failure(format!("key generation failed: {error}")))
    }

    /// Runs every conformance check against `backend`.
    ///
    /// The checks are behavioural, not statistical: none of them tests that the
    /// algorithm is *secure*, which no test suite can do. They test that the
    /// backend behaves the way the rest of Vanargand assumes it does.
    pub fn check(backend: &dyn SignatureBackend) -> Result<(), Failure> {
        let algorithm = backend.algorithm();
        if !algorithm.is_signature() {
            return fail(format!("{algorithm} is registered as a signature backend but is not a signature algorithm"));
        }

        let pair = keypair(backend, 1)?;
        if pair.verifying.algorithm() != algorithm || pair.signing.algorithm() != algorithm {
            return fail("generated keys do not carry the backend's algorithm id");
        }

        // 1. Round trip.
        let message = b"vanargand conformance message";
        let signature = sign_with(backend, &pair.signing, message)
            .map_err(|error| Failure(format!("signing failed: {error}")))?;
        verify_with(backend, &pair.verifying, message, &signature)
            .map_err(|error| Failure(format!("a freshly produced signature did not verify: {error}")))?;

        // 2. Deterministic signing. Load-bearing for R2's account equivocation
        //    proof: an honest wallet that retries a send must not manufacture
        //    two distinct signatures over the same lane and sequence.
        let again = sign_with(backend, &pair.signing, message)
            .map_err(|error| Failure(format!("second signing failed: {error}")))?;
        if again != signature {
            return fail("signing is not deterministic; Vanargand requires the non-hedged variant");
        }

        // 3. Deterministic key generation, for seed recovery.
        let same = keypair(backend, 1)?;
        if same.verifying != pair.verifying {
            return fail("key generation is not deterministic in the seed");
        }
        let other = keypair(backend, 2)?;
        if other.verifying == pair.verifying {
            return fail("two different seeds produced the same key");
        }

        // 4. Wrong message, wrong key.
        if verify_with(backend, &pair.verifying, b"a different message", &signature).is_ok() {
            return fail("a signature verified against the wrong message");
        }
        if verify_with(backend, &other.verifying, message, &signature).is_ok() {
            return fail("a signature verified under the wrong key");
        }

        // 5. Corruption at every byte position of the signature. A backend that
        //    ignores trailing bytes, or that only checks a prefix, fails here.
        let raw = signature.as_bytes().to_vec();
        for index in 0..raw.len() {
            let mut tampered = raw.clone();
            let Some(byte) = tampered.get_mut(index) else { continue };
            *byte ^= 0x01;
            let Ok(candidate) = super::Signature::new(algorithm, tampered) else { continue };
            if verify_with(backend, &pair.verifying, message, &candidate).is_ok() {
                return fail(format!("a signature with byte {index} flipped still verified"));
            }
        }

        // 6. The empty message is a message.
        let empty = sign_with(backend, &pair.signing, b"")
            .map_err(|error| Failure(format!("signing the empty message failed: {error}")))?;
        verify_with(backend, &pair.verifying, b"", &empty)
            .map_err(|error| Failure(format!("the empty message did not verify: {error}")))?;
        if verify_with(backend, &pair.verifying, message, &empty).is_ok() {
            return fail("a signature over the empty message verified over a non-empty one");
        }

        Ok(())
    }
}

/// Signs using a specific backend, bypassing the registry.
///
/// For [`conformance`] and for a backend being evaluated before it is
/// registered. Ordinary callers want [`sign`].
pub fn sign_with(
    backend: &dyn SignatureBackend,
    key: &SigningKey,
    message: &[u8],
) -> Result<Signature, CryptoError> {
    backend.sign(key, message)
}

/// Verifies using a specific backend, bypassing the registry.
pub fn verify_with(
    backend: &dyn SignatureBackend,
    key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    if key.algorithm() != signature.algorithm() {
        return Err(CryptoError::BadSignature);
    }
    backend.verify(key, message, signature)
}

#[cfg(test)]
mod tests {
    use super::{
        backend, keypair_from_seed, sign, verify, Signature, SigningKey, VerifyingKey,
    };
    use crate::algorithm::AlgorithmId;
    use crate::error::CryptoError;
    use crate::hash::Hash;

    const TEST: AlgorithmId = AlgorithmId::InsecureTest;

    fn seed(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let pair = keypair_from_seed(TEST, &seed(1)).unwrap();
        let signature = sign(&pair.signing, b"a transaction digest").unwrap();
        assert_eq!(verify(&pair.verifying, b"a transaction digest", &signature), Ok(()));
    }

    #[test]
    fn a_different_message_does_not_verify() {
        let pair = keypair_from_seed(TEST, &seed(2)).unwrap();
        let signature = sign(&pair.signing, b"pay alice 10").unwrap();
        assert_eq!(
            verify(&pair.verifying, b"pay alice 11", &signature),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let mine = keypair_from_seed(TEST, &seed(3)).unwrap();
        let theirs = keypair_from_seed(TEST, &seed(4)).unwrap();
        let signature = sign(&mine.signing, b"message").unwrap();
        assert_eq!(
            verify(&theirs.verifying, b"message", &signature),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn signing_is_deterministic() {
        // Load-bearing: R2's account equivocation proof is "two signatures on
        // the same lane and sequence". If signing were randomised, an honest
        // wallet that retried a send would produce that evidence against
        // itself.
        let pair = keypair_from_seed(TEST, &seed(5)).unwrap();
        let first = sign(&pair.signing, b"same message").unwrap();
        let second = sign(&pair.signing, b"same message").unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn key_generation_is_deterministic() {
        let first = keypair_from_seed(TEST, &seed(6)).unwrap();
        let second = keypair_from_seed(TEST, &seed(6)).unwrap();
        assert_eq!(first.verifying, second.verifying);
        assert_eq!(first.signing, second.signing);
    }

    #[test]
    fn lengths_are_checked_at_construction() {
        assert!(VerifyingKey::new(TEST, vec![0; 31]).is_err());
        assert!(VerifyingKey::new(TEST, vec![0; 32]).is_ok());
        assert!(VerifyingKey::new(TEST, vec![0; 33]).is_err());
        assert!(SigningKey::new(TEST, vec![0; 32]).is_ok());
        assert!(Signature::new(TEST, vec![0; 64]).is_ok());
        assert!(Signature::new(TEST, vec![0; 63]).is_err());
    }

    #[test]
    fn a_kem_algorithm_is_not_a_signature_algorithm() {
        assert!(matches!(
            VerifyingKey::new(AlgorithmId::MlKem768, vec![0; 1184]),
            Err(CryptoError::WrongAlgorithmKind { .. })
        ));
        assert!(matches!(
            backend(AlgorithmId::MlKem768),
            Err(CryptoError::WrongAlgorithmKind { .. })
        ));
    }

    #[test]
    fn a_missing_backend_is_distinguishable_from_an_unknown_algorithm() {
        // This build knows ML-DSA-44 and cannot perform it. The error must say
        // so rather than claim the algorithm is unknown: the first is a build
        // configuration problem, the second a protocol version problem, and an
        // operator reading a log at midnight should not have to guess which.
        assert_eq!(
            backend(AlgorithmId::MlDsa44).err(),
            Some(CryptoError::NoBackend(AlgorithmId::MlDsa44))
        );
        assert_eq!(AlgorithmId::from_byte(0xee).err(), Some(CryptoError::UnknownAlgorithm(0xee)));
    }

    #[test]
    fn the_test_backend_passes_its_own_conformance_suite() {
        // Not because the test backend matters — it has no security — but
        // because this is the suite a real backend will be judged by, and a
        // suite nothing has ever passed is a suite that does not work.
        super::conformance::check(&super::insecure_test::INSECURE_TEST).unwrap();
    }

    #[test]
    fn identifiers_separate_accounts_from_devices() {
        let pair = keypair_from_seed(TEST, &seed(7)).unwrap();
        assert_ne!(
            pair.verifying.account_id(),
            pair.verifying.device_id(),
            "the same key yields the same id in two roles"
        );
    }

    #[test]
    fn identifiers_commit_to_the_algorithm() {
        // Two keys with identical bytes under different algorithms must not
        // share an account id. Constructed by hand because the lengths differ.
        let same_bytes = vec![0xcd; 32];
        let a = VerifyingKey::new(TEST, same_bytes).unwrap();
        let digest = a.account_id();
        // Recompute with the algorithm byte flipped; must differ.
        let forged = crate::hash::Hasher::new(crate::hash::domain::ACCOUNT_ID)
            .update(&[AlgorithmId::MlDsa44.to_byte()])
            .update(a.as_bytes())
            .finalize();
        assert_ne!(digest, forged);
    }

    #[test]
    fn a_secret_key_never_prints_itself() {
        let pair = keypair_from_seed(TEST, &seed(8)).unwrap();
        let text = format!("{:?}", pair.signing);
        assert!(text.contains("redacted"), "Debug did not redact: {text}");
        assert!(!text.contains("0808"), "Debug leaked key bytes: {text}");
    }
}
