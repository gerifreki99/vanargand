// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cryptographic primitives for Vanargand.
//!
//! This crate is the **only** place in the workspace that names a cryptographic
//! library. `CONTRIBUTING.md` states the rule:
//!
//! > Toutes les primitives passent par l'abstraction de `vanargand-crypto`.
//! > N'appelez jamais une primitive directement depuis ailleurs.
//!
//! The rule exists because the post-quantum landscape is young. ML-DSA-44 is
//! today's choice (R1.7), made for implementation safety on heterogeneous
//! hardware rather than for compactness, and it will not be the last choice. A
//! crate that depends on `ml-dsa` directly is a crate that has to be rewritten
//! when that changes; a crate that depends on [`sign::VerifyingKey`] is not.
//!
//! # What lives here
//!
//! - [`hash`] — BLAKE3, and the domain separation that every hash in the
//!   protocol is required to use.
//! - [`chain`] — hash chains, which are both the consensus randomness beacon
//!   (A4) and the PayWord micro-payment scheme, read in opposite directions.
//! - [`mod@derive`] — the key hierarchy: one master seed, everything else derived.
//! - [`sign`] / [`kem`] — algorithm-agnostic signature and key-encapsulation
//!   interfaces, plus the backend registry.
//!
//! # What deliberately does not live here
//!
//! Randomness. This crate generates no keys from entropy and holds no RNG:
//! every secret is derived from a seed the caller supplies, which is what makes
//! key generation reproducible and test vectors possible. Obtaining the master
//! seed from a real entropy source is the wallet's job, not the protocol's.
//!
//! # Backends
//!
//! **No post-quantum library is a dependency of this crate yet**, and that is a
//! state rather than an oversight. What is here is the part that has to be
//! right before a library is chosen: the algorithm registry, the traits, and
//! [`sign::conformance`], a behavioural suite that a candidate backend has to
//! pass — deterministic signing, deterministic key generation, rejection of
//! every single-byte corruption. `BACKENDS.md` has the integration guide.
//!
//! The `test-backend` feature registers a deterministic stand-in with no
//! security at all, so that the rest of the workspace can be tested end to end
//! in the meantime. It sits at algorithm id `0x10`, which
//! [`AlgorithmId::valid_on_live_chain`] rejects.

pub mod algorithm;
pub mod chain;
pub mod derive;
pub mod error;
pub mod hash;
pub mod kem;
pub mod sign;

pub use algorithm::AlgorithmId;
pub use error::CryptoError;
pub use hash::{Context, Hash, Hasher};

/// Compares two byte strings in time independent of their contents.
///
/// Returns `true` only if the slices have the same length and the same bytes.
/// Length is not secret and is compared normally; an attacker who can vary the
/// length of a secret already knows more than this function can hide.
///
/// Use this for anything an adversary can submit repeatedly and adapt: a
/// PayWord token against its expected preimage, a MAC, a recovery code. Do not
/// use it for public values such as block hashes, where the extra cost buys
/// nothing.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // `black_box` discourages the optimiser from turning the accumulation back
    // into an early-exit comparison. It is a hint, not a guarantee; the real
    // guarantee would need assembly, and this is the standard pure-Rust
    // approximation.
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn ct_eq_matches_ordinary_equality() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"a", b"a"),
            (b"a", b"b"),
            (b"", b"a"),
            (b"abc", b"abcd"),
            (&[0x00, 0xff], &[0x00, 0xff]),
            (&[0x00, 0xff], &[0x01, 0xff]),
        ];
        for (a, b) in cases {
            assert_eq!(ct_eq(a, b), a == b, "ct_eq disagreed on {a:?} vs {b:?}");
        }
    }
}
