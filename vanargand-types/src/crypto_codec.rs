// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical encodings for the types owned by `vanargand-crypto`.
//!
//! They live here rather than in that crate so that the primitive layer stays
//! free of the transaction encoder: a recovery tool that only needs to derive a
//! key should not have to link the codec, and the codec's limits should not
//! constrain what a key is.
//!
//! # The shape of a key on the wire
//!
//! `algorithm_id` (one byte) followed by exactly as many raw bytes as that
//! algorithm requires. **No length prefix.** The length is a property of the
//! algorithm, and an encoding that stated it separately would give an attacker
//! a second number to disagree with the first.

use vanargand_crypto::algorithm::AlgorithmId;
use vanargand_crypto::hash::Hash;
use vanargand_crypto::sign::{Signature, VerifyingKey};

use crate::codec::{CodecError, Decode, Decoder, Encode, Encoder};

impl Encode for Hash {
    fn encode(&self, out: &mut Encoder) {
        out.write_raw(self.as_bytes());
    }
}

impl Decode for Hash {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self::from_bytes(input.read_array::<32>()?))
    }
}

/// Reads and validates an algorithm identifier byte.
fn decode_algorithm(input: &mut Decoder<'_>) -> Result<AlgorithmId, CodecError> {
    let byte = input.read_u8()?;
    AlgorithmId::from_byte(byte).map_err(|_| CodecError::Invalid { reason: "unknown algorithm" })
}

impl Encode for VerifyingKey {
    fn encode(&self, out: &mut Encoder) {
        out.write_u8(self.algorithm().to_byte());
        out.write_raw(self.as_bytes());
    }
}

impl Decode for VerifyingKey {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let algorithm = decode_algorithm(input)?;
        if !algorithm.is_signature() {
            return Err(CodecError::Invalid { reason: "not a signature algorithm" });
        }
        let bytes = input.read_raw(algorithm.public_key_len())?.to_vec();
        Self::new(algorithm, bytes).map_err(|_| CodecError::Invalid { reason: "malformed key" })
    }
}

impl Encode for Signature {
    fn encode(&self, out: &mut Encoder) {
        out.write_u8(self.algorithm().to_byte());
        out.write_raw(self.as_bytes());
    }
}

impl Decode for Signature {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let algorithm = decode_algorithm(input)?;
        if !algorithm.is_signature() {
            return Err(CodecError::Invalid { reason: "not a signature algorithm" });
        }
        let bytes = input.read_raw(algorithm.output_len())?.to_vec();
        Self::new(algorithm, bytes)
            .map_err(|_| CodecError::Invalid { reason: "malformed signature" })
    }
}

/// Whether a key or signature may appear on a production chain.
///
/// Consensus code MUST call this on every key and signature it decodes. The
/// codec deliberately does *not* enforce it: the test algorithms have to be
/// decodable so that test vectors and the workspace's own tests can use them,
/// and the line between "decodable" and "acceptable" is drawn here, in one
/// place, on purpose.
#[must_use]
pub fn valid_on_live_chain(algorithm: AlgorithmId) -> bool {
    algorithm.valid_on_live_chain()
}

#[cfg(test)]
mod tests {
    use super::valid_on_live_chain;
    use crate::codec::{CodecError, Decode, Encode, Encoder};
    use vanargand_crypto::algorithm::AlgorithmId;
    use vanargand_crypto::hash::Hash;
    use vanargand_crypto::sign::{Signature, VerifyingKey};

    const TEST: AlgorithmId = AlgorithmId::InsecureTest;

    #[test]
    fn hashes_are_thirty_two_raw_bytes() {
        let hash = Hash::from_bytes([0x3c; 32]);
        let bytes = hash.to_canonical_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(Hash::from_canonical_bytes(&bytes), Ok(hash));
    }

    #[test]
    fn keys_round_trip_and_carry_no_length_prefix() {
        let key = VerifyingKey::new(TEST, vec![0xa1; 32]).unwrap();
        let bytes = key.to_canonical_bytes();
        assert_eq!(bytes.len(), 33, "one algorithm byte plus the key, nothing else");
        assert_eq!(bytes.first().copied(), Some(TEST.to_byte()));
        assert_eq!(VerifyingKey::from_canonical_bytes(&bytes), Ok(key));
    }

    #[test]
    fn signatures_round_trip() {
        let signature = Signature::new(TEST, vec![0x7b; 64]).unwrap();
        let bytes = signature.to_canonical_bytes();
        assert_eq!(bytes.len(), 65);
        assert_eq!(Signature::from_canonical_bytes(&bytes), Ok(signature));
    }

    #[test]
    fn a_truncated_key_is_rejected_without_allocating() {
        // Claims ML-DSA-44, supplies four bytes. The decoder must notice from
        // the input length, not from a failed 1312-byte read.
        let mut encoder = Encoder::new();
        encoder.write_u8(AlgorithmId::MlDsa44.to_byte());
        encoder.write_raw(&[0; 4]);
        let bytes = encoder.finish();
        assert!(matches!(
            VerifyingKey::from_canonical_bytes(&bytes),
            Err(CodecError::LengthBeyondInput { .. })
        ));
    }

    #[test]
    fn an_unknown_algorithm_byte_is_rejected() {
        let mut encoder = Encoder::new();
        encoder.write_u8(0x00);
        encoder.write_raw(&[0; 32]);
        assert_eq!(
            VerifyingKey::from_canonical_bytes(&encoder.finish()),
            Err(CodecError::Invalid { reason: "unknown algorithm" })
        );
    }

    #[test]
    fn a_kem_algorithm_is_not_a_verifying_key() {
        let mut encoder = Encoder::new();
        encoder.write_u8(AlgorithmId::MlKem768.to_byte());
        encoder.write_raw(&[0; 1184]);
        assert_eq!(
            VerifyingKey::from_canonical_bytes(&encoder.finish()),
            Err(CodecError::Invalid { reason: "not a signature algorithm" })
        );
    }

    #[test]
    fn trailing_bytes_after_a_key_are_rejected() {
        let key = VerifyingKey::new(TEST, vec![0x11; 32]).unwrap();
        let mut bytes = key.to_canonical_bytes();
        bytes.push(0);
        assert_eq!(
            VerifyingKey::from_canonical_bytes(&bytes),
            Err(CodecError::TrailingBytes(1))
        );
    }

    #[test]
    fn the_test_algorithm_decodes_but_is_not_live_chain_valid() {
        // Both halves matter. If it did not decode, test vectors could not
        // exist; if it were live-chain valid, anyone could forge every
        // signature on the network.
        let key = VerifyingKey::new(TEST, vec![0; 32]).unwrap();
        assert!(VerifyingKey::from_canonical_bytes(&key.to_canonical_bytes()).is_ok());
        assert!(!valid_on_live_chain(TEST));
        assert!(valid_on_live_chain(AlgorithmId::MlDsa44));
        assert!(valid_on_live_chain(AlgorithmId::MlDsa65));
    }
}
