// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The protocol's identifiers.
//!
//! All of them are 32-byte digests, and all of them are distinct types. The
//! repetition is the point: an [`AccountId`] and a [`DeviceId`] are both
//! `[u8; 32]` underneath, and a function that takes the wrong one compiles
//! perfectly well if they share a type. They do not share a type.
//!
//! Each is derived under its own domain (`spec/draft/02-hashing.md` §3), so the
//! separation holds on the wire as well as in the compiler.

use core::fmt;

use vanargand_crypto::hash::{domain, Hash};
use vanargand_crypto::sign::VerifyingKey;

use crate::codec::{CodecError, Decode, Decoder, Encode, Encoder};

/// Defines a 32-byte identifier newtype with the same shape as the others.
///
/// A macro rather than three hand-written copies: these types must stay
/// identical in every respect but their name and their domain, and hand-copied
/// code drifts. Each expansion still carries its own documentation.
macro_rules! digest_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
        pub struct $name(Hash);

        impl $name {
            /// The all-zero identifier.
            ///
            /// Not the identifier of anything: finding a key that hashes to
            /// zero would be a break of BLAKE3. Used as a sentinel where the
            /// protocol needs "no such thing" — the genesis block's parent, an
            /// empty subtree.
            pub const ZERO: Self = Self(Hash::ZERO);

            /// Wraps a digest that is already this kind of identifier.
            #[must_use]
            pub const fn from_hash(hash: Hash) -> Self {
                Self(hash)
            }

            /// The underlying digest.
            #[must_use]
            pub const fn as_hash(&self) -> &Hash {
                &self.0
            }

            /// The 32 bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            /// Lowercase hex, 64 characters.
            #[must_use]
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }

            /// Parses 64 hex characters.
            pub fn from_hex(text: &str) -> Result<Self, CodecError> {
                Hash::from_hex(text)
                    .map(Self)
                    .map_err(|_| CodecError::Invalid { reason: concat!("not a valid ", stringify!($name)) })
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl Encode for $name {
            fn encode(&self, out: &mut Encoder) {
                // Fixed width: no length prefix. The schema knows it is 32
                // bytes, and a prefix would be a second place to put a number.
                out.write_raw(self.0.as_bytes());
            }
        }

        impl Decode for $name {
            fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
                Ok(Self(Hash::from_bytes(input.read_array::<32>()?)))
            }
        }
    };
}

digest_id! {
    /// An account: the state key under which balances, names, devices,
    /// guardians and the nomad credit live.
    ///
    /// `H[vanargand v1 account id](algorithm_id ‖ root_public_key)`.
    ///
    /// Derived from the **root** key, never from a device key, so that
    /// revoking every device on an account does not change its address. That
    /// is the whole reason the root-key layer exists, and it is what makes
    /// losing a phone survivable.
    AccountId
}

digest_id! {
    /// A device subkey of an account.
    ///
    /// `H[vanargand v1 device id](algorithm_id ‖ device_public_key)`.
    ///
    /// A device owns a nonce lane and a share of the nomad credit. R2's
    /// correction is why this type exists at all: equivocation is provable
    /// *within one device subkey*, because two honest devices of one account,
    /// each isolated in its own partition, would otherwise produce an innocent
    /// equivocation and be punished for being in two places at once.
    DeviceId
}

digest_id! {
    /// A chain: the hash of its genesis block.
    ///
    /// Every signature in the protocol covers it, which is what makes a
    /// transaction signed for one chain invalid everywhere else — D4, replay
    /// across chains, resolved by construction. Cloning a chain is free and
    /// harmless: the clone has a running ledger and no other chain's locks
    /// recognise its keys.
    ChainId
}

digest_id! {
    /// A transaction: `H[vanargand v1 txid](canonical encoding of the body)`.
    ///
    /// Over the *body*, not the envelope, so the identifier does not depend on
    /// the signature — which is what makes it stable while a transaction is
    /// being assembled, and what stops a third party from changing the id by
    /// re-wrapping it.
    TxId
}

digest_id! {
    /// A block: `H[vanargand v1 block id](canonical encoding of the header)`.
    BlockId
}

digest_id! {
    /// An asset other than VAN: a festival's closed token, a local currency.
    ///
    /// R2's monetary inversion brings these forward from Tier 3 to Tier 1. The
    /// VAN is the machines' money — relays, gateways, archives and validators
    /// settle in it — while humans pay in an issuer's existing token, running
    /// on Vanargand's rails. That keeps the consumer-facing regulatory surface
    /// where it already was (G7).
    AssetId
}

impl AccountId {
    /// Derives the account identifier of a root key.
    #[must_use]
    pub fn of_root_key(key: &VerifyingKey) -> Self {
        Self::from_hash(key.identifier(domain::ACCOUNT_ID))
    }
}

impl DeviceId {
    /// Derives the device identifier of a device subkey.
    #[must_use]
    pub fn of_device_key(key: &VerifyingKey) -> Self {
        Self::from_hash(key.identifier(domain::DEVICE_ID))
    }
}

/// The VAN itself, as an asset identifier.
///
/// The native asset is not an [`AssetId`] — it is represented by `None` in
/// every field that can carry one, so that a transaction in VAN has no asset
/// field to forge and the common case is also the smallest encoding.
pub const NATIVE_ASSET: Option<AssetId> = None;

#[cfg(test)]
mod tests {
    use super::{AccountId, AssetId, BlockId, ChainId, DeviceId, TxId};
    use crate::codec::{Decode, Encode};
    use vanargand_crypto::hash::Hash;

    #[test]
    fn identifiers_are_fixed_width_with_no_length_prefix() {
        let id = AccountId::from_hash(Hash::from_bytes([0xab; 32]));
        let bytes = id.to_canonical_bytes();
        assert_eq!(bytes.len(), 32, "an identifier must not carry a length prefix");
        assert_eq!(AccountId::from_canonical_bytes(&bytes), Ok(id));
    }

    #[test]
    fn every_identifier_round_trips() {
        let hash = Hash::from_bytes([0x5c; 32]);
        assert_eq!(
            AccountId::from_canonical_bytes(&AccountId::from_hash(hash).to_canonical_bytes()),
            Ok(AccountId::from_hash(hash))
        );
        assert_eq!(
            DeviceId::from_canonical_bytes(&DeviceId::from_hash(hash).to_canonical_bytes()),
            Ok(DeviceId::from_hash(hash))
        );
        assert_eq!(
            ChainId::from_canonical_bytes(&ChainId::from_hash(hash).to_canonical_bytes()),
            Ok(ChainId::from_hash(hash))
        );
        assert_eq!(
            TxId::from_canonical_bytes(&TxId::from_hash(hash).to_canonical_bytes()),
            Ok(TxId::from_hash(hash))
        );
        assert_eq!(
            BlockId::from_canonical_bytes(&BlockId::from_hash(hash).to_canonical_bytes()),
            Ok(BlockId::from_hash(hash))
        );
        assert_eq!(
            AssetId::from_canonical_bytes(&AssetId::from_hash(hash).to_canonical_bytes()),
            Ok(AssetId::from_hash(hash))
        );
    }

    #[test]
    fn a_truncated_identifier_is_rejected() {
        assert!(AccountId::from_canonical_bytes(&[0xab; 31]).is_err());
        assert!(AccountId::from_canonical_bytes(&[0xab; 33]).is_err());
    }

    #[test]
    fn hex_round_trips_and_debug_shows_the_type() {
        let id = ChainId::from_hash(Hash::from_bytes([0x01; 32]));
        assert_eq!(ChainId::from_hex(&id.to_hex()), Ok(id));
        assert!(format!("{id:?}").starts_with("ChainId("));
        assert!(AccountId::from_hex("not hex").is_err());
    }

    #[test]
    fn the_zero_identifier_is_all_zeroes() {
        assert_eq!(AccountId::ZERO.as_bytes(), &[0_u8; 32]);
        assert_eq!(BlockId::ZERO.as_bytes(), &[0_u8; 32]);
    }

    #[test]
    fn ordering_is_lexicographic_over_the_bytes() {
        // Relied on by the canonical set ordering rule: a set of account ids is
        // sorted by the same comparison the decoder performs on encoded bytes,
        // which for a fixed-width identifier is the identity.
        let low = AccountId::from_hash(Hash::from_bytes([0x00; 32]));
        let high = AccountId::from_hash(Hash::from_bytes([0x01; 32]));
        assert!(low < high);
        assert!(low.to_canonical_bytes() < high.to_canonical_bytes());
    }
}
