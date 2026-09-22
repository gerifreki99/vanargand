// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! State keys: one namespace per kind of record.
//!
//! The sparse Merkle tree is a flat map from 32-byte keys to 32-byte digests,
//! and it now holds several kinds of record. Deriving every key through a
//! namespace keeps them in separate halves of the space.
//!
//! # Why not just use the identifiers directly
//!
//! An account identifier and a channel identifier are both 32 bytes. Storing
//! them raw means one key space shared by two kinds of record, and a proof that
//! "key *k* holds this value" carries no statement about *what kind of thing*
//! lives there. A verifier would have to decide from the value's shape, which
//! is how a parser confusion becomes a consensus bug.
//!
//! Colliding would still require a preimage, so this is not the difference
//! between safe and broken. It is the difference between a rule that holds
//! because nobody can break the hash and a rule that holds because the
//! namespaces differ — and only the second survives a future record type whose
//! identifier is *not* a hash.
//!
//! # The encoding
//!
//! ```text
//! key = H[vanargand v1 state value]( len(namespace) ‖ namespace ‖ payload )
//! ```
//!
//! The length byte makes the split unambiguous: without it, namespace `"asset"`
//! with a payload starting `x` and namespace `"assetx"` would hash the same
//! bytes.

use vanargand_crypto::hash::{domain, Hash, Hasher};
use vanargand_types::id::{AccountId, AssetId, TxId};
use vanargand_types::name::Name;

/// Accounts.
pub const NAMESPACE_ACCOUNT: &[u8] = b"account";
/// Micro-payment channels, keyed by the transaction that opened them.
pub const NAMESPACE_PURSE: &[u8] = b"purse";
/// Local assets.
pub const NAMESPACE_ASSET: &[u8] = b"asset";
/// The ticker index: a name to the asset that holds it.
pub const NAMESPACE_TICKER: &[u8] = b"ticker";
/// Registered human-readable names.
pub const NAMESPACE_NAME: &[u8] = b"name";
/// Sealed name-registration commitments, awaiting their reveal.
pub const NAMESPACE_COMMITMENT: &[u8] = b"commitment";
/// Recoveries in progress.
///
/// Keyed by the account being recovered, and therefore *not* in the `account`
/// namespace: a pending recovery and the account it concerns are two records
/// about the same identifier, and sharing a key would have one silently
/// overwrite the other.
pub const NAMESPACE_RECOVERY: &[u8] = b"recovery";
/// Equivocations that have already been punished.
pub const NAMESPACE_OFFENCE: &[u8] = b"offence";
/// Protocol counters that belong to no account.
pub const NAMESPACE_RESERVED: &[u8] = b"reserved";

/// Derives a state key.
///
/// Public so that a light client can recompute a key without reimplementing the
/// namespace rule from prose.
#[must_use]
pub fn derive(namespace: &[u8], payload: &[u8]) -> Hash {
    let length = u8::try_from(namespace.len()).unwrap_or(u8::MAX);
    Hasher::new(domain::STATE_VALUE)
        .update(&[length])
        .update(namespace)
        .update(payload)
        .finalize()
}

/// The key an account's record lives at.
#[must_use]
pub fn account(id: &AccountId) -> Hash {
    derive(NAMESPACE_ACCOUNT, id.as_bytes())
}

/// The key a channel's record lives at.
#[must_use]
pub fn purse(id: &TxId) -> Hash {
    derive(NAMESPACE_PURSE, id.as_bytes())
}

/// The key an asset's record lives at.
#[must_use]
pub fn asset(id: &AssetId) -> Hash {
    derive(NAMESPACE_ASSET, id.as_bytes())
}

/// The key a ticker reservation lives at.
///
/// Keyed by the name's bytes, so that the uniqueness of a ticker is a property
/// of the tree rather than of a side index somebody has to remember to check.
#[must_use]
pub fn ticker(name: &Name) -> Hash {
    derive(NAMESPACE_TICKER, name.as_str().as_bytes())
}

/// The key a registered name's owner lives at.
#[must_use]
pub fn name(value: &Name) -> Hash {
    derive(NAMESPACE_NAME, value.as_str().as_bytes())
}

/// The key a sealed registration commitment lives at.
#[must_use]
pub fn commitment(value: &Hash) -> Hash {
    derive(NAMESPACE_COMMITMENT, value.as_bytes())
}

/// The key a pending recovery lives at.
#[must_use]
pub fn recovery(target: &AccountId) -> Hash {
    derive(NAMESPACE_RECOVERY, target.as_bytes())
}

/// The key a punished equivocation is recorded at.
///
/// Keyed by the digest of the offence itself, so that "has this already been
/// punished?" is a question about the tree rather than about a side index
/// somebody has to remember to consult — and so that a light client can prove
/// a bounty was already paid.
#[must_use]
pub fn offence(digest: &Hash) -> Hash {
    derive(NAMESPACE_OFFENCE, digest.as_bytes())
}

/// The key a reserved protocol counter lives at.
#[must_use]
pub fn reserved(label: &[u8]) -> Hash {
    derive(NAMESPACE_RESERVED, label)
}

#[cfg(test)]
mod tests {
    use super::{account, asset, commitment, derive, offence, purse, recovery, reserved, ticker};
    use std::collections::BTreeSet;
    use vanargand_crypto::hash::Hash;
    use vanargand_types::id::{AccountId, AssetId, TxId};
    use vanargand_types::name::Name;

    fn same_bytes() -> [u8; 32] {
        [0x5a; 32]
    }

    #[test]
    fn identical_identifiers_land_in_different_namespaces() {
        // The property the module exists for: an account and a channel with
        // byte-identical identifiers are different keys.
        let bytes = Hash::from_bytes(same_bytes());
        let keys: BTreeSet<Hash> = [
            account(&AccountId::from_hash(bytes)),
            purse(&TxId::from_hash(bytes)),
            asset(&AssetId::from_hash(bytes)),
            recovery(&AccountId::from_hash(bytes)),
            commitment(&bytes),
            offence(&bytes),
            reserved(&same_bytes()),
        ]
        .into_iter()
        .collect();
        assert_eq!(keys.len(), 7, "two namespaces collided on identical payloads");
    }

    #[test]
    fn the_length_prefix_makes_the_split_unambiguous() {
        // Without it, namespace "asset" with payload "xy" and namespace
        // "assetx" with payload "y" would hash the same bytes.
        assert_ne!(derive(b"asset", b"xy"), derive(b"assetx", b"y"));
        assert_ne!(derive(b"a", b"bc"), derive(b"ab", b"c"));
    }

    #[test]
    fn derivation_is_deterministic() {
        let id = AccountId::from_hash(Hash::from_bytes(same_bytes()));
        assert_eq!(account(&id), account(&id));
    }

    #[test]
    fn different_payloads_give_different_keys() {
        let first = AccountId::from_hash(Hash::from_bytes([1; 32]));
        let second = AccountId::from_hash(Hash::from_bytes([2; 32]));
        assert_ne!(account(&first), account(&second));
    }

    #[test]
    fn tickers_are_keyed_by_their_text() {
        let festival = Name::new("festi").expect("a valid name");
        let other = Name::new("festo").expect("a valid name");
        assert_eq!(ticker(&festival), ticker(&festival));
        assert_ne!(ticker(&festival), ticker(&other));
    }

    #[test]
    fn a_reserved_key_is_not_reachable_from_an_identifier() {
        // Not a proof — hitting it would need a preimage — but a check that the
        // namespaces really do differ, which is the part that does not depend
        // on the hash being strong.
        let label = b"burn and context pot";
        let as_account = account(&AccountId::from_hash(Hash::from_bytes([9; 32])));
        assert_ne!(reserved(label), as_account);
    }
}
