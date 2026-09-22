// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registered names, and the commit-and-reveal that protects them.
//!
//! # Why two transactions and not one
//!
//! R1.7 records this as an acknowledged omission in the original design, filed
//! under F4. Without commit-and-reveal, a validator that sees `name_reveal` in
//! the mempool registers the name first — front-running, against exactly the
//! kind of object where being first is the entire value.
//!
//! So a registration is two acts. First a sealed commitment, which says
//! nothing about the name. Then, once the commitment is settled and public, the
//! reveal that opens it. A front-runner seeing the reveal has nothing to run in
//! front of: the claim was staked before the name was knowable.
//!
//! The delay between them is counted in **finalised** height, like every other
//! deadline. A reveal in the same block as its commitment would let the
//! proposer reorder the two and defeat the whole mechanism.

use std::collections::BTreeMap;

use core::fmt;

use vanargand_crypto::hash::{domain, Hash, Hasher};
use vanargand_types::block::params::EPOCH_BLOCKS;
use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::id::AccountId;
use vanargand_types::name::Name;
use vanargand_types::tx::name_commitment;

/// How long a commitment must settle before it may be revealed, in finalised
/// blocks.
///
/// Ten blocks — under a minute of healthy chain. Enough that the commitment is
/// unambiguously earlier than the reveal in every honest node's view; short
/// enough that registering a name is not an errand.
///
/// A parameter. What is not a parameter is that it is greater than zero and
/// counted in finalised height.
pub const MIN_REVEAL_DELAY_FINALIZED_BLOCKS: u64 = 10;

/// How long an unopened commitment survives, in finalised blocks.
///
/// Twelve epochs, about half a day. Commitments are opaque, so an abandoned one
/// is a row nobody can ever interpret; letting them accumulate would be a slow
/// leak in the state that `docs/01-concept.pdf` promises stays small.
pub const COMMITMENT_EXPIRY_FINALIZED_BLOCKS: u64 = 12 * EPOCH_BLOCKS;

/// A sealed registration claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentRecord {
    /// Who staked it.
    pub account: AccountId,
    /// The finalised height it was recorded at.
    pub committed_at_finalized: u64,
}

impl CommitmentRecord {
    /// The digest stored in the state tree.
    #[must_use]
    pub fn value_hash(&self) -> Hash {
        Hasher::new(domain::STATE_VALUE).update(&self.to_canonical_bytes()).finalize()
    }
}

impl Encode for CommitmentRecord {
    fn encode(&self, out: &mut Encoder) {
        self.account.encode(out);
        out.write_varint(self.committed_at_finalized);
    }
}

impl Decode for CommitmentRecord {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            account: AccountId::decode(input)?,
            committed_at_finalized: input.read_varint()?,
        })
    }
}

/// Why a name operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameError {
    /// The commitment is already staked.
    CommitmentExists,
    /// No such commitment — or it was staked by somebody else.
    ///
    /// The two are one error on purpose. A commitment is a hash of the name,
    /// the salt *and* the claimant, so "this is not yours" and "this does not
    /// exist" are the same observation, and distinguishing them would let
    /// someone probe for other people's pending claims.
    NoSuchCommitment,
    /// The commitment has not settled for long enough.
    TooSoon {
        /// The finalised height it was staked at.
        committed_at: u64,
        /// The finalised height now.
        now: u64,
    },
    /// The commitment expired unopened.
    CommitmentExpired {
        /// The finalised height it was staked at.
        committed_at: u64,
        /// The finalised height now.
        now: u64,
    },
    /// Somebody already holds the name.
    NameTaken {
        /// Who holds it.
        owner: AccountId,
    },
    /// The name is short enough to be auctioned, and auctions do not exist yet.
    PremiumNotAuctioned {
        /// The name in question.
        name: Name,
    },
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommitmentExists => write!(f, "that commitment is already staked"),
            Self::NoSuchCommitment => write!(f, "no such commitment"),
            Self::TooSoon { committed_at, now } => write!(
                f,
                "committed at finalised height {committed_at}, now {now}; \
                 {MIN_REVEAL_DELAY_FINALIZED_BLOCKS} must pass"
            ),
            Self::CommitmentExpired { committed_at, now } => {
                write!(f, "commitment from finalised height {committed_at} expired before {now}")
            }
            Self::NameTaken { owner } => write!(f, "that name belongs to {owner}"),
            Self::PremiumNotAuctioned { name } => write!(
                f,
                "'{name}' is short enough to be auctioned, and the auction is not built"
            ),
        }
    }
}

impl std::error::Error for NameError {}

/// Registered names and the commitments waiting to become them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameBook {
    owners: BTreeMap<Name, AccountId>,
    commitments: BTreeMap<Hash, CommitmentRecord>,
}

impl NameBook {
    /// Nothing registered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Who holds a name.
    #[must_use]
    pub fn owner(&self, name: &Name) -> Option<AccountId> {
        self.owners.get(name).copied()
    }

    /// How many names are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    /// Whether no name is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// Every registered name, in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = (&Name, &AccountId)> {
        self.owners.iter()
    }

    /// Every pending commitment, in ascending digest order.
    pub fn commitments(&self) -> impl Iterator<Item = (&Hash, &CommitmentRecord)> {
        self.commitments.iter()
    }

    /// Stakes a sealed claim.
    pub fn commit(
        &mut self,
        commitment: Hash,
        account: AccountId,
        finalized_height: u64,
    ) -> Result<(), NameError> {
        if self.commitments.contains_key(&commitment) {
            return Err(NameError::CommitmentExists);
        }
        self.commitments
            .insert(commitment, CommitmentRecord { account, committed_at_finalized: finalized_height });
        Ok(())
    }

    /// Opens a commitment and registers the name.
    ///
    /// The commitment is recomputed from the name, the salt and the claimant,
    /// so a reveal cannot open somebody else's claim even with their salt.
    pub fn reveal(
        &mut self,
        name: &Name,
        salt: &[u8; 32],
        account: AccountId,
        finalized_height: u64,
    ) -> Result<(), NameError> {
        if name.is_premium() {
            // R1.7 auctions short names rather than handing them out
            // first-come. The auction is not built, and registering them
            // first-come in the meantime would give away precisely the names
            // the auction exists to protect. Refusing is the reversible
            // decision; handing them out is not.
            return Err(NameError::PremiumNotAuctioned { name: name.clone() });
        }

        let commitment = name_commitment(name, salt, account);
        let record = *self.commitments.get(&commitment).ok_or(NameError::NoSuchCommitment)?;
        if record.account != account {
            // Unreachable: the account is hashed into the commitment. Kept so
            // that the invariant is stated where it is relied on.
            return Err(NameError::NoSuchCommitment);
        }

        let earliest =
            record.committed_at_finalized.saturating_add(MIN_REVEAL_DELAY_FINALIZED_BLOCKS);
        if finalized_height < earliest {
            return Err(NameError::TooSoon {
                committed_at: record.committed_at_finalized,
                now: finalized_height,
            });
        }
        let deadline =
            record.committed_at_finalized.saturating_add(COMMITMENT_EXPIRY_FINALIZED_BLOCKS);
        if finalized_height > deadline {
            return Err(NameError::CommitmentExpired {
                committed_at: record.committed_at_finalized,
                now: finalized_height,
            });
        }

        if let Some(owner) = self.owner(name) {
            return Err(NameError::NameTaken { owner });
        }

        self.commitments.remove(&commitment);
        self.owners.insert(name.clone(), account);
        Ok(())
    }

    /// Drops commitments that expired unopened, returning how many.
    ///
    /// Called once per block by the block processor. Settled or abandoned
    /// obligations leave state; an opaque row nobody can ever interpret is the
    /// worst kind to leave behind.
    pub fn prune_expired(&mut self, finalized_height: u64) -> usize {
        let stale: Vec<Hash> = self
            .commitments
            .iter()
            .filter(|(_, record)| {
                finalized_height
                    > record
                        .committed_at_finalized
                        .saturating_add(COMMITMENT_EXPIRY_FINALIZED_BLOCKS)
            })
            .map(|(digest, _)| *digest)
            .collect();
        for digest in &stale {
            self.commitments.remove(digest);
        }
        stale.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NameBook, NameError, COMMITMENT_EXPIRY_FINALIZED_BLOCKS,
        MIN_REVEAL_DELAY_FINALIZED_BLOCKS,
    };
    use vanargand_crypto::hash::Hash;
    use vanargand_types::id::AccountId;
    use vanargand_types::name::Name;
    use vanargand_types::tx::name_commitment;

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn name(text: &str) -> Name {
        Name::new(text).expect("a valid name")
    }

    const SALT: [u8; 32] = [0x5a; 32];

    #[test]
    fn a_name_is_registered_by_commit_then_reveal() {
        let mut book = NameBook::new();
        let wanted = name("cafe-du-port");
        let commitment = name_commitment(&wanted, &SALT, account(1));

        book.commit(commitment, account(1), 100).expect("a fresh commitment");
        assert!(book.owner(&wanted).is_none(), "the name leaked from the commitment");

        book.reveal(&wanted, &SALT, account(1), 100 + MIN_REVEAL_DELAY_FINALIZED_BLOCKS)
            .expect("the delay has passed");
        assert_eq!(book.owner(&wanted), Some(account(1)));
        assert_eq!(book.len(), 1);
        assert_eq!(book.commitments().count(), 0, "the spent commitment stayed in state");
    }

    #[test]
    fn a_reveal_in_the_same_block_is_refused() {
        // Without the delay, a proposer could reorder the commitment and the
        // reveal within one block and defeat the whole mechanism.
        let mut book = NameBook::new();
        let wanted = name("cafe-du-port");
        book.commit(name_commitment(&wanted, &SALT, account(1)), account(1), 100).unwrap();

        assert_eq!(
            book.reveal(&wanted, &SALT, account(1), 100),
            Err(NameError::TooSoon { committed_at: 100, now: 100 })
        );
        assert_eq!(
            book.reveal(&wanted, &SALT, account(1), 100 + MIN_REVEAL_DELAY_FINALIZED_BLOCKS - 1),
            Err(NameError::TooSoon {
                committed_at: 100,
                now: 100 + MIN_REVEAL_DELAY_FINALIZED_BLOCKS - 1
            })
        );
    }

    #[test]
    fn a_front_runner_cannot_open_someone_elses_claim() {
        // The commitment hashes the claimant, so knowing the name and even the
        // salt buys nothing. This is the F4 parade, tested where it bites.
        let mut book = NameBook::new();
        let wanted = name("cafe-du-port");
        book.commit(name_commitment(&wanted, &SALT, account(1)), account(1), 100).unwrap();

        assert_eq!(
            book.reveal(&wanted, &SALT, account(2), 200),
            Err(NameError::NoSuchCommitment),
            "a front-runner opened another account's claim"
        );
        assert!(book.owner(&wanted).is_none());

        // The rightful claimant still can.
        book.reveal(&wanted, &SALT, account(1), 200).expect("the claim is intact");
        assert_eq!(book.owner(&wanted), Some(account(1)));
    }

    #[test]
    fn the_wrong_salt_opens_nothing() {
        let mut book = NameBook::new();
        let wanted = name("cafe-du-port");
        book.commit(name_commitment(&wanted, &SALT, account(1)), account(1), 100).unwrap();
        assert_eq!(
            book.reveal(&wanted, &[0x00; 32], account(1), 200),
            Err(NameError::NoSuchCommitment)
        );
    }

    #[test]
    fn a_taken_name_is_refused() {
        let mut book = NameBook::new();
        let wanted = name("cafe-du-port");
        book.commit(name_commitment(&wanted, &SALT, account(1)), account(1), 100).unwrap();
        book.reveal(&wanted, &SALT, account(1), 200).unwrap();

        book.commit(name_commitment(&wanted, &SALT, account(2)), account(2), 300).unwrap();
        assert_eq!(
            book.reveal(&wanted, &SALT, account(2), 400),
            Err(NameError::NameTaken { owner: account(1) })
        );
    }

    #[test]
    fn premium_names_are_refused_until_the_auction_exists() {
        // R1.7 auctions names under six characters. Handing them out
        // first-come in the meantime would give away exactly the names the
        // auction exists to protect — and unlike refusing, it cannot be undone.
        let mut book = NameBook::new();
        let short = name("marie");
        book.commit(name_commitment(&short, &SALT, account(1)), account(1), 100).unwrap();

        assert_eq!(
            book.reveal(&short, &SALT, account(1), 200),
            Err(NameError::PremiumNotAuctioned { name: short })
        );
        assert!(book.is_empty());
    }

    #[test]
    fn a_commitment_expires_unopened() {
        let mut book = NameBook::new();
        let wanted = name("cafe-du-port");
        book.commit(name_commitment(&wanted, &SALT, account(1)), account(1), 100).unwrap();

        let too_late = 100 + COMMITMENT_EXPIRY_FINALIZED_BLOCKS + 1;
        assert_eq!(
            book.reveal(&wanted, &SALT, account(1), too_late),
            Err(NameError::CommitmentExpired { committed_at: 100, now: too_late })
        );
    }

    #[test]
    fn expired_commitments_are_pruned() {
        // An opaque row nobody can ever interpret is the worst kind to leave in
        // a state that is meant to stay small for ever.
        let mut book = NameBook::new();
        for byte in 1..5_u8 {
            let wanted = name(&format!("name-{byte}"));
            book.commit(name_commitment(&wanted, &SALT, account(byte)), account(byte), 100)
                .unwrap();
        }
        assert_eq!(book.commitments().count(), 4);

        assert_eq!(book.prune_expired(100), 0, "pruned a live commitment");
        assert_eq!(book.prune_expired(100 + COMMITMENT_EXPIRY_FINALIZED_BLOCKS), 0);
        assert_eq!(book.prune_expired(100 + COMMITMENT_EXPIRY_FINALIZED_BLOCKS + 1), 4);
        assert_eq!(book.commitments().count(), 0);
    }

    #[test]
    fn a_duplicate_commitment_is_refused() {
        let mut book = NameBook::new();
        let commitment = name_commitment(&name("cafe-du-port"), &SALT, account(1));
        book.commit(commitment, account(1), 100).unwrap();
        assert_eq!(book.commit(commitment, account(1), 101), Err(NameError::CommitmentExists));
    }

    #[test]
    fn names_iterate_in_order() {
        // Consensus-critical: hashed into the state root.
        let mut book = NameBook::new();
        for text in ["zebra-one", "alpha-one", "milieu-un"] {
            let wanted = name(text);
            book.commit(name_commitment(&wanted, &SALT, account(1)), account(1), 100).unwrap();
            book.reveal(&wanted, &SALT, account(1), 200).unwrap();
        }
        let observed: Vec<String> = book.iter().map(|(name, _)| name.to_string()).collect();
        assert_eq!(observed, vec!["alpha-one", "milieu-un", "zebra-one"]);
    }
}
