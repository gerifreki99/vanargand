// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Votes, certificates, and the two-thirds threshold.
//!
//! A certificate is what turns a proposed block into a rung-2 final one. It is
//! also the object a light client checks, so everything here is designed to be
//! verifiable from the committee and the validator set alone.

use core::fmt;
use std::collections::BTreeSet;

use vanargand_crypto::sign::Signature;
use vanargand_types::block::BlockHeader;
use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::id::{AccountId, BlockId};

use crate::committee::Committee;
use crate::validator::ValidatorSet;
use crate::weight::Weight;

/// One member's vote for a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    /// Who voted.
    pub member: AccountId,
    /// Their signature over the block's signing digest.
    pub signature: Signature,
}

impl Encode for Vote {
    fn encode(&self, out: &mut Encoder) {
        self.member.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for Vote {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self { member: AccountId::decode(input)?, signature: Signature::decode(input)? })
    }
}

/// A set of votes for one block.
///
/// Votes are held in ascending member order, which is also how they are
/// encoded. That is not tidiness: it is what makes "no member voted twice" a
/// property a verifier checks in one pass rather than with a set on the side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The block this certificate finalises.
    pub block: BlockId,
    /// The votes, ascending by member.
    pub votes: Vec<Vote>,
}

/// Why a certificate was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateError {
    /// The certificate names a block other than the header supplied.
    WrongBlock {
        /// What the certificate claims.
        certified: BlockId,
        /// What the header actually is.
        header: BlockId,
    },
    /// Votes are not in strictly ascending member order.
    ///
    /// Covers duplicates too: a repeated member is not ascending. A duplicate
    /// would count its weight twice and let a third of the committee
    /// manufacture finality.
    Unordered {
        /// Index of the offending vote.
        index: usize,
    },
    /// A voter is not on duty at this block.
    NotOnDuty(AccountId),
    /// A voter is not in the validator set, so there is no key to check.
    UnknownValidator(AccountId),
    /// A signature did not verify.
    BadSignature(AccountId),
    /// A voter used a test algorithm on a production chain.
    TestAlgorithmOnLiveChain(AccountId),
    /// Weight arithmetic overflowed.
    Overflow,
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongBlock { certified, header } => {
                write!(f, "certificate is for {certified}, header is {header}")
            }
            Self::Unordered { index } => {
                write!(f, "vote {index} is not after its predecessor")
            }
            Self::NotOnDuty(member) => write!(f, "{member} is not on duty at this block"),
            Self::UnknownValidator(member) => write!(f, "{member} is not a validator"),
            Self::BadSignature(member) => write!(f, "{member}'s signature did not verify"),
            Self::TestAlgorithmOnLiveChain(member) => {
                write!(f, "{member} used a test algorithm on a production chain")
            }
            Self::Overflow => write!(f, "weight arithmetic overflowed"),
        }
    }
}

impl std::error::Error for CertificateError {}

impl Certificate {
    /// Verifies every vote and returns the weight they carry.
    ///
    /// Returns the **signed weight**, not a yes-or-no answer. Deciding whether
    /// that weight is enough is [`Certificate::finalises`], and the two are
    /// separate on purpose: the inactivity leak changes the denominator without
    /// changing the votes, so a caller sometimes needs the numerator alone.
    ///
    /// `allow_test_algorithms` exists for the test network. A production node
    /// passes `false`, and the check is here rather than left to the caller
    /// because a certificate is exactly the object where forgetting it would
    /// let anyone finalise anything.
    pub fn verify(
        &self,
        header: &BlockHeader,
        committee: &Committee,
        block_in_epoch: u64,
        validators: &ValidatorSet,
        allow_test_algorithms: bool,
    ) -> Result<Weight, CertificateError> {
        let header_id = header.id();
        if self.block != header_id {
            return Err(CertificateError::WrongBlock {
                certified: self.block,
                header: header_id,
            });
        }

        let on_duty: BTreeSet<AccountId> =
            committee.active_at(block_in_epoch).into_iter().map(|member| member.account).collect();
        let digest = header.signing_digest();

        let mut previous: Option<AccountId> = None;
        let mut signed = Weight::ZERO;

        for (index, vote) in self.votes.iter().enumerate() {
            if let Some(last) = previous {
                if vote.member <= last {
                    return Err(CertificateError::Unordered { index });
                }
            }
            previous = Some(vote.member);

            if !on_duty.contains(&vote.member) {
                return Err(CertificateError::NotOnDuty(vote.member));
            }
            let record = validators
                .get(&vote.member)
                .ok_or(CertificateError::UnknownValidator(vote.member))?;

            if !allow_test_algorithms && !record.key.algorithm().valid_on_live_chain() {
                return Err(CertificateError::TestAlgorithmOnLiveChain(vote.member));
            }
            vanargand_crypto::sign::verify(&record.key, digest.as_bytes(), &vote.signature)
                .map_err(|_| CertificateError::BadSignature(vote.member))?;

            let weight = committee
                .weight_of(&vote.member)
                .ok_or(CertificateError::NotOnDuty(vote.member))?;
            signed = signed.checked_add(weight).ok_or(CertificateError::Overflow)?;
        }

        Ok(signed)
    }

    /// Whether `signed` weight is enough against `active_total`.
    ///
    /// Strictly more than two thirds, by cross-multiplication. See
    /// [`Weight::exceeds_two_thirds_of`].
    #[must_use]
    pub fn finalises(signed: Weight, active_total: Weight) -> bool {
        signed.exceeds_two_thirds_of(active_total)
    }

    /// How many votes it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.votes.len()
    }

    /// Whether it holds no votes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }
}

impl Encode for Certificate {
    fn encode(&self, out: &mut Encoder) {
        self.block.encode(out);
        out.write_seq(&self.votes);
    }
}

impl Decode for Certificate {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self { block: BlockId::decode(input)?, votes: input.read_seq::<Vote>()? })
    }
}

#[cfg(test)]
mod tests {
    use super::{Certificate, CertificateError, Vote};
    use crate::committee::Committee;
    use crate::seed::{mix_reveals, EpochSeed};
    use crate::validator::{ValidatorRecord, ValidatorSet};
    use crate::weight::Weight;
    use std::collections::BTreeMap;
    use vanargand_crypto::algorithm::AlgorithmId;
    use vanargand_crypto::hash::Hash;
    use vanargand_crypto::sign::{self, Keypair};
    use vanargand_types::amount::Ratio;
    use vanargand_types::block::{BlockHeader, FinalityRung, HEADER_VERSION};
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::id::{AccountId, BlockId, ChainId};
    use vanargand_types::Amount;

    fn keypair(index: u32) -> Keypair {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        sign::keypair_from_seed(AlgorithmId::InsecureTest, &Hash::from_bytes(bytes))
            .expect("the test backend is compiled in")
    }

    /// Account identifiers carry their fixture index in their first four bytes,
    /// so that a committee member can be mapped back to the keypair that signs
    /// for it without maintaining a side table.
    fn account(index: u32) -> AccountId {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        bytes[31] = 0xaa;
        AccountId::from_hash(Hash::from_bytes(bytes))
    }

    /// The inverse of [`account`].
    fn index_of(account: &AccountId) -> usize {
        let head: [u8; 4] =
            account.as_bytes().get(..4).and_then(|slice| slice.try_into().ok()).unwrap_or([0; 4]);
        usize::try_from(u32::from_be_bytes(head)).unwrap_or(0)
    }

    /// `count` validators, each bonding the same amount.
    fn fixture(count: u32) -> (ValidatorSet, Vec<Keypair>) {
        let mut set = ValidatorSet::new();
        let mut keys = Vec::new();
        for index in 0..count {
            let pair = keypair(index);
            set.insert(ValidatorRecord::new(
                account(index),
                pair.verifying.clone(),
                Amount::from_ulf(1_000),
                Hash::from_bytes([0xcc; 32]),
            ));
            keys.push(pair);
        }
        (set, keys)
    }

    fn seed() -> EpochSeed {
        let mut reveals = BTreeMap::new();
        reveals.insert(account(0), Hash::from_bytes([1; 32]));
        EpochSeed::from_delay_function(mix_reveals(1, &reveals))
    }

    fn header() -> BlockHeader {
        BlockHeader {
            version: HEADER_VERSION,
            chain: ChainId::from_hash(Hash::from_bytes([0x11; 32])),
            height: 10,
            parent: BlockId::from_hash(Hash::from_bytes([0x22; 32])),
            rung: FinalityRung::Chain,
            finalized_height: 10,
            state_root: Hash::from_bytes([0x33; 32]),
            tx_root: Hash::from_bytes([0x44; 32]),
            proposer: account(0),
            randomness_reveal: Hash::from_bytes([0x66; 32]),
            archive_commitment: Hash::from_bytes([0x77; 32]),
            emitted_supply: Amount::from_ulf(1),
            security_budget: Amount::from_ulf(1),
            fee_emission_ratio: Ratio::new(1, 1),
        }
    }

    /// Builds a certificate signed by the first `signers` members on duty.
    fn certificate_for(
        header: &BlockHeader,
        committee: &Committee,
        block_in_epoch: u64,
        keys: &[Keypair],
        signers: usize,
    ) -> Certificate {
        let digest = header.signing_digest();
        let mut votes: Vec<Vote> = committee
            .active_at(block_in_epoch)
            .into_iter()
            .take(signers)
            .filter_map(|member| {
                let pair = keys.get(index_of(&member.account))?;
                Some(Vote {
                    member: member.account,
                    signature: sign::sign(&pair.signing, digest.as_bytes())
                        .expect("the test backend signs"),
                })
            })
            .collect();
        votes.sort_by(|left, right| left.member.cmp(&right.member));
        Certificate { block: header.id(), votes }
    }

    #[test]
    fn a_full_certificate_verifies_and_finalises() {
        let (set, keys) = fixture(100);
        let committee = Committee::draw(&set, &seed());
        let head = header();
        let certificate = certificate_for(&head, &committee, 0, &keys, 64);

        let signed = certificate
            .verify(&head, &committee, 0, &set, true)
            .expect("a full certificate must verify");
        assert_eq!(signed, committee.active_weight_at(0));
        assert!(Certificate::finalises(signed, committee.active_weight_at(0)));
    }

    #[test]
    fn exactly_two_thirds_does_not_finalise() {
        // The strict bound, at the certificate level. Sixty-four equal members:
        // forty-two of them is under two thirds, forty-three is over, and the
        // exact boundary only exists because the weights divide evenly — which
        // is precisely when a hand-written comparison gets it wrong.
        let total = Weight::from_raw(64 * 1_000);
        assert!(!Certificate::finalises(Weight::from_raw(42 * 1_000), total));
        assert!(Certificate::finalises(Weight::from_raw(43 * 1_000), total));

        let divisible = Weight::from_raw(3_000);
        assert!(!Certificate::finalises(Weight::from_raw(2_000), divisible), "exactly 2/3 passed");
        assert!(Certificate::finalises(Weight::from_raw(2_001), divisible));
    }

    #[test]
    fn a_partial_certificate_verifies_but_does_not_finalise() {
        let (set, keys) = fixture(100);
        let committee = Committee::draw(&set, &seed());
        let head = header();
        let certificate = certificate_for(&head, &committee, 0, &keys, 30);

        let signed = certificate.verify(&head, &committee, 0, &set, true).expect("valid votes");
        assert!(!Certificate::finalises(signed, committee.active_weight_at(0)));
    }

    #[test]
    fn a_certificate_for_another_block_is_rejected() {
        let (set, keys) = fixture(100);
        let committee = Committee::draw(&set, &seed());
        let head = header();
        let certificate = certificate_for(&head, &committee, 0, &keys, 64);

        let mut elsewhere = head.clone();
        elsewhere.state_root = Hash::from_bytes([0xee; 32]);
        assert!(matches!(
            certificate.verify(&elsewhere, &committee, 0, &set, true),
            Err(CertificateError::WrongBlock { .. })
        ));
    }

    #[test]
    fn a_duplicated_vote_is_rejected() {
        // Counting a member twice would let a third of the committee
        // manufacture finality.
        let (set, keys) = fixture(100);
        let committee = Committee::draw(&set, &seed());
        let head = header();
        let mut certificate = certificate_for(&head, &committee, 0, &keys, 40);
        let Some(first) = certificate.votes.first().cloned() else { return };
        certificate.votes.insert(1, first);

        assert!(matches!(
            certificate.verify(&head, &committee, 0, &set, true),
            Err(CertificateError::Unordered { .. })
        ));
    }

    #[test]
    fn unordered_votes_are_rejected() {
        let (set, keys) = fixture(100);
        let committee = Committee::draw(&set, &seed());
        let head = header();
        let mut certificate = certificate_for(&head, &committee, 0, &keys, 10);
        certificate.votes.reverse();
        assert!(matches!(
            certificate.verify(&head, &committee, 0, &set, true),
            Err(CertificateError::Unordered { .. })
        ));
    }

    #[test]
    fn a_vote_from_someone_off_duty_is_rejected() {
        let (set, keys) = fixture(200);
        let committee = Committee::draw(&set, &seed());
        let head = header();

        // Find a committee member who is not on duty at block 0.
        let on_duty: Vec<AccountId> =
            committee.active_at(0).into_iter().map(|member| member.account).collect();
        let Some(off_duty) =
            committee.members().iter().find(|member| !on_duty.contains(&member.account))
        else {
            return;
        };

        let Some(pair) = keys.get(index_of(&off_duty.account)) else { return };

        let certificate = Certificate {
            block: head.id(),
            votes: vec![Vote {
                member: off_duty.account,
                signature: sign::sign(&pair.signing, head.signing_digest().as_bytes())
                    .expect("the test backend signs"),
            }],
        };

        assert_eq!(
            certificate.verify(&head, &committee, 0, &set, true),
            Err(CertificateError::NotOnDuty(off_duty.account))
        );
    }

    #[test]
    fn a_bad_signature_is_rejected() {
        let (set, keys) = fixture(100);
        let committee = Committee::draw(&set, &seed());
        let head = header();
        let mut certificate = certificate_for(&head, &committee, 0, &keys, 40);

        // Re-sign the first vote over a different message.
        let Some(vote) = certificate.votes.first_mut() else { return };
        let wrong = keys.first().map(|pair| {
            sign::sign(&pair.signing, b"not the block digest").expect("the test backend signs")
        });
        let Some(wrong) = wrong else { return };
        vote.signature = wrong;

        assert!(matches!(
            certificate.verify(&head, &committee, 0, &set, true),
            Err(CertificateError::BadSignature(_))
        ));
    }

    #[test]
    fn the_production_path_refuses_a_test_algorithm() {
        // The whole certificate is the object where forgetting this check would
        // let anyone finalise anything.
        let (set, keys) = fixture(100);
        let committee = Committee::draw(&set, &seed());
        let head = header();
        let certificate = certificate_for(&head, &committee, 0, &keys, 64);

        assert!(matches!(
            certificate.verify(&head, &committee, 0, &set, false),
            Err(CertificateError::TestAlgorithmOnLiveChain(_))
        ));
    }

    #[test]
    fn an_unknown_validator_is_rejected() {
        let (set, keys) = fixture(100);
        let committee = Committee::draw(&set, &seed());
        let head = header();
        let certificate = certificate_for(&head, &committee, 0, &keys, 20);

        // Remove one voter from the validator set: there is now no key to
        // check the vote against.
        let Some(victim) = certificate.votes.first().map(|vote| vote.member) else { return };
        let mut thinned = set.clone();
        thinned.remove(&victim);

        assert_eq!(
            certificate.verify(&head, &committee, 0, &thinned, true),
            Err(CertificateError::UnknownValidator(victim))
        );
    }

    #[test]
    fn an_empty_certificate_verifies_to_nothing() {
        let (set, _) = fixture(100);
        let committee = Committee::draw(&set, &seed());
        let head = header();
        let certificate = Certificate { block: head.id(), votes: Vec::new() };

        assert_eq!(certificate.verify(&head, &committee, 0, &set, true), Ok(Weight::ZERO));
        assert!(!Certificate::finalises(Weight::ZERO, committee.active_weight_at(0)));
        assert!(certificate.is_empty());
    }

    #[test]
    fn certificates_round_trip() {
        let (set, keys) = fixture(100);
        let committee = Committee::draw(&set, &seed());
        let head = header();
        let certificate = certificate_for(&head, &committee, 0, &keys, 8);
        let bytes = certificate.to_canonical_bytes();
        assert_eq!(Certificate::from_canonical_bytes(&bytes), Ok(certificate));
    }
}
