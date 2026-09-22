// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Building a block.
//!
//! # A producer drops; a validator rejects
//!
//! The two sides run the same rules with opposite dispositions, and that is the
//! whole difference between them.
//!
//! A **validator** is handed a set and must say yes or no to it as a whole. One
//! bad transaction invalidates the block, because dropping the offender and
//! keeping the rest would make two honest nodes disagree about what the block
//! was.
//!
//! A **producer** is choosing the set. A candidate that does not apply is
//! simply not chosen — there is nothing to disagree about yet, and refusing to
//! build anything because one transaction in the mempool was stale would be a
//! liveness bug rather than a safety property.
//!
//! So [`build`] returns the block it managed to build *and* the candidates it
//! declined, with the reason. A producer that silently swallowed rejections
//! would be a producer whose operator cannot tell a stale mempool from a broken
//! node.
//!
//! # Order is the producer's only real freedom
//!
//! Everything else is determined: the roots follow from the set, the signature
//! follows from the header. Which transactions, and in what order, is where a
//! proposer can extract value — A5 censorship at one end, F4 front-running at
//! the other. This module takes the candidates in the order it is given them
//! and does not reorder, which is the honest default and is **not** a defence:
//! the caller chose the order.
//!
//! Inclusion lists, which A5 names as the eventual parade against censorship,
//! are not implemented. **(open)**

use core::fmt;

use vanargand_consensus::committee::Committee;
use vanargand_consensus::emission;
use vanargand_consensus::validator::ValidatorSet;
use vanargand_crypto::hash::Hash;
use vanargand_crypto::sign::SigningKey;
use vanargand_types::block::{
    params::EPOCH_BLOCKS, BlockHeader, FinalityRung, SignedHeader, HEADER_VERSION,
};
use vanargand_types::id::AccountId;
use vanargand_types::tx::Transaction;
use vanargand_types::Amount;
use vanargand_state::ledger::{BlockContext, Ledger, StateError};

use crate::block::Block;
use crate::validate::ChainParameters;

/// What the producer needs that the candidates do not supply.
#[derive(Debug, Clone)]
pub struct ProposalInputs<'a> {
    /// The block being built on.
    pub parent: &'a BlockHeader,
    /// Who is proposing.
    pub proposer: AccountId,
    /// The next link of the proposer's sealed commitment chain.
    ///
    /// Revealing and proposing are one act (A4). A producer that has run out of
    /// chain cannot propose, which is by design: the chain is sealed at bond
    /// time and its length is how many turns were paid for.
    pub randomness_reveal: Hash,
    /// Which rung this block claims.
    pub rung: FinalityRung,
    /// The most recent rung-2 height this block builds on.
    pub finalized_height: u64,
    /// Commitment to the slice of history archived at this height.
    pub archive_commitment: Hash,
    /// The chain's cumulative emission after this block.
    ///
    /// Supplied rather than computed, because *distributing* emission is not
    /// implemented — see `spec/draft/09-emission.md` §7. It is checked against
    /// the formula before the block is built, so a producer cannot publish a
    /// counter its own validator would reject.
    pub emitted_supply: Amount,
}

/// A candidate that did not make it into the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declined {
    /// Its position in the candidate list.
    pub index: usize,
    /// Why.
    pub reason: DeclineReason,
}

/// Why a candidate was left out.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeclineReason {
    /// Its account is not on this chain.
    NoSuchAccount,
    /// Its signing device is not registered to its account.
    UnknownDevice,
    /// Its signature did not verify.
    BadSignature,
    /// This kind is grammatically illegal in a provisional block (C9).
    ForbiddenInProvisional {
        /// Which kind.
        kind: &'static str,
    },
    /// The ledger refused it.
    Rejected(StateError),
}

impl fmt::Display for DeclineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchAccount => write!(f, "no such account"),
            Self::UnknownDevice => write!(f, "the account holds no such device"),
            Self::BadSignature => write!(f, "invalid signature"),
            Self::ForbiddenInProvisional { kind } => {
                write!(f, "{kind} is not permitted in a provisional block")
            }
            Self::Rejected(error) => write!(f, "{error}"),
        }
    }
}

/// Why a block could not be built at all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProposeError {
    /// The proposer is not on duty at this height.
    NotOnDuty(AccountId),
    /// The proposer is not a registered validator.
    UnknownProposer(AccountId),
    /// The claimed finalised height is below the parent's.
    FinalizedWentBackwards {
        /// The parent's.
        parent: u64,
        /// The one asked for.
        claimed: u64,
    },
    /// A header cannot claim this rung.
    UnclaimableRung(FinalityRung),
    /// The emission counter would fail the border check.
    ///
    /// Caught here so that a producer never publishes a block its own validator
    /// would reject — which is the difference between an operator error and a
    /// chain being demoted out of the VAN zone.
    Emission(emission::EmissionError),
    /// The block's own housekeeping failed.
    Housekeeping(StateError),
    /// Signing failed.
    Signing,
}

impl fmt::Display for ProposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOnDuty(account) => write!(f, "{account} is not on duty at this height"),
            Self::UnknownProposer(account) => write!(f, "{account} is not a validator"),
            Self::FinalizedWentBackwards { parent, claimed } => {
                write!(f, "finalised tip would go from {parent} back to {claimed}")
            }
            Self::UnclaimableRung(rung) => write!(f, "a header cannot claim {rung} finality"),
            Self::Emission(error) => write!(f, "{error}"),
            Self::Housekeeping(error) => write!(f, "block housekeeping: {error}"),
            Self::Signing => write!(f, "the proposer could not sign its own header"),
        }
    }
}

impl std::error::Error for ProposeError {}

/// A built block and the candidates that did not make it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The block.
    pub block: Block,
    /// Candidates left out, in the order they were offered.
    pub declined: Vec<Declined>,
}

/// Builds a block from a list of candidate transactions.
///
/// `ledger` is **not** modified: the block is built against a working copy, and
/// applying it is the validator's job — including the producer's own, which is
/// what makes a producer's bug a rejected block rather than a divergent chain.
pub fn build(
    inputs: &ProposalInputs<'_>,
    candidates: Vec<Transaction>,
    ledger: &Ledger,
    validators: &ValidatorSet,
    committee: &Committee,
    signing: &SigningKey,
    params: &ChainParameters,
) -> Result<Proposal, ProposeError> {
    let parent = inputs.parent;
    let height = parent.height.saturating_add(1);
    let block_in_epoch = height % EPOCH_BLOCKS;

    if !inputs.rung.claimable_by_a_header() {
        return Err(ProposeError::UnclaimableRung(inputs.rung));
    }
    if !committee.is_active_at(&inputs.proposer, block_in_epoch) {
        return Err(ProposeError::NotOnDuty(inputs.proposer));
    }
    if validators.get(&inputs.proposer).is_none() {
        return Err(ProposeError::UnknownProposer(inputs.proposer));
    }
    if inputs.finalized_height < parent.finalized_height {
        return Err(ProposeError::FinalizedWentBackwards {
            parent: parent.finalized_height,
            claimed: inputs.finalized_height,
        });
    }
    // A block claiming chain finality *is* the finalised tip it refers to, so
    // the caller's `finalized_height` is only honoured for a provisional block.
    let finalized_height =
        if inputs.rung == FinalityRung::Chain { height } else { inputs.finalized_height };

    emission::check_counter(
        parent.emitted_supply,
        inputs.emitted_supply,
        emission::epoch_of_height(height),
    )
    .map_err(ProposeError::Emission)?;

    // Build against a copy. Housekeeping first, exactly as validation does it —
    // a channel that settled at this height can fund a payment made at it.
    let mut working = ledger.clone();
    working
        .settle_elapsed_purses(finalized_height)
        .map_err(ProposeError::Housekeeping)?;
    working.prune_expired_commitments(finalized_height);

    let context = BlockContext {
        chain: params.chain,
        height,
        finalized_height,
        rung: inputs.rung,
        proposer: inputs.proposer,
    };

    let mut included: Vec<Transaction> = Vec::with_capacity(candidates.len());
    let mut declined: Vec<Declined> = Vec::new();

    for (index, transaction) in candidates.into_iter().enumerate() {
        if let Some(reason) = screen(&transaction, &working, &context, params) {
            declined.push(Declined { index, reason });
            continue;
        }
        match working.apply(&context, &transaction.body) {
            Ok(_) => included.push(transaction),
            Err(error) => {
                declined.push(Declined { index, reason: DeclineReason::Rejected(error) });
            }
        }
    }

    let leaves: Vec<Hash> =
        included.iter().map(|transaction| *transaction.id().as_hash()).collect();

    let header = BlockHeader {
        version: HEADER_VERSION,
        chain: params.chain,
        height,
        parent: parent.id(),
        rung: inputs.rung,
        finalized_height,
        state_root: working.state_root(),
        tx_root: vanargand_types::merkle::list_root(&leaves),
        proposer: inputs.proposer,
        randomness_reveal: inputs.randomness_reveal,
        archive_commitment: inputs.archive_commitment,
        emitted_supply: inputs.emitted_supply,
        security_budget: validators.security_budget().unwrap_or(Amount::ZERO),
        fee_emission_ratio: working.fee_emission_ratio(inputs.emitted_supply),
    };

    let signature = vanargand_crypto::sign::sign(signing, header.signing_digest().as_bytes())
        .map_err(|_| ProposeError::Signing)?;

    let block = Block {
        header: SignedHeader { header, signature },
        transactions: included,
        certificate: None,
    };
    Ok(Proposal { block, declined })
}

/// Checks the things that do not need the ledger to be mutated.
fn screen(
    transaction: &Transaction,
    ledger: &Ledger,
    context: &BlockContext,
    params: &ChainParameters,
) -> Option<DeclineReason> {
    if context.rung == FinalityRung::Provisional
        && !transaction.body.kind.allowed_in_provisional()
    {
        return Some(DeclineReason::ForbiddenInProvisional {
            kind: transaction.body.kind.name(),
        });
    }

    // `let … else`, not `?`: this function returns `Option<DeclineReason>`,
    // where `None` means "nothing wrong with it". A `?` here would silently
    // *approve* a transaction from an account that does not exist.
    let Some(account) = ledger.account(&transaction.body.account) else {
        return Some(DeclineReason::NoSuchAccount);
    };
    let Some(device) = account.devices.get(&transaction.body.device) else {
        return Some(DeclineReason::UnknownDevice);
    };

    let verified = if params.allow_test_algorithms {
        transaction.verify_allowing_test_algorithms(&device.key)
    } else {
        transaction.verify(&device.key)
    };
    if verified.is_err() {
        return Some(DeclineReason::BadSignature);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{DeclineReason, ProposeError};

    #[test]
    fn decline_reasons_read_like_sentences() {
        assert_eq!(DeclineReason::NoSuchAccount.to_string(), "no such account");
        assert_eq!(
            DeclineReason::ForbiddenInProvisional { kind: "unbond" }.to_string(),
            "unbond is not permitted in a provisional block"
        );
    }

    #[test]
    fn propose_errors_name_what_went_wrong() {
        assert_eq!(
            ProposeError::FinalizedWentBackwards { parent: 5, claimed: 4 }.to_string(),
            "finalised tip would go from 5 back to 4"
        );
    }
}
