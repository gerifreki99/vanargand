// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validating a block and applying it.
//!
//! This is where the pieces meet: the header rules from `vanargand-types`, the
//! committee and certificate from `vanargand-consensus`, and the ledger from
//! `vanargand-state`. Nothing here invents a rule — it puts the existing ones
//! in the one order that makes them sound.
//!
//! # The order is the design
//!
//! 1. the header's own consistency, which needs no chain;
//! 2. its place in the chain: height, parent, and a finalised tip that never
//!    goes backwards;
//! 3. the proposer's authority — on duty, and its signature;
//! 4. the randomness reveal, which advances the proposer's commitment chain;
//! 5. the body matches `tx_root`;
//! 6. the partition grammar, if this block claims rung 1;
//! 7. **housekeeping**: settle elapsed channels, prune expired commitments;
//! 8. the transactions, each signature checked before its effect;
//! 9. `state_root` matches what the ledger now holds;
//! 10. the certificate, if one came with it.
//!
//! Housekeeping *before* transactions, because a channel that settled at this
//! height should be able to fund a payment made at this height — and because
//! two nodes doing it in different orders compute different state roots.
//!
//! `state_root` **after** everything, because it is the commitment that makes
//! all of it checkable: a proposer that got any of the preceding steps wrong
//! produces a root nobody else can reproduce.
//!
//! # All or nothing
//!
//! A block containing one invalid transaction is invalid **entirely**. Dropping
//! the offender and keeping the rest would make two honest nodes disagree about
//! what the block was, which is the failure the whole exercise exists to
//! prevent. Validation therefore works on a copy of the ledger and commits only
//! on success — the same discipline `Ledger::apply` uses per transaction, one
//! level up.

use core::fmt;

use vanargand_consensus::certificate::CertificateError;
use vanargand_consensus::committee::Committee;
use vanargand_consensus::emission::{self, EmissionError};
use vanargand_consensus::validator::ValidatorSet;
use vanargand_consensus::weight::Weight;
use vanargand_crypto::chain::ChainCursor;
use vanargand_crypto::hash::{domain, Hash};
use vanargand_types::block::{params::EPOCH_BLOCKS, BlockHeader, FinalityRung, HeaderError};
use vanargand_types::id::{AccountId, BlockId, ChainId};
use vanargand_types::tx::{check_provisional_grammar, TxError};
use vanargand_state::ledger::{BlockContext, Ledger, StateError};
use vanargand_state::purse_book::Payout;

use crate::block::Block;

/// How far a proposer's randomness reveal may skip.
///
/// One epoch — 720, the value of `EPOCH_BLOCKS`, written as a literal because
/// that constant is a `u64` and a narrowing cast is exactly the kind of thing
/// this workspace denies. The test below keeps the two in step.
///
/// A proposer that missed every turn for an hour is still recognised; one that
/// presents a value further along is not, and that bound is what stops a peer
/// from making a node hash indefinitely (A6). It answers, for the consensus
/// chain specifically, the open point named in `spec/draft/02-hashing.md` §4.1.
pub const MAX_REVEAL_CATCHUP: u32 = 720;

/// What a chain is, for the purpose of validating a block on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainParameters {
    /// Which chain.
    pub chain: ChainId,
    /// Whether the insecure test algorithms are acceptable.
    ///
    /// `false` on any chain holding real value. It is a field rather than a
    /// compile-time choice because the test network is a permanent organ of the
    /// protocol, not a scaffold — `docs/02-scope.pdf` is explicit about that —
    /// so both settings have to exist in the same binary.
    pub allow_test_algorithms: bool,
}

/// What applying a block did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The block.
    pub block: BlockId,
    /// The rung it claimed.
    pub claimed_rung: FinalityRung,
    /// The rung it actually reached, once the certificate was weighed.
    pub reached_rung: FinalityRung,
    /// The committee weight that signed it.
    pub signed_weight: Weight,
    /// Channels that settled during this block's housekeeping.
    pub settlements: Vec<Payout>,
    /// Name commitments that expired and were dropped.
    pub pruned_commitments: usize,
}

/// Why a block was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockError {
    /// The header failed its own consistency rules.
    Header(HeaderError),
    /// The block is for another chain.
    WrongChain,
    /// The height does not follow the parent's.
    NotTheNextHeight {
        /// The parent's height.
        parent: u64,
        /// This block's claimed height.
        claimed: u64,
    },
    /// The parent link does not name the parent supplied.
    WrongParent {
        /// What the header names.
        claimed: BlockId,
        /// What the parent actually is.
        actual: BlockId,
    },
    /// The finalised tip went backwards.
    ///
    /// It may stand still for an arbitrarily long partition, and it may leap
    /// forward when finality returns. It may never retreat: every contestation
    /// clock in the protocol is measured against it, and a tip that can go back
    /// is a window that can reopen.
    FinalizedWentBackwards {
        /// The parent's finalised height.
        parent: u64,
        /// This block's.
        claimed: u64,
    },
    /// The proposer is not on duty at this block.
    ProposerNotOnDuty(AccountId),
    /// The proposer is not a registered validator.
    UnknownProposer(AccountId),
    /// The proposer's signature did not verify.
    BadProposerSignature,
    /// A test algorithm was used on a chain that forbids them.
    TestAlgorithmOnLiveChain,
    /// The randomness reveal does not advance the proposer's commitment chain.
    ///
    /// Either a forgery, or a value further ahead than [`MAX_REVEAL_CATCHUP`]
    /// allows. The two are one error on purpose: distinguishing them would tell
    /// a prober how far along somebody else's chain it had guessed.
    BadRandomnessReveal,
    /// The body does not match the header's transaction root.
    TxRootMismatch {
        /// What the header commits to.
        claimed: Hash,
        /// What the body computes.
        computed: Hash,
    },
    /// The body carries a transaction the partition grammar forbids.
    ForbiddenInProvisional(TxError),
    /// A transaction's signing device is not registered to its account.
    UnknownDevice {
        /// Which transaction, by position.
        index: usize,
    },
    /// A transaction's signature did not verify.
    BadTransactionSignature {
        /// Which transaction, by position.
        index: usize,
    },
    /// A transaction could not be applied.
    Transaction {
        /// Which transaction, by position.
        index: usize,
        /// Why.
        cause: StateError,
    },
    /// The block's own housekeeping failed — settling channels, pruning
    /// commitments — before any transaction was reached.
    Housekeeping(StateError),
    /// The resulting state does not match the header's commitment.
    StateRootMismatch {
        /// What the header commits to.
        claimed: Hash,
        /// What the ledger computes.
        computed: Hash,
    },
    /// The emission counter is inconsistent with the formula or with its
    /// parent.
    ///
    /// The border check of `docs/05-emission.pdf` §5, reduced to a comparison a
    /// phone can make: one number in the header against a pure function of the
    /// height. A chain that fails it is demoted out of the VAN zone by
    /// arithmetic rather than by a vote.
    Emission(EmissionError),
    /// The published fee/emission ratio is not what the ledger computes.
    ///
    /// Compared as the exact pair of integers, not as a value: `2/4` and `1/2`
    /// are the same number and different headers, and a field with two valid
    /// spellings is a field two honest nodes can hash differently.
    FeeRatioMismatch {
        /// What the header claims.
        claimed: vanargand_types::amount::Ratio,
        /// What the ledger computes.
        computed: vanargand_types::amount::Ratio,
    },
    /// The published security budget is not a third of the bonded stake.
    ///
    /// Checked against the validator set, which is **not** currently derived
    /// from the ledger — bonds live in both, and nothing reconciles them. That
    /// is a real gap, recorded in this crate's documentation rather than papered
    /// over, and it is why this error can in principle fire on a block that is
    /// perfectly valid. **(open)**
    SecurityBudgetMismatch,
    /// The certificate did not verify.
    Certificate(CertificateError),
    /// A provisional block carried a certificate.
    ///
    /// A certificate is a claim of rung-2 finality. A block that stamped itself
    /// provisional and then carried one is claiming both rungs at once, and the
    /// grammar it was validated under was the wrong one.
    CertifiedProvisionalBlock,
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(error) => write!(f, "{error}"),
            Self::WrongChain => write!(f, "the block is for another chain"),
            Self::NotTheNextHeight { parent, claimed } => {
                write!(f, "parent is at height {parent}, block claims {claimed}")
            }
            Self::WrongParent { claimed, actual } => {
                write!(f, "block names parent {claimed}, parent is {actual}")
            }
            Self::FinalizedWentBackwards { parent, claimed } => {
                write!(f, "finalised tip went from {parent} back to {claimed}")
            }
            Self::ProposerNotOnDuty(account) => write!(f, "{account} is not on duty"),
            Self::UnknownProposer(account) => write!(f, "{account} is not a validator"),
            Self::BadProposerSignature => write!(f, "the proposer's signature did not verify"),
            Self::TestAlgorithmOnLiveChain => {
                write!(f, "a test algorithm was used on a production chain")
            }
            Self::BadRandomnessReveal => write!(f, "the randomness reveal does not verify"),
            Self::TxRootMismatch { claimed, computed } => {
                write!(f, "header commits to tx_root {claimed}, body computes {computed}")
            }
            Self::ForbiddenInProvisional(error) => write!(f, "{error}"),
            Self::UnknownDevice { index } => {
                write!(f, "transaction {index} names a device its account does not hold")
            }
            Self::BadTransactionSignature { index } => {
                write!(f, "transaction {index} has an invalid signature")
            }
            Self::Transaction { index, cause } => write!(f, "transaction {index}: {cause}"),
            Self::Housekeeping(cause) => write!(f, "block housekeeping: {cause}"),
            Self::StateRootMismatch { claimed, computed } => {
                write!(f, "header commits to state_root {claimed}, ledger computes {computed}")
            }
            Self::Emission(error) => write!(f, "{error}"),
            Self::FeeRatioMismatch { claimed, computed } => write!(
                f,
                "header publishes fees/emission {}/{}, ledger computes {}/{}",
                claimed.numerator, claimed.denominator, computed.numerator, computed.denominator
            ),
            Self::SecurityBudgetMismatch => {
                write!(f, "the published security budget is not a third of the bonded stake")
            }
            Self::Certificate(error) => write!(f, "{error}"),
            Self::CertifiedProvisionalBlock => {
                write!(f, "a provisional block carried a finality certificate")
            }
        }
    }
}

impl std::error::Error for BlockError {}

impl From<HeaderError> for BlockError {
    fn from(error: HeaderError) -> Self {
        Self::Header(error)
    }
}

impl From<CertificateError> for BlockError {
    fn from(error: CertificateError) -> Self {
        Self::Certificate(error)
    }
}

/// Validates a block and applies it, or changes nothing.
///
/// `validators` is taken mutably because applying a block really does advance
/// validator state: the proposer's commitment chain moves on by one reveal. It
/// is updated only on success, like the ledger.
pub fn validate_and_apply(
    block: &Block,
    parent: &BlockHeader,
    ledger: &mut Ledger,
    validators: &mut ValidatorSet,
    committee: &Committee,
    params: &ChainParameters,
) -> Result<Applied, BlockError> {
    let mut working_ledger = ledger.clone();
    let mut working_validators = validators.clone();

    let applied =
        run(block, parent, &mut working_ledger, &mut working_validators, committee, params)?;

    *ledger = working_ledger;
    *validators = working_validators;
    Ok(applied)
}

fn run(
    block: &Block,
    parent: &BlockHeader,
    ledger: &mut Ledger,
    validators: &mut ValidatorSet,
    committee: &Committee,
    params: &ChainParameters,
) -> Result<Applied, BlockError> {
    let header = block.header();

    // 1. The header on its own.
    header.check_self_consistent()?;
    if header.chain != params.chain {
        return Err(BlockError::WrongChain);
    }

    // 2. Its place in the chain.
    if header.height != parent.height.saturating_add(1) {
        return Err(BlockError::NotTheNextHeight {
            parent: parent.height,
            claimed: header.height,
        });
    }
    let parent_id = parent.id();
    if header.parent != parent_id {
        return Err(BlockError::WrongParent { claimed: header.parent, actual: parent_id });
    }
    if header.finalized_height < parent.finalized_height {
        return Err(BlockError::FinalizedWentBackwards {
            parent: parent.finalized_height,
            claimed: header.finalized_height,
        });
    }

    // The emission counter, against its parent and against the formula. Cheap,
    // and the one check a foreign chain can perform on this one with nothing
    // but a header.
    emission::check_counter(
        parent.emitted_supply,
        header.emitted_supply,
        emission::epoch_of_height(header.height),
    )
    .map_err(BlockError::Emission)?;

    // 3. The proposer's authority.
    let block_in_epoch = header.height % EPOCH_BLOCKS;
    if !committee.is_active_at(&header.proposer, block_in_epoch) {
        return Err(BlockError::ProposerNotOnDuty(header.proposer));
    }
    let record = validators
        .get(&header.proposer)
        .ok_or(BlockError::UnknownProposer(header.proposer))?;
    if !params.allow_test_algorithms && !record.key.algorithm().valid_on_live_chain() {
        return Err(BlockError::TestAlgorithmOnLiveChain);
    }
    block
        .header
        .verify_allowing_test_algorithms(&record.key)
        .map_err(|_| BlockError::BadProposerSignature)?;

    // 4. The randomness reveal advances the proposer's sealed chain.
    //
    // Revealing and proposing are one act, which is why silence costs a missed
    // turn rather than a seizure (R2). A forged reveal is simply not a block.
    let mut cursor =
        ChainCursor::new(domain::COMMITMENT_CHAIN, record.last_reveal, MAX_REVEAL_CATCHUP);
    cursor
        .advance(&header.randomness_reveal)
        .map_err(|_| BlockError::BadRandomnessReveal)?;

    // 5. The body matches what the header committed to.
    let computed_root = block.computed_tx_root();
    if header.tx_root != computed_root {
        return Err(BlockError::TxRootMismatch {
            claimed: header.tx_root,
            computed: computed_root,
        });
    }

    // 6. The partition grammar (C9).
    if header.rung == FinalityRung::Provisional {
        if block.certificate.is_some() {
            return Err(BlockError::CertifiedProvisionalBlock);
        }
        check_provisional_grammar(block.transactions.iter().map(|tx| &tx.body))
            .map_err(BlockError::ForbiddenInProvisional)?;
    }

    // 7. Housekeeping, before the transactions.
    let settlements = ledger
        .settle_elapsed_purses(header.finalized_height)
        .map_err(BlockError::Housekeeping)?;
    let pruned_commitments = ledger.prune_expired_commitments(header.finalized_height);

    // 8. The transactions.
    let context = BlockContext {
        chain: header.chain,
        height: header.height,
        finalized_height: header.finalized_height,
        rung: header.rung,
        proposer: header.proposer,
    };
    for (index, transaction) in block.transactions.iter().enumerate() {
        let account = ledger
            .account(&transaction.body.account)
            .ok_or(BlockError::Transaction {
                index,
                cause: StateError::NoSuchAccount(transaction.body.account),
            })?;
        // Cloned rather than borrowed across the `apply` below. The borrow
        // checker would probably allow the reference — the last use is the
        // verification — but a consensus loop is not the place to rely on
        // "probably", and a key is a few kilobytes once a year.
        let key = account
            .devices
            .get(&transaction.body.device)
            .ok_or(BlockError::UnknownDevice { index })?
            .key
            .clone();

        if params.allow_test_algorithms {
            transaction
                .verify_allowing_test_algorithms(&key)
                .map_err(|_| BlockError::BadTransactionSignature { index })?;
        } else {
            transaction
                .verify(&key)
                .map_err(|_| BlockError::BadTransactionSignature { index })?;
        }

        ledger
            .apply(&context, &transaction.body)
            .map_err(|cause| BlockError::Transaction { index, cause })?;
    }

    // 9. The state commitment, which is what makes all of the above checkable.
    let computed_state = ledger.state_root();
    if header.state_root != computed_state {
        return Err(BlockError::StateRootMismatch {
            claimed: header.state_root,
            computed: computed_state,
        });
    }

    // The two health metrics `docs/05-emission.pdf` §4 requires every header to
    // publish. The emission counter was checked earlier, against the formula;
    // these are checked against what the ledger actually holds.
    let computed_ratio = ledger.fee_emission_ratio(header.emitted_supply);
    if header.fee_emission_ratio != computed_ratio {
        return Err(BlockError::FeeRatioMismatch {
            claimed: header.fee_emission_ratio,
            computed: computed_ratio,
        });
    }
    if validators.security_budget() != Some(header.security_budget) {
        return Err(BlockError::SecurityBudgetMismatch);
    }

    // 10. The certificate, and therefore the rung actually reached.
    let mut signed_weight = Weight::ZERO;
    let mut reached_rung = FinalityRung::Provisional;
    if let Some(certificate) = &block.certificate {
        signed_weight = certificate.verify(
            header,
            committee,
            block_in_epoch,
            validators,
            params.allow_test_algorithms,
        )?;
        let active = committee.active_weight_at(block_in_epoch);
        if vanargand_consensus::certificate::Certificate::finalises(signed_weight, active) {
            reached_rung = FinalityRung::Chain;
        }
    }

    // The reveal is spent: record it, so the next block from this proposer has
    // to move further along the chain.
    if let Some(record) = validators.get_mut(&header.proposer) {
        record.last_reveal = header.randomness_reveal;
    }

    Ok(Applied {
        block: header.id(),
        claimed_rung: header.rung,
        reached_rung,
        signed_weight,
        settlements,
        pruned_commitments,
    })
}
