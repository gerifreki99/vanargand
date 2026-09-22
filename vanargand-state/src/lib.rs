// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ledger: the sparse Merkle tree, the account model, and the
//! deterministic application of transactions.
//!
//! Where `vanargand-types` decides what a transaction *is*, this crate decides
//! what it *does*. Two implementations that agree about both agree about the
//! chain.
//!
//! # The rule this crate exists to enforce
//!
//! > Toute transition d'état doit être prouvable et reproductible. Une
//! > divergence entre deux nœuds honnêtes est une défaillance de consensus.
//!
//! Concretely, in this crate: every collection is a `BTreeMap` or a `BTreeSet`,
//! there is no floating point, there is no clock, and no function reads
//! anything outside the transaction bytes and the state those bytes name. The
//! CI job `determinism` greps for the ways round the lint.
//!
//! # The mechanism worth reading first
//!
//! [`ledger::Ledger::apply`] enforces the **nomad credit** in provisional
//! blocks: an account cut off from the world may spend exactly what it declared
//! in advance, per device, and not one ulf more. That is the bounded offline
//! exposure of `docs/01-concept.pdf` reduced to a subtraction, and it is what
//! lets a baker accept a payment during a week-long outage knowing the ceiling
//! before she hands over the bread.
//!
//! # State of completeness
//!
//! **All twenty-one transaction kinds apply.** The sparse Merkle tree is
//! complete, including non-inclusion proofs.
//!
//! What is not finished is performance and one gap of substance. Both the tree
//! and the ledger recompute their root from scratch, which is correct and is
//! not what a production node should run — see the notes on each. And the
//! offline ceiling still does not cover local assets, which is exactly the
//! payment the Tier 1 pilot is built around; it is recorded in
//! `spec/draft/04-transactions.md` §4.1 and pinned by a test rather than
//! quietly resolved.

pub mod account;
pub mod asset;
pub mod keys;
pub mod ledger;
pub mod name_book;
pub mod purse_book;
pub mod recovery;
pub mod slashing;
pub mod smt;

pub use account::{Account, Device};
pub use asset::{AssetError, AssetRecord, AssetRegistry};
pub use ledger::{Applied, BlockContext, Ledger, StateError};
pub use name_book::{NameBook, NameError};
pub use purse_book::{Payout, PurseBook, PurseBookError};
pub use recovery::{PendingRecovery, RecoveryBook, RecoveryError};
pub use slashing::{AccountOffence, Penalty, SlashingBook, SlashingError, ValidatorOffence};
pub use smt::{SmtLeaf, SmtProof, SparseMerkleTree};
