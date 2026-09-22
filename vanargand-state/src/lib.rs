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
//! Six transaction kinds apply; the rest return
//! [`ledger::StateError::NotImplemented`]. The sparse Merkle tree is complete,
//! including non-inclusion proofs. Both the tree and the ledger recompute their
//! root from scratch, which is correct and is not what a production node should
//! run — see the notes on each.

pub mod account;
pub mod ledger;
pub mod smt;

pub use account::{Account, Device};
pub use ledger::{Applied, BlockContext, Ledger, StateError};
pub use smt::{SmtLeaf, SmtProof, SparseMerkleTree};
