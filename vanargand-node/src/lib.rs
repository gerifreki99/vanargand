// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node: assembling a block and deciding whether it is one.
//!
//! Tier 1 of the roadmap in `docs/02-scope.pdf`.
//!
//! This is the first crate that makes the others work together — the header
//! rules from `vanargand-types`, the committee and certificate from
//! `vanargand-consensus`, the ledger from `vanargand-state`. It invents no
//! rule. What it contributes is the **order**, which is the part that cannot be
//! got right one crate at a time: see [`validate`].
//!
//! # What is here
//!
//! - [`block`] — a block as it travels: header, body, optional certificate.
//! - [`propose`] — building one.
//! - [`validate`] — validate and apply, entirely or not at all.
//!
//! The two halves run the same rules with opposite dispositions: a producer
//! **drops** a candidate that does not apply, a validator **rejects** the whole
//! block. Which is why they are separate modules and why the round-trip —
//! build, then validate what you built — is the test that matters.
//!
//! # What is not here, and what that costs
//!
//! **Networking, gossip and peer selection.** `vanargand-net` is empty. A node
//! that cannot fetch a block cannot validate one, so nothing here runs against
//! a real chain yet.
//!
//! **Transaction selection policy.** [`propose::build`] takes the candidates in
//! the order it is given them and does not reorder. That is the honest default
//! and not a defence: ordering is where a proposer extracts value — A5
//! censorship at one end, F4 front-running at the other — and the inclusion
//! lists A5 names as the eventual parade do not exist.
//!
//! **Emission distribution.** The curve and the border check are enforced;
//! *paying* emission out — missions, usage credits, vesting, the
//! self-constituting bond — is not implemented, so a producer is told its
//! chain's emission counter rather than deriving it.
//!
//! **A7 fraud proofs.** A full node is supposed to be able to produce a compact
//! refutation of a bad state transition for light clients. The sparse Merkle
//! tree gives the branches; the refutation format does not exist.
//!
//! # A gap this crate exposed
//!
//! Bonded stake lives in **two** places: `Account::bonded` in the ledger, which
//! `bond` and `unbond` transactions move, and `ValidatorRecord::bond` in the
//! consensus validator set, which nothing updates. They can silently diverge,
//! and committee weight is drawn from the second.
//!
//! The right shape is almost certainly that the validator set is *derived* from
//! ledger state rather than maintained beside it — a validator is an account
//! with a bond and a sealed commitment chain, and there is no reason for the
//! same fact to be written down twice. That refactor is not done, and until it
//! is, keeping the two in step is the caller's problem. **(open)**
//!
//! Writing this crate is what surfaced it, which is the argument for having
//! written it before the network layer rather than after.

pub mod block;
pub mod propose;
pub mod validate;

pub use block::Block;
pub use propose::{build, Declined, ProposalInputs, ProposeError};
pub use validate::{validate_and_apply, Applied, BlockError, ChainParameters};
