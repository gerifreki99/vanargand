// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two-party micro-payment channels — *bourses*.
//!
//! Implements `spec/draft/08-bourse.md`. Tier 1 of the roadmap in
//! `docs/02-scope.pdf`.
//!
//! Two parties lock a sum on the ledger, exchange acknowledgements off-chain
//! for free, and write only the final balance. A thousand micro-payments cost
//! two entries in the register, which is what makes paying a stranger per
//! megabyte for their connection affordable at all.
//!
//! # What is here
//!
//! - [`payword`] — the off-chain half. Rivest and Shamir, 1997, adopted
//!   unchanged by R2: 32 bytes per tranche instead of a 2420-byte signature.
//! - [`purse`] — the on-chain record and the closing state machine.
//! - [`watchtower`] — what objects to a stale closure while the victim sleeps.
//!
//! # C9, and where its parade actually lives
//!
//! This crate is shaped by one finding, and reading only this crate would hide
//! half of it. Closing a channel is where payment channels and partitions meet:
//! publish a **stale** unilateral closure into provisional blocks while the
//! counterparty and its watchtower are on the far side of a partition, and the
//! contestation window runs out in a world where the objector cannot exist. The
//! payment-channel literature assumes liveness; the partition literature
//! ignores channels.
//!
//! The parade has two halves and neither is in this crate's logic:
//!
//! 1. `purse_close_unilateral` and `purse_dispute` are **grammatically
//!    illegal** in a provisional block — see
//!    `vanargand_types::tx::TxKind::allowed_in_provisional`. The *cooperative*
//!    closure is whitelisted, because both parties signed it and there is no
//!    absent victim.
//! 2. Every deadline is a `vanargand_types::block::ContestationWindow`, which
//!    takes a finalised height and offers no way to pass an ordinary one. A
//!    partition raises the height freely and cannot move the finalised tip, so
//!    the window stands still for exactly as long as the objector cannot speak.
//!
//! # Strictly two parties
//!
//! R1.6. Multi-party channels are a research topic; groups go through a hub or
//! through unanimous locking, and tree-shaped channels mature on the test
//! network before anyone bets a festival on them.
//!
//! # What is not here
//!
//! The transactions themselves live in `vanargand_types::tx` and their effect
//! on balances belongs to `vanargand-state`, which does not yet apply them.
//! This crate decides what a channel *means*; it does not move money.
//!
//! Signature checking is likewise absent: a cooperative closure is agreed by
//! two signatures, and establishing that is the transaction layer's job. Mixing
//! "who authorised this" with "what does it settle to" would put an authority
//! bug and an accounting bug in the same function.

pub mod payword;
pub mod purse;
pub mod watchtower;

pub use payword::{PayWordError, PayWordPayee, PayWordPayer, PayWordToken, MAX_TRANCHES};
pub use purse::{
    PendingClosure, Purse, PurseError, PurseId, Settlement, DISPUTE_WINDOW_FINALIZED_BLOCKS,
};
pub use watchtower::{Verdict, Watchtower};
