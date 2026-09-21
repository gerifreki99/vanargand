// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two-party micro-payment channels: signed states, PayWord, paid watchtowers.
//!
//! **Not implemented.** Three pieces already exist: `vanargand_crypto::chain`
//! has PayWord, and `vanargand_types::tx` has the four channel transactions
//! along with the partition grammar that governs them.
//!
//! Strictly two parties (R1.6). Multi-party channels are a research topic;
//! groups go through a hub or through unanimous locking.
//!
//! The mechanism to read first is **C9**, because it is this crate's reason to
//! exist in the shape it has. Publishing a stale unilateral closure while the
//! counterparty and its watchtower are behind a partition would let the
//! contestation window elapse in a world where the objector cannot exist. The
//! parade is two rules, both already enforced upstream: unilateral closure is
//! grammatically illegal in a provisional block, and every window is counted in
//! finalised height.
//!
//! Tier 1 of the roadmap in `docs/02-scope.pdf`.
