// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The full node: wiring crypto, types, state, consensus and networking
//! together, and exposing the RPC that light clients consume.
//!
//! **Not implemented.**
//!
//! Two obligations this crate owes the rest of the system, both of which are
//! easy to forget until they are expensive:
//!
//! - **State-transition fraud proofs (A7).** A two-thirds-corrupt committee can
//!   finalise an invalid state, and a light client that checks signatures and
//!   Merkle branches would never notice. A full node must be able to produce a
//!   compact refutation — the branches the bad transition touched — and gossip
//!   it on an alert channel.
//! - **Snapshot sync.** A new device starts from the last widely co-signed
//!   milestone, never from genesis. Joining a ten-year-old chain must cost the
//!   price of today's state, not of the decade.
//!
//! Tier 1 of the roadmap in `docs/02-scope.pdf`.
