// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The mobile and desktop application: one core, two faces.
//!
//! **Not implemented.** Embeds crypto, types, messaging and channels, and a
//! light client, behind an FFI boundary.
//!
//! Two product constraints that are protocol decisions in disguise:
//!
//! - **Device asymmetry is admitted, not hidden.** The phone is a client and a
//!   payer. Relays, watchtowers and gateways live on plugged-in machines,
//!   because iOS and Android background restrictions make anything else
//!   unreliable infrastructure. R1.6 requires the product narrative to say so.
//! - **A provisional payment is a cheque, and the interface says which rung it
//!   is on.** The finality ladder is a visible cursor rather than a uniform
//!   promise; hiding it would be the one dishonesty the whole design is built
//!   to avoid.
//!
//! Tier 1 of the roadmap in `docs/02-scope.pdf`.
