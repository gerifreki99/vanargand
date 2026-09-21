// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-chain bridges: named single-destination freezes, contestation
//! windows, cross-milestones.
//!
//! **Not implemented.**
//!
//! The rule is the prudent traveller's: you only expose what you carry. Freeze
//! a hundred VAN at home in a contract naming the destination chain, that
//! chain's validator set at that instant, you, a unique number and an expiry;
//! the host chain credits a hundred. Everything else stays home and out of
//! reach. The worst case is exactly what was carried.
//!
//! Open before this can be built: D2 (validator key rotation), D3 (data
//! withholding — a milestone signed without publishing what it commits to, the
//! subtlest trap in the federation and an open research problem industry-wide),
//! and the trust-versus-bond schedule of A1 and D6.
//!
//! Tier 3 of the roadmap in `docs/02-scope.pdf`.
