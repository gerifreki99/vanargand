// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Full distributed storage for user data: shards, erasure coding, real
//! sealing.
//!
//! **Not implemented, and deliberately absent from Tier 1.**
//!
//! R2's second acknowledged error was the claim that Tier 1 used only proven
//! components. Sealing is not a proven component: making each replica expensive
//! to regenerate is a problem the industry took years and considerable weight
//! to solve. E1 to E3 were reclassified "to be designed" as a result.
//!
//! Tier 1 sidesteps it for public data by paying for delivery instead of
//! holding (`vanargand-archive`). Private data cannot use that trick, and R2
//! leaves two documented roads: import an audited sealing construction and
//! accept its weight, or accept degraded guarantees compensated by more
//! redundancy and a lower price. The decision waits on a prototype.
//!
//! C4 and E4 — correlated loss, and a rich actor quietly holding every shard —
//! are open under C7. The parade is that **diversity is chosen and paid for by
//! the client**, never promised by the protocol.
//!
//! Tier 2 of the roadmap in `docs/02-scope.pdf`.
