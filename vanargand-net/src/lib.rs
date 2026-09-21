// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The network stack: QUIC, TCP, WebRTC, mDNS and Bluetooth transports,
//! gossipsub topics, and a Kademlia DHT.
//!
//! **Not implemented.**
//!
//! The design constraint that shapes everything here: no message ever says "I
//! need the Internet", only "pass me on". A neighbourhood, a mountain village,
//! a festival or a ship keeps a living Vanargand network among themselves.
//!
//! Multi-transport is also B1's parade — eclipsing a device means controlling
//! its Internet, its Wi-Fi *and* the Bluetooth in the room at once, which takes
//! physical presence. The peer selection rules that make that true are
//! unspecified and are the real work.
//!
//! Tier 1 of the roadmap in `docs/02-scope.pdf`.
