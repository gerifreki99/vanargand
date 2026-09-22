// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Addresses: the text form of an account identifier.
//!
//! An address is the one part of this protocol that a human reads aloud, types
//! from a screen, or photographs. Everything here is therefore strict and
//! everything fails loudly. See `spec/draft/03-addresses.md` §5.

use core::fmt;
use core::str::FromStr;

use vanargand_crypto::hash::Hash;

use crate::bech32::{self, Bech32Error};
use crate::id::AccountId;

/// The address payload version. Only 0 is defined.
pub const ADDRESS_VERSION: u8 = 0;

/// Which network an address belongs to.
///
/// The prefixes differ so that a test-network address pasted into a mainnet
/// wallet fails immediately instead of being accepted and paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Network {
    /// The production chain. Prefix `van`.
    Mainnet,
    /// The permanent public test network — an organ of the protocol rather
    /// than a draft, per `docs/02-scope.pdf`, where every tier runs and is
    /// attacked while the public uses the tier below. Prefix `tvan`.
    Testnet,
}

impl Network {
    /// The human-readable part used in addresses on this network.
    #[must_use]
    pub const fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "van",
            Self::Testnet => "tvan",
        }
    }

    /// The network with this prefix, if any.
    #[must_use]
    pub fn from_hrp(hrp: &str) -> Option<Self> {
        match hrp {
            "van" => Some(Self::Mainnet),
            "tvan" => Some(Self::Testnet),
            _ => None,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.hrp())
    }
}

/// Why an address string was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressError {
    /// The Bech32m layer rejected it.
    Bech32(Bech32Error),
    /// The prefix is not one this build knows.
    UnknownNetwork(String),
    /// The prefix names a network other than the one expected.
    ///
    /// Separate from [`AddressError::UnknownNetwork`] because it is the one a
    /// user will actually hit, and the message a wallet should show is
    /// different: not "this is not an address" but "this is a test-network
    /// address".
    WrongNetwork {
        /// The network the caller was working in.
        expected: Network,
        /// The network the address belongs to.
        found: Network,
    },
    /// The version character is not one this version of the protocol defines.
    UnknownVersion(u8),
    /// The data part is empty, so there is no version character.
    MissingVersion,
    /// The payload was not 32 bytes.
    BadPayloadLength(usize),
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bech32(error) => write!(f, "{error}"),
            Self::UnknownNetwork(hrp) => write!(f, "'{hrp}' is not a Vanargand address prefix"),
            Self::WrongNetwork { expected, found } => {
                write!(f, "this is a {found} address; expected {expected}")
            }
            Self::UnknownVersion(version) => write!(f, "unknown address version {version}"),
            Self::MissingVersion => write!(f, "address has no version character"),
            Self::BadPayloadLength(length) => {
                write!(f, "address payload is {length} bytes, expected 32")
            }
        }
    }
}

impl std::error::Error for AddressError {}

impl From<Bech32Error> for AddressError {
    fn from(error: Bech32Error) -> Self {
        Self::Bech32(error)
    }
}

/// An account address: a network, a version and an account identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    network: Network,
    account: AccountId,
}

impl Address {
    /// Builds an address for an account on a network.
    #[must_use]
    pub const fn new(network: Network, account: AccountId) -> Self {
        Self { network, account }
    }

    /// The network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// The account.
    #[must_use]
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Parses an address, requiring it to belong to `expected`.
    ///
    /// Prefer this over [`FromStr`] everywhere a network is known, which is
    /// everywhere in a running node. `FromStr` accepts any known network
    /// because a parser that cannot represent "this is a test-network address"
    /// cannot produce that error message.
    pub fn parse_on(expected: Network, text: &str) -> Result<Self, AddressError> {
        let address = Self::from_str(text)?;
        if address.network == expected {
            Ok(address)
        } else {
            Err(AddressError::WrongNetwork { expected, found: address.network })
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Ok(payload) = bech32::convert_bits(self.account.as_bytes(), 8, 5, true) else {
            return Err(fmt::Error);
        };
        let mut data = Vec::with_capacity(payload.len().saturating_add(1));
        data.push(ADDRESS_VERSION);
        data.extend_from_slice(&payload);
        let Ok(text) = bech32::encode(self.network.hrp(), &data) else {
            return Err(fmt::Error);
        };
        f.write_str(&text)
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (hrp, data) = bech32::decode(text)?;
        let network =
            Network::from_hrp(&hrp).ok_or_else(|| AddressError::UnknownNetwork(hrp.clone()))?;

        let version = data.first().copied().ok_or(AddressError::MissingVersion)?;
        if version != ADDRESS_VERSION {
            // Reject rather than treat the payload as opaque and forward it. A
            // wallet that passes an address version it does not understand is a
            // wallet that will one day forward funds to a rule it cannot read.
            return Err(AddressError::UnknownVersion(version));
        }

        let payload = data.get(1..).unwrap_or(&[]);
        let bytes = bech32::convert_bits(payload, 5, 8, false)?;
        let array: [u8; 32] =
            bytes.as_slice().try_into().map_err(|_| AddressError::BadPayloadLength(bytes.len()))?;

        Ok(Self { network, account: AccountId::from_hash(Hash::from_bytes(array)) })
    }
}

#[cfg(test)]
mod tests {
    use super::{Address, AddressError, Network, ADDRESS_VERSION};
    use crate::bech32::Bech32Error;
    use crate::id::AccountId;
    use core::str::FromStr;
    use vanargand_crypto::hash::Hash;

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    #[test]
    fn addresses_round_trip() {
        for network in [Network::Mainnet, Network::Testnet] {
            for byte in [0x00_u8, 0x01, 0x7f, 0xff] {
                let address = Address::new(network, account(byte));
                let text = address.to_string();
                assert_eq!(Address::from_str(&text), Ok(address), "round trip failed for {text}");
            }
        }
    }

    #[test]
    fn a_mainnet_address_looks_the_way_the_specification_says() {
        let address = Address::new(Network::Mainnet, account(0));
        let text = address.to_string();
        assert!(text.starts_with("van1"), "{text}");
        assert_eq!(text.len(), 63, "{text}");
        // Matches the vector generated independently by tools/vectorgen.
        assert_eq!(text, "van1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj5d0qu");
    }

    #[test]
    fn a_testnet_address_is_not_accepted_on_mainnet() {
        let text = Address::new(Network::Testnet, account(9)).to_string();
        assert!(text.starts_with("tvan1"), "{text}");
        assert_eq!(
            Address::parse_on(Network::Mainnet, &text),
            Err(AddressError::WrongNetwork {
                expected: Network::Mainnet,
                found: Network::Testnet
            }),
            "a test-network address was accepted on mainnet"
        );
        assert!(Address::parse_on(Network::Testnet, &text).is_ok());
    }

    #[test]
    fn the_two_networks_never_produce_the_same_string() {
        let mainnet = Address::new(Network::Mainnet, account(3)).to_string();
        let testnet = Address::new(Network::Testnet, account(3)).to_string();
        assert_ne!(mainnet, testnet);
        // And not merely by the prefix: the checksum covers the HRP, so the
        // trailing characters differ too. Truncating "tvan..." to "van..."
        // must not yield a valid mainnet address.
        assert!(Address::from_str(testnet.trim_start_matches('t')).is_err());
    }

    #[test]
    fn an_unknown_prefix_is_rejected() {
        // A valid Bech32m string that is not a Vanargand address.
        assert_eq!(
            Address::from_str("split1checkupstagehandshakeupstreamerranterredcaperredlc445v"),
            Err(AddressError::UnknownNetwork("split".to_owned()))
        );
    }

    #[test]
    fn a_bech32_string_is_rejected_as_such() {
        assert_eq!(
            Address::from_str("A1G7SGD8"),
            Err(AddressError::Bech32(Bech32Error::WrongVariantBech32))
        );
    }

    #[test]
    fn a_single_character_typo_is_always_caught() {
        // The property an address checksum exists for, over the whole string.
        let text = Address::new(Network::Mainnet, account(0x5a)).to_string();
        for index in 0..text.len() {
            for replacement in crate::bech32::CHARSET.iter().copied() {
                if text.as_bytes().get(index) == Some(&replacement) {
                    continue;
                }
                let mut tampered = text.clone();
                tampered.replace_range(index..index.saturating_add(1), &char::from(replacement).to_string());
                assert!(
                    Address::from_str(&tampered).is_err(),
                    "a typo at position {index} produced a valid address: {tampered}"
                );
            }
        }
    }

    #[test]
    fn a_truncated_address_is_rejected() {
        let text = Address::new(Network::Mainnet, account(1)).to_string();
        for cut in 1..text.len() {
            let truncated = text.get(..cut).unwrap_or("");
            assert!(
                Address::from_str(truncated).is_err(),
                "a {cut}-character prefix parsed as an address"
            );
        }
    }

    #[test]
    fn the_version_is_checked_rather_than_forwarded() {
        // Build an address string with version 1 by hand, and confirm it is
        // rejected rather than treated as an opaque payload.
        let payload = crate::bech32::convert_bits(&[0_u8; 32], 8, 5, true).unwrap();
        let mut data = vec![ADDRESS_VERSION.saturating_add(1)];
        data.extend_from_slice(&payload);
        let text = crate::bech32::encode("van", &data).unwrap();
        assert_eq!(Address::from_str(&text), Err(AddressError::UnknownVersion(1)));
    }

    #[test]
    fn a_short_payload_is_rejected() {
        // Valid Bech32m, valid version, wrong number of payload bytes.
        let payload = crate::bech32::convert_bits(&[0_u8; 20], 8, 5, true).unwrap();
        let mut data = vec![ADDRESS_VERSION];
        data.extend_from_slice(&payload);
        let text = crate::bech32::encode("van", &data).unwrap();
        assert!(matches!(
            Address::from_str(&text),
            Err(AddressError::BadPayloadLength(_) | AddressError::Bech32(_))
        ));
    }

    #[test]
    fn case_is_accepted_uniformly_or_not_at_all() {
        let text = Address::new(Network::Mainnet, account(7)).to_string();
        assert_eq!(Address::from_str(&text.to_uppercase()), Address::from_str(&text));
        let mut mixed = text.clone();
        mixed.replace_range(0..1, "V");
        assert_eq!(Address::from_str(&mixed), Err(AddressError::Bech32(Bech32Error::MixedCase)));
    }
}
