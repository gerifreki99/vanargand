// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Human-readable names and asset tickers.
//!
//! One grammar for both. A registered name and an asset ticker are the same
//! kind of object — a short string that is unique in state and that a human
//! reads — so they get the same rules, and there is one place to argue about
//! what those rules are.
//!
//! # Why the grammar is this narrow
//!
//! A name is a **state key**. Two strings that a person cannot tell apart, but
//! that hash differently, are two accounts that look identical on a screen —
//! which is the entire homograph attack, and it is far more dangerous against a
//! payment address than against a website.
//!
//! The choice made here is the blunt one: **ASCII lowercase, digits and
//! hyphen**. Not because other scripts do not deserve names — they do, and a
//! protocol aimed at "anywhere there are devices and people" excluding them is
//! a real cost, written down here rather than glossed over — but because the
//! alternative is a Unicode confusable table, baked into consensus, that has to
//! be identical in every implementation forever, and that has to be updated
//! when Unicode is. That is a consensus dependency on a moving external
//! document.
//!
//! **(open)** Whether Tier 2 adds internationalised names behind a separate,
//! visually distinct namespace, so that the confusable set is a property of
//! that namespace rather than of the whole protocol.
//!
//! # A decoder never normalises
//!
//! `NAME-1` is not accepted and lowercased to `name-1`; it is rejected. If a
//! decoder normalised, two distinct encodings would map to one state key, which
//! is exactly the malleability that `01-canonical-encoding.md` exists to
//! prevent.

use core::fmt;

use crate::codec::{CodecError, Decode, Decoder, Encode, Encoder};

/// Shortest legal name.
pub const MIN_NAME_LEN: usize = 1;
/// Longest legal name.
///
/// Thirty-two so that a name and a hash cost the same in state, and so that the
/// rent rule of `docs/01-concept.pdf` — "un loyer symbolique fait le ménage" —
/// has a predictable object to price.
pub const MAX_NAME_LEN: usize = 32;

/// Names shorter than this are auctioned rather than first-come, and carry the
/// Harberger-style rent (R1.7).
///
/// R1.7 rejected the rent in general and kept it for short names only: it is a
/// legitimate anti-squatting tool on premium names, and unacceptable hostility
/// against a private person's `@marie`, whose own name must never be
/// purchasable against their will.
///
/// # The rule and its own example disagree
///
/// R1.7 states the threshold as "noms de moins de six caractères" and, in the
/// same sentence, gives `@marie` as the case the rent must never touch.
/// `marie` is five characters. Under the rule as written it is premium, rented,
/// and purchasable against its owner's will — which is precisely what the
/// sentence says must not happen.
///
/// The value below implements the rule **as written**, because silently moving
/// a design parameter to fit an example is how a specification stops describing
/// what was decided. The contradiction is recorded in
/// `spec/draft/04-transactions.md` as an open point, with the three ways out:
/// lower the threshold to four, keep six and accept that five-letter given
/// names are premium, or separate the two mechanisms so that auction applies to
/// short names while rent applies only to names held without an account that
/// uses them.
///
/// **(open)**
pub const PREMIUM_NAME_LEN: usize = 6;

/// A validated name or ticker.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name(String);

/// Why a name was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameError {
    /// Shorter than [`MIN_NAME_LEN`] or longer than [`MAX_NAME_LEN`].
    BadLength(usize),
    /// Contains a character outside the grammar.
    BadCharacter(char),
    /// Starts or ends with a hyphen.
    EdgeHyphen,
    /// Contains two hyphens in a row.
    DoubleHyphen,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength(length) => write!(
                f,
                "a name is {MIN_NAME_LEN} to {MAX_NAME_LEN} characters, got {length}"
            ),
            Self::BadCharacter(character) => write!(
                f,
                "'{character}' is not allowed; names use a-z, 0-9 and '-'"
            ),
            Self::EdgeHyphen => write!(f, "a name may not start or end with '-'"),
            Self::DoubleHyphen => write!(f, "a name may not contain '--'"),
        }
    }
}

impl std::error::Error for NameError {}

impl Name {
    /// Validates a name. Never normalises.
    pub fn new(text: &str) -> Result<Self, NameError> {
        let length = text.len();
        if !(MIN_NAME_LEN..=MAX_NAME_LEN).contains(&length) {
            return Err(NameError::BadLength(length));
        }
        for character in text.chars() {
            let ok = character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-';
            if !ok {
                return Err(NameError::BadCharacter(character));
            }
        }
        if text.starts_with('-') || text.ends_with('-') {
            return Err(NameError::EdgeHyphen);
        }
        if text.contains("--") {
            return Err(NameError::DoubleHyphen);
        }
        Ok(Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this name falls in the premium range and is therefore auctioned
    /// and subject to rent.
    #[must_use]
    pub fn is_premium(&self) -> bool {
        self.0.len() < PREMIUM_NAME_LEN
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Encode for Name {
    fn encode(&self, out: &mut Encoder) {
        out.write_str(&self.0);
    }
}

impl Decode for Name {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let text = input.read_str()?;
        Self::new(text).map_err(|_| CodecError::Invalid { reason: "not a valid name" })
    }
}

#[cfg(test)]
mod tests {
    use super::{Name, NameError, MAX_NAME_LEN};
    use crate::codec::{CodecError, Decode, Encode, Encoder};

    #[test]
    fn ordinary_names_are_accepted() {
        for text in ["marie", "a", "cafe-du-port", "x1", "0", "z9-z"] {
            assert!(Name::new(text).is_ok(), "rejected: {text}");
        }
    }

    #[test]
    fn the_grammar_is_enforced_rather_than_repaired() {
        // The rule that matters: reject, never normalise. A decoder that
        // lowercased would map two encodings to one state key.
        assert_eq!(Name::new("Marie"), Err(NameError::BadCharacter('M')));
        assert_eq!(Name::new("marie!"), Err(NameError::BadCharacter('!')));
        assert_eq!(Name::new("ma rie"), Err(NameError::BadCharacter(' ')));
        assert_eq!(Name::new("marié"), Err(NameError::BadCharacter('é')));
        assert_eq!(Name::new("маrie"), Err(NameError::BadCharacter('м')));
        assert_eq!(Name::new("marie_x"), Err(NameError::BadCharacter('_')));
    }

    #[test]
    fn a_cyrillic_lookalike_cannot_impersonate_a_latin_name() {
        // The homograph attack, blocked at the grammar rather than by a
        // confusable table that would have to live in consensus forever.
        assert!(Name::new("marie").is_ok());
        assert!(Name::new("\u{43c}arie").is_err(), "Cyrillic 'м' was accepted");
        assert!(Name::new("mar\u{456}e").is_err(), "Cyrillic 'і' was accepted");
    }

    #[test]
    fn hyphens_are_constrained() {
        assert_eq!(Name::new("-marie"), Err(NameError::EdgeHyphen));
        assert_eq!(Name::new("marie-"), Err(NameError::EdgeHyphen));
        assert_eq!(Name::new("ma--rie"), Err(NameError::DoubleHyphen));
        assert!(Name::new("ma-rie").is_ok());
        assert_eq!(Name::new("-"), Err(NameError::EdgeHyphen));
    }

    #[test]
    fn lengths_are_bounded() {
        assert_eq!(Name::new(""), Err(NameError::BadLength(0)));
        assert!(Name::new(&"a".repeat(MAX_NAME_LEN)).is_ok());
        assert_eq!(
            Name::new(&"a".repeat(MAX_NAME_LEN + 1)),
            Err(NameError::BadLength(MAX_NAME_LEN + 1))
        );
    }

    #[test]
    fn premium_names_are_the_short_ones() {
        // R1.7: names under six characters are auctioned and rented.
        assert!(Name::new("ab").unwrap().is_premium());
        assert!(Name::new("abcde").unwrap().is_premium());
        assert!(!Name::new("abcdef").unwrap().is_premium());
    }

    #[test]
    fn the_documented_contradiction_is_pinned_rather_than_papered_over() {
        // R1.7 sets the premium threshold at six characters and, in the same
        // sentence, names `@marie` as the case the rent must never touch.
        // `marie` is five characters, so the rule as written does exactly what
        // the sentence forbids. This test asserts the behaviour that follows
        // from the rule as written, so that whoever resolves the contradiction
        // has to come through here and say which way it went.
        assert!(
            Name::new("marie").unwrap().is_premium(),
            "if this now fails, the premium threshold was changed; \
             see PREMIUM_NAME_LEN and 04-transactions.md"
        );
    }

    #[test]
    fn names_round_trip() {
        let name = Name::new("cafe-du-port").unwrap();
        assert_eq!(Name::from_canonical_bytes(&name.to_canonical_bytes()), Ok(name));
    }

    #[test]
    fn an_invalid_name_on_the_wire_is_rejected() {
        let mut encoder = Encoder::new();
        encoder.write_str("Marie");
        assert_eq!(
            Name::from_canonical_bytes(&encoder.finish()),
            Err(CodecError::Invalid { reason: "not a valid name" })
        );
    }
}
