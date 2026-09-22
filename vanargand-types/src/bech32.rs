// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bech32m (BIP-350), the text encoding for addresses.
//!
//! **Bech32m only. Bech32 (BIP-173) is rejected.** The two differ in exactly
//! one constant, and the reason for the change is worth restating because a
//! reader who does not know it will be tempted to accept both for
//! compatibility: Bech32's checksum loses its guarantees when the length of the
//! data part varies, which allowed an address with an appended or removed `q`
//! to still validate. Vanargand has no legacy to preserve, so it takes the
//! fixed constant and refuses the broken one.
//!
//! Everything here is strict. An address is a string a human retypes from a
//! screen or a phone camera, and the whole purpose of a checksum is to fail
//! loudly rather than route money somewhere plausible.

use core::fmt;

/// The Bech32 character set: five bits per character.
///
/// Ordered so that the characters most easily confused — `1`, `b`, `i`, `o` —
/// are absent entirely.
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The Bech32m checksum constant. Bech32 uses `1`; that is the whole
/// difference, and it is why they must never be mixed.
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// The Bech32 (BIP-173) constant, kept only so that this implementation can
/// recognise a Bech32 string and reject it with a precise message.
const BECH32_CONST: u32 = 1;

/// Maximum total length of a Bech32m string, from BIP-173.
pub const MAX_LENGTH: usize = 90;

/// Why a Bech32m string was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bech32Error {
    /// The string mixes upper and lower case. BIP-173 forbids it because a
    /// mixed-case string has no canonical form to checksum.
    MixedCase,
    /// The string is longer than [`MAX_LENGTH`].
    TooLong(usize),
    /// The string has no `1` separator.
    NoSeparator,
    /// The human-readable part is empty.
    EmptyHrp,
    /// The human-readable part contains a character outside `[33, 126]`.
    BadHrpChar(u8),
    /// The data part is shorter than the six checksum characters, or empty
    /// after them.
    DataTooShort(usize),
    /// A data character is not in [`CHARSET`].
    BadDataChar(char),
    /// The checksum did not verify.
    BadChecksum,
    /// The checksum verified — as **Bech32**, not Bech32m.
    ///
    /// Reported separately from [`Bech32Error::BadChecksum`] because it is a
    /// completely different situation: not a typo, but a correctly formed
    /// address in the encoding this protocol does not use. A wallet can say
    /// "this is not a Vanargand address" instead of "check for a typo".
    WrongVariantBech32,
    /// Bit conversion left non-zero padding, or padded by five bits or more.
    ///
    /// Non-zero padding is a second encoding of the same payload, which is
    /// exactly the malleability the canonical encoding rules exist to prevent.
    BadPadding,
}

impl fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MixedCase => write!(f, "mixed upper and lower case"),
            Self::TooLong(length) => write!(f, "{length} characters, maximum is {MAX_LENGTH}"),
            Self::NoSeparator => write!(f, "no '1' separator"),
            Self::EmptyHrp => write!(f, "empty human-readable part"),
            Self::BadHrpChar(byte) => {
                write!(f, "human-readable part contains byte 0x{byte:02x}")
            }
            Self::DataTooShort(length) => write!(f, "data part is {length} characters, too short"),
            Self::BadDataChar(character) => write!(f, "'{character}' is not a data character"),
            Self::BadChecksum => write!(f, "checksum does not verify"),
            Self::WrongVariantBech32 => {
                write!(f, "this is a Bech32 string; Vanargand uses Bech32m only")
            }
            Self::BadPadding => write!(f, "non-canonical padding bits"),
        }
    }
}

impl std::error::Error for Bech32Error {}

fn polymod(values: &[u8]) -> u32 {
    const GENERATOR: [u32; 5] =
        [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut checksum: u32 = 1;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (index, generator) in GENERATOR.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= *generator;
            }
        }
    }
    checksum
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut expanded = Vec::with_capacity(hrp.len().saturating_mul(2).saturating_add(1));
    for byte in hrp.bytes() {
        expanded.push(byte >> 5);
    }
    expanded.push(0);
    for byte in hrp.bytes() {
        expanded.push(byte & 31);
    }
    expanded
}

fn charset_value(character: u8) -> Option<u8> {
    CHARSET.iter().position(|c| *c == character).and_then(|index| u8::try_from(index).ok())
}

/// Regroups `data` from `from_bits`-wide groups into `to_bits`-wide groups.
///
/// With `pad = true` (encoding), a final partial group is zero-padded. With
/// `pad = false` (decoding), a final partial group must be fewer than
/// `from_bits` bits and must be all zero, or [`Bech32Error::BadPadding`] is
/// returned — a non-zero pad would be a second encoding of the same payload.
pub fn convert_bits(
    data: &[u8],
    from_bits: u32,
    to_bits: u32,
    pad: bool,
) -> Result<Vec<u8>, Bech32Error> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let max_value: u32 = (1_u32 << to_bits).saturating_sub(1);
    // Only the low `bits + from_bits` bits of the accumulator are ever read,
    // and that is at most 13 for the two conversions this protocol performs.
    // Masking keeps the value provably bounded instead of relying on shift
    // overflow to discard the history.
    const ACCUMULATOR_MASK: u32 = 0xffff;

    for value in data {
        accumulator = ((accumulator << from_bits) | u32::from(*value)) & ACCUMULATOR_MASK;
        bits = bits.saturating_add(from_bits);
        while bits >= to_bits {
            bits = bits.saturating_sub(to_bits);
            let group = (accumulator >> bits) & max_value;
            out.push(u8::try_from(group).unwrap_or(0));
        }
    }

    if pad {
        if bits > 0 {
            let group = (accumulator << (to_bits.saturating_sub(bits))) & max_value;
            out.push(u8::try_from(group).unwrap_or(0));
        }
    } else if bits >= from_bits || (accumulator << (to_bits.saturating_sub(bits))) & max_value != 0 {
        return Err(Bech32Error::BadPadding);
    }

    Ok(out)
}

/// Encodes a human-readable part and 5-bit data into a Bech32m string.
///
/// `data` must already be 5-bit groups; use [`convert_bits`] to get there from
/// bytes.
pub fn encode(hrp: &str, data: &[u8]) -> Result<String, Bech32Error> {
    if hrp.is_empty() {
        return Err(Bech32Error::EmptyHrp);
    }
    for byte in hrp.bytes() {
        if !(33..=126).contains(&byte) {
            return Err(Bech32Error::BadHrpChar(byte));
        }
        if byte.is_ascii_uppercase() {
            // Encoding always produces lowercase. An uppercase HRP handed in
            // would produce a string whose checksum is computed over the
            // lowercase form, which is a trap rather than a convenience.
            return Err(Bech32Error::BadHrpChar(byte));
        }
    }

    let mut checksum_input = hrp_expand(hrp);
    checksum_input.extend_from_slice(data);
    checksum_input.extend_from_slice(&[0; 6]);
    let checksum = polymod(&checksum_input) ^ BECH32M_CONST;

    let mut out = String::with_capacity(
        hrp.len().saturating_add(1).saturating_add(data.len()).saturating_add(6),
    );
    out.push_str(hrp);
    out.push('1');
    for value in data {
        let Some(&character) = CHARSET.get(usize::from(*value)) else {
            return Err(Bech32Error::BadDataChar('?'));
        };
        out.push(char::from(character));
    }
    for index in 0..6_u32 {
        let shift = 5_u32.saturating_mul(5_u32.saturating_sub(index));
        let value = (checksum >> shift) & 31;
        let Some(&character) = CHARSET.get(usize::try_from(value).unwrap_or(0)) else {
            return Err(Bech32Error::BadDataChar('?'));
        };
        out.push(char::from(character));
    }

    if out.len() > MAX_LENGTH {
        return Err(Bech32Error::TooLong(out.len()));
    }
    Ok(out)
}

/// Decodes a Bech32m string into its human-readable part and 5-bit data.
///
/// The returned data excludes the six checksum characters. The human-readable
/// part is returned lowercased.
pub fn decode(text: &str) -> Result<(String, Vec<u8>), Bech32Error> {
    if text.len() > MAX_LENGTH {
        return Err(Bech32Error::TooLong(text.len()));
    }

    let has_lower = text.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = text.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }
    let lowered = text.to_ascii_lowercase();

    // The separator is the *last* '1', so that an HRP may contain one.
    let separator = lowered.rfind('1').ok_or(Bech32Error::NoSeparator)?;
    let hrp = lowered.get(..separator).ok_or(Bech32Error::NoSeparator)?;
    let data_part = lowered
        .get(separator.saturating_add(1)..)
        .ok_or(Bech32Error::NoSeparator)?;

    if hrp.is_empty() {
        return Err(Bech32Error::EmptyHrp);
    }
    for byte in hrp.bytes() {
        if !(33..=126).contains(&byte) {
            return Err(Bech32Error::BadHrpChar(byte));
        }
    }
    if data_part.len() < 6 {
        return Err(Bech32Error::DataTooShort(data_part.len()));
    }

    let mut values = Vec::with_capacity(data_part.len());
    for character in data_part.chars() {
        let byte = u8::try_from(u32::from(character))
            .map_err(|_| Bech32Error::BadDataChar(character))?;
        let value = charset_value(byte).ok_or(Bech32Error::BadDataChar(character))?;
        values.push(value);
    }

    let mut checksum_input = hrp_expand(hrp);
    checksum_input.extend_from_slice(&values);
    match polymod(&checksum_input) {
        BECH32M_CONST => {}
        BECH32_CONST => return Err(Bech32Error::WrongVariantBech32),
        _ => return Err(Bech32Error::BadChecksum),
    }

    // An empty payload — a string that is nothing but HRP and checksum — is
    // valid Bech32m and appears in the BIP-350 vectors. Whether it is a valid
    // *address* is a question for the address layer, which requires a version
    // and 32 bytes; deciding it here would make this function fail the
    // reference vectors.
    let payload_len = values.len().saturating_sub(6);
    let payload = values.get(..payload_len).unwrap_or(&[]).to_vec();
    Ok((hrp.to_owned(), payload))
}

#[cfg(test)]
mod tests {
    use super::{convert_bits, decode, encode, Bech32Error, CHARSET};

    /// Round-trips bytes through the 8-to-5 conversion and back.
    fn encode_bytes(hrp: &str, version: u8, payload: &[u8]) -> String {
        let mut data = vec![version];
        data.extend(convert_bits(payload, 8, 5, true).unwrap());
        encode(hrp, &data).unwrap()
    }

    #[test]
    fn the_charset_omits_every_confusable_character() {
        // The reason Bech32 picked this alphabet. Asserted so that nobody
        // "completes" it later.
        for forbidden in [b'1', b'b', b'i', b'o'] {
            assert!(
                !CHARSET.contains(&forbidden),
                "'{}' is in the charset",
                char::from(forbidden)
            );
        }
        assert_eq!(CHARSET.len(), 32);
    }

    #[test]
    fn bip350_test_vectors_decode() {
        // Valid Bech32m strings from BIP-350. These are what tell us this
        // implementation agrees with the rest of the world rather than merely
        // with itself.
        let long_run = format!("11{}udsr8", "l".repeat(83));
        let mut vectors = vec![
            "A1LQFN3A".to_owned(),
            "a1lqfn3a".to_owned(),
            "an83characterlonghumanreadablepartthatcontainsthet\
             heexcludedcharactersbioandnumber11sg7hg6"
                .to_owned(),
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx".to_owned(),
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v".to_owned(),
            "?1v759aa".to_owned(),
        ];
        vectors.push(long_run);

        for valid in &vectors {
            assert!(decode(valid).is_ok(), "BIP-350 valid vector rejected: {valid}");
            assert!(valid.len() <= 90);
        }
    }

    #[test]
    fn bip350_vectors_re_encode_identically() {
        // Decoding and re-encoding must be the identity on a canonical
        // lowercase string. This catches a decoder that is lenient in a way the
        // encoder is not — the two halves drifting apart is how one
        // implementation ends up producing addresses another cannot read.
        for valid in [
            "a1lqfn3a",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ] {
            let (hrp, data) = decode(valid).unwrap();
            assert_eq!(encode(&hrp, &data).unwrap(), valid);
        }
    }

    #[test]
    fn bip350_invalid_vectors_are_rejected() {
        for (invalid, why) in [
            ("qyrz8wqd2c9m", "no separator"),
            ("1qyrz8wqd2c9m", "empty hrp"),
            ("y1b0jsk6g", "invalid data character 'b'"),
            ("lt1igcx5c0", "invalid data character 'i'"),
            ("in1muywd", "too short data part"),
            ("mm1crxm3i", "invalid data character 'i'"),
            ("A1G7SGD8", "this is Bech32, not Bech32m"),
            ("16plkw9", "empty hrp"),
            ("1p2gdwpf", "empty hrp"),
        ] {
            assert!(decode(invalid).is_err(), "should have been rejected ({why}): {invalid}");
        }
    }

    #[test]
    fn a_bech32_string_is_reported_as_bech32_not_as_a_typo() {
        // "A1G7SGD8" is a valid Bech32 string. A wallet should be able to tell
        // its user "wrong kind of address", not "check for a typo".
        assert_eq!(decode("A1G7SGD8"), Err(Bech32Error::WrongVariantBech32));
    }

    #[test]
    fn a_32_byte_payload_round_trips() {
        let payload = [0xab_u8; 32];
        let text = encode_bytes("van", 0, &payload);
        let (hrp, data) = decode(&text).unwrap();
        assert_eq!(hrp, "van");
        assert_eq!(data.first().copied(), Some(0), "version character lost");
        let decoded = convert_bits(data.get(1..).unwrap(), 5, 8, false).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn a_mainnet_address_is_sixty_three_characters() {
        // 3 hrp + 1 separator + 1 version + 52 payload + 6 checksum.
        let text = encode_bytes("van", 0, &[0; 32]);
        assert_eq!(text.len(), 63, "{text}");
        assert!(text.starts_with("van1"));
    }

    #[test]
    fn mixed_case_is_rejected() {
        let text = encode_bytes("van", 0, &[0x11; 32]);
        let mut mixed = text.clone();
        mixed.replace_range(0..1, "V");
        assert_eq!(decode(&mixed), Err(Bech32Error::MixedCase));
        // But a uniformly uppercased string is valid and decodes the same.
        assert_eq!(decode(&text.to_uppercase()), decode(&text));
    }

    #[test]
    fn a_single_character_change_breaks_the_checksum() {
        // The property the whole encoding exists for. Every single-character
        // substitution at every position must fail.
        let text = encode_bytes("van", 0, &[0x5a; 32]);
        let bytes = text.as_bytes();
        for index in 4..bytes.len() {
            for &replacement in CHARSET.iter() {
                if bytes.get(index) == Some(&replacement) {
                    continue;
                }
                let mut tampered = text.clone();
                tampered.replace_range(index..index + 1, &char::from(replacement).to_string());
                assert!(
                    decode(&tampered).is_err(),
                    "changing position {index} to '{}' still verified",
                    char::from(replacement)
                );
            }
        }
    }

    #[test]
    fn non_zero_padding_bits_are_rejected() {
        // 32 bytes is 256 bits, which is 51 groups of five plus one bit; the
        // final group carries four padding bits that MUST be zero. A payload
        // with a non-zero pad is a second encoding of the same address.
        let mut data = vec![0_u8]; // version
        data.extend(convert_bits(&[0xff_u8; 32], 8, 5, true).unwrap());
        // Set a padding bit in the last group.
        if let Some(last) = data.last_mut() {
            *last |= 0b0000_1;
        }
        let text = encode("van", &data).unwrap();
        let (_, decoded) = decode(&text).unwrap();
        assert_eq!(
            convert_bits(decoded.get(1..).unwrap(), 5, 8, false),
            Err(Bech32Error::BadPadding)
        );
    }

    #[test]
    fn an_over_length_string_is_rejected() {
        let long_hrp = "v".repeat(90);
        assert!(matches!(encode(&long_hrp, &[0; 10]), Err(Bech32Error::TooLong(_))));
        assert!(matches!(decode(&"a".repeat(91)), Err(Bech32Error::TooLong(_))));
    }

    #[test]
    fn an_empty_or_bad_hrp_is_rejected() {
        assert_eq!(encode("", &[0; 10]), Err(Bech32Error::EmptyHrp));
        assert!(matches!(encode("va n", &[0; 10]), Err(Bech32Error::BadHrpChar(_))));
        assert!(matches!(encode("VAN", &[0; 10]), Err(Bech32Error::BadHrpChar(_))));
    }

    #[test]
    fn the_separator_is_the_last_one() {
        // BIP-173: an HRP may itself contain '1'. Reading the first '1' as the
        // separator is a classic implementation bug.
        let text = encode_bytes("va1n", 0, &[0x01; 32]);
        let (hrp, _) = decode(&text).unwrap();
        assert_eq!(hrp, "va1n");
    }

    #[test]
    fn bit_conversion_round_trips_for_every_length_we_use() {
        for length in [1_usize, 2, 20, 31, 32, 33] {
            let payload = vec![0x9c_u8; length];
            let five = convert_bits(&payload, 8, 5, true).unwrap();
            let eight = convert_bits(&five, 5, 8, false).unwrap();
            assert_eq!(eight, payload, "round trip failed at {length} bytes");
        }
    }
}
