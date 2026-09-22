// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The canonical encoding.
//!
//! Implements `spec/draft/01-canonical-encoding.md`. The property this module
//! exists to provide is **bijectivity**: every valid object has exactly one
//! valid encoding, and every valid encoding decodes to exactly one object.
//!
//! The second half is the half that gets forgotten, and it is the half that
//! matters here. An encoder that only ever emits canonical bytes is easy. A
//! decoder that *rejects* the non-canonical encoding of an object it could have
//! understood is the work — and without it, an attacker can produce two byte
//! strings that a node treats as the same transaction but that hash
//! differently, which is a transaction-malleability bug and, in a chain whose
//! fraud proofs are "two signatures over the same thing", an equivocation
//! forgery.
//!
//! Hence the rule enforced throughout: **a decoder never normalises.** It
//! accepts the one encoding or it errors.

use core::fmt;

/// Largest single top-level object this codec will decode.
pub const MAX_OBJECT_SIZE: usize = 1_048_576;
/// Largest element count in any sequence, set or map.
pub const MAX_SEQ_LEN: usize = 65_536;
/// Largest length-prefixed byte string or UTF-8 string.
pub const MAX_BYTES_LEN: usize = 1_048_576;
/// Deepest nesting of composite types.
pub const MAX_NESTING: usize = 32;
/// Widest legal `varint`, the width of `u64::MAX`.
pub const MAX_VARINT_BYTES: usize = 10;

/// Anything that can go wrong while decoding.
///
/// Encoding cannot fail except through the ordering check in
/// [`Encoder::write_set`], which is a caller bug rather than hostile input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// The input ended in the middle of a value.
    UnexpectedEnd {
        /// What was being read.
        wanted: &'static str,
    },
    /// Bytes remained after a complete top-level object was decoded.
    ///
    /// Not a harmless condition: trailing bytes are a second place to put data
    /// that hashes differently but parses the same.
    TrailingBytes(usize),
    /// A `varint` was encoded with more bytes than necessary.
    NonCanonicalVarint,
    /// A `varint` was wider than ten bytes.
    VarintTooWide,
    /// A `varint` decoded to a value too large for its declared field.
    VarintOverflow {
        /// The narrower type it had to fit.
        target: &'static str,
    },
    /// A `bool` was a byte other than `0x00` or `0x01`.
    NonCanonicalBool(u8),
    /// An `Option` tag was a byte other than `0x00` or `0x01`.
    BadOptionTag(u8),
    /// A declared length exceeded the limit for its kind.
    LimitExceeded {
        /// Which limit.
        limit: &'static str,
        /// The limit's value.
        max: usize,
        /// What was declared.
        got: usize,
    },
    /// A declared length exceeded the bytes actually remaining.
    LengthBeyondInput {
        /// What was declared.
        declared: usize,
        /// What remained.
        remaining: usize,
    },
    /// A `string` was not valid UTF-8.
    InvalidUtf8,
    /// Elements of a set or map were not in strictly ascending order.
    UnorderedSet {
        /// Index of the offending element.
        index: usize,
    },
    /// Composite nesting exceeded [`MAX_NESTING`].
    TooDeep,
    /// An enum discriminant is not one this version defines.
    UnknownVariant {
        /// The enum's name, for the message.
        enum_name: &'static str,
        /// The discriminant read.
        discriminant: u64,
    },
    /// A field held a structurally valid value that the schema forbids —
    /// a zero amount where a positive one is required, a reserved algorithm id.
    Invalid {
        /// What was wrong, in words.
        reason: &'static str,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd { wanted } => write!(f, "input ended while reading {wanted}"),
            Self::TrailingBytes(count) => {
                write!(f, "{count} trailing bytes after a complete object")
            }
            Self::NonCanonicalVarint => {
                write!(f, "varint is not in shortest form")
            }
            Self::VarintTooWide => write!(f, "varint wider than {MAX_VARINT_BYTES} bytes"),
            Self::VarintOverflow { target } => write!(f, "varint does not fit in {target}"),
            Self::NonCanonicalBool(byte) => {
                write!(f, "bool must be 0x00 or 0x01, got 0x{byte:02x}")
            }
            Self::BadOptionTag(byte) => {
                write!(f, "option tag must be 0x00 or 0x01, got 0x{byte:02x}")
            }
            Self::LimitExceeded { limit, max, got } => {
                write!(f, "{limit} is at most {max}, got {got}")
            }
            Self::LengthBeyondInput { declared, remaining } => {
                write!(f, "declared length {declared} exceeds {remaining} bytes remaining")
            }
            Self::InvalidUtf8 => write!(f, "string is not valid UTF-8"),
            Self::UnorderedSet { index } => {
                write!(f, "set element {index} is not greater than its predecessor")
            }
            Self::TooDeep => write!(f, "nesting deeper than {MAX_NESTING}"),
            Self::UnknownVariant { enum_name, discriminant } => {
                write!(f, "unknown {enum_name} discriminant {discriminant}")
            }
            Self::Invalid { reason } => write!(f, "invalid: {reason}"),
        }
    }
}

impl std::error::Error for CodecError {}

/// A type with a canonical encoding.
pub trait Encode {
    /// Appends this value's canonical encoding to `out`.
    fn encode(&self, out: &mut Encoder);

    /// This value's canonical encoding, standalone.
    #[must_use]
    fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder);
        encoder.finish()
    }
}

/// A type that can be decoded from its canonical encoding.
pub trait Decode: Sized {
    /// Reads one value from `input`, leaving the cursor after it.
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError>;

    /// Decodes a complete object, requiring that `bytes` is consumed entirely.
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut decoder = Decoder::new(bytes)?;
        let value = Self::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }
}

/// Accumulates canonical bytes.
#[derive(Debug, Default, Clone)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// A new, empty encoder.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// A new encoder with room reserved.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self { buf: Vec::with_capacity(capacity) }
    }

    /// The bytes written so far.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Consumes the encoder, returning its bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Writes one raw byte.
    pub fn write_u8(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    /// Writes a `u16` little-endian, fixed width.
    pub fn write_u16(&mut self, value: u16) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Writes a `bool` as `0x00` or `0x01`.
    pub fn write_bool(&mut self, value: bool) -> &mut Self {
        self.buf.push(u8::from(value));
        self
    }

    /// Writes an unsigned LEB128 `varint` in shortest form.
    pub fn write_varint(&mut self, mut value: u64) -> &mut Self {
        while value >= 0x80 {
            // The mask keeps seven bits, so the conversion is exact; the
            // fallback exists only so that no path here can panic.
            let byte = u8::try_from(value & 0x7f).unwrap_or(0) | 0x80;
            self.buf.push(byte);
            value >>= 7;
        }
        self.buf.push(u8::try_from(value & 0x7f).unwrap_or(0));
        self
    }

    /// Writes a length prefix, saturating rather than wrapping.
    ///
    /// Public so that a type whose shape the generic helpers do not fit — an
    /// ordered map written as interleaved keys and values, say — can still emit
    /// the same length encoding as everything else rather than inventing one.
    ///
    /// A length that does not fit in a `u64` cannot occur on a 64-bit target
    /// and would be rejected by the decoder's limits anyway; saturating keeps
    /// the function total.
    pub fn write_len(&mut self, length: usize) -> &mut Self {
        self.write_varint(u64::try_from(length).unwrap_or(u64::MAX))
    }

    /// Writes raw bytes with no length prefix. For fixed-width fields.
    pub fn write_raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Writes a length-prefixed byte string.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.write_len(bytes.len());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Writes a length-prefixed UTF-8 string.
    pub fn write_str(&mut self, text: &str) -> &mut Self {
        self.write_bytes(text.as_bytes())
    }

    /// Writes an optional value.
    pub fn write_option<T: Encode>(&mut self, value: Option<&T>) -> &mut Self {
        match value {
            None => self.write_u8(0),
            Some(inner) => {
                self.write_u8(1);
                inner.encode(self);
                self
            }
        }
    }

    /// Writes a sequence: count, then elements in order.
    pub fn write_seq<T: Encode>(&mut self, items: &[T]) -> &mut Self {
        self.write_len(items.len());
        for item in items {
            item.encode(self);
        }
        self
    }

    /// Writes a set: count, then elements in strictly ascending encoded order.
    ///
    /// Returns an error rather than silently sorting. Sorting here would hide a
    /// caller that built a set in a non-deterministic order, which is the
    /// failure this whole encoding exists to make impossible — the bug would
    /// simply move to whichever other component forgot to sort.
    ///
    /// # Ordering is by encoded bytes, which is not numeric order
    ///
    /// For `varint`-encoded elements the two differ: 255 encodes as
    /// `ff 01` and 256 as `80 02`, so 255 sorts *after* 256. This is not a
    /// defect in the rule — comparing encoded bytes is what a verifier can
    /// check without decoding — but it does mean a caller must not assume that
    /// a numerically sorted `Vec<u64>` is a valid set. In practice every set in
    /// the protocol holds fixed-width 32-byte identifiers, where encoded order,
    /// byte order and `Ord` all coincide; see `01-canonical-encoding.md` §3.3.
    ///
    /// Prefer [`Encoder::write_ordered_set`] wherever the value can be held in
    /// a `BTreeSet`: this function has to be able to fail, `Encode::encode`
    /// cannot, and a caller that ignores the error emits a truncated object.
    pub fn write_set<T: Encode>(&mut self, items: &[T]) -> Result<&mut Self, CodecError> {
        let mut previous: Option<Vec<u8>> = None;
        for (index, item) in items.iter().enumerate() {
            let encoded = item.to_canonical_bytes();
            if let Some(ref last) = previous {
                if encoded.as_slice() <= last.as_slice() {
                    return Err(CodecError::UnorderedSet { index });
                }
            }
            previous = Some(encoded);
        }
        Ok(self.write_seq(items))
    }
}

impl Encoder {
    /// Writes a `BTreeSet` as a canonical set.
    ///
    /// Cannot fail, which is why it exists. A `BTreeSet<T>` whose `Ord` agrees
    /// with its encoded byte order is *already* a canonical set, so there is
    /// nothing left to check and nothing for a caller to ignore. Every set in
    /// the protocol holds fixed-width identifiers, for which the two orders are
    /// the same comparison — a set over a `varint`-encoded element type would
    /// need [`Encoder::write_set`] and its error instead.
    pub fn write_ordered_set<T: Encode + Ord>(
        &mut self,
        items: &std::collections::BTreeSet<T>,
    ) -> &mut Self {
        self.write_len(items.len());
        for item in items {
            item.encode(self);
        }
        self
    }
}

/// Reads canonical bytes.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
    depth: usize,
}

impl<'a> Decoder<'a> {
    /// Wraps an input buffer, rejecting one larger than [`MAX_OBJECT_SIZE`].
    pub fn new(input: &'a [u8]) -> Result<Self, CodecError> {
        if input.len() > MAX_OBJECT_SIZE {
            return Err(CodecError::LimitExceeded {
                limit: "object size",
                max: MAX_OBJECT_SIZE,
                got: input.len(),
            });
        }
        Ok(Self { input, position: 0, depth: 0 })
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    /// How many bytes have been consumed.
    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Requires that the input has been consumed entirely.
    ///
    /// Trailing bytes are an error, not a courtesy: they are a second place to
    /// put data that changes an object's hash without changing how it parses.
    pub fn finish(&self) -> Result<(), CodecError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes(self.remaining()))
        }
    }

    fn take(&mut self, count: usize, wanted: &'static str) -> Result<&'a [u8], CodecError> {
        let end = self.position.checked_add(count).ok_or(CodecError::UnexpectedEnd { wanted })?;
        let slice = self
            .input
            .get(self.position..end)
            .ok_or(CodecError::UnexpectedEnd { wanted })?;
        self.position = end;
        Ok(slice)
    }

    /// Reads one raw byte.
    pub fn read_u8(&mut self) -> Result<u8, CodecError> {
        let slice = self.take(1, "u8")?;
        slice.first().copied().ok_or(CodecError::UnexpectedEnd { wanted: "u8" })
    }

    /// Reads a fixed-width little-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, CodecError> {
        let slice = self.take(2, "u16")?;
        let array: [u8; 2] =
            slice.try_into().map_err(|_| CodecError::UnexpectedEnd { wanted: "u16" })?;
        Ok(u16::from_le_bytes(array))
    }

    /// Reads a `bool`, rejecting any byte but `0x00` and `0x01`.
    pub fn read_bool(&mut self) -> Result<bool, CodecError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(CodecError::NonCanonicalBool(other)),
        }
    }

    /// Reads a `varint`, enforcing shortest form, width and overflow.
    ///
    /// The three checks are the whole point. Without the shortest-form check,
    /// `81 00` and `01` both mean 1 and a transaction has two encodings.
    pub fn read_varint(&mut self) -> Result<u64, CodecError> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        let mut bytes_read: usize = 0;

        loop {
            let byte = self.read_u8()?;
            bytes_read = bytes_read.saturating_add(1);
            if bytes_read > MAX_VARINT_BYTES {
                return Err(CodecError::VarintTooWide);
            }

            let payload = u64::from(byte & 0x7f);
            // On the tenth byte only one payload bit fits in a u64.
            let fits = shift < 64 && (payload << shift.min(63)) >> shift.min(63) == payload;
            if !fits {
                return Err(CodecError::VarintOverflow { target: "u64" });
            }
            value |= payload << shift;

            if byte & 0x80 == 0 {
                // Shortest form: a multi-byte encoding whose last byte is zero
                // could have been written shorter. The single byte 0x00 is the
                // canonical encoding of zero and is exempt.
                if bytes_read > 1 && byte == 0 {
                    return Err(CodecError::NonCanonicalVarint);
                }
                return Ok(value);
            }

            shift = shift.saturating_add(7);
            if shift >= 64 && bytes_read >= MAX_VARINT_BYTES {
                return Err(CodecError::VarintTooWide);
            }
        }
    }

    /// Reads a `varint` that must fit in a `u32`.
    pub fn read_varint_u32(&mut self) -> Result<u32, CodecError> {
        let value = self.read_varint()?;
        u32::try_from(value).map_err(|_| CodecError::VarintOverflow { target: "u32" })
    }

    /// Reads a `varint` that must fit in a `u8`.
    pub fn read_varint_u8(&mut self) -> Result<u8, CodecError> {
        let value = self.read_varint()?;
        u8::try_from(value).map_err(|_| CodecError::VarintOverflow { target: "u8" })
    }

    /// Reads a `varint` length, checking it against a limit *and* against the
    /// bytes actually remaining.
    ///
    /// The second check is what stops a 40-byte hostile message from making a
    /// node reserve a gigabyte: the allocation never happens, because the
    /// declared length is compared to the input before anything is allocated.
    fn read_length(&mut self, limit: &'static str, max: usize) -> Result<usize, CodecError> {
        let declared = self.read_varint()?;
        let declared =
            usize::try_from(declared).map_err(|_| CodecError::VarintOverflow { target: "usize" })?;
        if declared > max {
            return Err(CodecError::LimitExceeded { limit, max, got: declared });
        }
        if declared > self.remaining() {
            return Err(CodecError::LengthBeyondInput {
                declared,
                remaining: self.remaining(),
            });
        }
        Ok(declared)
    }

    /// Reads `count` raw bytes, with no length prefix.
    ///
    /// For fields whose width is fixed by something outside the encoding — a
    /// public key, whose length is a property of its algorithm. Checks the
    /// input before anything is allocated.
    pub fn read_raw(&mut self, count: usize) -> Result<&'a [u8], CodecError> {
        if count > self.remaining() {
            return Err(CodecError::LengthBeyondInput {
                declared: count,
                remaining: self.remaining(),
            });
        }
        self.take(count, "raw bytes")
    }

    /// Reads exactly `N` raw bytes.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let slice = self.take(N, "fixed-width array")?;
        slice.try_into().map_err(|_| CodecError::UnexpectedEnd { wanted: "fixed-width array" })
    }

    /// Reads a length-prefixed byte string.
    pub fn read_bytes(&mut self) -> Result<&'a [u8], CodecError> {
        let length = self.read_length("byte string length", MAX_BYTES_LEN)?;
        self.take(length, "byte string")
    }

    /// Reads a length-prefixed UTF-8 string.
    pub fn read_str(&mut self) -> Result<&'a str, CodecError> {
        let bytes = self.read_bytes()?;
        core::str::from_utf8(bytes).map_err(|_| CodecError::InvalidUtf8)
    }

    /// Reads an optional value.
    pub fn read_option<T: Decode>(&mut self) -> Result<Option<T>, CodecError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.nested(T::decode)?)),
            other => Err(CodecError::BadOptionTag(other)),
        }
    }

    /// Reads a sequence.
    pub fn read_seq<T: Decode>(&mut self) -> Result<Vec<T>, CodecError> {
        let count = self.read_seq_len()?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(self.nested(T::decode)?);
        }
        Ok(items)
    }

    /// Reads a set, checking strictly ascending encoded order.
    ///
    /// The order check is done on the input bytes themselves rather than by
    /// re-encoding the decoded values, which means it also catches an element
    /// that was encoded non-canonically in a way its own decoder happened to
    /// tolerate.
    pub fn read_set<T: Decode>(&mut self) -> Result<Vec<T>, CodecError> {
        let count = self.read_seq_len()?;
        let mut items = Vec::with_capacity(count);
        let mut previous: Option<&'a [u8]> = None;
        for index in 0..count {
            let start = self.position;
            let item = self.nested(T::decode)?;
            let encoded =
                self.input.get(start..self.position).ok_or(CodecError::UnexpectedEnd {
                    wanted: "set element",
                })?;
            if let Some(last) = previous {
                if encoded <= last {
                    return Err(CodecError::UnorderedSet { index });
                }
            }
            previous = Some(encoded);
            items.push(item);
        }
        Ok(items)
    }

    /// Reads a sequence count, checked against [`MAX_SEQ_LEN`] and against the
    /// bytes actually remaining.
    ///
    /// The counterpart of [`Encoder::write_len`], for a type that reads its
    /// elements itself. An element occupies at least one byte, so a count
    /// larger than the remaining input is a lie — which is what keeps
    /// `Vec::with_capacity` honest on hostile input.
    pub fn read_seq_len(&mut self) -> Result<usize, CodecError> {
        let declared = self.read_varint()?;
        let declared =
            usize::try_from(declared).map_err(|_| CodecError::VarintOverflow { target: "usize" })?;
        if declared > MAX_SEQ_LEN {
            return Err(CodecError::LimitExceeded {
                limit: "sequence length",
                max: MAX_SEQ_LEN,
                got: declared,
            });
        }
        // An element is at least one byte, so a count larger than the remaining
        // input is a lie. This is what keeps `Vec::with_capacity` honest.
        if declared > self.remaining() {
            return Err(CodecError::LengthBeyondInput {
                declared,
                remaining: self.remaining(),
            });
        }
        Ok(declared)
    }

    /// Runs `f` one level deeper, enforcing [`MAX_NESTING`].
    pub fn nested<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, CodecError>,
    ) -> Result<T, CodecError> {
        if self.depth >= MAX_NESTING {
            return Err(CodecError::TooDeep);
        }
        self.depth = self.depth.saturating_add(1);
        let result = f(self);
        self.depth = self.depth.saturating_sub(1);
        result
    }
}

// --- Primitive implementations -------------------------------------------

impl Encode for u64 {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(*self);
    }
}

impl Decode for u64 {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        input.read_varint()
    }
}

impl Encode for u32 {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(u64::from(*self));
    }
}

impl Decode for u32 {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        input.read_varint_u32()
    }
}

impl Encode for u8 {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(u64::from(*self));
    }
}

impl Decode for u8 {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        input.read_varint_u8()
    }
}

impl Encode for bool {
    fn encode(&self, out: &mut Encoder) {
        out.write_bool(*self);
    }
}

impl Decode for bool {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        input.read_bool()
    }
}

impl Encode for Vec<u8> {
    fn encode(&self, out: &mut Encoder) {
        out.write_bytes(self);
    }
}

impl Decode for Vec<u8> {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(input.read_bytes()?.to_vec())
    }
}

impl Encode for String {
    fn encode(&self, out: &mut Encoder) {
        out.write_str(self);
    }
}

impl Decode for String {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(input.read_str()?.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CodecError, Decode, Decoder, Encode, Encoder, MAX_SEQ_LEN, MAX_VARINT_BYTES,
    };

    fn varint(value: u64) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.write_varint(value);
        encoder.finish()
    }

    fn read_varint(bytes: &[u8]) -> Result<u64, CodecError> {
        let mut decoder = Decoder::new(bytes).unwrap();
        let value = decoder.read_varint()?;
        decoder.finish()?;
        Ok(value)
    }

    #[test]
    fn varint_matches_the_specification_table() {
        assert_eq!(varint(0), vec![0x00]);
        assert_eq!(varint(1), vec![0x01]);
        assert_eq!(varint(127), vec![0x7f]);
        assert_eq!(varint(128), vec![0x80, 0x01]);
        assert_eq!(varint(300), vec![0xac, 0x02]);
        assert_eq!(varint(u64::from(u32::MAX)), vec![0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert_eq!(
            varint(u64::MAX),
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
    }

    #[test]
    fn varint_round_trips_over_a_wide_range() {
        let mut value: u64 = 0;
        loop {
            assert_eq!(read_varint(&varint(value)), Ok(value), "failed at {value}");
            let Some(next) = value.checked_mul(3).and_then(|v| v.checked_add(1)) else { break };
            value = next;
        }
        assert_eq!(read_varint(&varint(u64::MAX)), Ok(u64::MAX));
    }

    #[test]
    fn non_canonical_varints_are_rejected() {
        // This is the malleability test. Each of these is a longer encoding of
        // a value that has a shorter one.
        assert_eq!(read_varint(&[0x81, 0x00]), Err(CodecError::NonCanonicalVarint));
        assert_eq!(read_varint(&[0x80, 0x00]), Err(CodecError::NonCanonicalVarint));
        assert_eq!(
            read_varint(&[0xff, 0x80, 0x00]),
            Err(CodecError::NonCanonicalVarint)
        );
        // Ten bytes ending in zero is still non-canonical.
        assert_eq!(
            read_varint(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]),
            Err(CodecError::NonCanonicalVarint)
        );
        // But a single zero byte is the canonical zero.
        assert_eq!(read_varint(&[0x00]), Ok(0));
    }

    #[test]
    fn overwide_varints_are_rejected() {
        let too_many = vec![0x80_u8; MAX_VARINT_BYTES + 1];
        assert!(matches!(
            read_varint(&too_many),
            Err(CodecError::VarintTooWide | CodecError::UnexpectedEnd { .. })
        ));
    }

    #[test]
    fn varints_that_overflow_their_target_are_rejected() {
        // 2^32, one past u32::MAX.
        let mut encoder = Encoder::new();
        encoder.write_varint(1_u64 << 32);
        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes).unwrap();
        assert_eq!(
            decoder.read_varint_u32(),
            Err(CodecError::VarintOverflow { target: "u32" })
        );
    }

    #[test]
    fn a_truncated_varint_is_an_error_not_a_value() {
        assert!(matches!(read_varint(&[0x80]), Err(CodecError::UnexpectedEnd { .. })));
        assert!(matches!(read_varint(&[]), Err(CodecError::UnexpectedEnd { .. })));
    }

    #[test]
    fn bools_are_exactly_two_bytes() {
        for byte in 0_u8..=255 {
            let buf = [byte];
            let mut decoder = Decoder::new(&buf).unwrap();
            match byte {
                0 => assert_eq!(decoder.read_bool(), Ok(false)),
                1 => assert_eq!(decoder.read_bool(), Ok(true)),
                other => {
                    assert_eq!(decoder.read_bool(), Err(CodecError::NonCanonicalBool(other)));
                }
            }
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = varint(1);
        bytes.push(0x00);
        assert_eq!(read_varint(&bytes), Err(CodecError::TrailingBytes(1)));
    }

    #[test]
    fn a_declared_length_beyond_the_input_does_not_allocate() {
        // A four-byte message claiming a gigabyte. The error must be about the
        // input, not about memory.
        let mut encoder = Encoder::new();
        encoder.write_varint(1_000_000);
        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes).unwrap();
        assert!(matches!(
            decoder.read_bytes(),
            Err(CodecError::LengthBeyondInput { .. })
        ));
    }

    #[test]
    fn an_oversized_sequence_count_is_rejected_before_allocating() {
        let mut encoder = Encoder::new();
        encoder.write_varint(u64::try_from(MAX_SEQ_LEN).unwrap() + 1);
        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes).unwrap();
        assert!(matches!(
            decoder.read_seq::<u64>(),
            Err(CodecError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn byte_strings_round_trip() {
        let cases: Vec<Vec<u8>> = vec![vec![], vec![0], vec![0xff; 300]];
        for case in cases {
            let encoded = case.to_canonical_bytes();
            assert_eq!(Vec::<u8>::from_canonical_bytes(&encoded), Ok(case));
        }
    }

    #[test]
    fn strings_must_be_utf8() {
        let mut encoder = Encoder::new();
        encoder.write_bytes(&[0xff, 0xfe]);
        let bytes = encoder.finish();
        assert_eq!(String::from_canonical_bytes(&bytes), Err(CodecError::InvalidUtf8));
    }

    #[test]
    fn options_reject_tags_other_than_zero_and_one() {
        for byte in 2_u8..=255 {
            let buf = [byte];
            let mut decoder = Decoder::new(&buf).unwrap();
            assert_eq!(decoder.read_option::<u64>(), Err(CodecError::BadOptionTag(byte)));
        }
    }

    #[test]
    fn an_absent_option_is_not_a_present_zero() {
        let mut absent = Encoder::new();
        absent.write_option::<u64>(None);
        let mut present_zero = Encoder::new();
        present_zero.write_option(Some(&0_u64));
        assert_ne!(absent.finish(), present_zero.finish());
    }

    #[test]
    fn sets_must_be_strictly_ascending() {
        let mut encoder = Encoder::new();
        assert!(encoder.write_set(&[1_u64, 2, 3]).is_ok());

        let mut unsorted = Encoder::new();
        assert_eq!(
            unsorted.write_set(&[3_u64, 1, 2]).err(),
            Some(CodecError::UnorderedSet { index: 1 })
        );

        let mut duplicated = Encoder::new();
        assert_eq!(
            duplicated.write_set(&[1_u64, 1]).err(),
            Some(CodecError::UnorderedSet { index: 1 })
        );
    }

    #[test]
    fn a_decoder_rejects_an_unordered_set() {
        // Built by hand: a well-formed sequence that is not a well-formed set.
        let mut encoder = Encoder::new();
        encoder.write_seq(&[3_u64, 1, 2]);
        let bytes = encoder.finish();

        let mut as_seq = Decoder::new(&bytes).unwrap();
        assert_eq!(as_seq.read_seq::<u64>(), Ok(vec![3, 1, 2]));

        let mut as_set = Decoder::new(&bytes).unwrap();
        assert_eq!(as_set.read_set::<u64>(), Err(CodecError::UnorderedSet { index: 1 }));
    }

    #[test]
    fn a_decoder_rejects_a_duplicated_set_element() {
        let mut encoder = Encoder::new();
        encoder.write_seq(&[7_u64, 7]);
        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes).unwrap();
        assert_eq!(decoder.read_set::<u64>(), Err(CodecError::UnorderedSet { index: 1 }));
    }

    #[test]
    fn sets_round_trip_when_sorted() {
        let items = vec![1_u64, 2, 300, u64::MAX];
        let mut encoder = Encoder::new();
        encoder.write_set(&items).unwrap();
        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes).unwrap();
        assert_eq!(decoder.read_set::<u64>(), Ok(items));
    }

    #[test]
    fn set_ordering_is_by_encoded_bytes_not_by_value() {
        // Pinned deliberately. 255 encodes as `ff 01`, 256 as `80 02`, so the
        // numerically ascending pair [255, 256] is NOT a valid set while the
        // numerically descending pair [256, 255] is. Anyone who later "fixes"
        // this by sorting numerically will break verification against every
        // other implementation, so the surprising behaviour is asserted rather
        // than left to be rediscovered.
        let mut numeric = Encoder::new();
        assert_eq!(
            numeric.write_set(&[255_u64, 256]).err(),
            Some(CodecError::UnorderedSet { index: 1 })
        );

        let mut by_bytes = Encoder::new();
        assert!(by_bytes.write_set(&[256_u64, 255]).is_ok());
    }

    #[test]
    fn fixed_arrays_round_trip() {
        let mut encoder = Encoder::new();
        encoder.write_raw(&[0xaa; 32]);
        let bytes = encoder.finish();
        assert_eq!(bytes.len(), 32, "a fixed array must not carry a length prefix");
        let mut decoder = Decoder::new(&bytes).unwrap();
        assert_eq!(decoder.read_array::<32>(), Ok([0xaa; 32]));
        assert_eq!(decoder.finish(), Ok(()));
    }

    #[test]
    fn nesting_is_bounded() {
        let mut decoder = Decoder::new(&[0x00]).unwrap();
        fn deep(decoder: &mut Decoder<'_>, remaining: u32) -> Result<(), CodecError> {
            if remaining == 0 {
                return Ok(());
            }
            decoder.nested(|inner| deep(inner, remaining - 1))
        }
        assert_eq!(deep(&mut decoder, 32), Ok(()));
        assert_eq!(deep(&mut decoder, 33), Err(CodecError::TooDeep));
    }

    #[test]
    fn u16_is_fixed_width_little_endian() {
        let mut encoder = Encoder::new();
        encoder.write_u16(0x0102);
        let bytes = encoder.finish();
        assert_eq!(bytes, vec![0x02, 0x01]);
        let mut decoder = Decoder::new(&bytes).unwrap();
        assert_eq!(decoder.read_u16(), Ok(0x0102));
    }
}
