// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block headers, the finality ladder, and the clocks that run on it.
//!
//! See `spec/draft/05-blocks.md`.
//!
//! # There is no timestamp
//!
//! A Vanargand block header carries no wall-clock time, and this is the most
//! visible consequence of `CONTRIBUTING.md`'s rule that "la seule horloge est la
//! hauteur de bloc". Every other chain carries one and every other chain then
//! has to decide what to do when a proposer lies about it.
//!
//! Nothing in the protocol needs one. Epochs are `height / EPOCH_BLOCKS`.
//! Contestation windows are counted in finalised height. The archive market's
//! timed-response challenges measure latency at the transport layer, between
//! two parties, and never enter state. Adding a timestamp would create an
//! input that a proposer controls, that honest nodes cannot check, and that
//! nothing reads.

use core::fmt;

use vanargand_crypto::hash::{domain, Hash, Hasher};
use vanargand_crypto::sign::{Signature, VerifyingKey};

use crate::amount::{Amount, Ratio};
use crate::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use crate::id::{AccountId, BlockId, ChainId};

/// The consensus parameters of `docs/04-proof-of-service.pdf` §9.
///
/// Every one of these is a **point of departure to be fixed by simulation**,
/// not a frozen constant. They are gathered here so that a change is one edit
/// and so that a simulation can report which values it ran with.
pub mod params {
    /// Blocks per epoch. One hour at five seconds a block.
    pub const EPOCH_BLOCKS: u64 = 720;

    /// Nominal seconds between blocks.
    ///
    /// **Not a consensus parameter.** Nothing validates against it; it exists
    /// so that operational tooling can turn heights into rough durations for a
    /// human. Constrained by worldwide network latency.
    pub const NOMINAL_BLOCK_SECONDS: u64 = 5;

    /// Committee members active at any one block.
    pub const COMMITTEE_ACTIVE: u32 = 64;

    /// Committee members drawn per epoch: three times the active count (R1).
    ///
    /// The oversampling is real, but R2 requires it to be described honestly:
    /// which 64 of the 192 activate is derived from the epoch seed and is
    /// therefore **known an hour in advance**. What protects a validator from
    /// being targeted is not unpredictability it does not have — it is the
    /// sentinel architecture, rotating relays in front of the validator, so
    /// that knowing an identity does not give an address.
    pub const COMMITTEE_SAMPLED: u32 = COMMITTEE_ACTIVE * 3;

    /// Numerator of the finality threshold: strictly more than two thirds.
    pub const FINALITY_NUMERATOR: u64 = 2;
    /// Denominator of the finality threshold.
    pub const FINALITY_DENOMINATOR: u64 = 3;

    /// Bond withdrawal delay, in epochs. About three weeks.
    ///
    /// The window during which a fraud committed while bonded can still be
    /// denounced. A bond that could leave faster than evidence can travel is
    /// not a bond.
    pub const UNBONDING_EPOCHS: u64 = 504;
}

/// The three rungs of the finality ladder.
///
/// `docs/04-proof-of-service.pdf` §5 replaces the usual all-or-nothing finality
/// with a public scale, because a protocol whose normal operating condition is
/// partition cannot afford a consensus that stops when a third of its
/// validators are unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FinalityRung {
    /// Rung 1 — local finality. A cut-off group keeps producing blocks with
    /// the validators it has. Honestly stamped as provisional, replayed on
    /// reconnection, and the full chain always has the last word.
    ///
    /// "C'est un chèque : presque toujours honoré, garanti à l'encaissement."
    Provisional = 1,

    /// Rung 2 — chain finality. More than two thirds of the committee's weight
    /// has signed. Seconds, and permanent.
    Chain = 2,

    /// Rung 3 — federal finality. The chain's milestone has been anchored with
    /// its neighbours, so that even collusion of every one of its validators
    /// cannot rewrite that past.
    ///
    /// **Never a value in a header.** Federal finality is conferred by other
    /// chains after the fact; a block cannot claim it about itself. Reserved
    /// here so that the application-facing scale is one type.
    Federal = 3,
}

impl FinalityRung {
    /// Whether a block header may claim this rung.
    ///
    /// A proposer declares Provisional or Chain. Federal is not a claim a
    /// header can make about itself.
    #[must_use]
    pub const fn claimable_by_a_header(self) -> bool {
        matches!(self, Self::Provisional | Self::Chain)
    }
}

impl fmt::Display for FinalityRung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Provisional => "provisional",
            Self::Chain => "chain",
            Self::Federal => "federal",
        })
    }
}

impl Encode for FinalityRung {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(u64::from(*self as u8));
    }
}

impl Decode for FinalityRung {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        match input.read_varint()? {
            1 => Ok(Self::Provisional),
            2 => Ok(Self::Chain),
            3 => Ok(Self::Federal),
            other => {
                Err(CodecError::UnknownVariant { enum_name: "FinalityRung", discriminant: other })
            }
        }
    }
}

/// The header version this build writes.
pub const HEADER_VERSION: u16 = 1;

/// A block header.
///
/// Fields are encoded in declaration order; adding one is a compatibility
/// break. The ordering below groups them by who reads them: chain position
/// first, then commitments, then the proposer's contribution, then the health
/// metrics that `docs/05-emission.pdf` §4 requires every header to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// Header format version.
    pub version: u16,
    /// Which chain. Present although the signature also covers it — thirty-two
    /// bytes against a 2420-byte signature is not a cost, and it makes a block
    /// identifier globally meaningful rather than meaningful only next to the
    /// signature that binds it.
    pub chain: ChainId,
    /// Height above genesis. Genesis is zero.
    pub height: u64,
    /// The previous block. [`BlockId::ZERO`] at genesis.
    pub parent: BlockId,

    /// The rung this block claims: [`FinalityRung::Provisional`] or
    /// [`FinalityRung::Chain`].
    ///
    /// The proposer declares it, and the declaration changes which
    /// transactions are grammatically legal — see
    /// [`crate::tx::TxKind::allowed_in_provisional`]. A block claiming Chain
    /// that never collects two thirds is simply not final; a block claiming
    /// Provisional can never become final without being replayed.
    pub rung: FinalityRung,

    /// The height of the most recent rung-2 block this one builds on.
    ///
    /// **This is the C9 parade, made into a field.** Every contestation clock
    /// in the protocol is counted in this number and never in `height`. An
    /// attacker who forces a partition and publishes a stale channel closure
    /// into provisional blocks gains nothing, because the window during which
    /// the counterparty could object does not advance while the counterparty
    /// cannot exist.
    pub finalized_height: u64,

    /// Root of the sparse Merkle tree of state after this block.
    pub state_root: Hash,
    /// Root of the Merkle tree over this block's transaction identifiers.
    pub tx_root: Hash,

    /// The account that proposed this block.
    pub proposer: AccountId,

    /// The next link of the proposer's commitment chain (A4).
    ///
    /// Revealing and proposing are one act, which is why R2 could drop the
    /// slashing penalty for non-revelation: a proposer that withholds simply
    /// misses its turn, and a crash and a deliberate withholding no longer
    /// need to be told apart.
    pub randomness_reveal: Hash,

    /// Commitment to the slice of chain history archived at this height.
    ///
    /// "Chaque tranche archivée laisse son empreinte dans un en-tête de bloc" —
    /// history leaves the validators' machines but stays verifiable forever.
    pub archive_commitment: Hash,

    /// Total VAN this chain has ever emitted, in ulf.
    ///
    /// One number, comparable in an instant against what the formula permits at
    /// this height. It is what makes a chain auditable from a distance in a few
    /// kilobytes, and therefore what makes the VAN zone possible at all.
    pub emitted_supply: Amount,

    /// The security budget: a third of bonded stake, the cost of attacking
    /// finality. Published per `docs/05-emission.pdf` §4.
    pub security_budget: Amount,

    /// Real fees over emission: how much of the network lives on its use rather
    /// than on subsidy.
    ///
    /// A fraction, carried as the two integers it was computed from. There is
    /// no floating point in this protocol, and a verifier that recomputes the
    /// comparison rather than the division gets an exact answer.
    pub fee_emission_ratio: Ratio,
}

impl BlockHeader {
    /// This header's identifier: `H[block id](canonical encoding)`.
    #[must_use]
    pub fn id(&self) -> BlockId {
        BlockId::from_hash(Hasher::new(domain::BLOCK_ID).update(&self.to_canonical_bytes()).finalize())
    }

    /// The digest a proposer signs: `H[block signing](chain_id ‖ block_id)`.
    #[must_use]
    pub fn signing_digest(&self) -> Hash {
        Hasher::new(domain::BLOCK_SIGNING)
            .update(self.chain.as_bytes())
            .update(self.id().as_bytes())
            .finalize()
    }

    /// The epoch this height falls in.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.height / params::EPOCH_BLOCKS
    }

    /// Whether this is the last block of its epoch.
    ///
    /// The committee for the next epoch is drawn here, seconds before it takes
    /// office rather than hours (R1.4).
    #[must_use]
    pub const fn is_epoch_boundary(&self) -> bool {
        (self.height % params::EPOCH_BLOCKS) == params::EPOCH_BLOCKS - 1
    }

    /// Structural checks that need no chain state.
    ///
    /// Deliberately narrow: everything here can be decided from the header
    /// alone. Anything needing the parent, the committee or the state belongs
    /// to `vanargand-consensus`.
    pub fn check_self_consistent(&self) -> Result<(), HeaderError> {
        if self.version != HEADER_VERSION {
            return Err(HeaderError::UnsupportedVersion(self.version));
        }
        if !self.rung.claimable_by_a_header() {
            return Err(HeaderError::UnclaimableRung(self.rung));
        }
        if self.finalized_height > self.height {
            return Err(HeaderError::FinalizedAhead {
                finalized: self.finalized_height,
                height: self.height,
            });
        }
        if self.rung == FinalityRung::Chain && self.finalized_height != self.height {
            // A block that claims chain finality *is* the finalised tip it
            // refers to. Letting the two differ would give a proposer a second
            // number to lie about, and every contestation clock in the protocol
            // reads that number.
            return Err(HeaderError::FinalizedAhead {
                finalized: self.finalized_height,
                height: self.height,
            });
        }
        if self.height == 0 && self.parent != BlockId::ZERO {
            return Err(HeaderError::GenesisHasParent);
        }
        if self.height != 0 && self.parent == BlockId::ZERO {
            return Err(HeaderError::MissingParent);
        }
        if !self.emitted_supply.within_cap() {
            return Err(HeaderError::SupplyOverCap(self.emitted_supply));
        }
        Ok(())
    }
}

impl Encode for BlockHeader {
    fn encode(&self, out: &mut Encoder) {
        out.write_u16(self.version);
        self.chain.encode(out);
        out.write_varint(self.height);
        self.parent.encode(out);
        self.rung.encode(out);
        out.write_varint(self.finalized_height);
        self.state_root.encode(out);
        self.tx_root.encode(out);
        self.proposer.encode(out);
        self.randomness_reveal.encode(out);
        self.archive_commitment.encode(out);
        self.emitted_supply.encode(out);
        self.security_budget.encode(out);
        self.fee_emission_ratio.encode(out);
    }
}

impl Decode for BlockHeader {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: input.read_u16()?,
            chain: ChainId::decode(input)?,
            height: input.read_varint()?,
            parent: BlockId::decode(input)?,
            rung: FinalityRung::decode(input)?,
            finalized_height: input.read_varint()?,
            state_root: Hash::decode(input)?,
            tx_root: Hash::decode(input)?,
            proposer: AccountId::decode(input)?,
            randomness_reveal: Hash::decode(input)?,
            archive_commitment: Hash::decode(input)?,
            emitted_supply: Amount::decode(input)?,
            security_budget: Amount::decode(input)?,
            fee_emission_ratio: Ratio::decode(input)?,
        })
    }
}

/// A header with its proposer's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeader {
    /// The header.
    pub header: BlockHeader,
    /// The proposer's signature over [`BlockHeader::signing_digest`].
    pub signature: Signature,
}

impl SignedHeader {
    /// Verifies the signature against a key.
    ///
    /// The caller supplies the key because this crate holds no validator set.
    /// It must also have checked that the key belongs to
    /// [`BlockHeader::proposer`]; this function verifies a signature, it does
    /// not establish authority.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), HeaderError> {
        if !key.algorithm().valid_on_live_chain() {
            return Err(HeaderError::TestAlgorithmOnLiveChain);
        }
        vanargand_crypto::sign::verify(
            key,
            self.header.signing_digest().as_bytes(),
            &self.signature,
        )
        .map_err(|_| HeaderError::BadSignature)
    }

    /// Verifies the signature without rejecting the test algorithm.
    ///
    /// For test networks and for the workspace's own tests. A production node
    /// must call [`SignedHeader::verify`].
    pub fn verify_allowing_test_algorithms(&self, key: &VerifyingKey) -> Result<(), HeaderError> {
        vanargand_crypto::sign::verify(
            key,
            self.header.signing_digest().as_bytes(),
            &self.signature,
        )
        .map_err(|_| HeaderError::BadSignature)
    }
}

impl Encode for SignedHeader {
    fn encode(&self, out: &mut Encoder) {
        self.header.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for SignedHeader {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self { header: BlockHeader::decode(input)?, signature: Signature::decode(input)? })
    }
}

/// Proof that a validator signed two different blocks at one height.
///
/// A2, resolved by construction: the fraud produces its own evidence. A few
/// hundred bytes, publishable by anyone on any chain, convicting automatically.
///
/// This is the *only* shape of validator misbehaviour that is slashed. R2's
/// first acknowledged error was a penalty for non-revelation, withdrawn because
/// a crash and a deliberate withholding produce the same silence and the
/// protocol must not punish what it cannot attribute. Equivocation is
/// attributable; absence is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorEquivocation {
    /// The accused.
    pub validator: AccountId,
    /// One signed header.
    pub first: SignedHeader,
    /// The other.
    pub second: SignedHeader,
}

impl ValidatorEquivocation {
    /// Checks that this really is equivocation, given the validator's key.
    ///
    /// Requires: same chain, same height, the same accused proposer on both,
    /// two *different* block identifiers, and two valid signatures. The
    /// different-identifier check is what stops a "proof" built by presenting
    /// one block twice.
    pub fn check(&self, key: &VerifyingKey) -> Result<(), HeaderError> {
        if self.first.header.chain != self.second.header.chain {
            return Err(HeaderError::EvidenceNotEquivocation { why: "different chains" });
        }
        if self.first.header.height != self.second.header.height {
            return Err(HeaderError::EvidenceNotEquivocation { why: "different heights" });
        }
        if self.first.header.proposer != self.validator
            || self.second.header.proposer != self.validator
        {
            return Err(HeaderError::EvidenceNotEquivocation { why: "not both by the accused" });
        }
        if self.first.header.id() == self.second.header.id() {
            return Err(HeaderError::EvidenceNotEquivocation { why: "the same block twice" });
        }
        self.first.verify_allowing_test_algorithms(key)?;
        self.second.verify_allowing_test_algorithms(key)?;
        Ok(())
    }
}

impl Encode for ValidatorEquivocation {
    fn encode(&self, out: &mut Encoder) {
        self.validator.encode(out);
        self.first.encode(out);
        self.second.encode(out);
    }
}

impl Decode for ValidatorEquivocation {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            validator: AccountId::decode(input)?,
            first: SignedHeader::decode(input)?,
            second: SignedHeader::decode(input)?,
        })
    }
}

/// A contestation window, counted in finalised height only.
///
/// The C9 parade as a type. Every deadline in Vanargand that protects an absent
/// party — a channel closure, a recovery, a bridge exit — is one of these, and
/// none of them can be run out inside a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContestationWindow {
    /// The finalised height at which the window opened.
    pub opened_at_finalized: u64,
    /// How many finalised blocks it lasts.
    pub duration: u64,
}

impl ContestationWindow {
    /// Opens a window at a header's finalised height.
    #[must_use]
    pub const fn open(header: &BlockHeader, duration: u64) -> Self {
        Self { opened_at_finalized: header.finalized_height, duration }
    }

    /// Whether the window has elapsed, as of a given finalised height.
    ///
    /// Takes a *finalised* height, and there is no overload that takes an
    /// ordinary one. Passing `header.height` here would be the C9 bug, so the
    /// type makes it a thing you have to write on purpose.
    #[must_use]
    pub const fn has_elapsed(&self, current_finalized_height: u64) -> bool {
        match self.opened_at_finalized.checked_add(self.duration) {
            // A window whose end overflows never elapses, which is the safe
            // direction: it protects the absent party forever rather than
            // expiring immediately.
            None => false,
            Some(deadline) => current_finalized_height >= deadline,
        }
    }
}

/// Why a header or a piece of header evidence was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderError {
    /// The header format version is not one this build understands.
    UnsupportedVersion(u16),
    /// The header claims a rung a header cannot claim.
    UnclaimableRung(FinalityRung),
    /// `finalized_height` is inconsistent with `height`.
    FinalizedAhead {
        /// The claimed finalised height.
        finalized: u64,
        /// This block's height.
        height: u64,
    },
    /// Genesis named a parent.
    GenesisHasParent,
    /// A non-genesis block named no parent.
    MissingParent,
    /// The emitted supply counter exceeds the protocol cap.
    SupplyOverCap(Amount),
    /// The signature did not verify.
    BadSignature,
    /// A key or signature used a test algorithm on a production chain.
    TestAlgorithmOnLiveChain,
    /// Evidence that does not show what it claims to show.
    EvidenceNotEquivocation {
        /// Which requirement failed.
        why: &'static str,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(f, "unsupported header version {version}"),
            Self::UnclaimableRung(rung) => write!(f, "a header cannot claim {rung} finality"),
            Self::FinalizedAhead { finalized, height } => {
                write!(f, "finalised height {finalized} is inconsistent with height {height}")
            }
            Self::GenesisHasParent => write!(f, "the genesis block named a parent"),
            Self::MissingParent => write!(f, "a non-genesis block named no parent"),
            Self::SupplyOverCap(amount) => write!(f, "emitted supply {amount} exceeds the cap"),
            Self::BadSignature => write!(f, "signature verification failed"),
            Self::TestAlgorithmOnLiveChain => {
                write!(f, "a test algorithm was used on a production chain")
            }
            Self::EvidenceNotEquivocation { why } => write!(f, "not equivocation: {why}"),
        }
    }
}

impl std::error::Error for HeaderError {}

#[cfg(test)]
mod tests {
    use super::{
        params, BlockHeader, ContestationWindow, FinalityRung, HeaderError, SignedHeader,
        ValidatorEquivocation, HEADER_VERSION,
    };
    use crate::amount::{Amount, Ratio};
    use crate::codec::{CodecError, Decode, Encode};
    use crate::id::{AccountId, BlockId, ChainId};
    use vanargand_crypto::algorithm::AlgorithmId;
    use vanargand_crypto::hash::Hash;
    use vanargand_crypto::sign::{self, Keypair};

    fn keypair(byte: u8) -> Keypair {
        sign::keypair_from_seed(AlgorithmId::InsecureTest, &Hash::from_bytes([byte; 32])).unwrap()
    }

    fn header(height: u64) -> BlockHeader {
        BlockHeader {
            version: HEADER_VERSION,
            chain: ChainId::from_hash(Hash::from_bytes([0x11; 32])),
            height,
            parent: if height == 0 {
                BlockId::ZERO
            } else {
                BlockId::from_hash(Hash::from_bytes([0x22; 32]))
            },
            rung: FinalityRung::Chain,
            finalized_height: height,
            state_root: Hash::from_bytes([0x33; 32]),
            tx_root: Hash::from_bytes([0x44; 32]),
            proposer: AccountId::from_hash(Hash::from_bytes([0x55; 32])),
            randomness_reveal: Hash::from_bytes([0x66; 32]),
            archive_commitment: Hash::from_bytes([0x77; 32]),
            emitted_supply: Amount::from_ulf(1_234),
            security_budget: Amount::from_ulf(5_678),
            fee_emission_ratio: Ratio::new(3, 7),
        }
    }

    #[test]
    fn headers_round_trip() {
        let original = header(100);
        let bytes = original.to_canonical_bytes();
        assert_eq!(BlockHeader::from_canonical_bytes(&bytes), Ok(original));
    }

    #[test]
    fn a_header_has_no_timestamp_field() {
        // Asserted through the encoding rather than by reading the struct: the
        // header is a fixed set of fields plus three varints, and its size is
        // pinned so that adding a field is a deliberate act with a failing test
        // attached.
        let bytes = header(1).to_canonical_bytes();
        // 2 (version) + 32 (chain) + varint height + 32 (parent) + 1 (rung)
        // + varint finalized + 32 + 32 + 32 + 32 + 32 + 3 varints.
        assert_eq!(bytes.len(), 2 + 32 + 1 + 32 + 1 + 1 + 32 * 5 + 2 + 2 + 2, "{bytes:?}");
    }

    #[test]
    fn the_identifier_changes_with_every_field() {
        let base = header(10);
        let baseline = base.id();

        let mut other = base.clone();
        other.height = 11;
        assert_ne!(other.id(), baseline);

        let mut other = base.clone();
        other.rung = FinalityRung::Provisional;
        assert_ne!(other.id(), baseline);

        let mut other = base.clone();
        other.emitted_supply = Amount::from_ulf(1_235);
        assert_ne!(other.id(), baseline);

        let mut other = base;
        other.fee_emission_ratio = Ratio::new(3, 8);
        assert_ne!(other.id(), baseline);
    }

    #[test]
    fn the_signing_digest_is_bound_to_the_chain() {
        // D4: a header signed for one chain must not verify on another.
        let mut a = header(5);
        let mut b = a.clone();
        b.chain = ChainId::from_hash(Hash::from_bytes([0x99; 32]));
        assert_ne!(a.signing_digest(), b.signing_digest());
        a.chain = b.chain;
        assert_eq!(a.signing_digest(), b.signing_digest());
    }

    #[test]
    fn epochs_are_derived_from_height_alone() {
        let mut candidate = header(0);
        assert_eq!(candidate.epoch(), 0);
        candidate.height = params::EPOCH_BLOCKS - 1;
        assert_eq!(candidate.epoch(), 0);
        assert!(candidate.is_epoch_boundary());
        candidate.height = params::EPOCH_BLOCKS;
        assert_eq!(candidate.epoch(), 1);
        assert!(!candidate.is_epoch_boundary());
    }

    #[test]
    fn self_consistency_rejects_the_obvious_lies() {
        assert_eq!(header(1).check_self_consistent(), Ok(()));

        let mut bad = header(1);
        bad.version = HEADER_VERSION + 1;
        assert_eq!(
            bad.check_self_consistent(),
            Err(HeaderError::UnsupportedVersion(HEADER_VERSION + 1))
        );

        let mut bad = header(1);
        bad.rung = FinalityRung::Federal;
        assert_eq!(
            bad.check_self_consistent(),
            Err(HeaderError::UnclaimableRung(FinalityRung::Federal))
        );

        let mut bad = header(5);
        bad.finalized_height = 6;
        assert!(matches!(bad.check_self_consistent(), Err(HeaderError::FinalizedAhead { .. })));

        let mut bad = header(0);
        bad.parent = BlockId::from_hash(Hash::from_bytes([1; 32]));
        assert_eq!(bad.check_self_consistent(), Err(HeaderError::GenesisHasParent));

        let mut bad = header(1);
        bad.parent = BlockId::ZERO;
        assert_eq!(bad.check_self_consistent(), Err(HeaderError::MissingParent));

        let mut bad = header(1);
        bad.emitted_supply = Amount::from_ulf(Amount::MAX.as_ulf() + 1);
        assert!(matches!(bad.check_self_consistent(), Err(HeaderError::SupplyOverCap(_))));
    }

    #[test]
    fn a_chain_rung_block_is_its_own_finalised_tip() {
        let mut candidate = header(10);
        candidate.rung = FinalityRung::Chain;
        candidate.finalized_height = 9;
        assert!(
            matches!(candidate.check_self_consistent(), Err(HeaderError::FinalizedAhead { .. })),
            "a block claiming chain finality was allowed to point its clocks elsewhere"
        );
    }

    #[test]
    fn a_provisional_block_may_lag_the_finalised_tip() {
        // The normal case in a partition: heights keep climbing while the
        // finalised tip stands still, which is precisely what stops every
        // contestation clock.
        let mut candidate = header(100);
        candidate.rung = FinalityRung::Provisional;
        candidate.finalized_height = 40;
        assert_eq!(candidate.check_self_consistent(), Ok(()));
    }

    #[test]
    fn a_contestation_window_does_not_run_during_a_partition() {
        // The C9 parade, end to end. A window opens at finalised height 40.
        // The partition then produces sixty provisional blocks. The window has
        // not moved, because nothing it counts has moved.
        let mut at_open = header(100);
        at_open.rung = FinalityRung::Provisional;
        at_open.finalized_height = 40;
        let window = ContestationWindow::open(&at_open, 10);

        let mut later = at_open.clone();
        later.height = 160;
        later.finalized_height = 40;
        assert!(
            !window.has_elapsed(later.finalized_height),
            "the window expired inside a partition; C9 is open"
        );

        // Only finalised progress moves it.
        assert!(window.has_elapsed(50));
        assert!(!window.has_elapsed(49));
    }

    #[test]
    fn a_window_whose_deadline_overflows_never_elapses() {
        let window = ContestationWindow { opened_at_finalized: u64::MAX, duration: 10 };
        assert!(!window.has_elapsed(u64::MAX), "an overflowing window expired immediately");
    }

    #[test]
    fn a_signed_header_verifies_and_a_tampered_one_does_not() {
        let pair = keypair(1);
        let mut candidate = header(7);
        candidate.proposer = AccountId::of_root_key(&pair.verifying);
        let signature =
            sign::sign(&pair.signing, candidate.signing_digest().as_bytes()).unwrap();
        let signed = SignedHeader { header: candidate.clone(), signature };
        assert_eq!(signed.verify_allowing_test_algorithms(&pair.verifying), Ok(()));

        let mut tampered = signed.clone();
        tampered.header.state_root = Hash::from_bytes([0xee; 32]);
        assert_eq!(
            tampered.verify_allowing_test_algorithms(&pair.verifying),
            Err(HeaderError::BadSignature)
        );
    }

    #[test]
    fn a_test_algorithm_signature_is_refused_by_the_production_path() {
        let pair = keypair(2);
        let candidate = header(3);
        let signature =
            sign::sign(&pair.signing, candidate.signing_digest().as_bytes()).unwrap();
        let signed = SignedHeader { header: candidate, signature };
        assert_eq!(
            signed.verify(&pair.verifying),
            Err(HeaderError::TestAlgorithmOnLiveChain),
            "the insecure test signer was accepted by the production verification path"
        );
    }

    #[test]
    fn equivocation_evidence_needs_two_different_blocks() {
        let pair = keypair(3);
        let validator = AccountId::from_hash(Hash::from_bytes([0x55; 32]));

        let mut first = header(42);
        first.proposer = validator;
        let mut second = first.clone();
        second.state_root = Hash::from_bytes([0xaa; 32]);

        let sign_it = |candidate: &BlockHeader| SignedHeader {
            header: candidate.clone(),
            signature: sign::sign(&pair.signing, candidate.signing_digest().as_bytes()).unwrap(),
        };

        let good = ValidatorEquivocation {
            validator,
            first: sign_it(&first),
            second: sign_it(&second),
        };
        assert_eq!(good.check(&pair.verifying), Ok(()));

        // The same block presented twice is not equivocation.
        let doubled = ValidatorEquivocation {
            validator,
            first: sign_it(&first),
            second: sign_it(&first),
        };
        assert_eq!(
            doubled.check(&pair.verifying),
            Err(HeaderError::EvidenceNotEquivocation { why: "the same block twice" })
        );

        // Nor are two blocks at different heights.
        let mut elsewhere = second.clone();
        elsewhere.height = 43;
        let different_height = ValidatorEquivocation {
            validator,
            first: sign_it(&first),
            second: sign_it(&elsewhere),
        };
        assert_eq!(
            different_height.check(&pair.verifying),
            Err(HeaderError::EvidenceNotEquivocation { why: "different heights" })
        );

        // Nor blocks by someone else.
        let other_validator = AccountId::from_hash(Hash::from_bytes([0x56; 32]));
        let misattributed = ValidatorEquivocation {
            validator: other_validator,
            first: sign_it(&first),
            second: sign_it(&second),
        };
        assert_eq!(
            misattributed.check(&pair.verifying),
            Err(HeaderError::EvidenceNotEquivocation { why: "not both by the accused" })
        );
    }

    #[test]
    fn equivocation_evidence_round_trips() {
        let pair = keypair(4);
        let validator = AccountId::from_hash(Hash::from_bytes([0x55; 32]));
        let first = header(1);
        let mut second = first.clone();
        second.tx_root = Hash::from_bytes([0xbb; 32]);
        let sign_it = |candidate: &BlockHeader| SignedHeader {
            header: candidate.clone(),
            signature: sign::sign(&pair.signing, candidate.signing_digest().as_bytes()).unwrap(),
        };
        let evidence = ValidatorEquivocation {
            validator,
            first: sign_it(&first),
            second: sign_it(&second),
        };
        let bytes = evidence.to_canonical_bytes();
        assert_eq!(ValidatorEquivocation::from_canonical_bytes(&bytes), Ok(evidence));
    }

    #[test]
    fn an_unknown_rung_discriminant_is_rejected() {
        let mut bytes = header(1).to_canonical_bytes();
        // The rung byte sits after version (2) + chain (32) + height varint (1)
        // + parent (32).
        let index = 2 + 32 + 1 + 32;
        if let Some(byte) = bytes.get_mut(index) {
            *byte = 9;
        }
        assert_eq!(
            BlockHeader::from_canonical_bytes(&bytes),
            Err(CodecError::UnknownVariant { enum_name: "FinalityRung", discriminant: 9 })
        );
    }

    #[test]
    fn committee_oversampling_is_threefold() {
        assert_eq!(params::COMMITTEE_SAMPLED, params::COMMITTEE_ACTIVE * 3);
        assert_eq!(params::COMMITTEE_ACTIVE, 64);
        assert_eq!(params::EPOCH_BLOCKS, 720);
    }
}
