// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The sequential delay function, and an honest interim proof for it.
//!
//! # What it is for
//!
//! The epoch seed is the mix of every proposer's commitment-chain reveal. The
//! last proposer of an epoch sees every other reveal before choosing whether to
//! publish its own, which is one bit of influence over the next committee — A4,
//! grinding. Passing the mix through a computation that takes longer than the
//! window in which that proposer could act removes the bit: by the time it
//! could evaluate one variant, its turn is over.
//!
//! The function is deliberately the dullest one available: iterated hashing.
//! `H[delay](H[delay](…))`, a fixed number of times. It is inherently
//! sequential — each step needs the previous one — and it is post-quantum for
//! the same reason every hash here is.
//!
//! # What is missing, precisely
//!
//! R2 puts a **VDF proved in STARK** on the critical launch path, and that is
//! not implemented here. Without a succinct proof, checking the output costs
//! exactly what producing it cost, which defeats the purpose: every node would
//! pay the delay on every epoch.
//!
//! What this module provides instead is a **proof of sequential work** with
//! checkpoints, which is cheap to check probabilistically and whose soundness
//! is stated rather than assumed. It is an interim mechanism. R2's documented
//! fallback is hardened commit-and-reveal, and choosing between the two is a
//! decision for whoever ships a chain, not for this file.
//!
//! # The soundness, exactly
//!
//! The prover publishes `s` checkpoints: `c[0]` is the input, `c[i+1]` is `c[i]`
//! hashed `iterations / s` times, and `c[s]` is the output. A verifier checks
//! one segment by recomputing it — `iterations / s` hashes rather than
//! `iterations`.
//!
//! Suppose a prover skips a fraction *f* of the work. Skipping means at least
//! one checkpoint does not follow from its predecessor, and in fact every
//! segment it skipped is wrong. Checking one segment uniformly at random
//! catches it with probability *f*; checking *k* independent segments catches it
//! with probability **1 − (1 − f)ᵏ**.
//!
//! Two consequences worth stating in the same breath:
//!
//! - A prover that skips *half* the work is caught by 10 samples with
//!   probability 1 − 2⁻¹⁰ ≈ 99.9 %.
//! - A prover that skips *one segment in a thousand* is caught by 10 samples
//!   with probability about 1 %. It also saved one part in a thousand of the
//!   delay, which is not an attack on anything.
//!
//! So the guarantee degrades exactly as the cheating becomes pointless, which
//! is the property that makes this usable at all — and it is still weaker than
//! a STARK, which catches *any* deviation with overwhelming probability.

use core::fmt;

use vanargand_crypto::hash::{domain, Hash, Hasher};
use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};

/// Most checkpoints a proof may carry.
///
/// A proof is 32 bytes per checkpoint, so 4096 is 128 KiB — already more than a
/// block header should reasonably carry, and the bound exists so that a hostile
/// proof cannot be used to make a node allocate.
pub const MAX_SEGMENTS: u32 = 4_096;

/// How many segments a verifier samples by default.
///
/// Ten. Catches a prover that skipped half the work with probability 99.9 %,
/// and costs ten segment recomputations. A parameter, and one that trades
/// verification cost against soundness on a curve that is written out in the
/// module documentation rather than left to intuition.
pub const DEFAULT_SAMPLES: u32 = 10;

/// One step of the delay function.
#[must_use]
pub fn step(previous: &Hash) -> Hash {
    Hasher::new(domain::DELAY_FUNCTION).update(previous.as_bytes()).finalize()
}

/// Iterates the delay function `count` times from `input`.
///
/// Inherently sequential, which is the entire point. Costs `count` hashes and
/// cannot be parallelised.
#[must_use]
pub fn iterate(input: &Hash, count: u64) -> Hash {
    let mut current = *input;
    let mut remaining = count;
    while remaining > 0 {
        current = step(&current);
        remaining = remaining.saturating_sub(1);
    }
    current
}

/// How long the delay runs and how finely it is checkpointed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelayParameters {
    /// Total sequential hashes.
    pub iterations: u64,
    /// Checkpoints published, which is also the number of segments.
    pub segments: u32,
}

impl DelayParameters {
    /// Builds parameters, checking that they divide evenly.
    ///
    /// Requiring divisibility rather than handling a ragged last segment is a
    /// small restriction that removes a whole class of off-by-one disagreement
    /// between two implementations — and a consensus rule that two
    /// implementations can read differently is worse than an inconvenient one.
    pub fn new(iterations: u64, segments: u32) -> Result<Self, DelayError> {
        if segments == 0 || segments > MAX_SEGMENTS {
            return Err(DelayError::BadSegmentCount(segments));
        }
        if iterations == 0 {
            return Err(DelayError::NoWork);
        }
        if iterations % u64::from(segments) != 0 {
            return Err(DelayError::Indivisible { iterations, segments });
        }
        Ok(Self { iterations, segments })
    }

    /// Hashes per segment.
    #[must_use]
    pub fn segment_length(self) -> u64 {
        if self.segments == 0 {
            return 0;
        }
        self.iterations / u64::from(self.segments)
    }
}

/// Why a delay-function operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DelayError {
    /// Zero segments, or more than [`MAX_SEGMENTS`].
    BadSegmentCount(u32),
    /// Zero iterations, which is not a delay.
    NoWork,
    /// The iteration count is not a multiple of the segment count.
    Indivisible {
        /// The iteration count.
        iterations: u64,
        /// The segment count.
        segments: u32,
    },
    /// The proof does not carry `segments + 1` checkpoints.
    MalformedProof {
        /// How many it carries.
        checkpoints: usize,
        /// How many it should.
        expected: usize,
    },
    /// The proof's first checkpoint is not the input it claims.
    WrongInput,
    /// A sampled segment did not recompute to its checkpoint.
    BadSegment {
        /// Which segment.
        index: u32,
    },
}

impl fmt::Display for DelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSegmentCount(count) => {
                write!(f, "{count} segments; must be between 1 and {MAX_SEGMENTS}")
            }
            Self::NoWork => write!(f, "a delay of zero iterations is not a delay"),
            Self::Indivisible { iterations, segments } => {
                write!(f, "{iterations} iterations do not divide into {segments} segments")
            }
            Self::MalformedProof { checkpoints, expected } => {
                write!(f, "proof carries {checkpoints} checkpoints, expected {expected}")
            }
            Self::WrongInput => write!(f, "the proof does not start from the claimed input"),
            Self::BadSegment { index } => write!(f, "segment {index} does not recompute"),
        }
    }
}

impl std::error::Error for DelayError {}

/// A delay-function evaluation with its checkpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayProof {
    /// The parameters it was produced under.
    pub parameters: DelayParameters,
    /// `segments + 1` values: the input, each segment boundary, and the output.
    pub checkpoints: Vec<Hash>,
}

impl DelayProof {
    /// Evaluates the delay function, recording checkpoints.
    ///
    /// Costs `iterations` hashes — that is what it is for — and
    /// `32 × (segments + 1)` bytes.
    pub fn evaluate(input: Hash, parameters: DelayParameters) -> Result<Self, DelayError> {
        let segment = parameters.segment_length();
        let count = usize::try_from(parameters.segments)
            .map_err(|_| DelayError::BadSegmentCount(parameters.segments))?;

        let mut checkpoints = Vec::with_capacity(count.saturating_add(1));
        checkpoints.push(input);
        let mut current = input;
        for _ in 0..count {
            current = iterate(&current, segment);
            checkpoints.push(current);
        }
        Ok(Self { parameters, checkpoints })
    }

    /// The input the evaluation started from.
    #[must_use]
    pub fn input(&self) -> Hash {
        self.checkpoints.first().copied().unwrap_or(Hash::ZERO)
    }

    /// The output: the epoch seed, once verified.
    #[must_use]
    pub fn output(&self) -> Hash {
        self.checkpoints.last().copied().unwrap_or(Hash::ZERO)
    }

    /// Structural checks: the right number of checkpoints, from the right
    /// input.
    pub fn check_shape(&self, input: &Hash) -> Result<(), DelayError> {
        let expected = usize::try_from(self.parameters.segments)
            .map_err(|_| DelayError::BadSegmentCount(self.parameters.segments))?
            .saturating_add(1);
        if self.checkpoints.len() != expected {
            return Err(DelayError::MalformedProof {
                checkpoints: self.checkpoints.len(),
                expected,
            });
        }
        if self.input() != *input {
            return Err(DelayError::WrongInput);
        }
        Ok(())
    }

    /// Recomputes one segment. Costs `iterations / segments` hashes.
    pub fn check_segment(&self, index: u32) -> Result<(), DelayError> {
        let position = usize::try_from(index).map_err(|_| DelayError::BadSegment { index })?;
        let (Some(from), Some(to)) =
            (self.checkpoints.get(position), self.checkpoints.get(position.saturating_add(1)))
        else {
            return Err(DelayError::BadSegment { index });
        };
        if iterate(from, self.parameters.segment_length()) == *to {
            Ok(())
        } else {
            Err(DelayError::BadSegment { index })
        }
    }

    /// Checks `samples` segments chosen by `challenge`.
    ///
    /// Catches a prover that skipped a fraction *f* of the work with
    /// probability **1 − (1 − f)^samples**. Samples are drawn with replacement,
    /// so a repeat is possible and the bound above already accounts for it.
    ///
    /// The challenge must not be chosen by the prover — otherwise it picks a
    /// challenge that samples only the segments it computed honestly. In the
    /// protocol it comes from the block that publishes the proof, which the
    /// prover does not control.
    pub fn check_sampled(
        &self,
        input: &Hash,
        challenge: &Hash,
        samples: u32,
    ) -> Result<(), DelayError> {
        self.check_shape(input)?;
        for sample in 0..samples {
            let index = sample_index(challenge, sample, self.parameters.segments);
            self.check_segment(index)?;
        }
        Ok(())
    }

    /// Recomputes every segment. Costs as much as producing the proof did.
    ///
    /// The only check with no probabilistic gap, and the reason a succinct
    /// proof is on the roadmap rather than optional: if every node ran this,
    /// every node would pay the delay and the delay would protect nothing.
    pub fn check_fully(&self, input: &Hash) -> Result<(), DelayError> {
        self.check_shape(input)?;
        for index in 0..self.parameters.segments {
            self.check_segment(index)?;
        }
        Ok(())
    }
}

impl Encode for DelayProof {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(self.parameters.iterations);
        out.write_varint(u64::from(self.parameters.segments));
        out.write_seq(&self.checkpoints);
    }
}

impl Decode for DelayProof {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let iterations = input.read_varint()?;
        let segments = input.read_varint_u32()?;
        let parameters = DelayParameters::new(iterations, segments)
            .map_err(|_| CodecError::Invalid { reason: "bad delay parameters" })?;
        let checkpoints = input.read_seq::<Hash>()?;
        Ok(Self { parameters, checkpoints })
    }
}

/// Picks a segment to sample.
fn sample_index(challenge: &Hash, sample: u32, segments: u32) -> u32 {
    if segments == 0 {
        return 0;
    }
    let digest = Hasher::new(domain::COMMITTEE_DRAW)
        .update(challenge.as_bytes())
        .update(b"delay sample")
        .update(&sample.to_be_bytes())
        .finalize();
    let head: [u8; 4] =
        digest.as_bytes().get(..4).and_then(|slice| slice.try_into().ok()).unwrap_or([0; 4]);
    u32::from_be_bytes(head) % segments
}

#[cfg(test)]
mod tests {
    use super::{
        iterate, sample_index, step, DelayError, DelayParameters, DelayProof, DEFAULT_SAMPLES,
        MAX_SEGMENTS,
    };
    use std::collections::BTreeSet;
    use vanargand_crypto::hash::Hash;
    use vanargand_types::codec::{Decode, Encode};

    fn input() -> Hash {
        Hash::from_bytes([0x42; 32])
    }

    fn parameters() -> DelayParameters {
        DelayParameters::new(4_096, 64).expect("4096 divides into 64")
    }

    #[test]
    fn iteration_is_sequential_and_deterministic() {
        assert_eq!(iterate(&input(), 0), input());
        assert_eq!(iterate(&input(), 1), step(&input()));
        assert_eq!(iterate(&input(), 3), step(&step(&step(&input()))));
        assert_eq!(iterate(&input(), 100), iterate(&input(), 100));
    }

    #[test]
    fn the_delay_has_its_own_domain() {
        // A delay-function intermediate must never be presentable as a
        // commitment-chain link or a PayWord token: all three are iterated
        // hashes of 32 bytes.
        let as_delay = step(&input());
        let as_payword =
            vanargand_crypto::chain::link(vanargand_crypto::hash::domain::PAYWORD, &input());
        let as_commitment = vanargand_crypto::chain::link(
            vanargand_crypto::hash::domain::COMMITMENT_CHAIN,
            &input(),
        );
        let distinct: BTreeSet<Hash> = [as_delay, as_payword, as_commitment].into_iter().collect();
        assert_eq!(distinct.len(), 3);
    }

    #[test]
    fn a_proof_reproduces_the_plain_evaluation() {
        let proof = DelayProof::evaluate(input(), parameters()).expect("evaluation");
        assert_eq!(proof.input(), input());
        assert_eq!(proof.output(), iterate(&input(), parameters().iterations));
        assert_eq!(proof.checkpoints.len(), 65, "one checkpoint per boundary, plus the input");
    }

    #[test]
    fn an_honest_proof_passes_every_check() {
        let proof = DelayProof::evaluate(input(), parameters()).expect("evaluation");
        assert_eq!(proof.check_shape(&input()), Ok(()));
        assert_eq!(proof.check_fully(&input()), Ok(()));
        assert_eq!(proof.check_sampled(&input(), &Hash::from_bytes([1; 32]), DEFAULT_SAMPLES), Ok(()));
        for index in 0..parameters().segments {
            assert_eq!(proof.check_segment(index), Ok(()));
        }
    }

    #[test]
    fn a_proof_for_another_input_is_refused() {
        let proof = DelayProof::evaluate(input(), parameters()).expect("evaluation");
        assert_eq!(
            proof.check_shape(&Hash::from_bytes([0x43; 32])),
            Err(DelayError::WrongInput)
        );
    }

    #[test]
    fn a_tampered_output_is_caught_by_the_full_check() {
        let mut proof = DelayProof::evaluate(input(), parameters()).expect("evaluation");
        if let Some(last) = proof.checkpoints.last_mut() {
            *last = Hash::from_bytes([0xee; 32]);
        }
        assert_eq!(
            proof.check_fully(&input()),
            Err(DelayError::BadSegment { index: parameters().segments - 1 })
        );
    }

    #[test]
    fn skipping_half_the_work_is_caught_almost_always() {
        // The soundness claim, measured rather than asserted. A prover that
        // computes only the second half and fabricates the first is caught by
        // ten samples with probability 1 - 2^-10; over a hundred challenges it
        // should escape at most a couple of times.
        let honest = DelayProof::evaluate(input(), parameters()).expect("evaluation");
        let half = usize::try_from(parameters().segments / 2).expect("fits");

        // Fabricate the first half: checkpoints that do not follow from the
        // input, with the second half computed honestly from the forged
        // midpoint.
        let mut cheat = honest.clone();
        for index in 1..=half {
            if let Some(slot) = cheat.checkpoints.get_mut(index) {
                *slot = Hash::from_bytes([u8::try_from(index).unwrap_or(0); 32]);
            }
        }
        let midpoint = cheat.checkpoints.get(half).copied().expect("midpoint");
        let mut running = midpoint;
        for index in (half + 1)..cheat.checkpoints.len() {
            running = iterate(&running, parameters().segment_length());
            if let Some(slot) = cheat.checkpoints.get_mut(index) {
                *slot = running;
            }
        }

        let mut escapes = 0;
        for challenge in 0..100_u8 {
            let challenge = Hash::from_bytes([challenge; 32]);
            if cheat.check_sampled(&input(), &challenge, DEFAULT_SAMPLES).is_ok() {
                escapes += 1;
            }
        }
        assert!(
            escapes <= 5,
            "a prover that skipped half the work escaped {escapes} of 100 challenges; \
             the sampling soundness is not what the documentation claims"
        );
        // And the full check never lets it through.
        assert!(cheat.check_fully(&input()).is_err());
    }

    #[test]
    fn a_single_forged_checkpoint_is_caught_by_the_segment_that_covers_it() {
        let mut proof = DelayProof::evaluate(input(), parameters()).expect("evaluation");
        if let Some(slot) = proof.checkpoints.get_mut(7) {
            *slot = Hash::from_bytes([0xab; 32]);
        }
        // Segment 6 ends at checkpoint 7, and segment 7 starts from it.
        assert_eq!(proof.check_segment(6), Err(DelayError::BadSegment { index: 6 }));
        assert_eq!(proof.check_segment(7), Err(DelayError::BadSegment { index: 7 }));
        assert_eq!(proof.check_segment(5), Ok(()), "an untouched segment was rejected");
    }

    #[test]
    fn parameters_must_divide_evenly() {
        // Not pedantry: a ragged last segment is an off-by-one two
        // implementations can read differently, and a consensus rule that can
        // be read two ways is worse than an inconvenient one.
        assert!(DelayParameters::new(100, 7).is_err());
        assert!(DelayParameters::new(100, 10).is_ok());
        assert_eq!(DelayParameters::new(0, 10), Err(DelayError::NoWork));
        assert!(matches!(
            DelayParameters::new(100, 0),
            Err(DelayError::BadSegmentCount(0))
        ));
        assert!(matches!(
            DelayParameters::new(100, MAX_SEGMENTS + 1),
            Err(DelayError::BadSegmentCount(_))
        ));
    }

    #[test]
    fn segment_length_is_the_obvious_quotient() {
        assert_eq!(parameters().segment_length(), 64);
        assert_eq!(DelayParameters::new(1_000, 10).expect("divides").segment_length(), 100);
    }

    #[test]
    fn a_malformed_proof_is_refused_before_any_work() {
        let mut proof = DelayProof::evaluate(input(), parameters()).expect("evaluation");
        proof.checkpoints.truncate(10);
        assert!(matches!(
            proof.check_shape(&input()),
            Err(DelayError::MalformedProof { .. })
        ));
        assert!(matches!(
            proof.check_sampled(&input(), &Hash::ZERO, DEFAULT_SAMPLES),
            Err(DelayError::MalformedProof { .. })
        ));
    }

    #[test]
    fn sampling_is_deterministic_and_spreads_out() {
        let first: Vec<u32> = (0..DEFAULT_SAMPLES)
            .map(|sample| sample_index(&Hash::from_bytes([1; 32]), sample, 64))
            .collect();
        let again: Vec<u32> = (0..DEFAULT_SAMPLES)
            .map(|sample| sample_index(&Hash::from_bytes([1; 32]), sample, 64))
            .collect();
        assert_eq!(first, again, "sampling is not deterministic");

        let elsewhere: Vec<u32> = (0..DEFAULT_SAMPLES)
            .map(|sample| sample_index(&Hash::from_bytes([2; 32]), sample, 64))
            .collect();
        assert_ne!(first, elsewhere, "the challenge does not steer the sampling");

        // Ten draws from sixty-four should not all land on one segment.
        let distinct: BTreeSet<u32> = first.into_iter().collect();
        assert!(distinct.len() > 5, "sampling is clustered: {distinct:?}");
    }

    #[test]
    fn every_sampled_index_is_in_range() {
        for segments in [1_u32, 2, 7, 64, MAX_SEGMENTS] {
            for sample in 0..50_u32 {
                let index = sample_index(&Hash::from_bytes([9; 32]), sample, segments);
                assert!(index < segments, "index {index} out of range for {segments} segments");
            }
        }
    }

    #[test]
    fn proofs_round_trip() {
        let proof = DelayProof::evaluate(input(), parameters()).expect("evaluation");
        let bytes = proof.to_canonical_bytes();
        assert_eq!(DelayProof::from_canonical_bytes(&bytes), Ok(proof));
    }

    #[test]
    fn bad_parameters_are_rejected_on_the_wire() {
        let mut encoder = vanargand_types::codec::Encoder::new();
        encoder.write_varint(100);
        encoder.write_varint(7); // does not divide
        encoder.write_seq(&[Hash::ZERO; 8]);
        assert!(DelayProof::from_canonical_bytes(&encoder.finish()).is_err());
    }
}
