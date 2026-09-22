// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runs the delay-function vectors against this implementation.
//!
//! The vectors come from `tools/vectorgen/generate.py`, a second implementation
//! written from the prose in `spec/draft/` rather than from this code. The
//! delay function is a frozen construction — a chain whose nodes iterate it
//! differently computes different epoch seeds and draws different committees —
//! so it is worth cross-checking rather than trusting.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use serde_json::Value;
use vanargand_consensus::vdf::{iterate, DelayParameters, DelayProof};
use vanargand_crypto::hash::Hash;

fn vectors(name: &str) -> Value {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("spec");
    path.push("vectors");
    path.push(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("cannot parse {}: {error}", path.display()))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("vector file has no array '{key}'"))
}

fn hash(value: &Value, key: &str) -> Hash {
    let text = value.get(key).and_then(Value::as_str).expect("a hex string");
    Hash::from_hex(text).expect("a valid digest")
}

fn number(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).expect("a number")
}

#[test]
fn delay_iteration_matches_the_vectors() {
    let file = vectors("02-hashing.json");
    let cases = array(&file, "delay");
    assert!(!cases.is_empty(), "the delay vectors are missing");

    for case in cases {
        let input = hash(case, "input");
        let iterations = number(case, "iterations");
        assert_eq!(
            iterate(&input, iterations),
            hash(case, "output"),
            "the delay function disagreed after {iterations} iterations"
        );
    }
}

#[test]
fn delay_proofs_match_the_vectors() {
    let file = vectors("02-hashing.json");
    let cases = array(&file, "delay_proofs");
    assert!(!cases.is_empty(), "the delay proof vectors are missing");

    for case in cases {
        let input = hash(case, "input");
        let iterations = number(case, "iterations");
        let segments = u32::try_from(number(case, "segments")).expect("fits");
        let parameters = DelayParameters::new(iterations, segments).expect("valid parameters");

        let produced = DelayProof::evaluate(input, parameters).expect("evaluation");
        let expected: Vec<Hash> = array(case, "checkpoints")
            .iter()
            .map(|value| Hash::from_hex(value.as_str().expect("a hex string")).expect("a digest"))
            .collect();

        assert_eq!(
            produced.checkpoints, expected,
            "checkpoints disagreed for {iterations} iterations in {segments} segments"
        );

        // And the proof this implementation produced verifies under its own
        // rules, which is the other half of the cross-check: agreeing on the
        // bytes is not the same as agreeing on what they mean.
        produced.check_fully(&input).expect("an honest proof verifies");
    }
}
