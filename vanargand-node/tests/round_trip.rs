// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build a block, then validate what you built.
//!
//! This is the test the two halves of the node exist for. Each has its own
//! rules and its own tests; what neither can check alone is that a producer
//! following them makes something a validator following them accepts.
//!
//! When it fails, the two sides have drifted — and that is a far more useful
//! signal than either side's own tests failing, because a producer whose blocks
//! nobody accepts is a validator seat that produces nothing, and a validator
//! that accepts what nobody else does is a fork.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use vanargand_consensus::committee::Committee;
use vanargand_consensus::seed::{mix_reveals, EpochSeed};
use vanargand_consensus::validator::{ValidatorRecord, ValidatorSet};
use vanargand_crypto::algorithm::AlgorithmId;
use vanargand_crypto::chain::HashChain;
use vanargand_crypto::hash::{domain, Hash};
use vanargand_crypto::sign::{self, Keypair};
use vanargand_node::propose::{build, DeclineReason, ProposalInputs};
use vanargand_node::validate::{validate_and_apply, ChainParameters};
use vanargand_state::account::{Account, Device};
use vanargand_state::ledger::Ledger;
use vanargand_types::amount::Ratio;
use vanargand_types::block::{BlockHeader, FinalityRung, HEADER_VERSION};
use vanargand_types::id::{AccountId, BlockId, ChainId, DeviceId};
use vanargand_types::nonce::{Lane, Nonce};
use vanargand_types::tx::{Transaction, TxBody, TxKind, TX_VERSION};
use vanargand_types::{Amount, Hash as H};

const VALIDATORS: u32 = 100;

fn keypair(index: u32) -> Keypair {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    sign::keypair_from_seed(AlgorithmId::InsecureTest, &Hash::from_bytes(bytes)).unwrap()
}

fn account_id(index: u32) -> AccountId {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    bytes[31] = 0xaa;
    AccountId::from_hash(Hash::from_bytes(bytes))
}

fn index_of(account: &AccountId) -> u32 {
    let head: [u8; 4] =
        account.as_bytes().get(..4).and_then(|slice| slice.try_into().ok()).unwrap_or([0; 4]);
    u32::from_be_bytes(head)
}

fn chain_id() -> ChainId {
    ChainId::from_hash(Hash::from_bytes([0x11; 32]))
}

fn params() -> ChainParameters {
    ChainParameters { chain: chain_id(), allow_test_algorithms: true }
}

fn commitment_chain(index: u32) -> HashChain {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    bytes[31] = 0xcc;
    HashChain::generate(domain::COMMITMENT_CHAIN, &Hash::from_bytes(bytes), 64).unwrap()
}

fn funded(key: &vanargand_crypto::sign::VerifyingKey, balance: u64) -> Account {
    let mut account = Account::new();
    account.credit(None, Amount::from_ulf(balance)).unwrap();
    account.nomad_credit = Amount::from_ulf(balance);
    account.devices.insert(
        DeviceId::of_device_key(key),
        Device {
            key: key.clone(),
            lane: Lane::FIRST,
            nomad_share: Amount::from_ulf(balance),
            nomad_spent: Amount::ZERO,
        },
    );
    account.next_lane = Lane::new(1);
    account
}

struct World {
    ledger: Ledger,
    validators: ValidatorSet,
    committee: Committee,
    chains: BTreeMap<u32, HashChain>,
    parent: BlockHeader,
}

fn world() -> World {
    let mut ledger = Ledger::new();
    let mut validators = ValidatorSet::new();
    let mut chains = BTreeMap::new();

    for index in 0..VALIDATORS {
        let pair = keypair(index);
        let chain = commitment_chain(index);
        ledger.put_account(account_id(index), funded(&pair.verifying, 100_000));
        validators.insert(ValidatorRecord::new(
            account_id(index),
            pair.verifying.clone(),
            Amount::from_ulf(100_000),
            chain.root(),
        ));
        chains.insert(index, chain);
    }

    let mut reveals = BTreeMap::new();
    reveals.insert(account_id(0), Hash::from_bytes([1; 32]));
    let committee =
        Committee::draw(&validators, &EpochSeed::from_delay_function(mix_reveals(0, &reveals)));

    let parent = BlockHeader {
        version: HEADER_VERSION,
        chain: chain_id(),
        height: 0,
        parent: BlockId::ZERO,
        rung: FinalityRung::Chain,
        finalized_height: 0,
        state_root: ledger.state_root(),
        tx_root: H::ZERO,
        proposer: account_id(0),
        randomness_reveal: H::ZERO,
        archive_commitment: H::ZERO,
        emitted_supply: Amount::ZERO,
        security_budget: validators.security_budget().unwrap(),
        fee_emission_ratio: ledger.fee_emission_ratio(Amount::ZERO),
    };

    World { ledger, validators, committee, chains, parent }
}

fn transfer(from: u32, to: u32, sequence: u64, amount: u64) -> Transaction {
    let pair = keypair(from);
    let body = TxBody {
        version: TX_VERSION,
        chain: chain_id(),
        account: account_id(from),
        device: DeviceId::of_device_key(&pair.verifying),
        nonce: Nonce::new(Lane::FIRST, sequence),
        fee: Amount::from_ulf(10),
        valid_until_finalized: None,
        kind: TxKind::Transfer {
            to: account_id(to),
            asset: None,
            amount: Amount::from_ulf(amount),
        },
    };
    let signature = sign::sign(&pair.signing, body.signing_digest().as_bytes()).unwrap();
    Transaction { body, signature }
}

/// The inputs a proposer on duty at height 1 would have.
fn proposal_inputs<'a>(world: &'a World, rung: FinalityRung) -> (ProposalInputs<'a>, u32) {
    let proposer = world
        .committee
        .active_at(1)
        .first()
        .expect("somebody is on duty")
        .account;
    let index = index_of(&proposer);
    let reveal = world.chains.get(&index).expect("a chain").reveal(1).expect("a link");
    (
        ProposalInputs {
            parent: &world.parent,
            proposer,
            randomness_reveal: reveal,
            rung,
            finalized_height: 0,
            archive_commitment: H::ZERO,
            emitted_supply: Amount::ZERO,
        },
        index,
    )
}

// --------------------------------------------------------------------------

#[test]
fn what_a_producer_builds_a_validator_accepts() {
    let mut world = world();
    let (inputs, index) = proposal_inputs(&world, FinalityRung::Chain);
    let signing = keypair(index).signing;

    let proposal = build(
        &inputs,
        vec![transfer(0, 9_999, 0, 500), transfer(1, 9_998, 0, 250)],
        &world.ledger,
        &world.validators,
        &world.committee,
        &signing,
        &params(),
    )
    .expect("a proposer on duty with a live chain");

    assert!(proposal.declined.is_empty(), "declined: {:?}", proposal.declined);
    assert_eq!(proposal.block.len(), 2);

    let applied = validate_and_apply(
        &proposal.block,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("the two halves have drifted apart");

    assert_eq!(applied.block, proposal.block.id());
    assert_eq!(
        world.ledger.account(&account_id(9_999)).unwrap().balance(None),
        Amount::from_ulf(500)
    );
    assert_eq!(world.ledger.total_fees(), Amount::from_ulf(20));
}

#[test]
fn an_empty_block_round_trips() {
    // The common case for a quiet committee, and the one where every root is a
    // sentinel rather than a digest.
    let mut world = world();
    let (inputs, index) = proposal_inputs(&world, FinalityRung::Chain);
    let signing = keypair(index).signing;

    let proposal =
        build(&inputs, vec![], &world.ledger, &world.validators, &world.committee, &signing, &params())
            .expect("an empty block is a block");
    assert!(proposal.block.is_empty());

    validate_and_apply(
        &proposal.block,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("an empty block must validate");
}

#[test]
fn a_producer_drops_what_a_validator_would_reject() {
    // The asymmetry the two modules exist to express. The same stale
    // transaction that makes a *block* invalid simply does not get chosen.
    let mut world = world();
    let (inputs, index) = proposal_inputs(&world, FinalityRung::Chain);
    let signing = keypair(index).signing;

    let good = transfer(0, 9_999, 0, 500);
    let overdraft = transfer(1, 9_999, 0, 1_000_000);
    let wrong_nonce = transfer(2, 9_999, 7, 1);

    let proposal = build(
        &inputs,
        vec![good, overdraft, wrong_nonce],
        &world.ledger,
        &world.validators,
        &world.committee,
        &signing,
        &params(),
    )
    .expect("one good candidate is enough");

    assert_eq!(proposal.block.len(), 1, "a bad candidate was included");
    assert_eq!(proposal.declined.len(), 2);
    assert!(proposal.declined.iter().all(|declined| matches!(
        declined.reason,
        DeclineReason::Rejected(_)
    )));

    // And what survived the screening is accepted.
    validate_and_apply(
        &proposal.block,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("the surviving set must validate");
}

#[test]
fn a_producer_declines_a_forged_signature_without_consulting_the_ledger() {
    let mut world = world();
    let (inputs, index) = proposal_inputs(&world, FinalityRung::Chain);
    let signing = keypair(index).signing;

    let mut forged = transfer(0, 9_999, 0, 500);
    forged.body.fee = Amount::from_ulf(11); // signature no longer matches

    let proposal = build(
        &inputs,
        vec![forged],
        &world.ledger,
        &world.validators,
        &world.committee,
        &signing,
        &params(),
    )
    .expect("a block with nothing in it");

    assert!(proposal.block.is_empty());
    assert_eq!(proposal.declined.len(), 1);
    assert_eq!(proposal.declined[0].reason, DeclineReason::BadSignature);

    validate_and_apply(
        &proposal.block,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("an empty block is still a block");
}

#[test]
fn a_provisional_producer_declines_what_the_grammar_forbids() {
    // C9 from the producer's side. `unbond` is named explicitly in R1.3, and a
    // proposer offered one during a partition simply leaves it out rather than
    // publishing a block its peers will reject.
    let mut world = world();
    let (inputs, index) = proposal_inputs(&world, FinalityRung::Provisional);
    let signing = keypair(index).signing;

    let pair = keypair(0);
    let body = TxBody {
        version: TX_VERSION,
        chain: chain_id(),
        account: account_id(0),
        device: DeviceId::of_device_key(&pair.verifying),
        nonce: Nonce::new(Lane::FIRST, 0),
        fee: Amount::from_ulf(10),
        valid_until_finalized: None,
        kind: TxKind::Unbond { amount: Amount::from_ulf(1) },
    };
    let forbidden = Transaction {
        signature: sign::sign(&pair.signing, body.signing_digest().as_bytes()).unwrap(),
        body,
    };

    let proposal = build(
        &inputs,
        vec![forbidden, transfer(1, 9_999, 0, 5)],
        &world.ledger,
        &world.validators,
        &world.committee,
        &signing,
        &params(),
    )
    .expect("the transfer is legal offline");

    assert_eq!(proposal.block.len(), 1);
    assert_eq!(
        proposal.declined[0].reason,
        DeclineReason::ForbiddenInProvisional { kind: "unbond" }
    );

    validate_and_apply(
        &proposal.block,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("a provisional block of whitelisted transactions");
}

#[test]
fn the_published_ratio_is_what_the_ledger_computes() {
    // `docs/05-emission.pdf` §4's health metric, now checkable. Two fees of ten
    // against an emission of zero: the denominator is zero, which is
    // "undefined" rather than "infinite", and a genesis chain living entirely
    // on fees is exactly the shape that produces it.
    let mut world = world();
    let (inputs, index) = proposal_inputs(&world, FinalityRung::Chain);
    let signing = keypair(index).signing;

    let proposal = build(
        &inputs,
        vec![transfer(0, 9_999, 0, 1), transfer(1, 9_999, 0, 1)],
        &world.ledger,
        &world.validators,
        &world.committee,
        &signing,
        &params(),
    )
    .unwrap();

    assert_eq!(
        proposal.block.header().fee_emission_ratio,
        Ratio::new(20, 0),
        "the producer published a ratio the ledger does not compute"
    );
    assert_eq!(proposal.block.header().fee_emission_ratio.to_ppm(), None);

    validate_and_apply(
        &proposal.block,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("the validator recomputes the same pair");
}

#[test]
fn a_producer_not_on_duty_refuses_to_build() {
    let world = world();
    let (mut inputs, index) = proposal_inputs(&world, FinalityRung::Chain);
    let signing = keypair(index).signing;

    let on_duty: Vec<AccountId> =
        world.committee.active_at(1).into_iter().map(|member| member.account).collect();
    let Some(off_duty) =
        (0..VALIDATORS).map(account_id).find(|candidate| !on_duty.contains(candidate))
    else {
        panic!("every validator is on duty; the fixture is too small");
    };
    inputs.proposer = off_duty;

    assert!(matches!(
        build(&inputs, vec![], &world.ledger, &world.validators, &world.committee, &signing, &params()),
        Err(vanargand_node::propose::ProposeError::NotOnDuty(_))
    ));
}

#[test]
fn a_producer_refuses_to_publish_a_counter_its_own_validator_would_reject() {
    // The difference between an operator error and a chain being demoted out of
    // the VAN zone.
    let world = world();
    let (mut inputs, index) = proposal_inputs(&world, FinalityRung::Chain);
    let signing = keypair(index).signing;

    let permitted = vanargand_consensus::emission::permitted_through(
        vanargand_consensus::emission::epoch_of_height(1),
    );
    inputs.emitted_supply = Amount::from_ulf(permitted.as_ulf() + 1);

    assert!(matches!(
        build(&inputs, vec![], &world.ledger, &world.validators, &world.committee, &signing, &params()),
        Err(vanargand_node::propose::ProposeError::Emission(_))
    ));
}
