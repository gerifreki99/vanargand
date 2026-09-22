// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A block, built and validated end to end.
//!
//! This is the first test in the workspace that exercises the header rules, the
//! committee draw, the certificate, the ledger and the commitment chain
//! together. Each of those has its own tests; none of them can catch a mistake
//! in how they are *combined*, which is what this file is for.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use vanargand_consensus::certificate::{Certificate, Vote};
use vanargand_consensus::committee::Committee;
use vanargand_consensus::seed::{mix_reveals, EpochSeed};
use vanargand_consensus::validator::{ValidatorRecord, ValidatorSet};
use vanargand_crypto::algorithm::AlgorithmId;
use vanargand_crypto::chain::HashChain;
use vanargand_crypto::hash::{domain, Hash};
use vanargand_crypto::sign::{self, Keypair};
use vanargand_node::block::Block;
use vanargand_node::validate::{validate_and_apply, BlockError, ChainParameters};
use vanargand_state::account::{Account, Device};
use vanargand_state::ledger::Ledger;
use vanargand_types::amount::Ratio;
use vanargand_types::block::{BlockHeader, FinalityRung, SignedHeader, HEADER_VERSION};
use vanargand_types::id::{AccountId, BlockId, ChainId, DeviceId};
use vanargand_types::nonce::{Lane, Nonce};
use vanargand_types::tx::{Transaction, TxBody, TxKind, TX_VERSION};
use vanargand_types::{Amount, Hash as H};

const VALIDATORS: u32 = 100;
const CHAIN_LENGTH: u32 = 64;

fn keypair(index: u32) -> Keypair {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    sign::keypair_from_seed(AlgorithmId::InsecureTest, &Hash::from_bytes(bytes)).unwrap()
}

/// Validator accounts carry their index in the first four bytes, so a committee
/// member can be mapped back to its keypair without a side table.
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

fn commitment_chain(index: u32) -> HashChain {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    bytes[31] = 0xcc;
    HashChain::generate(domain::COMMITMENT_CHAIN, &Hash::from_bytes(bytes), CHAIN_LENGTH).unwrap()
}

/// A validator's account, holding its block-signing key as a device.
fn validator_account(key: &vanargand_crypto::sign::VerifyingKey, balance: u64) -> Account {
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

/// A chain with a hundred validators, a drawn committee, and a genesis parent.
fn world() -> World {
    let mut ledger = Ledger::new();
    let mut validators = ValidatorSet::new();
    let mut chains = BTreeMap::new();

    for index in 0..VALIDATORS {
        let pair = keypair(index);
        let chain = commitment_chain(index);
        ledger.put_account(account_id(index), validator_account(&pair.verifying, 100_000));
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
    let seed = EpochSeed::from_delay_function(mix_reveals(0, &reveals));
    let committee = Committee::draw(&validators, &seed);

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
        fee_emission_ratio: Ratio::ZERO,
    };

    World { ledger, validators, committee, chains, parent }
}

fn params() -> ChainParameters {
    ChainParameters { chain: chain_id(), allow_test_algorithms: true }
}

/// Builds a valid block at height 1, proposed by whoever is first on duty.
///
/// The header's roots are filled in by *simulating* the application on a copy
/// of the ledger — which is what a real proposer does, and what makes the
/// `state_root` check meaningful rather than circular.
fn propose(world: &World, transactions: Vec<Transaction>, rung: FinalityRung) -> Block {
    let block_in_epoch = 1_u64;
    let on_duty = world.committee.active_at(block_in_epoch);
    let proposer = on_duty.first().expect("a committee member is on duty").account;
    let index = index_of(&proposer);
    let pair = keypair(index);
    let reveal = world.chains.get(&index).expect("a chain").reveal(1).expect("a link");

    let mut draft = BlockHeader {
        version: HEADER_VERSION,
        chain: chain_id(),
        height: 1,
        parent: world.parent.id(),
        rung,
        finalized_height: if rung == FinalityRung::Chain { 1 } else { 0 },
        state_root: H::ZERO,
        tx_root: H::ZERO,
        proposer,
        randomness_reveal: reveal,
        archive_commitment: H::ZERO,
        emitted_supply: Amount::ZERO,
        security_budget: world.validators.security_budget().unwrap(),
        fee_emission_ratio: Ratio::ZERO,
    };

    let mut probe = Block {
        header: SignedHeader {
            header: draft.clone(),
            signature: sign::sign(&pair.signing, draft.signing_digest().as_bytes()).unwrap(),
        },
        transactions,
        certificate: None,
    };
    draft.tx_root = probe.computed_tx_root();

    // Simulate to learn the resulting state root.
    let mut rehearsal = world.ledger.clone();
    let context = vanargand_state::ledger::BlockContext {
        chain: chain_id(),
        height: draft.height,
        finalized_height: draft.finalized_height,
        rung: draft.rung,
        proposer,
    };
    rehearsal.settle_elapsed_purses(draft.finalized_height).unwrap();
    rehearsal.prune_expired_commitments(draft.finalized_height);
    for transaction in &probe.transactions {
        rehearsal.apply(&context, &transaction.body).expect("the proposer's own transactions");
    }
    draft.state_root = rehearsal.state_root();
    draft.fee_emission_ratio = rehearsal.fee_emission_ratio(draft.emitted_supply);

    probe.header = SignedHeader {
        signature: sign::sign(&pair.signing, draft.signing_digest().as_bytes()).unwrap(),
        header: draft,
    };
    probe
}

/// Re-signs a header whose fields have been changed.
///
/// Mutating a header changes its identifier, and the signature covers the
/// identifier — so a test that tampers and does not re-sign is testing the
/// signature check, whatever it meant to test. This helper exists because the
/// first draft of this file got that wrong three times.
fn resign(block: &mut Block) {
    let pair = keypair(index_of(&block.header().proposer));
    block.header.signature =
        sign::sign(&pair.signing, block.header.header.signing_digest().as_bytes()).unwrap();
}

/// A transfer from one validator account to another.
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

/// A certificate signed by the first `signers` members on duty.
fn certify(world: &World, header: &BlockHeader, block_in_epoch: u64, signers: usize) -> Certificate {
    let digest = header.signing_digest();
    let mut votes: Vec<Vote> = world
        .committee
        .active_at(block_in_epoch)
        .into_iter()
        .take(signers)
        .map(|member| Vote {
            member: member.account,
            signature: sign::sign(&keypair(index_of(&member.account)).signing, digest.as_bytes())
                .unwrap(),
        })
        .collect();
    votes.sort_by(|left, right| left.member.cmp(&right.member));
    Certificate { block: header.id(), votes }
}

// --------------------------------------------------------------------------

#[test]
fn a_well_formed_block_validates_and_applies() {
    let mut world = world();
    // The recipient is deliberately outside the validator set: a committee
    // member would also collect the proposer's share of the fee, and the
    // assertion below would then depend on who happened to be drawn.
    let stranger = 9_999_u32;
    let block = propose(&world, vec![transfer(0, stranger, 0, 500)], FinalityRung::Chain);

    let applied = validate_and_apply(
        &block,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("a block built by the rules must pass them");

    assert_eq!(applied.block, block.id());
    assert_eq!(applied.claimed_rung, FinalityRung::Chain);
    assert_eq!(applied.reached_rung, FinalityRung::Provisional, "no certificate, no finality");
    assert_eq!(
        world.ledger.account(&account_id(stranger)).unwrap().balance(None),
        Amount::from_ulf(500)
    );
}

#[test]
fn a_certificate_over_two_thirds_reaches_chain_finality() {
    let mut world = world();
    let mut block = propose(&world, vec![], FinalityRung::Chain);
    block.certificate = Some(certify(&world, block.header(), 1, 64));

    let applied = validate_and_apply(
        &block,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("a fully certified block");
    assert_eq!(applied.reached_rung, FinalityRung::Chain);
    assert_eq!(applied.signed_weight, world.committee.active_weight_at(1));
}

#[test]
fn a_certificate_below_two_thirds_does_not() {
    let mut world = world();
    let mut block = propose(&world, vec![], FinalityRung::Chain);
    // Forty of sixty-four is under two thirds.
    block.certificate = Some(certify(&world, block.header(), 1, 40));

    let applied = validate_and_apply(
        &block,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("the votes are valid, they are simply not enough");
    assert_eq!(
        applied.reached_rung,
        FinalityRung::Provisional,
        "forty of sixty-four reached chain finality"
    );
}

#[test]
fn a_provisional_block_may_not_carry_a_certificate() {
    // Claiming rung 1 and rung 2 at once. The grammar it was validated under
    // would be the wrong one.
    let mut world = world();
    let mut block = propose(&world, vec![], FinalityRung::Provisional);
    block.certificate = Some(certify(&world, block.header(), 1, 64));

    assert_eq!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::CertifiedProvisionalBlock)
    );
}

#[test]
fn a_forbidden_transaction_invalidates_a_provisional_block() {
    // C9 at the block level. `unbond` is named explicitly in R1.3, and the
    // whole block is rejected rather than the offending transaction dropped:
    // dropping it would make two honest nodes disagree about what the block
    // was.
    let mut world = world();
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

    // Built as a chain block — which is legal — then restamped provisional.
    let mut block = propose(&world, vec![forbidden], FinalityRung::Chain);
    block.header.header.rung = FinalityRung::Provisional;
    block.header.header.finalized_height = 0;
    resign(&mut block);

    assert!(matches!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::ForbiddenInProvisional(_))
    ));
}

#[test]
fn a_rejected_block_changes_nothing() {
    // The property that makes validation safe to run on anything a peer sends.
    let mut world = world();
    let mut block = propose(&world, vec![transfer(0, 9_999, 0, 500)], FinalityRung::Chain);
    block.header.header.state_root = H::from_bytes([0xee; 32]);
    resign(&mut block);

    let ledger_before = world.ledger.clone();
    let validators_before = world.validators.clone();

    assert!(matches!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::StateRootMismatch { .. })
    ));
    assert_eq!(world.ledger, ledger_before, "a rejected block mutated the ledger");
    assert_eq!(world.validators, validators_before, "a rejected block spent a reveal");
}

#[test]
fn a_tampered_body_is_caught_by_the_transaction_root() {
    let mut world = world();
    let mut block = propose(&world, vec![transfer(0, 1, 0, 500)], FinalityRung::Chain);
    block.transactions.push(transfer(0, 2, 1, 1));

    assert!(matches!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::TxRootMismatch { .. })
    ));
}

#[test]
fn a_block_from_someone_off_duty_is_refused() {
    let mut world = world();
    let block = propose(&world, vec![], FinalityRung::Chain);

    // Find a validator who is not on duty at block 1 and put its name on the
    // header. The signature will not match either, but the duty check comes
    // first and is the one being exercised.
    let on_duty: Vec<AccountId> =
        world.committee.active_at(1).into_iter().map(|member| member.account).collect();
    let Some(intruder) = (0..VALIDATORS)
        .map(account_id)
        .find(|candidate| !on_duty.contains(candidate))
    else {
        panic!("every validator is on duty; the fixture is too small");
    };

    let mut forged = block;
    forged.header.header.proposer = intruder;
    assert_eq!(
        validate_and_apply(
            &forged,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::ProposerNotOnDuty(intruder))
    );
}

#[test]
fn a_forged_randomness_reveal_is_refused() {
    // A4. Revealing and proposing are one act, so a block whose reveal does not
    // advance the proposer's sealed chain is simply not a block.
    let mut world = world();
    let mut block = propose(&world, vec![], FinalityRung::Chain);
    block.header.header.randomness_reveal = H::from_bytes([0xab; 32]);
    resign(&mut block);

    assert_eq!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::BadRandomnessReveal)
    );
}

#[test]
fn a_reveal_is_spent_and_cannot_be_reused() {
    // The proposer's chain moves on. Re-presenting the same link would be
    // proposing twice from one turn.
    let mut world = world();
    let block = propose(&world, vec![], FinalityRung::Chain);
    let proposer = block.header().proposer;

    validate_and_apply(
        &block,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("the first block");

    assert_eq!(
        world.validators.get(&proposer).unwrap().last_reveal,
        block.header().randomness_reveal,
        "the reveal was not recorded as spent"
    );

    // The same block again: the reveal no longer advances anything.
    assert_eq!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::BadRandomnessReveal)
    );
}

#[test]
fn the_finalised_tip_may_stand_still_but_never_retreat() {
    // It may stand still for an arbitrarily long partition. It may never go
    // back: every contestation clock is measured against it, and a tip that
    // retreats is a window that reopens.
    let mut world = world();
    world.parent.finalized_height = 5;
    world.parent.height = 0;
    world.parent.rung = FinalityRung::Provisional;

    let mut block = propose(&world, vec![], FinalityRung::Provisional);
    block.header.header.finalized_height = 4;
    resign(&mut block);

    assert_eq!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::FinalizedWentBackwards { parent: 5, claimed: 4 })
    );
}

#[test]
fn a_block_for_another_chain_is_refused() {
    // D4, at the block level.
    let mut world = world();
    let block = propose(&world, vec![], FinalityRung::Chain);
    let elsewhere =
        ChainParameters { chain: ChainId::from_hash(H::from_bytes([0x99; 32])), ..params() };

    assert_eq!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &elsewhere
        ),
        Err(BlockError::WrongChain)
    );
}

#[test]
fn the_production_path_refuses_the_test_signer() {
    let mut world = world();
    let block = propose(&world, vec![], FinalityRung::Chain);
    let live = ChainParameters { allow_test_algorithms: false, ..params() };

    assert_eq!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &live
        ),
        Err(BlockError::TestAlgorithmOnLiveChain)
    );
}

#[test]
fn a_counterfeiting_chain_is_caught_by_its_own_header() {
    // `docs/05-emission.pdf` §5, at the block level: one number against a pure
    // function of the height. A chain that mints past its formula is demoted by
    // arithmetic, and the check costs a foreign auditor a header.
    let mut world = world();
    let mut block = propose(&world, vec![], FinalityRung::Chain);

    let permitted = vanargand_consensus::emission::permitted_through(
        vanargand_consensus::emission::epoch_of_height(1),
    );
    block.header.header.emitted_supply = Amount::from_ulf(permitted.as_ulf() + 1);
    resign(&mut block);

    assert!(matches!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::Emission(_))
    ));

    // And exactly at the ceiling is fine.
    let mut honest = propose(&world, vec![], FinalityRung::Chain);
    honest.header.header.emitted_supply = permitted;
    resign(&mut honest);
    validate_and_apply(
        &honest,
        &world.parent,
        &mut world.ledger,
        &mut world.validators,
        &world.committee,
        &params(),
    )
    .expect("a chain emitting exactly what the formula allows");
}

#[test]
fn the_emission_counter_may_never_go_backwards() {
    let mut world = world();
    world.parent.emitted_supply = Amount::from_ulf(1_000);

    let mut block = propose(&world, vec![], FinalityRung::Chain);
    block.header.header.emitted_supply = Amount::from_ulf(999);
    resign(&mut block);

    assert!(matches!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::Emission(_))
    ));
}

#[test]
fn a_block_at_the_wrong_height_is_refused() {
    let mut world = world();
    let mut block = propose(&world, vec![], FinalityRung::Chain);
    block.header.header.height = 7;

    assert!(matches!(
        validate_and_apply(
            &block,
            &world.parent,
            &mut world.ledger,
            &mut world.validators,
            &world.committee,
            &params()
        ),
        Err(BlockError::NotTheNextHeight { parent: 0, claimed: 7 })
    ));
}
