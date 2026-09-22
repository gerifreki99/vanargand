// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An assembled block: a header, the transactions it commits to, and the
//! certificate that finalises it.
//!
//! # Why this type is here and not in `vanargand-types`
//!
//! The header is the consensus object. It is what is hashed, what is signed,
//! and what a light client stores; its encoding is frozen in
//! `spec/draft/05-blocks.md`. The body is not: the header commits to it through
//! `tx_root`, so two implementations can gossip the transaction list in
//! whatever shape they like and still agree on the chain.
//!
//! So the block-as-transmitted is an assembly concern, and assembly is this
//! crate's job. What is *not* negotiable is the relationship between the two,
//! and [`Block::computed_tx_root`] is where it is stated.

use vanargand_consensus::certificate::Certificate;
use vanargand_crypto::hash::Hash;
use vanargand_types::block::{BlockHeader, SignedHeader};
use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::id::{BlockId, TxId};
use vanargand_types::merkle;
use vanargand_types::tx::Transaction;

/// A block as it travels between nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The header and its proposer's signature.
    pub header: SignedHeader,
    /// The transactions, in the order the header commits to.
    pub transactions: Vec<Transaction>,
    /// The certificate that finalises it, if one has been collected.
    ///
    /// Absent on a freshly proposed block and on every provisional one. A block
    /// is not less valid for lacking one; it is less *final*, which is a
    /// different thing and the whole point of the finality ladder.
    pub certificate: Option<Certificate>,
}

impl Block {
    /// The block's identifier.
    #[must_use]
    pub fn id(&self) -> BlockId {
        self.header.header.id()
    }

    /// The header, unwrapped.
    #[must_use]
    pub fn header(&self) -> &BlockHeader {
        &self.header.header
    }

    /// The transaction identifiers, in block order.
    #[must_use]
    pub fn tx_ids(&self) -> Vec<TxId> {
        self.transactions.iter().map(Transaction::id).collect()
    }

    /// The transaction root implied by the body.
    ///
    /// A Merkle tree over the transaction identifiers, in block order, with an
    /// odd node **promoted and never duplicated** — see
    /// `vanargand_types::merkle`. This must equal the header's `tx_root`, and
    /// checking it is what makes the body's shape irrelevant to consensus: any
    /// encoding that yields these identifiers in this order is the same block.
    #[must_use]
    pub fn computed_tx_root(&self) -> Hash {
        let leaves: Vec<Hash> = self.tx_ids().iter().map(|id| *id.as_hash()).collect();
        merkle::list_root(&leaves)
    }

    /// How many transactions it carries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether it carries none.
    ///
    /// An empty block is legitimate and common: a committee that has nothing to
    /// include still has to keep the chain moving.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

impl Encode for Block {
    fn encode(&self, out: &mut Encoder) {
        self.header.encode(out);
        out.write_seq(&self.transactions);
        out.write_option(self.certificate.as_ref());
    }
}

impl Decode for Block {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            header: SignedHeader::decode(input)?,
            transactions: input.read_seq::<Transaction>()?,
            certificate: input.read_option::<Certificate>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Block;
    use vanargand_crypto::algorithm::AlgorithmId;
    use vanargand_crypto::hash::Hash;
    use vanargand_crypto::sign::{self, Keypair};
    use vanargand_types::amount::Ratio;
    use vanargand_types::block::{BlockHeader, FinalityRung, SignedHeader, HEADER_VERSION};
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::id::{AccountId, BlockId, ChainId, DeviceId};
    use vanargand_types::merkle;
    use vanargand_types::nonce::{Lane, Nonce};
    use vanargand_types::tx::{Transaction, TxBody, TxKind, TX_VERSION};
    use vanargand_types::Amount;

    fn keypair(byte: u8) -> Keypair {
        sign::keypair_from_seed(AlgorithmId::InsecureTest, &Hash::from_bytes([byte; 32]))
            .expect("the test backend is compiled in")
    }

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn header() -> BlockHeader {
        BlockHeader {
            version: HEADER_VERSION,
            chain: ChainId::from_hash(Hash::from_bytes([0x11; 32])),
            height: 10,
            parent: BlockId::from_hash(Hash::from_bytes([0x22; 32])),
            rung: FinalityRung::Chain,
            finalized_height: 10,
            state_root: Hash::from_bytes([0x33; 32]),
            tx_root: Hash::from_bytes([0x44; 32]),
            proposer: account(0xee),
            randomness_reveal: Hash::from_bytes([0x66; 32]),
            archive_commitment: Hash::from_bytes([0x77; 32]),
            emitted_supply: Amount::from_ulf(1),
            security_budget: Amount::from_ulf(1),
            fee_emission_ratio: Ratio::new(1, 1),
        }
    }

    fn transaction(pair: &Keypair, sequence: u64) -> Transaction {
        let body = TxBody {
            version: TX_VERSION,
            chain: ChainId::from_hash(Hash::from_bytes([0x11; 32])),
            account: account(1),
            device: DeviceId::of_device_key(&pair.verifying),
            nonce: Nonce::new(Lane::FIRST, sequence),
            fee: Amount::from_ulf(10),
            valid_until_finalized: None,
            kind: TxKind::Transfer {
                to: account(2),
                asset: None,
                amount: Amount::from_ulf(1),
            },
        };
        let signature =
            sign::sign(&pair.signing, body.signing_digest().as_bytes()).expect("the test backend");
        Transaction { body, signature }
    }

    fn block(count: u64) -> Block {
        let pair = keypair(1);
        let candidate = header();
        let signature = sign::sign(&pair.signing, candidate.signing_digest().as_bytes())
            .expect("the test backend");
        Block {
            header: SignedHeader { header: candidate, signature },
            transactions: (0..count).map(|index| transaction(&pair, index)).collect(),
            certificate: None,
        }
    }

    #[test]
    fn the_transaction_root_is_the_merkle_root_of_the_identifiers() {
        for count in [0_u64, 1, 2, 3, 5, 9] {
            let candidate = block(count);
            let leaves: Vec<Hash> =
                candidate.tx_ids().iter().map(|id| *id.as_hash()).collect();
            assert_eq!(candidate.computed_tx_root(), merkle::list_root(&leaves));
        }
    }

    #[test]
    fn reordering_the_body_changes_the_root() {
        // The header commits to an order, not to a set. Two blocks with the
        // same transactions in different orders are different blocks.
        let mut candidate = block(4);
        let forwards = candidate.computed_tx_root();
        candidate.transactions.reverse();
        assert_ne!(candidate.computed_tx_root(), forwards);
    }

    #[test]
    fn an_empty_block_has_the_zero_root() {
        // Legitimate and common: a committee with nothing to include still has
        // to keep the chain moving.
        let candidate = block(0);
        assert!(candidate.is_empty());
        assert_eq!(candidate.computed_tx_root(), Hash::ZERO);
    }

    #[test]
    fn blocks_round_trip() {
        for count in [0_u64, 1, 7] {
            let candidate = block(count);
            let bytes = candidate.to_canonical_bytes();
            assert_eq!(Block::from_canonical_bytes(&bytes), Ok(candidate));
        }
    }

    #[test]
    fn the_identifier_ignores_the_body() {
        // The header is the consensus object; the body reaches it only through
        // `tx_root`. Two assemblies carrying different transactions under the
        // same header share an identifier — which is why validation checks the
        // root rather than trusting the assembly.
        let one = block(1);
        let two = block(3);
        assert_eq!(one.id(), two.id());
        assert_ne!(one.computed_tx_root(), two.computed_tx_root());
    }
}
