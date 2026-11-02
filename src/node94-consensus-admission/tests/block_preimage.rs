use node94_consensus_admission::block_preimage::{
    block_digest, block_preimage, block_preimage_len, PackedBlockTime,
};
use node94_consensus_admission::{
    BlockHash, Hardfork, Qc, QcVote, Round, SignatureBytes, SignedBlock, Tc, TimeoutVote,
    TransactionHash, ValidatorAddress,
};

fn address(value: u64) -> ValidatorAddress {
    let mut bytes = [0; 20];
    bytes[12..].copy_from_slice(&value.to_be_bytes());
    ValidatorAddress(bytes)
}

fn qc() -> Qc {
    Qc {
        votes: vec![],
        hardfork: Hardfork {
            version: 0,
            start_round: Round(0),
        },
        round: Round(0),
        block_hash: BlockHash(std::array::from_fn(|i| i as u8)),
    }
}

fn base() -> (SignedBlock, PackedBlockTime) {
    (
        SignedBlock {
            transaction_hashes: vec![],
            qc: qc(),
            tc: None,
            round: Round(0),
            proposer: address(0x123456),
            signature: SignatureBytes([0; 72]),
        },
        PackedBlockTime {
            packed_date: 16_138_256,
            seconds: 0,
            nanoseconds: 0,
        },
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn frozen_minimal_witness() {
    // Immutable pre-Rust C000000; no target execution supplied this constant.
    let (block, time) = base();
    let bytes = block_preimage(&block, time).unwrap();
    assert_eq!(block_preimage_len(&block, time).unwrap(), 91);
    assert_eq!(hex(&bytes), "48797065726c697175696420436f6e73656e737573205061796c6f616400000000000000000000000000000000000012345600000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000");
    assert_eq!(
        hex(&block_digest(&block, time).unwrap()),
        "e7890d4ddf2fdd920f65d99ff186ed63c2ad78f59ba9575a6fa366f7daa9329c"
    );
}

#[test]
fn raw_time_extrema_epoch_and_ignored_flags() {
    let (block, mut time) = base();
    assert_eq!(time.timestamp_seconds(), 0);
    time.packed_date = (1969 << 13) | (365 << 4);
    time.seconds = 86_399;
    assert_eq!(time.timestamp_seconds(), -1);
    assert_eq!(block_preimage(&block, time).unwrap()[52], 1);
    let bytes = block_preimage(&block, time).unwrap();
    time.packed_date |= 15;
    assert_eq!(block_preimage(&block, time).unwrap(), bytes);
    time.packed_date = i32::MIN;
    time.seconds = 0;
    assert_eq!(time.timestamp_seconds(), -8_334_632_937_600);
    time.packed_date = i32::MAX;
    time.seconds = u32::MAX;
    time.nanoseconds = u32::MAX;
    assert_eq!(time.timestamp_seconds(), 8_214_605_908_095);
    assert!(block_preimage(&block, time).is_ok());
}

#[test]
fn present_empty_certificate_is_distinct() {
    // Immutable pre-Rust C000919.
    let (mut block, time) = base();
    let absent = block_preimage(&block, time).unwrap();
    block.tc = Some(Tc {
        round: Round(251),
        votes: vec![],
    });
    let present = block_preimage(&block, time).unwrap();
    assert_eq!(&present[..90], &absent[..90]);
    assert_eq!(&present[90..], &[1, 251, 251, 0, 0]);
    assert_eq!(
        hex(&block_digest(&block, time).unwrap()),
        "55726f47ed6a6b3fd8e362c92b7f6d3906ad3de0ec5fdb4905d0b9ca112e3860"
    );
}

#[test]
fn timeout_signature_precedes_body_and_uses_limb_encoding() {
    let (mut block, time) = base();
    let mut signature = [0; 72];
    signature[..8].copy_from_slice(&251_u64.to_le_bytes());
    signature[64] = 255;
    block.tc = Some(Tc {
        round: Round(251),
        votes: vec![TimeoutVote {
            signer: address(0x1001),
            round: Round(0),
            qc: qc(),
            signature: SignatureBytes(signature),
        }],
    });
    let bytes = block_preimage(&block, time).unwrap();
    assert_eq!(&bytes[90..95], &[1, 251, 251, 0, 1]);
    assert_eq!(&bytes[95..106], &[251, 251, 0, 0, 0, 0, 0, 0, 0, 0, 255]);
    assert_eq!(&bytes[106..126], &address(0x1001).0);
    assert_eq!(bytes.len(), block_preimage_len(&block, time).unwrap());
}

#[test]
fn active_nested_signatures_and_inactive_padding_are_distinct() {
    let (mut block, time) = base();
    block.qc.votes.push(QcVote {
        signer: address(1),
        signature: SignatureBytes([0; 72]),
    });
    block.tc = Some(Tc {
        round: Round(2),
        votes: vec![TimeoutVote {
            signer: address(3),
            round: Round(2),
            qc: block.qc.clone(),
            signature: SignatureBytes([0; 72]),
        }],
    });
    let original = block_preimage(&block, time).unwrap();
    block.signature.0.fill(255);
    block.qc.votes[0].signature.0[65..].fill(255);
    let timeout = &mut block.tc.as_mut().unwrap().votes[0];
    timeout.signature.0[65..].fill(255);
    timeout.qc.votes[0].signature.0[65..].fill(255);
    assert_eq!(block_preimage(&block, time).unwrap(), original);
    block.tc.as_mut().unwrap().votes[0].signature.0[64] = 255;
    assert_ne!(block_preimage(&block, time).unwrap(), original);
    block.tc.as_mut().unwrap().votes[0].signature.0[64] = 0;
    block.tc.as_mut().unwrap().votes[0].qc.votes[0].signature.0[0] = 1;
    assert_ne!(block_preimage(&block, time).unwrap(), original);
}

#[test]
fn supplied_hash_vote_order_and_claimed_identity_are_preserved() {
    let (mut block, time) = base();
    block.transaction_hashes = vec![TransactionHash([1; 32]), TransactionHash([2; 32])];
    block.qc.votes = vec![
        QcVote {
            signer: address(1),
            signature: SignatureBytes([0; 72]),
        },
        QcVote {
            signer: address(2),
            signature: SignatureBytes([0; 72]),
        },
    ];
    let original = block_preimage(&block, time).unwrap();
    block.transaction_hashes.reverse();
    assert_ne!(block_preimage(&block, time).unwrap(), original);
    block.transaction_hashes.reverse();
    block.qc.votes.reverse();
    assert_ne!(block_preimage(&block, time).unwrap(), original);
    block.qc.votes.reverse();
    block.proposer = address(9);
    assert_ne!(block_preimage(&block, time).unwrap(), original);
}

#[test]
fn frozen_exact_and_over_rate_boundary_digests() {
    // Immutable pre-Rust C001133/C001134; the exact rate requires a padding block.
    let (mut block, mut time) = base();
    time.nanoseconds = 65_536;
    block.qc.hardfork.start_round = Round(65_536);
    block.qc.round = Round(1 << 32);
    block.qc.votes.push(QcVote {
        signer: address(1),
        signature: SignatureBytes([0; 72]),
    });
    assert_eq!(block_preimage_len(&block, time).unwrap(), 136);
    assert_eq!(
        hex(&block_digest(&block, time).unwrap()),
        "4511fb5486645e512c7eacca17da85899a9642a5f945afd30c4c87d0c13d17d0"
    );
    block.transaction_hashes.push(TransactionHash([0x5a; 32]));
    block.qc.votes.clear();
    block.qc.hardfork.start_round = Round(251);
    assert_eq!(block_preimage_len(&block, time).unwrap(), 137);
    assert_eq!(
        hex(&block_digest(&block, time).unwrap()),
        "19af802e3ee58deb2c09df31552445735216c2b6c57422671d50f1605b3c8af2"
    );
}
