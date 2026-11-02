// Selected immutable pre-Rust fixtures; the task-local driver checks all 534 cases.
use node94_consensus_admission::message_preimages::*;
use node94_consensus_admission::{
    BlockHash, Hardfork, Qc, QcVote, Round, SignatureBytes, ValidatorAddress,
};
fn bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn fixed<const N: usize>(text: &str) -> [u8; N] {
    bytes(text).try_into().unwrap()
}

#[test]
fn frozen_signature_mixed_final_255() {
    let qc = Qc {votes: vec![QcVote {signer: ValidatorAddress(fixed("0000000000000000000000000000000000000001")), signature: SignatureBytes(fixed("f900000000000000fa00000000000000fb00000000000000fc00000000000000feff000000000000ffff00000000000000000100000000000100010000000000ffa5a5a5a5a5a5a5"))}, QcVote {signer: ValidatorAddress(fixed("0000000000000000000000000000000000000002")), signature: SignatureBytes(fixed("fa00000000000000fb00000000000000fc00000000000000feff000000000000ffff00000000000000000100000000000100010000000000ffffffff00000000ffa5a5a5a5a5a5a5"))}], hardfork: Hardfork {version: 0, start_round: Round(0)}, round: Round(0), block_hash: BlockHash(fixed("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))};
    let preimage = timeout_preimage(
        &qc,
        Round(0),
        ValidatorAddress(fixed("0000000000000000000000000000000000123456")),
    )
    .unwrap();
    let digest = timeout_digest(
        &qc,
        Round(0),
        ValidatorAddress(fixed("0000000000000000000000000000000000123456")),
    )
    .unwrap();
    assert_eq!(preimage.len(), timeout_preimage_len(&qc, Round(0)).unwrap());
    assert_eq!(preimage, bytes("48797065726c697175696420436f6e73656e737573205061796c6f616402000000000000000000000000000000000012345600000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f020000000000000000000000000000000000000001f9fafbfb00fbfc00fbfefffbfffffc00000100fc01000100ff0000000000000000000000000000000000000002fafbfb00fbfc00fbfefffbfffffc00000100fc01000100fcffffffffff"));
    assert_eq!(
        digest,
        fixed::<32>("642ef9c0f744b69f6413be93c694679135f65ba3907cb5dc76a39f415835bcc1")
    );
}

#[test]
fn frozen_heartbeat_option_1111() {
    let stakes = [
        OrderedWordEntry {
            address: ValidatorAddress(fixed("0000000000000000000000000000000000000002")),
            word: 251,
        },
        OrderedWordEntry {
            address: ValidatorAddress(fixed("0000000000000000000000000000000000000001")),
            word: 18446744073709551615,
        },
    ];
    let jailed = [
        ValidatorAddress(fixed("0000000000000000000000000000000000000007")),
        ValidatorAddress(fixed("0000000000000000000000000000000000000003")),
    ];
    let summaries = [
        ConsensusSummary {
            first: 251,
            second: 4294967296,
            block_hash: BlockHash(fixed(
                "0101010101010101010101010101010101010101010101010101010101010101",
            )),
        },
        ConsensusSummary {
            first: 252,
            second: 4294967297,
            block_hash: BlockHash(fixed(
                "0202020202020202020202020202020202020202020202020202020202020202",
            )),
        },
        ConsensusSummary {
            first: 253,
            second: 4294967298,
            block_hash: BlockHash(fixed(
                "0303030303030303030303030303030303030303030303030303030303030303",
            )),
        },
    ];
    let peers = [
        OrderedWordEntry {
            address: ValidatorAddress(fixed("0000000000000000000000000000000000000008")),
            word: 65536,
        },
        OrderedWordEntry {
            address: ValidatorAddress(fixed("0000000000000000000000000000000000000004")),
            word: 0,
        },
    ];
    let message = HeartbeatMessage {
        signer: ValidatorAddress(fixed("0000000000000000000000000000000000abcdef")),
        round: Round(0),
        random: 0,
        snapshot: Some(HeartbeatSnapshot {
            stakes: Some(&stakes),
            jailed: Some(&jailed),
            evm_word: 123,
            summaries: Some(&summaries),
        }),
        peers: Some(&peers),
    };
    let preimage = heartbeat_preimage(&message).unwrap();
    let digest = heartbeat_digest(&message).unwrap();
    assert_eq!(preimage.len(), heartbeat_preimage_len(&message).unwrap());
    assert_eq!(preimage, bytes("48797065726c697175696420436f6e73656e737573205061796c6f6164030000000000000000000000000000000000abcdef000101020000000000000000000000000000000000000002fbfb000000000000000000000000000000000000000001fdffffffffffffffff0102000000000000000000000000000000000000000700000000000000000000000000000000000000037b01fbfb00fd00000000010000000101010101010101010101010101010101010101010101010101010101010101fbfc00fd01000000010000000202020202020202020202020202020202020202020202020202020202020202fbfd00fd0200000001000000030303030303030303030303030303030303030303030303030303030303030301020000000000000000000000000000000000000008fc0000010000000000000000000000000000000000000000040000"));
    assert_eq!(
        digest,
        fixed::<32>("be899be905e15ad009ce3c88fd0bad4e83274e1de302ddb3450ccd9658aac64a")
    );
}

#[test]
fn frozen_empty_vs_absent_111() {
    let stakes = [];
    let jailed = [];
    let peers = [];
    let message = HeartbeatMessage {
        signer: ValidatorAddress(fixed("0000000000000000000000000000000000abcdef")),
        round: Round(0),
        random: 0,
        snapshot: Some(HeartbeatSnapshot {
            stakes: Some(&stakes),
            jailed: Some(&jailed),
            evm_word: 0,
            summaries: None,
        }),
        peers: Some(&peers),
    };
    let preimage = heartbeat_preimage(&message).unwrap();
    let digest = heartbeat_digest(&message).unwrap();
    assert_eq!(preimage.len(), heartbeat_preimage_len(&message).unwrap());
    assert_eq!(preimage, bytes("48797065726c697175696420436f6e73656e737573205061796c6f6164030000000000000000000000000000000000abcdef0001010001000000010000"));
    assert_eq!(
        digest,
        fixed::<32>("9291f96da03749f08de8afa469f21c48b9f5b821fcdb3aea0f0b5c8bb12b1de5")
    );
}

#[test]
fn frozen_ack_4294967296_65536() {
    let preimage = acknowledgement_preimage(
        ValidatorAddress(fixed("00000000000000000000000000000000000000ff")),
        65536,
        Round(4294967296),
    )
    .unwrap();
    let digest = acknowledgement_digest(
        ValidatorAddress(fixed("00000000000000000000000000000000000000ff")),
        65536,
        Round(4294967296),
    )
    .unwrap();
    assert_eq!(
        preimage.len(),
        acknowledgement_preimage_len(65536, Round(4294967296))
    );
    assert_eq!(preimage, bytes("48797065726c697175696420436f6e73656e737573205061796c6f61640400000000000000000000000000000000000000fffc00000100fd0000000001000000"));
    assert_eq!(
        digest,
        fixed::<32>("37152e0d8386cca550801528cd238dcdeb0662cabb0e8e167e63f1e1847cb837")
    );
}

#[test]
fn frozen_rate_boundary_137() {
    let stakes = [
        OrderedWordEntry {
            address: ValidatorAddress(fixed("0000000000000000000000000000000000000001")),
            word: 4294967296,
        },
        OrderedWordEntry {
            address: ValidatorAddress(fixed("0000000000000000000000000000000000000002")),
            word: 4294967296,
        },
    ];
    let message = HeartbeatMessage {
        signer: ValidatorAddress(fixed("0000000000000000000000000000000000abcdef")),
        round: Round(4294967296),
        random: 65536,
        snapshot: Some(HeartbeatSnapshot {
            stakes: Some(&stakes),
            jailed: None,
            evm_word: 4294967296,
            summaries: None,
        }),
        peers: None,
    };
    let preimage = heartbeat_preimage(&message).unwrap();
    let digest = heartbeat_digest(&message).unwrap();
    assert_eq!(preimage.len(), heartbeat_preimage_len(&message).unwrap());
    assert_eq!(preimage, bytes("48797065726c697175696420436f6e73656e737573205061796c6f6164030000000000000000000000000000000000abcdeffd00000000010000000101020000000000000000000000000000000000000001fd00000000010000000000000000000000000000000000000000000002fd000000000100000000fd00000000010000000000fc00000100"));
    assert_eq!(
        digest,
        fixed::<32>("1ad5a19e6a8fa52c6a7f47c694f040df425be9d1dc691a74a7f47100743ab909")
    );
}

#[test]
fn padding_is_ignored_but_active_signature_signer_and_order_are_not() {
    let mut qc = Qc {
        votes: vec![
            QcVote {
                signer: ValidatorAddress([1; 20]),
                signature: SignatureBytes([0; 72]),
            },
            QcVote {
                signer: ValidatorAddress([2; 20]),
                signature: SignatureBytes([0; 72]),
            },
        ],
        hardfork: Hardfork {
            version: 0,
            start_round: Round(0),
        },
        round: Round(0),
        block_hash: BlockHash([3; 32]),
    };
    let signer = ValidatorAddress([4; 20]);
    let original = timeout_preimage(&qc, Round(0), signer).unwrap();
    qc.votes[0].signature.0[65..].fill(255);
    assert_eq!(timeout_preimage(&qc, Round(0), signer).unwrap(), original);
    qc.votes[0].signature.0[64] = 255; // Unrestricted final byte, not recovery-ID validation.
    assert_ne!(timeout_preimage(&qc, Round(0), signer).unwrap(), original);
    qc.votes[0].signature.0[64] = 0;
    qc.votes[0].signature.0[7] = 1; // Little-endian limb, not eight raw encoded bytes.
    assert_ne!(timeout_preimage(&qc, Round(0), signer).unwrap(), original);
    qc.votes[0].signature.0[7] = 0;
    qc.votes.reverse();
    assert_ne!(timeout_preimage(&qc, Round(0), signer).unwrap(), original);
    qc.votes.reverse();
    assert_ne!(
        timeout_preimage(&qc, Round(0), ValidatorAddress([5; 20])).unwrap(),
        original
    );
    qc.votes.clear();
    assert_ne!(timeout_preimage(&qc, Round(0), signer).unwrap(), original);
}

#[test]
fn heartbeat_option_presence_and_supplied_order_are_observable() {
    let rows = [
        OrderedWordEntry {
            address: ValidatorAddress([2; 20]),
            word: 251,
        },
        OrderedWordEntry {
            address: ValidatorAddress([1; 20]),
            word: 65536,
        },
    ];
    let mut message = HeartbeatMessage {
        signer: ValidatorAddress([3; 20]),
        round: Round(4),
        random: 5,
        snapshot: None,
        peers: None,
    };
    let absent = heartbeat_preimage(&message).unwrap();
    message.peers = Some(&[]);
    assert_ne!(heartbeat_preimage(&message).unwrap(), absent);
    message.peers = Some(&rows);
    let supplied = heartbeat_preimage(&message).unwrap();
    let reversed = [rows[1], rows[0]];
    message.peers = Some(&reversed);
    assert_ne!(heartbeat_preimage(&message).unwrap(), supplied);
    message.peers = None;
    message.snapshot = Some(HeartbeatSnapshot {
        stakes: None,
        jailed: None,
        evm_word: 0,
        summaries: None,
    });
    assert_ne!(heartbeat_preimage(&message).unwrap(), absent);
}
