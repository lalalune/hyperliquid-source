use node94_consensus_admission::{
    qc_vote_digest, qc_vote_preimage, BlockHash, Hardfork, Qc, QcVote, Round, SignatureBytes,
    ValidatorAddress,
};

fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn make_qc(version: u64, start: u64, round: u64, hash: &str) -> Qc {
    Qc {
        votes: vec![],
        hardfork: Hardfork {
            version,
            start_round: Round(start),
        },
        round: Round(round),
        block_hash: BlockHash(bytes(hash).try_into().unwrap()),
    }
}

// Literal expected bytes come from the pre-Rust receipt, not this implementation.
#[test]
fn frozen_native_preimage_and_independent_digest_examples() {
    // zero
    let qc = make_qc(
        0,
        0,
        0,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let signer = ValidatorAddress(
        bytes("0000000000000000000000000000000000000000")
            .try_into()
            .unwrap(),
    );
    assert_eq!(qc_vote_preimage(&qc, signer), bytes("48797065726c697175696420436f6e73656e737573205061796c6f61640100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
    assert_eq!(
        qc_vote_digest(&qc, signer).as_slice(),
        bytes("fc8e2a35833eda2538e12bac1504c96dcfc6d2c8ad33a1cf369a9a2115bd8c49")
    );
    // boundary-194
    let qc = make_qc(
        250,
        251,
        65536,
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
    );
    let signer = ValidatorAddress(
        bytes("000102030405060708090a0b0c0d0e0f10111213")
            .try_into()
            .unwrap(),
    );
    assert_eq!(qc_vote_preimage(&qc, signer), bytes("48797065726c697175696420436f6e73656e737573205061796c6f616401000102030405060708090a0b0c0d0e0f10111213fafbfb00fc00000100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"));
    assert_eq!(
        qc_vote_digest(&qc, signer).as_slice(),
        bytes("3e4704923f4b8f363571f900bdf8eb406f1e2d5280a516d17f9696f9fe6dd5e3")
    );
    // maximum
    let qc = make_qc(
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    let signer = ValidatorAddress(
        bytes("ffffffffffffffffffffffffffffffffffffffff")
            .try_into()
            .unwrap(),
    );
    assert_eq!(qc_vote_preimage(&qc, signer), bytes("48797065726c697175696420436f6e73656e737573205061796c6f616401fffffffffffffffffffffffffffffffffffffffffdfffffffffffffffffdfffffffffffffffffdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    assert_eq!(
        qc_vote_digest(&qc, signer).as_slice(),
        bytes("7676d68ef2d2ead05b4d46990118bd7042820acca56840907fec9124157edea0")
    );
}

#[test]
fn only_the_explicit_signer_and_signed_qc_fields_affect_the_preimage() {
    let mut qc = make_qc(250, 251, 65536, &"03".repeat(32));
    let signer = ValidatorAddress([1; 20]);
    let original = qc_vote_preimage(&qc, signer);
    qc.votes.push(QcVote {
        signer: ValidatorAddress([9; 20]),
        signature: SignatureBytes([7; 72]),
    });
    assert_eq!(qc_vote_preimage(&qc, signer), original);
    qc.votes[0].signature.0[0] ^= 1;
    assert_eq!(qc_vote_preimage(&qc, signer), original);
    assert_ne!(qc_vote_preimage(&qc, ValidatorAddress([2; 20])), original);
    qc.hardfork.version += 1;
    assert_ne!(qc_vote_preimage(&qc, signer), original);
}
