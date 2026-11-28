use node115_replay_completed_payload::{
    CompletedPayload, CompressionError, LocalStartupState, REPLAY_LIMIT, ReplayBlockCheck,
    ReplayPayload, StaleFreezeHeight, decode_completed_payload,
};

fn compress_literals(input: &[u8], declared_capacity: u32) -> Vec<u8> {
    let mut output = vec![0; 6 + input.len()];
    output[..4].copy_from_slice(&declared_capacity.to_le_bytes());
    let mut used = 4;
    node115_lz4_literal_encoder::encode(input, 0, input.len(), &mut output, &mut used).unwrap();
    output.truncate(used);
    output
}

#[test]
fn tx_uses_the_actual_decoded_span_and_preserves_the_prefix_boundary() {
    let tx = [1, 3, 0x42, 0x43, 0x44, 0xee];
    let encoded = compress_literals(&tx, 20);
    let plain = decode_completed_payload(CompletedPayload::Plain(&tx)).unwrap();
    let compressed = decode_completed_payload(CompletedPayload::SizePrefixedLz4(&encoded)).unwrap();
    assert_eq!(compressed, plain);
    assert_eq!(plain.decoder_input_len, 6);
    assert_eq!(plain.consumed, 5);
    assert_eq!(plain.charged, 15);
    assert_eq!(plain.result, Ok(ReplayPayload::Tx(vec![0x42, 0x43, 0x44])));
    assert_eq!(plain.check_block_identity([0, 0]), ReplayBlockCheck::Tx);
}

fn replay_block(parent_words: [u64; 3]) -> Vec<u8> {
    let mut block = vec![0];
    block.extend([0; 9]); // signature
    block.extend([0x31; 20]); // proposer address
    block.extend([0, 0, 0, 0]); // hashes, seconds, nanos, quorum parent
    for word in parent_words {
        if word < 251 {
            block.push(word as u8);
        } else {
            block.push(253);
            block.extend(word.to_le_bytes());
        }
    }
    block.extend([4, 5]);
    block.extend([0x71; 32]); // quorum hash
    block.extend([0, 0, 1, 0]); // votes, omitted proof, present empty attachments
    block
}

#[test]
fn block_and_empty_attachment_option_survive_both_arms() {
    let block = replay_block([1, 2, 3]);
    let encoded = compress_literals(&block, block.len() as u32);
    let plain = decode_completed_payload(CompletedPayload::Plain(&block)).unwrap();
    let compressed = decode_completed_payload(CompletedPayload::SizePrefixedLz4(&encoded)).unwrap();
    assert_eq!(compressed, plain);
    assert_eq!(plain.consumed, block.len());
    assert_eq!(
        plain.check_block_identity([1, 2]),
        ReplayBlockCheck::Match { successor: 4 },
    );
    for wrong in [[9, 2], [1, 9], [2, 1]] {
        assert_eq!(
            compressed.check_block_identity(wrong),
            ReplayBlockCheck::Mismatch { observed: [1, 2] },
        );
    }
    let ReplayPayload::Block { block, attachments } = plain.result.unwrap() else {
        panic!("expected Block");
    };
    assert_eq!(block.header.address, [0x31; 20]);
    assert_eq!(attachments, Some(vec![]));
}

#[test]
fn local_startup_selects_original_or_rewritten_words_before_the_block_check() {
    let state = LocalStartupState {
        height: 100,
        context_round: 7,
        hardfork_version: 1,
        hardfork_round: 2,
        scheduled_freeze_height: None,
    };
    let original = replay_block([1, 2, 3]);
    let original = decode_completed_payload(CompletedPayload::Plain(&original)).unwrap();
    let updated = replay_block([2, 7, 3]);
    let encoded = compress_literals(&updated, updated.len() as u32);
    let updated = decode_completed_payload(CompletedPayload::SizePrefixedLz4(&encoded)).unwrap();
    for target in [None, Some(101)] {
        let bypass = LocalStartupState {
            scheduled_freeze_height: target,
            ..state
        };
        assert_eq!(
            original.check_local_startup(bypass),
            Ok(ReplayBlockCheck::Match { successor: 4 })
        );
    }
    let rewrite = LocalStartupState {
        scheduled_freeze_height: Some(100),
        ..state
    };
    assert_eq!(
        original.check_local_startup(rewrite),
        Ok(ReplayBlockCheck::Mismatch { observed: [1, 2] })
    );
    assert_eq!(
        updated.check_local_startup(rewrite),
        Ok(ReplayBlockCheck::Match { successor: 4 })
    );
    let stale = LocalStartupState {
        scheduled_freeze_height: Some(99),
        ..state
    };
    assert_eq!(
        updated.check_local_startup(stale),
        Err(StaleFreezeHeight {
            target: 99,
            restored: 100
        })
    );
    let saturated = replay_block([u64::MAX, 7, 3]);
    let saturated = decode_completed_payload(CompletedPayload::Plain(&saturated)).unwrap();
    let saturated_state = LocalStartupState {
        hardfork_version: u64::MAX,
        ..rewrite
    };
    assert_eq!(
        saturated.check_local_startup(saturated_state),
        Ok(ReplayBlockCheck::Match { successor: 4 })
    );
}

#[test]
fn stage_boundaries_preserve_the_inner_result_or_the_compression_error() {
    let empty = decode_completed_payload(CompletedPayload::Plain(&[])).unwrap();
    assert!(empty.result.is_err());
    assert_eq!(
        empty.check_block_identity([0, 0]),
        ReplayBlockCheck::DecodeFailed,
    );
    assert_eq!((empty.consumed, empty.charged), (0, 4));

    let encoded = compress_literals(&[1, 0], REPLAY_LIMIT as u32 + 1);
    assert_eq!(
        decode_completed_payload(CompletedPayload::SizePrefixedLz4(&encoded)),
        Err(CompressionError::Limit),
    );
}
