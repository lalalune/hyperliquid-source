use node115_replay_completed_payload::CompletedPayload;
use node115_replay_completed_payload::first_block::{SelectionError, select_first_block};

fn block(version: u8, round: u8, identity: u8) -> Vec<u8> {
    let mut wire = vec![0; 10]; // Block tag and signature placeholder
    wire.extend([0x31; 20]); // proposer
    wire.extend([0, 0, 7, 0]); // hashes, timestamp, quorum parent
    wire.extend([version, round, identity, 4, 5]); // quorum-certificate fields
    wire.extend([0x71; 32]); // quorum hash
    wire.extend([0, 0, 1, 0]); // votes, omitted proof, present empty attachments
    wire
}

fn compress_literals(payload: &[u8]) -> Vec<u8> {
    let mut output = vec![0; payload.len() + 6];
    output[..4].copy_from_slice(&128_u32.to_le_bytes());
    let mut used = 4;
    node115_lz4_literal_encoder::encode(payload, 0, payload.len(), &mut output, &mut used).unwrap();
    output.truncate(used);
    output
}

#[test]
fn mixed_capture_preserves_record_position_and_decoder_boundary() {
    let opaque = [1, 2, 0x42, 0x43];
    let mut incoming = block(1, 2, 40);
    let consumed = incoming.len();
    incoming.extend([0xee, 0xdf]);
    let compressed = compress_literals(&incoming);
    let later_block = block(1, 2, 92);
    let items = [
        CompletedPayload::Plain(&opaque),
        CompletedPayload::Plain(&opaque),
        CompletedPayload::SizePrefixedLz4(&compressed),
        CompletedPayload::Plain(&later_block),
    ];

    let selected = select_first_block(&items, [1, 2]).unwrap().unwrap();
    assert_eq!(selected.position, 2);
    assert_eq!(selected.decoder_input_len, incoming.len());
    assert_eq!(selected.decoder_consumed, consumed);
    assert!(selected.decoder_charged > 0);
    assert_eq!(selected.successor, 41);
    assert_eq!(selected.block.header.address, [0x31; 20]);
    assert_eq!(selected.attachments, Some(Vec::new()));
}

#[test]
fn opaque_only_fixture_contains_no_block() {
    let compressed = compress_literals(&[1, 1, 0x42]);
    let items = [
        CompletedPayload::Plain(&[1, 0]),
        CompletedPayload::SizePrefixedLz4(&compressed),
    ];
    assert_eq!(select_first_block(&items, [1, 2]), Ok(None));
    assert_eq!(select_first_block(&[], [1, 2]), Ok(None));
}

#[test]
fn selection_reports_the_first_block_mismatch_without_using_a_later_candidate() {
    let first = block(1, 3, 40);
    let later = block(1, 2, 92);
    let items = [
        CompletedPayload::Plain(&[1, 0]),
        CompletedPayload::Plain(&first),
        CompletedPayload::Plain(&later),
    ];
    assert_eq!(
        select_first_block(&items, [1, 2]),
        Err(SelectionError::StartupPair {
            position: 1,
            expected: [1, 2],
            observed: [1, 3],
        }),
    );
}
