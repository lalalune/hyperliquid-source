use node115_replay_completed_payload::{
    CompletedPayload, ReplayBlockCheck, ReplayPayload, decode_completed_payload,
    decode_framed_replay,
};

fn frame(payload: &[u8], flag: u8) -> Vec<u8> {
    let mut wire = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    wire.push(flag);
    wire.extend(payload);
    wire
}

fn compress_literals(bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![0; 6 + bytes.len()];
    output[..4].copy_from_slice(&128_u32.to_le_bytes());
    let mut used = 4;
    node115_lz4_literal_encoder::encode(bytes, 0, bytes.len(), &mut output, &mut used).unwrap();
    output.truncate(used);
    output
}

#[test]
fn adjacent_plain_and_compressed_frames_reach_the_same_block_decoder() {
    let mut block = vec![0; 10]; // Block tag and signature placeholder
    block.extend([0x31; 20]); // proposer
    block.extend([0, 0, 7, 0]); // hashes, timestamp, quorum parent
    block.extend([1, 2, 3, 4, 5]); // quorum-certificate fields
    block.extend([0x71; 32]); // quorum hash
    block.extend([0, 0, 1, 0]); // votes, omitted proof, present empty attachments
    let block_length = block.len();
    block.extend([0xee, 0xdf]); // bytes outside the decoded prefix within the frame
    let literal = compress_literals(&block);
    let plain = frame(&block, 0);
    let compressed = frame(&literal, 1);
    let wire = [plain.as_slice(), compressed.as_slice()].concat();
    let mut input = wire.as_slice();

    let first = decode_framed_replay(&mut input).unwrap().unwrap();
    assert_eq!(input, compressed);
    let second = decode_framed_replay(&mut input).unwrap().unwrap();
    assert_eq!(first.frame_bytes_consumed, plain.len());
    assert_eq!(second.frame_bytes_consumed, compressed.len());
    assert!(!first.was_compressed);
    assert!(second.was_compressed);
    assert_eq!(first.prefix, second.prefix);
    assert_eq!(first.prefix.decoder_input_len, block.len());
    assert_eq!(first.prefix.consumed, block_length);
    assert_eq!(
        first.prefix.check_block_identity([1, 2]),
        ReplayBlockCheck::Match { successor: 4 },
    );
    assert_eq!(decode_framed_replay(&mut input), Ok(None));
}

#[test]
fn a_non_one_flag_uses_the_plain_payload_bytes() {
    let wire = frame(&[1, 2, 0x42, 0x43], 2);
    let framed = decode_framed_replay(&mut wire.as_slice()).unwrap().unwrap();
    let direct = decode_completed_payload(CompletedPayload::Plain(&[1, 2, 0x42, 0x43])).unwrap();
    assert!(!framed.was_compressed);
    assert_eq!(framed.prefix, direct);
    assert_eq!(
        framed.prefix.result,
        Ok(ReplayPayload::Tx(vec![0x42, 0x43]))
    );
}
