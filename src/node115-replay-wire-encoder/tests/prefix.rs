use node115_client_block_success::decode_payload_prefix;
use node115_replay_wire_encoder::encode_replay_payload;

// Existing fixed byte fixtures from node115-client-block-success/tests/payload.rs.
fn u64v(out: &mut Vec<u8>, value: u64) {
    assert!(value <= 250);
    out.push(value as u8);
}

fn signature(out: &mut Vec<u8>) {
    for _ in 0..8 {
        u64v(out, 0);
    }
    out.push(7);
}

fn qc(out: &mut Vec<u8>, vote: bool) {
    for value in 1..=5 {
        u64v(out, value);
    }
    out.extend([0x44; 32]);
    u64v(out, u64::from(vote));
    if vote {
        out.extend([0x22; 20]);
        signature(out);
    }
}

fn header(out: &mut Vec<u8>, timeout_parent: bool, nested_qc: bool) {
    out.extend([0x11; 20]);
    u64v(out, 1);
    out.extend([0x33; 32]);
    // ZigZag(-1), then nanoseconds.
    out.extend([1, 9]);
    if timeout_parent {
        u64v(out, 1);
        u64v(out, 8);
        qc(out, false);
        u64v(out, 1);
        out.extend([0x55; 20]);
        u64v(out, 9);
        signature(out);
        out.push(u8::from(nested_qc));
        if nested_qc {
            qc(out, false);
        }
    } else {
        u64v(out, 0);
        qc(out, false);
    }
}

fn successful_payload() -> Vec<u8> {
    let mut out = Vec::new();
    u64v(&mut out, 1); // Vec<Client>
    signature(&mut out);
    header(&mut out, true, true);
    out.push(1); // Some(CommitProof)
    signature(&mut out);
    header(&mut out, false, false);
    qc(&mut out, true);
    u64v(&mut out, 1); // one attachment
    out.extend([0x66; 32]);
    u64v(&mut out, 4);
    out.extend([251, 252, 253, 255]); // opaque; not decoded as varints
    out
}

fn replay_block(option: u8) -> Vec<u8> {
    let mut input = vec![0];
    signature(&mut input);
    header(&mut input, false, false);
    input.extend([0, option]); // no commit proof, then replay attachment option
    input
}

#[test]
fn replay_writer_reproduces_fixed_outer_prefix_fixtures() {
    use node115_client_block_success::{ReplayPayload, decode_replay_payload_prefix};

    let absent = replay_block(0);
    let mut empty = replay_block(1);
    empty.push(0);
    let mut populated = replay_block(1);
    populated.extend([1]);
    populated.extend([0x66; 32]);
    populated.extend([3, 251, 252, 255]);
    for fixture in [
        absent,
        empty,
        populated,
        vec![1, 0],
        vec![1, 3, 251, 252, 255],
    ] {
        let decoded = decode_replay_payload_prefix(&fixture, 10_000_000);
        assert!(decoded.remaining.is_empty());
        assert_eq!(
            encode_replay_payload(&decoded.result.unwrap()).unwrap(),
            fixture
        );
    }

    let bytes = vec![0x88; 251];
    let mut expected = vec![1, 251, 251, 0];
    expected.extend_from_slice(&bytes);
    assert_eq!(
        encode_replay_payload(&ReplayPayload::Tx(bytes)).unwrap(),
        expected
    );
}

#[test]
fn replay_writer_reproduces_timeout_commit_proof_and_attachment_bytes() {
    use node115_client_block_success::ReplayPayload;
    use node115_replay_wire_encoder::ReplayEncodeError;

    let client_bytes = successful_payload();
    let mut clients = decode_payload_prefix(&client_bytes).result.unwrap();
    let client = clients.pop().unwrap();

    let attachment_count_offset = client_bytes.len() - 38;
    assert_eq!(client_bytes[attachment_count_offset], 1);
    let mut expected = vec![0];
    expected.extend_from_slice(&client_bytes[1..attachment_count_offset]);
    expected.push(1);
    expected.extend_from_slice(&client_bytes[attachment_count_offset..]);
    let mut payload = ReplayPayload::Block {
        block: Box::new(client.block),
        attachments: Some(client.attachments),
    };
    assert_eq!(encode_replay_payload(&payload).unwrap(), expected);
    if let ReplayPayload::Block { block, .. } = &mut payload {
        block.header.timestamp.packed_date ^= 1;
    }
    assert_eq!(
        encode_replay_payload(&payload),
        Err(ReplayEncodeError::InvalidTimestamp)
    );
}
