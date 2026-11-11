use node115_frame_stream::{FrameError, FrameReader, Status};
use node115_lz4_decode::DecodeError;

#[test]
fn fragmented_header_and_payload_at_exact_limit() {
    let mut r = FrameReader::new(3);
    let a = r.feed(&[0, 0]);
    assert_eq!((a.consumed, a.status), (2, Status::Pending));
    let b = r.feed(&[0, 3, 0, b'a']);
    assert_eq!((b.consumed, b.status), (4, Status::Pending));
    let c = r.feed(b"bc");
    assert_eq!(
        (c.consumed, c.status),
        (2, Status::Complete(b"abc".to_vec()))
    );
    assert_eq!(
        r.feed(b"extra").status,
        Status::Failed(FrameError::AlreadyTerminal)
    );
}

#[test]
fn coalesced_frames_leave_the_next_frame_unconsumed() {
    let data = [0, 0, 0, 2, 0, b'a', b'b', 0, 0, 0, 1, 2, b'z'];
    let mut first = FrameReader::new(2);
    let out = first.feed(&data);
    assert_eq!(
        (out.consumed, out.status),
        (7, Status::Complete(b"ab".to_vec()))
    );
    let mut second = FrameReader::new(2);
    let out = second.feed(&data[7..]);
    assert_eq!(
        (out.consumed, out.status),
        (6, Status::Complete(b"z".to_vec()))
    );
}

#[test]
fn compressed_frame_joins_the_actual_decoder() {
    let data = [0, 0, 0, 9, 1, 8, 0, 0, 0, 0x13, b'A', 1, 0, 0];
    let mut r = FrameReader::new(9);
    assert_eq!(r.feed(&data[..8]).status, Status::Pending);
    let out = r.feed(&data[8..]);
    assert_eq!(out.status, Status::Complete(vec![b'A'; 8]));
}

#[test]
fn over_limit_and_decoder_errors_are_terminal() {
    let mut over = FrameReader::new(2);
    let out = over.feed(&[0, 0, 0, 3, 0, b'x']);
    assert_eq!(
        (out.consumed, out.status),
        (5, Status::Failed(FrameError::OverLimit))
    );
    assert_eq!(
        over.feed(b"x").status,
        Status::Failed(FrameError::AlreadyTerminal)
    );

    let mut bad = FrameReader::new(0);
    let out = bad.feed(&[0, 0, 0, 0, 1]);
    assert_eq!(
        out.status,
        Status::Failed(FrameError::Decode(DecodeError::Header))
    );
    assert_eq!(
        bad.eof().status,
        Status::Failed(FrameError::AlreadyTerminal)
    );
}

#[test]
fn explicit_eof_fails_partial_header_and_body_without_reuse() {
    let mut h = FrameReader::new(10);
    assert_eq!(h.feed(&[]).status, Status::Pending);
    assert_eq!(h.feed(&[0, 0]).status, Status::Pending);
    assert_eq!(h.eof().status, Status::Failed(FrameError::EarlyEof));
    assert_eq!(
        h.feed(&[]).status,
        Status::Failed(FrameError::AlreadyTerminal)
    );

    let mut b = FrameReader::new(10);
    assert_eq!(b.feed(&[0, 0, 0, 2, 0, b'a']).status, Status::Pending);
    assert_eq!(b.eof().status, Status::Failed(FrameError::EarlyEof));
}

#[test]
fn compressed_output_can_be_shorter_than_capacity() {
    let payload = [3, 0, 0, 0, 0x20, b'a', b'b'];
    let mut r = FrameReader::new(7);
    let mut input = vec![0, 0, 0, payload.len() as u8, 1];
    input.extend_from_slice(&payload);
    assert_eq!(r.feed(&input).status, Status::Complete(b"ab".to_vec()));
}

#[test]
fn compressed_capacity_limit_is_inclusive() {
    let mut equal = FrameReader::new(6);
    assert_eq!(
        equal.feed(&[0, 0, 0, 6, 1, 6, 0, 0, 0, 0x10, b'a']).status,
        Status::Complete(b"a".to_vec())
    );
    let mut above = FrameReader::new(6);
    assert_eq!(
        above.feed(&[0, 0, 0, 6, 1, 7, 0, 0, 0, 0x10, b'a']).status,
        Status::Failed(FrameError::Decode(DecodeError::Limit))
    );
}

#[test]
fn all_two_fragment_splits_and_empty_mid_body() {
    let fixtures: &[(&[u8], &[u8])] = &[
        (&[0, 0, 0, 3, 0, b'a', b'b', b'c'], b"abc"),
        (&[0, 0, 0, 6, 1, 6, 0, 0, 0, 0x10, b'a'], b"a"),
    ];
    for &(wire, expected) in fixtures {
        for split in 0..wire.len() {
            let mut reader = FrameReader::new(6);
            assert_eq!(reader.feed(&wire[..split]).status, Status::Pending);
            assert_eq!(reader.feed(&[]).status, Status::Pending);
            assert_eq!(
                reader.feed(&wire[split..]).status,
                Status::Complete(expected.to_vec())
            );
        }
    }
}

#[test]
fn failed_decode_leaves_next_frame_unconsumed() {
    let mut reader = FrameReader::new(6);
    let data = [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, b'x'];
    let result = reader.feed(&data);
    assert_eq!(result.consumed, 5);
    assert_eq!(
        result.status,
        Status::Failed(FrameError::Decode(DecodeError::Header))
    );
}

#[test]
fn empty_frame_respects_the_transform_flag() {
    let mut raw = FrameReader::new(0);
    assert_eq!(raw.feed(&[0, 0, 0, 0, 0]).status, Status::Complete(vec![]));
    let mut compressed = FrameReader::new(0);
    assert_eq!(
        compressed.feed(&[0, 0, 0, 0, 1]).status,
        Status::Failed(FrameError::Decode(DecodeError::Header))
    );
}

#[test]
fn body_crosses_native_chunk_boundary() {
    let length = 4_000_001u32;
    let mut reader = FrameReader::new(u64::from(length));
    let mut input = Vec::from(length.to_be_bytes());
    input.push(0);
    input.extend(std::iter::repeat_n(0x5a, length as usize));
    assert_eq!(reader.feed(&input[..4_000_005]).status, Status::Pending);
    assert_eq!(
        reader.feed(&input[4_000_005..]).status,
        Status::Complete(vec![0x5a; length as usize])
    );
}
