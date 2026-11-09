use node115_listener_prefix::*;

fn frame(flag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut result = (bytes.len() as u32).to_be_bytes().to_vec();
    result.push(flag);
    result.extend_from_slice(bytes);
    result
}
fn prefix_body() -> Vec<u8> {
    let mut result: Vec<u8> = (0..20).collect();
    result.push(3);
    result.extend_from_slice(&[99, 98, 97]);
    result
}
fn literal_lz4(bytes: &[u8]) -> Vec<u8> {
    let mut result = (bytes.len() as u32).to_le_bytes().to_vec();
    if bytes.len() < 15 {
        result.push((bytes.len() as u8) << 4);
    } else {
        result.push(0xf0);
        let mut n = bytes.len() - 15;
        while n >= 255 {
            result.push(255);
            n -= 255;
        }
        result.push(n as u8);
    }
    result.extend_from_slice(bytes);
    result
}

#[test]
fn real_plain_and_literal_compressed_frames_reach_the_same_fresh_typed_prefix() {
    let body = prefix_body();
    for (flag, payload) in [
        (0, body.clone()),
        (2, body.clone()),
        (255, body.clone()),
        (1, literal_lz4(&body)),
    ] {
        let bytes = frame(flag, &payload);
        let mut reader = ListenerPrefixReader::new();
        let outcome = reader.feed(&bytes);
        assert_eq!(outcome.consumed, bytes.len());
        match outcome.status {
            Status::Prefix(prefix) => {
                assert_eq!(prefix.identity, std::array::from_fn(|i| i as u8));
                assert_eq!(prefix.kind, 3);
                assert_eq!(prefix.body(), [99, 98, 97]);
                assert_eq!(prefix.body_offset, 21);
                assert_eq!(prefix.charged, 24);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn outer_limit_is_payload_length_not_header_or_connection_total() {
    for length in [LISTENER_LIMIT - 1, LISTENER_LIMIT] {
        let mut header = (length as u32).to_be_bytes().to_vec();
        header.push(0);
        assert!(matches!(
            ListenerPrefixReader::new().feed(&header).status,
            Status::Pending
        ));
    }
    let mut header = ((LISTENER_LIMIT + 1) as u32).to_be_bytes().to_vec();
    header.push(0);
    let outcome = ListenerPrefixReader::new().feed(&header);
    assert_eq!(outcome.consumed, 5);
    assert!(matches!(
        outcome.status,
        Status::FrameFailed(node115_frame_stream::FrameError::OverLimit)
    ));
}

#[test]
fn small_compressed_input_can_fail_the_separate_decoded_length_limit() {
    let payload = ((LISTENER_LIMIT + 1) as u32).to_le_bytes();
    let bytes = frame(1, &payload);
    let outcome = ListenerPrefixReader::new().feed(&bytes);
    assert_eq!(outcome.consumed, 9);
    assert!(matches!(
        outcome.status,
        Status::FrameFailed(node115_frame_stream::FrameError::Decode(_))
    ));
    // These same four bytes are ordinary raw payload for any non-one flag.
    let raw = ListenerPrefixReader::new().feed(&frame(2, &payload));
    assert!(matches!(
        raw.status,
        Status::PrefixFailed(PrefixFailure {
            charged: 20,
            consumed: 0,
            ..
        })
    ));
}

#[test]
fn declared_output_at_the_limit_reuses_the_same_native_caller_bound() {
    let body = prefix_body();
    for declared in [LISTENER_LIMIT - 1, LISTENER_LIMIT] {
        let mut compressed = literal_lz4(&body);
        compressed[..4].copy_from_slice(&(declared as u32).to_le_bytes());
        let bytes = frame(1, &compressed);
        match ListenerPrefixReader::new().feed(&bytes).status {
            Status::Prefix(prefix) => {
                // The declared capacity is checked even when the actual output is shorter.
                assert_eq!(prefix.frame.len(), body.len());
                assert_eq!(prefix.kind, 3);
                assert_eq!(prefix.charged, 24);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn accepted_full_limit_plain_payload_is_not_debited_from_typed_budget() {
    let mut body = vec![0; LISTENER_LIMIT as usize];
    body[..24].copy_from_slice(&prefix_body());
    let bytes = frame(0, &body);
    match ListenerPrefixReader::new().feed(&bytes).status {
        Status::Prefix(prefix) => {
            assert_eq!(prefix.frame.len(), LISTENER_LIMIT as usize);
            assert_eq!(prefix.charged, 24);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn split_input_and_unconsumed_next_frame_do_not_share_typed_charge() {
    let one = frame(0, &prefix_body());
    let mut both = one.clone();
    both.extend_from_slice(&one);
    for split in 0..one.len() {
        let mut reader = ListenerPrefixReader::new();
        let first = reader.feed(&both[..split]);
        assert_eq!(first.consumed, split);
        assert!(matches!(first.status, Status::Pending));
        let next = reader.feed(&both[split..]);
        assert_eq!(next.consumed, one.len() - split);
        let Status::Prefix(p) = next.status else {
            panic!("not prefix")
        };
        assert_eq!(p.charged, 24);
        // A separate reader is used deliberately: target connection reuse is outside scope.
        let Status::Prefix(p) = ListenerPrefixReader::new().feed(&both[one.len()..]).status else {
            panic!("not second prefix")
        };
        assert_eq!(p.charged, 24);
    }
}

#[test]
fn short_address_charges_twenty_without_cursor_commit() {
    for n in 0..20 {
        let error = decode_prefix(vec![1; n]).unwrap_err();
        assert_eq!(error.consumed, 0);
        assert_eq!(error.charged, 20);
        assert!(
            matches!(error.error,PrefixError::AddressUnexpectedEnd { deficit } if deficit==20-n)
        );
    }
}

#[test]
fn u32_kind_charges_four_regardless_of_encoded_width_and_body_is_untouched() {
    for (encoded, expected) in [
        (vec![3], 3),
        (vec![251, 3, 0], 3),
        (vec![252, 3, 0, 0, 0], 3),
        (vec![252, 255, 255, 255, 255], u32::MAX),
    ] {
        let mut bytes = vec![9; 20];
        bytes.extend_from_slice(&encoded);
        bytes.extend_from_slice(&[7; 8]);
        let parsed = decode_prefix(bytes).unwrap();
        assert_eq!(parsed.kind, expected);
        assert_eq!(parsed.body_offset, 20 + encoded.len());
        assert_eq!(parsed.charged, 24);
        assert_eq!(parsed.body(), [7; 8]);
    }
    // The helper's own short-tail behavior is reused, rather than guessed here.
    let error = decode_prefix(vec![1; 20]).unwrap_err();
    assert_eq!(error.charged, 24);
    assert_eq!(error.consumed, 20);
    assert!(matches!(error.error, PrefixError::Kind(_)));
}
