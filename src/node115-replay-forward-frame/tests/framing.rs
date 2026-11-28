use node115_replay_forward_frame::{Error, decode_prefix};

#[test]
fn retains_origin_and_exact_inner_span() {
    let mut wire = vec![0x31; 20];
    wire.extend([0, 5, 1, 3, 0xfb, 0xfc, 0xff, 0xee, 0xff]);
    let frame = decode_prefix(&wire).unwrap();
    assert_eq!(frame.origin, &[0x31; 20]);
    assert_eq!(frame.payload, &[1, 3, 0xfb, 0xfc, 0xff]);
    assert_eq!(frame.remaining, &[0xee, 0xff]);
    let inner = node115_client_block_success::decode_replay_payload_prefix(frame.payload, 15);
    assert_eq!(
        inner.result,
        Ok(node115_client_block_success::ReplayPayload::Tx(vec![
            0xfb, 0xfc, 0xff
        ]))
    );
    assert!(inner.remaining.is_empty());
}

#[test]
fn compact_lengths_preserve_the_selected_boundary() {
    let mut wire = vec![0x31; 20];
    wire.extend([0, 251, 251, 0]);
    wire.extend([0x78; 251]);
    wire.push(0x99);
    let frame = decode_prefix(&wire).unwrap();
    assert_eq!(frame.payload, &[0x78; 251]);
    assert_eq!(frame.remaining, &[0x99]);

    assert_eq!(decode_prefix(&wire[..20]), Err(Error::IncompleteHeader));
    assert_eq!(decode_prefix(&wire[..100]), Err(Error::IncompletePayload));
    wire[20] = 1;
    assert_eq!(decode_prefix(&wire), Err(Error::UnsupportedTag(1)));
}
