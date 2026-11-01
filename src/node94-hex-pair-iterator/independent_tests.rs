use node94_hex_pair_iterator::HexPairs;

#[test]
fn native_byte_end_and_odd_masks_keep_payload() {
    let mut output = [0xa5; 16];
    let mut pairs = HexPairs::new("ab c \t");
    let original = output.as_ptr();
    assert!(std::ptr::eq(pairs.next_into(&mut output).as_ptr(), original));
    assert_eq!(&output[..5], &[2, 0, 0, 0, 0xab]);
    assert_eq!(&output[5..], &[0xa5; 11]);
    pairs.next_into(&mut output);
    assert_eq!(&output[..5], &[1, 0, 0, 0, 0xab]);
    assert_eq!((pairs.cursor(), pairs.consumed(), pairs.halted()), (6, 6, true));
    pairs.next_into(&mut output);
    assert_eq!(&output[..5], &[3, 0, 0, 0, 0xab]);
}

#[test]
fn native_unicode_error_decodes_scalar_but_outer_consumes_one_byte() {
    let mut output = [0xa5; 16];
    let mut pairs = HexPairs::new("a \t\u{10ffff}cd");
    pairs.next_into(&mut output);
    assert_eq!(&output[..4], &[0; 4]);
    assert_eq!(&output[4..8], &0x10ffffu32.to_le_bytes());
    assert_eq!(&output[8..], &3u64.to_le_bytes());
    assert_eq!((pairs.cursor(), pairs.consumed(), pairs.halted()), (4, 4, true));
    let payload = output[4..].to_vec();
    pairs.next_into(&mut output);
    assert_eq!(&output[..4], &[3, 0, 0, 0]);
    assert_eq!(&output[4..], payload.as_slice());
    assert_eq!((pairs.cursor(), pairs.consumed(), pairs.halted()), (4, 4, true));
}

#[test]
fn native_leaf_has_no_prefix_and_natural_end_does_not_halt() {
    let mut output = [0xff; 16];
    let mut pairs = HexPairs::new("0x00");
    pairs.next_into(&mut output);
    assert_eq!(&output[..4], &[0; 4]);
    assert_eq!(&output[4..8], &u32::from(b'x').to_le_bytes());
    assert_eq!(&output[8..], &1u64.to_le_bytes());
    let mut spaces = HexPairs::new("\t\r\n ");
    spaces.next_into(&mut output);
    assert_eq!(&output[..4], &[3, 0, 0, 0]);
    assert_eq!((spaces.cursor(), spaces.consumed(), spaces.halted()), (4, 4, false));
}
