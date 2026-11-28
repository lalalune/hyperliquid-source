use net_utils::{compress_prepend_size, decompress_size_prepended};

#[test]
fn match_end_seed_and_backward_extension_select_the_next_match() {
    let input = b"ECEABCEABEEABEEEABEEABE";
    let expected = b"\x17\0\0\0\x50ECEAB\x04\0\x11E\x04\0\x80EABEEABE";
    assert_eq!(compress_prepend_size(input).unwrap(), expected);
    assert_eq!(
        decompress_size_prepended(expected, input.len() as u64).unwrap(),
        input
    );
}

#[test]
fn repeated_spans_preserve_the_reference_literal_and_offset_bytes() {
    let input = b"EFECBFECBECBFCBECBFCAAEBFCAA";
    let expected = b"\x1c\0\0\0\x50EFECB\x04\0\0\x07\0\x03\x06\0\x80AAEBFCAA";
    assert_eq!(compress_prepend_size(input).unwrap(), expected);
}
