use hl_bincode_varint::{
    DecodeError, DecodedU64, PayloadOrder, decode_u64_slice_fast, encode_u32, encode_u64,
    encoded_len_u32, encoded_len_u64,
};

fn encoded_u32(value: u32, order: PayloadOrder) -> (usize, Vec<u8>) {
    let mut output = Vec::new();
    let written = encode_u32(value, order, &mut output);
    (written, output)
}

fn encoded_u64(value: u64, order: PayloadOrder) -> (usize, Vec<u8>) {
    let mut output = Vec::new();
    let written = encode_u64(value, order, &mut output);
    (written, output)
}

#[test]
fn u32_lengths_follow_observed_thresholds() {
    // 0x27ab281..0x27ab2cd: comparisons at 251 and 65_536, then +1/+3/+5.
    let cases = [
        (0, 1),
        (250, 1),
        (251, 3),
        (u16::MAX as u32, 3),
        (u16::MAX as u32 + 1, 5),
        (u32::MAX, 5),
    ];
    for (value, expected) in cases {
        assert_eq!(encoded_len_u32(value), expected, "value {value}");
    }
}

#[test]
fn u64_lengths_follow_observed_thresholds() {
    // 0x27ab5b1..0x27ab623: comparisons at 251, 2^16 and 2^32.
    let cases = [
        (0, 1),
        (250, 1),
        (251, 3),
        (u16::MAX as u64, 3),
        (u16::MAX as u64 + 1, 5),
        (u32::MAX as u64, 5),
        (u32::MAX as u64 + 1, 9),
        (u64::MAX, 9),
    ];
    for (value, expected) in cases {
        assert_eq!(encoded_len_u64(value), expected, "value {value}");
    }
}

#[test]
fn u32_little_endian_vectors_match_target_stores() {
    // Markers: 0x27ab0e8/0x27ab128. Unswapped stores: 0x4aa9b41/0x4aa9b78.
    let cases: &[(u32, &[u8])] = &[
        (0, &[0x00]),
        (250, &[0xfa]),
        (251, &[0xfb, 0xfb, 0x00]),
        (u16::MAX as u32, &[0xfb, 0xff, 0xff]),
        (65_536, &[0xfc, 0x00, 0x00, 0x01, 0x00]),
        (u32::MAX, &[0xfc, 0xff, 0xff, 0xff, 0xff]),
    ];
    for &(value, expected) in cases {
        let (written, actual) = encoded_u32(value, PayloadOrder::Little);
        assert_eq!(actual, expected, "value {value}");
        assert_eq!(written, expected.len(), "value {value}");
    }
}

#[test]
fn u32_big_endian_vectors_match_target_swap_arms() {
    // rol cx,8 at 0x27ab0f8 and bswap ecx at 0x27ab138.
    let cases: &[(u32, &[u8])] = &[
        (251, &[0xfb, 0x00, 0xfb]),
        (0x1234, &[0xfb, 0x12, 0x34]),
        (65_536, &[0xfc, 0x00, 0x01, 0x00, 0x00]),
        (0x1234_5678, &[0xfc, 0x12, 0x34, 0x56, 0x78]),
    ];
    for &(value, expected) in cases {
        let (_, actual) = encoded_u32(value, PayloadOrder::Big);
        assert_eq!(actual, expected, "value {value}");
    }
}

#[test]
fn u64_little_endian_vectors_cover_width_and_overflow_boundaries() {
    // Width selection: 0x27ab331 and 0x27ab380. Marker 0xfd: 0x27ab3d4.
    let cases: &[(u64, &[u8])] = &[
        (250, &[0xfa]),
        (251, &[0xfb, 0xfb, 0x00]),
        (65_536, &[0xfc, 0x00, 0x00, 0x01, 0x00]),
        (u32::MAX as u64, &[0xfc, 0xff, 0xff, 0xff, 0xff]),
        (
            u32::MAX as u64 + 1,
            &[0xfd, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
        ),
        (
            u64::MAX,
            &[0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];
    for &(value, expected) in cases {
        let (written, actual) = encoded_u64(value, PayloadOrder::Little);
        assert_eq!(actual, expected, "value {value}");
        assert_eq!(written, expected.len(), "value {value}");
    }
}

#[test]
fn u64_big_endian_vectors_match_target_swap_arms() {
    // bswap rcx at 0x27ab3e4 and the corresponding store at 0x27ab3f7.
    let cases: &[(u64, &[u8])] = &[
        (
            u32::MAX as u64 + 1,
            &[0xfd, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        ),
        (
            0x0102_0304_0506_0708,
            &[0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        ),
    ];
    for &(value, expected) in cases {
        let (_, actual) = encoded_u64(value, PayloadOrder::Big);
        assert_eq!(actual, expected, "value {value}");
    }
}

#[test]
fn encoders_append_without_replacing_existing_output() {
    let mut output = vec![0xaa, 0x55];
    assert_eq!(encode_u32(251, PayloadOrder::Little, &mut output), 3);
    assert_eq!(output, [0xaa, 0x55, 0xfb, 0xfb, 0x00]);
    assert_eq!(encode_u64(65_536, PayloadOrder::Little, &mut output), 5);
    assert_eq!(
        output,
        [0xaa, 0x55, 0xfb, 0xfb, 0x00, 0xfc, 0x00, 0x00, 0x01, 0x00]
    );
}

#[test]
fn decoder_vectors_match_observed_loads_and_consumed_lengths() {
    // Loads at 0x466bd76/0x466bd8e/0x466bd82; lengths at
    // 0x466bd53/0x466bd7a/0x466bd91/0x466bd86.
    let cases: &[(&[u8], DecodedU64)] = &[
        (
            &[0xfa, 0, 0, 0, 0, 0, 0, 0, 0],
            DecodedU64 {
                value: 250,
                consumed: 1,
            },
        ),
        (
            &[0xfb, 0x34, 0x12, 0, 0, 0, 0, 0, 0],
            DecodedU64 {
                value: 0x1234,
                consumed: 3,
            },
        ),
        (
            &[0xfc, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0],
            DecodedU64 {
                value: 0x1234_5678,
                consumed: 5,
            },
        ),
        (
            &[0xfd, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            DecodedU64 {
                value: 0x0102_0304_0506_0708,
                consumed: 9,
            },
        ),
    ];
    for &(input, expected) in cases {
        assert_eq!(decode_u64_slice_fast(input), Ok(expected), "{input:02x?}");
    }
}

#[test]
fn decoder_fast_path_accepts_non_minimal_widths() {
    // The three load arms join directly at 0x466bd97 without a canonicality check.
    assert_eq!(
        decode_u64_slice_fast(&[0xfb, 1, 0, 0, 0, 0, 0, 0, 0]),
        Ok(DecodedU64 {
            value: 1,
            consumed: 3,
        })
    );
    assert_eq!(
        decode_u64_slice_fast(&[0xfc, 1, 0, 0, 0, 0, 0, 0, 0]),
        Ok(DecodedU64 {
            value: 1,
            consumed: 5,
        })
    );
}

#[test]
fn decoder_rejects_observed_error_markers() {
    // Jump target 0x466bdc5 handles 0xfe; 0x466bddd handles out-of-range 0xff.
    for marker in [0xfe, 0xff] {
        let mut input = [0_u8; 9];
        input[0] = marker;
        assert_eq!(
            decode_u64_slice_fast(&input),
            Err(DecodeError::RejectedMarker { marker })
        );
    }
}

#[test]
fn decoder_does_not_guess_slow_path_truncation_semantics() {
    // cmp remaining,8; jbe slow at 0x466bd3d..0x466bd41 precedes the tag load.
    for remaining in 0..=8 {
        let mut input = vec![0_u8; remaining];
        if let Some(tag) = input.first_mut() {
            *tag = 0xfd;
        }
        assert_eq!(
            decode_u64_slice_fast(&input),
            Err(DecodeError::FastPathUnavailable { remaining })
        );
    }
}

#[test]
fn independent_marker_corruption_control_changes_the_result() {
    let (_, mut encoded) = encoded_u64(u64::MAX, PayloadOrder::Little);
    assert_eq!(encoded[0], 0xfd);
    assert_eq!(
        decode_u64_slice_fast(&encoded),
        Ok(DecodedU64 {
            value: u64::MAX,
            consumed: 9,
        })
    );

    encoded[0] = 0xfe;
    assert_eq!(
        decode_u64_slice_fast(&encoded),
        Err(DecodeError::RejectedMarker { marker: 0xfe })
    );
}
