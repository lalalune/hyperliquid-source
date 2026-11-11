use node115_block_handle_codec::{
    decode_into, decode_varint64, encode, encode_varint64, BlockHandle, InputSlice,
    BAD_BLOCK_HANDLE,
};

#[test]
fn encoder_matches_unsigned_leb128_vectors() {
    let vectors = [
        (0, "00"),
        (1, "01"),
        (0x7f, "7f"),
        (0x80, "8001"),
        (300, "ac02"),
        (0x3fff, "ff7f"),
        (0x4000, "808001"),
        (1 << 63, "80808080808080808001"),
        (u64::MAX, "ffffffffffffffffff01"),
    ];
    for (value, hex) in vectors {
        let mut bytes = Vec::new();
        encode_varint64(value, &mut bytes);
        assert_eq!(bytes, parse_hex(hex));
    }
    assert_eq!(
        encode(BlockHandle {
            offset: 0x80,
            size: 0x7f
        }),
        [0x80, 0x01, 0x7f]
    );
}

#[test]
fn decoder_accepts_target_overlong_and_tenth_byte_forms() {
    assert_eq!(decode_varint64(&[0x80, 0x80, 0x00], 0), Some((0, 3)));
    assert_eq!(decode_varint64(&[0x81, 0x80, 0x00], 0), Some((1, 3)));
    assert_eq!(
        decode_varint64(
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f],
            0
        ),
        Some((1 << 63, 10))
    );
    assert_eq!(
        decode_varint64(
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            0
        ),
        Some((u64::MAX, 10))
    );
    assert_eq!(
        decode_varint64(
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00],
            0
        ),
        Some(((1 << 63) - 1, 10))
    );
    assert_eq!(
        decode_varint64(
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80],
            0
        ),
        None
    );
}

#[test]
fn decode_commits_only_completed_varints_and_zeros_failed_output() {
    let mut handle = BlockHandle {
        offset: 17,
        size: 99,
    };

    let mut first_partial = InputSlice::new(&[0x80]);
    let status = decode_into(&mut handle, &mut first_partial);
    assert_eq!(status.code, 2);
    assert_eq!(status.subcode, 0);
    assert_eq!(status.severity, 0);
    assert_eq!(status.message, Some(BAD_BLOCK_HANDLE));
    assert!(!status.is_ok());
    assert_eq!(handle, BlockHandle::default());
    assert_eq!(first_partial.position(), 0);

    handle = BlockHandle {
        offset: 17,
        size: 99,
    };
    let mut second_partial = InputSlice::new(&[0x01, 0x80]);
    let status = decode_into(&mut handle, &mut second_partial);
    assert_eq!(status.message, Some(BAD_BLOCK_HANDLE));
    assert_eq!(handle, BlockHandle::default());
    assert_eq!(second_partial.position(), 1);
    assert_eq!(second_partial.remaining(), &[0x80]);

    let mut input = InputSlice::new(&[0xac, 0x02, 0x7f, 0xaa]);
    let status = decode_into(&mut handle, &mut input);
    assert!(status.is_ok());
    assert_eq!(
        handle,
        BlockHandle {
            offset: 300,
            size: 127
        }
    );
    assert_eq!(input.position(), 3);
    assert_eq!(input.remaining(), &[0xaa]);
}

#[test]
fn deterministic_round_trips_cover_u64_boundaries() {
    let edges = [
        0,
        1,
        0x7f,
        0x80,
        0x3fff,
        0x4000,
        (1 << 21) - 1,
        1 << 21,
        (1 << 32) - 1,
        1 << 32,
        (1 << 63) - 1,
        1 << 63,
        u64::MAX,
    ];
    let mut state = 0xB10Cu64;
    for i in 0..3_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let offset = if i % 2 == 0 {
            edges[i % edges.len()]
        } else {
            state
        };
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let size = if i % 3 == 0 {
            edges[(i / 3) % edges.len()]
        } else {
            state
        };
        let expected = BlockHandle { offset, size };
        let bytes = encode(expected);
        assert!(bytes.len() <= 20);
        let mut actual = BlockHandle::default();
        let mut input = InputSlice::new(&bytes);
        let status = decode_into(&mut actual, &mut input);
        assert!(status.is_ok());
        assert_eq!(actual, expected);
        assert_eq!(input.position(), bytes.len());
    }
}

fn parse_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(digits, 16).unwrap()
        })
        .collect()
}
