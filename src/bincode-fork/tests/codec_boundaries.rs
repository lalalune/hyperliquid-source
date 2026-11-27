use bincode_fork::wire_compat::{
    bulk_record_decoder, signed_scalar, tcp_bincode_error, u32_varint, u64_reader_state,
    varint_buffer_writer,
};
use bincode_fork::{
    AllowedEnumVariants, ByteVec, Decode, DecodeError, DecoderImpl, EncodeError, IntegerType,
    SizeWriter, SliceReader, decode_from_slice, encode_into_slice, encode_size, encode_to_vec,
    legacy, standard,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

#[test]
fn varint_u64_boundaries_match_node115_writer_and_reader() {
    let cases: &[u64] = &[
        0,
        1,
        250,
        251,
        252,
        65_535,
        65_536,
        u32::MAX as u64,
        (u32::MAX as u64) + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    for &v in cases {
        let encoded = encode_to_vec(v, standard()).unwrap();
        let mut compat_buf = Vec::new();
        varint_buffer_writer::write_u64(&mut compat_buf, v).unwrap();
        assert_eq!(encoded, compat_buf, "varint wire bytes mismatch for {v}");
        assert_eq!(encode_size(v, standard()).unwrap(), encoded.len() as u64);

        let (decoded, used) = decode_from_slice::<u64>(&encoded, standard()).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(used, encoded.len());

        let mut compat_reader = u64_reader_state::Reader::new(&encoded, None, 0);
        assert_eq!(compat_reader.read_u64(), Ok(v));
        assert!(compat_reader.remaining().is_empty());
    }
}

#[test]
fn varint_u32_fast_slow_and_errors_match_node115_u32_varint() {
    let inputs: &[&[u8]] = &[
        &[],
        &[0],
        &[250],
        &[251, 0],
        &[251, 0x34, 0x12],
        &[252, 0x78, 0x56, 0x34],
        &[252, 0x78, 0x56, 0x34, 0x12],
        &[253, 1, 2, 3],
        &[253, 1, 2, 3, 4],
        &[254, 1, 2, 3, 4],
        &[255, 1, 2, 3, 4],
        &[255, 1, 2, 3],
        &[251, 0, 0, 0xaa, 0xbb], // non-minimal accepted
    ];
    for &input in inputs {
        for limit in [None, Some(0u64), Some(3u64), Some(4u64), Some(100u64)] {
            let cfg = match limit {
                None => standard(),
                Some(n) => standard().with_limit_bytes(n),
            };
            let mut dec = DecoderImpl::new(SliceReader::new(input), cfg);
            let res = u32::decode(&mut dec);

            let mut rem = input;
            let mut charged = 0u64;
            let (mode, lim) = match limit {
                None => (0u32, 0u64),
                Some(n) => (1u32, n),
            };
            let compat = u32_varint::read_u32(&mut rem, mode, lim, &mut charged);

            assert_eq!(dec.reader().remaining(), rem, "cursor mismatch for {input:?} limit={limit:?}");
            assert_eq!(dec.bytes_read(), charged, "charge mismatch for {input:?} limit={limit:?}");
            match (res, compat) {
                (Ok(a), Ok(b)) => assert_eq!(a, b),
                (
                    Err(DecodeError::UnexpectedEnd { additional: a }),
                    Err(u32_varint::ReadError::UnexpectedEnd { additional: b }),
                ) => assert_eq!(a as u64, b),
                (Err(DecodeError::LimitExceeded), Err(u32_varint::ReadError::Limit)) => {}
                (
                    Err(DecodeError::InvalidIntegerType { expected, found }),
                    Err(u32_varint::ReadError::Invalid { found_raw }),
                ) => {
                    assert_eq!(expected, IntegerType::U32);
                    assert_eq!(found.as_raw(), found_raw);
                }
                (a, b) => panic!("result mismatch for {input:?} limit={limit:?}: {a:?} vs {b:?}"),
            }
        }
    }
}

#[test]
fn varint_u64_partial_state_matches_node115_u64_reader_state() {
    let inputs: &[&[u8]] = &[
        &[],
        &[251, 1],
        &[252, 1, 2, 3],
        &[253, 1, 2, 3, 4, 5, 6, 7],
        &[254, 1, 2, 3, 4, 5, 6, 7],       // slow (len=8): consumes marker, expected=U64(3)
        &[254, 1, 2, 3, 4, 5, 6, 7, 8],    // fast (len=9): retains marker, expected=U32(2)
        &[255, 1, 2, 3, 4, 5, 6, 7],       // slow: found=Reserved(12)
        &[255, 1, 2, 3, 4, 5, 6, 7, 8],    // fast: found=Reserved(12)
        &[251, 0, 0, 9, 9, 9, 9, 9, 9],    // non-minimal 0
    ];
    for &input in inputs {
        for (limit, init_charged) in [
            (None, 0u64),
            (Some(7), 0),
            (Some(8), 0),
            (Some(u64::MAX), u64::MAX - 7), // overflow without mutation
        ] {
            let cfg = match limit {
                None => standard(),
                Some(n) => standard().with_limit_bytes(n),
            };
            let mut dec = DecoderImpl::with_initial_bytes_read(SliceReader::new(input), cfg, init_charged);
            let res = u64::decode(&mut dec);

            let mut compat = u64_reader_state::Reader::new(input, limit, init_charged);
            let compat_res = compat.read_u64();

            assert_eq!(dec.reader().remaining(), compat.remaining(), "input={input:?} limit={limit:?}");
            assert_eq!(dec.bytes_read(), compat.charged(), "input={input:?} limit={limit:?}");
            match (res, compat_res) {
                (Ok(a), Ok(b)) => assert_eq!(a, b),
                (
                    Err(DecodeError::UnexpectedEnd { additional: a }),
                    Err(u64_reader_state::Error::UnexpectedEnd { additional: b }),
                ) => assert_eq!(a as u64, b),
                (Err(DecodeError::LimitExceeded), Err(u64_reader_state::Error::Limit)) => {}
                (
                    Err(DecodeError::InvalidIntegerType { expected, found }),
                    Err(u64_reader_state::Error::Invalid {
                        expected_raw,
                        found_raw,
                    }),
                ) => {
                    assert_eq!(expected.as_raw(), expected_raw);
                    assert_eq!(found.as_raw(), found_raw);
                }
                (a, b) => panic!("mismatch for {input:?}: {a:?} vs {b:?}"),
            }
        }
    }
}

#[test]
fn signed_i64_zigzag_matches_node115_signed_scalar() {
    let values = [
        0i64,
        -1,
        1,
        -2,
        125,
        -126,
        32_767,
        -32_768,
        i32::MAX as i64,
        i32::MIN as i64,
        i64::MAX,
        i64::MIN,
    ];
    for &v in &values {
        let enc = encode_to_vec(v, standard()).unwrap();
        let (dec, used) = decode_from_slice::<i64>(&enc, standard()).unwrap();
        assert_eq!(dec, v);
        assert_eq!(used, enc.len());

        let mut cursor = signed_scalar::Cursor::new(&enc);
        assert_eq!(cursor.read_signed(0), Ok(v));
        assert!(cursor.remaining().is_empty());
    }

    // Check fast vs slow invalid marker diagnostics on i64
    let slow_bad = [254u8; 8];
    let mut dec_slow = DecoderImpl::new(SliceReader::new(&slow_bad), standard());
    assert_eq!(
        i64::decode(&mut dec_slow),
        Err(DecodeError::InvalidIntegerType {
            expected: IntegerType::I64,
            found: IntegerType::I128,
        })
    );
    assert_eq!(dec_slow.reader().remaining().len(), 7);

    let fast_bad = [255u8; 9];
    let mut dec_fast = DecoderImpl::new(SliceReader::new(&fast_bad), standard());
    assert_eq!(
        i64::decode(&mut dec_fast),
        Err(DecodeError::InvalidIntegerType {
            expected: IntegerType::I32,
            found: IntegerType::Reserved,
        })
    );
    assert_eq!(dec_fast.reader().remaining().len(), 9);
}

#[test]
fn fork_invalid_bytes_length_precedence_and_oom_defense() {
    // 1. Valid ByteVec round-trip including empty and multi-byte length prefix
    let payload = ByteVec((0..300u16).map(|i| (i & 0xff) as u8).collect());
    let wire = encode_to_vec(&payload, standard()).unwrap();
    let (decoded, used) = decode_from_slice::<ByteVec>(&wire, standard()).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(used, wire.len());

    // 2. Truncated payload by 1 byte returns fork tag 1 (InvalidBytesLength)
    let err = decode_from_slice::<ByteVec>(&wire[..wire.len() - 1], standard()).unwrap_err();
    assert_eq!(err, DecodeError::InvalidBytesLength);
    assert_eq!(err.tag(), 1);

    // 3. Adversarial huge length (1 TiB) on tiny buffer MUST return InvalidBytesLength
    //    without attempting allocation!
    let huge_len_wire = encode_to_vec(1u64 << 40, standard()).unwrap();
    let err = decode_from_slice::<ByteVec>(&huge_len_wire, standard()).unwrap_err();
    assert_eq!(err, DecodeError::InvalidBytesLength);

    // 4. LimitExceeded (tag 2) takes precedence over InvalidBytesLength (tag 1),
    //    matching node #115 `0x5821b40` before `0x5821b64`!
    let cfg = standard().with_limit_bytes(16);
    // Varint length = 100 (charges 8 for usize + 100 for bytes = 108 > 16) on 1-byte buffer
    let err = decode_from_slice::<ByteVec>(&[100], cfg).unwrap_err();
    assert_eq!(err, DecodeError::LimitExceeded);
    assert_eq!(err.tag(), 2);

    // 5. Within limit (limit=200), remaining < len triggers InvalidBytesLength (tag 1)
    let cfg_ok_limit = standard().with_limit_bytes(200);
    let err = decode_from_slice::<ByteVec>(&[100], cfg_ok_limit).unwrap_err();
    assert_eq!(err, DecodeError::InvalidBytesLength);
}

#[test]
fn decode_error_debug_format_matches_node115_tcp_bincode_error() {
    let cases: &[(DecodeError, [u8; 24])] = &[
        (
            DecodeError::UnexpectedEnd { additional: 42 },
            {
                let mut r = [0u8; 24];
                r[0] = 0;
                r[8..16].copy_from_slice(&42u64.to_le_bytes());
                r
            },
        ),
        (
            DecodeError::InvalidBytesLength,
            {
                let mut r = [0u8; 24];
                r[0] = 1;
                r
            },
        ),
        (
            DecodeError::LimitExceeded,
            {
                let mut r = [0u8; 24];
                r[0] = 2;
                r
            },
        ),
        (
            DecodeError::InvalidIntegerType {
                expected: IntegerType::U64,
                found: IntegerType::U128,
            },
            {
                let mut r = [0u8; 24];
                r[0] = 3;
                r[1] = IntegerType::U64.as_raw();
                r[2] = IntegerType::U128.as_raw();
                r
            },
        ),
    ];

    for (err, raw) in cases {
        let converted = tcp_bincode_error::convert(raw, vec![1, 2, 3]).unwrap();
        let expected_msg = format!("TcpRead::bincode err: {err:?}");
        assert_eq!(converted.error.message(), expected_msg);
        assert_eq!(err.tag(), raw[0]);
    }
}

#[test]
fn bulk_record_wire_layout_matches_node115_bulk_record_decoder() {
    let f0 = 123_456u64;
    let f1 = 987_654_321u64;
    let mut bytes = [0u8; 2048];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37);
    }
    let wire = encode_to_vec((f0, f1, bytes), standard()).unwrap();
    let compat = bulk_record_decoder::decode_prefix(&wire, None, 0);
    let rec = compat.result.unwrap();
    assert_eq!(rec.fields, [f0, f1]);
    assert_eq!(rec.bytes, bytes);
    assert!(compat.remaining.is_empty());

    let ((df0, df1, dbytes), used) =
        decode_from_slice::<(u64, u64, [u8; 2048])>(&wire, standard()).unwrap();
    assert_eq!((df0, df1, dbytes), (f0, f1, bytes));
    assert_eq!(used, wire.len());
}

#[test]
fn containers_primitives_strings_and_corruption_controls() {
    let mut map = BTreeMap::new();
    map.insert("alpha".to_string(), vec![1i32, -2, 300, i32::MIN]);
    map.insert("beta".to_string(), vec![]);
    let mut set = BTreeSet::new();
    set.insert(u128::MAX);
    set.insert(0u128);
    let dur = Duration::new(1_700_000_000, 999_999_999);
    let complex = (
        (true, '🦀', -123.5f64),
        (Some(map.clone()), None::<u64>, Ok::<_, u32>(set.clone())),
        dur,
    );

    let wire = encode_to_vec(&complex, standard()).unwrap();
    let (decoded_complex, decoded_len) = decode_from_slice::<(
        (bool, char, f64),
        (Option<BTreeMap<String, Vec<i32>>>, Option<u64>, Result<BTreeSet<u128>, u32>),
        Duration,
    )>(&wire, standard())
    .unwrap();
    assert_eq!(decoded_complex, complex);
    assert_eq!(decoded_len, wire.len());
    let mut slice_buf = vec![0u8; wire.len()];
    let written = encode_into_slice(&complex, &mut slice_buf, standard()).unwrap();
    assert_eq!(written, wire.len());
    assert_eq!(slice_buf, wire);

    // Slice too short -> EncodeError::UnexpectedEnd
    let mut short_buf = vec![0u8; wire.len() - 1];
    assert_eq!(
        encode_into_slice(&complex, &mut short_buf, standard()),
        Err(EncodeError::UnexpectedEnd)
    );

    // Invalid boolean byte
    assert_eq!(
        decode_from_slice::<bool>(&[2], standard()),
        Err(DecodeError::InvalidBooleanValue(2))
    );

    // Invalid Option tag
    let opt_err = decode_from_slice::<Option<u8>>(&[7], standard()).unwrap_err();
    assert_eq!(opt_err.tag(), 5);
    assert!(matches!(
        opt_err,
        DecodeError::UnexpectedVariant {
            type_name: "Option",
            allowed: &AllowedEnumVariants::Range { min: 0, max: 1 },
            found: 7,
        }
    ));

    // Invalid UTF-8 string
    let bad_utf8 = encode_to_vec(ByteVec(vec![0xff, 0xfe]), standard()).unwrap();
    let utf8_err = decode_from_slice::<String>(&bad_utf8, standard()).unwrap_err();
    assert_eq!(utf8_err.tag(), 6);

    // Invalid Duration nanos >= 1_000_000_000
    let bad_dur = encode_to_vec((10u64, 1_000_000_000u32), standard()).unwrap();
    assert_eq!(
        decode_from_slice::<Duration>(&bad_dur, standard()),
        Err(DecodeError::InvalidDuration {
            secs: 10,
            nanos: 1_000_000_000,
        })
    );

    // SizeWriter overflow matches node115 `0x5822850` (marker write survives payload overflow)
    let mut sw = SizeWriter::with_initial(u64::MAX - 2);
    let mut enc = bincode_fork::EncoderImpl::new(&mut sw, standard());
    // 251 takes 1 marker + 2 payload bytes = 3 > remaining 2
    assert_eq!(enc.write_u64(251), Err(EncodeError::SizeOverflow));
    assert_eq!(sw.bytes_written, u64::MAX - 1);

    // Fixed-width big-endian round-trip
    let cfg_be = legacy().with_big_endian();
    let be_wire = encode_to_vec((0x1234_5678u32, -42i64), cfg_be).unwrap();
    assert_eq!(&be_wire[..4], &[0x12, 0x34, 0x56, 0x78]);
    let (be_dec, be_used) = decode_from_slice::<(u32, i64)>(&be_wire, cfg_be).unwrap();
    assert_eq!(be_dec, (0x1234_5678u32, -42i64));
    assert_eq!(be_used, 12);
}

#[test]
fn vec_decode_preallocation_and_unclaim_limit_accounting() {
    // 4 elements of u64 (8 bytes each) + usize length (8 bytes charged) = 40 bytes total.
    let data = vec![10u64, 20, 30, 40];
    let wire = encode_to_vec(&data, standard()).unwrap();
    let (decoded, used) =
        decode_from_slice::<Vec<u64>>(&wire, standard().with_limit_bytes(40)).unwrap();
    assert_eq!(decoded, data);
    assert_eq!(used, wire.len());

    // Limit of 39 bytes fails container claim!
    assert_eq!(
        decode_from_slice::<Vec<u64>>(&wire, standard().with_limit_bytes(39)),
        Err(DecodeError::LimitExceeded)
    );
}
