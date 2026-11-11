use node115_storage_value_decode::{decode, Decoded, InvalidValue};

fn framed(marker: u8, length: u32, payload: &[u8]) -> Vec<u8> {
    let width = match marker {
        0xc4 | 0xd9 => 1,
        0xc5 | 0xda => 2,
        0xc6 | 0xdb => 4,
        _ => 0,
    };
    let mut bytes = vec![marker];
    bytes.extend_from_slice(&length.to_be_bytes()[4 - width..]);
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn binary_forms_limb_order_truncation_and_trailing_bytes() {
    let payload: Vec<u8> = (0..32).collect();
    let expected = [
        0x18191a1b1c1d1e1f,
        0x1011121314151617,
        0x08090a0b0c0d0e0f,
        0x0001020304050607,
    ];
    for marker in [0xc4, 0xc5, 0xc6] {
        let mut bytes = framed(marker, 32, &payload);
        for end in 0..bytes.len() {
            assert_eq!(decode(&bytes[..end]), Err(InvalidValue));
        }
        let consumed = bytes.len();
        bytes.extend_from_slice(&[0xc1, 0xff, 0]);
        assert_eq!(
            decode(&bytes),
            Ok(Decoded {
                limbs: expected,
                consumed
            })
        );
        for length in [0, 1, 31, 33, 255] {
            assert_eq!(decode(&framed(marker, length, &payload)), Err(InvalidValue));
        }
    }
}

#[test]
fn string_visitor_rejects_valid_utf8_but_accepts_invalid_bytes() {
    let valid = [b'a'; 32];
    for marker in [0xd9, 0xda, 0xdb] {
        assert_eq!(decode(&framed(marker, 32, &valid)), Err(InvalidValue));
        let mut invalid = valid;
        invalid[0] = 0xff;
        assert!(decode(&framed(marker, 32, &invalid)).is_ok());
        // A valid multi-byte string still takes the rejecting text visitor.
        let mut utf8 = valid;
        utf8[..4].copy_from_slice(&[0xf0, 0x9f, 0x92, 0xa9]);
        assert_eq!(decode(&framed(marker, 32, &utf8)), Err(InvalidValue));
    }
}

#[test]
fn every_marker_and_independent_reference_vectors() {
    for marker in 0_u8..=255 {
        let payload = [0xff; 32];
        let bytes = framed(marker, 32, &payload);
        assert_eq!(
            decode(&bytes).is_ok(),
            matches!(marker, 0xc4..=0xc6 | 0xd9..=0xdb)
        );
    }
    let mut cases = 0;
    for line in include_str!("reference-vectors.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (hex, expected) = line.split_once(' ').unwrap();
        let input: Vec<_> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let actual = decode(&input);
        if expected == "reject" {
            assert_eq!(actual, Err(InvalidValue), "case {cases}: {hex}");
        } else {
            let fields: Vec<_> = expected.split(',').collect();
            let limbs = core::array::from_fn(|i| u64::from_str_radix(fields[i], 16).unwrap());
            let consumed = fields[4].parse().unwrap();
            assert_eq!(
                actual,
                Ok(Decoded { limbs, consumed }),
                "case {cases}: {hex}"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 4716);
}
