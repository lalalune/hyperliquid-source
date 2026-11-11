use node115_noop_preimage::{inner_digest, preimage};

#[test]
fn full_zero_vector_includes_a_map_and_absent_vault_marker() {
    assert_eq!(
        preimage(0, None, None).as_bytes(),
        b"\x81\xa4type\xa4noop\0\0\0\0\0\0\0\0\0"
    );
}

#[test]
fn all_suffix_shapes_keep_exact_byte_order_and_markers() {
    let vault = core::array::from_fn(|i| i as u8);
    for nonce in [0, 1, 0x0102_0304_0506_0708, u64::MAX] {
        for address in [None, Some(vault)] {
            for expiry in [None, Some(0), Some(0x1112_1314_1516_1718), Some(u64::MAX)] {
                let owned = preimage(nonce, address, expiry);
                let bytes = owned.as_bytes();
                assert_eq!(&bytes[..11], b"\x81\xa4type\xa4noop");
                assert_eq!(u64::from_be_bytes(bytes[11..19].try_into().unwrap()), nonce);
                let end = if let Some(value) = address {
                    assert_eq!(bytes[19], 1);
                    assert_eq!(&bytes[20..40], &value);
                    40
                } else {
                    assert_eq!(bytes[19], 0);
                    20
                };
                if let Some(value) = expiry {
                    assert_eq!(bytes[end], 0);
                    assert_eq!(
                        u64::from_be_bytes(bytes[end + 1..end + 9].try_into().unwrap()),
                        value
                    );
                    assert_eq!(bytes.len(), end + 9);
                } else {
                    assert_eq!(bytes.len(), end);
                }
            }
        }
    }
}

#[test]
fn present_zero_values_remain_distinct_from_absent_values() {
    let absent = preimage(0, None, None);
    assert_ne!(
        absent.as_bytes(),
        preimage(0, Some([0; 20]), None).as_bytes()
    );
    assert_ne!(absent.as_bytes(), preimage(0, None, Some(0)).as_bytes());
}

#[test]
fn sixty_four_complete_digests_match_independent_openssl_vectors() {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    let mut vectors = include_str!("digest-vectors.txt").lines();
    let mut count = 0;
    for nonce in [0, 1, u64::MAX, 0x0123_4567_89ab_cdef] {
        for vault in [None, Some([0; 20]), Some([0x80; 20]), Some([0xff; 20])] {
            for expiry in [None, Some(0), Some(1), Some(u64::MAX)] {
                let p = preimage(nonce, vault, expiry);
                let (expected_bytes, expected_digest) =
                    vectors.next().unwrap().split_once(' ').unwrap();
                assert_eq!(hex(p.as_bytes()), expected_bytes);
                assert_eq!(hex(&inner_digest(&p)), expected_digest);
                count += 1;
            }
        }
    }
    assert_eq!(count, 64);
    assert!(vectors.next().is_none());
}
