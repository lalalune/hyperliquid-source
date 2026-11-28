use node115_abci::lt_hash::{LT_HASH_BYTES, LT_HASH_RECORD_BYTES, LtHash};

#[test]
fn empty_input_yields_native_zero_record() {
    let empty = LtHash::from_rebuild_batches(std::iter::empty());
    assert_eq!(empty.to_record_bytes(), [0; LT_HASH_RECORD_BYTES]);
}

#[test]
fn native_batch_records_preserve_all_lanes_and_saturate_counters_independently() {
    let mut first = [0; LT_HASH_RECORD_BYTES];
    let mut second = [0; LT_HASH_RECORD_BYTES];
    let mut final_tail = [0; LT_HASH_RECORD_BYTES];
    let mut expected = [0; LT_HASH_BYTES];
    for i in 0..LT_HASH_BYTES / 2 {
        let offset = 2 * i;
        let a = 65_531 - i as u16;
        let b = 12 + 2 * i as u16;
        let c = 9 + i as u16;
        first[offset..offset + 2].copy_from_slice(&a.to_be_bytes());
        second[offset..offset + 2].copy_from_slice(&b.to_be_bytes());
        final_tail[offset..offset + 2].copy_from_slice(&c.to_be_bytes());
        let sum = ((u32::from(a) + u32::from(b) + u32::from(c)) % 65_536) as u16;
        expected[offset..offset + 2].copy_from_slice(&sum.to_be_bytes());
    }

    first[0x800..0x808].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    second[0x800..0x808].copy_from_slice(&3_u64.to_le_bytes());
    final_tail[0x800..0x808].copy_from_slice(&1_u64.to_le_bytes());
    first[0x808..].copy_from_slice(&17_u64.to_le_bytes());
    second[0x808..].copy_from_slice(&2_u64.to_le_bytes());
    final_tail[0x808..].copy_from_slice(&4_u64.to_le_bytes());

    let rebuilt = LtHash::from_rebuild_batches([&first, &second, &final_tail]);
    assert_eq!(rebuilt.hash, expected);
    assert_eq!((rebuilt.n_elements, rebuilt.n_bytes), (u64::MAX, 23));
    let image = rebuilt.to_record_bytes();
    assert_eq!(&image[..0x800], &expected);
    assert_eq!(&image[0x800..0x808], &u64::MAX.to_le_bytes());
    assert_eq!(&image[0x808..], &23_u64.to_le_bytes());

    let partial = LtHash::from_rebuild_batches([&first, &second]).to_record_bytes();
    assert_eq!(
        LtHash::from_rebuild_batches([&partial, &final_tail]),
        rebuilt
    );

    first[0x800..0x808].copy_from_slice(&7_u64.to_le_bytes());
    first[0x808..].copy_from_slice(&u64::MAX.to_le_bytes());
    let opposite = LtHash::from_rebuild_batches([&first, &second, &final_tail]);
    assert_eq!((opposite.n_elements, opposite.n_bytes), (11, u64::MAX));
}
