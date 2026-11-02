use hl_bincode_varint::{count_u32, count_u64};
#[test]
fn target_counter_states() {
    for row in include_str!(
        "../../../research/work-items/RE-005-bincode-size-state-rust-94/target-smoke.tsv"
    )
    .lines()
    {
        let f: Vec<_> = row.split('\t').collect();
        assert_eq!(f.len(), 7);
        let owner: u8 = f[0].parse().unwrap();
        let value: u64 = f[1].parse().unwrap();
        let mut counter: u64 = f[2].parse().unwrap();
        let result = if owner == 0 {
            count_u32(u32::try_from(value).unwrap(), &mut counter)
        } else {
            count_u64(value, &mut counter)
        };
        assert_eq!(result.is_ok(), f[4] == "O", "{row}");
        assert_eq!(counter, f[5].parse::<u64>().unwrap(), "{row}");
    }
}
#[test]
fn sequential_calls_keep_a_partial_marker_when_payload_overflows() {
    let mut count = u64::MAX - 4;
    assert!(count_u32(251, &mut count).is_ok());
    assert_eq!(count, u64::MAX - 1);
    assert!(count_u64(1 << 32, &mut count).is_err());
    assert_eq!(count, u64::MAX);
    assert!(count_u32(0, &mut count).is_err());
    assert_eq!(count, u64::MAX);
}
