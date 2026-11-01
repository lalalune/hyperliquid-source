//! Value reconstruction of node94 ELF VA 0x55442e0..0x554431b.
#![no_std]
#![forbid(unsafe_code)]

/// Select a table word by the highest set bit of two contiguous u64 fields.
///
/// `value` packs the field at object+0x1488 into its low half and the field at
/// object+0x1490 into its high half. `table` snapshots 128 little-endian words
/// beginning at object+0x1088. Every bit pattern is admitted. Zero returns zero
/// without selecting an entry. Stable ordinary memory is assumed; pointer ABI,
/// faults and concurrent field changes are outside this numeric projection.
pub fn lookup(value: u128, table: &[u64; 128]) -> u64 {
    if value == 0 {
        return 0;
    }
    let index = 127 - value.leading_zeros() as usize;
    table[index]
}

#[cfg(test)]
mod tests {
    use super::lookup;

    #[test]
    fn all_positions_and_zero() {
        let table = core::array::from_fn(|i| i as u64 + 10);
        assert_eq!(lookup(0, &table), 0);
        for index in 0..128 {
            assert_eq!(lookup(1_u128 << index, &table), index as u64 + 10);
        }
    }

    #[test]
    fn high_field_priority_and_full_table_values() {
        let mut table = [0_u64; 128];
        table[63] = 17;
        table[64] = u64::MAX;
        table[127] = 1_u64 << 63;
        assert_eq!(lookup(u64::MAX as u128, &table), 17);
        assert_eq!(lookup((1_u128 << 64) | u64::MAX as u128, &table), u64::MAX);
        assert_eq!(lookup(u128::MAX, &table), 1_u64 << 63);
    }
}
