#![no_std]
//! Safe logical model of the #115 20-byte record equality leaf.
//! This is not the original ABI or a complete raw-signature-tracker model.

/// Compare equal-length sequences of fixed 20-byte records.
///
/// The target returns false before reading either sequence when counts differ,
/// returns true for equal empty sequences, and otherwise stops at the first
/// differing byte. The function's meaning and the record type remain unknown.
pub fn records_equal(left: &[[u8; 20]], right: &[[u8; 20]]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    for (left_record, right_record) in left.iter().zip(right) {
        if left_record != right_record {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::records_equal;

    #[test]
    fn equal_empty_and_mismatched_counts_follow_the_leaf_rule() {
        let empty: [[u8; 20]; 0] = [];
        let one = [[0x31; 20]];
        let two = [[0x31; 20]; 2];
        assert!(records_equal(&empty, &empty));
        assert!(!records_equal(&empty, &one));
        assert!(!records_equal(&one, &empty));
        assert!(!records_equal(&one, &two));
    }

    #[test]
    fn matching_sequences_cover_multiple_records() {
        for count in 1..=3 {
            let left = [[0x5a; 20]; 3];
            let right = left;
            assert!(records_equal(&left[..count], &right[..count]));
        }
    }

    #[test]
    fn every_byte_of_first_middle_and_final_records_is_significant() {
        let left = [[0x5a; 20]; 3];
        for record in 0..3 {
            for byte in 0..20 {
                let mut right = left;
                right[record][byte] ^= 1;
                assert!(
                    !records_equal(&left, &right),
                    "mismatch at record {record}, byte {byte}"
                );
            }
        }
    }

    #[test]
    fn matching_zero_and_all_one_records_are_equal() {
        assert!(records_equal(&[[0; 20]], &[[0; 20]]));
        assert!(records_equal(&[[u8::MAX; 20]], &[[u8::MAX; 20]]));
    }
}
