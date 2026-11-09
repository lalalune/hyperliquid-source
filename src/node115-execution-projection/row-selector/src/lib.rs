#![no_std]
#![forbid(unsafe_code)]
//! Bounded 32-byte row selection from node115 `0x2af756d`.

fn first_word(row: &[u8; 32]) -> u64 {
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&row[..8]);
    u64::from_le_bytes(bytes)
}

/// Selects one row with the measured unsigned-first-word tie rule.
///
/// `compare_suffix(current, candidate)` returns the signed comparator byte used
/// when the first words are equal. A positive result keeps `current`; zero or a
/// negative result selects the later `candidate`.
pub fn select_32<F>(rows: &[[u8; 32]], mut compare_suffix: F) -> Option<usize>
where
    F: FnMut(&[u8; 32], &[u8; 32]) -> i8,
{
    let mut selected = 0;
    for candidate in 1..rows.len() {
        let current_word = first_word(&rows[selected]);
        let candidate_word = first_word(&rows[candidate]);
        let order = if current_word < candidate_word {
            -1
        } else if current_word > candidate_word {
            1
        } else {
            compare_suffix(&rows[selected], &rows[candidate])
        };

        if order <= 0 {
            selected = candidate;
        }
    }

    if rows.is_empty() {
        None
    } else {
        Some(selected)
    }
}

#[cfg(test)]
mod tests {
    use super::select_32;
    use core::cell::Cell;

    fn row(first: u64, suffix: u8) -> [u8; 32] {
        let mut value = [0_u8; 32];
        value[..8].copy_from_slice(&first.to_le_bytes());
        value[8] = suffix;
        value
    }

    fn suffix_order(left: &[u8; 32], right: &[u8; 32]) -> i8 {
        match left[8].cmp(&right[8]) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }
    }

    #[test]
    fn empty_and_single_rows() {
        assert_eq!(select_32(&[], |_, _| unreachable!()), None);
        assert_eq!(select_32(&[row(9, 0)], |_, _| unreachable!()), Some(0));
    }

    #[test]
    fn unequal_first_words_prefer_the_larger_value() {
        let calls = Cell::new(0);
        let rows = [row(7, 100), row(9, 0), row(8, 200)];
        assert_eq!(
            select_32(&rows, |_, _| {
                calls.set(calls.get() + 1);
                unreachable!()
            }),
            Some(1)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn suffix_positive_keeps_current() {
        let rows = [row(7, 9), row(7, 2)];
        assert_eq!(select_32(&rows, suffix_order), Some(0));
    }

    #[test]
    fn suffix_zero_prefers_later_candidate() {
        let rows = [row(7, 7), row(7, 7)];
        assert_eq!(select_32(&rows, suffix_order), Some(1));
    }

    #[test]
    fn suffix_negative_prefers_later_candidate() {
        let rows = [row(7, 7), row(7, 8)];
        assert_eq!(select_32(&rows, suffix_order), Some(1));
    }

    #[test]
    fn later_unequal_word_replaces_a_tied_current_row() {
        let rows = [row(7, 9), row(7, 8), row(10, 0), row(3, 255)];
        assert_eq!(select_32(&rows, suffix_order), Some(2));
    }
}
