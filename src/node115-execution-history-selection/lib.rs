//! Row membership for the flat-history arms of node #115's 0x2af6580.
//! Returns physical slot indices in native visit order. It does not project the
//! selected rows into owned result payloads or implement the tree variant.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidRing {
    LengthExceedsCapacity,
    HeadOutsideSingleWrap,
}

/// Select 32-byte source rows from state+0xed8. Every visited row above the
/// optional unsigned cutoff is included, including rows with empty payloads.
pub fn select32(
    slots: &[[u8; 32]],
    head: usize,
    len: usize,
    cutoff: Option<u64>,
) -> Result<Vec<usize>, InvalidRing> {
    select(slots, head, len, cutoff, false)
}

/// Select 80-byte source rows from state+0xdd0. The native key cutoff is checked
/// before the nonzero word at row+0x30; a below-cutoff empty row still stops it.
pub fn select80(
    slots: &[[u8; 80]],
    head: usize,
    len: usize,
    cutoff: Option<u64>,
) -> Result<Vec<usize>, InvalidRing> {
    select(slots, head, len, cutoff, true)
}

fn select<const N: usize>(
    slots: &[[u8; N]],
    head: usize,
    len: usize,
    cutoff: Option<u64>,
    require_nonempty: bool,
) -> Result<Vec<usize>, InvalidRing> {
    let capacity = slots.len();
    if len > capacity {
        return Err(InvalidRing::LengthExceedsCapacity);
    }
    // Native empty initialization ignores the physical head.
    if len == 0 {
        return Ok(Vec::new());
    }
    let start = if head >= capacity { head - capacity } else { head };
    if start >= capacity {
        return Err(InvalidRing::HeadOutsideSingleWrap);
    }
    let first_len = len.min(capacity - start);
    let wrapped_len = len - first_len;
    let mut selected = Vec::new();
    // Native walks the wrapped segment backward, then the first segment.
    for index in (0..wrapped_len).rev().chain((start..start + first_len).rev()) {
        let row = &slots[index];
        let key = u64::from_le_bytes(row[..8].try_into().unwrap());
        if cutoff.is_some_and(|bound| key <= bound) {
            break;
        }
        if !require_nonempty || row[0x30..0x38].iter().any(|&byte| byte != 0) {
            selected.push(index);
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_small_wraps_against_logical_order() {
        for capacity in 1..=9 {
            for head in 0..2 * capacity {
                for len in 0..=capacity {
                    let logical: Vec<usize> = (0..len).map(|i| (head + i) % capacity).collect();
                    let mut rows32 = vec![[0; 32]; capacity];
                    let mut rows80 = vec![[0; 80]; capacity];
                    for (i, &slot) in logical.iter().enumerate() {
                        let key = (10 + i as u64).to_le_bytes();
                        rows32[slot][..8].copy_from_slice(&key);
                        rows80[slot][..8].copy_from_slice(&key);
                        rows80[slot][0x37] = (i % 2) as u8;
                    }
                    for cutoff in [None, Some(0), Some(10), Some(13), Some(18), Some(u64::MAX)] {
                        let eligible: Vec<usize> = logical.iter().enumerate().rev()
                            .take_while(|(i, _)| cutoff.is_none_or(|bound| 10 + *i as u64 > bound))
                            .map(|(_, &slot)| slot).collect();
                        assert_eq!(select32(&rows32, head, len, cutoff).unwrap(), eligible);
                        let occupied: Vec<usize> = eligible.into_iter()
                            .filter(|&slot| rows80[slot][0x37] != 0).collect();
                        assert_eq!(select80(&rows80, head, len, cutoff).unwrap(), occupied);
                    }
                }
            }
        }
    }

    #[test]
    fn cutoff_stops_instead_of_filtering_and_precedes_empty_gate() {
        let mut rows = [[0u8; 80]; 3];
        for (row, key) in rows.iter_mut().zip([100u64, 5, 10]) {
            row[..8].copy_from_slice(&key.to_le_bytes());
            row[0x30] = 1;
        }
        rows[1][0x30] = 0;
        assert_eq!(select80(&rows, 0, 3, Some(5)).unwrap(), vec![2]);
        assert_eq!(select80(&rows, 0, 3, None).unwrap(), vec![2, 0]);
        // Equality at the first row stops the entire scan.
        assert!(select80(&rows, 0, 3, Some(10)).unwrap().is_empty());
    }

    #[test]
    fn valid_domain_and_inactive_fields() {
        assert_eq!(select32(&[], usize::MAX, 0, Some(0)), Ok(vec![]));
        assert_eq!(select80(&[[0; 80]], usize::MAX, 0, None), Ok(vec![]));
        assert_eq!(select32(&[], 0, 1, None), Err(InvalidRing::LengthExceedsCapacity));
        assert_eq!(select32(&[[0; 32]], 2, 1, None), Err(InvalidRing::HeadOutsideSingleWrap));
        let mut row = [0u8; 32];
        row[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(select32(&[row], 1, 1, Some(u64::MAX - 1)), Ok(vec![0]));
        assert_eq!(select32(&[row], 1, 1, Some(u64::MAX)), Ok(vec![]));
    }
}
