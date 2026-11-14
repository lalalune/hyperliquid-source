//! Node115 0x593212c..0x593233d: admission of already prepared 72-byte rows.
//! Earlier state-dependent admission and the 56 -> 72 byte transform are outside
//! this projection. Raw field names deliberately avoid unproved domain labels.

pub type PreparedRow = [u8; 72];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionError {
    UnsupportedMode,
    InvalidDirection,
}

/// Returns the native status (0x1a2 on success). The caller has already passed
/// earlier admission, including state-dependent optional-buffer checks. Inputs
/// must have a valid Boolean direction byte, as required by the native layout.
/// The explicit source errors represent failed premises, not native statuses.
pub fn admit(mode: u32, rows: &[PreparedRow]) -> Result<u16, ProjectionError> {
    if mode > 3 {
        return Err(ProjectionError::UnsupportedMode);
    }
    if rows.iter().any(|r| r[0x30] > 1) {
        return Err(ProjectionError::InvalidDirection);
    }
    let Some(first) = rows.first() else {
        return Ok(0x6e);
    };
    if mode == 0 || mode == 3 {
        return Ok(0x1a2);
    }
    let (checked, direction) = if mode == 1 {
        if first[0x19] != 2 {
            return Ok(0x72);
        }
        (&rows[1..], first[0x30] ^ 1)
    } else {
        (rows, first[0x30])
    };
    for row in checked {
        if row[0x19] == 2 {
            return Ok(0x73);
        }
        if row[0x30] != direction {
            return Ok(0x6f);
        }
        if row[0x31] != 1 {
            return Ok(0x70);
        }
        if row[0x28..0x30] != first[0x28..0x30] {
            return Ok(0x74);
        }
    }
    // Native dec then unsigned cmp <2: admitted checked-row count is 1 or 2.
    Ok(if (1..=2).contains(&checked.len()) {
        0x1a2
    } else {
        0x71
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(tag: u8, direction: u8, flag: u8, identity: u64) -> PreparedRow {
        let mut r = [0x55; 72];
        r[0x19] = tag;
        r[0x30] = direction;
        r[0x31] = flag;
        r[0x28..0x30].copy_from_slice(&identity.to_le_bytes());
        r
    }
    #[test]
    fn count_matrix_and_direction_symmetry() {
        for direction in 0..=1 {
            for count in 0..=5 {
                let children = vec![row(0, direction ^ 1, 1, u64::MAX); count];
                let mut with_prefix = vec![row(2, direction, 0, u64::MAX)];
                with_prefix.extend_from_slice(&children);
                assert_eq!(
                    admit(1, &with_prefix),
                    Ok(if (1..=2).contains(&count) {
                        0x1a2
                    } else {
                        0x71
                    })
                );
                assert_eq!(
                    admit(2, &children),
                    Ok(match count {
                        0 => 0x6e,
                        1 | 2 => 0x1a2,
                        _ => 0x71,
                    })
                );
            }
        }
    }
    #[test]
    fn failure_precedence_is_row_order_before_count() {
        let prefix = row(2, 0, 0, 7);
        let good = row(0, 1, 1, 7);
        let mut bad = row(2, 0, 0, 8);
        assert_eq!(admit(1, &[prefix, bad]), Ok(0x73));
        bad[0x19] = 1;
        assert_eq!(admit(1, &[prefix, bad]), Ok(0x6f));
        bad[0x30] = 1;
        assert_eq!(admit(1, &[prefix, bad]), Ok(0x70));
        bad[0x31] = 1;
        assert_eq!(admit(1, &[prefix, bad]), Ok(0x74));
        // Third child fails its identity check before the cardinality rejection.
        assert_eq!(admit(1, &[prefix, good, good, bad]), Ok(0x74));
        assert_eq!(admit(1, &[prefix, good, good, good]), Ok(0x71));
        assert_eq!(admit(1, &[good, bad]), Ok(0x72));
    }
    #[test]
    fn modes_zero_and_three_skip_the_late_group_checks_only() {
        let deliberately_bad = row(2, 0, 0, 7);
        for mode in [0, 3] {
            assert_eq!(admit(mode, &[]), Ok(0x6e));
            assert_eq!(admit(mode, &[deliberately_bad; 4]), Ok(0x1a2));
        }
    }
    #[test]
    fn whole_identity_and_unread_bytes() {
        let prefix = row(2, 0, 0, 0x0102_0304_0506_0708);
        let good = row(1, 1, 1, 0x0102_0304_0506_0708);
        for byte in 0..72 {
            let mut changed = good;
            changed[byte] ^= 0x40;
            if (0x28..0x30).contains(&byte) {
                assert_eq!(admit(1, &[prefix, changed]), Ok(0x74));
            } else if ![0x19, 0x30, 0x31].contains(&byte) {
                assert_eq!(admit(1, &[prefix, changed]), Ok(0x1a2));
            }
        }
    }
    #[test]
    fn explicit_premise_errors_are_not_native_statuses() {
        assert_eq!(admit(4, &[]), Err(ProjectionError::UnsupportedMode));
        assert_eq!(
            admit(1, &[row(2, 2, 0, 0)]),
            Err(ProjectionError::InvalidDirection)
        );
    }
}
