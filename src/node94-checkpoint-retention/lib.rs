//! Selected checkpoint row policy conditional on opaque helper results.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub keep: bool,
    pub diagnostic_requested: bool,
}

/// A nonzero marker-helper AL takes the unconditional keep path. For other
/// rows, a below-lower diagnostic is requested; if that helper returns normally,
/// keep iff lower <= height < upper and height <= cap, all unsigned.
pub const fn decide(marker_al: u8, height: u64, lower: u64, upper: u64, cap: u64) -> Decision {
    if marker_al != 0 {
        return Decision {
            keep: true,
            diagnostic_requested: false,
        };
    }
    Decision {
        keep: lower <= height && height < upper && height <= cap,
        diagnostic_requested: height < lower,
    }
}

/// Read the observed little-endian height at +0x18 of an opaque 32-byte row.
pub const fn height(row: &[u8; 32]) -> u64 {
    u64::from_le_bytes([
        row[24], row[25], row[26], row[27], row[28], row[29], row[30], row[31],
    ])
}

/// Copy one selected row unchanged. The marker result is supplied, never
/// queried from the filesystem. Diagnostic/helper effects are not performed.
pub fn retained_row(
    row: [u8; 32],
    marker_al: u8,
    lower: u64,
    upper: u64,
    cap: u64,
) -> Option<[u8; 32]> {
    if decide(marker_al, height(&row), lower, upper, cap).keep {
        Some(row)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_bypasses_even_empty_or_inverted_intervals() {
        for marker in [1, 2, 128, 255] {
            assert_eq!(
                decide(marker, 0, 100, 1, 0),
                Decision {
                    keep: true,
                    diagnostic_requested: false
                }
            );
        }
    }

    #[test]
    fn lower_and_cap_are_inclusive_but_upper_is_exclusive() {
        assert!(decide(0, 10, 10, 20, 10).keep);
        assert!(!decide(0, 20, 10, 20, 30).keep);
        assert!(!decide(0, 11, 10, 20, 10).keep);
        assert!(decide(0, 9, 10, 20, 30).diagnostic_requested);
        assert!(!decide(0, 20, 10, 20, 30).diagnostic_requested);
    }

    #[test]
    fn selected_rows_preserve_all_bytes_including_opaque_fields() {
        let mut row = [0xa5; 32];
        row[24..32].copy_from_slice(&10u64.to_le_bytes());
        assert_eq!(height(&row), 10);
        assert_eq!(retained_row(row, 0, 10, 20, 10), Some(row));
        assert_eq!(retained_row(row, 0, 0, 10, 20), None);
    }
}
