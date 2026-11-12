//! Selected normal continuation of 0x2f063f0 after its helper outputs.
//! Row construction, lookups, diagnostics and public units remain open.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    pub tag: u64,
    pub upper: u64,
    pub word_10: i64,
    pub byte_18: u8,
    pub lower: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Decimals,
    NegativeWord,
}

/// On a valid resolved input, returns the first accepted candidate in row order.
/// `base` is the already-combined helper result, `held` is incoming R9, and
/// `quantity`/`decimals` are the resolved source fields. A tag 2 ends the scan.
/// Native diagnostic calls on integer overflow are assumed to return normally.
pub fn scan(
    rows: &[Row],
    base: i64,
    held: i64,
    quantity: i64,
    decimals: u8,
) -> Result<Option<f64>, Stop> {
    const POWERS: [f64; 22] = [
        1.0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16,
        1e17, 1e18, 1e19, 1e20, 1e21,
    ];
    let magnitude = quantity.unsigned_abs() as f64;
    let direction = if quantity <= 0 { -1.0 } else { 1.0 };
    for row in rows {
        if row.tag == 2 {
            break;
        }
        let normalized = if quantity == 0 {
            0.0
        } else if decimals <= 21 {
            magnitude / POWERS[usize::from(decimals)]
        } else {
            return Err(Stop::Decimals);
        };
        // A negative row word takes a native exceptional branch, not this path.
        if row.word_10 < 0 {
            return Err(Stop::NegativeWord);
        }
        let numerator = base.saturating_add(row.word_10).saturating_sub(held) as f64 / 1_000_000.0;
        let candidate =
            numerator / ((1.0 / f64::from(u16::from(row.byte_18) * 2) - direction) * normalized);
        if !(candidate > 0.0 && candidate <= 1.0e15) {
            continue;
        }
        let product = normalized * candidate;
        if !matches!(
            product.partial_cmp(&(row.lower as f64 / 1_000_000.0)),
            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        ) {
            continue;
        }
        if row.tag & 1 != 0
            && !matches!(
                (row.upper as f64 / 1_000_000.0).partial_cmp(&product),
                Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
            )
        {
            continue;
        }
        return Ok(Some(candidate));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(tag: u64, lower: u64, upper: u64) -> Row {
        Row {
            tag,
            lower,
            upper,
            word_10: 0,
            byte_18: 1,
        }
    }
    #[test]
    fn ordered_first_match_and_tag_termination() {
        // Positive quantity: divisor 2 gives -0.5 denominator; -1e6 numerator => 2.
        let rows = [
            row(0, 3_000_000, 0),
            row(1, 1_000_000, 3_000_000),
            row(0, 0, 0),
        ];
        assert_eq!(scan(&rows, -1_000_000, 0, 1, 0), Ok(Some(2.0)));
        assert_eq!(
            scan(&[row(2, 0, 0), rows[1]], -1_000_000, 0, 1, 0),
            Ok(None)
        );
    }
    #[test]
    fn boundaries_and_stops() {
        let r = row(1, 2_000_000, 2_000_000);
        assert_eq!(scan(&[r], -1_000_000, 0, 1, 0), Ok(Some(2.0)));
        assert_eq!(scan(&[row(1, 0, 1_999_999)], -1_000_000, 0, 1, 0), Ok(None));
        assert_eq!(scan(&[r], -1_000_000, 0, 0, 0), Ok(None));
        assert_eq!(scan(&[r], 1, 0, 1, 22), Err(Stop::Decimals));
        assert_eq!(
            scan(&[Row { word_10: -1, ..r }], 1, 0, 1, 0),
            Err(Stop::NegativeWord)
        );
    }
    #[test]
    fn inactive_fields_and_ieee_edges() {
        let terminal = row(2, 0, 0);
        assert_eq!(scan(&[], 0, 0, 1, 255), Ok(None));
        assert_eq!(scan(&[terminal], 0, 0, 1, 255), Ok(None));
        let zero_divisor = Row {
            byte_18: 0,
            ..row(0, 0, 0)
        };
        assert_eq!(scan(&[zero_divisor], -1_000_000, 0, 1, 0), Ok(None));
        assert_eq!(scan(&[zero_divisor], 0, 0, 0, 255), Ok(None));
        // q=MIN normalizes using its unsigned magnitude, without signed overflow.
        let min_result = scan(&[row(0, 0, 0)], i64::MAX, 0, i64::MIN, 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            min_result,
            (i64::MAX as f64 / 1e6) / (1.5 * (1u64 << 63) as f64)
        );
        // Saturating both integer operations retains the MAX endpoint.
        let overflow = Row {
            word_10: 1,
            ..row(0, 0, 0)
        };
        assert_eq!(
            scan(&[overflow], i64::MAX, i64::MIN, -1, 0),
            Ok(Some((i64::MAX as f64 / 1e6) / 1.5))
        );
        // The upper candidate endpoint is inclusive.
        assert_eq!(
            scan(&[row(0, 0, 0)], -500_000_000_000_000_000, 0, 1, 3),
            Ok(Some(1e15))
        );
    }
}
