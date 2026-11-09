//! Flat-span collector ownership and ordered output around credited ratio code.
#![forbid(unsafe_code)]
#[allow(dead_code, unused_attributes)]
#[path = "../node115-clearinghouse-ntl-ratio/lib.rs"]
pub mod prior;
pub type Row = [u8; 72];
pub type OracleRow = [u8; 96];
pub type Output = [u64; 4];
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
#[derive(Clone, Debug)]
pub struct FlatCursor<'a> {
    pub first: &'a [Row],
    pub second: &'a [Row],
    pub consumed: usize,
}
impl FlatCursor<'_> {
    fn next(&mut self) -> Option<&Row> {
        let n = self.consumed;
        let row = if n < self.first.len() {
            self.first.get(n)
        } else {
            self.second.get(n - self.first.len())
        };
        if row.is_some() {
            self.consumed += 1;
        }
        row
    }
}
#[derive(Debug)]
pub enum Stop {
    OracleBounds { key: u64 },
    Arithmetic(prior::ApplyError),
    DifferenceDiagnostic { key: u64 },
    BalanceDiagnostic { key: u64 },
}
#[derive(Debug)]
pub struct Report {
    pub rows: Vec<Output>,
    pub local_consumed: usize,
    pub stop: Option<Stop>,
}
fn next_output(
    cursor: &mut FlatCursor<'_>,
    oracles: &[OracleRow],
    denominator: u64,
    scale: i64,
    balance: &mut i64,
) -> Result<Option<Output>, Stop> {
    while let Some(row) = cursor.next() {
        let multiplier = word(row, 24) as i64;
        let tag = u32::from_le_bytes(row[8..12].try_into().unwrap());
        if multiplier == 0 || tag != 0 {
            continue;
        }
        let key = word(row, 0);
        let Some(oracle) = oracles.get((key % 10000) as usize) else {
            return Err(Stop::OracleBounds { key });
        };
        let field = word(oracle, 32) as i64;
        let outcome = prior::apply(
            key,
            oracles.len() as u64,
            field,
            multiplier,
            denominator,
            scale,
            *balance,
        )
        .map_err(Stop::Arithmetic)?;
        match outcome {
            prior::Outcome::Absent => continue,
            prior::Outcome::Applied(prior::Applied {
                key,
                multiplier,
                difference,
                product,
                balance: next,
                difference_overflow,
                balance_overflow,
                ..
            }) => {
                // Prior apply is pure and reports its assumptions. Stop before
                // the native callback rather than commit its hypothetical result.
                if difference_overflow {
                    return Err(Stop::DifferenceDiagnostic { key });
                }
                if balance_overflow {
                    return Err(Stop::BalanceDiagnostic { key });
                }
                *balance = next;
                return Ok(Some([
                    key,
                    multiplier as u64,
                    difference as u64,
                    product as u64,
                ]));
            }
        }
    }
    Ok(None)
}
/// Non-aliasing oracle/denominator/scale/balance references match the selected
/// caller's distinct captured stack locations. A diagnostic stop is an observation
/// of partial state, not a native successful return or assumed unwind result.
pub fn collect(
    cursor: &mut FlatCursor<'_>,
    oracles: &[OracleRow],
    denominator: u64,
    scale: i64,
    balance: &mut i64,
) -> Report {
    let first = match next_output(cursor, oracles, denominator, scale, balance) {
        Ok(Some(output)) => output,
        Ok(None) => {
            return Report {
                rows: Vec::new(),
                local_consumed: cursor.consumed,
                stop: None,
            };
        }
        Err(stop) => {
            return Report {
                rows: Vec::new(),
                local_consumed: cursor.consumed,
                stop: Some(stop),
            };
        }
    };
    let mut rows = Vec::with_capacity(4);
    rows.push(first);
    // Native 0x3db85be..0x3db8614 copies the iterator/captured context. Later
    // iteration mutates the local copy, not the caller's original cursor.
    let mut local = cursor.clone();
    loop {
        match next_output(&mut local, oracles, denominator, scale, balance) {
            Ok(Some(output)) => rows.push(output),
            Ok(None) => {
                return Report {
                    rows,
                    local_consumed: local.consumed,
                    stop: None,
                };
            }
            Err(stop) => {
                return Report {
                    rows,
                    local_consumed: local.consumed,
                    stop: Some(stop),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(key: u64, tag: u32, quantity: i64) -> Row {
        let mut row = [0; 72];
        row[..8].copy_from_slice(&key.to_le_bytes());
        row[8..12].copy_from_slice(&tag.to_le_bytes());
        row[24..32].copy_from_slice(&quantity.to_le_bytes());
        row
    }
    fn oracle(value: i64) -> OracleRow {
        let mut row = [0; 96];
        row[32..40].copy_from_slice(&value.to_le_bytes());
        row
    }
    #[test]
    fn ordered_two_position_outputs_and_cursor_copy() {
        let first = [row(999, 1, 10), row(10000, 0, 3)];
        let second = [row(10001, 0, -2)];
        let mut cursor = FlatCursor {
            first: &first,
            second: &second,
            consumed: 0,
        };
        let mut balance = 1000;
        let out = collect(
            &mut cursor,
            &[oracle(10), oracle(20)],
            100,
            100,
            &mut balance,
        );
        assert!(out.stop.is_none());
        assert_eq!(
            out.rows,
            [
                [10000, 3, 0, 30],
                [10001, (-2i64) as u64, 80, (-40i64) as u64]
            ]
        );
        assert_eq!(balance, 930);
        assert_eq!(cursor.consumed, 2);
        assert_eq!(out.local_consumed, 3);
    }
    #[test]
    fn all_filtered_or_absent_consumes_original_cursor() {
        let rows = [row(u64::MAX, 0, 0), row(u64::MAX, 2, 1), row(0, 0, 2)];
        let mut cursor = FlatCursor {
            first: &rows,
            second: &[],
            consumed: 0,
        };
        let mut balance = 8;
        let out = collect(&mut cursor, &[oracle(1)], 0, 10, &mut balance);
        assert!(out.stop.is_none());
        assert!(out.rows.is_empty());
        assert_eq!(cursor.consumed, 3);
        assert_eq!(balance, 8);
    }
    #[test]
    fn oracle_bounds_precedes_zero_denominator_for_eligible_rows() {
        let rows = [row(2, 0, 1)];
        let mut cursor = FlatCursor {
            first: &rows,
            second: &[],
            consumed: 0,
        };
        let mut balance = 8;
        let out = collect(&mut cursor, &[oracle(1)], 0, 10, &mut balance);
        assert!(matches!(out.stop, Some(Stop::OracleBounds { key: 2 })));
        assert_eq!(balance, 8);
    }
    #[test]
    fn balance_diagnostic_keeps_prior_debits_and_omits_current_output() {
        let rows = [row(0, 0, 1), row(1, 0, 1)];
        let mut cursor = FlatCursor {
            first: &rows,
            second: &[],
            consumed: 0,
        };
        let mut balance = i64::MIN;
        let out = collect(&mut cursor, &[oracle(0), oracle(1)], 1, 1, &mut balance);
        assert!(matches!(out.stop, Some(Stop::BalanceDiagnostic { key: 1 })));
        assert_eq!(out.rows, [[0, 1, 0, 0]]);
        assert_eq!(balance, i64::MIN);
        assert_eq!(cursor.consumed, 1);
        assert_eq!(out.local_consumed, 2);
    }
    #[test]
    fn difference_diagnostic_precedes_balance_mutation_and_output() {
        let rows = [row(0, 0, -1)];
        let mut cursor = FlatCursor {
            first: &rows,
            second: &[],
            consumed: 0,
        };
        let mut balance = 10;
        let out = collect(
            &mut cursor,
            &[oracle(i64::MAX)],
            i64::MAX as u64,
            i64::MAX,
            &mut balance,
        );
        assert!(matches!(
            out.stop,
            Some(Stop::DifferenceDiagnostic { key: 0 })
        ));
        assert_eq!(balance, 10);
        assert!(out.rows.is_empty());
    }
    #[test]
    fn span_splits_and_growth_preserve_all_full_keys() {
        let rows: Vec<_> = (0..65).map(|i| row(i * 10000, 0, 1)).collect();
        for split in 0..=rows.len() {
            let mut cursor = FlatCursor {
                first: &rows[..split],
                second: &rows[split..],
                consumed: 0,
            };
            let mut balance = 1000;
            let out = collect(&mut cursor, &[oracle(2)], 1, 1, &mut balance);
            assert!(out.stop.is_none());
            assert_eq!(out.rows.len(), 65);
            assert_eq!(cursor.consumed, 1);
            assert_eq!(out.local_consumed, 65);
            for (i, r) in out.rows.iter().enumerate() {
                assert_eq!(*r, [(i as u64) * 10000, 1, 0, 2]);
            }
            assert_eq!(balance, 870);
        }
    }
}
