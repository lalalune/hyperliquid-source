//! Selected funding read-then-reset handoff from node #115.
//! Rows are a logical projection; native allocation/tree shapes are premises.
use node115_funding_rate::{Config, rate};
use std::collections::BTreeMap;

pub struct Row {
    pub group_word: u64,
    pub item_count: u64,
    pub samples: BTreeMap<u64, Vec<f64>>,
}
#[derive(Debug, PartialEq)]
pub struct RateRead {
    pub row: usize,
    pub key: u64,
    pub value: Option<f64>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    KeyOverflow,
}

/// Snapshot direct rate-helper results in outer-row then inner-index order.
/// `None` stops at the helper result: the native caller's subsequent fallback
/// is deliberately not modelled. Normal diagnostics and stable inputs assumed.
pub fn read_rates(rows: &[Row], configs: &[Config<'_>]) -> Result<Vec<RateRead>, Stop> {
    assert_eq!(rows.len(), configs.len(), "paired row premise");
    let mut results = Vec::new();
    for (row_index, (row, config)) in rows.iter().zip(configs).enumerate() {
        for index in 0..row.item_count {
            let key = row
                .group_word
                .checked_mul(10_000)
                .and_then(|x| x.checked_add(index))
                .ok_or(Stop::KeyOverflow)?;
            results.push(RateRead {
                row: row_index,
                key,
                value: rate(key, &row.samples, config),
            });
        }
    }
    Ok(results)
}

/// Resume at the native selected reset after the intervening per-row helper
/// and its result cleanup have returned normally. All existing map entries are
/// retained; only each vector's logical length changes to zero.
pub fn reset_after_normal_helper(row: &mut Row) {
    for samples in row.samples.values_mut() {
        samples.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config<'a>(m: &'a BTreeMap<u64, f64>) -> Config<'a> {
        Config {
            baselines: m,
            correction_bounds: m,
            default_correction_bound: 0.0,
            multipliers: m,
        }
    }
    #[test]
    fn read_then_clear_preserves_entries_and_allocation() {
        let empty = BTreeMap::new();
        let mut values = Vec::with_capacity(8);
        values.extend([0.01, 0.03]);
        let mut rows = [Row {
            group_word: 1,
            item_count: 2,
            samples: BTreeMap::from([(10_000, values), (99, vec![9.0]), (10_001, Vec::new())]),
        }];
        let ptr = rows[0].samples[&10_000].as_ptr();
        let cap = rows[0].samples[&10_000].capacity();
        let result = read_rates(&rows, &[config(&empty)]).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].key, 10_000);
        assert_eq!(result[0].value, Some(0.0025));
        assert_eq!(result[1].value, None);
        reset_after_normal_helper(&mut rows[0]);
        assert_eq!(rows[0].samples.len(), 3);
        assert!(rows[0].samples.values().all(Vec::is_empty));
        assert_eq!(rows[0].samples[&10_000].as_ptr(), ptr);
        assert_eq!(rows[0].samples[&10_000].capacity(), cap);
        assert!(
            read_rates(&rows, &[config(&empty)])
                .unwrap()
                .iter()
                .all(|x| x.value.is_none())
        );
        rows[0].samples.get_mut(&10_000).unwrap().push(0.04);
        assert_eq!(
            read_rates(&rows, &[config(&empty)]).unwrap()[0].value,
            Some(0.005)
        );
        reset_after_normal_helper(&mut rows[0]);
        assert_eq!(rows[0].samples[&10_000].capacity(), cap);
    }
    #[test]
    fn two_rows_empty_and_checked_keys() {
        let empty = BTreeMap::new();
        let rows = [
            Row {
                group_word: 2,
                item_count: 2,
                samples: BTreeMap::new(),
            },
            Row {
                group_word: 4,
                item_count: 1,
                samples: BTreeMap::new(),
            },
        ];
        let result = read_rates(&rows, &[config(&empty), config(&empty)]).unwrap();
        assert_eq!(
            result.iter().map(|r| (r.row, r.key)).collect::<Vec<_>>(),
            vec![(0, 20_000), (0, 20_001), (1, 40_000)]
        );
        assert!(read_rates(&[], &[]).unwrap().is_empty());
        let overflow = [Row {
            group_word: u64::MAX,
            item_count: 1,
            samples: BTreeMap::new(),
        }];
        assert_eq!(
            read_rates(&overflow, &[config(&empty)]),
            Err(Stop::KeyOverflow)
        );
    }
}
