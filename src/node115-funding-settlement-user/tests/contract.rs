use node115_funding_settlement_user::*;
use std::{collections::BTreeMap, num::NonZeroU32};
fn time() -> Timestamp {
    Timestamp {
        date_word: NonZeroU32::new(12345).unwrap(),
        seconds: 100,
        nanos: 999,
    }
}
fn positions(s: &str) -> BTreeMap<u64, Position> {
    if s == "-" {
        return BTreeMap::new();
    }
    s.split(';')
        .map(|row| {
            let v: Vec<_> = row.split(',').collect();
            (
                v[0].parse().unwrap(),
                Position {
                    margin_mode: v[1].parse().unwrap(),
                    isolated_balance: v[2].parse().unwrap(),
                    size: v[3].parse().unwrap(),
                    funding_accumulators: [
                        v[4].parse().unwrap(),
                        v[5].parse().unwrap(),
                        v[6].parse().unwrap(),
                    ],
                },
            )
        })
        .collect()
}
#[test]
fn independent_python_integer_and_binary64_reference() {
    let mut outcomes = [0; 3];
    for (case, line) in include_str!("reference.tsv").lines().enumerate() {
        let v: Vec<_> = line.split('\t').collect();
        assert_eq!(v.len(), 11);
        let when = (v[0] == "1").then_some(time());
        let mut cross = v[1].parse().unwrap();
        let prices: Vec<u64> = if v[2] == "-" {
            Vec::new()
        } else {
            v[2].split(',').map(|x| x.parse().unwrap()).collect()
        };
        let rates: BTreeMap<u64, f64> = if v[3] == "-" {
            BTreeMap::new()
        } else {
            v[3].split(';')
                .map(|row| {
                    let (key, bits) = row.split_once(',').unwrap();
                    (
                        key.parse().unwrap(),
                        f64::from_bits(u64::from_str_radix(bits, 16).unwrap()),
                    )
                })
                .collect()
        };
        let mut state = positions(v[4]);
        let result = settle(&mut state, &rates, &prices, &mut cross, [0xab; 20], when);
        assert_eq!(cross, v[6].parse::<i64>().unwrap(), "cross case{case}");
        assert_eq!(state, positions(v[7]), "state case{case}");
        if v[5] != "ok" {
            let (kind, key) = v[5].split_once(':').unwrap();
            let asset = key.parse().unwrap();
            let fault = if kind == "index" {
                outcomes[1] += 1;
                Fault::OracleIndex { asset }
            } else {
                outcomes[2] += 1;
                Fault::NotionalRange { asset }
            };
            assert_eq!(result.unwrap_err(), fault, "fault case{case}");
            continue;
        }
        outcomes[0] += 1;
        let result = result.unwrap();
        assert_eq!(
            result.total_payment,
            v[9].parse::<i64>().unwrap(),
            "total case{case}"
        );
        let rows: Vec<_> = if v[8] == "-" {
            Vec::new()
        } else {
            v[8].split(';').collect()
        };
        assert_eq!(result.records.len(), rows.len(), "records case{case}");
        for (record, row) in result.records.iter().zip(rows) {
            let x: Vec<_> = row.split(',').collect();
            assert_eq!(
                (
                    record.asset,
                    record.payment,
                    record.size,
                    record.rate.to_bits(),
                    record.notional
                ),
                (
                    x[0].parse().unwrap(),
                    x[1].parse().unwrap(),
                    x[2].parse().unwrap(),
                    u64::from_str_radix(x[3], 16).unwrap(),
                    x[4].parse().unwrap()
                ),
                "record case{case}"
            );
            assert_eq!(record.user, [0xab; 20]);
            assert_eq!(record.time, time());
        }
        let largest = if v[10] == "-" {
            None
        } else {
            let (a, n) = v[10].split_once(',').unwrap();
            Some(Largest {
                asset: a.parse().unwrap(),
                absolute_notional: n.parse().unwrap(),
                user: [0xab; 20],
            })
        };
        assert_eq!(result.largest, largest, "largest case{case}");
    }
    assert_eq!(outcomes.iter().sum::<usize>(), 7000);
    assert!(outcomes.iter().all(|&x| x > 100));
}
fn position(size: i64) -> Position {
    Position {
        margin_mode: 0,
        isolated_balance: 0,
        size,
        funding_accumulators: [0; 3],
    }
}
#[test]
fn signed_minimum_notional_and_stable_largest_tie() {
    let mut p = BTreeMap::from([(0, position(i64::MIN)), (10000, position(i64::MIN))]);
    let r = BTreeMap::from([(0, 1.), (10000, 1.)]);
    let mut cross = 0;
    let out = settle(&mut p, &r, &[1], &mut cross, [1; 20], Some(time())).unwrap();
    assert_eq!(out.records[0].payment, i64::MAX);
    assert_eq!(out.total_payment, i64::MAX);
    assert_eq!(cross, i64::MAX);
    assert_eq!(p[&0].funding_accumulators, [-i64::MAX; 3]);
    assert_eq!(
        out.largest.unwrap(),
        Largest {
            asset: 0,
            absolute_notional: 1 << 63,
            user: [1; 20]
        }
    );
}
#[test]
fn sequential_total_saturation_is_not_wide_sum() {
    let mut p = BTreeMap::from([(0, position(1)), (10000, position(1)), (20000, position(1))]);
    let r = BTreeMap::from([(0, 1e100), (10000, 1e100), (20000, -1e100)]);
    let mut cross = 0;
    let out = settle(&mut p, &r, &[1], &mut cross, [0; 20], Some(time())).unwrap();
    assert_eq!(out.total_payment, -1);
}
#[test]
fn missing_time_checks_index_before_zero_size_without_writes() {
    let mut p = BTreeMap::from([(1, position(0))]);
    let r = BTreeMap::from([(1, 1.)]);
    let before = p.clone();
    let mut cross = 9;
    assert_eq!(
        settle(&mut p, &r, &[], &mut cross, [0; 20], None).unwrap_err(),
        Fault::OracleIndex { asset: 1 }
    );
    assert_eq!(p, before);
    assert_eq!(cross, 9);
    let out = settle(&mut p, &r, &[u64::MAX, u64::MAX], &mut cross, [0; 20], None).unwrap();
    assert!(out.records.is_empty());
    assert_eq!(out.total_payment, 0);
}
