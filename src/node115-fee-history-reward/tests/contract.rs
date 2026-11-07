use node115_fee_history_reward::{
    build_reward_rows, select_ordered, CumulativeUnderflow, RewardRow, TxFields, WeightOverflow,
};

fn tx(prefix: u128, zero_cap: u128, other_cap: u128, priority_cap: u128) -> TxFields {
    TxFields {
        prefix,
        zero_cap,
        other_cap,
        priority_cap,
    }
}
fn row(reward: u128, gas: u64) -> RewardRow {
    RewardRow { reward, gas }
}

#[test]
fn paired_construction_and_failure_are_bounded() {
    let items = [
        tx(0, 4, 900, 0),
        tx(1, 0, (1u128 << 64) + 4, 0),
        tx(2, 0, 200, 7),
    ];
    assert_eq!(
        build_reward_rows(&items, &[2, 5, 8, 7], 5).unwrap(),
        vec![row(0, 2), row((1u128 << 64) - 1, 3), row(7, 3)]
    );
    assert_eq!(build_reward_rows(&items, &[2], 5).unwrap(), vec![row(0, 2)]);
    assert_eq!(
        build_reward_rows(&items, &[4, 3], 5),
        Err(CumulativeUnderflow { index: 1 })
    );
    assert!(build_reward_rows(&[], &[1], 0).unwrap().is_empty());
}

#[test]
fn ordered_selection_keeps_cursor_and_independent_total() {
    let rows = [row(10, 2), row(20, 3), row(30, 5)];
    assert_eq!(
        select_ordered(&rows, &[0.0, 20.0, 21.0, 50.0, 100.0, 0.0], 10).unwrap(),
        vec![10, 10, 10, 20, 30, 30]
    );
    assert_eq!(select_ordered(&rows, &[50.0], 100).unwrap(), vec![30]);
    assert_eq!(
        select_ordered(&[], &[f64::NAN, 42.0], 10).unwrap(),
        vec![0, 0]
    );
    assert_eq!(
        select_ordered(&[row(1, u64::MAX), row(2, 1)], &[100.0], u64::MAX).unwrap(),
        vec![1]
    );
    assert_eq!(
        select_ordered(&[row(1, u64::MAX - 1), row(2, 2)], &[f64::INFINITY], 1),
        Err(WeightOverflow { index: 1 })
    );
}

#[test]
fn percentile_cast_handles_nonfinite_negative_and_large_values() {
    let rows = [row(1, 0), row(2, 1), row(3, 1)];
    assert_eq!(
        select_ordered(&rows, &[f64::NAN, f64::NEG_INFINITY, -10.0, -0.0], 100).unwrap(),
        vec![1, 1, 1, 1]
    );
    assert_eq!(select_ordered(&rows, &[f64::INFINITY], 1).unwrap(), vec![3]);
    assert_eq!(
        select_ordered(&rows, &[f64::MAX], u64::MAX).unwrap(),
        vec![3]
    );
    assert_eq!(select_ordered(&rows, &[f64::INFINITY], 0).unwrap(), vec![1]);
}

// Compare 128-bit reward math with an independently written limb oracle.
fn limb_oracle(prefix: u128, zero: u128, other: u128, tip: u128, base: u64) -> u128 {
    let cap = if prefix == 0 { zero } else { other };
    let low = cap as u64;
    let high = (cap >> 64) as u64;
    let (lo, borrow) = low.overflowing_sub(base);
    let (hi, underflow) = high.overflowing_sub(u64::from(borrow));
    let d = if underflow {
        0
    } else {
        (u128::from(hi) << 64) | u128::from(lo)
    };
    if prefix >= 2 && tip < d {
        tip
    } else {
        d
    }
}

#[test]
fn deterministic_limb_crosscheck() {
    let mut state = 0x3e4c7a92d6b58f10u64;
    fn next(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }
    for i in 0..10_000 {
        let mut wide = || (u128::from(next(&mut state)) << 64) | u128::from(next(&mut state));
        let z = wide();
        let o = wide();
        let cap = wide();
        let random = wide();
        let prefix = match i % 4 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => random,
        };
        let base = next(&mut state);
        let result = build_reward_rows(&[tx(prefix, z, o, cap)], &[u64::MAX], base).unwrap();
        assert_eq!(
            result,
            vec![row(limb_oracle(prefix, z, o, cap, base), u64::MAX)]
        );
    }
}

#[test]
fn prior_python_selection_model_fixtures() {
    let mut count = 0;
    for line in include_str!("selection-fixtures.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let columns: Vec<_> = line.split_whitespace().collect();
        assert_eq!(columns.len(), 4);
        let total = columns[0].parse::<u64>().unwrap();
        let pct = f64::from_bits(u64::from_str_radix(columns[1], 16).unwrap());
        let rows: Vec<_> = if columns[2] == "-" {
            vec![]
        } else {
            columns[2]
                .split(',')
                .map(|entry| {
                    let (gas, reward) = entry.split_once(':').unwrap();
                    row(reward.parse().unwrap(), gas.parse().unwrap())
                })
                .collect()
        };
        let actual = select_ordered(&rows, &[pct], total);
        if columns[3] == "overflow" {
            assert!(actual.is_err());
        } else {
            assert_eq!(actual.unwrap(), vec![columns[3].parse::<u128>().unwrap()]);
        }
        count += 1;
    }
    assert_eq!(count, 1200);
}

#[test]
fn explicit_order_composes_constructed_rows_with_selection() {
    let transactions = [tx(2, 0, 70, 30), tx(0, 20, 0, 0), tx(1, 0, 40, 0)];
    let generated = build_reward_rows(&transactions, &[5, 9, 10], 10).unwrap();
    assert_eq!(generated, vec![row(30, 5), row(10, 4), row(30, 1)]);
    // This ordering is a test input, not a claim about the native sorter.
    let ordered = [generated[1], generated[0], generated[2]];
    assert_eq!(
        select_ordered(&ordered, &[0.0, 40.0, 41.0, 100.0], 10).unwrap(),
        vec![10, 10, 10, 30]
    );
}

#[test]
fn unsigned_total_conversion_at_binary64_precision_boundary() {
    let rows = [row(11, 1u64 << 53), row(22, 2)];
    assert_eq!(
        select_ordered(&rows, &[100.0], (1u64 << 53) + 1).unwrap(),
        vec![11]
    );
    assert_eq!(
        select_ordered(&rows, &[100.0], (1u64 << 53) + 2).unwrap(),
        vec![22]
    );
    assert_eq!(
        select_ordered(&[row(7, u64::MAX)], &[100.0], u64::MAX).unwrap(),
        vec![7]
    );
}
