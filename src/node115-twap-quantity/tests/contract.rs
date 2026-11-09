use node115_twap_quantity::{State, TimestampMs, plan, slice_count};
use std::num::NonZeroU64;

fn state() -> State {
    State {
        total: 1_000_000,
        filled: 0,
        slice_index: 1,
        duration: 600.0,
        jitter: false,
    }
}
fn run(s: State, price: u64) -> Option<node115_twap_quantity::Slice> {
    plan(
        s,
        NonZeroU64::new(price).unwrap(),
        TimestampMs::new(20).unwrap(),
    )
}

#[test]
fn duration_normalization_and_saturation() {
    for d in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -100.0,
        -0.0,
        0.0,
        59.999,
    ] {
        assert_eq!(slice_count(d), 1);
    }
    assert_eq!(slice_count(60.0), 3);
    assert_eq!(slice_count(120.0), 5);
    assert_eq!(slice_count(f64::MAX), u64::MAX);
    assert!(TimestampMs::new((1 << 53) - 1).is_some());
    assert!(TimestampMs::new(1 << 53).is_none());
}

#[test]
fn notional_boundary_and_minimum_rounding() {
    let s = state();
    assert_eq!(run(s, 30).unwrap().quantity, 1_000_000);
    let at = run(s, 31).unwrap();
    assert_eq!(
        (at.slice_count, at.target, at.quantity),
        (21, 47_619, 387_090)
    );
    assert_eq!(run(s, 100).unwrap().quantity, 120_000);
    // Native small-remaining-notional branch may flush despite a zero target.
    assert_eq!(
        run(
            State {
                slice_index: 0,
                ..s
            },
            30
        )
        .unwrap()
        .quantity,
        1_000_000
    );
    assert_eq!(
        run(
            State {
                filled: 47_620,
                ..s
            },
            30
        ),
        None
    );
    assert_eq!(run(State { total: 0, ..s }, 30), None);
}

#[test]
fn terminal_index_skips_target_float_and_size_rounding() {
    let s = State {
        total: 1_000_000_000,
        ..state()
    };
    assert_eq!(run(s, 1).unwrap().quantity, 47_619_000);
    let terminal = run(
        State {
            slice_index: 21,
            ..s
        },
        1,
    )
    .unwrap();
    assert_eq!(terminal.target, 1_000_000_000);
    assert_eq!(terminal.quantity, 142_857_142); // 3*floor(1e9/21)+1; no significant-digit trim.
    assert_eq!(
        run(
            State {
                filled: u64::MAX,
                ..s
            },
            1
        ),
        None
    );
}

#[test]
fn rational_binary64_reference() {
    let mut count = 0;
    for line in include_str!("reference-vectors.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let c: Vec<_> = line.split_whitespace().collect();
        let n = |i: usize| c[i].parse::<u64>().unwrap();
        let s = State {
            total: n(0),
            filled: n(1),
            slice_index: n(2),
            duration: f64::from_bits(u64::from_str_radix(c[3], 16).unwrap()),
            jitter: n(4) != 0,
        };
        assert_eq!(slice_count(s.duration), n(7), "case {count}");
        let result = plan(
            s,
            NonZeroU64::new(n(5)).unwrap(),
            TimestampMs::new(n(6)).unwrap(),
        );
        if n(9) == 0 {
            assert_eq!(result, None, "case {count}");
        } else {
            let out = result.unwrap();
            assert_eq!(
                (out.slice_count, out.target, out.quantity),
                (n(7), n(8), n(9)),
                "case {count}"
            );
        }
        count += 1;
    }
    assert_eq!(count, 12000);
}
