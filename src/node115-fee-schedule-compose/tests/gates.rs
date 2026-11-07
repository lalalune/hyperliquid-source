use node115_fee_schedule_compose::{evaluate, FloorSide, Outcome, Schedule, Secondary, Tier};
fn empty<'a>() -> Schedule<'a> {
    Schedule {
        seeds: [0.0; 4],
        tiers: &[],
        secondary: &[],
        stake_pairs: &[],
        extra_values: &[],
        ranges: [0.0, 1.0],
    }
}
#[test]
fn calls_both_dependencies_only_after_preceding_gates() {
    let mut calls = Vec::new();
    assert_eq!(
        evaluate(&empty(), |side, _, discount| {
            calls.push((side, discount));
            true
        }),
        Outcome::Passed
    );
    assert_eq!(calls, [(FloorSide::First, 0.0), (FloorSide::Second, 0.0)]);
    calls.clear();
    assert_eq!(
        evaluate(&empty(), |side, _, _| {
            calls.push((side, 0.0));
            false
        }),
        Outcome::Rejected
    );
    assert_eq!(calls, [(FloorSide::First, 0.0)]);
    let mut s = empty();
    s.ranges = [0.0, 1.01];
    calls.clear();
    assert_eq!(
        evaluate(&s, |side, _, _| {
            calls.push((side, 0.0));
            true
        }),
        Outcome::Rejected
    );
    assert!(calls.is_empty());
}
#[test]
fn finite_gate_precedes_any_dependency() {
    for v in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
        let mut s = empty();
        s.seeds[0] = v;
        assert_eq!(
            evaluate(&s, |_, _, _| panic!("not reached")),
            Outcome::Rejected
        );
        s = empty();
        s.extra_values = core::slice::from_ref(&v);
        assert_eq!(
            evaluate(&s, |_, _, _| panic!("not reached")),
            Outcome::Rejected
        );
    }
}
#[test]
fn tier_cutoff_and_monotonic_fields_are_both_required() {
    let t = Tier {
        values: [0.0002, -0.0002, 0.0002, -0.0002],
        cutoff: 1,
        tail: 0.9,
    };
    let tiers = [t];
    let mut s = empty();
    s.seeds = [0.0003, -0.0001, 0.0003, -0.0001];
    s.tiers = &tiers;
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Passed);
    let bad = [Tier { cutoff: 0, ..t }];
    s.tiers = &bad;
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Rejected);
    let bad = [Tier { tail: 1.1, ..t }];
    s.tiers = &bad;
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Rejected);
    let bad = [Tier {
        values: [0.0004, -0.0002, 0.0002, -0.0002],
        ..t
    }];
    s.tiers = &bad;
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Rejected);
}
#[test]
fn secondary_pairs_and_stake_boundaries() {
    let rows = [
        Secondary {
            first: 0.1,
            second: 0.0,
        },
        Secondary {
            first: 0.2,
            second: -0.0001,
        },
    ];
    let mut s = empty();
    s.secondary = &rows;
    s.stake_pairs = &[(1.0, 0.1), (5.0, 0.5)];
    assert_eq!(evaluate(&s, |_, _, d| d == 0.5), Outcome::Passed);
    s.stake_pairs = &[(1.0, 0.1), (5.0, 0.5000001)];
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Rejected);
    s.stake_pairs = &[(f64::NAN, 0.1)];
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Rejected);
    let rows = [Secondary {
        first: 0.0,
        second: 0.0,
    }];
    s.secondary = &rows;
    s.stake_pairs = &[];
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Rejected);
}
#[test]
fn post_floor_ranges_reject_the_gap_but_accept_exact_bounds() {
    for (v, pass) in [
        (0.0, true),
        (0.0001, true),
        (0.001, true),
        (0.00009999, false),
        (0.00100001, false),
        (-0.0001, false),
    ] {
        let mut s = empty();
        s.seeds[0] = v;
        let mut calls = 0;
        assert_eq!(
            evaluate(&s, |_, _, _| {
                calls += 1;
                true
            }),
            if pass {
                Outcome::Passed
            } else {
                Outcome::Rejected
            }
        );
        assert_eq!(calls, 2);
    }
    for (v, pass) in [
        (-0.001, true),
        (-0.00100001, false),
        (0.0, true),
        (0.0001, true),
        (0.0000999, false),
    ] {
        let mut s = empty();
        s.seeds[1] = v;
        assert_eq!(
            evaluate(&s, |_, _, _| true),
            if pass {
                Outcome::Passed
            } else {
                Outcome::Rejected
            }
        );
    }
}
#[test]
fn extra_sum_is_ordered_and_ceiling_inclusive() {
    let mut s = empty();
    s.extra_values = &[0.5, 0.5];
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Passed);
    s.extra_values = &[0.5, 0.50001];
    assert_eq!(
        evaluate(&s, |_, _, _| panic!("not reached")),
        Outcome::Rejected
    );
}

#[test]
fn prior_published_schedule_and_selected_counterexamples() {
    let tiers = [
        Tier {
            values: [0.0004, 0.00012, 0.0006, 0.0003],
            cutoff: 5_000_000,
            tail: 0.9,
        },
        Tier {
            values: [0.0003, 0.0001, 0.0005, 0.0002],
            cutoff: 25_000_000,
            tail: 0.5,
        },
    ];
    let secondary = [
        Secondary {
            first: 0.005,
            second: -0.00001,
        },
        Secondary {
            first: 0.015,
            second: -0.00002,
        },
    ];
    let mut s = Schedule {
        seeds: [0.00045, 0.00015, 0.0007, 0.0004],
        tiers: &tiers,
        secondary: &secondary,
        stake_pairs: &[(0.0001, 0.05), (0.001, 0.1), (5.0, 0.4)],
        extra_values: &[0.25, 0.5],
        ranges: [0.2, 0.5],
    };
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Passed);
    assert_eq!(
        evaluate(&s, |side, _, _| side == FloorSide::First),
        Outcome::Rejected
    );
    s.extra_values = &[0.6, 0.5];
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Rejected);
    s.extra_values = &[0.25, 0.5];
    s.seeds[0] = 0.0011;
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Rejected);
}

#[test]
fn signed_zero_negative_extra_and_sum_overflow() {
    let mut s = empty();
    s.seeds = [-0.0, 0.0, -0.0, 0.0];
    s.extra_values = &[-1.0, 0.5];
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Passed);
    s.extra_values = &[f64::MAX, f64::MAX];
    assert_eq!(
        evaluate(&s, |_, _, _| panic!("sum gate precedes floor")),
        Outcome::Rejected
    );
}
#[test]
fn equality_is_accepted_for_descending_values_but_not_strict_keys() {
    let t = Tier {
        values: [0.0; 4],
        cutoff: 1,
        tail: 1.0,
    };
    let duplicate = [t, t];
    let mut s = empty();
    s.tiers = &duplicate;
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Rejected);
    let increasing = [t, Tier { cutoff: 2, ..t }];
    s.tiers = &increasing;
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Passed);
    let duplicate = [Secondary {
        first: 0.1,
        second: 0.0,
    }; 2];
    s.tiers = &[];
    s.secondary = &duplicate;
    assert_eq!(evaluate(&s, |_, _, _| true), Outcome::Rejected);
}
