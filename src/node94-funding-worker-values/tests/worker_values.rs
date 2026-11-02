use node94_funding_worker_values::{
    Inputs, Outcome, Position, RefusalKind, RequestField, UserState, funding_worker,
};
use std::collections::{BTreeMap, BTreeSet};

const ADDRESS: [u8; 20] = [17; 20];
const ONE: u64 = 0x3ff0_0000_0000_0000;
const ACTIVE_TIME: [u8; 12] = [1, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2];

fn position(tag: u32, size: i64) -> Position {
    Position {
        tag,
        local_balance: 7,
        size,
        accumulators: [0; 3],
    }
}

fn state(positions: Vec<(u64, Position)>) -> UserState {
    UserState {
        balance: 0,
        positions: positions.into_iter().collect(),
    }
}

fn calculate(
    state: &UserState,
    prices: &[i64],
    rates: &[(u64, u64)],
    time: [u8; 12],
) -> Result<Outcome, node94_funding_worker_values::Refusal> {
    funding_worker(
        &Inputs {
            address: ADDRESS,
            bypass: 255,
            members: &BTreeSet::new(),
            time,
            metadata: prices,
            rates: &BTreeMap::from_iter(rates.iter().copied()),
        },
        state,
    )
}

#[test]
fn two_roundings_match_the_frozen_discriminator() {
    // Frozen case1804: exact single-round multiplication would yield-2.
    let original = state(vec![(0, position(0, -18_014_398_509_481_986))]);
    let Outcome::Accepted {
        state,
        rows,
        summary,
        ..
    } = calculate(&original, &[1], &[(0, 0x3c9f_ffff_ffff_ffff)], ACTIVE_TIME).unwrap()
    else {
        panic!("accepted case");
    };
    assert_eq!(rows[0].payment, 1);
    assert_eq!(state.balance, 1);
    assert_eq!(state.positions[&0].accumulators, [-1; 3]);
    assert_eq!(summary.sum, 1);
    assert_eq!(original.balance, 0);
}

#[test]
fn raw_nan_and_minimum_product_are_active_values() {
    let original = state(vec![(0, position(0, i64::MIN))]);
    for rate in [1, 0x7ff0_0000_0000_0001, 0xfff8_0000_0000_0013] {
        let Outcome::Accepted {
            state,
            rows,
            summary,
            ..
        } = calculate(&original, &[1], &[(0, rate)], ACTIVE_TIME).unwrap()
        else {
            panic!("accepted case");
        };
        assert_eq!(rows[0].raw_rate, rate);
        assert_eq!(rows[0].payment, 0);
        assert_eq!(rows[0].product, i64::MIN);
        assert_eq!(summary.maximum.unwrap().magnitude, 1 << 63);
        assert_eq!(state, original);
    }
}

#[test]
fn nonfinite_products_differ_from_finite_minimum_amount() {
    let original = state(vec![(0, position(0, i64::MIN))]);
    assert_eq!(
        calculate(&original, &[1], &[(0, ONE)], [0; 12])
            .unwrap_err()
            .kind,
        RefusalKind::MinimumAmount
    );
    for rate in [0x7ff0_0000_0000_0000, 0xfff0_0000_0000_0000] {
        let Outcome::Accepted { rows, .. } =
            calculate(&original, &[1], &[(0, rate)], ACTIVE_TIME).unwrap()
        else {
            panic!("accepted infinity");
        };
        assert_eq!(rows[0].payment, 0);
    }
    let positive = state(vec![(0, position(0, i64::MAX))]);
    let Outcome::Accepted { rows, .. } =
        calculate(&positive, &[1], &[(0, 0x7fef_ffff_ffff_ffff)], ACTIVE_TIME).unwrap()
    else {
        panic!("accepted finite overflow");
    };
    assert_eq!(rows[0].payment, 0);
}

#[test]
fn guard_order_precedes_size_and_raw_time() {
    let original = state(vec![(0, position(0, 0))]);
    assert_eq!(
        calculate(&original, &[], &[(0, ONE)], [0; 12])
            .unwrap_err()
            .kind,
        RefusalKind::MetadataIndex
    );
    for rates in [&[][..], &[(0, 0)][..], &[(0, 1 << 63)][..]] {
        let Outcome::Accepted { rows, .. } = calculate(&original, &[], rates, ACTIVE_TIME).unwrap()
        else {
            panic!("skipped rate");
        };
        assert!(rows.is_empty());
    }
    assert!(calculate(&original, &[-1], &[(0, ONE)], ACTIVE_TIME).is_ok());
    let original = state(vec![(0, position(0, 2))]);
    assert_eq!(
        calculate(&original, &[i64::MAX], &[(0, ONE)], [0; 12])
            .unwrap_err()
            .kind,
        RefusalKind::ProductOverflow
    );
}

#[test]
fn exact_tag_and_ordered_saturation_requests() {
    let mut p = position(1, 3);
    p.local_balance = i64::MIN;
    p.accumulators = [i64::MAX; 3];
    let original = state(vec![(0, p)]);
    let Outcome::Accepted {
        state, requests, ..
    } = calculate(&original, &[1], &[(0, ONE)], ACTIVE_TIME).unwrap()
    else {
        panic!("accepted case");
    };
    assert_eq!(state.balance, 0);
    assert_eq!(state.positions[&0].local_balance, i64::MIN);
    assert_eq!(state.positions[&0].accumulators, [i64::MAX; 3]);
    assert_eq!(
        requests.iter().map(|r| r.field).collect::<Vec<_>>(),
        vec![
            RequestField::SelectedBalance,
            RequestField::Accumulator0,
            RequestField::Accumulator1,
            RequestField::Accumulator2,
        ]
    );
    let original = super_tag_state();
    let Outcome::Accepted { state, .. } =
        calculate(&original, &[1], &[(0, ONE)], ACTIVE_TIME).unwrap()
    else {
        panic!("accepted raw tag");
    };
    assert_eq!(state.balance, -3);
    assert_eq!(state.positions[&0].local_balance, 7);
}

fn super_tag_state() -> UserState {
    state(vec![(0, position(0x10001, 3))])
}

#[test]
fn summary_saturation_is_ordered_and_requests_follow_updates() {
    let n = 1 << 62;
    let original = state(vec![
        (0, position(0, n)),
        (1, position(0, n)),
        (2, position(0, -n)),
    ]);
    let rates = [
        (0, ONE | (1 << 63)),
        (1, ONE | (1 << 63)),
        (2, ONE | (1 << 63)),
    ];
    let Outcome::Accepted {
        summary, requests, ..
    } = calculate(&original, &[1, 1, 1], &rates, ACTIVE_TIME).unwrap()
    else {
        panic!("accepted case");
    };
    assert_eq!(summary.sum, n - 1);
    assert_eq!(summary.maximum.unwrap().asset, 0);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].field, RequestField::SelectedBalance);
    assert_eq!(requests[1].field, RequestField::Summary);
    assert_eq!(requests[0].asset, 1);
    assert_eq!(requests[1].asset, 1);
}

#[test]
fn maximum_is_product_not_size_and_full_unsigned_asset_indexes() {
    let original = state(vec![(0, position(0, 7)), (1, position(0, 5))]);
    let Outcome::Accepted { summary, .. } =
        calculate(&original, &[2, 3], &[(0, ONE), (1, ONE)], ACTIVE_TIME).unwrap()
    else {
        panic!("accepted case");
    };
    let maximum = summary.maximum.unwrap();
    assert_eq!((maximum.asset, maximum.magnitude), (1, 15));
    let original = state(vec![(u64::MAX, position(0, 7))]);
    let Outcome::Accepted { rows, .. } =
        calculate(&original, &vec![1; 10000], &[(u64::MAX, ONE)], ACTIVE_TIME).unwrap()
    else {
        panic!("accepted unsigned index");
    };
    assert_eq!(rows[0].asset, u64::MAX);
    assert_eq!(rows[0].payment, -7);
}

#[test]
fn membership_exclusion_and_zero_time_preserve_modeled_state() {
    let original = state(vec![(0, position(0, 1))]);
    assert_eq!(
        funding_worker(
            &Inputs {
                address: ADDRESS,
                bypass: 0,
                members: &BTreeSet::new(),
                time: ACTIVE_TIME,
                metadata: &[-1],
                rates: &BTreeMap::from([(0, ONE)]),
            },
            &original
        ),
        Ok(Outcome::Excluded)
    );
    let Outcome::Accepted {
        state,
        rows,
        summary,
        requests,
    } = calculate(&original, &[1], &[(0, ONE)], [0; 12]).unwrap()
    else {
        panic!("accepted zero time");
    };
    assert_eq!(state, original);
    assert!(rows.is_empty() && requests.is_empty());
    assert_eq!(summary.sum, 0);
    assert_eq!(summary.maximum, None);
}
