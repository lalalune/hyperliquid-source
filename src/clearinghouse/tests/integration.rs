use clearinghouse::{
    borrow_lend_codec::Operation as BoleOp,
    margin_mode_codec::MarginMode,
    oracle_outcome_kind::OracleOutcomeKind,
    position_risk::{
        asset_decimal_scale, check_isolated_position, compute_position_ratio, evaluate_margin_test,
        fold_account_positions, IsolatedCheckOutcome, MarginTestInput, MarginTestOutcome,
        PositionRiskError, PositionRiskRecord, RATIO_FLOOR, TAG_INVALID_FRACTION, TAG_OK,
        TAG_UNSUPPORTED_ASSET_MODE,
    },
};

#[test]
fn position_fold_0x3bebd70_handles_cross_isolated_and_bounds() {
    let oracle_rows = [100_000, 2_000];
    let positions = [
        // Cross position (tag=0): product = 100_000 * 10 = 1_000_000, divisor = 10 -> quot = 100_000.
        // acc: 0 + 1_000_000 - 100_000 = 900_000.
        (
            0,
            PositionRiskRecord {
                tag: 0,
                divisor: 10,
                stored_balance: 0,
                signed_size: 10,
                entry_ntl: 0,
            },
        ),
        // Isolated position (tag=1): product = 2_000 * (-50) = -100_000, stored = 50_000 -> extra = -50_000.
        // divisor = 5 -> quot = 20_000. extra (-50_000) < quot (20_000) -> acc += -50_000 - 20_000 = 830_000.
        (
            10_001,
            PositionRiskRecord {
                tag: 1,
                divisor: 5,
                stored_balance: 50_000,
                signed_size: -50,
                entry_ntl: 0,
            },
        ),
    ];
    let res = fold_account_positions(0, &positions, &oracle_rows).unwrap();
    assert_eq!(res.raw_accumulator, 830_000);
    assert_eq!(res.required_equity, 0);

    // Negative accumulator yields positive required_equity = -acc.
    let deficit = fold_account_positions(-1_000_000, &positions, &oracle_rows).unwrap();
    assert_eq!(deficit.raw_accumulator, -170_000);
    assert_eq!(deficit.required_equity, 170_000);

    // Zero divisor rejected.
    let zero_div = [(
        0,
        PositionRiskRecord {
            tag: 0,
            divisor: 0,
            stored_balance: 0,
            signed_size: 1,
            entry_ntl: 0,
        },
    )];
    assert_eq!(
        fold_account_positions(0, &zero_div, &oracle_rows),
        Err(PositionRiskError::ZeroDivisor)
    );
}

#[test]
fn isolated_check_0x447e810_enforces_fraction_mode_and_shortfall_emit() {
    let modes = [1, 2];
    let oracles = [100, 1_000];
    let rec = PositionRiskRecord {
        tag: 1,
        divisor: 10,
        stored_balance: 500,
        signed_size: 10,
        entry_ntl: 0,
    };

    // Fraction outside [0.5, 1.0] -> 0x46.
    assert_eq!(
        check_isolated_position(0, 1, 0.49, &modes, &oracles, Some(rec)).unwrap(),
        IsolatedCheckOutcome::Status(TAG_INVALID_FRACTION)
    );
    // Asset mode != 2 -> 0x14e.
    assert_eq!(
        check_isolated_position(0, 0, 0.5, &modes, &oracles, Some(rec)).unwrap(),
        IsolatedCheckOutcome::Status(TAG_UNSUPPORTED_ASSET_MODE)
    );
    // Shortfall: product = 10_000, total = 10_500; scaled = 10_000 / 0.5 = 20_000 -> diff = 9_500 > 0.
    assert_eq!(
        check_isolated_position(0, 1, 0.5, &modes, &oracles, Some(rec)).unwrap(),
        IsolatedCheckOutcome::EmitRequired { diff: 9_500 }
    );
    // No shortfall at fraction 1.0 (10_000 - 10_500 = -500 <= 0) -> Ok(0x1a2).
    assert_eq!(
        check_isolated_position(0, 1, 1.0, &modes, &oracles, Some(rec)).unwrap(),
        IsolatedCheckOutcome::Status(TAG_OK)
    );
}

#[test]
fn position_ratio_0x446b840_and_margin_test_0x469b990_match_rules() {
    let oracles = [1_000];
    // Long position: signed_size = 100 > 0, is_long = true.
    let long_pos = PositionRiskRecord {
        tag: 0,
        divisor: 10,
        stored_balance: 0,
        signed_size: 100,
        entry_ntl: 50_000,
    };
    // product = 100_000, cross_figure = 200_000 -> ratio1 = 0.5.
    // diff = 100_000 - 50_000 = 50_000 -> ratio2 = 50_000 / 50_000 = 1.0.
    let r = compute_position_ratio(0, true, Some(long_pos), &oracles, 200_000)
        .unwrap()
        .unwrap();
    assert!((r - 0.5).abs() < 1e-12);

    // Opposite side test returns None.
    assert_eq!(
        compute_position_ratio(0, false, Some(long_pos), &oracles, 200_000).unwrap(),
        None
    );

    // Zero cross figure falls back to RATIO_FLOOR = 1e-8.
    let r_floor = compute_position_ratio(0, true, Some(long_pos), &oracles, 0)
        .unwrap()
        .unwrap();
    assert_eq!(r_floor, RATIO_FLOOR * 1.0);

    // Margin test 0x469b990 passes at -100 floor and fails at -101.
    let mut m = MarginTestInput {
        route_a: 100,
        route_b: 50,
        account_acc: 200,
        eval_tag: 1,
        extra: 0,
        unit: 1,
        delta: 0,
        third: -100,
        second: 0,
    };
    assert_eq!(evaluate_margin_test(m), Some(MarginTestOutcome::Pass));
    m.third = -101;
    assert_eq!(evaluate_margin_test(m), Some(MarginTestOutcome::Fail));

    // Asset decimal scale.
    assert_eq!(asset_decimal_scale(8, 2), Some(1_000_000));
    assert_eq!(asset_decimal_scale(2, 8), None);
    assert_eq!(asset_decimal_scale(25, 0), None);
}

#[test]
fn clearinghouse_micro_crates_compose_cleanly() {
    assert_eq!(MarginMode::from_name("strictIsolated"), Some(MarginMode::StrictIsolated));
    assert_eq!(BoleOp::from_name("supply"), Some(BoleOp::Supply));
    assert_eq!(
        OracleOutcomeKind::from_name("Question"),
        Ok(OracleOutcomeKind::Question)
    );
}
