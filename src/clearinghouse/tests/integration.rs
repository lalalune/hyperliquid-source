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

#[test]
fn margin_table_maintenance_and_backstop_match_node115_0x38b54b0_and_0x38b5300() {
    use clearinghouse::margin_user_state::{
        MarginTable, MarginTableStore, MarginTier, MarginStateError, BUILTIN_MARGIN_TABLE_ID_LIMIT,
    };

    // Tiered table: [0, 1_000_000) @ 50x ded=0; [1_000_000, inf) @ 20x ded=15_000.
    // Note continuity at 1_000_000: 1_000_000 / 100 = 10_000 == 1_000_000 / 40 - 15_000.
    let tiered = MarginTable::from_tiers([
        MarginTier {
            lower_bound: 0,
            max_leverage: 50,
            maintenance_deduction: 0,
        },
        MarginTier {
            lower_bound: 1_000_000,
            max_leverage: 20,
            maintenance_deduction: 15_000,
        },
    ])
    .unwrap();

    assert_eq!(tiered.first_tier().unwrap().max_leverage, 50);

    // Lower tier: ntl = 500_000 -> maint = 500_000 / 100 = 5_000;
    // backstop = (1_000_000 - 0) / 300 = 3_333 (= floor(2/3 * 5_000)).
    assert_eq!(tiered.maintenance_margin(500_000).unwrap(), (5_000, false));
    assert_eq!(tiered.backstop_margin(500_000).unwrap(), (3_333, false));

    // Upper tier: ntl = 2_000_000 -> maint = 2_000_000 / 40 - 15_000 = 35_000;
    // backstop = (4_000_000 - 4*20*15_000) / (6*20) = 2_800_000 / 120 = 23_333.
    assert_eq!(tiered.maintenance_margin(2_000_000).unwrap(), (35_000, false));
    assert_eq!(tiered.backstop_margin(2_000_000).unwrap(), (23_333, false));

    // Underflow saturation (deduction exceeds raw margin -> 0 with saturated=true).
    let huge_ded = MarginTable::from_tiers([MarginTier {
        lower_bound: 0,
        max_leverage: 10,
        maintenance_deduction: 1_000_000,
    }])
    .unwrap();
    assert_eq!(huge_ded.maintenance_margin(100).unwrap(), (0, true));
    assert_eq!(huge_ded.backstop_margin(100).unwrap(), (0, true));

    // Built-in (< 50) vs custom (>= 50) store resolution (0x3c43150).
    let mut store = MarginTableStore::new();
    store.insert_custom(BUILTIN_MARGIN_TABLE_ID_LIMIT, tiered.clone());
    assert_eq!(store.resolve(20).unwrap().first_tier().unwrap().max_leverage, 20);
    assert_eq!(store.resolve(50).unwrap(), tiered);
    assert_eq!(store.resolve(51), Err(MarginStateError::UnknownMarginTableId(51)));
    assert_eq!(store.resolve(0), Err(MarginStateError::ZeroLeverage));
}

#[test]
fn position_margin_summary_0x448b800_and_available_margin_0x3beb700_match_rules() {
    use clearinghouse::margin_user_state::{
        available_margin_cross, available_margin_isolated, position_margin_summary,
        MarginRequirement, MarginStateError, MarginTableStore, PositionMarginInput,
        PositionMarginSummary, HIP3_PERP_ASSET_STRIDE,
    };

    let store = MarginTableStore::new();
    let pos = PositionMarginInput {
        is_isolated: true,
        leverage: 20,
        raw_usd: 50_000,
        szi: 100,
        margin_table_id: 20,
    };

    // Mark px = 1_000 -> ntli = 100_000, ntl = 100_000.
    // Initial (arm 1): 100_000 / 20 = 5_000; account_value = 150_000.
    assert_eq!(
        position_margin_summary(&pos, 1_000, MarginRequirement::Initial, 10, &store).unwrap(),
        PositionMarginSummary::Isolated {
            account_value: 150_000,
            margin_used: 150_000,
            ntl: 100_000,
            raw_usd: 50_000,
            margin_required: 5_000,
            saturated_account_value: false,
        }
    );
    // InitialCapped (arm 4): min(20, 10) = 10 -> margin_required = 10_000.
    assert_eq!(
        position_margin_summary(&pos, 1_000, MarginRequirement::InitialCapped, 10, &store).unwrap(),
        PositionMarginSummary::Isolated {
            account_value: 150_000,
            margin_used: 150_000,
            ntl: 100_000,
            raw_usd: 50_000,
            margin_required: 10_000,
            saturated_account_value: false,
        }
    );
    // Maintenance (arm 2, id=20): 100_000 / 40 = 2_500.
    // Backstop (arm 3, id=20): 200_000 / 120 = 1_666.
    // Zero (arm 0): 0.
    assert_eq!(
        available_margin_isolated(
            HIP3_PERP_ASSET_STRIDE + 1,
            Some(&pos),
            &[500, 1_000],
            MarginRequirement::Maintenance,
            10,
            &store
        )
        .unwrap(),
        (147_500, false)
    );
    assert_eq!(
        available_margin_isolated(
            HIP3_PERP_ASSET_STRIDE + 1,
            Some(&pos),
            &[500, 1_000],
            MarginRequirement::Backstop,
            10,
            &store
        )
        .unwrap(),
        (148_334, false)
    );
    assert_eq!(
        available_margin_isolated(
            0,
            Some(&pos),
            &[1_000],
            MarginRequirement::Zero,
            10,
            &store
        )
        .unwrap(),
        (150_000, false)
    );

    // Cross saturating subtraction and negative margin_used guard.
    assert_eq!(available_margin_cross(i64::MIN, 5).unwrap(), (i64::MIN, true));
    assert_eq!(
        available_margin_cross(100, -1),
        Err(MarginStateError::NegativeMarginUsed(-1))
    );
    // Negative mark price rejected (position.rs:204:57).
    assert_eq!(
        position_margin_summary(&pos, -1, MarginRequirement::Initial, 10, &store),
        Err(MarginStateError::InvalidMarkOrNotionalOverflow)
    );
}

#[test]
fn spot_existing_token_balances_0x3d5e540_enforces_ratio_filter_and_overflow() {
    use clearinghouse::margin_user_state::{
        compute_existing_token_balances, ExistingTokenBalanceError, TokenBalanceAllocation,
        TAG_EXISTING_TOKEN_BALANCE_OVERFLOW,
    };

    let u1 = [0x11; 20];
    let u2 = [0x22; 20];
    let mut total = 0u64;
    let res = compute_existing_token_balances(
        &[(u1, 750), (u2, 250)],
        1_000,
        10_000,
        3_000,
        &mut total,
    )
    .unwrap();
    // u1 gets 7_500 (>= 3_000), u2 gets 2_500 (< 3_000 filtered out).
    assert_eq!(res, vec![TokenBalanceAllocation { user: u1, wei: 7_500 }]);
    assert_eq!(total, 7_500);

    // Ratio > 1.01 rejected (0x4590b8).
    let mut t2 = 0u64;
    assert!(matches!(
        compute_existing_token_balances(&[(u1, 1_020)], 1_000, 10_000, 0, &mut t2),
        Err(ExistingTokenBalanceError::RatioOutOfBounds { .. })
    ));

    // Ratio == 1.01 passes.
    let mut t3 = 0u64;
    let ok = compute_existing_token_balances(&[(u1, 1_010)], 1_000, 10_000, 0, &mut t3).unwrap();
    assert_eq!(ok[0].wei, 10_100);

    // u64 total_wei overflow produces tag 0x109 + exact #115 error template.
    let mut near_max = u64::MAX - 5;
    let err = compute_existing_token_balances(&[(u1, 1_000)], 1_000, 100, 0, &mut near_max)
        .unwrap_err();
    match err {
        ExistingTokenBalanceError::TotalWeiOverflow {
            tag,
            total_wei,
            marginal_wei,
            message,
        } => {
            assert_eq!(tag, TAG_EXISTING_TOKEN_BALANCE_OVERFLOW);
            assert_eq!(total_wei, u64::MAX - 5);
            assert_eq!(marginal_wei, 100);
            assert!(message.starts_with(
                "error while computing existing token balances total_wei="
            ));
        }
        other => panic!("expected TotalWeiOverflow, got {other:?}"),
    }
}

#[test]
fn reference_oracle_0x366f900_and_oracle_kind_0x3db4e40_match_rules() {
    use clearinghouse::reference_oracle::{
        evaluate_reference_oracle, reference_price_deviation, OracleKind, ReferenceOracleEval,
        ReferenceOraclePolicy, ReferenceOracleTracker,
    };

    assert_eq!(OracleKind::ALL.len(), 3);
    assert!((reference_price_deviation(100, 105).unwrap() - 0.05).abs() < 1e-12);
    assert_eq!(reference_price_deviation(0, 100), None);

    let mut tracker = ReferenceOracleTracker::new(60.0);
    let policy = ReferenceOraclePolicy::Active {
        max_diff: 0.02,
        alert_enabled: true,
    };

    // Deviation 5% > 2% at t=100s -> flagged, within 60s grace window (no alert yet).
    assert_eq!(
        evaluate_reference_oracle(policy, Some(100), Some(105), 100_000_000_000, &mut tracker),
        ReferenceOracleEval {
            flagged: true,
            alert_fired: false,
            tracker_cleared: false,
        }
    );
    // Still violating at t=161s (elapsed 61s > 60s) -> alert fires!
    assert_eq!(
        evaluate_reference_oracle(policy, Some(100), Some(105), 161_000_000_000, &mut tracker),
        ReferenceOracleEval {
            flagged: true,
            alert_fired: true,
            tracker_cleared: false,
        }
    );
    // Back within tolerance (1% < 2%) -> tracker cleared.
    assert_eq!(
        evaluate_reference_oracle(policy, Some(100), Some(101), 162_000_000_000, &mut tracker),
        ReferenceOracleEval {
            flagged: false,
            alert_fired: false,
            tracker_cleared: true,
        }
    );
    assert_eq!(tracker.first_violation_ns, None);

    // Disabled policy exits immediately without touching tracker.
    assert_eq!(
        evaluate_reference_oracle(
            ReferenceOraclePolicy::Disabled,
            None,
            None,
            200_000_000_000,
            &mut tracker
        ),
        ReferenceOracleEval {
            flagged: false,
            alert_fired: false,
            tracker_cleared: false,
        }
    );
}
