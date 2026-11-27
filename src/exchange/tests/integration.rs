use exchange::{
    action_dispatch::display_name_state::{set_name, Status as DisplayStatus},
    dex_registry::{registry::Pdi, schema::DexMetadata},
    orchestrator::{Exchange, PerpDexClearinghouse},
    spot_deploy::{
        ceil_div_100, evaluate_spot_deploy_charge, scale_deploy_rate, SpotDeployChargeOutcome,
        SpotDeployLedgerRow, ERR_TEXT_PERP_TO_SPOT, RATE_SCALER_PASSTHROUGH,
        SPOT_DEPLOY_COUNTER_LIMIT, TAG_REFUSAL_TEXT,
    },
    token_scaling::{
        scaled_mul_div, scaled_percent_div, signed_exponent_scale_u256, ScalingError,
        TokenDecimals, PERCENT_DIV_BOUND, SIGNED_SCALER_BOUND, U256,
    },
};

#[test]
fn token_decimal_scaling_matches_0x434f660_0x434f790_0x434f910() {
    let tokens = [
        TokenDecimals {
            sz_decimals: 2,
            wei_decimals: 8,
        },
        TokenDecimals {
            sz_decimals: 0,
            wei_decimals: 6,
        },
    ];

    // 0x434f660: token 0 skips lookup entirely (works even on empty slice!).
    assert_eq!(scaled_mul_div(123, 0, 456, &[]), Ok(Some(123 * 456)));
    // Token 1 divides by 10^6.
    assert_eq!(
        scaled_mul_div(5_000_000, 1, 3, &tokens),
        Ok(Some(15))
    );
    // Overflow fallback: (a / scale) * b when a * b overflows u64.
    let big = u64::MAX / 2;
    assert_eq!(
        scaled_mul_div(big, 1, 4, &tokens),
        Ok(Some((big / 1_000_000) * 4))
    );

    // 0x434f790: DOES bounds-check token 0, divides by scale * 100, optional round-up.
    assert_eq!(
        scaled_percent_div(100, 0, 1, false, &[]),
        Err(ScalingError::TokenIndexOutOfBounds { index: 0, len: 0 })
    );
    assert_eq!(
        scaled_percent_div(100_000_001, 1, 1, false, &tokens),
        Ok(Some(1))
    );
    assert_eq!(
        scaled_percent_div(100_000_001, 1, 1, true, &tokens),
        Ok(Some(2))
    );
    const { assert!(PERCENT_DIV_BOUND == u64::MAX / 100) };

    // 0x434f910: positive exp divides in-place even on bound refusal; negative exp multiplies.
    let mut v = U256([5_000, 0, 0, 0]);
    assert_eq!(signed_exponent_scale_u256(2, &mut v), Some(50));
    assert_eq!(v.0[0], 50);

    let mut v2 = U256([50, 0, 0, 0]);
    assert_eq!(signed_exponent_scale_u256(-2, &mut v2), Some(5_000));
    assert_eq!(v2.0[0], 5_000);

    // Bound refusal (>= 2^63 / 10) still updates in place on divide path.
    let mut huge = U256([SIGNED_SCALER_BOUND, 0, 0, 0]);
    assert_eq!(signed_exponent_scale_u256(0, &mut huge), None);
    assert_eq!(huge.0[0], SIGNED_SCALER_BOUND);

    // Exponent magnitude >= 20 refused.
    assert_eq!(signed_exponent_scale_u256(20, &mut huge), None);
    assert_eq!(signed_exponent_scale_u256(-128, &mut huge), None);
}

#[test]
fn spot_deploy_charge_and_rate_scaler_match_0x2c57090_and_0x44811d0() {
    assert_eq!(ceil_div_100(0), 0);
    assert_eq!(ceil_div_100(1), 1);
    assert_eq!(ceil_div_100(100), 1);
    assert_eq!(ceil_div_100(101), 2);

    // Passthrough above RATE_SCALER_PASSTHROUGH.
    assert_eq!(
        scale_deploy_rate(RATE_SCALER_PASSTHROUGH + 1, 0.5),
        Some(RATE_SCALER_PASSTHROUGH + 1)
    );
    // Negative rate scales and negates to positive charge.
    assert_eq!(scale_deploy_rate(1_000, -0.25), Some(250));

    // Counter above limit refuses with exact 35-byte text.
    let mut row = SpotDeployLedgerRow::default();
    assert_eq!(
        evaluate_spot_deploy_charge(SPOT_DEPLOY_COUNTER_LIMIT + 1, 500, &mut row),
        SpotDeployChargeOutcome::Refused {
            tag: TAG_REFUSAL_TEXT,
            message: ERR_TEXT_PERP_TO_SPOT,
        }
    );
    assert!(!row.marked);

    // Zero fee marks ledger and skips debits.
    assert_eq!(
        evaluate_spot_deploy_charge(SPOT_DEPLOY_COUNTER_LIMIT, 0, &mut row),
        SpotDeployChargeOutcome::ZeroChargeNoDebit
    );
    assert!(row.marked);
    assert_eq!(row.charge, 0);

    // Non-zero fee charges ceil(fee/100) and keeps previously marked row unchanged.
    assert_eq!(
        evaluate_spot_deploy_charge(10, 250, &mut row),
        SpotDeployChargeOutcome::Charged {
            charge: 3,
            event_amount_usd: -3.0 / 1_000_000.0,
        }
    );
    assert_eq!(row.charge, 0);
}

#[test]
fn exchange_orchestrator_runs_block_nonce_dispatch_and_funding_lifecycle() {
    let mut ex = Exchange::new();
    let main_meta = DexMetadata::Main {
        asset_to_recent_oi: vec![0x80],
        override_max_oi_per_second: vec![0xc0],
        reset_recent_oi_bucket_guard: vec![0xc0],
        assets_at_open_interest_cap: vec![0x90],
    };
    let mut ch = PerpDexClearinghouse::default();
    ch.funding_samples.insert(0, vec![0.0002, 0.0004]);
    let pdi = ex.dex_registry.register_main(main_meta, ch).unwrap();
    assert_eq!(pdi, Pdi::MAIN);

    let now_ms = 1_767_225_600_000u64;
    ex.begin_block(1, now_ms);

    let trader = [0x42; 20];
    ex.admit_nonce(&trader, now_ms).unwrap();

    // Dispatch SetDisplayName (tag 0x99, index 19) through central 92-arm router.
    let (arm, status) = ex
        .dispatch_tag(0x99, |ex, _| {
            set_name(&mut ex.display_names, trader, "HyperTrader".to_string())
        })
        .unwrap();
    assert_eq!(arm.variant().wire_name, "setDisplayName");
    assert_eq!(status, DisplayStatus::Accepted);
    assert_eq!(
        ex.display_names.get(&trader).map(String::as_str),
        Some("HyperTrader")
    );

    // End block settles funding rates and clears sample buffers.
    let summary = ex.end_block(true);
    assert_eq!(summary.height, 1);
    assert_eq!(summary.updated_funding_rates, 1);
    let slot = ex.dex_registry.get(Pdi::MAIN).unwrap();
    assert!(slot.clearinghouse.funding_samples.is_empty());
    assert!(slot.clearinghouse.last_funding_rates.contains_key(&0));
}
