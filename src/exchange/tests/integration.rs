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

#[test]
fn stake_requirement_table_cooldown_and_gates_match_node115_0x2c59480() {
    use exchange::stake_requirement::{
        check_stake_requirement, compute_total_required_stake, stake_unit_amount, Chain,
        Hip3DexStakeEntry, Hip3StakeStateTag, SpotQuoteTokenStakeEntry, StakeCheckOutcome,
        StakeRequirement, UserStakeSnapshot, PRE_DEPLOY_ACCOUNT_CAP, STAKE_COOLDOWN_SECONDS,
        TAG_ACCOUNT_CAP_EXCEEDED, TAG_DISALLOWED_ACCOUNT, TAG_INSUFFICIENT_STAKE, TAG_OK,
    };

    // Exact Mainnet stake amounts from 0x602d1c -> 0x457d00 / 0x457b00 / 0x457f00.
    assert_eq!(
        stake_unit_amount(StakeRequirement::Hip3PerpDex, Chain::Mainnet),
        50_000_000_000_000
    );
    assert_eq!(
        stake_unit_amount(StakeRequirement::SpotQuoteToken, Chain::Mainnet),
        20_000_000_000_000
    );
    assert_eq!(
        stake_unit_amount(StakeRequirement::UserSetMembership, Chain::Mainnet),
        50_000_000_000_000
    );
    assert_eq!(
        stake_unit_amount(StakeRequirement::OutcomeDeployer, Chain::Mainnet),
        50_000_000_000_000
    );
    assert_eq!(STAKE_COOLDOWN_SECONDS, 183 * 86_400);

    let deployer = [0xaa; 20];
    let other = [0xbb; 20];
    let base_time = 1_700_000_000u64;

    let mut snap = UserStakeSnapshot {
        user: deployer,
        now_secs: base_time + STAKE_COOLDOWN_SECONDS,
        account_disallowed_for_deploy: false,
        account_and_sub_account_values: vec![1_000_000_000, 1_000_000_000],
        perp_dexs: vec![
            // Active HIP-3 DEX owned by deployer -> counts (1).
            Hip3DexStakeEntry {
                is_hip3: true,
                deployer,
                state_tag: Hip3StakeStateTag::Active0,
                disabled_at_secs: None,
            },
            // DisabledPendingCooldown right at exact boundary `now == disabled_at + 183d` -> still counts (1).
            Hip3DexStakeEntry {
                is_hip3: true,
                deployer,
                state_tag: Hip3StakeStateTag::DisabledPendingCooldown,
                disabled_at_secs: Some(base_time),
            },
            // Permanently Disabled -> skipped (0).
            Hip3DexStakeEntry {
                is_hip3: true,
                deployer,
                state_tag: Hip3StakeStateTag::Disabled,
                disabled_at_secs: None,
            },
            // Main DEX or other deployer -> skipped (0).
            Hip3DexStakeEntry {
                is_hip3: false,
                deployer,
                state_tag: Hip3StakeStateTag::Active0,
                disabled_at_secs: None,
            },
            Hip3DexStakeEntry {
                is_hip3: true,
                deployer: other,
                state_tag: Hip3StakeStateTag::Active0,
                disabled_at_secs: None,
            },
        ],
        spot_quote_tokens: vec![
            // Disabled past cooldown (`now > disabled_at + 183d`) -> skipped (0).
            SpotQuoteTokenStakeEntry {
                is_disabled: true,
                disabled_at_secs: Some(base_time - 1),
            },
            // Active quote token -> counts (1).
            SpotQuoteTokenStakeEntry {
                is_disabled: false,
                disabled_at_secs: None,
            },
        ],
        in_special_user_set: true,
        is_active_outcome_deployer: true,
        active_stake: Some(220_000_000_000_000),
    };

    // Required = 2 * 500k + 1 * 200k + 1 * 500k + 1 * 500k = 2_200_000 HYPE = 220_000_000_000_000 wei.
    assert_eq!(
        compute_total_required_stake(Chain::Mainnet, &snap, None, false),
        Ok(220_000_000_000_000)
    );
    // With `is_override = true` (unstake check 0x2bebe20), DisabledPendingCooldown drops out -> 1_700_000 HYPE.
    assert_eq!(
        compute_total_required_stake(Chain::Mainnet, &snap, None, true),
        Ok(170_000_000_000_000)
    );

    // Exact match passes with tag 0x1a2.
    assert_eq!(
        check_stake_requirement(Chain::Mainnet, &snap, None),
        StakeCheckOutcome::Ok {
            tag: TAG_OK,
            total_required: 220_000_000_000_000,
        }
    );

    // Adding one more SpotQuoteToken (+200k HYPE) fails with 0x11a (InsufficientStake).
    assert_eq!(
        check_stake_requirement(Chain::Mainnet, &snap, Some(StakeRequirement::SpotQuoteToken)),
        StakeCheckOutcome::Rejected {
            tag: TAG_INSUFFICIENT_STAKE,
            total_required: Some(240_000_000_000_000),
        }
    );

    // Account cap exceeded (> 0x77359400 = 2_000_000_000) fails with 0x119 when additional is Some.
    snap.account_and_sub_account_values = vec![PRE_DEPLOY_ACCOUNT_CAP, 1];
    assert_eq!(
        check_stake_requirement(Chain::Mainnet, &snap, Some(StakeRequirement::Hip3PerpDex)),
        StakeCheckOutcome::Rejected {
            tag: TAG_ACCOUNT_CAP_EXCEEDED,
            total_required: None,
        }
    );

    // Disallowed account flag fails first with 0x118.
    snap.account_disallowed_for_deploy = true;
    assert_eq!(
        check_stake_requirement(Chain::Mainnet, &snap, Some(StakeRequirement::Hip3PerpDex)),
        StakeCheckOutcome::Rejected {
            tag: TAG_DISALLOWED_ACCOUNT,
            total_required: None,
        }
    );
}

#[test]
fn bole_liquidation_0x2c80670_and_begin_block_7_phase_schedule_match_node115() {
    use exchange::bole_liquidation::{
        build_bole_liquidation_spot_order, compute_bole_liquidation_limit_px, BeginBlockPhase,
        SpotPairMeta, BOLE_LIQUIDATOR_ADDRESS,
    };

    // Exact 7-phase begin_block schedule order & bucket-guard constants from 0x2bdf8f0.
    let names: Vec<&str> = BeginBlockPhase::SCHEDULE_ORDER
        .iter()
        .map(|p| p.name())
        .collect();
    assert_eq!(
        names,
        vec![
            "distribute_funding",
            "update_funding_rates",
            "cancel_aggressive_orders_at_oi_cap",
            "prune_book_empty_user_states",
            "refresh_main_perp_dex_stale_oracle",
            "refresh_hip3_stale_mark_pxs",
            "apply_bole_liquidations",
        ]
    );
    assert_eq!(BeginBlockPhase::DistributeFunding.bucket_guard(), (0.35, 0.05));
    assert_eq!(BeginBlockPhase::PruneBookEmptyUserStates.bucket_guard(), (0.05, 0.05));
    assert_eq!(BeginBlockPhase::ApplyBoleLiquidations.bucket_guard(), (0.01, 0.05));
    assert_eq!(BOLE_LIQUIDATOR_ADDRESS, [0xbb; 20]);

    let spots = [
        SpotPairMeta {
            spot_id: 7,
            base_token: 3,
            quote_token: 1, // non-USDC quote skipped
        },
        SpotPairMeta {
            spot_id: 12,
            base_token: 3,
            quote_token: 0, // USDC quote selected
        },
    ];
    let user = [0x44; 20];
    let mut next_oid = 500u64;

    // Token 0 (USDC) rejected.
    assert_eq!(
        build_bole_liquidation_spot_order(0, 100, 0.95, user, &spots, Some(10_000), &mut next_oid),
        None
    );
    assert_eq!(next_oid, 500);

    // Token 3 picks spot_id 12 (quote=0), rounds limit_px, increments oid, uses 0xbb*20 liquidator & IOC tif=1.
    let order = build_bole_liquidation_spot_order(
        3,
        250,
        0.95,
        user,
        &spots,
        Some(1_001),
        &mut next_oid,
    )
    .unwrap();
    assert_eq!(order.oid, 500);
    assert_eq!(next_oid, 501);
    assert_eq!(order.spot_id, 12);
    assert_eq!(order.liquidator, BOLE_LIQUIDATOR_ADDRESS);
    assert_eq!(order.liquidated_user, user);
    assert_eq!(order.limit_px, 951); // round(1001 * 0.95) = round(950.95) = 951
    assert_eq!(order.tif, 1);

    // Zero or negative rounded price floors to 1 (`cmpq $1, %r8; adcq $0, %r8`).
    assert_eq!(compute_bole_liquidation_limit_px(10, 0.0), 1);
    assert_eq!(compute_bole_liquidation_limit_px(10, -0.5), 1);
}
