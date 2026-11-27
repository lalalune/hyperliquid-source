use std::collections::BTreeSet;

use l1_shared::{
    agent_erase::{erase, Agent, Moment, State as AgentState},
    decimal_scaler::{
        decimal_from_f64, scale_decimal_to_u64, scale_nonzero_w2, scale_perp_w4, scale_spot_w3,
        scale_usdc_w1, Decimal96, ScalerMode, TAG_F64_PARSE_REFUSED, TAG_SCALER_REFUSED,
        TAG_WRAPPER_REFUSED,
    },
    hyperliquidity::{
        funding_cost, generate_ladder, market_cap_in_band, price_tick, validate_hyperliquidity_seed,
        SeedCheckInput, SPECIAL_TOKEN_TICK,
    },
    nonce_set::{
        clock_to_unix_millis, has_expanded_window, NonceReject, NonceRing, DEFAULT_WINDOW,
        EXPANDED_WINDOW, EXPANDED_WINDOW_ADDRESSES, TAG_NONCE_DUPLICATE, TAG_NONCE_TOO_HIGH,
        TAG_NONCE_TOO_LOW, TAG_TOO_MANY_PENDING,
    },
};

#[test]
fn decimal_scaler_modes_and_wrappers_match_node115_rules() {
    // 1.234567 with 6 digits exact -> 1_234_567.
    let d = Decimal96::new(false, 6, 1_234_567).unwrap();
    let out = scale_decimal_to_u64(d, ScalerMode::Exact, 6).unwrap();
    assert_eq!(out.value, 1_234_567);
    assert!(!out.touched_lazy_global);

    // Tolerant mode (1): 1.0009 -> diff 0.0009 < 0.001 rounds to 1 and touches lazy global.
    let tol_ok = Decimal96::new(false, 4, 10_009).unwrap();
    let out_tol = scale_decimal_to_u64(tol_ok, ScalerMode::Tolerant, 0).unwrap();
    assert_eq!(out_tol.value, 1);
    assert!(out_tol.touched_lazy_global);

    // Tolerant mode (1): 1.001 -> diff == 0.001 is NOT strictly below -> refused (0xac).
    let tol_edge = Decimal96::new(false, 3, 1_001).unwrap();
    assert_eq!(
        scale_decimal_to_u64(tol_edge, ScalerMode::Tolerant, 0),
        Err(TAG_SCALER_REFUSED)
    );

    // RoundHalfEven (mode 2): ties to even (2.5 -> 2, 3.5 -> 4).
    let tie2 = Decimal96::new(false, 1, 25).unwrap();
    let tie3 = Decimal96::new(false, 1, 35).unwrap();
    assert_eq!(
        scale_decimal_to_u64(tie2, ScalerMode::RoundHalfEven, 0)
            .unwrap()
            .value,
        2
    );
    assert_eq!(
        scale_decimal_to_u64(tie3, ScalerMode::RoundHalfEven, 0)
            .unwrap()
            .value,
        4
    );

    // Negative that rounds to 0 succeeds with 0 in w1, folded to 0xad in w2.
    let neg_tiny = Decimal96::new(true, 7, 1).unwrap();
    assert_eq!(scale_usdc_w1(neg_tiny), Ok(0));
    assert_eq!(scale_nonzero_w2(neg_tiny, 6), Err(TAG_WRAPPER_REFUSED));

    // w4 (6 - sz_decimals) and w3 (quote_wei - base_sz) borrow checks.
    let d1 = Decimal96::new(false, 0, 10).unwrap();
    assert_eq!(scale_perp_w4(d1, 2), Some(Ok(100_000)));
    assert_eq!(scale_perp_w4(d1, 7), None);
    assert_eq!(scale_spot_w3(d1, 2, 8), Some(Ok(10_000_000)));
    assert_eq!(scale_spot_w3(d1, 9, 8), None);
}

#[test]
fn f64_to_decimal_matches_0x5c43c60_and_0x43099f0() {
    let d = decimal_from_f64(0.1).unwrap();
    assert!(!d.negative);
    assert_eq!(d.scale, 1);
    assert_eq!(d.mantissa, 1);

    let neg = decimal_from_f64(-12.5).unwrap();
    assert!(neg.negative);
    assert_eq!(neg.scale, 1);
    assert_eq!(neg.mantissa, 125);

    assert_eq!(decimal_from_f64(f64::NAN), Err(TAG_F64_PARSE_REFUSED));
    assert_eq!(decimal_from_f64(f64::INFINITY), Err(TAG_F64_PARSE_REFUSED));
}

#[test]
fn nonce_ring_enforces_precedence_bounds_pending_eviction_and_19_expanded_addresses() {
    // Unix epoch 1970-01-01 00:00:00 -> 0 ms.
    assert_eq!(clock_to_unix_millis(1970, 1, 0, 0), 0);
    // 2026-01-01 00:00:00.500 -> exact Unix ms.
    let now = clock_to_unix_millis(2026, 1, 0, 500_000_000);
    assert_eq!(now, 1_767_225_600_500);

    let regular = [0xaa; 20];
    let special = EXPANDED_WINDOW_ADDRESSES[0];
    assert!(!has_expanded_window(&regular));
    assert!(has_expanded_window(&special));

    let mut ring = NonceRing::new();
    // Fill to DEFAULT_WINDOW (100).
    for i in 0..DEFAULT_WINDOW as u64 {
        ring.admit(&regular, now - 10_000 + i, now, None).unwrap();
    }
    assert_eq!(ring.len(), DEFAULT_WINDOW);

    // Below ring floor -> 0xcb.
    let err_floor = ring.admit(&regular, now - 10_001, now, None).unwrap_err();
    assert_eq!(err_floor.tag(), TAG_NONCE_TOO_LOW);

    // Above upper bound (+86,400,000) -> 0xcc.
    let err_hi = ring
        .admit(&regular, now + 86_400_001, now, None)
        .unwrap_err();
    assert_eq!(err_hi.tag(), TAG_NONCE_TOO_HIGH);

    // Duplicate -> 0xcd.
    let err_dup = ring.admit(&regular, now - 10_000, now, None).unwrap_err();
    assert_eq!(err_dup.tag(), TAG_NONCE_DUPLICATE);

    // Pending eviction blocks dropping oldest nonce -> 0x61.
    let pending = BTreeSet::from([now - 10_000]);
    let err_pend = ring.admit(&regular, now, now, Some(&pending)).unwrap_err();
    assert_eq!(err_pend, NonceReject::TooManyPendingNonces);
    assert_eq!(err_pend.tag(), TAG_TOO_MANY_PENDING);

    // Same ring with one of the 19 special addresses gets 400 window, so no eviction occurs!
    ring.admit(&special, now, now, Some(&pending)).unwrap();
    assert_eq!(ring.len(), DEFAULT_WINDOW + 1);
    assert!(ring.len() < EXPANDED_WINDOW);
}

#[test]
fn hyperliquidity_tick_ladder_cost_and_seed_validation() {
    assert_eq!(price_tick(50_000, 8, false), 1);
    assert_eq!(price_tick(100_000, 8, false), 10);
    assert_eq!(price_tick(1_000_000, 1, false), 10); // clamped to 10^1
    assert_eq!(price_tick(50_000, 8, true), SPECIAL_TOKEN_TICK);

    let ladder = generate_ladder(100_000, 12, 6, false);
    assert_eq!(ladder.len(), 12);
    assert_eq!(ladder[0], 100_000);
    assert!(ladder[11] > ladder[0]);

    assert_eq!(funding_cost(&ladder, 2, 10), Ok((ladder[0] + ladder[1]) * 10));
    assert!(market_cap_in_band(10_000_000_000 * 100_000_000, 1_000_000_000, 100_000_000_000));

    // Full seed validation passes for HYPE-exempt valid config and rejects bad levels/balance.
    let mut input = SeedCheckInput {
        start_price: 100_000,
        order_size: 100,
        levels: 20,
        seeded_levels: 5,
        funding_cap: 1_000_000_000,
        already_exists: false,
        held_balance: 1,
        has_token_hold: false,
        quote_is_usdc: true,
        has_max_supply: true,
        available_token_balance: Some(100 * 15),
        decimals_diff: 6,
        is_special_token: false,
        token_name: "HYPE",
    };
    let ok = validate_hyperliquidity_seed(&input, |_| Some(0)).unwrap();
    assert_eq!(ok.levels.len(), 20);
    assert!(ok.cost > 0);

    input.levels = 4_001;
    assert_eq!(
        validate_hyperliquidity_seed(&input, |_| Some(0)),
        Err("too many Hyperliquidity orders")
    );
}

#[test]
fn agent_erase_state_reexport_works_cleanly() {
    let mut st = AgentState::default();
    let owner = [1; 20];
    let agent = [2; 20];
    let now = Moment::new(739_000, 100, 0).unwrap();
    st.agents.insert(
        owner,
        vec![Agent {
            name: "bot".to_string(),
            opaque: [0; 12],
            address: agent,
        }],
    );
    assert_eq!(erase(&mut st, owner, "bot", now), 0x1a2);
    assert!(st.agents[&owner].is_empty());
    assert_eq!(st.followups[&owner].len(), 1);
}
