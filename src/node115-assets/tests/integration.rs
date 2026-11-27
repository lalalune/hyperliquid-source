use node115_assets::meta::{
    MetaError, PerpAssetMeta, PerpMeta, SpotMeta, SpotPairMeta, SpotTokenMeta,
};
use node115_assets::pdi::{PDI_STRIDE, Pdi, PerpAsset, Side, SpotAsset, Token};
use node115_assets::qtys::{
    MAX_PERP_SZ_DECIMALS, Ntl, Ntli, OverflowKind, POW10_F64, Px, RecordingOverflowSink, Sz, Szi,
    Usdc, Wei,
};
use node115_assets::wire_qty::{format_wire_decimal, normalize_decimal96_parts};
use node115_assets::{
    decimal96_conversion, f64_decimal, five_significant_digits, spot_scalar_conversions,
    three_digit_decimal, u256_decimal_scale,
};

#[test]
fn pdi_encoding_and_range_match_node115_0x22b3160() {
    assert_eq!(PDI_STRIDE, 10_000);
    assert_eq!(Pdi(0).perp_checked(42), Some(PerpAsset(42)));
    assert_eq!(Pdi(3).perp_checked(7), Some(PerpAsset(30_007)));
    assert_eq!(PerpAsset(30_007).split(), (Pdi(3), 7));
    assert_eq!(Pdi(u64::MAX / 10_000 + 1).perp_checked(0), None);
    assert_eq!(Pdi(0).perp_in_namespace(10_000), None);
    assert_eq!(
        Pdi(2).perp_range(3, 6),
        Some(vec![PerpAsset(20_003), PerpAsset(20_004), PerpAsset(20_005)])
    );
    assert_eq!(Pdi(2).perp_range(6, 3), Some(Vec::new()));
}

#[test]
fn side_polarity_matches_node115_0x5911890() {
    assert_eq!(Side::from_raw_byte(0), Side::Bid);
    assert_eq!(Side::from_raw_byte(1), Side::Ask);
    assert_eq!(Side::from_raw_byte(255), Side::Ask);
    assert_eq!(Side::Bid.signed_price_key(12_345), -12_345);
    assert_eq!(Side::Ask.signed_price_key(12_345), 12_345);
}

#[test]
fn pow10_table_matches_rodata_0x5ed748() {
    assert_eq!(POW10_F64.len(), 20);
    for (i, &v) in POW10_F64.iter().enumerate() {
        assert_eq!(v, 10_f64.powi(i as i32));
    }
}

#[test]
fn perp_meta_checks_match_node115_0x22e4810() {
    let meta = PerpMeta::new(
        Pdi(1),
        vec![
            PerpAssetMeta {
                name: "BTC".into(),
                sz_decimals: 5,
                max_leverage: 50,
            },
            PerpAssetMeta {
                name: "BAD".into(),
                sz_decimals: 7, // violates < 7 check at 0x22e4888
                max_leverage: 10,
            },
        ],
    );
    assert_eq!(MAX_PERP_SZ_DECIMALS, 6);
    assert_eq!(
        meta.px_to_f64(PerpAsset(10_000), Px(654_321)),
        Ok(65_432.1)
    );
    assert_eq!(
        meta.sz_decimals(PerpAsset(0)),
        Err(MetaError::PdiMismatch {
            expected: Pdi(1),
            actual: Pdi(0),
        })
    );
    assert_eq!(
        meta.sz_decimals(PerpAsset(10_001)),
        Err(MetaError::InvalidPerpSzDecimals(7))
    );
    assert_eq!(
        meta.sz_decimals(PerpAsset(10_002)),
        Err(MetaError::PerpOutOfBounds { index: 2, len: 2 })
    );
}

#[test]
fn spot_meta_dual_price_matches_node115_0x22f5de0() {
    let meta = SpotMeta::new(
        vec![
            SpotPairMeta {
                base: Token(1),
                quote: Token(0),
            },
            SpotPairMeta {
                base: Token(2),
                quote: Token(0),
            },
        ],
        vec![
            SpotTokenMeta {
                sz_decimals: 6,
                wei_decimals: 8,
            },
            SpotTokenMeta {
                sz_decimals: 2,
                wei_decimals: 8,
            },
            SpotTokenMeta {
                sz_decimals: 9, // quote.wei_decimals (8) < base.sz_decimals (9) -> underflow
                wei_decimals: 9,
            },
        ],
    );
    // Zero prices short-circuit even for out-of-bounds pair (0x22f5df0 / 0x22f5e87).
    assert_eq!(
        meta.raw_pair_prices_to_f64(SpotAsset(999), 0, 0),
        Ok((0.0, 0.0))
    );
    // Nonzero uses quote.wei_decimals (8) - base.sz_decimals (2) = 6 -> / 1e6.
    assert_eq!(
        meta.raw_pair_prices_to_f64(SpotAsset(0), 12_345_000, 0),
        Ok((12.345, 0.0))
    );
    assert_eq!(
        meta.raw_pair_prices_to_f64(SpotAsset(1), 1, 0),
        Err(MetaError::SpotDecimalUnderflow {
            quote_wei_decimals: 8,
            base_sz_decimals: 9,
        })
    );

    // Bridge cleanly into node115-spot-scalar-conversions
    let (pairs, tokens) = meta.to_scalar_conversion_tables();
    let view = spot_scalar_conversions::Metadata {
        pair_tokens: &pairs,
        tokens: &tokens,
    };
    assert_eq!(view.scaled_ratio(5, 1, 2), Ok(2_500_000));
}

#[test]
fn saturating_quantities_report_and_clamp_like_node115() {
    let mut sink = RecordingOverflowSink::default();

    assert_eq!(Ntl(u64::MAX - 5).sat_add(Ntl(10), &mut sink), Ntl(u64::MAX));
    assert_eq!(Sz(3).sat_sub(Sz(7), &mut sink), Sz(0));
    assert_eq!(Ntli(i64::MAX).sat_add(Ntli(1), &mut sink), Ntli(i64::MAX));
    assert_eq!(Ntli(i64::MIN).sat_add(Ntli(-1), &mut sink), Ntli(i64::MIN));
    assert_eq!(
        sink.events,
        vec![
            OverflowKind::UnsignedAdd,
            OverflowKind::UnsignedSub,
            OverflowKind::SignedAdd,
            OverflowKind::SignedAdd,
        ]
    );

    // Signed position sign-class transitions (0x22f6d94..0x22f6dc6)
    assert_eq!(Szi(5).sign_class(), 0);
    assert_eq!(Szi(-5).sign_class(), 1);
    assert_eq!(Szi(0).sign_class(), 2);
    assert!(Szi(5).sign_changed_from_nonzero(Szi(0)));
    assert!(Szi(5).sign_changed_from_nonzero(Szi(-1)));
    assert!(!Szi(0).sign_changed_from_nonzero(Szi(5)));
    assert!(!Szi(5).sign_changed_from_nonzero(Szi(10)));

    // Bounded wei hold (0x22e642d)
    assert_eq!(
        Wei::checked_hold_add(Wei(40), Wei(60), Wei(100)),
        Some(Wei(100))
    );
    assert_eq!(Wei::checked_hold_add(Wei(40), Wei(61), Wei(100)), None);
    assert_eq!(Wei::checked_hold_add(Wei(u64::MAX), Wei(1), Wei(u64::MAX)), None);

    assert_eq!(Usdc(1_250_000).to_f64(), 1.25);
    assert_eq!(Ntli(i64::MIN).checked_neg(), None);
    assert_eq!(Ntli(-10).clamp_non_negative(), Ntl(0));
    assert_eq!(Ntli(42).clamp_non_negative(), Ntl(42));
}

#[test]
fn wire_qty_and_reexported_microcrates_interoperate() {
    assert_eq!(format_wire_decimal(123_450_000, 6), "123.45");
    assert_eq!(format_wire_decimal(100_000_000, 6), "100");
    assert_eq!(
        normalize_decimal96_parts(1000, 0, 0, 0x8002_0000).observed_words(),
        [0x8000_0000, 0, 10, 0]
    );
    assert_eq!(five_significant_digits::truncate(123_456), 123_450);
    assert_eq!(three_digit_decimal::parse_three_digit_ascii(b"142"), 142);
    assert_eq!(three_digit_decimal::parse_three_digit_ascii(b"042"), 0);

    let d = decimal96_conversion::Decimal96::new(12345, 0, 2, false).unwrap();
    assert_eq!(d.to_f64(), 123.45);
    assert!(f64_decimal::from_f64_bits(123.45_f64.to_bits()).is_some());

    let mut limbs = [100_u64, 0, 0, 0];
    assert_eq!(u256_decimal_scale::scale_amount(&mut limbs, 2), Some(1));
    let mut limbs2 = [100_u64, 0, 0, 0];
    assert_eq!(u256_decimal_scale::scale_amount(&mut limbs2, -2), Some(10_000));
}

#[test]
fn meta_scaling_lookups_deployer_fee_share_and_clamped_f64_match_node115() {
    use node115_assets::{
        DeployerFeeShareError, LEGACY_MAINNET_TOKEN_MAX, MAINNET_CHAIN_TAG,
        MAX_DEPLOYER_TRADING_FEE_SHARE_E5, scale_nonneg_i64_by_f64_clamped,
        update_deployer_trading_fee_share,
    };

    // PerpMeta: 0x3d19800 (px_decimals), 0x50bea90 (px_to_f64), 0x50beb30 (sz_to_f64_zero_fast)
    let pmeta = PerpMeta::new(
        Pdi(0),
        vec![PerpAssetMeta {
            name: "ETH".into(),
            sz_decimals: 4,
            max_leverage: 50,
        }],
    );
    assert_eq!(pmeta.px_decimals(PerpAsset(0)), Ok(2));
    assert_eq!(pmeta.px_to_f64(PerpAsset(0), Px(345_678)), Ok(3456.78));
    assert_eq!(pmeta.sz_to_f64(PerpAsset(0), 25_000), Ok(2.5));
    // 0x50beb30 fast-zero path returns 0.0 even without valid asset lookup
    assert_eq!(pmeta.sz_to_f64_zero_fast(PerpAsset(999), 0), Ok(0.0));
    assert_eq!(pmeta.sz_to_f64_zero_fast(PerpAsset(0), 25_000), Ok(2.5));

    // SpotMeta: 0x50be9e0, 0x3c47660, 0x3c47ae0, 0x3c49df0, 0x3c49360, 0x3c4b280, 0x3c4b1a0
    let smeta = SpotMeta::new(
        vec![
            SpotPairMeta {
                base: Token(1),
                quote: Token(2),
            },
            SpotPairMeta {
                base: Token(1),
                quote: Token(0),
            },
        ],
        vec![
            SpotTokenMeta {
                sz_decimals: 6,
                wei_decimals: 8,
            }, // Token(0) USDC
            SpotTokenMeta {
                sz_decimals: 2,
                wei_decimals: 8,
            }, // Token(1) HYPE-like
            SpotTokenMeta {
                sz_decimals: 4,
                wei_decimals: 8,
            }, // Token(2) alt quote
            SpotTokenMeta {
                sz_decimals: 0,
                wei_decimals: 20,
            }, // Token(3) pow10 overflow (>10^19)
        ],
    );
    assert_eq!(smeta.px_to_f64(SpotAsset(1), Px(15_500_000)), Ok(15.5));
    assert_eq!(smeta.first_spot_for_token(Token(1)), Ok(Some(SpotAsset(0))));
    assert_eq!(smeta.first_spot_for_token(Token(2)), Ok(None));
    assert_eq!(
        smeta.spot_for_token_and_quote(Token(1), Token(0)),
        Ok(Some(SpotAsset(1)))
    );
    assert_eq!(smeta.has_usdc_spot(Token(1)), Ok(true));
    assert_eq!(smeta.has_usdc_spot(Token(2)), Ok(false));
    assert_eq!(smeta.usdc_wei_per_base_sz(Token(1)), Ok(1_000_000));
    assert_eq!(smeta.tokens[1].wei_per_sz(), Ok(1_000_000));
    assert_eq!(smeta.tokens[3].wei_per_sz(), Err(MetaError::Pow10Overflow(20)));
    assert_eq!(smeta.checked_sz_to_wei(Token(1), 42), Ok(Some(42_000_000)));
    assert_eq!(smeta.checked_sz_to_wei(Token(1), u64::MAX), Ok(None));

    // Deployer trading fee share state machine (0x2c58880)
    assert_eq!(MAX_DEPLOYER_TRADING_FEE_SHARE_E5, 100_000);
    assert_eq!(LEGACY_MAINNET_TOKEN_MAX, 195);
    assert_eq!(MAINNET_CHAIN_TAG, 3);
    assert_eq!(
        update_deployer_trading_fee_share(10, 0, 100_001, MAINNET_CHAIN_TAG),
        Err(DeployerFeeShareError::ExceedsMax)
    );
    assert_eq!(
        DeployerFeeShareError::ExceedsMax.as_str(),
        "deployer trading fee share cannot be more than 100%"
    );
    // Legacy Mainnet token (<= 195): one-time init from 0 is allowed
    assert_eq!(
        update_deployer_trading_fee_share(195, 0, 50_000, MAINNET_CHAIN_TAG),
        Ok(50_000)
    );
    // Legacy Mainnet token: decreasing to nonzero allowed, resetting to 0 rejected, increasing rejected
    assert_eq!(
        update_deployer_trading_fee_share(195, 50_000, 25_000, MAINNET_CHAIN_TAG),
        Ok(25_000)
    );
    assert_eq!(
        update_deployer_trading_fee_share(195, 25_000, 0, MAINNET_CHAIN_TAG),
        Err(DeployerFeeShareError::CannotResetLegacy)
    );
    assert_eq!(
        DeployerFeeShareError::CannotResetLegacy.as_str(),
        "cannot reset legacy token fee share"
    );
    assert_eq!(
        update_deployer_trading_fee_share(195, 25_000, 25_000, MAINNET_CHAIN_TAG),
        Err(DeployerFeeShareError::CannotIncrease)
    );
    assert_eq!(
        DeployerFeeShareError::CannotIncrease.as_str(),
        "deployer trading fee share cannot increase"
    );
    // Non-legacy token (> 195) or non-Mainnet: strictly decreasing (can go to 0, cannot init from 0)
    assert_eq!(
        update_deployer_trading_fee_share(196, 0, 50_000, MAINNET_CHAIN_TAG),
        Err(DeployerFeeShareError::CannotIncrease)
    );
    assert_eq!(
        update_deployer_trading_fee_share(196, 50_000, 0, MAINNET_CHAIN_TAG),
        Ok(0)
    );
    assert_eq!(
        update_deployer_trading_fee_share(10, 50_000, 0, 2),
        Ok(0)
    );

    // Clamped f64 scaling (0x46a6aa0 / qtys/mod.rs:847)
    assert_eq!(scale_nonneg_i64_by_f64_clamped(-1, 1.0), None);
    assert_eq!(scale_nonneg_i64_by_f64_clamped(1_000, 0.25), Some(250));
    assert_eq!(scale_nonneg_i64_by_f64_clamped(1_000, -0.5), Some(0));
    assert_eq!(scale_nonneg_i64_by_f64_clamped(1_000, f64::NAN), Some(0));
    assert_eq!(scale_nonneg_i64_by_f64_clamped(1_000, f64::INFINITY), Some(0));
    assert_eq!(
        scale_nonneg_i64_by_f64_clamped(1_000, f64::NEG_INFINITY),
        Some(0)
    );
    assert_eq!(
        scale_nonneg_i64_by_f64_clamped(i64::MAX, 2.0),
        Some(i64::MAX as u64)
    );

    // Built-in vs custom margin-table ID threshold (`l1/src/perp_meta.rs:247:72`, `0x3c4315d`)
    assert_eq!(node115_assets::BUILTIN_MARGIN_TABLE_LIMIT, 50);
    assert!(node115_assets::is_builtin_margin_table_id(0));
    assert!(node115_assets::is_builtin_margin_table_id(49));
    assert!(!node115_assets::is_builtin_margin_table_id(50));
    assert!(!node115_assets::is_builtin_margin_table_id(100));
}
