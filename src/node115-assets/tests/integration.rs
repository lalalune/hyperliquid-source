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
