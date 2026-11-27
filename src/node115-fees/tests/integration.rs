use node115_assets::qtys::{OverflowKind, RecordingOverflowSink};
use node115_fees::credit::{
    FILL_FEE_INPUT_CAP, FILL_FEE_PRE_X100_CAP, FeeCreditMode, FeeDistributionRecord, FeeLedger,
    FeeScaleError, SecondarySplitRow, compute_fill_fee_triple, settle_fill_fee, tally_millionths,
};
use node115_fees::schedule::{is_monotonically_non_increasing, matches_node115_0x36e1b10};
use node115_fees::vlm::{
    OPEN_ORDER_PASS_HEAD, OPEN_ORDER_REJECT_HEAD, OpenOrderDecision, OpenOrderDescriptor,
    PRIVILEGED_OPEN_ORDER_ADDRESSES, RawVlm, ScaledVlm, UserVolumeTotals, check_open_order_cap,
    fold_user_volumes, fold_users_raw_volume, open_order_limit,
};
use node115_fees::{fee_rate_map_codec, fee_schedule_compose};

fn addr(tag: u8) -> [u8; 20] {
    [tag; 20]
}

#[test]
fn fee_credit_distribution_matches_node115_worked_examples() {
    // Worked example 1 from fees-credit-distribution-115/README.md (0x3c1ae50):
    // flag=1, gross=100, rebate=30, protocol=20, primary=40, secondary_total=1000,
    // rows 70000 -> user 3, 20000 -> user 4, dest -> user 2, key=5, user=0, recipient=1.
    let mut ledger = FeeLedger::default();
    let mut sink = RecordingOverflowSink::default();
    let rec = FeeDistributionRecord {
        primary: Some((addr(1), 40)),
        secondary: Some((
            vec![
                SecondarySplitRow {
                    numerator: 70_000,
                    recipient: addr(3),
                },
                SecondarySplitRow {
                    numerator: 20_000,
                    recipient: addr(4),
                },
            ],
            1_000,
            addr(2),
        )),
        gross: 100,
        rebate: 30,
        protocol: 20,
    };
    ledger.distribute(addr(0), 5, &rec, &mut sink);
    assert!(sink.events.is_empty());

    let u0 = ledger.primary_cells[&(addr(0), 5)];
    assert_eq!(u0.protocol_fee, 20);
    assert_eq!(u0.net_fee, 50);
    assert_eq!(u0.primary_paid, 40);

    assert_eq!(ledger.primary_cells[&(addr(1), 5)].credit, 40);
    assert!(!ledger.secondary_credits.contains_key(&(addr(1), 5)));

    assert_eq!(ledger.primary_cells[&(addr(3), 5)].credit, 700);
    assert_eq!(ledger.secondary_credits[&(addr(3), 5)], 700);
    assert_eq!(ledger.primary_cells[&(addr(4), 5)].credit, 200);
    assert_eq!(ledger.secondary_credits[&(addr(4), 5)], 200);
    assert_eq!(ledger.primary_cells[&(addr(2), 5)].credit, 100);
    assert_eq!(ledger.secondary_credits[&(addr(2), 5)], 100);
}

#[test]
fn fee_credit_borrow_hooks_and_zero_semantics_match_node115() {
    // Worked example 2: gross=0, rebate=1, protocol=1 -> two separate borrow hooks.
    let mut ledger = FeeLedger::default();
    let mut sink = RecordingOverflowSink::default();
    let rec = FeeDistributionRecord {
        primary: Some((addr(1), 0)),
        secondary: None,
        gross: 0,
        rebate: 1,
        protocol: 1,
    };
    ledger.distribute(addr(0), 9, &rec, &mut sink);
    assert_eq!(
        sink.events,
        vec![OverflowKind::UnsignedSub, OverflowKind::UnsignedSub]
    );
    assert_eq!(ledger.primary_cells[&(addr(0), 9)].net_fee, 0);

    // credit(0) creates no cell; extra_credit(0) creates a cell.
    ledger.credit(addr(9), 1, 0, &mut sink);
    assert!(!ledger.primary_cells.contains_key(&(addr(9), 1)));
    ledger.extra_credit(addr(9), 1, 0, &mut sink);
    assert!(ledger.primary_cells.contains_key(&(addr(9), 1)));

    // Secondary row above 1.01 (101_001 / 100_000) is skipped; row exceeding remaining is skipped.
    let rec_skip = FeeDistributionRecord {
        primary: None,
        secondary: Some((
            vec![
                SecondarySplitRow {
                    numerator: 101_001,
                    recipient: addr(5),
                },
                SecondarySplitRow {
                    numerator: 60_000,
                    recipient: addr(6),
                },
                SecondarySplitRow {
                    numerator: 50_000,
                    recipient: addr(7),
                },
            ],
            1_000,
            addr(8),
        )),
        gross: 0,
        rebate: 0,
        protocol: 0,
    };
    ledger.distribute(addr(0), 10, &rec_skip, &mut sink);
    assert!(!ledger.primary_cells.contains_key(&(addr(5), 10)));
    assert_eq!(ledger.primary_cells[&(addr(6), 10)].credit, 600);
    assert!(!ledger.primary_cells.contains_key(&(addr(7), 10)));
    assert_eq!(ledger.primary_cells[&(addr(8), 10)].credit, 400);
}

#[test]
fn fee_x100_scaler_and_credit_mode_match_0x46a6860_and_0x3c10000() {
    let rec = FeeDistributionRecord {
        primary: Some((addr(1), 5)),
        secondary: Some((vec![], 7, addr(2))),
        gross: 10,
        rebate: 2,
        protocol: 3,
    };
    let scaled = rec.scale_x100().unwrap();
    assert_eq!(scaled.gross, 1_000);
    assert_eq!(scaled.rebate, 200);
    assert_eq!(scaled.primary.unwrap().1, 500);
    assert_eq!(scaled.secondary.unwrap().1, 700);
    assert_eq!(scaled.protocol, 300);

    let overflow_gross = FeeDistributionRecord {
        gross: u64::MAX / 100 + 1,
        ..Default::default()
    };
    assert_eq!(overflow_gross.scale_x100(), Err(FeeScaleError::GrossOverflow));

    assert_eq!(FeeCreditMode::Identity.apply(5_000_000), 5_000_000);
    assert_eq!(FeeCreditMode::OneFifth.apply(5_000_000), 1_000_000);
    assert_eq!(FeeCreditMode::FloatFactor(f64::NAN).apply(100), 0);
    assert_eq!(FeeCreditMode::FloatFactor(-1.0).apply(100), 0);
    assert_eq!(
        FeeCreditMode::FloatFactor(1e30).apply(100),
        i64::MAX as u64
    );
    assert_eq!(tally_millionths(5_000_000, FeeCreditMode::OneFifth), (5, 1));
}

#[test]
fn volume_fold_and_open_order_cap_match_node115() {
    let mut sink = RecordingOverflowSink::default();
    let totals = fold_user_volumes(
        &[
            UserVolumeTotals {
                raw: RawVlm(u64::MAX - 5),
                scaled: ScaledVlm(1_000),
            },
            UserVolumeTotals {
                raw: RawVlm(10),
                scaled: ScaledVlm(2_000),
            },
        ],
        UserVolumeTotals {
            raw: RawVlm(1),
            scaled: ScaledVlm(3_000),
        },
        &mut sink,
    );
    assert_eq!(totals.raw, RawVlm(u64::MAX));
    assert_eq!(totals.scaled, ScaledVlm(6_000));
    assert_eq!(
        sink.events,
        vec![OverflowKind::UnsignedAdd, OverflowKind::UnsignedAdd]
    );

    let batch = fold_users_raw_volume(
        RawVlm(100),
        [(
            &[UserVolumeTotals {
                raw: RawVlm(250),
                scaled: ScaledVlm(0),
            }][..],
            UserVolumeTotals {
                raw: RawVlm(50),
                scaled: ScaledVlm(0),
            },
        )],
        &mut sink,
    );
    assert_eq!(batch, RawVlm(400));

    // Open-order limit math (0x5495210)
    assert_eq!(open_order_limit(&addr(1), ScaledVlm(0)), 1_000);
    assert_eq!(open_order_limit(&addr(1), ScaledVlm(500_000_000)), 1_001);
    assert_eq!(open_order_limit(&addr(1), ScaledVlm(u64::MAX)), 5_000);
    for priv_addr in &PRIVILEGED_OPEN_ORDER_ADDRESSES {
        assert_eq!(open_order_limit(priv_addr, ScaledVlm(0)), 10_000);
    }

    let d = check_open_order_cap(
        &addr(1),
        1_000,
        OpenOrderDescriptor::Other {
            flag_31: false,
            tag_19: 2,
        },
        &[UserVolumeTotals {
            raw: RawVlm(500_000_000),
            scaled: ScaledVlm(500_000_000),
        }],
        UserVolumeTotals::default(),
        &mut sink,
    );
    assert_eq!(d, OpenOrderDecision::Pass);
    assert_eq!(d.raw_head(), OPEN_ORDER_PASS_HEAD);

    let r = check_open_order_cap(
        &addr(1),
        1_001,
        OpenOrderDescriptor::Other {
            flag_31: false,
            tag_19: 2,
        },
        &[UserVolumeTotals {
            raw: RawVlm(500_000_000),
            scaled: ScaledVlm(500_000_000),
        }],
        UserVolumeTotals::default(),
        &mut sink,
    );
    assert_eq!(r, OpenOrderDecision::Reject);
    assert_eq!(r.raw_head(), OPEN_ORDER_REJECT_HEAD);

    // All-ones key always passes
    assert_eq!(
        check_open_order_cap(
            &[0xff; 20],
            999_999,
            OpenOrderDescriptor::KindTwo,
            &[],
            UserVolumeTotals::default(),
            &mut sink,
        ),
        OpenOrderDecision::Pass
    );
}

#[test]
fn schedule_monotonicity_and_microcrate_interop() {
    assert!(is_monotonically_non_increasing(&[0.00045, 0.00040, 0.00035]));
    assert!(!is_monotonically_non_increasing(&[0.00035, 0.00040]));
    assert!(!is_monotonically_non_increasing(&[0.00035, f64::NAN]));
    assert!(matches_node115_0x36e1b10(&[0.00045, 0.00040, 0.00040]));
    assert!(!matches_node115_0x36e1b10(&[0.00040, 0.00045]));

    let encoded = fee_rate_map_codec::encode_bits([
        0.00045_f64.to_bits(),
        0.00015_f64.to_bits(),
        0.00035_f64.to_bits(),
        0.00010_f64.to_bits(),
    ]);
    assert_eq!(encoded.len(), 37);

    let sched = fee_schedule_compose::Schedule {
        seeds: [0.00045, 0.00015, 0.00035, 0.00010],
        tiers: &[],
        secondary: &[],
        stake_pairs: &[],
        extra_values: &[],
        ranges: [0.0, 1.0],
    };
    let _ = fee_schedule_compose::evaluate(&sched, |_, _, _| true);
}

#[test]
fn fill_fee_scaling_and_settlement_pipeline_match_0x44896f0() {
    assert_eq!(FILL_FEE_INPUT_CAP, i64::MAX as u64 / 50);
    assert_eq!(FILL_FEE_PRE_X100_CAP, i64::MAX / 100);

    // Main DEX (is_hip3=false): scale_a=1.0, scale_b=0.0
    // notional=100_000_000 (100 USD), fee_rate=0.0005 -> 50_000 / 10_000 = 5
    let (extra, base, deployer) = compute_fill_fee_triple(100_000_000, 0.0005, false, false, None);
    assert_eq!((extra, base, deployer), (5, 5, 0));

    // HIP-3 growth mode with deployer_scale=0.5 -> deployer gets 50%
    let (extra_h, base_h, dep_h) =
        compute_fill_fee_triple(100_000_000, 0.0005, true, true, Some(0.5));
    assert_eq!((extra_h, base_h, dep_h), (5, 5, 2));

    // Full settlement pipeline (`0x44896f0 -> 0x3c1a3f0 -> 0x46a6860 -> 0x3c1ae50`)
    let mut ledger = FeeLedger::default();
    let mut sink = RecordingOverflowSink::default();
    let rec = FeeDistributionRecord {
        primary: Some((addr(2), 4)),
        secondary: None,
        gross: 10,
        rebate: 2,
        protocol: 3,
    };
    // side_kind == 2 skips settlement completely (`0x4489b34`)
    assert_eq!(
        settle_fill_fee(&mut ledger, addr(1), 0, 2, 7, &rec, &mut sink),
        Ok(false)
    );
    assert!(ledger.primary_cells.is_empty());

    // side_kind == 0 runs extra_credit(7), scales record x100, and distributes
    assert_eq!(
        settle_fill_fee(&mut ledger, addr(1), 0, 0, 7, &rec, &mut sink),
        Ok(true)
    );
    let cell = ledger.primary_cells[&(addr(1), 0)];
    assert_eq!(cell.extra_credit, 7);
    assert_eq!(cell.protocol_fee, 300);
    assert_eq!(cell.net_fee, 500);
    assert_eq!(cell.primary_paid, 400);
    assert_eq!(ledger.primary_cells[&(addr(2), 0)].credit, 400);
}

#[test]
fn fee_tiers_staking_referral_spot_and_builder_fees() {
    use node115_fees::{
        BaseFeeRates, BuilderFeeError, BuilderFeeRegistry, FeeSchedule, MmFeeTier,
        StakeDiscountTier, VipFeeTier,
    };

    let sched = FeeSchedule {
        rates: BaseFeeRates {
            perp_cross: 0.00045,
            perp_add: 0.00015,
            spot_cross: 0.00070,
            spot_add: 0.00040,
        },
        vip_tiers: vec![
            VipFeeTier {
                ntl_cutoff: 5_000_000,
                cross: 0.00040,
                add: 0.00012,
                spot_cross: 0.00060,
                spot_add: 0.00030,
                tail: 1.0,
            },
            VipFeeTier {
                ntl_cutoff: 25_000_000,
                cross: 0.00035,
                add: 0.00010,
                spot_cross: 0.00050,
                spot_add: 0.00020,
                tail: 1.0,
            },
        ],
        mm_tiers: vec![
            MmFeeTier {
                maker_fraction_cutoff: 0.005,
                add: -0.00001,
            },
            MmFeeTier {
                maker_fraction_cutoff: 0.03,
                add: -0.00003,
            },
        ],
        referral_discount: 0.04,
        referrer_keep: 0.10,
        destination: addr(9),
        extra_destination_fractions: vec![(addr(8), 0.20)],
        stake_discount_tiers: vec![
            StakeDiscountTier {
                bps_of_max_supply_staked: 0.001,
                discount: 0.05,
            },
            StakeDiscountTier {
                bps_of_max_supply_staked: 0.1,
                discount: 0.20,
            },
        ],
        weigh_spot_volume_double: true,
    };

    // Passes `#115` `node115-fee-schedule-compose::evaluate`!
    assert_eq!(sched.validate(), fee_schedule_compose::Outcome::Passed);

    // Spot volume weighted 2x: perp 15M + 2 * spot 6M = 27M -> qualifies for VIP tier 2!
    let rates = sched.user_fee_rates(15_000_000, 6_000_000, 0.03, 0.1, true);
    // perp_cross = 0.00035 * (1 - 0.20) * (1 - 0.04) = 0.0002688
    assert!((rates.perp_cross - 0.0002688).abs() < 1e-12);
    // spot_cross = 0.00050 * 0.80 * 0.96 = 0.000384
    assert!((rates.spot_cross - 0.000384).abs() < 1e-12);
    // MM maker rebate (-0.00003) is NOT diluted by fee discounts!
    assert_eq!(rates.perp_add, -0.00003);
    assert_eq!(rates.spot_add, -0.00003);

    // Builder fee approval & trade fee breakdown
    let mut builders = BuilderFeeRegistry::default();
    let trader = addr(1);
    let builder = addr(7);
    assert_eq!(
        builders.validate_charge(&trader, &builder, 0.0005, false),
        Err(BuilderFeeError::NotApproved)
    );
    builders.approve(trader, builder, 0.0005).unwrap();
    assert_eq!(
        builders.validate_charge(&trader, &builder, 0.0006, false),
        Err(BuilderFeeError::ExceedsUserApproval)
    );
    assert_eq!(
        builders.validate_charge(&trader, &builder, 0.002, false),
        Err(BuilderFeeError::ExceedsProtocolMax)
    );
    let approved_rate = builders
        .validate_charge(&trader, &builder, 0.0005, false)
        .unwrap();

    // Taker perp trade of 100_000_000 notional
    let taker_fee =
        sched.compute_trade_fee(100_000_000, false, true, rates, true, Some(approved_rate));
    assert_eq!(taker_fee.user_fee, 26_880);
    assert_eq!(taker_fee.maker_rebate, 0);
    assert_eq!(taker_fee.referrer_reward, 2_688);
    assert_eq!(taker_fee.protocol_fee, 24_192);
    assert_eq!(taker_fee.builder_fee, 50_000);
    builders.record_collected(builder, taker_fee.builder_fee);
    assert_eq!(builders.collected_builder_fees[&builder], 50_000);

    // Maker fill earns positive maker_rebate and pays 0 user_fee / 0 referrer_reward
    let maker_fee = sched.compute_trade_fee(100_000_000, false, false, rates, true, None);
    assert_eq!(maker_fee.user_fee, 0);
    assert_eq!(maker_fee.maker_rebate, 3_000);
    assert_eq!(maker_fee.referrer_reward, 0);
}
