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

#[test]
fn protocol_fee_solvency_floor_rate_bounds_and_volume_gates_match_node115() {
    use node115_fees::{
        BaseFeeRates, COMBINED_SUBACCOUNT_MIN_RAW_VLM, FeeSchedule, MAX_FEE_RATE,
        MIN_NET_PROTOCOL_FEE, MIN_POSITIVE_FEE_RATE, MmFeeTier, PROTOCOL_FEE_SCALES,
        SCHEDULE_CANCEL_MAX_DAYS_AHEAD, SCHEDULE_CANCEL_MAX_PER_DAY, SCHEDULE_CANCEL_MIN_RAW_VLM,
        SolvencyCheckInputs, StakeDiscountTier, VipFeeTier, check_combined_subaccount_volume_gate,
        check_net_fee_solvency_0x36a58d0, check_schedule_cancel_volume_gate, fee_schedule_compose,
        is_valid_maker_rate, is_valid_taker_rate,
    };

    assert_eq!(PROTOCOL_FEE_SCALES, [1.0, 0.2, 6.0, 0.1, 2.0, 40.0]);
    assert_eq!(MIN_NET_PROTOCOL_FEE, 5e-6);
    assert_eq!(MIN_POSITIVE_FEE_RATE, 0.0001);
    assert_eq!(MAX_FEE_RATE, 0.001);
    assert_eq!(SCHEDULE_CANCEL_MIN_RAW_VLM, 100_000_000);
    assert_eq!(SCHEDULE_CANCEL_MAX_DAYS_AHEAD, 5);
    assert_eq!(SCHEDULE_CANCEL_MAX_PER_DAY, 10);
    assert_eq!(COMBINED_SUBACCOUNT_MIN_RAW_VLM, 2_000_000_000);

    // Rate dust/cap bounds (`0x36a2ef3..0x36a3059`)
    assert!(is_valid_taker_rate(0.0));
    assert!(is_valid_taker_rate(0.0001));
    assert!(is_valid_taker_rate(0.001));
    assert!(!is_valid_taker_rate(0.00005)); // sub-1bps positive dust rejected
    assert!(!is_valid_taker_rate(-0.0001));
    assert!(!is_valid_taker_rate(0.0011));

    assert!(is_valid_maker_rate(-0.0003)); // negative MM rebate allowed
    assert!(is_valid_maker_rate(0.0));
    assert!(is_valid_maker_rate(0.0001));
    assert!(!is_valid_maker_rate(0.00005)); // sub-1bps positive dust rejected
    assert!(!is_valid_maker_rate(-0.0011)); // exceeds |-0.001|

    // Exact `0x36a58d0` 6-scale solvency check:
    // min_cross = 0.00025, stake = 0.20 -> 0.00020; ref = 0.04, keep = 0.10 -> 0.0001728;
    // min_add = -0.00003 -> net = 0.0001428; at smallest scale 0.1 -> 1.428e-5 >= 5e-6 -> PASS.
    assert!(check_net_fee_solvency_0x36a58d0(SolvencyCheckInputs {
        vip_adds: &[0.0001],
        mm_adds: &[-0.00003],
        vip_crosses: &[0.00025],
        base_add: 0.00015,
        base_cross: 0.00045,
        max_staking_discount: 0.20,
        referral_discount: 0.04,
        trial_discount: 0.0,
        referrer_keep: 0.10,
    }));
    // Excessive rebate (-0.00015) fails solvency at scale 0.1: (0.0001728 - 0.00015) * 0.1 = 2.28e-6 < 5e-6
    assert!(!check_net_fee_solvency_0x36a58d0(SolvencyCheckInputs {
        vip_adds: &[0.0001],
        mm_adds: &[-0.00015],
        vip_crosses: &[0.00025],
        base_add: 0.00015,
        base_cross: 0.00045,
        max_staking_discount: 0.20,
        referral_discount: 0.04,
        trial_discount: 0.0,
        referrer_keep: 0.10,
    }));

    // Integrated FeeSchedule::validate_with_solvency (`0x36a1c20` + `0x36a58d0`)
    let solvent_sched = FeeSchedule {
        rates: BaseFeeRates {
            perp_cross: 0.00045,
            perp_add: 0.00015,
            spot_cross: 0.00070,
            spot_add: 0.00040,
        },
        vip_tiers: vec![VipFeeTier {
            ntl_cutoff: 5_000_000,
            cross: 0.00040,
            add: 0.00012,
            spot_cross: 0.00060,
            spot_add: 0.00030,
            tail: 1.0,
        }],
        mm_tiers: vec![MmFeeTier {
            maker_fraction_cutoff: 0.005,
            add: -0.00003,
        }],
        referral_discount: 0.04,
        referrer_keep: 0.10,
        destination: addr(1),
        extra_destination_fractions: vec![],
        stake_discount_tiers: vec![StakeDiscountTier {
            bps_of_max_supply_staked: 1.0,
            discount: 0.20,
        }],
        weigh_spot_volume_double: true,
    };
    assert_eq!(
        solvent_sched.validate_with_solvency(0.0),
        fee_schedule_compose::Outcome::Passed
    );

    let mut insolvent_sched = solvent_sched.clone();
    insolvent_sched.mm_tiers[0].add = -0.00035;
    assert_eq!(
        insolvent_sched.validate_with_solvency(0.0),
        fee_schedule_compose::Outcome::Rejected
    );

    // Volume gates (`0x2c2cb40` & `0x2c59480`)
    assert_eq!(check_schedule_cancel_volume_gate(RawVlm(99_999_999)), Err(999_999.99));
    assert_eq!(check_schedule_cancel_volume_gate(RawVlm(100_000_000)), Ok(()));

    let mut sink = RecordingOverflowSink::default();
    assert!(!check_combined_subaccount_volume_gate(
        RawVlm(1_500_000_000),
        &[RawVlm(500_000_000)],
        &mut sink,
    ));
    assert!(check_combined_subaccount_volume_gate(
        RawVlm(1_500_000_000),
        &[RawVlm(500_000_001)],
        &mut sink,
    ));
    assert!(sink.events.is_empty());
}

#[test]
fn fee_trial_referral_claim_and_builder_cap_match_node115() {
    use node115_fees::{
        BaseFeeRates, BuilderFeeRegistry, CLAIM_REWARD_MIN_USDC_WEI, DEFAULT_REFERRALS_PER_BUCKET,
        ERR_NO_MORE_REFERRALS, ERR_REFERRAL_CODE_NOT_REGISTERED, ERR_REWARD_TOO_SMALL,
        ERR_SELF_REFER, ERR_TOO_MANY_BUILDERS, FEE_TRIAL_DURATION_DAYS, FeeLifecycleError,
        FeeLifecycleTracker, FeeSchedule, MAX_APPROVED_BUILDERS, MmFeeTier,
        REFERRAL_DISCOUNT_VLM_CAP_RAW, StakeDiscountTier, UserRewardEntry, VipFeeTier,
        approve_builder_fee_capped,
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
                add: 0.00008,
                spot_cross: 0.00050,
                spot_add: 0.00020,
                tail: 1.0,
            },
        ],
        mm_tiers: vec![MmFeeTier {
            maker_fraction_cutoff: 0.005,
            add: -0.00001,
        }],
        referral_discount: 0.04,
        referrer_keep: 0.10,
        destination: addr(1),
        extra_destination_fractions: vec![],
        stake_discount_tiers: vec![StakeDiscountTier {
            bps_of_max_supply_staked: 1.0,
            discount: 0.20,
        }],
        weigh_spot_volume_double: true,
    };

    let mut tracker = FeeLifecycleTracker::new(sched, 86_400_000);
    let referrer = addr(10);
    let alice = addr(11);
    let bob = addr(12);
    let linked = addr(13);

    // 1. Referral registration & set_referrer (`0x3c17590`)
    assert_eq!(
        tracker.set_referrer(alice, "MISSING", 100_000),
        Err(FeeLifecycleError::ReferralCodeNotRegistered)
    );
    assert_eq!(
        FeeLifecycleError::ReferralCodeNotRegistered.status_word(),
        Some(ERR_REFERRAL_CODE_NOT_REGISTERED)
    );
    tracker.register_referrer_code("ALPHA", referrer, 1);
    assert_eq!(
        tracker.set_referrer(referrer, "ALPHA", 100_000),
        Err(FeeLifecycleError::CannotSelfRefer)
    );
    assert_eq!(
        FeeLifecycleError::CannotSelfRefer.status_word(),
        Some(ERR_SELF_REFER)
    );
    assert_eq!(tracker.set_referrer(alice, "ALPHA", 86_400_000), Ok(()));
    assert_eq!(
        tracker.set_referrer(alice, "ALPHA", 86_400_000),
        Err(FeeLifecycleError::ReferrerAlreadySet)
    );
    // Bucket refreshes to max(custom_bucket_limit, 1000) (`0x3c17ab9..0x3c17ac4`)
    assert_eq!(
        tracker.code_to_referrer["ALPHA"].remaining_in_bucket,
        DEFAULT_REFERRALS_PER_BUCKET - 1
    );
    // Exhaust bucket -> 0xa5, then advance to next bucket -> refreshes to 1000
    tracker
        .code_to_referrer
        .get_mut("ALPHA")
        .unwrap()
        .remaining_in_bucket = 0;
    assert_eq!(
        tracker.set_referrer(bob, "ALPHA", 86_400_000),
        Err(FeeLifecycleError::NoMoreReferralsInBucket)
    );
    assert_eq!(
        FeeLifecycleError::NoMoreReferralsInBucket.status_word(),
        Some(ERR_NO_MORE_REFERRALS)
    );
    assert_eq!(tracker.set_referrer(bob, "ALPHA", 2 * 86_400_000), Ok(()));

    // 2. Referral discount $25M cumulative RawVlm cutoff (`0x3c17390..0x3c17590`)
    assert_eq!(REFERRAL_DISCOUNT_VLM_CAP_RAW, 2_500_000_000);
    tracker
        .user_states
        .get_mut(&alice)
        .unwrap()
        .token_states
        .insert(
            0,
            UserRewardEntry {
                cum_raw_vlm: REFERRAL_DISCOUNT_VLM_CAP_RAW - 1,
                unclaimed_rewards: 50_000_000, // $0.50 < $1.00
                claimed_rewards: 0,
            },
        );
    assert_eq!(tracker.active_referral_discount(&alice), 0.04);
    tracker
        .user_states
        .get_mut(&alice)
        .unwrap()
        .token_states
        .get_mut(&0)
        .unwrap()
        .cum_raw_vlm = REFERRAL_DISCOUNT_VLM_CAP_RAW;
    assert_eq!(tracker.active_referral_discount(&alice), 0.0);

    // 3. Claim rewards `$1.00` (`0x5f5e100`) threshold (`0x3c17fc0`: `0xaa` vs `0xab`)
    assert_eq!(
        tracker.claim_rewards(&addr(99), |_, min_usdc| Some(min_usdc)),
        Err(FeeLifecycleError::NoRewardsToClaim)
    );
    assert_eq!(
        tracker.claim_rewards(&alice, |_, min_usdc| Some(min_usdc)),
        Err(FeeLifecycleError::RewardTooSmallToClaim)
    );
    assert_eq!(
        FeeLifecycleError::RewardTooSmallToClaim.status_word(),
        Some(ERR_REWARD_TOO_SMALL)
    );
    tracker
        .user_states
        .get_mut(&alice)
        .unwrap()
        .token_states
        .get_mut(&0)
        .unwrap()
        .unclaimed_rewards = CLAIM_REWARD_MIN_USDC_WEI;
    let claimed = tracker
        .claim_rewards(&alice, |_, min_usdc| Some(min_usdc))
        .unwrap();
    assert_eq!(claimed, vec![(0, CLAIM_REWARD_MIN_USDC_WEI)]);
    assert_eq!(
        tracker.user_states[&alice].token_states[&0].claimed_rewards,
        CLAIM_REWARD_MIN_USDC_WEI
    );

    // 4. Fee trial lifecycle (`0x3c18390`: disabled/nonexistent/already-met/start/90d cooldown/14d duration)
    let cur_base = BaseFeeRates {
        perp_cross: 0.00045,
        perp_add: 0.00015,
        spot_cross: 0.00070,
        spot_add: 0.00040,
    };
    let vip1_mm = BaseFeeRates {
        perp_cross: 0.00040,
        perp_add: -0.00001,
        spot_cross: 0.00060,
        spot_add: -0.00001,
    };
    tracker.trials_disabled = true;
    assert_eq!(
        tracker.start_fee_trial(alice, vip1_mm, cur_base, 0.0, 20_000, &[]),
        Err(FeeLifecycleError::FeeTrialsDisabled)
    );
    tracker.trials_disabled = false;

    assert_eq!(
        tracker.start_fee_trial(alice, cur_base, cur_base, 0.0, 20_000, &[]),
        Err(FeeLifecycleError::FeeTrialRateNotFound)
    );
    // Already met when current rates beat requested VIP tier
    let better_cur = BaseFeeRates {
        perp_cross: 0.00020,
        perp_add: -0.00005,
        spot_cross: 0.00020,
        spot_add: -0.00005,
    };
    assert_eq!(
        tracker.start_fee_trial(alice, vip1_mm, better_cur, 1.0, 20_000, &[]),
        Err(FeeLifecycleError::FeeTrialRatesAlreadyMet)
    );

    // Valid VIP+MM trial with 20% staking discount on positive rates only (negative maker rebate untouched)
    let trial = tracker
        .start_fee_trial(alice, vip1_mm, cur_base, 1.0, 20_000, &[linked])
        .unwrap();
    assert_eq!(trial.end_day, 20_000 + FEE_TRIAL_DURATION_DAYS);
    assert!((trial.effective_rates.perp_cross - 0.00032).abs() < 1e-12);
    assert_eq!(trial.effective_rates.perp_add, -0.00001);
    assert_eq!(tracker.user_states[&linked].active_trial, Some(trial));

    // Active trial rejects duplicate start (`0x149`)
    assert_eq!(
        tracker.start_fee_trial(alice, vip1_mm, cur_base, 1.0, 20_001, &[]),
        Err(FeeLifecycleError::FeeTrialAlreadyStarted)
    );
    // Expire at day 20_014, then test 90-day cooldown (`0x14c`)
    assert!(tracker.expire_trial_if_due(&alice, 20_014));
    assert_eq!(
        tracker.start_fee_trial(alice, vip1_mm, cur_base, 0.0, 20_014 + 89, &[]),
        Err(FeeLifecycleError::FeeTrialEndedTooRecently)
    );
    assert!(
        tracker
            .start_fee_trial(alice, vip1_mm, cur_base, 0.0, 20_014 + 90, &[])
            .is_ok()
    );

    // 5. 10-builder per-user approval cap (`0x3c1a510`: `0xa` -> `0x13c`)
    let mut reg = BuilderFeeRegistry::default();
    for i in 1..=MAX_APPROVED_BUILDERS {
        assert_eq!(
            approve_builder_fee_capped(&mut reg, alice, addr(100 + i as u8), 0.0005),
            Ok(())
        );
    }
    // 11th distinct builder rejected (`0x13c`)
    assert_eq!(
        approve_builder_fee_capped(&mut reg, alice, addr(200), 0.0005),
        Err(FeeLifecycleError::TooManyBuildersApproved)
    );
    assert_eq!(
        FeeLifecycleError::TooManyBuildersApproved.status_word(),
        Some(ERR_TOO_MANY_BUILDERS)
    );
    // Updating existing builder or removing via 0.0 succeeds
    assert_eq!(
        approve_builder_fee_capped(&mut reg, alice, addr(101), 0.0002),
        Ok(())
    );
    assert_eq!(
        approve_builder_fee_capped(&mut reg, alice, addr(101), 0.0),
        Ok(())
    );
    assert_eq!(
        approve_builder_fee_capped(&mut reg, alice, addr(200), 0.0005),
        Ok(())
    );
}

#[test]
fn fee_tracker_closure_zero_fee_state_referrer_reward_and_code_registration() {
    use node115_fees::{
        BaseFeeRates, ERR_REFERRAL_CODE_ALREADY_TAKEN, ERR_REFERRAL_CODE_TOO_LONG,
        ERR_REFERRAL_INSUFFICIENT_VOLUME, ERR_REFERRER_CODE_ALREADY_REGISTERED, FeeLifecycleError,
        FeeLifecycleTracker, FeeSchedule, MAX_REFERRAL_CODE_LEN, REFERRER_REWARD_VLM_CAP_RAW,
        REGISTER_REFERRER_MIN_VLM_RAW, StakeDiscountTier, ZERO_FEE_SYSTEM_ADDRESSES,
        is_zero_fee_system_address,
    };

    assert_eq!(REFERRER_REWARD_VLM_CAP_RAW, 100_000_000_000);
    assert_eq!(REGISTER_REFERRER_MIN_VLM_RAW, 1_000_000);
    assert_eq!(MAX_REFERRAL_CODE_LEN, 100);
    for sys in &ZERO_FEE_SYSTEM_ADDRESSES {
        assert!(is_zero_fee_system_address(sys));
    }
    assert!(!is_zero_fee_system_address(&addr(1)));

    let sched = FeeSchedule {
        rates: BaseFeeRates {
            perp_cross: 0.00045,
            perp_add: 0.00015,
            spot_cross: 0.00070,
            spot_add: 0.00040,
        },
        vip_tiers: vec![],
        mm_tiers: vec![],
        referral_discount: 0.04,
        referrer_keep: 0.10,
        destination: addr(99),
        extra_destination_fractions: vec![],
        stake_discount_tiers: vec![
            StakeDiscountTier {
                bps_of_max_supply_staked: 1.0,
                discount: 0.05,
            },
            StakeDiscountTier {
                bps_of_max_supply_staked: 10.0,
                discount: 0.25,
            },
        ],
        weigh_spot_volume_double: true,
    };
    let mut tracker = FeeLifecycleTracker::new(sched, 3_600_000);
    let ref_user = addr(10);
    let trader = addr(11);
    let other = addr(12);

    // 1. user_fee_state (`0x3c18260`): zero-fee system addresses vs default fallback
    let sys_ff = tracker.user_fee_state(&[0xff; 20]);
    assert_eq!(sys_ff.fee_scale, 0.0);
    assert_eq!(sys_ff.rates.perp_cross, 0.0);
    let sys_fe = tracker.user_fee_state(&[0xfe; 20]);
    assert_eq!(sys_fe.fee_scale, 0.0);
    let default_state = tracker.user_fee_state(&trader);
    assert_eq!(default_state.fee_scale, 1.0);
    assert_eq!(default_state.rates.perp_cross, 0.00045);

    // 2. active_staking_discount (`0x3c154d0`) & referrer_reward_fraction (`0x3c15810`)
    assert_eq!(tracker.active_staking_discount(&[0xff; 20], 100.0), 0.0);
    assert_eq!(tracker.active_staking_discount(&ref_user, 10.0), 0.25);
    assert_eq!(tracker.active_staking_discount(&trader, 1.0), 0.05);
    // Spot returns referrer_keep (0.10) under $1B cap
    assert_eq!(
        tracker.referrer_reward_fraction(&ref_user, &trader, 10.0, 1.0, 1.0, true),
        0.10
    );
    // Perp returns max(0.0, fee_scale * (ref_disc - user_disc)) = 1.0 * (0.25 - 0.05) = 0.20
    assert!(
        (tracker.referrer_reward_fraction(&ref_user, &trader, 10.0, 1.0, 1.0, false) - 0.20).abs()
            < 1e-12
    );
    // Crossing $1B cumulative RawVlm cap zeroes referrer reward
    tracker
        .user_states
        .entry(trader)
        .or_default()
        .token_states
        .entry(0)
        .or_default()
        .cum_raw_vlm += REFERRER_REWARD_VLM_CAP_RAW - 1;
    assert_eq!(
        tracker.referrer_reward_fraction(&ref_user, &trader, 10.0, 1.0, 1.0, true),
        0.10
    );
    tracker
        .user_states
        .entry(trader)
        .or_default()
        .token_states
        .entry(0)
        .or_default()
        .cum_raw_vlm += 1;
    assert_eq!(
        tracker.referrer_reward_fraction(&ref_user, &trader, 10.0, 1.0, 1.0, true),
        0.0
    );

    // 3. create_referral_code (`0x3c193d0`): $10k min volume (`0xa9`), len <= 100 (`0xa4`),
    //    user already registered (`0xa8`), duplicate code (`0xa7`), admin override
    assert_eq!(
        tracker.create_referral_code(ref_user, "MYCODE", false),
        Err(FeeLifecycleError::InsufficientVolumeForReferralCode)
    );
    assert_eq!(
        FeeLifecycleError::InsufficientVolumeForReferralCode.status_word(),
        Some(ERR_REFERRAL_INSUFFICIENT_VOLUME)
    );
    tracker
        .user_states
        .entry(ref_user)
        .or_default()
        .token_states
        .entry(0)
        .or_default()
        .cum_raw_vlm += REGISTER_REFERRER_MIN_VLM_RAW;
    let long_code = "A".repeat(MAX_REFERRAL_CODE_LEN + 1);
    assert_eq!(
        tracker.create_referral_code(ref_user, &long_code, false),
        Err(FeeLifecycleError::ReferralCodeTooLong)
    );
    assert_eq!(
        FeeLifecycleError::ReferralCodeTooLong.status_word(),
        Some(ERR_REFERRAL_CODE_TOO_LONG)
    );
    assert_eq!(
        tracker.create_referral_code(ref_user, "MYCODE", false),
        Ok(())
    );
    assert_eq!(
        tracker.create_referral_code(ref_user, "OTHERCODE", false),
        Err(FeeLifecycleError::ReferrerAlreadyRegisteredCode)
    );
    assert_eq!(
        FeeLifecycleError::ReferrerAlreadyRegisteredCode.status_word(),
        Some(ERR_REFERRER_CODE_ALREADY_REGISTERED)
    );
    tracker
        .user_states
        .entry(other)
        .or_default()
        .token_states
        .entry(0)
        .or_default()
        .cum_raw_vlm += REGISTER_REFERRER_MIN_VLM_RAW;
    assert_eq!(
        tracker.create_referral_code(other, "MYCODE", false),
        Err(FeeLifecycleError::ReferralCodeAlreadyTaken)
    );
    assert_eq!(
        FeeLifecycleError::ReferralCodeAlreadyTaken.status_word(),
        Some(ERR_REFERRAL_CODE_ALREADY_TAKEN)
    );
    // Admin bypasses volume check and already-registered check, still enforces <= 100 len
    assert_eq!(
        tracker.create_referral_code(addr(20), "ADMINCODE", true),
        Ok(())
    );
    assert_eq!(
        tracker.create_referral_code(addr(20), &long_code, true),
        Err(FeeLifecycleError::ReferralCodeTooLong)
    );
}
