use std::collections::BTreeMap;

use vaults::{
    address::{caller_address, CreateVaultRequest, AMOUNT_BOUND, NAME_LEN_LIMIT},
    amount::{
        accumulate_base_conversion, base_entry_amount, vault_amount, AmountOverflow,
        ConversionMode, ConversionRow, ConversionStop,
    },
    checked_ratio,
    create_context::after_wrapper_checks,
    deposit::{
        leader_share_usd, vault_move_core, DepositorRecord, MoveOutcome, MoveRequest,
        MoveState, ERR_INSUFFICIENT_BALANCE, ERR_LEADER_SHARE_TOO_LOW, ERR_NEGATIVE_VAULT_EQUITY,
        PROTECTED_VAULT_SET_A, PROTECTED_VAULT_SET_B,
    },
    identity_guards::{MODE_ONE_IDENTITY_MISMATCH, POLICY_IDENTITY_MISMATCH},
    redistribution::reweight_value,
    split::{execute_vault_split, SplitEntry, SplitOutcome, SplitRequest, SplitState},
    sub_account::{
        admit_sub_account, max_sub_accounts_for_volume, validate_sub_account_label,
        ExistingSubAccount, SubAccountReject, MIN_VOLUME_RAW, TAG_ERR_DUPLICATE_ADDRESS,
        TAG_ERR_DUPLICATE_LABEL, TAG_ERR_INVALID_LABEL_LEN, TAG_ERR_LIMIT_REACHED,
        TAG_ERR_NAME_TOO_LONG, TAG_ERR_VOLUME_TOO_LOW,
    },
    weight_update::{continuation_after_normal_prepass, Value as WeightValue},
    withdraw::{
        evaluate_withdraw_gate, GateDateTime, WithdrawDepositor, WithdrawGateOutcome,
        WithdrawGateRequest, ERR_EXCEEDS_AVAILABLE, ERR_LEADER_MIN_REMAINING,
        ERR_LEADER_SLACK_VIOLATION, ERR_LOCKUP_NOT_EXPIRED, ERR_MISSING_DEPOSITOR,
        ERR_NONPOSITIVE_VAULT_EQUITY, ERR_RATIO_OUT_OF_RANGE, ERR_REMAINING_BELOW_DUST,
        ERR_VAULT_BELOW_MIN_REMAINING, KIND_RATIO_FLOOR,
    },
};

#[test]
fn protected_vault_sets_match_node115_binary_constants() {
    let hex_of = |a: &[u8; 20]| a.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let want_a = [
        "2e3d94f0562703b25c83308a05046ddaf9a8dd14",
        "b0a55f13d22f66e6d495ac98113841b2326e9540",
        "5e177e5e39c0f4e421f5865a6d8beed8d921cb70",
        "2ed5c4484ea3ff8b57d5f2fb152a40d9f2b68308",
        "6a8750a4cccffdb394a7bbe9d4d0dcef23fb1417",
        "d0761c281945ec084d324415bb0606be2c8df382",
        "cbf4dfba8cdf9558e81553b08f0d7c910b8c4e90",
        "4fbe634d3328b1d56f105b887ed25dcb2c71b88d",
    ];
    let want_b = [
        "010461c14e146ac35fe42271bdc1134ee31c703a",
        "31ca8395cf837de08b24da3f660e77761dfb974b",
        "768484f7e2ebb675c57838366c02ae99ba2a9b08",
        "c64cc00b46101bd40aa1c3121195e85c0b0918d8",
        "07bed5c08306e026797e5ea93c293abc5673c2ad",
        "93e2551d821dda1080a372f0b04b86468320333d",
        "a15099a30bbf2e68942d6f4c43d70d04faeab0a0",
        "dfc24b077bc1425ad1dea75bcb6f8158e10df303",
    ];
    for (got, want) in PROTECTED_VAULT_SET_A.iter().zip(want_a) {
        assert_eq!(hex_of(got), want);
    }
    for (got, want) in PROTECTED_VAULT_SET_B.iter().zip(want_b) {
        assert_eq!(hex_of(got), want);
    }
}

#[test]
fn checked_ratio_matches_0x14ca350_boundaries() {
    assert_eq!(checked_ratio(1.0, 2.0), Some(0.5));
    // Tiny negative strictly greater than -1e-15 clamps to +0.0.
    assert_eq!(checked_ratio(-5e-16, 1e-15), Some(0.0));
    assert_eq!(checked_ratio(-1e-15, 1.0), None);
    assert_eq!(checked_ratio(1.0, 9e-16), None);
    assert_eq!(checked_ratio(f64::NAN, 1.0), None);
    assert_eq!(checked_ratio(1.0, f64::INFINITY), None);
}

#[test]
fn vault_amount_helper_handles_floor_div_100_and_overflows() {
    let r = vault_amount(Some(1_000), 0, 299, true, 0, 100);
    assert_eq!(r.value, 1_003);
    assert!(r.overflows.is_empty());

    // extra_flag bit 0 suppresses extra.
    let r2 = vault_amount(None, -50, 199, true, 1, 500);
    assert_eq!(r2.value, -49);
    assert!(r2.overflows.is_empty());

    // u64 sum overflow + i64 total overflow both recorded.
    let r3 = vault_amount(Some(i64::MAX), 0, u64::MAX, true, 0, 1);
    assert_eq!(r3.value, i64::MAX);
    assert_eq!(r3.overflows, vec![AmountOverflow::Sum, AmountOverflow::Total]);
}

#[test]
fn base_conversion_modes_bounds_and_saturation() {
    let row = ConversionRow {
        tag: 1,
        divisor: 10,
        offset: 5,
        multiplier: -2,
        precision: 3,
    };
    let e = base_entry_amount(row, 100, ConversionMode::CappedDivisor, 4, |_, _, _| 0).unwrap();
    assert_eq!(e.first, -195);
    assert_eq!(e.second, 0);
    assert_eq!(e.magnitude, 200);
    assert_eq!(e.quotient, 50); // 200 / min(10, 4)

    // Mode 4 division by zero halts.
    assert_eq!(
        base_entry_amount(row, 10, ConversionMode::CappedDivisor, 0, |_, _, _| 0),
        Err(ConversionStop::DivideByZeroHalt)
    );
    // Input >= 2^63 panics.
    assert_eq!(
        base_entry_amount(row, 1u64 << 63, ConversionMode::Zero, 1, |_, _, _| 0),
        Err(ConversionStop::UnwrapPanic)
    );

    // Loop index % 10_000 bounds check & skip_flag behavior.
    let items = vec![
        (10_001, ConversionRow { tag: 0, divisor: 2, offset: 0, multiplier: 3, precision: 0 }),
        (20_005, ConversionRow { tag: 1, divisor: 2, offset: 7, multiplier: 1, precision: 0 }),
    ];
    let acc = accumulate_base_conversion(
        10,
        false,
        &items,
        &[100, 20],
        ConversionMode::DirectDivisor,
        10,
        |_, _, _| 0,
    )
    .unwrap();
    // Second item skipped (tag=1, include_tagged=false), first uses values[1] = 20 -> product 60, quotient 30.
    assert_eq!(acc.signed_total, 70);
    assert_eq!(acc.unsigned_second, 30);
    assert_eq!(acc.unsigned_magnitude, 60);
    assert_eq!(acc.signed_offset_total, 10);

    // Enabling include_tagged hits index 5 >= len(2).
    assert_eq!(
        accumulate_base_conversion(10, true, &items, &[100, 20], ConversionMode::Zero, 1, |_, _, _| 0),
        Err(ConversionStop::IndexOutOfBounds { index: 5, len: 2 })
    );
}

#[test]
fn vault_move_core_enforces_identity_protected_sets_and_leader_5_percent() {
    let leader = [0x11; 20];
    let follower = [0x22; 20];
    let vault = [0x33; 20];

    let mut state = MoveState {
        global_balance: 500_000_000,
        entries: BTreeMap::from([(
            leader,
            DepositorRecord {
                weight: 0.06,
                deposited_u64: 60_000_000,
                net_i64: 60_000_000,
                mid: [0; 12],
                timestamp_aux: [0; 12],
            },
        )]),
    };

    // Guard 1: mode 1 mismatch -> 0x16.
    let mut req = MoveRequest {
        depositor: follower,
        leader,
        vault,
        raw_mode: 1,
        policy_byte: 1,
        bypass_leader_check: false,
        amount: 100_000_000,
        depositor_available: 1_000_000_000,
        child_vaults: vec![],
        timestamp_aux: [7; 12],
    };
    assert_eq!(
        vault_move_core(&req, &mut state, |_| 1_000_000_000, |_, _, _, _, _| {}),
        MoveOutcome::Rejected {
            reason: MODE_ONE_IDENTITY_MISMATCH
        }
    );

    // Guard 2: policy 0 mismatch -> 0x17.
    req.raw_mode = 0;
    req.policy_byte = 0;
    assert_eq!(
        vault_move_core(&req, &mut state, |_| 1_000_000_000, |_, _, _, _, _| {}),
        MoveOutcome::Rejected {
            reason: POLICY_IDENTITY_MISMATCH
        }
    );

    // Negative vault equity rejected for regular vault (0x09) but allowed for SET_A.
    req.policy_byte = 1;
    assert_eq!(
        vault_move_core(&req, &mut state, |_| -1, |_, _, _, _, _| {}),
        MoveOutcome::Rejected {
            reason: ERR_NEGATIVE_VAULT_EQUITY
        }
    );
    req.vault = PROTECTED_VAULT_SET_A[0];
    req.bypass_leader_check = true;
    req.depositor_available = 0;
    // Passes negative equity check and reaches insufficient balance (0x2d).
    assert_eq!(
        vault_move_core(&req, &mut state, |_| -1, |_, _, _, _, _| {}),
        MoveOutcome::Rejected {
            reason: ERR_INSUFFICIENT_BALANCE
        }
    );

    // Leader 5% share check: 60M / (1000M + 300M) = 4.615% < 5% -> 0x02.
    req.vault = vault;
    req.bypass_leader_check = false;
    req.depositor_available = 1_000_000_000;
    req.amount = 300_000_000;
    assert!(leader_share_usd(1_000_000_000, 0.06) == 60.0);
    assert_eq!(
        vault_move_core(&req, &mut state, |_| 1_000_000_000, |_, _, _, _, _| {}),
        MoveOutcome::Rejected {
            reason: ERR_LEADER_SHARE_TOO_LOW
        }
    );

    // Protected set B bypasses the 5% leader share check and settles cleanly.
    req.vault = PROTECTED_VAULT_SET_B[0];
    let outcome = vault_move_core(
        &req,
        &mut state,
        |_| 1_000_000_000,
        |st, dep, _amt, _eq, aux| {
            st.entries.entry(dep).or_insert(DepositorRecord {
                weight: 0.2,
                deposited_u64: 0,
                net_i64: 0,
                mid: [0; 12],
                timestamp_aux: aux,
            });
        },
    );
    assert_eq!(
        outcome,
        MoveOutcome::Accepted {
            amount_usd: 300.0,
            vault: PROTECTED_VAULT_SET_B[0],
            vault_equity_before: 1_000_000_000,
            overflows: vec![],
        }
    );
    assert_eq!(state.entries[&follower].deposited_u64, 300_000_000);
    assert_eq!(state.entries[&follower].net_i64, 300_000_000);
    assert_eq!(state.entries[&follower].timestamp_aux, [7; 12]);
}

#[test]
fn withdraw_gate_enforces_lockup_dust_leader_slack_and_kind_floor() {
    let vault = [0xaa; 20];
    let leader = [0xbb; 20];
    let follower = [0xcc; 20];
    let unlock = GateDateTime {
        date_days: 739_000,
        seconds: 100,
        nanos: 0,
    };
    let depositors = BTreeMap::from([
        (
            follower,
            WithdrawDepositor {
                share_fraction: 0.25,
                unlock_time: unlock,
            },
        ),
        (
            leader,
            WithdrawDepositor {
                share_fraction: 0.10,
                unlock_time: unlock,
            },
        ),
    ]);

    let base_req = WithdrawGateRequest {
        vault_tag: 0,
        vault_leader_key: vault,
        self_leader_key: leader,
        depositor: follower,
        child_vaults: vec![],
        request_time: unlock,
        mode: 1,
        requested_amount: 100_000_000,
        available_amount: 250_000_000,
        enforce_min_remaining: true,
        min_remaining_vault: 500_000_000,
        locked_amount: 50_000_000,
        kind_flag: false,
    };

    // Non-positive vault equity -> 0x0A.
    assert_eq!(
        evaluate_withdraw_gate(&base_req, &depositors, |_| 0),
        WithdrawGateOutcome::Rejected {
            code: ERR_NONPOSITIVE_VAULT_EQUITY
        }
    );

    // Missing depositor -> 0x0B.
    let mut missing = base_req.clone();
    missing.depositor = [0xdd; 20];
    assert_eq!(
        evaluate_withdraw_gate(&missing, &depositors, |_| 1_000_000_000),
        WithdrawGateOutcome::Rejected {
            code: ERR_MISSING_DEPOSITOR
        }
    );

    // 1 nanosecond before unlock -> 0x0C.
    let mut early = base_req.clone();
    early.request_time = GateDateTime {
        date_days: 739_000,
        seconds: 99,
        nanos: 999_999_999,
    };
    assert_eq!(
        evaluate_withdraw_gate(&early, &depositors, |_| 1_000_000_000),
        WithdrawGateOutcome::Rejected {
            code: ERR_LOCKUP_NOT_EXPIRED
        }
    );

    // Leaving < 5_000_000 dust -> 0x2A.
    let mut dust = base_req.clone();
    dust.requested_amount = 246_000_000;
    assert_eq!(
        evaluate_withdraw_gate(&dust, &depositors, |_| 1_000_000_000),
        WithdrawGateOutcome::Rejected {
            code: ERR_REMAINING_BELOW_DUST
        }
    );

    // Ratio above share_fraction -> 0x0E; amount > available -> 0x0D.
    let mut too_high = base_req.clone();
    too_high.requested_amount = 260_000_000;
    assert_eq!(
        evaluate_withdraw_gate(&too_high, &depositors, |_| 1_000_000_000),
        WithdrawGateOutcome::Rejected {
            code: ERR_RATIO_OUT_OF_RANGE
        }
    );
    let mut over_avail = base_req.clone();
    over_avail.available_amount = 50_000_000;
    assert_eq!(
        evaluate_withdraw_gate(&over_avail, &depositors, |_| 1_000_000_000),
        WithdrawGateOutcome::Rejected {
            code: ERR_EXCEEDS_AVAILABLE
        }
    );

    // Leader self-withdrawal checks: 5% slack (0x0F) and 100M minimum remaining (0x10).
    let mut self_slack = base_req.clone();
    self_slack.depositor = leader;
    self_slack.requested_amount = 60_000_000; // diff = 0.04 < (1-0.06)*0.05 = 0.047
    assert_eq!(
        evaluate_withdraw_gate(&self_slack, &depositors, |_| 1_000_000_000),
        WithdrawGateOutcome::Rejected {
            code: ERR_LEADER_SLACK_VIOLATION
        }
    );
    let mut self_min_rem = base_req.clone();
    self_min_rem.depositor = leader;
    self_min_rem.requested_amount = 40_000_000; // diff = 0.06 >= 0.048, but 0.06 * 1e9 = 60M < 100M
    assert_eq!(
        evaluate_withdraw_gate(&self_min_rem, &depositors, |_| 1_000_000_000),
        WithdrawGateOutcome::Rejected {
            code: ERR_LEADER_MIN_REMAINING
        }
    );

    // Remaining vault below minimum -> 0x11F.
    let mut min_rem = base_req.clone();
    min_rem.min_remaining_vault = 950_000_000;
    assert_eq!(
        evaluate_withdraw_gate(&min_rem, &depositors, |_| 1_000_000_000),
        WithdrawGateOutcome::Rejected {
            code: ERR_VAULT_BELOW_MIN_REMAINING
        }
    );

    // Valid withdrawal with taken (100M) > locked (50M) clamps shown_ratio up to 0.2.
    assert_eq!(
        evaluate_withdraw_gate(&base_req, &depositors, |_| 1_000_000_000),
        WithdrawGateOutcome::Admitted {
            kind: 1,
            shown_ratio: Some(KIND_RATIO_FLOOR),
            taken: 100_000_000,
            ratio: 0.1,
            vault_equity: 1_000_000_000,
            sum_overflows: 0,
        }
    );
}

#[test]
fn share_split_computes_leader_profit_commission_and_updates_state() {
    let vault = [0x10; 20];
    let leader = [0x20; 20];
    let depositor = [0x30; 20];

    let mut state = SplitState {
        counter: 1_000_000_000,
        entries: BTreeMap::from([(
            depositor,
            SplitEntry {
                share_fraction: 0.5,
                basis_units: 300_000_000,
                net_slot: 300_000_000,
            },
        )]),
    };

    // Vault equity = 1_000M; depositor owns 50% (500M value, 300M basis -> 200M profit).
    // Withdraw half of their share (ratio = 0.25 -> 250M held, 150M basis -> 100M profit).
    // At 10% leader commission: leader gets 10M, depositor keeps 240M.
    let req = SplitRequest {
        vault_tag: 0,
        vault,
        leader,
        depositor,
        child_vaults: vec![],
        ratio: 0.25,
        commission_rate: 0.10,
        limit: 250_000_000,
        first_balance: 500_000_000,
        second_balance: 500_000_000,
    };

    let res = execute_vault_split(&req, &mut state, |_| 1_000_000_000, |_, _, _, _| {});
    let SplitOutcome::Settled(receipt) = res else {
        panic!("expected Settled, got {res:?}");
    };
    assert_eq!(receipt.leader_payout_raw, 10_000_000);
    assert_eq!(receipt.depositor_keep_raw, 240_000_000);
    assert_eq!(receipt.leader_recipient, Some(leader));
    assert_eq!(receipt.leader_commission_usd, 10.0);
    assert_eq!(receipt.depositor_keep_usd, 240.0);
    assert_eq!(receipt.basis_units_usd, 150.0);
    assert_eq!(receipt.closing_gap_usd, 0.0);
    assert_eq!(state.entries[&depositor].basis_units, 150_000_000);
    assert_eq!(state.entries[&depositor].net_slot, 60_000_000);
    // Counter: 1000M - 250M + 10M + 240M = 1000M.
    assert_eq!(state.counter, 1_000_000_000);
}

#[test]
fn sub_account_admission_and_label_guard_match_0x366a620_and_0x366b350() {
    // Volume below 10_000_000 -> 0xec with volume / 100.0.
    let err = admit_sub_account(MIN_VOLUME_RAW - 1, [1; 20], "alpha", &[], false).unwrap_err();
    assert_eq!(err.tag(), TAG_ERR_VOLUME_TOO_LOW);
    assert_eq!(
        err,
        SubAccountReject::VolumeTooLow {
            volume_scaled: 99_999.99
        }
    );

    // Cap formula: 10 + min(volume / 10_000_000_000, 70).
    assert_eq!(max_sub_accounts_for_volume(10_000_000), 10);
    assert_eq!(max_sub_accounts_for_volume(10_000_000_000), 11);
    assert_eq!(max_sub_accounts_for_volume(699_999_999_999), 79);
    assert_eq!(max_sub_accounts_for_volume(700_000_000_000), 80);
    assert_eq!(max_sub_accounts_for_volume(u64::MAX), 80);

    let existing: Vec<ExistingSubAccount> = (0..10)
        .map(|i| ExistingSubAccount {
            address: [i; 20],
            label: format!("Sub{i}"),
        })
        .collect();
    let lim = admit_sub_account(MIN_VOLUME_RAW, [99; 20], "new", &existing, false).unwrap_err();
    assert_eq!(lim.tag(), TAG_ERR_LIMIT_REACHED);

    // Duplicate address -> 0xe7.
    let dup_addr = admit_sub_account(MIN_VOLUME_RAW, [99; 20], "ok", &existing[..1], true).unwrap_err();
    assert_eq!(dup_addr.tag(), TAG_ERR_DUPLICATE_ADDRESS);

    // Name >= 101 bytes -> 0x158 before inner label guard.
    let too_long = "a".repeat(101);
    let long_err = admit_sub_account(MIN_VOLUME_RAW, [99; 20], &too_long, &[], false).unwrap_err();
    assert_eq!(long_err.tag(), TAG_ERR_NAME_TOO_LONG);

    // Inner label guard 0x366b350: 0 bytes and 17 bytes -> 0xe8; case-folded dup -> 0xe6.
    assert_eq!(validate_sub_account_label("", &[]).unwrap_err().tag(), TAG_ERR_INVALID_LABEL_LEN);
    assert_eq!(
        validate_sub_account_label("12345678901234567", &[])
            .unwrap_err()
            .tag(),
        TAG_ERR_INVALID_LABEL_LEN
    );
    assert_eq!(
        validate_sub_account_label("sUb0", &["Sub0"]).unwrap_err().tag(),
        TAG_ERR_DUPLICATE_LABEL
    );
    assert!(validate_sub_account_label("1234567890123456", &["Sub0"]).is_ok());

    // Valid admission succeeds.
    let ok = admit_sub_account(MIN_VOLUME_RAW, [42; 20], "Maker-1", &existing[..1], false).unwrap();
    assert_eq!(ok.address, [42; 20]);
    assert_eq!(ok.label, "Maker-1");
}

#[test]
fn end_to_end_vault_creation_handoff_and_reweight_pipeline() {
    let creator = [0x42; 20];
    let req = CreateVaultRequest {
        max_usdc_fee: Some(AMOUNT_BOUND - 1),
        name: "a".repeat(NAME_LEN_LIMIT),
        description: "Node #115 integrated vault test".to_string(),
        initial_usd: 100_000_000,
        nonce: 1,
    };
    let derived = caller_address(&creator, &req).unwrap();
    let handoff = after_wrapper_checks(creator, derived);
    assert_eq!(
        handoff.prelude(),
        vaults::create_context::existing_guards::PreludeResult::ContinueToNextStage
    );

    // Reweight after initial deposit + follower deposit.
    let mut weights = BTreeMap::from([(
        creator,
        WeightValue {
            ratio: 1.0,
            tail: [0; 40],
        },
    )]);
    continuation_after_normal_prepass(&mut weights, [0x99; 20], 100_000_000, 100_000_000, [5; 12])
        .unwrap();
    assert_eq!(weights[&creator].ratio, 0.5);
    assert_eq!(weights[&[0x99; 20]].ratio, 0.5);
    assert_eq!(reweight_value(100_000_000, 100_000_000, 1.0, false), 0.5);
}
