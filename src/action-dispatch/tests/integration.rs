use std::collections::{BTreeMap, BTreeSet};

use action_dispatch::{
    admission::{
        check_timed_router_arm_guard, classify_action_tag, run_prior_key_wrapper,
        ClassifierAction, PriorKeyWrapperOutcome, TimedRouterGuardOutcome,
        NO_0X120_HANDLER_INDICES, PRIOR_KEY_CLONE_INDICES, PRIOR_KEY_REJECT_CODE,
        TIMED_ROUTER_ARM61_OVERFLOW_CODE, TIMED_ROUTER_ARM75_DISABLED_CODE,
        TIMED_ROUTER_CTX_B9A_REJECT_CODE, TIMED_ROUTER_CTX_B9A_REJECT_VALUE,
        TIMED_ROUTER_MAX_CWITHDRAW_WORD,
    },
    builder_approval::{approve, Status as BuilderStatus},
    display_name_state::{set_name, Status as DisplayStatus},
    router::{
        arm_for_tag, is_gated_by_flag_50, route_action, ArgShape, LatencySpan,
        FLAG_50_GATE_MASK, ROUTER_ARMS, ROUTER_FEATURE_FLAG_ID, TIMER_SKIPPED_SENTINEL,
    },
};

#[test]
fn router_table_matches_0x2bda7c0_92_arms_and_flag_50_mask() {
    assert_eq!(ROUTER_ARMS.len(), 92);
    let mut gated_indices = Vec::new();
    let mut arg_none = 0;
    let mut arg_tag = 0;
    let mut arg_plus8 = 0;
    let mut arg_loads = 0;

    for (i, arm) in ROUTER_ARMS.iter().enumerate() {
        assert_eq!(arm.index, i);
        assert_eq!(arm.gated_by_flag_50, is_gated_by_flag_50(i));
        if arm.gated_by_flag_50 {
            gated_indices.push(i);
        }
        match arm.arg_shape {
            ArgShape::None => arg_none += 1,
            ArgShape::TagPointer => arg_tag += 1,
            ArgShape::TagPointerPlus8 => arg_plus8 += 1,
            ArgShape::PayloadLoads { .. } => arg_loads += 1,
        }
    }
    assert_eq!(FLAG_50_GATE_MASK, 0x501d);
    assert_eq!(gated_indices, vec![0, 2, 3, 4, 12, 14]);
    assert_eq!((arg_none, arg_tag, arg_plus8, arg_loads), (4, 1, 80, 7));

    // Niche tag < 0x86 routes to VoteGlobal (index 20, 0x2c1da50, TagPointer).
    let niche = arm_for_tag(0x05).unwrap();
    assert_eq!(niche.index, 20);
    assert_eq!(niche.handler_va, 0x2c1da50);
    assert_eq!(niche.arg_shape, ArgShape::TagPointer);
    assert_eq!(niche.variant().variant_name, "VoteGlobal");

    // Out-of-bounds tag returns None.
    assert!(arm_for_tag(0xe2).is_none());
}

#[test]
fn route_action_honors_flag_50_gate_and_timer_sentinel() {
    // Order (tag 0x94, index 14) is gated by flag 50.
    // When flag 50 is false, timer is skipped (0 clock calls).
    let mut ticks = 0u64;
    let r_off = route_action(
        0x94,
        |id| {
            assert_eq!(id, ROUTER_FEATURE_FLAG_ID);
            false
        },
        || {
            ticks += 1;
            (ticks, 0)
        },
        |arm| arm.variant().wire_name,
    )
    .unwrap();
    assert!(r_off.queried_flag_50);
    assert_eq!(r_off.latency, None);
    assert_eq!(ticks, 0);
    assert_eq!(r_off.output, "order");

    // When flag 50 is true, timer reads start and end clock.
    let r_on = route_action(
        0x94,
        |_| true,
        || {
            ticks += 1;
            (100 + ticks, 500)
        },
        |arm| arm.variant().wire_name,
    )
    .unwrap();
    assert!(r_on.queried_flag_50);
    assert_eq!(
        r_on.latency,
        Some(LatencySpan {
            start: (101, 500),
            end: (102, 500)
        })
    );

    // Non-gated action (SetDisplayName, tag 0x99, index 19) does NOT query flag 50.
    let r_ungated = route_action(
        0x99,
        |_| panic!("flag 50 must not be queried for index 19"),
        || (200, TIMER_SKIPPED_SENTINEL),
        |arm| arm.variant().wire_name,
    )
    .unwrap();
    assert!(!r_ungated.queried_flag_50);
    assert_eq!(r_ungated.latency, None);
    assert_eq!(r_ungated.output, "setDisplayName");
}

#[test]
fn handler_micro_crates_compose_under_action_dispatch() {
    // Display name state (0x2c08600 family).
    let mut names: BTreeMap<[u8; 20], String> = BTreeMap::new();
    let user = [0x11; 20];
    assert_eq!(
        set_name(&mut names, user, "Alice".to_string()),
        DisplayStatus::Accepted
    );
    assert_eq!(names.get(&user).map(String::as_str), Some("Alice"));

    // Builder approval (0x3c1a510).
    let mut approvals: BTreeMap<[u8; 20], BTreeMap<[u8; 20], u64>> = BTreeMap::new();
    let builder = [0x22; 20];
    assert_eq!(
        approve(&mut approvals, user, builder, 50),
        BuilderStatus::Accepted
    );
    assert_eq!(approvals[&user][&builder], 50);
}

#[test]
fn prior_key_wrapper_enforces_override_alias_btree_and_dual_checks() {
    assert_eq!(PRIOR_KEY_CLONE_INDICES.len(), 10);
    assert_eq!(NO_0X120_HANDLER_INDICES, [3, 4, 18, 35]);

    let mut ok_slot = [0u8; 0x70];
    ok_slot[0..2].copy_from_slice(&0x1a2u16.to_le_bytes());
    let mut err_slot = [0u8; 0x70];
    err_slot[0..2].copy_from_slice(&0x00cbu16.to_le_bytes());

    let user = [0x11; 20];
    let alias = [0x22; 20];
    let override_addr = [0x33; 20];
    let aliases = [(user, alias)];

    // Prior-key hit on resolved alias rejects with 0x0f / 0x120 before check1/check2.
    let prior = BTreeSet::from([alias]);
    let rej = run_prior_key_wrapper(
        user,
        None,
        &aliases,
        &prior,
        |_| panic!("check1 must not run after prior-key rejection"),
        |_| panic!("check2 must not run after prior-key rejection"),
        |_| 0u8,
    );
    assert_eq!(
        rej,
        PriorKeyWrapperOutcome::PriorKeyRejected {
            tag_byte: 0x0f,
            code: PRIOR_KEY_REJECT_CODE,
        }
    );

    // Override from 0x2a8ab70 bypasses B-tree check and proceeds to check1/check2/sink.
    let dis = run_prior_key_wrapper(
        user,
        Some(override_addr),
        &aliases,
        &prior,
        |k| {
            assert_eq!(k, override_addr);
            ok_slot
        },
        |k| {
            assert_eq!(k, override_addr);
            ok_slot
        },
        |orig| orig,
    );
    assert_eq!(
        dis,
        PriorKeyWrapperOutcome::Dispatched {
            effective_key: override_addr,
            output: user,
        }
    );

    // First check failure returns FirstCheckFailed without calling check2 or sink.
    let empty_prior = BTreeSet::new();
    let f1 = run_prior_key_wrapper(
        user,
        None,
        &aliases,
        &empty_prior,
        |_| err_slot,
        |_| panic!("check2 must not run after check1 failure"),
        |_| 0u8,
    );
    assert_eq!(
        f1,
        PriorKeyWrapperOutcome::FirstCheckFailed {
            tag_byte: 0x0f,
            error_tag: 0x00cb,
            payload: err_slot,
        }
    );

    // Second check failure returns SecondCheckFailed without calling sink.
    let f2 = run_prior_key_wrapper(
        user,
        None,
        &aliases,
        &empty_prior,
        |_| ok_slot,
        |_| err_slot,
        |_| 0u8,
    );
    assert_eq!(
        f2,
        PriorKeyWrapperOutcome::SecondCheckFailed {
            tag_byte: 0x0f,
            error_tag: 0x00cb,
            payload: err_slot,
        }
    );
}

#[test]
fn timed_router_guards_and_action_tag_classifier_match_node115() {
    // Timed router 0x55f99b0 special arms.
    assert_eq!(
        check_timed_router_arm_guard(0, 0, 0, 0),
        TimedRouterGuardOutcome::ImmediateOk { tag_byte: 0x0e }
    );
    assert_eq!(
        check_timed_router_arm_guard(52, 0, 0, 0),
        TimedRouterGuardOutcome::RecurseMultiSig
    );
    assert_eq!(
        check_timed_router_arm_guard(61, 0, 1, TIMED_ROUTER_MAX_CWITHDRAW_WORD - 1),
        TimedRouterGuardOutcome::DispatchHandler
    );
    assert_eq!(
        check_timed_router_arm_guard(61, 0, 1, TIMED_ROUTER_MAX_CWITHDRAW_WORD),
        TimedRouterGuardOutcome::InlineError {
            tag_byte: 0x0f,
            code: TIMED_ROUTER_ARM61_OVERFLOW_CODE,
        }
    );
    for arm in [63, 64] {
        assert_eq!(
            check_timed_router_arm_guard(arm, TIMED_ROUTER_CTX_B9A_REJECT_VALUE, 1, 0),
            TimedRouterGuardOutcome::InlineError {
                tag_byte: 0x0f,
                code: TIMED_ROUTER_CTX_B9A_REJECT_CODE,
            }
        );
    }
    assert_eq!(
        check_timed_router_arm_guard(75, 0, 0, 0),
        TimedRouterGuardOutcome::InlineError {
            tag_byte: 0x0f,
            code: TIMED_ROUTER_ARM75_DISABLED_CODE,
        }
    );
    assert_eq!(
        check_timed_router_arm_guard(75, 0, 1, 0),
        TimedRouterGuardOutcome::DispatchHandler
    );

    // Tag classifier 0x36c30f0 (arms 3, 4, 18, 35 -> true; 14 -> all(); 52 -> recurse; default -> false).
    for tag in [0x89u64, 0x8a, 0x98, 0xa9] {
        assert_eq!(
            classify_action_tag(&ClassifierAction::Leaf {
                tag,
                flag_byte: false,
                order_flags: &[],
            }),
            Some(true)
        );
    }
    // Order (tag 0x94, idx 14): empty -> true, all true -> true, any false -> false.
    assert_eq!(
        classify_action_tag(&ClassifierAction::Leaf {
            tag: 0x94,
            flag_byte: false,
            order_flags: &[],
        }),
        Some(true)
    );
    assert_eq!(
        classify_action_tag(&ClassifierAction::Leaf {
            tag: 0x94,
            flag_byte: false,
            order_flags: &[true, false],
        }),
        Some(false)
    );
    // MultiSig recursion delegates to inner action.
    let inner = ClassifierAction::Leaf {
        tag: 0x89,
        flag_byte: false,
        order_flags: &[],
    };
    assert_eq!(classify_action_tag(&ClassifierAction::MultiSig(&inner)), Some(true));
    // Default arm (Noop, tag 0x86) -> false; out-of-range tag 0xe2 -> None.
    assert_eq!(
        classify_action_tag(&ClassifierAction::Leaf {
            tag: 0x86,
            flag_byte: true,
            order_flags: &[],
        }),
        Some(false)
    );
    assert_eq!(
        classify_action_tag(&ClassifierAction::Leaf {
            tag: 0xe2,
            flag_byte: false,
            order_flags: &[],
        }),
        None
    );
}
