use std::collections::BTreeMap;

use action_dispatch::{
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
