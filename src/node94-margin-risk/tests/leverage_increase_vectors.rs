use node94_margin_risk::{
    CustomIncreaseDecision as Decision, CustomIncreaseDomainError as Domain,
    CustomLeverageIncrease as Input, MarginTable, RawMarginTable, RawMarginTier,
    check_custom_leverage_increase,
};
fn table(entries: &[(u64, u8)]) -> MarginTable {
    MarginTable::try_from(RawMarginTable {
        description: String::new(),
        tiers: entries.iter().map(|&(lower_bound, max_leverage)| RawMarginTier {
            lower_bound, max_leverage,
        }).collect(),
    }).unwrap()
}
fn input() -> Input {
    Input { metadata_table_id: 50, position_table_id: 50,
        position_mode_word: 0, old_leverage: 10, position_size: 1_000,
        requested_leverage: 20, price_word: 1, cross_requested: true, kind_byte: 0 }
}

#[test]
fn inclusive_maximum_and_position_cap_are_different_gates() {
    let table = table(&[(0, 50), (1_000, 20), (1_000_000, 10)]);
    let mut value = input();
    assert_eq!(check_custom_leverage_increase(&table, value), Ok(Decision::EnterCommit));
    value.old_leverage = 20; // Exact nondecrease equality reaches the same branch.
    assert_eq!(check_custom_leverage_increase(&table, value), Ok(Decision::EnterCommit));
    value.requested_leverage = 21;
    assert_eq!(check_custom_leverage_increase(&table, value), Ok(Decision::RejectPositionCap { cap: 20 }));
    value.requested_leverage = 51;
    assert_eq!(check_custom_leverage_increase(&table, value), Ok(Decision::RejectOverallMaximum));
    value.requested_leverage = 256; // Full u32, never truncated to a byte.
    assert_eq!(check_custom_leverage_increase(&table, value), Ok(Decision::RejectOverallMaximum));
}

#[test]
fn dword_mode_and_native_refusal_order_are_preserved() {
    let table = table(&[(0, 50), (1_000, 20), (1_000_000, 10)]);
    let mut value = input();
    value.position_mode_word = 256; value.cross_requested = false;
    assert_eq!(check_custom_leverage_increase(&table, value), Ok(Decision::EnterCommit));
    value.cross_requested = true;
    assert_eq!(check_custom_leverage_increase(&table, value), Ok(Decision::RejectAccountingMode));
    value.kind_byte = 1; value.requested_leverage = 51;
    assert_eq!(check_custom_leverage_increase(&table, value), Ok(Decision::RejectCrossKind));
    value = input(); value.position_size = 1_000_000; value.requested_leverage = 11;
    value.cross_requested = false; // Mode mismatch dominates cap10 rejection.
    assert_eq!(check_custom_leverage_increase(&table, value), Ok(Decision::RejectAccountingMode));
}

#[test]
fn unsigned_cap_join_and_single_zero_cap_remain_conditional() {
    let table = table(&[(0, 50), (1_000, 20), (1_000_000, 10)]);
    let mut value = input(); value.position_size = 2; value.price_word = 1_u64 << 63;
    value.requested_leverage = 11;
    assert_eq!(check_custom_leverage_increase(&table, value), Ok(Decision::RejectPositionCap { cap: 10 }));
    let zero = table_for_zero();
    value.old_leverage = 0; value.requested_leverage = 0;
    assert_eq!(check_custom_leverage_increase(&zero, value), Ok(Decision::EnterCommit));
}
fn table_for_zero() -> MarginTable { table(&[(0, 0)]) }

#[test]
fn chosen_domain_refusals_are_separate_from_native_tags() {
    let table = table(&[(0, 50), (1_000, 20), (1_000_000, 10)]);
    let mut value = input(); value.metadata_table_id = 49;
    assert_eq!(check_custom_leverage_increase(&table, value), Err(Domain::BuiltinTableOutsideScope));
    value = input(); value.position_table_id = 51;
    assert_eq!(check_custom_leverage_increase(&table, value), Err(Domain::DifferentPositionTable));
    value = input(); value.position_size = 0;
    assert_eq!(check_custom_leverage_increase(&table, value), Err(Domain::InactivePosition));
    value = input(); value.old_leverage = 21;
    assert_eq!(check_custom_leverage_increase(&table, value), Err(Domain::RequestedDecrease));
}
