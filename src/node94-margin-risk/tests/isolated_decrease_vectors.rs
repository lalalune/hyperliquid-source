use node94_margin_risk::{
    CustomIsolatedDecrease as Input, IsolatedDecreaseDecision as Decision,
    IsolatedDecreaseProjectionError as Error, MarginTable, RawMarginTable, RawMarginTier,
    check_custom_isolated_decrease,
};
fn table() -> MarginTable {
    MarginTable::try_from(RawMarginTable {
        description: String::new(),
        tiers: [(0, 50), (1_000, 20), (1_000_000, 10)].into_iter()
            .map(|(lower_bound, max_leverage)| RawMarginTier { lower_bound, max_leverage })
            .collect(),
    }).unwrap()
}
fn input() -> Input {
    Input { metadata_table_id: 50, position_table_id: 50, position_mode_word: 1,
        cross_requested: false, old_leverage: 2, requested_leverage: 1,
        position_size: 1, isolated_margin: -1, price_word: 0 }
}

#[test]
fn strictly_negative_refuses_but_zero_enters_commit() {
    let table = table(); let mut value = input();
    assert_eq!(check_custom_isolated_decrease(&table, value), Ok(Decision::RejectIsolatedMargin));
    value.isolated_margin = 0;
    assert_eq!(check_custom_isolated_decrease(&table, value), Ok(Decision::EnterCommit));
    assert_eq!(Decision::RejectIsolatedMargin.native_refusal(), Some((0x47, None)));
    assert_eq!(Decision::EnterCommit.native_refusal(), None);
}

#[test]
fn shadow_uses_new_divisor_and_original_signed_size_margin_and_price() {
    let table = table(); let mut value = input(); value.price_word = 1;
    // Frozen case49: old divisor2 would change this refusal into EnterCommit.
    assert_eq!(check_custom_isolated_decrease(&table, value), Ok(Decision::RejectIsolatedMargin));
    value.old_leverage = 3; value.requested_leverage = 2;
    assert_eq!(check_custom_isolated_decrease(&table, value), Ok(Decision::EnterCommit));
    // Frozen case98: unsigned magnitude substitution changes the decision.
    value = input(); value.price_word = 1; value.position_size = -1; value.isolated_margin = 1;
    assert_eq!(check_custom_isolated_decrease(&table, value), Ok(Decision::RejectIsolatedMargin));
}

#[test]
fn overall_and_same_price_cap_refusals_precede_shadow() {
    let table = table(); let mut value = input();
    value.old_leverage = 51; value.requested_leverage = 50;
    value.price_word = 1_000; value.position_size = -1; value.isolated_margin = 1_020;
    assert_eq!(check_custom_isolated_decrease(&table, value), Ok(Decision::RejectPositionCap { cap: 20 }));
    assert_eq!(Decision::RejectPositionCap { cap: 20 }.native_refusal(), Some((0x50, Some(20))));
    value.old_leverage = u32::MAX; value.requested_leverage = u32::MAX - 1;
    assert_eq!(check_custom_isolated_decrease(&table, value), Ok(Decision::RejectOverallMaximum));
}

#[test]
fn chosen_scope_errors_are_not_native_refusal_tags() {
    let table = table(); let mut value = input(); value.position_mode_word = 256;
    assert_eq!(check_custom_isolated_decrease(&table, value), Err(Error::NoncanonicalIsolated));
    value = input(); value.requested_leverage = 0;
    assert_eq!(check_custom_isolated_decrease(&table, value), Err(Error::NotPositiveDecrease));
    value = input(); value.price_word = 1_u64 << 63;
    assert_eq!(check_custom_isolated_decrease(&table, value), Err(Error::PriceOutsideSignedRange));
}
