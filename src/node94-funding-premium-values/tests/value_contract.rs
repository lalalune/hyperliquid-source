use node94_funding_premium_values::{Book, Entry, Input, Refusal, Slot, evaluate};

fn entry(key: i64, head: u64) -> Entry {
    Entry {
        key,
        active: 1,
        head,
    }
}

fn slot(quantity: u64) -> Slot {
    Slot {
        tag: 0,
        quantity,
        continuation: 0,
        next: u64::MAX,
    }
}

fn input<'a>(first: &'a [Entry], second: &'a [Entry], slots: &'a [Slot]) -> Input<'a> {
    Input {
        asset: u64::MAX,
        oracle: 100,
        target: 100,
        scale: 6,
        mode: 0,
        divide_by_100: false,
        book: Book {
            first,
            second,
            slots,
        },
    }
}

#[test]
fn both_trees_share_slots_and_modes_remain_distinct() {
    let first = [entry(50, 0)];
    let second = [entry(100, 1)];
    let slots = [
        Slot {
            quantity: 1,
            continuation: 1,
            next: 1,
            tag: 0,
        },
        slot(1),
    ];
    let mut request = input(&first, &second, &slots);
    let result = evaluate(request).unwrap();
    let premium = result.premium.unwrap();
    assert_eq!((premium.first_impact, premium.second_impact), (50, 100));
    assert_eq!(premium.bits, 0xbfd0_0000_0000_0000);
    assert_eq!(
        (
            result.record.asset,
            result.record.tag,
            result.record.payload
        ),
        (u64::MAX, 0, premium.bits)
    );
    request.mode = 255;
    assert_eq!(evaluate(request).unwrap().premium.unwrap().bits, 0);
}

#[test]
fn scale_then_oracle_then_target_policy_order() {
    let entries = [entry(100, 0)];
    let slots = [Slot {
        continuation: 1,
        next: 0,
        ..slot(1)
    }];
    let mut request = input(&entries, &entries, &slots);
    request.oracle = 0;
    request.target = 0;
    request.scale = 7;
    assert_eq!(evaluate(request), Err(Refusal::InvalidScale));
    request.scale = 6;
    let absent = evaluate(request).unwrap();
    assert_eq!(absent.premium, None);
    assert_eq!((absent.record.tag, absent.record.payload), (1, 0));
    request.oracle = 1;
    assert_eq!(evaluate(request), Err(Refusal::ZeroTarget));
}

#[test]
fn second_cycle_policy_is_checked_after_zero_first_impact() {
    // New safe-policy witness; this does not claim native equivalence on cycles.
    let second = [entry(100, 0)];
    let slots = [Slot {
        continuation: 1,
        next: 0,
        ..slot(1)
    }];
    assert_eq!(
        evaluate(input(&[], &second, &slots)),
        Err(Refusal::CycleSecond)
    );
    assert_eq!(
        evaluate(input(&second, &[], &slots)),
        Err(Refusal::CycleFirst)
    );
}

#[test]
fn whole_product_cap_precedes_partial_fill_and_preserves_raw_fallback() {
    let entries = [entry(i64::MAX, 0)];
    let slots = [slot(1)];
    let mut request = input(&entries, &entries, &slots);
    request.target = i64::MAX as u64;
    request.oracle = (1 << 63) + 1;
    let result = evaluate(request).unwrap();
    assert_eq!(result.premium, None);
    assert_eq!(
        (result.record.tag, result.record.payload),
        (1, (1 << 63) + 1)
    );
}

#[test]
fn terminal_floor_retains_previous_cost_quantity_and_actual_order() {
    let first = [entry(3, 0), entry(7, 1)];
    let second = [entry(3, 2)];
    let slots = [slot(2), slot(2), slot(4)];
    let mut request = input(&first, &second, &slots);
    request.target = 10;
    assert_eq!(evaluate(request).unwrap().premium.unwrap().first_impact, 3);
    let reversed = [entry(7, 1), entry(3, 0)];
    request.book.first = &reversed;
    assert_eq!(evaluate(request).unwrap().premium.unwrap().first_impact, 7);
}

#[test]
fn initial_and_later_bounds_and_native_field_widths_differ() {
    let first = [entry(50, 0)];
    let second = [entry(100, 1)];
    let slots = [
        Slot {
            tag: 258,
            quantity: 1,
            continuation: 256,
            next: 1,
        },
        Slot {
            continuation: 1,
            next: u64::MAX,
            ..slot(1)
        },
    ];
    let mut request = input(&first, &second, &slots);
    assert_eq!(evaluate(request).unwrap().premium.unwrap().first_impact, 50);
    let invalid = [entry(100, u64::MAX), entry(100, 1)];
    request.book.first = &invalid;
    assert_eq!(evaluate(request).unwrap().premium, None);
}

#[test]
fn zero_price_and_chain_saturation_are_not_discarded_or_wrapped() {
    let first = [entry(0, 0), entry(1, 1)];
    let second = [entry(1, 2)];
    let slots = [slot(u64::MAX), slot(2), slot(1)];
    let mut request = input(&first, &second, &slots);
    request.target = 1;
    assert_eq!(evaluate(request).unwrap().premium, None);
    let chained = [entry(1, 0)];
    let slots = [
        Slot {
            continuation: 1,
            next: 1,
            ..slot(u64::MAX)
        },
        slot(2),
        slot(1),
    ];
    request.book.first = &chained;
    request.book.slots = &slots;
    assert_eq!(evaluate(request).unwrap().premium, None);
}

#[test]
fn signed_keys_tag2_and_unused_cycles_keep_distinct_meaning() {
    let first = [entry(-100, 0), entry(1, 2)];
    let second = [entry(100, 0)];
    let slots = [
        Slot {
            continuation: 1,
            next: 1,
            ..slot(1)
        },
        Slot {
            tag: 2,
            quantity: u64::MAX,
            continuation: 1,
            next: 2,
        },
        Slot {
            continuation: 1,
            next: 2,
            ..slot(1)
        },
    ];
    let mut request = input(&first, &second, &slots);
    assert_eq!(
        evaluate(request).unwrap().premium.unwrap().first_impact,
        100
    );
    let minimum = [entry(i64::MIN, 0)];
    request.book.first = &minimum;
    assert_eq!(evaluate(request).unwrap().premium, None);
}

#[test]
fn rounded_unsigned_scale_uses_two_boundaries() {
    // Frozen pre-source case0xb53, independent Fraction oracle.
    let first = [entry(1000, 0)];
    let second = [entry(1001, 1)];
    let slots = [slot(2), slot(1)];
    let mut request = input(&first, &second, &slots);
    request.oracle = (1 << 53) + 1;
    request.target = 1001;
    request.scale = 0;
    request.divide_by_100 = true;
    assert_eq!(
        evaluate(request).unwrap().premium.unwrap().bits,
        0xbf84_7ae1_47ae_11fa
    );
}

#[test]
fn division_precedes_clamp_and_nonzero_mode_is_not_only_one() {
    // Frozen cases0x7f and0x95 retain their different rounding paths.
    let entries = [entry(1, 0)];
    let slots = [slot(1)];
    let mut request = input(&entries, &entries, &slots);
    request.oracle = 3;
    request.target = 1;
    request.scale = 0;
    request.divide_by_100 = true;
    assert_eq!(
        evaluate(request).unwrap().premium.unwrap().bits,
        0xbf7b_4e81_b4e8_1b4f
    );
    request.scale = 3;
    request.mode = 255;
    assert_eq!(
        evaluate(request).unwrap().premium.unwrap().bits,
        0xbf7b_4e81_b4e8_1b4e
    );
}
