use node94_margin_risk::{MarginTable, RawMarginTable, RawMarginTier, position_leverage_cap};

fn table(entries: &[(u64, u8)]) -> MarginTable {
    MarginTable::try_from(RawMarginTable {
        description: String::new(),
        tiers: entries.iter().map(|&(lower_bound, max_leverage)| RawMarginTier {
            lower_bound,
            max_leverage,
        }).collect(),
    }).unwrap()
}

#[test]
fn frozen_native_cap_boundaries_and_unsigned_arguments() {
    let tiers = table(&[(0, 50), (1_000, 20), (1_000_000, 10)]);
    // Literal outputs selected from the pre-Rust external corpus, not a model
    // calculated by the driver. Raw price and size have different signedness.
    for (price, size, cap) in [
        (0, i64::MIN, 50), (999, 1, 50), (1_000, 1, 20),
        (1_001, -1, 20), (7, 142, 50), (7, -143, 20),
        (1, -1, 50), (1, i64::MIN, 10), (1_000_000, 1, 10),
        ((1_u64 << 63) - 2, 1, 10), ((1_u64 << 63) - 1, 1, 10),
        (1_u64 << 63, 2, 10), (u64::MAX, 2, 10), (1_u64 << 32, 1, 10),
    ] {
        assert_eq!(position_leverage_cap(Some(&tiers), price, size), cap);
    }
}

#[test]
fn root_null_and_single_zero_cap_are_distinct() {
    let zero = table(&[(0, 0)]);
    for (price, size) in [(0, 0), (1, -1), (u64::MAX, i64::MIN)] {
        assert_eq!(position_leverage_cap(None, price, size), 50);
        assert_eq!(position_leverage_cap(Some(&zero), price, size), 0);
    }
}

#[test]
fn inclusive_maximum_constructor_bound_selects_later_tier() {
    let tiers = table(&[(0, 25), (1_000_000_000_000_000, 1)]);
    assert_eq!(position_leverage_cap(Some(&tiers), 999_999_999_999_999, 1), 25);
    assert_eq!(position_leverage_cap(Some(&tiers), 1_000_000_000_000_000, -1), 1);
    assert_eq!(position_leverage_cap(Some(&tiers), 1_u64 << 63, 2), 1);
}
