use node115_position_transition::*;
use std::num::NonZeroU64;

fn sides(first: i64, second: i64) -> [u8; 0x240] {
    let mut bytes = [0; 0x240];
    for (offset, saved, owner) in [(0, first, 0x11), (0x120, second, 0x22)] {
        bytes[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&saved.to_le_bytes());
        bytes[offset + 0xf8..offset + 0x10c].fill(owner);
    }
    bytes
}

fn fill(quantity: u64) -> Fill {
    Fill {
        unit_value: 7,
        quantity,
        added_value: 11,
    }
}

#[test]
fn captures_exact_tag_side_size_and_account() {
    let mut bytes = sides(-9, 13);
    bytes[0x10c] = 0xff;
    bytes[0x217] = 0xee;
    let first = select_side(&bytes, 0).unwrap();
    assert_eq!((first.saved_size, first.account), (-9, [0x11; 20]));
    let second = select_side(&bytes, 1).unwrap();
    assert_eq!((second.saved_size, second.account), (13, [0x22; 20]));
    bytes[0x121] = 1; // the full dword is checked
    assert!(select_side(&bytes, 1).is_none());
    assert!(select_side(&bytes, 0).is_some());
}

#[test]
fn saved_side_selects_value_and_row_size_selects_quantity_counter() {
    let bytes = sides(2, 2);
    let side = select_side(&bytes, 1).unwrap();
    for (origin, expected_counter) in [(Origin::Existing, 4), (Origin::Inserted, 5)] {
        let mut row = Row {
            size: 41,
            value: 99,
        };
        let after = side
            .update(&mut row, origin, fill(5), 4, NonZeroU64::MIN)
            .unwrap();
        assert_eq!(
            (row.value, row.size, after.value),
            (21, 41, expected_counter)
        );
    }
}

#[test]
fn zero_growth_reduction_and_crossing_both_directions() {
    for (old, side, quantity, expected) in [
        (-3, 0, 3, 0),
        (3, 1, 3, 0),
        (0, 0, 0, 0),
        (3, 0, 2, 51),
        (-3, 1, 2, 51),
        (4, 1, 1, 30),
        (-4, 0, 1, 30),
        (3, 1, 5, 14),
        (-3, 0, 5, 14),
        (0, 1, 4, 28),
    ] {
        let mut row = Row { size: 0, value: 40 };
        select_side(&sides(old, old), side)
            .unwrap()
            .update(
                &mut row,
                Origin::Existing,
                fill(quantity),
                0,
                NonZeroU64::MIN,
            )
            .unwrap();
        assert_eq!(row.value, expected, "{old} {side} {quantity}");
    }
}

#[test]
fn reduces_with_division_before_multiplication_in_binary64() {
    let old = (1_i64 << 53) - 1;
    let mut row = Row {
        size: old,
        value: (1_u64 << 52) - 1,
    };
    select_side(&sides(0, old), 1)
        .unwrap()
        .update(
            &mut row,
            Origin::Existing,
            fill((old - 2) as u64),
            0,
            NonZeroU64::MIN,
        )
        .unwrap();
    assert_eq!(row.value, 1); // Exact integer arithmetic would truncate to zero.
}

#[test]
fn saturation_and_refusals_preserve_native_store_order() {
    let mut row = Row {
        size: 9,
        value: u64::MAX - 1,
    };
    select_side(&sides(i64::MAX, 0), 0)
        .unwrap()
        .update(&mut row, Origin::Existing, fill(4), 0, NonZeroU64::MIN)
        .unwrap();
    assert_eq!(row.value, u64::MAX);

    let mut row = Row {
        size: 9,
        value: u64::MAX,
    };
    for (old, qty, unit, error) in [
        (12, 1, 1, Stop::ExistingValueOutOfSignedRange),
        (0, 1, i64::MAX as u64, Stop::CrossingProductOutOfRange),
        (0, 3, u64::MAX, Stop::CrossingProductOutOfRange),
        (0, 1 << 63, 0, Stop::QuantityOutOfSignedRange),
    ] {
        let result = select_side(&sides(0, old), 1).unwrap().update(
            &mut row,
            Origin::Existing,
            Fill {
                unit_value: unit,
                ..fill(qty)
            },
            0,
            NonZeroU64::MIN,
        );
        assert_eq!(result.err(), Some(error));
        assert_eq!((row.value, row.size), (u64::MAX, 9));
    }
}
