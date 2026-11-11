//! The nonzero-d8 continuation after the recovered order-unlink prefix.
//! Logical map removal and level totals; native tree nodes, allocator failures
//! and later linked-order continuation remain outside this contract.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::collections::BTreeMap;
// Include the unchanged standalone predecessor, including its large raw-result
// enum and ABI-shaped argument list; these allowances apply only to that module.
#[allow(
    dead_code,
    unused_attributes,
    clippy::large_enum_variant,
    clippy::too_many_arguments
)]
#[path = "../node115-book-order-unlink/lib.rs"]
pub mod prior;
use prior::{End, UnlinkStop};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Representation {
    Flat,
    Tree,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Level {
    /// Exact 12-byte key identity: order+f0 and order+dc, with value at row+16.
    /// Rust's physical ordering/storage is not the native map ABI.
    pub entries: BTreeMap<(u64, u32), u64>,
    pub representation: Representation,
    pub quantity: u64,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Removal {
    pub previous_value: Option<u64>,
    pub flattened: bool,
}

/// Must receive the amount captured from element+e0 before the prefix consumed
/// the element. This resumes only SideCall; the prefix's slab, event, cache and
/// external quantity writes are not repeated. Native callers ignore removal's
/// optional return and update level totals even if the key was absent.
pub fn resume(stop: &UnlinkStop, level: &mut Level, saved_quantity: u64) -> Option<Removal> {
    let UnlinkStop::Continued(continued) = stop else {
        return None;
    };
    let End::SideCall(call) = &continued.end else {
        return None;
    };
    let previous_value = level.entries.remove(&(call.field_f0, call.field_dc));
    let flattened = level.representation == Representation::Tree && level.entries.len() <= 31;
    if flattened {
        level.representation = Representation::Flat;
    }
    level.quantity = level.quantity.saturating_sub(saved_quantity);
    level.count = level.count.saturating_sub(1);
    Some(Removal {
        previous_value,
        flattened,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use prior::unlink;

    fn prefix(key: u64, subkey: u32, quantity: u64, tag: u8) -> UnlinkStop {
        let mut element = [0u8; 0x110];
        element[0xd8] = tag;
        element[0xdc..0xe0].copy_from_slice(&subkey.to_le_bytes());
        element[0xe0..0xe8].copy_from_slice(&quantity.to_le_bytes());
        element[0xf0..0xf8].copy_from_slice(&key.to_le_bytes());
        let mut raw_level = [0u8; 0x80];
        raw_level[0x70..0x78].copy_from_slice(&99u64.to_le_bytes());
        raw_level[0x78..0x80].copy_from_slice(&3u64.to_le_bytes());
        let mut count = 1;
        let mut free_head = u64::MAX;
        let mut total = 99;
        let stop = unlink(
            &mut [element],
            &mut count,
            &mut free_head,
            0,
            0,
            &mut total,
            Some(&mut raw_level),
            0,
            1,
        );
        assert_eq!(count, 0);
        assert_eq!(free_head, 0);
        assert_eq!(total, 99u64.saturating_sub(quantity));
        if tag != 0 {
            assert_eq!(&raw_level[0x70..0x78], &99u64.to_le_bytes());
            assert_eq!(&raw_level[0x78..0x80], &3u64.to_le_bytes());
        }
        stop
    }
    #[test]
    fn prior_prefix_to_level_continuation() {
        let stop = prefix(0x1234, 7, 8, 1);
        let mut level = Level {
            entries: BTreeMap::from([((0x1234, 7), 999), ((0x1234, 8), 888), ((1, 7), 777)]),
            representation: Representation::Flat,
            quantity: 99,
            count: 3,
        };
        assert_eq!(
            resume(&stop, &mut level, 8),
            Some(Removal {
                previous_value: Some(999),
                flattened: false
            })
        );
        assert_eq!(
            level.entries,
            BTreeMap::from([((0x1234, 8), 888), ((1, 7), 777)])
        );
        assert_eq!((level.quantity, level.count), (91, 2));
    }
    #[test]
    fn miss_still_updates_totals_and_can_flatten() {
        let stop = prefix(123, 4, 10, 2); // any nonzero byte, not merely tag1
        let mut level = Level {
            entries: BTreeMap::new(),
            representation: Representation::Tree,
            quantity: 3,
            count: 0,
        };
        assert_eq!(
            resume(&stop, &mut level, 10),
            Some(Removal {
                previous_value: None,
                flattened: true
            })
        );
        assert_eq!((level.quantity, level.count), (0, 0));
    }
    #[test]
    fn representation_boundary_uses_post_removal_length() {
        for n in [31, 32, 33, 64, 65] {
            let stop = prefix(0, 9, 0, 1);
            let mut level = Level {
                entries: (0..n).map(|k| ((k, 9), k + 100)).collect(),
                representation: Representation::Tree,
                quantity: 0,
                count: n,
            };
            let got = resume(&stop, &mut level, 0).unwrap();
            assert_eq!(got.flattened, n - 1 <= 31);
            assert_eq!(level.entries.len() as u64, n - 1);
            assert_eq!(level.count, n - 1);
        }
    }
    #[test]
    fn non_sidecall_leaves_level_unchanged() {
        let mut level = Level {
            entries: BTreeMap::new(),
            representation: Representation::Flat,
            quantity: 44,
            count: 4,
        };
        let before = level.clone();
        assert_eq!(resume(&UnlinkStop::Vacant, &mut level, 12), None);
        assert_eq!(level, before);
        assert_eq!(resume(&UnlinkStop::EventFull, &mut level, 12), None);
        assert_eq!(level, before);
    }
}
