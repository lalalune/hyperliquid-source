//! Logical cache-budget and byte-key selection for one node #115 open body.
//!
//! The body is the unwind extent `0x4524660..0x4524adb` in Linux x86-64 node
//! #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//! It is associated with `db/src/owned_db_home.rs:72:37` and
//! `db/src/rocks_db.rs:58:49`.
//!
//! These functions are the observed arithmetic and tree relation. They are not
//! the original RocksDB calling convention, object layout, or a database open.

#![no_std]

/// Default argument passed to the size builder when the caller's low flag bit is clear.
/// `0x800 << 20` is 2 GiB. The sibling open at `0x57c6530` uses `0x4000 << 20` instead.
pub const DEFAULT_CACHE_BUDGET: u64 = 0x800 << 20;

/// Immediate passed to the relocated block-size setter `0x5d34c40`.
pub const BLOCK_SIZE: u32 = 0x4000;

/// Immediate passed to the relocated setter `0x5d34c50`.
pub const OPTIONS_FLAG: u32 = 1;

/// Immediate passed to the relocated setter `0x5d34c60`.
pub const COMPANION_BYTES: u32 = 0x0800_0000;

/// Word that takes the `rocks_db.rs:58` unwrap arm after `cmp` with zero and `jo`.
pub const ERROR_NICHE: u64 = 0x8000_0000_0000_0000;

/// Cache-size argument selected before the relocated builder `0x5d35250`.
///
/// Only `flag & 1` is read. A clear bit ignores `value` and returns
/// [`DEFAULT_CACHE_BUDGET`]. A set bit returns `value << 30` when
/// `value < 2^34`, and `u64::MAX` when the native `>> 54` or post-shift
/// `>> 44` check would saturate.
pub fn cache_budget(flag: u8, value: u64) -> u64 {
    if flag & 1 == 0 {
        return DEFAULT_CACHE_BUDGET;
    }
    if value >= 1 << 34 {
        return u64::MAX;
    }
    value << 30
}

/// True when the open result's first word takes the unwrap failure arm.
pub fn result_word_is_error_niche(word: u64) -> bool {
    word == ERROR_NICHE
}

/// One in-memory node. `keys` is the zero-extended `u16` count at `+0x62`.
/// `children` has `keys.len() + 1` slots, matching child index `0..=count`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyNode {
    pub keys: &'static [u8],
    pub children: &'static [Option<&'static KeyNode>],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Matched key position. The native value pointer is `[node+8+8*index]`.
    Hit { index: usize },
    /// Null root, or a descent whose height qword borrows.
    Miss,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelError {
    /// The native count load is a `u16`. Longer slices are outside that encoding.
    CountExceedsU16,
    /// A valid child vector has one more slot than `keys`.
    ChildShape,
    /// The native load of a missing child is not the miss literal.
    NullChild,
}

/// Byte-key descent used before this open.
///
/// `height` is the qword at context `+0x20`. It is decremented only when a
/// child is followed. A hit does not read it. Ordering uses the unsigned byte
/// comparison (`query > key` continues; equality selects; a lesser query or
/// exhaustion descends).
pub fn lookup(
    root: Option<&'static KeyNode>,
    mut height: u64,
    key: u8,
) -> Result<Lookup, ModelError> {
    let Some(mut node) = root else {
        return Ok(Lookup::Miss);
    };
    loop {
        if node.keys.len() > u16::MAX as usize {
            return Err(ModelError::CountExceedsU16);
        }
        let count = node.keys.len();
        if node.children.len() != count + 1 {
            return Err(ModelError::ChildShape);
        }
        let neg = (count as u64).wrapping_neg();
        let mut index = u64::MAX;
        let child = loop {
            if neg.wrapping_add(index) == u64::MAX {
                break count;
            }
            let loaded = node.keys[index.wrapping_add(1) as usize];
            let order = if key < loaded {
                -1
            } else if key > loaded {
                1
            } else {
                0
            };
            index = index.wrapping_add(1);
            if order == 1 {
                continue;
            }
            if order == 0 {
                return Ok(Lookup::Hit {
                    index: index as usize,
                });
            }
            break index as usize;
        };
        if height == 0 {
            return Ok(Lookup::Miss);
        }
        height -= 1;
        node = match node.children[child] {
            Some(next) => next,
            None => return Err(ModelError::NullChild),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEAF_1: KeyNode = KeyNode {
        keys: &[1],
        children: &[None, None],
    };
    const LEAF_4: KeyNode = KeyNode {
        keys: &[4],
        children: &[None, None],
    };
    const LEAF_9: KeyNode = KeyNode {
        keys: &[9],
        children: &[None, None],
    };
    const ROOT: KeyNode = KeyNode {
        keys: &[2, 5],
        children: &[Some(&LEAF_1), Some(&LEAF_4), Some(&LEAF_9)],
    };

    #[test]
    fn clear_flag_ignores_value_and_is_not_the_sibling_default() {
        let sibling_default = 0x4000_u64 << 20;
        assert_ne!(DEFAULT_CACHE_BUDGET, sibling_default);
        assert_eq!(DEFAULT_CACHE_BUDGET, 2_147_483_648);
        for value in [0, 1, (1 << 34) - 1, 1 << 34, 1 << 54, u64::MAX] {
            assert_eq!(cache_budget(0, value), DEFAULT_CACHE_BUDGET);
            assert_eq!(cache_budget(2, value), DEFAULT_CACHE_BUDGET);
            assert_eq!(cache_budget(0xfe, value), DEFAULT_CACHE_BUDGET);
        }
    }

    #[test]
    fn set_flag_shifts_by_thirty_until_the_saturation_boundary() {
        assert_eq!(cache_budget(1, 0), 0);
        assert_eq!(cache_budget(1, 1), 1 << 30);
        assert_eq!(cache_budget(1, 1 << 33), 1 << 63);
        assert_eq!(cache_budget(0xff, 3), 3 << 30);
        let below = (1 << 34) - 1;
        assert_eq!(cache_budget(1, below), below << 30);
        assert_eq!(cache_budget(1, 1 << 34), u64::MAX);
        assert_eq!(cache_budget(1, (1 << 54) - 1), u64::MAX);
        assert_eq!(cache_budget(1, 1 << 54), u64::MAX);
        assert_eq!(cache_budget(1, u64::MAX), u64::MAX);
    }

    #[test]
    fn only_the_signed_min_word_is_the_unwrap_niche() {
        assert!(result_word_is_error_niche(ERROR_NICHE));
        assert!(!result_word_is_error_niche(0));
        assert!(!result_word_is_error_niche(1));
        assert!(!result_word_is_error_niche(ERROR_NICHE - 1));
        assert!(!result_word_is_error_niche(ERROR_NICHE + 1));
        assert!(!result_word_is_error_niche(u64::MAX));
    }

    #[test]
    fn null_root_misses_without_using_height() {
        assert_eq!(lookup(None, 0, 0), Ok(Lookup::Miss));
        assert_eq!(lookup(None, u64::MAX, 255), Ok(Lookup::Miss));
    }

    #[test]
    fn hits_do_not_consume_height_and_select_the_first_equal_key() {
        assert_eq!(lookup(Some(&ROOT), 0, 2), Ok(Lookup::Hit { index: 0 }));
        assert_eq!(lookup(Some(&ROOT), 0, 5), Ok(Lookup::Hit { index: 1 }));
        const DUP: KeyNode = KeyNode {
            keys: &[7, 7],
            children: &[None, None, None],
        };
        assert_eq!(lookup(Some(&DUP), 0, 7), Ok(Lookup::Hit { index: 0 }));
    }

    #[test]
    fn descent_uses_one_height_unit_and_the_child_index() {
        assert_eq!(lookup(Some(&ROOT), 1, 1), Ok(Lookup::Hit { index: 0 }));
        assert_eq!(lookup(Some(&ROOT), 1, 4), Ok(Lookup::Hit { index: 0 }));
        assert_eq!(lookup(Some(&ROOT), 1, 9), Ok(Lookup::Hit { index: 0 }));
        assert_eq!(lookup(Some(&ROOT), 0, 1), Ok(Lookup::Miss));
        assert_eq!(lookup(Some(&ROOT), 0, 6), Ok(Lookup::Miss));
        assert_eq!(lookup(Some(&ROOT), 0, 0), Ok(Lookup::Miss));
        assert_eq!(lookup(Some(&ROOT), 1, 3), Ok(Lookup::Miss));
        assert_eq!(lookup(Some(&ROOT), 1, 0), Ok(Lookup::Miss));
        assert_eq!(lookup(Some(&ROOT), 1, 6), Ok(Lookup::Miss));
        assert_eq!(
            lookup(Some(&ROOT), u64::MAX, 9),
            Ok(Lookup::Hit { index: 0 })
        );
    }

    #[test]
    fn empty_node_descends_through_child_zero() {
        const EMPTY: KeyNode = KeyNode {
            keys: &[],
            children: &[Some(&LEAF_9)],
        };
        assert_eq!(lookup(Some(&EMPTY), 1, 9), Ok(Lookup::Hit { index: 0 }));
        assert_eq!(lookup(Some(&EMPTY), 0, 9), Ok(Lookup::Miss));
    }

    #[test]
    fn endpoint_bytes_follow_the_same_ordering() {
        const ENDS: KeyNode = KeyNode {
            keys: &[0, 255],
            children: &[None, None, None],
        };
        assert_eq!(lookup(Some(&ENDS), 0, 0), Ok(Lookup::Hit { index: 0 }));
        assert_eq!(lookup(Some(&ENDS), 0, 255), Ok(Lookup::Hit { index: 1 }));
        assert_eq!(lookup(Some(&ENDS), 0, 1), Ok(Lookup::Miss));
    }

    #[test]
    fn shape_and_null_child_are_not_the_miss_literal() {
        const WIDE: KeyNode = KeyNode {
            keys: &[1],
            children: &[None],
        };
        assert_eq!(lookup(Some(&WIDE), 1, 0), Err(ModelError::ChildShape));
        const HOLE: KeyNode = KeyNode {
            keys: &[1],
            children: &[None, None],
        };
        assert_eq!(lookup(Some(&HOLE), 1, 0), Err(ModelError::NullChild));
    }

    #[test]
    fn recorded_option_immediates_stay_attached_to_this_body() {
        assert_eq!(BLOCK_SIZE, 0x4000);
        assert_eq!(OPTIONS_FLAG, 1);
        assert_eq!(COMPANION_BYTES, 0x0800_0000);
    }
}
