//! Node #115 tag10 rollback zero/absent-entry branches, complementing #4363.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::collections::BTreeMap;
pub type Address = [u8; 20];
pub type Word = [u8; 32];
pub type Transient = BTreeMap<Address, BTreeMap<Word, Word>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Journal {
    pub address: Address,
    pub key: Word,
    pub old: Word,
}
impl Journal {
    /// The target's selected fixed record; other tags/layouts are excluded.
    pub fn decode(bytes: &[u8; 88]) -> Option<Self> {
        if bytes[0] != 10 {
            return None;
        }
        let mut address = [0; 20];
        address.copy_from_slice(&bytes[1..21]);
        let mut key = [0; 32];
        key.copy_from_slice(&bytes[24..56]);
        let mut old = [0; 32];
        old.copy_from_slice(&bytes[56..88]);
        Some(Self { address, key, old })
    }
}

/// The handler borrows the journal; journal-pop/commit ownership is outside it.
/// Zero old value removes only the inner key and retains an empty outer entry.
/// Nonzero old value inserts missing address/key entries or restores an existing
/// value. None corresponds to the native null transient-context no-op.
pub fn restore(context: Option<&mut Transient>, record: &Journal) {
    let Some(context) = context else {
        return;
    };
    if record.old == [0; 32] {
        if let Some(inner) = context.get_mut(&record.address) {
            inner.remove(&record.key);
        }
    } else {
        context
            .entry(record.address)
            .or_default()
            .insert(record.key, record.old);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidControls {
    Shape,
    NotOccupied,
    EmptyCount,
    CounterOverflow,
}

/// Apply the observed erase metadata of 0x5be1140 to a valid occupied slot.
/// Controls include the native 16-byte trailing mirror/padding group. Probing,
/// payload movement, hashing and allocation are separate contracts.
pub fn erase_controls(
    controls: &mut [u8],
    mask: usize,
    slot: usize,
    growth_left: &mut u64,
    items: &mut u64,
) -> Result<u8, InvalidControls> {
    let buckets = mask.checked_add(1).ok_or(InvalidControls::Shape)?;
    if !buckets.is_power_of_two()
        || slot > mask
        || controls.len() < buckets.checked_add(16).ok_or(InvalidControls::Shape)?
    {
        return Err(InvalidControls::Shape);
    }
    if controls[slot] >= 0x80 {
        return Err(InvalidControls::NotOccupied);
    }
    if *items == 0 {
        return Err(InvalidControls::EmptyCount);
    }
    let before = slot.wrapping_sub(16) & mask;
    let empty_mask = |start: usize| -> u16 {
        (0..16).fold(0, |bits, i| {
            bits | if controls[start + i] == 0xff {
                1u16 << i
            } else {
                0
            }
        })
    };
    let before_empty = empty_mask(before);
    let after_empty = empty_mask(slot);
    let span = before_empty.leading_zeros() + after_empty.trailing_zeros();
    let marker = if span <= 15 { 0xff } else { 0x80 };
    let new_growth = if marker == 0xff {
        growth_left
            .checked_add(1)
            .ok_or(InvalidControls::CounterOverflow)?
    } else {
        *growth_left
    };
    controls[slot] = marker;
    controls[before + 16] = marker;
    *growth_left = new_growth;
    *items -= 1;
    Ok(marker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn record(old: Word) -> Journal {
        Journal {
            address: [1; 20],
            key: [2; 32],
            old,
        }
    }
    #[test]
    fn zero_old_missing_address_does_not_create() {
        let mut state = Transient::new();
        let r = record([0; 32]);
        restore(Some(&mut state), &r);
        assert!(state.is_empty());
        restore(None, &r);
    }
    #[test]
    fn zero_removal_retains_outer_entry_and_other_slots() {
        let r = record([0; 32]);
        let mut state = BTreeMap::from([(
            r.address,
            BTreeMap::from([(r.key, [3; 32]), ([4; 32], [5; 32])]),
        )]);
        restore(Some(&mut state), &r);
        assert_eq!(state[&r.address], BTreeMap::from([([4; 32], [5; 32])]));
        restore(
            Some(&mut state),
            &Journal {
                key: [4; 32],
                ..r.clone()
            },
        );
        assert!(state.contains_key(&r.address));
        assert!(state[&r.address].is_empty());
        let before = state.clone();
        restore(Some(&mut state), &r);
        assert_eq!(state, before);
    }
    #[test]
    fn nonzero_recreates_address_and_key_without_journal_mutation() {
        let r = record([7; 32]);
        let before = r.clone();
        let mut state = Transient::new();
        restore(Some(&mut state), &r);
        assert_eq!(state[&r.address][&r.key], [7; 32]);
        restore(
            Some(&mut state),
            &Journal {
                old: [8; 32],
                ..r.clone()
            },
        );
        assert_eq!(state[&r.address][&r.key], [8; 32]);
        assert_eq!(r, before);
    }
    #[test]
    fn tag_and_all_three_lane_offsets() {
        let mut bytes = [0xee; 88];
        bytes[0] = 10;
        bytes[1..21].fill(1);
        bytes[24..56].fill(2);
        bytes[56..88].fill(9);
        assert_eq!(Journal::decode(&bytes), Some(record([9; 32])));
        bytes[0] = 9;
        assert_eq!(Journal::decode(&bytes), None);
    }
    #[test]
    fn sparse_delete_empty_dense_delete_tombstone_and_mirror() {
        let mut sparse = vec![0xff; 48];
        sparse[7] = 0x22;
        sparse[39] = 0x22;
        let (mut growth, mut items) = (24, 1);
        assert_eq!(
            erase_controls(&mut sparse, 31, 7, &mut growth, &mut items),
            Ok(0xff)
        );
        assert_eq!((growth, items), (25, 0));
        assert_eq!(sparse[39], 0xff);
        let mut dense = vec![0x11; 48];
        let (mut growth, mut items) = (0, 32);
        assert_eq!(
            erase_controls(&mut dense, 31, 7, &mut growth, &mut items),
            Ok(0x80)
        );
        assert_eq!((growth, items), (0, 31));
        assert_eq!(dense[39], 0x80);
    }
    #[test]
    fn all_neighbor_empty_distances_match_probe_span_rule() {
        // Independent distances: l occupied slots immediately before deletion,
        // r occupied slots from deletion to next empty, with sentinels beyond group.
        for l in 0..=16 {
            for r in 1..=16 {
                let mut controls = vec![0x33; 80];
                let slot = 32;
                if l < 16 {
                    controls[slot - 1 - l] = 0xff;
                }
                if r < 16 {
                    controls[slot + r] = 0xff;
                }
                let (mut growth, mut items) = (0, 30);
                let marker =
                    erase_controls(&mut controls, 63, slot, &mut growth, &mut items).unwrap();
                assert_eq!(marker, if l + r < 16 { 0xff } else { 0x80 }, "l={l},r={r}");
                assert_eq!(items, 29);
            }
        }
    }
    #[test]
    fn invalid_source_inputs_do_not_mutate() {
        let mut controls = vec![0xff; 32];
        let before = controls.clone();
        let (mut growth, mut items) = (0, 1);
        assert_eq!(
            erase_controls(&mut controls, 15, 0, &mut growth, &mut items),
            Err(InvalidControls::NotOccupied)
        );
        assert_eq!(controls, before);
    }
}
