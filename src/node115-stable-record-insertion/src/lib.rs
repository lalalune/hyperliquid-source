//! Value model of node #115's stable insertion leaf over 40-byte records.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub const RECORD_BYTES: usize = 40;

/// A convenient host view: unsigned key followed by the remaining 32 bytes.
/// Original source type and ABI name are unresolved.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    pub key: u64,
    pub payload: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidPrefix {
    Zero,
    PastEnd,
}

/// Stably insertion-sorts records from `sorted_prefix` to the end.
///
/// The prefix length is one-based in the same sense as the target argument:
/// valid values satisfy `1 <= sorted_prefix <= records.len()`. The target
/// traps with UD2 outside that range; `InvalidPrefix` is a safe host result,
/// not a recovered native error. The caller's prefix is not validated or
/// repaired. If it is already sorted, the entire slice is sorted on return.
pub fn sort_suffix(records: &mut [Record], sorted_prefix: usize) -> Result<(), InvalidPrefix> {
    if sorted_prefix == 0 {
        return Err(InvalidPrefix::Zero);
    }
    if sorted_prefix > records.len() {
        return Err(InvalidPrefix::PastEnd);
    }

    for index in sorted_prefix..records.len() {
        let current = records[index];
        let mut hole = index;
        while hole > 0 && current.key < records[hole - 1].key {
            records[hole] = records[hole - 1];
            hole -= 1;
        }
        records[hole] = current;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn records(keys: &[u64]) -> Vec<Record> {
        keys.iter()
            .enumerate()
            .map(|(id, key)| Record {
                key: *key,
                payload: [id as u8; 32],
            })
            .collect()
    }

    fn ids(records: &[Record]) -> Vec<u8> {
        records.iter().map(|record| record.payload[0]).collect()
    }

    #[test]
    fn reproduces_target_grounded_order_vectors() {
        // Vectors and expected order are from the target-bound packet's records.json.
        let cases: &[(&[u64], usize, &[u8])] = &[
            (&[9], 1, &[0]),
            (&[0, 1, u64::MAX], 1, &[0, 1, 2]),
            (&[u64::MAX, 2, 1, 0], 1, &[3, 2, 1, 0]),
            (&[7, 7, 2, 7, 2], 1, &[2, 4, 0, 1, 3]),
            (&[u64::MAX, 0, 1 << 63, (1 << 63) - 1], 1, &[1, 3, 2, 0]),
            (&[1, 5, 9, 0, 5], 3, &[3, 0, 1, 4, 2]),
            (&[9, 1, 5], 2, &[0, 1, 2]),
            (&[3, 4, 1], 2, &[2, 0, 1]),
            (&[9, 1, 5], 3, &[0, 1, 2]),
        ];

        for (keys, prefix, expected_ids) in cases {
            let mut rows = records(keys);
            sort_suffix(&mut rows, *prefix).unwrap();
            assert_eq!(ids(&rows), *expected_ids, "keys={keys:?}, prefix={prefix}");
        }
    }

    #[test]
    fn preserves_full_payload_and_equal_key_order() {
        let mut rows = records(&[5, 5, 1, 5, 1]);
        let before = rows.clone();
        sort_suffix(&mut rows, 1).unwrap();
        assert_eq!(rows.iter().filter(|row| row.key == 5).count(), 3);
        assert_eq!(ids(&rows), [2, 4, 0, 1, 3]);
        for record in &rows {
            let id = record.payload[0] as usize;
            assert_eq!(*record, before[id]);
        }
    }

    #[test]
    fn target_guard_boundaries_are_reported_without_mutation() {
        let mut empty = [];
        assert_eq!(sort_suffix(&mut empty, 0), Err(InvalidPrefix::Zero));
        assert_eq!(sort_suffix(&mut empty, 1), Err(InvalidPrefix::PastEnd));

        let mut one = records(&[1]);
        let before = one.clone();
        assert_eq!(sort_suffix(&mut one, 0), Err(InvalidPrefix::Zero));
        assert_eq!(sort_suffix(&mut one, 2), Err(InvalidPrefix::PastEnd));
        assert_eq!(
            sort_suffix(&mut one, usize::MAX),
            Err(InvalidPrefix::PastEnd)
        );
        assert_eq!(one, before);
    }

    #[test]
    fn record_host_view_is_forty_bytes() {
        assert_eq!(core::mem::size_of::<Record>(), RECORD_BYTES);
        assert_eq!(core::mem::offset_of!(Record, payload), 8);
    }
}
