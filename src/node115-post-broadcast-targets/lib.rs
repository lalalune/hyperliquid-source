//! Node #115 0x2d34fc0: collect post-broadcast targets on the flat/ring domain.
//! Outer maps are logical projections. Tree-valued collections and the actual
//! 0x2d32de0 cancellation operation remain explicit boundaries.
use std::collections::BTreeMap;

pub type Key = [u8; 20];
pub const CALL_TARGET: u64 = 0x2d32de0;
pub const RAW_REASON: u64 = 0x8000_0000_0000_0001;

#[derive(Clone, Copy, Debug)]
pub struct Filter {
    pub raw_tag: u64,
    pub value: u64,
}
#[derive(Clone, Debug)]
pub enum Rows<const N: usize> {
    Ring {
        slots: Vec<[u8; N]>,
        head: usize,
        len: usize,
    },
    TreeBoundary,
}
#[derive(Default)]
pub struct Owner {
    /// Native owner+0x18, values contain 112-byte rows.
    pub first: BTreeMap<Key, Rows<112>>,
    /// Native owner+0x38, values contain 96-byte rows.
    pub second: BTreeMap<Key, Rows<96>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Collection {
    First,
    Second,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    Tree {
        collection: Collection,
        collected: Vec<u64>,
    },
    InvalidRing {
        collection: Collection,
        collected: Vec<u64>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Calls {
    pub key: Key,
    pub identifiers: Vec<u64>,
    pub raw_reason: u64,
    pub forwarded_r8: u64,
    pub forwarded_r9: u64,
}
fn qword(b: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(b[offset..offset + 8].try_into().unwrap())
}

fn append<const N: usize>(
    rows: &Rows<N>,
    offset: usize,
    filter: Filter,
    collection: Collection,
    ids: &mut Vec<u64>,
) -> Result<(), Stop> {
    let Rows::Ring { slots, head, len } = rows else {
        return Err(Stop::Tree {
            collection,
            collected: ids.clone(),
        });
    };
    // Invalid snapshots are outside the native invariant; these are source
    // domain errors, not reconstructed native error responses.
    let cap = slots.len();
    if *len > cap || (*len != 0 && (cap == 0 || head / cap > 1)) {
        return Err(Stop::InvalidRing {
            collection,
            collected: ids.clone(),
        });
    }
    if *len == 0 {
        return Ok(());
    }
    let start = if *head >= cap { *head - cap } else { *head };
    for i in 0..*len {
        // Avoid source addition overflow while retaining the native two-span order.
        let index = if i < cap - start {
            start + i
        } else {
            i - (cap - start)
        };
        let row = &slots[index];
        // Native tests only the low 32 bits of the raw discriminator.
        if filter.raw_tag as u32 != 1 || qword(row, offset) == filter.value {
            ids.push(qword(row, 0));
        }
    }
    Ok(())
}

/// Produces the exact argument stream at the native cancellation boundary.
/// No cancellation is simulated: callers must not apply these as completed
/// mutations. Both maps are read before the first native cancellation call.
pub fn collect(owner: &Owner, key: Key, filter: Filter, r8: u64, r9: u64) -> Result<Calls, Stop> {
    let mut ids = Vec::new();
    if let Some(rows) = owner.first.get(&key) {
        append(rows, 8, filter, Collection::First, &mut ids)?;
    }
    if let Some(rows) = owner.second.get(&key) {
        append(rows, 24, filter, Collection::Second, &mut ids)?;
    }
    Ok(Calls {
        key,
        identifiers: ids,
        raw_reason: RAW_REASON,
        forwarded_r8: r8,
        forwarded_r9: r9,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row<const N: usize>(id: u64, at8: u64, at24: u64) -> [u8; N] {
        let mut r = [0xaa; N];
        r[..8].copy_from_slice(&id.to_le_bytes());
        r[8..16].copy_from_slice(&at8.to_le_bytes());
        r[24..32].copy_from_slice(&at24.to_le_bytes());
        r
    }
    #[test]
    fn two_record_layouts_preserve_order_and_duplicates() {
        let key = [7; 20];
        let mut owner = Owner::default();
        owner.first.insert(
            key,
            Rows::Ring {
                slots: vec![row(30, 9, 0), row(20, 8, 9), row(40, 9, 0)],
                head: 2,
                len: 3,
            },
        );
        owner.second.insert(
            key,
            Rows::Ring {
                slots: vec![row(40, 0, 9), row(10, 9, 8)],
                head: 0,
                len: 2,
            },
        );
        let result = collect(
            &owner,
            key,
            Filter {
                raw_tag: 1,
                value: 9,
            },
            0x123,
            0x456,
        )
        .unwrap();
        assert_eq!(result.identifiers, vec![40, 30, 40]);
        assert_eq!(
            (result.raw_reason, result.forwarded_r8, result.forwarded_r9),
            (0x8000000000000001, 0x123, 0x456)
        );
        assert_eq!(result.key, key);
        assert_eq!(
            collect(
                &owner,
                key,
                Filter {
                    raw_tag: 2,
                    value: 9
                },
                0,
                0
            )
            .unwrap()
            .identifiers,
            vec![40, 30, 20, 40, 10]
        );
        assert_eq!(
            collect(
                &owner,
                key,
                Filter {
                    raw_tag: 0x100000001,
                    value: 9
                },
                0,
                0
            )
            .unwrap()
            .identifiers,
            vec![40, 30, 40]
        );
    }
    #[test]
    fn every_small_wrap_and_filter_tag() {
        let key = [0; 20];
        for cap in 1..8 {
            for head in 0..2 * cap {
                for len in 0..=cap {
                    let mut owner = Owner::default();
                    owner.first.insert(
                        key,
                        Rows::Ring {
                            slots: (0..cap)
                                .map(|i| row(i as u64, (i % 2) as u64, 55))
                                .collect(),
                            head,
                            len,
                        },
                    );
                    for tag in [0, 1, 2, 255, 0x100000001] {
                        let expected: Vec<u64> = (0..len)
                            .map(|i| ((head + i) % cap) as u64)
                            .filter(|i| tag as u32 != 1 || i % 2 == 1)
                            .collect();
                        assert_eq!(
                            collect(
                                &owner,
                                key,
                                Filter {
                                    raw_tag: tag,
                                    value: 1
                                },
                                0,
                                0
                            )
                            .unwrap()
                            .identifiers,
                            expected
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn empty_first_does_not_suppress_second_and_keys_are_full_width() {
        let key = [0; 20];
        let mut other = key;
        other[19] = 1;
        let mut owner = Owner::default();
        owner.first.insert(
            other,
            Rows::Ring {
                slots: vec![row(88, 0, 0)],
                head: 0,
                len: 1,
            },
        );
        owner.second.insert(
            key,
            Rows::Ring {
                slots: vec![row(u64::MAX, 0, 9)],
                head: 0,
                len: 1,
            },
        );
        assert_eq!(
            collect(
                &owner,
                key,
                Filter {
                    raw_tag: 1,
                    value: 9
                },
                0,
                0
            )
            .unwrap()
            .identifiers,
            vec![u64::MAX]
        );
        assert!(collect(
            &Owner::default(),
            key,
            Filter {
                raw_tag: 0,
                value: 0
            },
            0,
            0
        )
        .unwrap()
        .identifiers
        .is_empty());
    }
    #[test]
    fn tree_and_invalid_snapshots_stop_without_claiming_mutation() {
        let key = [0; 20];
        let mut owner = Owner::default();
        owner.first.insert(
            key,
            Rows::Ring {
                slots: vec![row(7, 0, 0)],
                head: 0,
                len: 1,
            },
        );
        owner.second.insert(key, Rows::TreeBoundary);
        assert_eq!(
            collect(
                &owner,
                key,
                Filter {
                    raw_tag: 0,
                    value: 0
                },
                0,
                0
            ),
            Err(Stop::Tree {
                collection: Collection::Second,
                collected: vec![7]
            })
        );
        owner.second.insert(
            key,
            Rows::Ring {
                slots: vec![],
                head: 0,
                len: 1,
            },
        );
        assert_eq!(
            collect(
                &owner,
                key,
                Filter {
                    raw_tag: 0,
                    value: 0
                },
                0,
                0
            ),
            Err(Stop::InvalidRing {
                collection: Collection::Second,
                collected: vec![7]
            })
        );
    }
}
