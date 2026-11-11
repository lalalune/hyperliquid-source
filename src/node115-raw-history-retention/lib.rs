//! Selected ordinary/flat history relation on valid unique unsigned keys.
//! Native allocation, tree conversion and digest computation remain premises.
use std::collections::BTreeMap;
pub type Digest = [u8; 32];
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct History {
    values: BTreeMap<u64, Digest>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Retention {
    pub replaced: Option<Digest>,
    pub removed: Vec<(u64, Digest)>,
    pub cutoff: Option<u64>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Scanned {
    Complete {
        compared: usize,
        skipped: usize,
    },
    BeforeMismatch {
        index: usize,
        key: u64,
        expected: Digest,
        actual: Digest,
        compared: usize,
        skipped: usize,
    },
}
impl History {
    pub fn get(&self, key: u64) -> Option<&Digest> {
        self.values.get(&key)
    }
    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &Digest)> {
        self.values.iter()
    }
    /// 5a03fa0: insert/update first; only count>=51 chooses the 50th largest key.
    /// Split at that key; discard strictly smaller keys and retain the equal key.
    pub fn publish(&mut self, key: u64, digest: Digest) -> Retention {
        let replaced = self.values.insert(key, digest);
        if self.values.len() < 51 {
            return Retention {
                replaced,
                removed: vec![],
                cutoff: None,
            };
        }
        let cutoff = *self.values.keys().rev().nth(49).unwrap();
        let kept = self.values.split_off(&cutoff);
        let removed = std::mem::replace(&mut self.values, kept)
            .into_iter()
            .collect();
        Retention {
            replaced,
            removed,
            cutoff: Some(cutoff),
        }
    }
    /// Later compact rows are read in supplied native order. Missing references
    /// skip comparison; found unequal digest stops before the native failure path.
    pub fn scan(&self, rows: &[[u8; 104]]) -> Scanned {
        let (mut compared, mut skipped) = (0, 0);
        for (index, row) in rows.iter().enumerate() {
            let key = u64::from_le_bytes(row[..8].try_into().unwrap());
            let actual: Digest = row[72..104].try_into().unwrap();
            let Some(&expected) = self.values.get(&key) else {
                skipped += 1;
                continue;
            };
            if expected != actual {
                return Scanned::BeforeMismatch {
                    index,
                    key,
                    expected,
                    actual,
                    compared,
                    skipped,
                };
            }
            compared += 1;
        }
        Scanned::Complete { compared, skipped }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn d(x: u64) -> Digest {
        std::array::from_fn(|i| (x.rotate_left(i as u32) as u8).wrapping_add(i as u8))
    }
    fn row(key: u64, value: Digest) -> [u8; 104] {
        let mut r = [0xa5; 104];
        r[..8].copy_from_slice(&key.to_le_bytes());
        r[72..].copy_from_slice(&value);
        r
    }
    #[test]
    fn exact_fiftieth_inclusive_boundary() {
        let mut h = History::default();
        for i in 0..50 {
            assert_eq!(h.publish(i, d(i)).cutoff, None);
        }
        let r = h.publish(50, d(50));
        assert_eq!(r.cutoff, Some(1));
        assert_eq!(r.removed, vec![(0, d(0))]);
        assert_eq!(h.len(), 50);
        assert_eq!(h.get(1), Some(&d(1)));
    }
    #[test]
    fn removed_reference_skips_then_retained_mismatch_stops() {
        let mut h = History::default();
        for i in 0..51 {
            h.publish(i, d(i));
        }
        let rows = [
            row(0, [255; 32]),
            row(1, d(1)),
            row(2, [255; 32]),
            row(3, d(3)),
        ];
        assert_eq!(
            h.scan(&rows),
            Scanned::BeforeMismatch {
                index: 2,
                key: 2,
                expected: d(2),
                actual: [255; 32],
                compared: 1,
                skipped: 1
            }
        );
    }
    #[test]
    fn duplicate_replaces_and_old_insertion_discards_itself() {
        let mut h = History::default();
        for i in 100..150 {
            h.publish(i, d(i));
        }
        let old = h.publish(125, [7; 32]);
        assert_eq!(old.replaced, Some(d(125)));
        assert_eq!(old.cutoff, None);
        assert_eq!(h.get(125), Some(&[7; 32]));
        let r = h.publish(1, d(1));
        assert_eq!(r.removed, vec![(1, d(1))]);
        assert_eq!(r.cutoff, Some(100));
        assert_eq!(h.len(), 50);
    }
    #[test]
    fn shuffled_unsigned_keys_against_sorted_log_oracle() {
        for seed in 0..32u64 {
            let mut h = History::default();
            let mut accepted = Vec::new();
            for i in 0..256u64 {
                let key = ((i * 73 + seed * 31) % 257) ^ if i % 3 == 0 { 1 << 63 } else { 0 };
                let value = d(i + seed);
                h.publish(key, value);
                accepted.retain(|(k, _)| *k != key);
                accepted.push((key, value));
                accepted.sort_by_key(|x| x.0);
                if accepted.len() > 50 {
                    accepted.remove(0);
                }
                assert_eq!(
                    h.iter().map(|(&k, &v)| (k, v)).collect::<Vec<_>>(),
                    accepted
                );
                let rows: Vec<_> = accepted.iter().map(|&(k, v)| row(k, v)).collect();
                assert_eq!(
                    h.scan(&rows),
                    Scanned::Complete {
                        compared: accepted.len(),
                        skipped: 0
                    }
                );
            }
        }
    }
    #[test]
    fn all_digest_lanes_and_incoming_padding() {
        let mut h = History::default();
        h.publish(u64::MAX, d(5));
        for lane in 0..32 {
            let mut r = row(u64::MAX, d(5));
            r[72 + lane] ^= 1;
            assert!(matches!(
                h.scan(&[r]),
                Scanned::BeforeMismatch { index: 0, .. }
            ));
        }
        for lane in 8..72 {
            let mut r = row(u64::MAX, d(5));
            r[lane] ^= 1;
            assert_eq!(
                h.scan(&[r]),
                Scanned::Complete {
                    compared: 1,
                    skipped: 0
                }
            );
        }
    }
}
