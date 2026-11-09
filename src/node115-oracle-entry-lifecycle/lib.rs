//! Selected selector-0/1 keyed oracle entry lifecycle in a valid flat ring.
//! Growth, tree conversion and the prior ratio gate are explicit boundaries.

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub threshold: f64,
    pub first: [u8; 12],
    pub latest: [u8; 12],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Selector {
    Zero,
    One,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    Selected(Selector),
    Other { word: u64, byte: u8 },
}
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub key: Key,
    pub value: Entry,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    BeforeGrowth,
}

/// Active rows are ordered and unique; inactive slots model no native bytes.
/// Capacity and head must describe a valid normal flat ring.
#[derive(Clone, Debug, PartialEq)]
pub struct FlatEntries {
    slots: Vec<Option<Row>>,
    head: usize,
    len: usize,
}
impl FlatEntries {
    pub fn empty(capacity: usize, head: usize) -> Self {
        assert!(capacity > 0 && head < capacity);
        Self {
            slots: vec![None; capacity],
            head,
            len: 0,
        }
    }
    /// Supply an already-valid ordered flat state, including other tag-1 keys.
    pub fn from_sorted(capacity: usize, head: usize, rows: Vec<Row>) -> Self {
        assert!(rows.len() <= capacity && rows.windows(2).all(|w| w[0].key < w[1].key));
        let mut result = Self::empty(capacity, head);
        result.len = rows.len();
        for (index, row) in rows.into_iter().enumerate() {
            let at = result.at(index);
            result.slots[at] = Some(row);
        }
        result
    }
    pub fn rows(&self) -> Vec<Row> {
        (0..self.len)
            .map(|i| self.slots[self.at(i)].as_ref().unwrap().clone())
            .collect()
    }
    pub fn head(&self) -> usize {
        self.head
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    fn at(&self, i: usize) -> usize {
        (self.head + i) % self.slots.len()
    }
    pub fn get(&self, selector: Selector) -> Option<&Entry> {
        (0..self.len).find_map(|i| {
            let r = self.slots[self.at(i)].as_ref().unwrap();
            (r.key == Key::Selected(selector)).then_some(&r.value)
        })
    }
    fn search(&self, selector: Selector) -> Result<usize, usize> {
        (0..self.len)
            .map(|i| self.slots[self.at(i)].as_ref().unwrap().key)
            .collect::<Vec<_>>()
            .binary_search(&Key::Selected(selector))
    }
    /// The two original caller sites pass [0,0] or [0,1]. Successful flat
    /// insertion and normal helper returns are premises; a full ring stops
    /// before the native grow helper.
    pub fn write_selected(&mut self, selector: Selector, now: [u8; 12]) -> Result<&Entry, Stop> {
        let index = match self.search(selector) {
            Ok(index) => index,
            Err(index) => {
                if self.len == self.slots.len() {
                    return Err(Stop::BeforeGrowth);
                }
                let capacity = self.slots.len();
                if self.len - index >= index {
                    let old = self.head;
                    self.head = (self.head + capacity - 1) % capacity;
                    for j in 0..index {
                        let src = (old + j) % capacity;
                        let dst = self.at(j);
                        self.slots[dst] = self.slots[src].take();
                    }
                } else {
                    for j in (index..self.len).rev() {
                        let src = self.at(j);
                        let dst = self.at(j + 1);
                        self.slots[dst] = self.slots[src].take();
                    }
                }
                let at = self.at(index);
                self.slots[at] = Some(Row {
                    key: Key::Selected(selector),
                    value: Entry {
                        threshold: 10.0,
                        first: now,
                        latest: now,
                    },
                });
                self.len += 1;
                index
            }
        };
        let at = self.at(index);
        let entry = &mut self.slots[at].as_mut().unwrap().value;
        if entry.first[..4] == [0; 4] {
            entry.first = now;
        }
        entry.latest = now;
        Ok(entry)
    }
    /// Selected removal after the prior reset gate; move the shorter side.
    pub fn reset_selected(&mut self, selector: Selector) -> bool {
        let Ok(index) = self.search(selector) else {
            return false;
        };
        let capacity = self.slots.len();
        if self.len - 1 - index >= index {
            for j in (0..index).rev() {
                let src = self.at(j);
                let dst = self.at(j + 1);
                self.slots[dst] = self.slots[src].take();
            }
            self.slots[self.head] = None;
            self.head = (self.head + 1) % capacity;
        } else {
            for j in index + 1..self.len {
                let src = self.at(j);
                let dst = self.at(j - 1);
                self.slots[dst] = self.slots[src].take();
            }
            let last = self.at(self.len - 1);
            self.slots[last] = None;
        }
        self.len -= 1;
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn stamp(first: u32, tail: u8) -> [u8; 12] {
        let mut v = [tail; 12];
        v[..4].copy_from_slice(&first.to_le_bytes());
        v
    }
    #[test]
    fn wrapped_two_key_insert_remove_and_head_choices() {
        for cap in 2..=12 {
            for head in 0..cap {
                for reverse in [false, true] {
                    let mut ring = FlatEntries::empty(cap, head);
                    let (a, b) = if reverse {
                        (Selector::One, Selector::Zero)
                    } else {
                        (Selector::Zero, Selector::One)
                    };
                    ring.write_selected(a, stamp(1, 7)).unwrap();
                    let before = ring.head();
                    ring.write_selected(b, stamp(2, 8)).unwrap();
                    assert_eq!(
                        ring.head(),
                        if reverse {
                            (before + cap - 1) % cap
                        } else {
                            before
                        }
                    );
                    assert_eq!(ring.len(), 2);
                    assert_eq!(ring.get(a).unwrap().first, stamp(1, 7));
                    let before = ring.head();
                    assert!(ring.reset_selected(b));
                    assert_eq!(
                        ring.head(),
                        if reverse { (before + 1) % cap } else { before }
                    );
                    assert_eq!(ring.get(a).unwrap().first, stamp(1, 7));
                    assert!(!ring.reset_selected(b));
                }
            }
        }
    }
    #[test]
    fn nonzero_first_marker_stays_and_latest_changes() {
        let mut r = FlatEntries::empty(3, 1);
        r.write_selected(Selector::One, stamp(1, 3)).unwrap();
        let entry = r.write_selected(Selector::One, stamp(3, 5)).unwrap();
        assert_eq!(entry.threshold, 10.0);
        assert_eq!(entry.first, stamp(1, 3));
        assert_eq!(entry.latest, stamp(3, 5));
    }
    #[test]
    fn only_low_dword_gates_first_record() {
        let mut r = FlatEntries::empty(2, 0);
        r.write_selected(Selector::Zero, stamp(0, 0xff)).unwrap();
        assert_eq!(
            r.write_selected(Selector::Zero, stamp(0, 6)).unwrap().first,
            stamp(0, 6)
        );
        assert_eq!(
            r.write_selected(Selector::Zero, stamp(8, 7)).unwrap().first,
            stamp(8, 7)
        );
    }
    #[test]
    fn full_ring_stops_before_growth_without_change() {
        let mut r = FlatEntries::empty(1, 0);
        r.write_selected(Selector::One, stamp(1, 0)).unwrap();
        let before = r.clone();
        assert_eq!(
            r.write_selected(Selector::Zero, stamp(2, 0)),
            Err(Stop::BeforeGrowth)
        );
        assert_eq!(r, before);
    }
    #[test]
    fn preexisting_other_variant_exercises_actual_row_moves() {
        let entry = |marker: u8| Entry {
            threshold: marker as f64,
            first: stamp(1, marker),
            latest: stamp(2, marker),
        };
        let rows = vec![
            Row {
                key: Key::Selected(Selector::Zero),
                value: entry(4),
            },
            Row {
                key: Key::Other { word: 1, byte: 0 },
                value: entry(5),
            },
            Row {
                key: Key::Other { word: 2, byte: 0 },
                value: entry(6),
            },
        ];
        for cap in 4..=10 {
            for head in 0..cap {
                let mut ring = FlatEntries::from_sorted(cap, head, rows.clone());
                ring.write_selected(Selector::One, stamp(8, 9)).unwrap();
                assert_eq!(ring.head(), (head + cap - 1) % cap); // prefix has one row, suffix has two
                let got = ring.rows();
                assert_eq!(got[0], rows[0]);
                assert_eq!(got[2], rows[1]);
                assert_eq!(got[3], rows[2]);
                assert!(ring.reset_selected(Selector::One));
                assert_eq!(ring.head(), head);
                assert_eq!(ring.rows(), rows);
            }
        }
    }
    #[test]
    fn occupied_arbitrary_threshold_is_preserved() {
        let original = Entry {
            threshold: f64::from_bits(0x7ff8_0000_0000_0042),
            first: stamp(2, 3),
            latest: stamp(4, 5),
        };
        let mut ring = FlatEntries::from_sorted(
            3,
            2,
            vec![Row {
                key: Key::Selected(Selector::One),
                value: original.clone(),
            }],
        );
        let changed = ring.write_selected(Selector::One, stamp(7, 8)).unwrap();
        assert_eq!(changed.threshold.to_bits(), original.threshold.to_bits());
        assert_eq!(changed.first, original.first);
        assert_eq!(changed.latest, stamp(7, 8));
    }
}
