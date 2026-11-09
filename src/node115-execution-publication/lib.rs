//! Normal sequential publication with valid initialized owners and successful
//! allocation/lock helpers. No native concurrency or pointer payload destruction.
use std::collections::BTreeMap;
use std::sync::Arc;
#[derive(Debug, PartialEq, Eq)]
pub struct Projection {
    pub rows: Vec<[u8; 5]>,
    pub context_word: u64,
}
#[derive(Debug)]
pub struct ProjectionOwner {
    pub published: Arc<Projection>,
}
impl ProjectionOwner {
    /// 2502370 -> 29dd5e0's disabled lock-order diagnostics -> 2a35190.
    /// Called only after the actual native lock/clock prerequisites return normally.
    pub fn replace(&mut self, next: Projection) {
        self.published = Arc::new(next);
    }
}
pub type Record = [u8; 176];
#[derive(Debug)]
pub struct Segment {
    pub rows: BTreeMap<u8, Record>,
    pub ready: u64,
    pub next: Option<u64>,
    pub retired_at: Option<u64>,
}
impl Segment {
    fn empty() -> Self {
        Self {
            rows: BTreeMap::new(),
            ready: 0,
            next: None,
            retired_at: None,
        }
    }
}
#[derive(Debug)]
pub struct Queue {
    pub state: u64,
    pub handle_count: u64,
    pub next_ticket: u64,
    pub head: u64,
    pub segments: BTreeMap<u64, Segment>,
    pub wake_state: u64,
    pub waker: Option<u64>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Sent {
    Returned5 { ticket: Option<u64> },
    BeforeWake { ticket: u64, waker: u64 },
    BeforeClosedPayloadDrop(Box<Record>),
    BeforeCapacityFatal(Box<Record>),
    BeforeSegmentBaseOverflow(Box<Record>),
    InvalidLogicalState(Box<Record>),
}
impl Default for Queue {
    fn default() -> Self {
        Self {
            state: 0,
            handle_count: 0,
            next_ticket: 0,
            head: 0,
            segments: BTreeMap::from([(0, Segment::empty())]),
            wake_state: 0,
            waker: None,
        }
    }
}
impl Queue {
    /// Sequential relation of 2cedc50 + no-CAS-contention 2cd0390.
    /// Counter wrapping follows the captured atomic instructions. Valid segment
    /// membership/ownership are caller premises. No receiver or reclamation runs.
    pub fn send(&mut self, record: Record) -> Sent {
        self.handle_count = self.handle_count.wrapping_add(1);
        if self.state & 1 != 0 {
            if u64::from_le_bytes(record[..8].try_into().unwrap()) == 1 << 63 {
                return Sent::Returned5 { ticket: None };
            }
            return Sent::BeforeClosedPayloadDrop(Box::new(record));
        }
        if self.state == u64::MAX - 1 {
            return Sent::BeforeCapacityFatal(Box::new(record));
        }
        self.state = self.state.wrapping_add(2);
        let ticket = self.next_ticket;
        self.next_ticket = self.next_ticket.wrapping_add(1);
        let target = ticket & !31;
        let Some(head) = self.segments.get(&self.head) else {
            return Sent::InvalidLogicalState(Box::new(record));
        };
        let _ = head;
        if target < self.head {
            return Sent::InvalidLogicalState(Box::new(record));
        }
        let mut advance = (target - self.head) / 32 > ticket & 31;
        let mut current = self.head;
        while current != target {
            let next = match self.segments[&current].next {
                Some(next) => next,
                None => {
                    let Some(next) = current.checked_add(32) else {
                        return Sent::BeforeSegmentBaseOverflow(Box::new(record));
                    };
                    self.segments.entry(next).or_insert_with(Segment::empty);
                    self.segments.get_mut(&current).unwrap().next = Some(next);
                    next
                }
            };
            if next <= current || !self.segments.contains_key(&next) {
                return Sent::InvalidLogicalState(Box::new(record));
            }
            if advance && self.segments[&current].ready as u32 == u32::MAX {
                self.head = next;
                let old = self.segments.get_mut(&current).unwrap();
                old.retired_at = Some(self.next_ticket);
                old.ready |= 1 << 32;
            } else {
                advance = false;
            }
            current = next;
        }
        let slot = (ticket & 31) as u8;
        let segment = self.segments.get_mut(&current).unwrap();
        segment.rows.insert(slot, record);
        segment.ready |= 1u64 << slot;
        let old_wake = self.wake_state;
        self.wake_state |= 2;
        if old_wake == 0 {
            let waker = self.waker.take();
            self.wake_state = 0;
            if let Some(waker) = waker {
                return Sent::BeforeWake { ticket, waker };
            }
        }
        Sent::Returned5 {
            ticket: Some(ticket),
        }
    }
}
/// Parent 2af7150 always replaces the compact publication before sending the
/// distinct 176-byte result. Queue failures do not roll back that replacement.
pub fn publish(
    owner: &mut ProjectionOwner,
    projection: Projection,
    queue: &mut Queue,
    record: Record,
) -> Sent {
    owner.replace(projection);
    queue.send(record)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn projection(x: u8) -> Projection {
        Projection {
            rows: vec![[x; 5]],
            context_word: 77,
        }
    }
    fn record(x: u8) -> Record {
        std::array::from_fn(|i| x.wrapping_add(i as u8))
    }
    #[test]
    fn replacement_preserves_alias_and_empty_is_new_state() {
        let old = Arc::new(projection(4));
        let weak = Arc::downgrade(&old);
        let mut owner = ProjectionOwner {
            published: old.clone(),
        };
        owner.replace(Projection {
            rows: vec![],
            context_word: 88,
        });
        assert!(owner.published.rows.is_empty());
        assert_eq!(owner.published.context_word, 88);
        assert_eq!(old.rows, vec![[4; 5]]);
        assert_eq!(Arc::strong_count(&old), 1);
        drop(old);
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn projection_remains_on_closed_and_overflow_boundaries() {
        for state in [1, u64::MAX - 1] {
            let mut owner = ProjectionOwner {
                published: Arc::new(projection(1)),
            };
            let mut q = Queue {
                state,
                ..Queue::default()
            };
            let sent = publish(&mut owner, projection(9), &mut q, record(1));
            assert_eq!(owner.published.rows, vec![[9; 5]]);
            assert_eq!(q.handle_count, 1);
            assert_eq!(q.state, state);
            assert_eq!(q.next_ticket, 0);
            assert!(matches!(
                sent,
                Sent::BeforeClosedPayloadDrop(_) | Sent::BeforeCapacityFatal(_)
            ));
        }
    }
    #[test]
    fn closed_sentinel_returns_five_without_queue_or_decrement() {
        let mut q = Queue {
            state: 1,
            ..Queue::default()
        };
        let mut r = record(3);
        r[..8].copy_from_slice(&(1u64 << 63).to_le_bytes());
        assert_eq!(q.send(r), Sent::Returned5 { ticket: None });
        assert_eq!(q.handle_count, 1);
        assert!(q.segments[&0].rows.is_empty());
    }
    #[test]
    fn three_hundred_records_preserve_every_byte_and_retirement() {
        let mut q = Queue::default();
        for i in 0..300u64 {
            assert_eq!(q.send(record(i as u8)), Sent::Returned5 { ticket: Some(i) });
            let s = &q.segments[&(i & !31)];
            assert_eq!(s.rows[&((i & 31) as u8)], record(i as u8));
            assert_ne!(s.ready & (1 << (i & 31)), 0);
        }
        assert_eq!(q.head, 288);
        assert_eq!(q.next_ticket, 300);
        assert_eq!(q.state, 600);
        assert_eq!(q.handle_count, 300);
        for base in (0..288).step_by(32) {
            let s = &q.segments[&base];
            assert_eq!(s.ready, 0x1ffffffff);
            assert_eq!(s.retired_at, Some(base + 33));
            assert_eq!(s.next, Some(base + 32));
        }
    }
    #[test]
    fn wake_boundary_after_publication_and_busy_state_preserves_waker() {
        for state in 0..4 {
            let mut q = Queue {
                wake_state: state,
                waker: Some(19),
                ..Queue::default()
            };
            let sent = q.send(record(8));
            assert_eq!(q.segments[&0].rows[&0], record(8));
            if state == 0 {
                assert_eq!(
                    sent,
                    Sent::BeforeWake {
                        ticket: 0,
                        waker: 19
                    }
                );
                assert_eq!(q.wake_state, 0);
                assert_eq!(q.waker, None);
            } else {
                assert_eq!(sent, Sent::Returned5 { ticket: Some(0) });
                assert_eq!(q.wake_state, state | 2);
                assert_eq!(q.waker, Some(19));
            }
        }
    }
    #[test]
    fn distinct_projection_and_full_record() {
        let mut owner = ProjectionOwner {
            published: Arc::new(projection(1)),
        };
        let mut q = Queue::default();
        let r = record(17);
        publish(&mut owner, projection(9), &mut q, r);
        assert_eq!(q.segments[&0].rows[&0], r);
        assert_eq!(owner.published.rows, vec![[9; 5]]);
    }
}
