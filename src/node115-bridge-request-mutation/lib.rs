//! Owned logical bridge request mutation, with explicit post-mutation stops.
//! Native allocation/representation changes and outer rollback are not modeled.
use std::collections::{BTreeMap, btree_map::Entry};

/// Native comparison uses twenty address bytes first, then the unsigned word.
/// The final four bytes of the 32-byte key are padding, not key identity.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub address: [u8; 20],
    pub word: u64,
}
impl Key {
    pub fn from_native_prefix(bytes: &[u8; 32]) -> Self {
        Self {
            address: bytes[8..28].try_into().unwrap(),
            word: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub amount: u64,
    pub recipient: [u8; 20],
}
/// Only the initialized fields are represented. Native pointer words are not
/// dereferenced or exported as owned source pointers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreshValue {
    pub leading_words: [u64; 5],
    pub nested_request: Request,
    pub nested_value_words: [u64; 8],
}
impl FreshValue {
    fn new(request: Request) -> Self {
        Self {
            leading_words: [1, 8, 0, 0, 0],
            nested_request: request,
            nested_value_words: [0, 8, 0, 0, 0, 8, 0, 0],
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub requests: BTreeMap<Key, FreshValue>,
    pub aggregate: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// Native helper returns 0x9e; wrapper is about to unwrap it at 0x44d8509.
    BeforeDuplicateUnwrap,
    /// Native helper already inserted, but aggregate store has not occurred.
    BeforeBalancePanic,
    /// Aggregate store occurred. Lazy Once/logging continuation is outside scope.
    AfterAggregateStore,
}
/// Implements the owned, logical mutation, not a supplied entry-result oracle.
/// Successful native allocation/entry operations and a valid map are premises.
pub fn apply(state: &mut State, key: Key, request: Request) -> Stop {
    let amount = request.amount;
    match state.requests.entry(key) {
        Entry::Occupied(_) => return Stop::BeforeDuplicateUnwrap,
        Entry::Vacant(slot) => {
            slot.insert(FreshValue::new(request));
        }
    }
    let Some(next) = state.aggregate.checked_sub(amount) else {
        return Stop::BeforeBalancePanic;
    };
    state.aggregate = next;
    Stop::AfterAggregateStore
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(a: u8, word: u64) -> Key {
        Key {
            address: [a; 20],
            word,
        }
    }
    fn request(amount: u64) -> Request {
        Request {
            amount,
            recipient: [7; 20],
        }
    }
    #[test]
    fn fresh_and_duplicate_preserve_first_request() {
        let mut s = State {
            requests: BTreeMap::new(),
            aggregate: 100,
        };
        assert_eq!(
            apply(&mut s, key(1, 9), request(20)),
            Stop::AfterAggregateStore
        );
        let first = s.clone();
        let mut other = request(99);
        other.recipient[19] = 8;
        assert_eq!(apply(&mut s, key(1, 9), other), Stop::BeforeDuplicateUnwrap);
        assert_eq!(s, first);
        let v = &s.requests[&key(1, 9)];
        assert_eq!(v.leading_words, [1, 8, 0, 0, 0]);
        assert_eq!(v.nested_value_words, [0, 8, 0, 0, 0, 8, 0, 0]);
        assert_eq!(v.nested_request, request(20));
    }
    #[test]
    fn borrow_leaves_inserted_request_without_aggregate_store() {
        let mut s = State {
            requests: BTreeMap::new(),
            aggregate: 0,
        };
        assert_eq!(
            apply(&mut s, key(2, 0), request(1)),
            Stop::BeforeBalancePanic
        );
        assert_eq!(s.aggregate, 0);
        assert_eq!(s.requests.len(), 1);
        assert_eq!(
            apply(&mut s, key(2, 0), request(0)),
            Stop::BeforeDuplicateUnwrap
        );
        assert_eq!(s.requests[&key(2, 0)].nested_request.amount, 1);
    }
    #[test]
    fn zero_and_full_width_boundaries() {
        for (aggregate, amount, stop, next) in [
            (0, 0, Stop::AfterAggregateStore, 0),
            (u64::MAX, u64::MAX, Stop::AfterAggregateStore, 0),
            (
                u64::MAX - 1,
                u64::MAX,
                Stop::BeforeBalancePanic,
                u64::MAX - 1,
            ),
        ] {
            let mut s = State {
                requests: BTreeMap::new(),
                aggregate,
            };
            assert_eq!(apply(&mut s, key(0, 0), request(amount)), stop);
            assert_eq!(s.aggregate, next);
            assert_eq!(s.requests.len(), 1);
        }
    }
    #[test]
    fn exact_key_ignores_only_padding() {
        let mut raw = [0; 32];
        raw[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        raw[8..28].fill(3);
        let k = Key::from_native_prefix(&raw);
        for i in 0..32 {
            let mut changed = raw;
            changed[i] ^= 1;
            assert_eq!(Key::from_native_prefix(&changed) == k, i >= 28);
        }
        assert!(key(1, u64::MAX) < key(2, 0));
    }
    #[test]
    fn independent_linear_history_oracle() {
        // A linear first-occurrence ledger and widened integer subtraction,
        // independent of the implementation's BTreeMap entry/checked_sub.
        let mut s = State {
            requests: BTreeMap::new(),
            aggregate: 1000,
        };
        let mut ledger: Vec<(Key, Request)> = Vec::new();
        let mut total = 1000u64;
        for i in 0..4096u64 {
            let k = key((i % 23) as u8, (i * 7) % 31);
            let r = request((i * 13) % 97);
            let duplicate = ledger.iter().any(|(old, _)| old == &k);
            let expected = if duplicate {
                Stop::BeforeDuplicateUnwrap
            } else {
                ledger.push((k.clone(), r.clone()));
                let diff = i128::from(total) - i128::from(r.amount);
                if diff < 0 {
                    Stop::BeforeBalancePanic
                } else {
                    total = diff as u64;
                    Stop::AfterAggregateStore
                }
            };
            assert_eq!(apply(&mut s, k, r), expected);
            assert_eq!(s.aggregate, total);
            assert_eq!(s.requests.len(), ledger.len());
            for (k, r) in &ledger {
                assert_eq!(&s.requests[k].nested_request, r);
            }
        }
    }
}
