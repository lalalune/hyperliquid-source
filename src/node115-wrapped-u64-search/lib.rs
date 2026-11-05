#![no_std]
#![forbid(unsafe_code)]
//! Logical coordinate relation for two qualified node115 ring-search leaves.
#[derive(Debug, PartialEq, Eq)]
pub struct Search {
    pub status: u64,
    pub index: usize,
}
fn result(status: u64, index: usize) -> Search {
    Search { status, index }
}
fn span(keys: &[u64], start: usize, end: usize, needle: u64) -> Search {
    let mut lo = start;
    let mut hi = end;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if keys[mid] <= needle {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo > start && keys[lo - 1] == needle {
        result(0, lo - 1)
    } else {
        result(1, lo)
    }
}
/// Own refusal for inputs outside the measured finite sorted geometry;
/// this is not a native malformed-pointer or error-handling claim.
pub fn probe(keys: &[u64], capacity: usize, head: usize, needle: u64) -> Option<Search> {
    if capacity > 32 || keys.len() > capacity || keys.windows(2).any(|w| w[0] > w[1]) {
        return None;
    }
    if capacity == 0 {
        return if head == 0 { Some(result(1, 0)) } else { None };
    }
    if head >= 2 * capacity {
        return None;
    }
    if keys.is_empty() {
        return Some(result(1, 0));
    }
    let normalized = if head >= capacity {
        head - capacity
    } else {
        head
    };
    let first = (capacity - normalized).min(keys.len());
    if first < keys.len() {
        let pivot = keys[first];
        if needle == pivot {
            return Some(result(0, first));
        }
        if needle < pivot {
            Some(span(keys, 0, first, needle))
        } else {
            Some(span(keys, first, keys.len(), needle))
        }
    } else {
        Some(span(keys, 0, keys.len(), needle))
    }
}
