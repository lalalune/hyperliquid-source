// SPDX-License-Identifier: MIT
//! Conditional node #115 flat-store search and all-or-nothing value projection.
//!
//! The supplied values are opaque integers, never native addresses. This API
//! does not implement native reference counts, locks, drops or allocation errors.
//! Its Result/Option types and input refusals are chosen safe host interfaces.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;

/// One supplied physical row. No native memory layout is promised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub key: [u8; 32],
    pub value: u64,
}

/// Safe host input refusals, not captured-node error discriminants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainError {
    InvalidHeader,
    ZeroLiveValue,
    UnsortedLiveKeys,
}

/// Logical and physical indices are distinct; a missing index may equal length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchResult {
    Found {
        logical_index: usize,
        physical_index: usize,
        value: u64,
    },
    Missing {
        insertion_index: usize,
    },
}

/// An immutable, validated view of the live part of a supplied physical ring.
///
/// Capacity is `rows.len()`. Only live rows must be sorted and have nonzero
/// values. The library imposes no driver-specific row or query count limits.
#[derive(Clone, Copy)]
pub struct RingView<'a> {
    rows: &'a [Row],
    head: usize,
    live_length: usize,
}

impl<'a> RingView<'a> {
    pub fn new(rows: &'a [Row], head: usize, live_length: usize) -> Result<Self, DomainError> {
        let capacity = rows.len();
        if live_length > capacity
            || (capacity == 0 && head != 0)
            || (capacity != 0 && head >= capacity)
        {
            return Err(DomainError::InvalidHeader);
        }
        let view = Self {
            rows,
            head,
            live_length,
        };
        let mut previous: Option<&[u8; 32]> = None;
        for logical in 0..live_length {
            let row = &rows[view.physical_index(logical)];
            if row.value == 0 {
                return Err(DomainError::ZeroLiveValue);
            }
            if previous.is_some_and(|key| key > &row.key) {
                return Err(DomainError::UnsortedLiveKeys);
            }
            previous = Some(&row.key);
        }
        Ok(view)
    }

    /// Search actual unsigned 32-byte keys, including the wrapped-seam tie rule.
    pub fn search(&self, query: &[u8; 32]) -> SearchResult {
        if self.live_length == 0 {
            return SearchResult::Missing { insertion_index: 0 };
        }
        let first_length = self.live_length.min(self.rows.len() - self.head);
        let second_length = self.live_length - first_length;
        let (offset, result) = if second_length == 0 {
            (
                0,
                segment_search(&self.rows[self.head..self.head + first_length], query),
            )
        } else {
            match self.rows[0].key.cmp(query) {
                Ordering::Equal => return self.found(first_length),
                Ordering::Greater => (
                    0,
                    segment_search(&self.rows[self.head..self.head + first_length], query),
                ),
                Ordering::Less => (
                    first_length,
                    segment_search(&self.rows[..second_length], query),
                ),
            }
        };
        match result {
            Ok(local) => self.found(offset + local),
            Err(local) => SearchResult::Missing {
                insertion_index: offset + local,
            },
        }
    }

    /// Return all selected values in query order, or None at the first miss.
    ///
    /// Empty queries yield Some(empty). Repeated queries retain repeated values.
    /// Allocations are host allocations; native capacity/growth is not modeled.
    pub fn materialize(&self, queries: &[[u8; 32]]) -> Option<Vec<u64>> {
        let mut values = Vec::new();
        for query in queries {
            match self.search(query) {
                SearchResult::Found { value, .. } => values.push(value),
                SearchResult::Missing { .. } => return None,
            }
        }
        Some(values)
    }

    // Callers establish logical < live_length <= capacity. Splitting the sum
    // avoids overflow: in the first arm head+logical < capacity; in the other
    // arm logical-tail < head. No modulo or native pointer arithmetic is used.
    fn physical_index(&self, logical: usize) -> usize {
        let tail = self.rows.len() - self.head;
        if logical < tail {
            self.head + logical
        } else {
            logical - tail
        }
    }

    fn found(&self, logical_index: usize) -> SearchResult {
        let physical_index = self.physical_index(logical_index);
        SearchResult::Found {
            logical_index,
            physical_index,
            value: self.rows[physical_index].value,
        }
    }
}

// The caller supplies a nonempty sorted contiguous segment. The candidate lies
// in [base, base+width); halving shrinks that interval without losing the last
// index whose key is <= query (or index0 if none). Equality takes the midpoint,
// so the final candidate is the last equal within this segment, not the first.
fn segment_search(rows: &[Row], query: &[u8; 32]) -> Result<usize, usize> {
    let mut base = 0;
    let mut width = rows.len();
    while width > 1 {
        let half = width / 2;
        let midpoint = base + half;
        if rows[midpoint].key.cmp(query) != Ordering::Greater {
            base = midpoint;
        }
        width -= half;
    }
    match rows[base].key.cmp(query) {
        Ordering::Equal => Ok(base),
        Ordering::Less => Err(base + 1),
        Ordering::Greater => Err(base),
    }
}
