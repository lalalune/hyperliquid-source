//! Logical certificate-row normalization for the pinned node115 artifact.
//!
//! Native long-sort stability is established by the accompanying static
//! contract, not by the embedded Rust source-path string. This implementation
//! uses its own merge sort. It preserves each opaque tail without assigning
//! cryptographic meaning to it. It does not verify signatures or quorum.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// First 20 bytes are the comparison key. `tail` preserves every other byte
/// of the source row; padding, signature fields and TC extras are not decoded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row<const TAIL: usize> {
    pub key: [u8; 20],
    pub tail: [u8; TAIL],
}

pub type QcRow = Row<76>;
pub type TcRow = Row<84>;

/// Native constructor's choice after deduplication. This enum does not encode
/// or reproduce either native container's memory layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageClass {
    Flat,
    Tree,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Normalized<const TAIL: usize> {
    pub rows: Vec<Row<TAIL>>,
    pub storage: StorageClass,
}

fn stable_sort<const TAIL: usize>(rows: &[Row<TAIL>]) -> Vec<Row<TAIL>> {
    if rows.len() < 2 {
        return rows.to_vec();
    }
    let mid = rows.len() / 2;
    let left = stable_sort(&rows[..mid]);
    let right = stable_sort(&rows[mid..]);
    let mut output = Vec::with_capacity(rows.len());
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        // Equality takes the earlier half, preserving original equal-key order.
        if left[i].key <= right[j].key {
            output.push(left[i].clone());
            i += 1;
        } else {
            output.push(right[j].clone());
            j += 1;
        }
    }
    output.extend_from_slice(&left[i..]);
    output.extend_from_slice(&right[j..]);
    output
}

fn normalize<const TAIL: usize>(rows: &[Row<TAIL>]) -> Normalized<TAIL> {
    let mut retained: Vec<Row<TAIL>> = Vec::new();
    for row in stable_sort(rows) {
        if let Some(previous) = retained.last_mut()
            && previous.key == row.key
        {
            // Native compaction retains the later whole sorted row. Stability
            // therefore makes this the last original row for the key.
            *previous = row;
        } else {
            retained.push(row);
        }
    }
    let storage = if retained.len() <= 64 {
        StorageClass::Flat
    } else {
        StorageClass::Tree
    };
    Normalized {
        rows: retained,
        storage,
    }
}

/// Normalize logical 96-byte QC rows by all 20 key bytes. The last original
/// row for each key wins, regardless of the 20/21 native sorting dispatch.
pub fn normalize_qc(rows: &[QcRow]) -> Normalized<76> {
    normalize(rows)
}

/// Normalize logical 104-byte TC rows with the same key and whole-row rule.
pub fn normalize_tc(rows: &[TcRow]) -> Normalized<84> {
    normalize(rows)
}
