//! The certificate's signature collection at input `+0x00..+0x20`.
//!
//! Natively a tree (first word `0x8000000000000000`: root `+8`, height `+0x10`, length `+0x18`; leaves hold
//! 20 byte keys from `+0x320` and 72 byte values from `+8`) or a ring of 0x60 byte rows (capacity `+0`,
//! buffer `+8`, head `+0x10`, length `+0x18`; key in the first 20 bytes, signature bytes at row `+0x18`).
//! `node115-certificate-long-sort` produces the rows of such a collection and picks the form by count
//! (at most 64 rows: ring, more: tree); [`SigMap::from_normalized`] builds the collection from its output.
//!
//! The signature pointer the verifier passes on differs by form: ring row `+0x18`, but for a tree the value
//! slot `leaf+8+72*i` that `0x513b200` returns next to the key address `leaf+0x320+20*i` (relations.tsv V5r,
//! V5t, T1; an earlier text said `+0x18` for both). The model holds no addresses: the check receives the
//! (key, signature) pair of an entry, which is what both forms hand over.

use std::collections::BTreeMap;

use node115_certificate_long_sort::{Normalized, StorageClass};

pub type Address = [u8; 20];
/// 64 signature bytes and one recovery byte; the other 7 bytes of the 72 byte native value are not read.
pub type Signature = [u8; 65];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigRow {
    pub key: Address,
    pub sig: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigMap {
    Tree(BTreeMap<Address, Signature>),
    /// `rows.len()` is the capacity; the live rows are `len` rows from `head`, wrapping.
    Ring { rows: Vec<SigRow>, head: usize, len: usize },
}

impl SigMap {
    pub fn empty_ring() -> Self {
        SigMap::Ring { rows: Vec::new(), head: 0, len: 0 }
    }

    pub fn tree(rows: impl IntoIterator<Item = SigRow>) -> Self {
        SigMap::Tree(rows.into_iter().map(|r| (r.key, r.sig)).collect())
    }

    /// `None` unless `len <= capacity` and `head < capacity` (head 0 for capacity 0). Nothing else is
    /// checked: the key order of the live rows is free, and they are visited in ring order from the head
    /// (`tests/sigslot.rs` walks a ring whose logical order is not sorted). The native consumers iterate
    /// this collection and do not search it, so no order requirement is read from the bytes; the producer
    /// `node115-certificate-long-sort` emits sorted rows. Native code also tolerates a head in
    /// `capacity..2*capacity` (one subtraction); that range is not modelled. The enum is public: building
    /// `SigMap::Ring` directly skips even these checks (`len > capacity` revisits rows, a non-zero `len`
    /// with no rows panics in [`SigMap::entries`]); such values are outside the model.
    pub fn ring(rows: Vec<SigRow>, head: usize, len: usize) -> Option<Self> {
        let cap = rows.len();
        (len <= cap && (head < cap || (cap == 0 && head == 0))).then_some(SigMap::Ring { rows, head, len })
    }

    /// Builds the collection the way the certificate normalizer chose it: rows are 96 byte rows whose
    /// 76 byte tail holds 4 padding bytes, the 65 signature bytes and 7 more bytes.
    pub fn from_normalized(n: &Normalized<76>) -> Self {
        let row = |r: &node115_certificate_long_sort::Row<76>| {
            let mut sig = [0u8; 65];
            sig.copy_from_slice(&r.tail[4..69]);
            SigRow { key: r.key, sig }
        };
        match n.storage {
            StorageClass::Tree => SigMap::tree(n.rows.iter().map(row)),
            StorageClass::Flat => {
                let rows: Vec<SigRow> = n.rows.iter().map(row).collect();
                let len = rows.len();
                SigMap::Ring { rows, head: 0, len }
            }
        }
    }

    /// The length word at `+0x18`.
    pub fn len(&self) -> usize {
        match self {
            SigMap::Tree(m) => m.len(),
            SigMap::Ring { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Entries in the order the native iterators visit them: tree key order, ring order from the head.
    pub fn entries(&self) -> Vec<(&Address, &Signature)> {
        match self {
            SigMap::Tree(m) => m.iter().collect(),
            SigMap::Ring { rows, head, len } => (0..*len)
                .map(|i| {
                    let r = &rows[(head + i) % rows.len()];
                    (&r.key, &r.sig)
                })
                .collect(),
        }
    }
}
