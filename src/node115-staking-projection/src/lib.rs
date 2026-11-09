//! Selected node #115 staking projection: reduction of yielded 32-byte rows.
//! Iterator traversal and append/allocation are caller-supplied boundaries.
#![no_std]
#![forbid(unsafe_code)]

/// The yielded row's first 24 bytes have no assigned meaning here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedRow {
    pub opaque: [u8; 24],
    pub value: u64,
}

impl NestedRow {
    /// Decode the native little-endian 32-byte row; the first 24 bytes stay opaque.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut opaque = [0; 24];
        opaque.copy_from_slice(&bytes[..24]);
        let mut value = [0; 8];
        value.copy_from_slice(&bytes[24..]);
        Self {
            opaque,
            value: u64::from_le_bytes(value),
        }
    }
}

/// Logical record handed to the caller's append helper. Metadata identities
/// are deliberately opaque: neither is proven to be an address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectedRow {
    pub total: u64,
    pub first: [u8; 20],
    pub second: [u8; 20],
}

impl ProjectedRow {
    /// Encode the observed 48-byte local handoff in little-endian order.
    pub fn to_bytes(self) -> [u8; 48] {
        let mut out = [0; 48];
        out[..8].copy_from_slice(&self.total.to_le_bytes());
        out[8..28].copy_from_slice(&self.first);
        out[28..48].copy_from_slice(&self.second);
        out
    }
}

/// Reduce valid iterator yields. Addition saturates independently at each step.
pub fn reduce(rows: impl IntoIterator<Item = NestedRow>) -> u64 {
    rows.into_iter()
        .fold(0u64, |sum, row| sum.saturating_add(row.value))
}

pub fn project(
    rows: impl IntoIterator<Item = NestedRow>,
    first: [u8; 20],
    second: [u8; 20],
) -> ProjectedRow {
    ProjectedRow {
        total: reduce(rows),
        first,
        second,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(value: u64) -> NestedRow {
        NestedRow {
            opaque: [0xa5; 24],
            value,
        }
    }
    #[test]
    fn empty_and_duplicate() {
        assert_eq!(reduce([]), 0);
        assert_eq!(reduce([row(7), row(7), row(0)]), 14);
    }
    #[test]
    fn saturates_without_wrapping() {
        assert_eq!(reduce([row(u64::MAX - 1), row(1)]), u64::MAX);
        assert_eq!(reduce([row(u64::MAX - 1), row(2), row(4)]), u64::MAX);
    }
    #[test]
    fn projection_keeps_distinct_metadata() {
        let p = project([row(4), row(9)], [0x12; 20], [0x34; 20]);
        assert_eq!(
            p,
            ProjectedRow {
                total: 13,
                first: [0x12; 20],
                second: [0x34; 20]
            }
        );
    }
    #[test]
    fn physical_row_and_record_offsets() {
        let mut raw = [0x5a; 32];
        raw[24..].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
        let output = project([NestedRow::from_bytes(raw)], [0x21; 20], [0x43; 20]).to_bytes();
        assert_eq!(&output[..8], &raw[24..]);
        assert_eq!(&output[8..28], &[0x21; 20]);
        assert_eq!(&output[28..], &[0x43; 20]);
    }
    #[test]
    fn reduction_matches_wide_oracle_for_boundaries() {
        let values = [0, 1, 2, u64::MAX / 2, u64::MAX - 1, u64::MAX];
        for a in values {
            for b in values {
                for c in values {
                    let expected = (a as u128 + b as u128 + c as u128).min(u64::MAX as u128) as u64;
                    assert_eq!(reduce([row(a), row(b), row(c)]), expected);
                }
            }
        }
    }
}
