//! Conditional node #115 flat margin-table range selection.
//!
//! This borrowed value API does not reproduce native layout, diagnostics or
//! margin arithmetic. Its correspondence assumes the stable flat-table domain
//! recorded in the accompanying evidence packet.
#![no_std]
#![forbid(unsafe_code)]

/// A complete physical row, preserving its opaque bytes.
pub type Row = [u8; 40];

/// Safe host admission errors, not recovered native error variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidView {
    Bounds,
    Order,
}

/// A stable, logically ordered view of the borrowed physical allocation.
#[derive(Clone, Copy, Debug)]
pub struct Ring<'a> {
    rows: &'a [Row],
    head: usize,
    live: usize,
}

/// The final included row and chosen value/identity observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedRow<'a> {
    pub logical_index: usize,
    pub physical_index: usize,
    pub row: &'a Row,
    pub key: u64,
    pub offset: u64,
    pub divisor: u8,
}

/// The complete included prefix, in its original two physical slices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarginRange<'a> {
    pub included_count: usize,
    pub first: &'a [Row],
    pub second: &'a [Row],
    pub selected: Option<SelectedRow<'a>>,
}

fn word(row: &Row, offset: usize) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&row[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

impl<'a> Ring<'a> {
    /// Checks bounds before comparing only the live logical keys.
    ///
    /// Empty backing requires head/live zero. Nonempty backing requires a
    /// canonical head even when live is zero. Duplicate keys are permitted;
    /// inactive rows and every non-key byte are unrestricted.
    pub fn new(rows: &'a [Row], head: usize, live: usize) -> Result<Self, InvalidView> {
        let capacity = rows.len();
        if live > capacity || (capacity == 0 && head != 0) || (capacity != 0 && head >= capacity) {
            return Err(InvalidView::Bounds);
        }
        let ring = Self { rows, head, live };
        for logical in 1..live {
            if word(&rows[ring.physical(logical - 1)], 0) > word(&rows[ring.physical(logical)], 0) {
                return Err(InvalidView::Order);
            }
        }
        Ok(ring)
    }

    // Called only for logical indices below live. Avoids overflowing head+i.
    fn physical(&self, logical: usize) -> usize {
        let tail = self.rows.len() - self.head;
        if logical < tail {
            self.head + logical
        } else {
            logical - tail
        }
    }

    /// Includes every live row with unsigned little-endian key <= exposure.
    ///
    /// The final logical equal row wins, including duplicates across the seam.
    /// Both empty slices point to backing index zero. A missing selected row
    /// is a chosen host observation, not the downstream native diagnostic.
    /// Divisor zero is accepted: this operation performs no margin arithmetic.
    pub fn through(&self, exposure: u64) -> MarginRange<'a> {
        let mut low = 0;
        let mut high = self.live;
        while low < high {
            let middle = low + (high - low) / 2;
            if word(&self.rows[self.physical(middle)], 0) <= exposure {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let included_count = low;
        if included_count == 0 {
            return MarginRange {
                included_count: 0,
                first: &self.rows[0..0],
                second: &self.rows[0..0],
                selected: None,
            };
        }

        let first_len = included_count.min(self.rows.len() - self.head);
        let first = &self.rows[self.head..self.head + first_len];
        let second = &self.rows[..included_count - first_len];
        let logical_index = included_count - 1;
        let physical_index = self.physical(logical_index);
        let row = &self.rows[physical_index];
        MarginRange {
            included_count,
            first,
            second,
            selected: Some(SelectedRow {
                logical_index,
                physical_index,
                row,
                key: word(row, 0),
                offset: word(row, 24),
                divisor: row[32],
            }),
        }
    }
}
