//! Conditional cursor prefix and independently fresh post-helper arithmetic.
//! The four observed columns are an explicit scope premise, not a recovered
//! native enum or validity bound. No numeric helper result is fabricated.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Index4(u8);
impl Index4 {
    pub fn new(raw: u8) -> Option<Self> {
        (raw < 4).then_some(Self(raw))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedColumn(u8);
impl ObservedColumn {
    /// Qualifies the reconstructed domain; this is not native rejection policy.
    pub fn new(raw: u8) -> Option<Self> {
        (raw < 4).then_some(Self(raw))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CursorNext {
    DiagnosticBoundary,
    Terminal {
        index: u64,
    },
    NumericHelperBoundary {
        index: u8,
        bonus: bool,
        selector: u8,
        payload: [u8; 20],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorObservation {
    pub cursor: u64,
    pub wrote_cursor: bool,
    pub next: CursorNext,
}

pub fn cursor_prefix(
    index: u64,
    offset: u64,
    identity_byte: u8,
    helper_selector: u8,
    payload: [u8; 20],
) -> CursorObservation {
    let diagnostic = CursorObservation {
        cursor: index,
        wrote_cursor: false,
        next: CursorNext::DiagnosticBoundary,
    };
    let Some(incremented) = index.checked_add(1) else {
        return diagnostic;
    };
    let Some(total) = offset.checked_add(incremented) else {
        return diagnostic;
    };
    let cursor = if total >= 5 { 4 } else { incremented };
    let next = if index >= 4 || total >= 5 {
        CursorNext::Terminal { index }
    } else {
        CursorNext::NumericHelperBoundary {
            index: index as u8,
            bonus: identity_byte == index as u8,
            selector: helper_selector,
            payload,
        }
    };
    CursorObservation {
        cursor,
        wrote_cursor: true,
        next,
    }
}

const A: [u64; 4] = [100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000];
const B: [u64; 4] = [
    50_000,
    20_000_000_000_000,
    5_000_000_000,
    20_000_000_000_000,
];
const C: [u64; 4] = [
    200_000,
    50_000_000_000_000,
    10_000_000_000,
    50_000_000_000_000,
];
const ROWS: [[u64; 4]; 4] = [A, B, C, A];

/// Analysis labels, not original Rust error or iterator variants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ItemNext {
    Yield(u64),
    FailedRawC5,
    ExistingCleanupBoundary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemObservation {
    pub output_tag: u16,
    pub wrote_tag: bool,
    pub next: ItemNext,
}

/// Fresh RAX/bonus/index/column point, not a claimed numeric-helper return.
/// Actual C5 cleanup CALL/RET is separately closed by original instruction
/// replay. Other existing-record cleanup remains a pre-call boundary.
pub fn post_helper(
    index: Index4,
    helper_value: u64,
    bonus: bool,
    column: ObservedColumn,
    old_tag: u16,
) -> ItemObservation {
    let base = helper_value.saturating_add(u64::from(bonus));
    let multiplier = ROWS[index.0 as usize][column.0 as usize];
    if let Some(product) = base.checked_mul(multiplier) {
        ItemObservation {
            output_tag: old_tag,
            wrote_tag: false,
            next: ItemNext::Yield(product),
        }
    } else if old_tag == 0x1a2 || old_tag == 0xc5 {
        ItemObservation {
            output_tag: 0xc5,
            wrote_tag: true,
            next: ItemNext::FailedRawC5,
        }
    } else {
        ItemObservation {
            output_tag: old_tag,
            wrote_tag: false,
            next: ItemNext::ExistingCleanupBoundary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("../../research/work-items/RE-001-stake-cursor-115/client_fixture.rs");
    #[test]
    fn sealed_original_cursor_and_actual_cleanup_observations() {
        for line in
            include_str!("../../research/work-items/RE-001-stake-cursor-115/target-smoke.tsv")
                .lines()
        {
            let fields: Vec<_> = line.split('\t').collect();
            let input: Vec<u64> = fields[..6].iter().map(|s| s.parse().unwrap()).collect();
            assert_eq!(evaluate_row(&input).unwrap(), fields[6]);
        }
    }
    #[test]
    fn qualified_columns_and_unclosed_cleanup_are_explicit() {
        assert_eq!(ObservedColumn::new(4), None);
        let point = post_helper(
            Index4::new(0).unwrap(),
            u64::MAX,
            true,
            ObservedColumn::new(0).unwrap(),
            0,
        );
        assert_eq!(point.next, ItemNext::ExistingCleanupBoundary);
        assert!(!point.wrote_tag);
        assert_eq!(
            cursor_prefix(u64::MAX, 0, 0, 0, [0; 20]).next,
            CursorNext::DiagnosticBoundary
        );
    }
}
