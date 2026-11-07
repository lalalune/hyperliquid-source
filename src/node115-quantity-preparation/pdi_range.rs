//! Fallible derivation of the selected node115 PDI-associated range.
//!
//! This streaming model performs no allocation and does not reproduce the
//! native partial output buffer, panic or return layout.

use core::iter::FusedIterator;

pub const MULTIPLIER: u64 = 10_000;
pub const MAX_RANGE_COUNT: u64 = (1 << 60) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdiRangeError {
    RangeTooLong,
    IndexOutOfRange,
    MultiplyOverflow,
    AddOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdiRange {
    start: u64,
    end: u64,
    base: u64,
    count: u64,
}

impl PdiRange {
    /// Admit the native `8*count` allocation bound without allocating.
    pub fn new(start: u64, end: u64, base: u64) -> Result<Self, PdiRangeError> {
        let count = end.saturating_sub(start);
        if count > MAX_RANGE_COUNT {
            return Err(PdiRangeError::RangeTooLong);
        }
        Ok(Self {
            start,
            end,
            base,
            count,
        })
    }

    pub fn len(self) -> u64 {
        self.count
    }

    pub fn is_empty(self) -> bool {
        self.count == 0
    }

    pub fn start(self) -> u64 {
        self.start
    }

    pub fn end(self) -> u64 {
        self.end
    }

    pub fn base(self) -> u64 {
        self.base
    }

    /// Compute one selected native word without mutating or allocating.
    pub fn get(self, index: u64) -> Result<u64, PdiRangeError> {
        if index >= self.count {
            return Err(PdiRangeError::IndexOutOfRange);
        }
        let product = self
            .base
            .checked_mul(MULTIPLIER)
            .ok_or(PdiRangeError::MultiplyOverflow)?;
        let offset = self
            .start
            .checked_add(index)
            .ok_or(PdiRangeError::AddOverflow)?;
        product
            .checked_add(offset)
            .ok_or(PdiRangeError::AddOverflow)
    }

    pub fn iter(self) -> PdiRangeIter {
        PdiRangeIter {
            range: self,
            index: 0,
        }
    }
}

impl IntoIterator for PdiRange {
    type Item = Result<u64, PdiRangeError>;
    type IntoIter = PdiRangeIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PdiRangeIter {
    range: PdiRange,
    index: u64,
}

impl Iterator for PdiRangeIter {
    type Item = Result<u64, PdiRangeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.range.count {
            return None;
        }
        let result = self.range.get(self.index);
        self.index += 1;
        if result.is_err() {
            self.index = self.range.count;
        }
        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.range.count - self.index;
        match usize::try_from(remaining) {
            Ok(value) => (0, Some(value)),
            Err(_) => (0, None),
        }
    }
}

impl FusedIterator for PdiRangeIter {}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{PdiRange, PdiRangeError, MAX_RANGE_COUNT};
    use std::vec::Vec;

    #[test]
    fn frozen_native_arithmetic_vectors() {
        let text = include_str!(
            "../../research/work-items/RE-004-node115-pdi-range/pdi-range-vectors.tsv"
        );
        let mut rows = 0;
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 6, "malformed vector: {line}");
            let start: u64 = fields[0].parse().unwrap();
            let end: u64 = fields[1].parse().unwrap();
            let base: u64 = fields[2].parse().unwrap();
            let index: u64 = fields[3].parse().unwrap();
            let result = PdiRange::new(start, end, base).and_then(|range| range.get(index));
            match fields[4] {
                "ok" => assert_eq!(result, Ok(fields[5].parse().unwrap()), "{line}"),
                "range" => assert_eq!(result, Err(PdiRangeError::RangeTooLong), "{line}"),
                "out_of_range" => {
                    assert_eq!(result, Err(PdiRangeError::IndexOutOfRange), "{line}")
                }
                "multiply" => {
                    assert_eq!(result, Err(PdiRangeError::MultiplyOverflow), "{line}")
                }
                "add" => assert_eq!(result, Err(PdiRangeError::AddOverflow), "{line}"),
                other => panic!("unknown result {other}: {line}"),
            }
            rows += 1;
        }
        assert_eq!(rows, 49);
    }

    #[test]
    fn range_boundaries_and_reverse_input() {
        assert!(PdiRange::new(10, 10, u64::MAX).unwrap().is_empty());
        assert!(PdiRange::new(10, 9, u64::MAX).unwrap().is_empty());
        assert_eq!(
            PdiRange::new(0, MAX_RANGE_COUNT, 0).map(PdiRange::len),
            Ok(MAX_RANGE_COUNT)
        );
        assert_eq!(
            PdiRange::new(0, MAX_RANGE_COUNT + 1, 0),
            Err(PdiRangeError::RangeTooLong)
        );
    }

    #[test]
    fn iterator_yields_all_values_or_one_terminal_error() {
        let values: Vec<_> = PdiRange::new(10, 14, 3).unwrap().into_iter().collect();
        assert_eq!(
            values,
            std::vec![Ok(30010), Ok(30011), Ok(30012), Ok(30013)]
        );

        let threshold = u64::MAX / super::MULTIPLIER;
        let partial: Vec<_> = PdiRange::new(0, 2000, threshold)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(partial.len(), 1617);
        for (index, item) in partial[..1616].iter().enumerate() {
            assert_eq!(*item, Ok(threshold * super::MULTIPLIER + index as u64));
        }
        assert_eq!(partial[1616], Err(PdiRangeError::AddOverflow));
        assert!(partial.iter().skip(1617).next().is_none());
    }

    #[test]
    fn checked_multiply_and_add_errors_are_distinct() {
        let threshold = u64::MAX / super::MULTIPLIER;
        assert_eq!(
            PdiRange::new(0, 1, threshold + 1).unwrap().get(0),
            Err(PdiRangeError::MultiplyOverflow)
        );
        assert_eq!(
            PdiRange::new(u64::MAX - 1, u64::MAX, threshold)
                .unwrap()
                .get(0),
            Err(PdiRangeError::AddOverflow)
        );
    }

    #[test]
    fn size_hint_allows_early_termination_on_arithmetic_error() {
        let threshold = u64::MAX / super::MULTIPLIER;
        let mut iter = PdiRange::new(0, 2000, threshold).unwrap().into_iter();
        let (lower, upper) = iter.size_hint();
        let actual = iter.by_ref().count();
        assert!(lower <= actual);
        assert!(upper.unwrap() >= actual);
        assert_eq!(actual, 1617);
        assert_eq!(iter.size_hint(), (0, Some(0)));
    }

    #[test]
    fn size_hint_bounds_small_iterators() {
        let mut iter = PdiRange::new(7, 10, 1).unwrap().into_iter();
        assert_eq!(iter.size_hint(), (0, Some(3)));
        assert!(iter.next().is_some());
        assert_eq!(iter.size_hint(), (0, Some(2)));
    }
}
