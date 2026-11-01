//! Safe value projection of node #94 [0x52cfe00, 0x52cfe4d).
//! Original table/base/count memory must remain stable throughout the call.
#![no_std]
#![forbid(unsafe_code)]

const STRIDE_WORDS: usize = 6600;

const fn element_count(field: u32) -> u64 {
    1_u64 << (field & 63)
}

/// Words through the last required element, including any intervening words.
///
/// Returns `None` if the span cannot form a valid slice on this platform.
/// This is a new safety preflight, not an original target return value.
pub fn required_words(index: u32, field: u32) -> Option<usize> {
    let count = usize::try_from(element_count(field)).ok()?;
    let index = usize::try_from(index).ok()?;
    let words = count
        .checked_sub(1)?
        .checked_mul(STRIDE_WORDS)?
        .checked_add(index)?
        .checked_add(1)?;
    let bytes = words.checked_mul(core::mem::size_of::<u64>())?;
    if bytes > isize::MAX as usize {
        return None;
    }
    Some(words)
}

/// Sum words at `index + row * 6600`, for `2^(field & 63)` rows.
///
/// Arithmetic wraps modulo 2^64. An insufficient or unrepresentable span
/// returns `None` before reading any table element. No arbitrary count cap
/// is imposed. The original pointer/stack ABI and mutable-memory behavior
/// are outside this immutable-slice API.
pub fn strided_sum(table: &[u64], index: u32, field: u32) -> Option<u64> {
    let required = required_words(index, field)?;
    if table.len() < required {
        return None;
    }
    let mut position = usize::try_from(index).ok()?;
    let mut remaining = element_count(field);
    let mut total = 0_u64;
    while remaining != 0 {
        total = total.wrapping_add(table[position]);
        remaining -= 1;
        if remaining != 0 {
            position += STRIDE_WORDS;
        }
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::{required_words, strided_sum};

    #[test]
    fn always_one_or_more_and_masked_field() {
        assert_eq!(strided_sum(&[7, 19], 1, 0), Some(19));
        assert_eq!(strided_sum(&[7, 19], 1, 64), Some(19));
        assert_eq!(strided_sum(&[7], 0, 0xffff_ffc0), Some(7));
        assert_eq!(required_words(2, 0), Some(3));
    }

    #[test]
    fn actual_stride_exact_span_and_wrapping_sum() {
        let mut table = [99_u64; 6602];
        table[1] = u64::MAX;
        table[6601] = 2;
        assert_eq!(required_words(1, 1), Some(6602));
        assert_eq!(strided_sum(&table, 1, 1), Some(1));
        assert_eq!(strided_sum(&table[..6601], 1, 1), None);
    }

    #[test]
    fn impossible_or_missing_memory_refused() {
        assert_eq!(strided_sum(&[], 0, 0), None);
        assert_eq!(strided_sum(&[], u32::MAX, 1), None);
        assert_eq!(required_words(0, 63), None);
        assert_eq!(strided_sum(&[], 0, u32::MAX), None);
    }
}
