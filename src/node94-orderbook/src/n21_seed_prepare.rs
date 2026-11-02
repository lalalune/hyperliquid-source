//! Normal-value reconstruction of the fixed n21 delegate route at node94.
//!
//! The complete 707-byte producer proves the seed/permutation premises needed
//! by the existing left steps and n21 continuation. This is exactly 21 raw
//! unsigned words with a disjoint 37-word scratch buffer, not a generic sort,
//! pointer ABI, exception/failure implementation or outer-core entry proof.

#![forbid(unsafe_code)]

use crate::{first_left_insertion, j9_first_front, n21_right_merge};

fn order_two(first: u64, second: u64) -> (u64, u64) {
    if second < first { (second, first) } else { (first, second) }
}

fn sort_four(words: [u64; 4]) -> [u64; 4] {
    let (low1, high1) = order_two(words[0], words[1]);
    let (low2, high2) = order_two(words[2], words[3]);
    let p = low2 < low1;
    let q = high2 < high1;
    let middle = match (p, q) {
        (false, false) => (low2, high1),
        (true, false) => (high1, low1),
        (false, true) => (high2, low2),
        (true, true) => (high2, low1),
    };
    let (low_middle, high_middle) = order_two(middle.0, middle.1);
    [low1.min(low2), low_middle, high_middle, high1.max(high2)]
}

/// The producer's disjoint-buffer value relation. Its failure dispatcher and
/// original pointer/stack ABI are excluded; the native cursor checks pass by
/// the sorted-quartet rank proof for every supplied eight-word value array.
pub fn seed_eight(input: [u64; 8], destination: &mut [u64; 8], temporary: &mut [u64; 8]) {
    let first = sort_four([input[0], input[1], input[2], input[3]]);
    let second = sort_four([input[4], input[5], input[6], input[7]]);
    temporary[..4].copy_from_slice(&first);
    temporary[4..].copy_from_slice(&second);

    let mut left_front = 0;
    let mut right_front = 4;
    let mut left_back: isize = 3;
    let mut right_back: isize = 7;
    for t in 0..4 {
        let left_front_word = temporary[left_front];
        let right_front_word = temporary[right_front];
        let left_back_word = temporary[left_back as usize];
        let right_back_word = temporary[right_back as usize];
        let take_right_front = right_front_word < left_front_word;
        let front_word = if take_right_front { right_front_word } else { left_front_word };
        let back_word = if right_back_word > left_back_word { right_back_word } else { left_back_word };
        destination[t] = front_word;
        destination[7 - t] = back_word;
        if take_right_front { right_front += 1; } else { left_front += 1; }
        if right_back_word < left_back_word { left_back -= 1; } else { right_back -= 1; }
    }
}

/// Chosen cutpoint observations, not a recovered native return object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection {
    pub source_after_seeds: [u64; 21],
    pub scratch_after_seeds: [u64; 37],
    pub prepared_scratch: [u64; 37],
    pub continuation: Result<n21_right_merge::Observation, n21_right_merge::PreparedPrefixError>,
}

/// Reconstruct the normal-value route for exactly the delegate-entry A21.
///
/// The original A and scratch buffers are disjoint by their Rust borrows.
/// Snapshots expose the target-derived producer/preparation cutpoints. The
/// continuation Result is this safe API's observation; production preparation
/// establishes its sorted premises, so it is Ok for every original A21.
pub fn sort_delegate21(output: &mut [u64; 21], scratch: &mut [u64; 37]) -> Projection {
    let first = std::array::from_fn(|index| output[index]);
    let second = std::array::from_fn(|index| output[10 + index]);
    {
        let (prefix, auxiliary) = scratch.split_at_mut(21);
        seed_eight(first, (&mut prefix[..8]).try_into().unwrap(), (&mut auxiliary[..8]).try_into().unwrap());
        seed_eight(second, (&mut prefix[10..18]).try_into().unwrap(), (&mut auxiliary[8..]).try_into().unwrap());
    }
    let source_after_seeds = *output;
    let scratch_after_seeds = *scratch;
    {
        let value = output[8];
        let window = (&mut scratch[..9]).try_into().unwrap();
        let _ = first_left_insertion::insert_loaded(window, value);
    }
    {
        let value = output[9];
        let window = (&mut scratch[..10]).try_into().unwrap();
        let _ = j9_first_front::insert_j9_loaded(window, value);
    }
    let prepared_scratch = *scratch;
    let continuation = n21_right_merge::finish_prepared(output, (&mut scratch[..21]).try_into().unwrap());
    Projection { source_after_seeds, scratch_after_seeds, prepared_scratch, continuation }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quartet_middle_case_partitions_preserve_all_four_words() {
        for input in [[0,2,1,3], [1,2,0,3], [0,3,1,2], [2,3,0,1]] {
            assert_eq!(sort_four(input), [0,1,2,3]);
        }
    }

    #[test]
    fn seed_uses_unsigned_words_and_retains_both_quartet_images() {
        let mut output = [99;8];
        let mut temporary = [77;8];
        seed_eight([u64::MAX,0,1<<63,1,5,2,4,3], &mut output, &mut temporary);
        assert_eq!(output, [0,1,2,3,4,5,1<<63,u64::MAX]);
        assert_eq!(temporary, [0,1,1<<63,u64::MAX,2,3,4,5]);
    }

    #[test]
    fn full_fixed_count_route_initializes_all_scratch_words() {
        let mut output = std::array::from_fn(|index| (20-index) as u64);
        let mut scratch = [u64::MAX;37];
        let projection = sort_delegate21(&mut output, &mut scratch);
        assert!(projection.continuation.is_ok());
        assert_eq!(output, std::array::from_fn(|index| index as u64));
        assert_eq!(projection.prepared_scratch[..10], [11,12,13,14,15,16,17,18,19,20]);
        assert_eq!(scratch[21..25], [17,18,19,20]);
        assert_eq!(scratch[33..37], [3,4,5,6]);
    }
}
