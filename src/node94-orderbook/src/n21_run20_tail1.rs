#![forbid(unsafe_code)]

//! Fixed n21, first-natural-run20/tail1 normal value projection.
//!
//! Target node94 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
//! This projects the selected native prefix normalization and backward merge,
//! not arbitrary counts, other run lengths, original ABI or physical stores.
//! Its native correspondence requires stable valid disjoint nonwrapping source,
//! scratch and live frames, normal returns, and an ordinary nonoverlap contract
//! for dynamically imported memcpy@GLIBC_2.14's selected0/8-byte requests.
//! No runtime provider, allocator freshness or provider frame bound is recovered.

use crate::n21_outer_admission::first_short_run21;

/// Chosen observation labels; neither native enum ABI nor element identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Left,
    Tail,
}

/// Logical native-loop observation, not measured compiler store instructions.
///
/// On equal bits, `loaded_bits_provider` is Left while `retired_cursor` is Tail.
/// These describe distinct operands; equal u64 bits cannot reveal identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopStore {
    pub output_index: usize,
    pub word: u64,
    pub compared_left_index: usize,
    pub compared_left_word: u64,
    pub compared_tail_word: u64,
    pub loaded_bits_provider: Side,
    pub retired_cursor: Side,
    pub left_remaining_after: usize,
    pub tail_remaining_after: usize,
}

/// Chosen value/observation result; not native return registers or a type layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Run20Observation {
    pub post_normalization21: [u64; 21],
    pub natural_run: usize,
    pub ascending: bool,
    pub upper_bound_index: usize,
    pub loop_stores: Vec<LoopStore>,
    pub reversal_word_writes: usize,
    pub first_copy_bytes: usize,
    pub terminal_copy_destination_index: usize,
    pub terminal_copy_bytes: usize,
    pub copy_call_count: usize,
}

/// Safe-API refusal outside this exact first-run20 domain; not native failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutsideRun20 {
    pub natural_run: usize,
    pub ascending: bool,
}

/// Project only the selected original-A21 run20/tail1 normal value route.
///
/// The established scan makes the first20 words nondecreasing or strictly
/// decreasing. The latter are normalized before the one-word tail's no-access
/// delegate return and backward merge. The safe scratch prefix is a chosen
/// initialized view; only scratch[0] changes. It does not model physical512-word
/// allocation, libc execution, stack addresses or pointer lifetime checks.
/// Unsupported run lengths leave both arrays unchanged by chosen API policy.
#[must_use]
pub fn project_first_run20(
    words: &mut [u64; 21],
    scratch: &mut [u64; 4],
) -> Result<Run20Observation, OutsideRun20> {
    let entry = first_short_run21(words, 0);
    if entry.natural_run != 20 {
        return Err(OutsideRun20 {
            natural_run: entry.natural_run,
            ascending: entry.ascending,
        });
    }
    let descending_normalized = !entry.ascending;
    if descending_normalized {
        words[..20].reverse();
    }
    let post_normalization21 = *words;
    let tail = words[20];
    scratch[0] = tail;
    let mut left = 20;
    let mut destination = 20;
    let mut tail_live = true;
    let mut loop_stores = Vec::with_capacity(20);
    loop {
        let previous_index = left - 1;
        let previous = words[previous_index];
        let loaded_bits_provider = if tail > previous { Side::Tail } else { Side::Left };
        let output = if tail > previous { tail } else { previous };
        words[destination] = output;
        let take_tail = tail >= previous;
        if take_tail {
            tail_live = false;
        } else {
            left -= 1;
        }
        loop_stores.push(LoopStore {
            output_index: destination,
            word: output,
            compared_left_index: previous_index,
            compared_left_word: previous,
            compared_tail_word: tail,
            loaded_bits_provider,
            retired_cursor: if take_tail { Side::Tail } else { Side::Left },
            left_remaining_after: left,
            tail_remaining_after: usize::from(tail_live),
        });
        if left == 0 || !tail_live {
            break;
        }
        destination -= 1;
    }
    if tail_live {
        words[left] = scratch[0];
    }
    Ok(Run20Observation {
        post_normalization21,
        natural_run: entry.natural_run,
        ascending: entry.ascending,
        upper_bound_index: left,
        loop_stores,
        reversal_word_writes: if descending_normalized { 20 } else { 0 },
        first_copy_bytes: 8,
        terminal_copy_destination_index: left,
        terminal_copy_bytes: if tail_live { 8 } else { 0 },
        copy_call_count: 2,
    })
}

#[cfg(test)]
mod tests {
    use super::{Side, project_first_run20};

    #[test]
    fn left_exhaustion_requires_the_terminal_eight_byte_copy() {
        let mut words = std::array::from_fn(|i| if i < 20 { 2 * i as u64 + 2 } else { 1 });
        let mut scratch = [99, 98, 97, 96];
        let result = project_first_run20(&mut words, &mut scratch).unwrap();
        assert_eq!(words[0], 1);
        assert_eq!(&words[1..], &std::array::from_fn::<_, 20, _>(|i| 2 * i as u64 + 2));
        assert_eq!(result.loop_stores.len(), 20);
        assert_eq!(result.terminal_copy_destination_index, 0);
        assert_eq!(result.terminal_copy_bytes, 8);
        assert_eq!(scratch, [1, 98, 97, 96]);
    }

    #[test]
    fn descending_prefix_normalizes_before_unsigned_max_tail() {
        let mut words = std::array::from_fn(|i| if i < 20 { 40 - 2 * i as u64 } else { u64::MAX });
        let mut scratch = [0; 4];
        let result = project_first_run20(&mut words, &mut scratch).unwrap();
        assert_eq!(result.post_normalization21[..20], std::array::from_fn::<_, 20, _>(|i| 2 * i as u64 + 2));
        assert_eq!(result.reversal_word_writes, 20);
        assert_eq!(result.loop_stores.len(), 1);
        assert_eq!(result.upper_bound_index, 20);
        assert_eq!(result.terminal_copy_bytes, 0);
        assert_eq!(words[20], u64::MAX);
    }

    #[test]
    fn equal_loaded_bits_and_retired_cursor_are_separate() {
        let mut words = std::array::from_fn(|i| if i < 20 { 2 * i as u64 + 2 } else { 20 });
        let mut scratch = [0; 4];
        let result = project_first_run20(&mut words, &mut scratch).unwrap();
        let last = result.loop_stores.last().unwrap();
        assert_eq!(last.word, 20);
        assert_eq!(last.loaded_bits_provider, Side::Left);
        assert_eq!(last.retired_cursor, Side::Tail);
        assert_eq!(last.left_remaining_after, 10);
        assert_eq!(result.upper_bound_index, 10);
        assert_eq!(result.copy_call_count, 2);
    }

    #[test]
    fn other_runs_are_safe_api_policy_without_native_refusal_claim() {
        let mut words = [7; 21];
        let mut scratch = [99, 98, 97, 96];
        let before = (words, scratch);
        assert_eq!(project_first_run20(&mut words, &mut scratch).unwrap_err().natural_run, 21);
        assert_eq!((words, scratch), before);
    }
}
