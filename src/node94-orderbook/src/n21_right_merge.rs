//! One qualified continuation at node94 `0x4918f4d..0x4919091`.
//!
//! The left ten words and right eight-word seed must already be sorted as
//! unsigned words. This module does not establish their native producer or
//! relation to the original source array. It inserts current A[18..21), then
//! performs the exact fixed n21 two-ended merge and center selection.
//! Returned records describe logical projections, not target ABI objects or
//! the compiled program's physical memory-write trace.

#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Half {
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Area {
    Scratch,
    Output,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogicalWrite {
    pub area: Area,
    pub index: usize,
    pub value: u64,
}

impl LogicalWrite {
    const EMPTY: Self = Self { area: Area::Scratch, index: 0, value: 0 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairObservation {
    pub front_retired: Half,
    pub back_value_loaded_from: Half,
    pub back_retired: Half,
}

impl PairObservation {
    const EMPTY: Self = Self {
        front_retired: Half::Left,
        back_value_loaded_from: Half::Left,
        back_retired: Half::Left,
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub insertion_indices: [usize; 3],
    pub center_from: Half,
    /// Left front/exclusive back, right front/exclusive back, as word indices.
    pub final_cursors: [usize; 4],
    pub pairs: [PairObservation; 10],
    pub writes: [LogicalWrite; 54],
    pub write_count: usize,
}

impl Observation {
    fn new() -> Self {
        Self {
            insertion_indices: [0; 3],
            center_from: Half::Left,
            final_cursors: [0; 4],
            pairs: [PairObservation::EMPTY; 10],
            writes: [LogicalWrite::EMPTY; 54],
            write_count: 0,
        }
    }

    fn record(&mut self, area: Area, index: usize, value: u64) {
        self.writes[self.write_count] = LogicalWrite { area, index, value };
        self.write_count += 1;
    }
}

/// These atomic refusals are this safe API's policy outside the native domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedPrefixError {
    LeftUnsorted,
    RightSeedUnsorted,
}

/// Finish the fixed n21 continuation from the explicit prepared-state premises.
///
/// On success, output is the unsigned sort of incoming scratch[0..18) plus
/// current output[18..21), and scratch's right eleven words are prepared.
/// Checking sorted premises before any write is a new safe API policy.
/// Original seed reachability, pointer aliases, failures and ABI are excluded.
pub fn finish_prepared(
    output: &mut [u64; 21],
    scratch: &mut [u64; 21],
) -> Result<Observation, PreparedPrefixError> {
    if scratch[..10].windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(PreparedPrefixError::LeftUnsorted);
    }
    if scratch[10..18].windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(PreparedPrefixError::RightSeedUnsorted);
    }
    let mut observation = Observation::new();
    for j in 8..11 {
        let value = output[10 + j];
        scratch[10 + j] = value;
        observation.record(Area::Scratch, 10 + j, value);
        let mut destination = j;
        while destination > 0 && value < scratch[10 + destination - 1] {
            scratch[10 + destination] = scratch[10 + destination - 1];
            observation.record(Area::Scratch, 10 + destination, scratch[10 + destination]);
            destination -= 1;
        }
        if destination < j {
            scratch[10 + destination] = value;
            observation.record(Area::Scratch, 10 + destination, value);
        }
        observation.insertion_indices[j - 8] = destination;
    }

    let mut left_front = 0;
    let mut right_front = 10;
    // Native left-back may temporarily reach relative index -1 after its
    // tenth retirement. It is never read then; +1 forms the exclusive end.
    let mut left_back: isize = 9;
    let mut right_back: isize = 20;
    for t in 0..10 {
        let left_front_word = scratch[left_front];
        let right_front_word = scratch[right_front];
        let left_back_word = scratch[left_back as usize];
        let right_back_word = scratch[right_back as usize];
        let (front_word, front_retired) = if right_front_word < left_front_word {
            (right_front_word, Half::Right)
        } else {
            (left_front_word, Half::Left)
        };
        // Keep value provenance distinct from the back cursor retirement.
        let (back_word, back_value_loaded_from) = if right_back_word > left_back_word {
            (right_back_word, Half::Right)
        } else {
            (left_back_word, Half::Left)
        };
        let back_retired = if right_back_word < left_back_word { Half::Left } else { Half::Right };
        observation.pairs[t] = PairObservation { front_retired, back_value_loaded_from, back_retired };

        output[t] = front_word;
        observation.record(Area::Output, t, front_word);
        match front_retired {
            Half::Left => left_front += 1,
            Half::Right => right_front += 1,
        }
        output[20 - t] = back_word;
        observation.record(Area::Output, 20 - t, back_word);
        match back_retired {
            Half::Left => left_back -= 1,
            Half::Right => right_back -= 1,
        }
    }

    let left_exclusive = (left_back + 1) as usize;
    let right_exclusive = (right_back + 1) as usize;
    let (center, center_from) = if left_front < left_exclusive {
        (scratch[left_front], Half::Left)
    } else {
        (scratch[right_front], Half::Right)
    };
    output[10] = center;
    observation.record(Area::Output, 10, center);
    match center_from {
        Half::Left => left_front += 1,
        Half::Right => right_front += 1,
    }
    observation.center_from = center_from;
    observation.final_cursors = [left_front, left_exclusive, right_front, right_exclusive];
    // The native final guards pass by the qualified rank/cursor proof. These
    // projections do not interpret what its failure dispatcher would do.
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_back_value_and_retirement_are_distinct() {
        let mut output = [42; 21];
        let mut scratch = [42; 21];
        let result = finish_prepared(&mut output, &mut scratch).unwrap();
        assert_eq!(result.pairs, [PairObservation {
            front_retired: Half::Left,
            back_value_loaded_from: Half::Left,
            back_retired: Half::Right,
        }; 10]);
        assert_eq!(result.final_cursors, [10, 10, 11, 11]);
        assert_eq!(result.write_count, 24);
    }

    #[test]
    fn left_back_can_finish_at_minus_one_without_a_read() {
        let mut output = [0; 21];
        output[18..].copy_from_slice(&[8, 9, 10]);
        let mut scratch = [0; 21];
        for (i, word) in scratch[..10].iter_mut().enumerate() { *word = 100 + i as u64; }
        for (i, word) in scratch[10..18].iter_mut().enumerate() { *word = i as u64; }
        let result = finish_prepared(&mut output, &mut scratch).unwrap();
        assert_eq!(result.final_cursors, [0, 0, 21, 21]);
        assert_eq!(output[10], 10);
        assert_eq!(output[11], 100);
    }

    #[test]
    fn unsupported_prepared_order_is_an_atomic_api_refusal() {
        let mut output = [7; 21];
        let mut scratch = [3; 21];
        scratch[10] = 4;
        let before = (output, scratch);
        assert_eq!(finish_prepared(&mut output, &mut scratch), Err(PreparedPrefixError::RightSeedUnsorted));
        assert_eq!((output, scratch), before);
    }
}
