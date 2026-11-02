#![no_std]
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Projection {
    ExcludedStatus,
    IndexOutsideI32,
    ZeroCallee { index: u32 },
    Stored { index: u32, words: [u32; 3] },
}

/// Integer/result-field projection conditional on normal opaque helper calls.
/// Raw status, signed word, retained DWORD and supplied callee EAX have no
/// asserted calendar units, concrete native types or original ABI meaning.
pub fn project(s: i64, status: u32, retained: u32, callee_eax: u32) -> Projection {
    if status == 1 {
        return Projection::ExcludedStatus;
    }
    // The maintained multiplier/shift proof establishes these Euclidean forms
    // for the entire i64 domain. No overflow or floating point is required.
    let quotient = s.div_euclid(86_400);
    let remainder = s.rem_euclid(86_400) as u32;
    let index = quotient + 719_163;
    if index < i32::MIN as i64 || index > i32::MAX as i64 {
        return Projection::IndexOutsideI32;
    }
    let index = index as u32;
    if callee_eax == 0 {
        Projection::ZeroCallee { index }
    } else {
        Projection::Stored {
            index,
            words: [callee_eax, remainder, retained],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negative_input_euclidean_field_and_callee_zero_are_distinct() {
        assert_eq!(
            project(-1, 0, 7, 8),
            Projection::Stored {
                index: 719162,
                words: [8, 86399, 7]
            }
        );
        assert_eq!(
            project(0, 0, 7, 0),
            Projection::ZeroCallee { index: 719163 }
        );
        assert_eq!(project(i64::MIN, 0, 0, 1), Projection::IndexOutsideI32);
        assert_eq!(project(i64::MIN, 1, 0, 1), Projection::ExcludedStatus);
    }
}
