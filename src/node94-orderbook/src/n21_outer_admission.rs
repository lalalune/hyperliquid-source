#![forbid(unsafe_code)]

//! Value projection of one fixed-21 wrapper/core/adapter admission route.
//!
//! Target node94 SHA256:
//! 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
//! The native route is wrapper 0x4486d10 -> core 0x4dbd490, its first
//! short-run branch 0x4dbd6f1 -> 0x4dbd593, adapter 0x4497a90, then entry
//! 0x4918d30. This module performs no delegate effect or sorting.
//!
//! The native statement requires stable valid A21, ordinary nonfaulting calls,
//! nonwrapping addresses and A disjoint from the live [S-0x420,W+8) chain,
//! where S=W-0x1028. This safe value API cannot establish those pointer,
//! allocator, stack, original ABI or runtime reachability premises.

/// Symbolic arguments at the selected delegate entry, not a native ABI type.
///
/// Source and scratch addresses are deliberately absent. The capacity records
/// the native wrapper's allocation; this API itself allocates no scratch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delegate21Request {
    pub word_count: u64,
    pub scratch_capacity_qwords: u64,
    pub opaque_context: u64,
}

/// Chosen observation of the first run and this one selected route.
///
/// A missing request means outside the recovered first-short-run path. It says
/// nothing about later calls on another core path. These fields are not native
/// return registers, an original enum layout, or a whole-wrapper result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirstRunRoute21 {
    pub natural_run: usize,
    pub ascending: bool,
    pub request: Option<Delegate21Request>,
}

/// Project the native first-run admission for exactly 21 unsigned qwords.
///
/// A1>=A0 chooses nondecreasing scan; ascending ties continue, descending
/// ties stop. Runs2..10 reach the delegate before reversal with A unchanged;
/// runs11..21 are outside this route. A valid21-word run cannot have length1.
/// All64 context bits are forwarded. Input immutability is the chosen safe
/// API's value boundary, not proof of native physical-memory isolation.
#[must_use]
pub fn first_short_run21(words: &[u64; 21], opaque_context: u64) -> FirstRunRoute21 {
    let ascending = words[1] >= words[0];
    let mut run = 2;
    while run < 21 {
        let continues = if ascending {
            words[run] >= words[run - 1]
        } else {
            words[run] < words[run - 1]
        };
        if !continues {
            break;
        }
        run += 1;
    }
    let request = if run < 11 {
        Some(Delegate21Request {
            word_count: 21,
            scratch_capacity_qwords: 512,
            opaque_context,
        })
    } else {
        None
    };
    FirstRunRoute21 { natural_run: run, ascending, request }
}

#[cfg(test)]
mod tests {
    use super::first_short_run21;

    #[test]
    fn threshold_is_ten_inclusive_and_eleven_exclusive() {
        let mut words = std::array::from_fn(|index| 100 + index as u64);
        words[10] = 0;
        assert_eq!(first_short_run21(&words, 7).natural_run, 10);
        assert!(first_short_run21(&words, 7).request.is_some());
        words[10] = 110;
        words[11] = 0;
        assert_eq!(first_short_run21(&words, 7).natural_run, 11);
        assert!(first_short_run21(&words, 7).request.is_none());
    }

    #[test]
    fn descending_tie_stops_without_reversing_source() {
        let mut words = [0; 21];
        words[..4].copy_from_slice(&[9, 8, 7, 7]);
        let before = words;
        let route = first_short_run21(&words, 0xF123_4567_89AB_CDEF);
        assert_eq!(route.natural_run, 3);
        assert!(!route.ascending);
        let request = route.request.unwrap();
        assert_eq!(request.word_count, 21);
        assert_eq!(request.scratch_capacity_qwords, 512);
        assert_eq!(request.opaque_context, 0xF123_4567_89AB_CDEF);
        assert_eq!(words, before);
    }

    #[test]
    fn high_bit_crossing_and_all_ties_remain_ascending() {
        let words = std::array::from_fn(|index| (1_u64 << 63) - 1 + index as u64);
        let route = first_short_run21(&words, 0);
        assert!(route.ascending);
        assert_eq!(route.natural_run, 21);
        assert!(route.request.is_none());
        let tied = first_short_run21(&[u64::MAX; 21], 0);
        assert_eq!(tied.natural_run, 21);
        assert!(tied.request.is_none());
    }
}
