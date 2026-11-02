#![forbid(unsafe_code)]

//! Raw-qword projection of node94's qualified monotone sort path.
//!
//! This module covers lengths 21 through 4096 and only wholly nondecreasing
//! or wholly strictly decreasing inputs. Its slice API and returned enums are
//! independently chosen; unsupported inputs are not target error results.

/// Smallest count in the qualified delegated path.
pub const MIN_WORDS: usize = 21;
/// Largest count before the core's unproved threshold-selection branch.
pub const MAX_WORDS: usize = 4096;

/// Ordering established before any mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualifiedOrdering {
    /// Unsigned ascending order, including adjacent equal words.
    Nondecreasing,
    /// Every following unsigned word is strictly smaller.
    StrictlyDecreasing,
}

/// Input outside this module's proved native relation.
///
/// These are safe-API refusal reasons. The target may continue into unproved
/// fallback or merge code for such inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unsupported {
    Length,
    Ordering,
}

/// Classify a qualified monotone input using unsigned qword comparisons.
pub fn classify(words: &[u64]) -> Result<QualifiedOrdering, Unsupported> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&words.len()) {
        return Err(Unsupported::Length);
    }

    let decreasing = words[1] < words[0];
    for pair in words.windows(2) {
        if decreasing {
            if pair[1] >= pair[0] {
                return Err(Unsupported::Ordering);
            }
        } else if pair[1] < pair[0] {
            return Err(Unsupported::Ordering);
        }
    }

    Ok(if decreasing {
        QualifiedOrdering::StrictlyDecreasing
    } else {
        QualifiedOrdering::Nondecreasing
    })
}

/// Normalize the qualified native monotone path in place.
///
/// Classification completes before any write. A nondecreasing input takes
/// the source path containing no input mutation. A strictly decreasing input
/// swaps opposite qword pairs, preserving every word's bits and the odd center.
/// The scalar Rust permutation equals the proved SIMD-plus-tail permutation;
/// physical generated stores or the original ABI are not asserted here.
///
/// Unsupported input is left unchanged by our safe API. No target refusal or
/// arbitrary-array sorting behavior is assigned to it.
pub fn normalize(words: &mut [u64]) -> Result<QualifiedOrdering, Unsupported> {
    let ordering = classify(words)?;
    if ordering == QualifiedOrdering::StrictlyDecreasing {
        let length = words.len();
        for left in 0..(length / 2) {
            words.swap(left, length - left - 1);
        }
    }
    Ok(ordering)
}

#[cfg(test)]
mod tests {
    use super::{QualifiedOrdering, Unsupported, classify, normalize};

    #[test]
    fn equal_and_unsigned_high_words_are_nondecreasing() {
        let mut words = [u64::MAX; 21];
        words[0] = 0;
        words[1] = 1 << 63;
        let original = words;
        assert_eq!(classify(&words), Ok(QualifiedOrdering::Nondecreasing));
        assert_eq!(normalize(&mut words), Ok(QualifiedOrdering::Nondecreasing));
        assert_eq!(words, original);
    }

    #[test]
    fn odd_and_even_descending_inputs_reverse_with_center_preserved() {
        for count in [21, 22, 4095, 4096] {
            let mut words: Vec<u64> = (0..count).rev().map(|word| word as u64).collect();
            let middle = words[count / 2];
            assert_eq!(normalize(&mut words), Ok(QualifiedOrdering::StrictlyDecreasing));
            assert_eq!(words, (0..count).map(|word| word as u64).collect::<Vec<_>>());
            if count % 2 == 1 {
                assert_eq!(words[count / 2], middle);
            }
        }
    }

    #[test]
    fn unsupported_policy_preserves_the_entire_input() {
        for count in [0, 20, 4097] {
            let mut words = vec![7; count];
            let original = words.clone();
            assert_eq!(normalize(&mut words), Err(Unsupported::Length));
            assert_eq!(words, original);
        }
        let mut words: Vec<u64> = (0..21).rev().collect();
        words[10] = words[9];
        let original = words.clone();
        assert_eq!(normalize(&mut words), Err(Unsupported::Ordering));
        assert_eq!(words, original);
    }
}
