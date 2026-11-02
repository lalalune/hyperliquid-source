#![forbid(unsafe_code)]

//! One local node94 short-run insertion, not a sorting entry point.
//!
//! Evidence: node94 `0x4918eef..0x4918f4d`, SHA-256
//! `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
//! The native caller has n=21..32 and has reached its first left insertion
//! after ordinary seed returns. No assumption about the seed's ordering is
//! needed for this local value effect. Later insertion/merge behavior is absent.

/// Insert the already-loaded A[8] into the selected nine-word scratch window.
///
/// Only the maximal contiguous suffix of the eight-word prefix that is
/// strictly greater than `value` moves right. A prefix need not become sorted. Equality stops
/// the scan, retaining old equal words before the inserted word.
///
/// The fixed array and value argument are a chosen safe projection, not the
/// target ABI, pointer layout or alias/lifetime contract. Slot 8 is overwritten
/// before its old value can affect the result. The returned index is chosen
/// metadata corresponding to the native final store position, not native RAX.
/// Physical generated store count/order is not asserted.
#[must_use]
pub fn insert_loaded(words: &mut [u64; 9], value: u64) -> usize {
    words[8] = value;
    let mut destination = 8;
    while destination > 0 && value < words[destination - 1] {
        words[destination] = words[destination - 1];
        destination -= 1;
    }
    if destination < 8 {
        words[destination] = value;
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::insert_loaded;

    #[test]
    fn arbitrary_prefix_only_moves_the_greater_suffix() {
        let mut words = [8, 0, 7, 1, 6, 2, 9, 10, 999];
        assert_eq!(insert_loaded(&mut words, 5), 6);
        assert_eq!(words, [8, 0, 7, 1, 6, 2, 5, 9, 10]);
    }

    #[test]
    fn unsigned_front_insertion_preserves_high_word_bits() {
        let mut words = [u64::MAX; 9];
        assert_eq!(insert_loaded(&mut words, 1), 0);
        assert_eq!(words[0], 1);
        assert_eq!(&words[1..], &[u64::MAX; 8]);
    }

    #[test]
    fn equality_stops_before_earlier_greater_words() {
        let mut words = [9, 0, 8, 1, 5, 7, 6, 10, 999];
        assert_eq!(insert_loaded(&mut words, 5), 5);
        assert_eq!(words, [9, 0, 8, 1, 5, 5, 7, 6, 10]);
    }
}
