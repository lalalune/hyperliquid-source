use node115_rng_refill::{refill, State};

// Independent known output from the MIT/Apache-2.0 rand_chacha 0.3.1
// ChaCha12Rng with an all-zero seed, stream and initial word position.
#[test]
fn zero_input_first_block_matches_independent_reference() {
    let mut state = State {
        key: [0; 8],
        tail: [0; 4],
    };
    let out = refill(&mut state);
    assert_eq!(
        &out[..16],
        &[
            0x6a9af49b, 0x53f95507, 0x12ce1f81, 0xd583265f, 0xbbc32904, 0x1474e049, 0xa589007e,
            0x5f15ae2e, 0x79f86405, 0xc0e37ad2, 0x3428e82c, 0x798cfaac, 0x2c9f623a, 0x1969dea0,
            0x2fe80b61, 0xbe261341
        ]
    );
    assert_eq!(state.tail, [4, 0, 0, 0]);
}
#[test]
fn counter_wrap_preserves_key_and_other_tail_words() {
    let key = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut state = State {
        key,
        tail: [u32::MAX - 1, u32::MAX, 0x12345678, 0x9abcdef0],
    };
    let _ = refill(&mut state);
    assert_eq!(state.key, key);
    assert_eq!(state.tail, [2, 0, 0x12345678, 0x9abcdef0]);
}
#[test]
fn consecutive_refills_equal_corresponding_block_positions() {
    let mut a = State {
        key: [7; 8],
        tail: [5, 0, 8, 9],
    };
    let first = refill(&mut a);
    let second = refill(&mut a);
    let mut b = State {
        key: [7; 8],
        tail: [6, 0, 8, 9],
    };
    let shifted = refill(&mut b);
    assert_eq!(&first[16..], &shifted[..48]);
    assert_eq!(&second[..16], &shifted[48..]);
}
