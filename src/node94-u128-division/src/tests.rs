extern crate std;

use super::{quotient, NonZeroWords, Words};
use std::{env, fs};

fn words(value: u128) -> Words {
    Words {
        low: value as u64,
        high: (value >> 64) as u64,
    }
}

fn check(numerator: u128, denominator: u128, expected: u128) {
    let divisor = NonZeroWords::new(words(denominator)).expect("nonzero fixture divisor");
    assert_eq!(quotient(words(numerator), divisor), words(expected));
}

#[test]
fn checked_boundary_rejects_only_the_zero_pair() {
    assert_eq!(NonZeroWords::new(Words::default()), None);
    for value in [1, u64::MAX as u128, 1 << 64, 1 << 127, u128::MAX] {
        assert!(NonZeroWords::new(words(value)).is_some());
    }
}

#[test]
fn quotient_preserves_both_limbs() {
    check(u128::MAX, 1, u128::MAX);
    check(1 << 127, 2, 1 << 126);
    check(u128::MAX, u64::MAX as u128, (1 << 64) + 1);
}

#[test]
fn exact_division_and_smaller_numerators() {
    check(0, 1, 0);
    check((1 << 127) - 1, 1 << 127, 0);
    check(1 << 127, 1 << 127, 1);
    check(u128::MAX, u128::MAX, 1);
    check(9, 3, 3);
    check(10, 3, 3);
}

#[test]
fn low_limb_borrow_reaches_the_high_limb() {
    check(1 << 65, (1 << 64) + 1, 1);
    check(u128::MAX, (1 << 127) + 1, 1);
    check((1 << 127) + 3, (1 << 64) + 1, (1 << 63) - 1);
}

#[test]
#[ignore = "requires a fresh authenticated GNU/LLVM vector export; run tools/u128_division_rust.py"]
fn authenticated_target_corpus() {
    let path = env::var_os("NODE94_U128_VECTORS").expect("authenticated corpus path");
    let corpus = fs::read_to_string(path).expect("read fresh instruction-evaluator export");
    let mut count = 0;
    for line in corpus.lines() {
        let (numerator, rest) = line.split_once('/').expect("numerator separator");
        let (denominator, expected) = rest.split_once('=').expect("quotient separator");
        let parse = |text| u128::from_str_radix(text, 16).expect("128-bit hexadecimal word");
        check(parse(numerator), parse(denominator), parse(expected));
        count += 1;
    }
    assert_eq!(count, 159_431);
    std::println!("authenticated nonzero-divisor cases: {count}");
}
