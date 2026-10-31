#![no_std]
#![forbid(unsafe_code)]
//! One numeric expression observed in node #94, not its guarded caller or ABI.
//!
//! For every `i64`, return the Euclidean remainder modulo the positive integer
//! 86_400. The result is in 0..86_400 and therefore fits `u32`. This does not
//! assign time units, reconstruct the original helper, or establish byte parity.

/// The total scalar expression; no allocation, clock access or original calls.
pub fn euclidean_remainder_86400(value: i64) -> u32 {
    value.rem_euclid(86_400) as u32
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::euclidean_remainder_86400;

    #[test]
    fn authenticated_target_expression_vectors() {
        let mut cases = 0;
        for line in include_str!("target-vectors.tsv").lines() {
            let (input, expected) = line.split_once('\t').expect("two fields");
            let input: i64 = input.parse().expect("signed64 input");
            let expected: u32 = expected.parse().expect("DWORD result");
            assert!(expected < 86_400);
            assert_eq!(euclidean_remainder_86400(input), expected, "input {input}");
            cases += 1;
        }
        assert!(cases >= 256, "the target-derived corpus must be present");
    }
}
