#![no_std]
#![forbid(unsafe_code)]
//! One visor request-to-class numeric relation, not an allocation interface.

/// Compute the proved numeric class only for `4096 < raw <= 0x7000_0000_0000_0000`.
///
/// `None` means outside this deliberately restricted numeric API domain. It does
/// not mean that the captured allocator fails, returns null, or sets an error.
/// The original TLS route, tables, allocation and caller ABI are not implemented.
pub fn large_request_class(raw: u64) -> Option<u32> {
    if raw <= 4096 || raw > 0x7000_0000_0000_0000 {
        return None;
    }
    // On the admitted domain, bit_length(raw - 1) equals BSR(2*raw - 1).
    // Here k is 13..=63, so the variable shift is 10..=60 and cannot overflow.
    let preceding = raw - 1;
    let k = 64 - preceding.leading_zeros();
    let fractional = ((preceding >> (k - 3)) & 3) as u32;
    Some(4 * k + fractional - 23)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::large_request_class;

    #[test]
    fn authenticated_target_class_and_chosen_domain_vectors() {
        let mut cases = 0;
        for line in include_str!("target-vectors.tsv").lines() {
            let (input, expected) = line.split_once('\t').expect("two fields");
            let input: u64 = input.parse().expect("unsigned64 input");
            let expected = if expected == "none" {
                None
            } else {
                Some(expected.parse::<u32>().expect("numeric class"))
            };
            assert_eq!(large_request_class(input), expected, "input {input}");
            cases += 1;
        }
        assert_eq!(cases, 1876, "the target-bound class/domain corpus must be present");
    }
}
