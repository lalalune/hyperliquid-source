//! Conditional unqualified-symbol prefix, not a complete token resolver.
//!
//! The caller supplies the already-selected unqualified lane. An allocation
//! observation is provisional: the original subsequently compares the formatted
//! decimal with the original suffix and consults opaque metadata. In particular,
//! `+0` and `00` reach this boundary but are not resolved symbol spellings.

/// Arguments observed immediately before the original allocation call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecimalRequest {
    pub parsed: u64,
    decimal: [u8; 20],
    start: usize,
}

impl DecimalRequest {
    /// Significant ASCII decimal bytes; unused array bytes are not native output.
    pub fn decimal_bytes(&self) -> &[u8] {
        &self.decimal[self.start..]
    }
}

/// Normal return or an explicitly unresolved helper boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrefixObservation {
    Rejected,
    Direct(u64),
    NeedsAllocation(DecimalRequest),
}

/// Observe the call-free prefix using a logical byte slice, not the native ABI.
pub fn observe(input: &[u8]) -> PrefixObservation {
    if input == b"USDC" {
        return PrefixObservation::Direct(0);
    }
    if input == b"PURR" {
        return PrefixObservation::Direct(1);
    }
    let Some(suffix) = input.strip_prefix(b"outcomeToken") else {
        return PrefixObservation::Rejected;
    };
    let digits = suffix.strip_prefix(b"+").unwrap_or(suffix);
    if digits.is_empty() {
        return PrefixObservation::Rejected;
    }
    let mut value = 0_u64;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return PrefixObservation::Rejected;
        }
        let Some(next) = value
            .checked_mul(10)
            .and_then(|scaled| scaled.checked_add(u64::from(byte - b'0')))
        else {
            return PrefixObservation::Rejected;
        };
        value = next;
    }
    let mut decimal = [0_u8; 20];
    let mut start = decimal.len();
    let mut remaining = value;
    loop {
        start -= 1;
        decimal[start] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    PrefixObservation::NeedsAllocation(DecimalRequest {
        parsed: value,
        decimal,
        start,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("../../research/work-items/RE-001-symbol-prefix-115/client_fixture.rs");

    #[test]
    fn sealed_original_observations() {
        for line in
            include_str!("../../research/work-items/RE-001-symbol-prefix-115/target-smoke.tsv")
                .lines()
        {
            let (input, expected) = line.split_once('\t').unwrap();
            assert_eq!(render(observe(&decode_hex(input).unwrap())), expected);
        }
    }

    #[test]
    fn provisional_spelling_is_not_resolution() {
        for suffix in [b"+0".as_slice(), b"00", b"0001"] {
            let input = [b"outcomeToken".as_slice(), suffix].concat();
            assert!(matches!(
                observe(&input),
                PrefixObservation::NeedsAllocation(_)
            ));
        }
        assert_eq!(
            observe(b"outcomeToken18446744073709551616"),
            PrefixObservation::Rejected
        );
        // Existing sealed input: multiplication overflow, distinct from add carry.
        assert_eq!(
            observe(b"outcomeToken99999999999999999999"),
            PrefixObservation::Rejected
        );
        let long_zero = [b"outcomeToken".as_slice(), &[b'0'; 1000]].concat();
        assert_eq!(render(observe(&long_zero)), "A:0:30");
    }
}
