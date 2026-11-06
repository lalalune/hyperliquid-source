#![no_std]
//! Node115 post-lookup integer prefix. Not the response ABI or decimal price.
use core::num::NonZeroI64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Width {
    Narrow32,
    Wide64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Division {
    pub quotient: u64,
    pub remainder: u64,
    pub width: Width,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    MarkOrProductBoundary,
    EntrySignBoundary,
    SubtractionBoundary,
    Normal {
        product_word: u64,
        pnl_word: u64,
        division: Option<Division>,
    },
}

/// Interpret raw mark/entry bits after the producer's lookup, given nonzero size.
/// Diagnostic boundaries are observed PCs, not reconstructed native errors.
/// `division` precedes asset-layout revalidation and binary64 decimal scaling.
pub fn project(size: NonZeroI64, mark_word: u64, entry_word: u64) -> Observation {
    let size = size.get();
    let mark = mark_word as i64;
    if mark < 0 {
        return Observation::MarkOrProductBoundary;
    }
    let Some(product) = size.checked_mul(mark) else {
        return Observation::MarkOrProductBoundary;
    };
    let entry = entry_word as i64;
    if entry == 0 {
        return Observation::Normal {
            product_word: product as u64,
            pnl_word: 0,
            division: None,
        };
    }
    if entry < 0 {
        return Observation::EntrySignBoundary;
    }
    let signed_entry = if size > 0 { entry } else { -entry };
    // The original JO is retained as a boundary. Given the preceding guards,
    // the subtraction cannot overflow: product and signed_entry share sign.
    let Some(pnl) = product.checked_sub(signed_entry) else {
        return Observation::SubtractionBoundary;
    };
    let magnitude = size.unsigned_abs();
    let division = if entry_word < magnitude {
        None
    } else {
        Some(Division {
            quotient: entry_word / magnitude,
            remainder: entry_word % magnitude,
            width: if (entry_word | magnitude) <= u64::from(u32::MAX) {
                Width::Narrow32
            } else {
                Width::Wide64
            },
        })
    };
    Observation::Normal {
        product_word: product as u64,
        pnl_word: pnl as u64,
        division,
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    include!("../../research/work-items/RE-012-position-integer-115/client_fixture.rs");
    #[test]
    fn original_before_rust_smoke() {
        for line in
            include_str!("../../research/work-items/RE-012-position-integer-115/target-smoke.tsv")
                .lines()
        {
            let fields: std::vec::Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 4);
            let result = project(
                NonZeroI64::new(fields[0].parse::<u64>().unwrap() as i64).unwrap(),
                fields[1].parse().unwrap(),
                fields[2].parse().unwrap(),
            );
            assert_eq!(observation_text(result), fields[3]);
        }
    }

    #[test]
    fn sealed_arithmetic_boundaries() {
        let cases = [
            (1_u64, 7_u64, 0_u64, "V:7:0:N"),
            (1_u64, 18446744073709551615_u64, 0_u64, "M"),
            (2_u64, 9223372036854775807_u64, 0_u64, "M"),
            (1_u64, 0_u64, 18446744073709551615_u64, "E"),
            (
                18446744073709551613_u64,
                7_u64,
                7_u64,
                "V:18446744073709551595:18446744073709551602:32:2:1",
            ),
            (3_u64, 7_u64, 7_u64, "V:21:14:32:2:1"),
            (
                1_u64,
                0_u64,
                4294967296_u64,
                "V:0:18446744069414584320:64:4294967296:0",
            ),
            (3_u64, 0_u64, 3_u64, "V:0:18446744073709551613:32:1:0"),
            (
                9223372036854775808_u64,
                1_u64,
                0_u64,
                "V:9223372036854775808:0:N",
            ),
            (
                9223372036854775808_u64,
                1_u64,
                9223372036854775807_u64,
                "V:9223372036854775808:18446744073709551615:N",
            ),
        ];
        for (size, mark, entry, expected) in cases {
            assert_eq!(
                observation_text(project(NonZeroI64::new(size as i64).unwrap(), mark, entry)),
                expected
            );
        }
    }
}
