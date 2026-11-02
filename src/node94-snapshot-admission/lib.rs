//! Selected node94 snapshot admission, not a filesystem snapshot API.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selected {
    PastFreezeAssertion,
    Freeze,
    Periodic,
    Skip,
}

/// Raw preloaded words shared by all three established lane prefixes.
/// Returns a branch classification, without executing an original assertion.
pub fn selected_admission(tag: u32, height: u64, freeze_target: u64) -> Selected {
    if tag == 1 {
        match freeze_target.cmp(&height) {
            core::cmp::Ordering::Less => return Selected::PastFreezeAssertion,
            core::cmp::Ordering::Equal => return Selected::Freeze,
            core::cmp::Ordering::Greater => {}
        }
    }
    if height.is_multiple_of(10_000) {
        Selected::Periodic
    } else {
        Selected::Skip
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::{selected_admission, Selected};
    use std::vec::Vec;

    #[test]
    fn target_smoke_rows() {
        for line in include_str!("target-smoke.tsv").lines() {
            let f: Vec<_> = line.split('\t').collect();
            let expected = match f[4] {
                "X" => Selected::PastFreezeAssertion,
                "F" => Selected::Freeze,
                "P" => Selected::Periodic,
                "S" => Selected::Skip,
                _ => panic!("unknown frozen outcome"),
            };
            assert_eq!(
                selected_admission(
                    f[1].parse().unwrap(),
                    f[2].parse().unwrap(),
                    f[3].parse().unwrap()
                ),
                expected,
                "{line}"
            );
        }
    }
}
