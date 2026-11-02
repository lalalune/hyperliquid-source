//! Bounded reconstruction of the established node94 selected bootstrap window.
//! No asynchronous caller, network request, original enum ABI or full node claim.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selected {
    EqualBranch,
    AheadBranch,
    Window { first: u64, last: u64 },
}

/// Qualified only at the selected unsigned compare, after earlier caller gates.
pub fn selected_window(current: u64, target: u64) -> Selected {
    match current.cmp(&target) {
        core::cmp::Ordering::Equal => Selected::EqualBranch,
        core::cmp::Ordering::Greater => Selected::AheadBranch,
        core::cmp::Ordering::Less => Selected::Window {
            // current < target <= MAX proves this addition cannot overflow.
            first: current + 1,
            last: core::cmp::min(target, current.saturating_add(100)),
        },
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{selected_window, Selected};
    use std::vec::Vec;

    #[test]
    fn target_smoke_rows() {
        for line in include_str!("target-smoke.tsv").lines() {
            let fields: Vec<_> = line.split('\t').collect();
            let current = fields[0].parse().unwrap();
            let target = fields[1].parse().unwrap();
            let expected = match fields[2] {
                "E" => Selected::EqualBranch,
                "A" => Selected::AheadBranch,
                "W" => Selected::Window {
                    first: fields[3].parse().unwrap(),
                    last: fields[4].parse().unwrap(),
                },
                _ => panic!("unknown frozen outcome"),
            };
            assert_eq!(selected_window(current, target), expected, "{line}");
        }
    }
}
