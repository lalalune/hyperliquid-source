//! Qualified node115 varint size accounting, including partial error state.
//! Err projects the pre-helper boundary; it is not the original panic/enum ABI.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeOverflow;

pub fn count_u32(value: u32, counter: &mut u64) -> Result<(), SizeOverflow> {
    count(u64::from(value), counter)
}

pub fn count_u64(value: u64, counter: &mut u64) -> Result<(), SizeOverflow> {
    count(value, counter)
}

fn count(value: u64, counter: &mut u64) -> Result<(), SizeOverflow> {
    let length = if value < 251 {
        1
    } else if value < 65_536 {
        3
    } else if value < (1 << 32) {
        5
    } else {
        9
    };
    let marked = counter.checked_add(1).ok_or(SizeOverflow)?;
    // The marker increment survives a later payload overflow.
    *counter = marked;
    let finished = marked.checked_add(length - 1).ok_or(SizeOverflow)?;
    *counter = finished;
    Ok(())
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{count_u32, count_u64};
    #[test]
    fn frozen_native_state_rows() {
        for line in include_str!("target-smoke.tsv").lines() {
            let f: std::vec::Vec<_> = line.split('\t').collect();
            let which: u8 = f[0].parse().unwrap();
            let value: u64 = f[1].parse().unwrap();
            let mut counter = f[2].parse().unwrap();
            let result = if which == 1 || which == 2 {
                count_u32(u32::try_from(value).unwrap(), &mut counter)
            } else {
                count_u64(value, &mut counter)
            };
            assert_eq!(result.is_ok(), f[4] == "O", "{line}");
            assert_eq!(counter, f[5].parse::<u64>().unwrap(), "{line}");
        }
    }
}
