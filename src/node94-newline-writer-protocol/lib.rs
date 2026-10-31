#![no_std]
#![forbid(unsafe_code)]
//! A chosen safe byte-request protocol, not an original formatter or writer ABI.

use core::cell::Cell;

/// Request nonempty LF-inclusive chunks, with four spaces when the flag is nonzero.
///
/// The callback may change `flag` to any byte. Its nonzero return byte stops this
/// invocation with status 1. References must be Rust-valid and callbacks must
/// return normally; raw native empty-pointer states and unwinding are excluded.
pub fn write_indented_chunks<W>(input: &[u8], flag: &Cell<u8>, writer: &mut W) -> u8
where
    W: FnMut(&[u8], &Cell<u8>) -> u8 + ?Sized,
{
    for piece in input.split_inclusive(|byte| *byte == b'\n') {
        if flag.get() != 0 && writer(b"    ", flag) != 0 {
            return 1;
        }
        flag.set(u8::from(piece.last() == Some(&b'\n')));
        if writer(piece, flag) != 0 {
            return 1;
        }
    }
    0
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod test_driver;

#[cfg(test)]
mod tests {
    use super::{test_driver, write_indented_chunks};

    #[test]
    fn authenticated_byte_protocol_transcripts() {
        let mut cases = 0;
        for line in include_str!("target-transcripts.tsv").lines() {
            let (stimulus, expected) = line.split_once('\t').expect("stimulus and expected trace");
            let actual = test_driver::transcript(stimulus, |input, flag, writer| {
                write_indented_chunks(input, flag, writer)
            });
            assert_eq!(actual, expected, "stimulus {stimulus}");
            cases += 1;
        }
        assert_eq!(cases, 3023, "the native-derived protocol corpus must be present");
    }
}
