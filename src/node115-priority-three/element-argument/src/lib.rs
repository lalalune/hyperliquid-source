#![no_std]
#![forbid(unsafe_code)]
//! Safe staging models for RE-006 element arguments.

pub const ELEMENT_BYTES: usize = 0xb0;
pub const RECORD_BYTES: usize = 0xf8;

pub fn copy_element_prefix(record: &[u8; RECORD_BYTES]) -> [u8; ELEMENT_BYTES] {
    let mut element = [0; ELEMENT_BYTES];
    element.copy_from_slice(&record[..ELEMENT_BYTES]);
    element
}

pub fn copy_element_tail(record: &[u8; RECORD_BYTES]) -> [u8; ELEMENT_BYTES] {
    let mut element = [0; ELEMENT_BYTES];
    element[..8].copy_from_slice(&record[..8]);
    element[8..].copy_from_slice(&record[8..ELEMENT_BYTES]);
    element
}

#[cfg(test)]
mod tests {
    use super::{ELEMENT_BYTES, RECORD_BYTES, copy_element_prefix, copy_element_tail};

    #[test]
    fn staged_copy_preserves_the_full_element() {
        let mut record = [0; RECORD_BYTES];
        for (index, byte) in record.iter_mut().enumerate() {
            *byte = (index * 17) as u8;
        }
        assert_eq!(&copy_element_prefix(&record), &record[..ELEMENT_BYTES]);
        assert_eq!(&copy_element_tail(&record), &record[..ELEMENT_BYTES]);
    }

    #[test]
    fn bytes_after_the_element_are_not_observed() {
        let mut left = [0; RECORD_BYTES];
        let mut right = [0; RECORD_BYTES];
        for index in ELEMENT_BYTES..RECORD_BYTES {
            left[index] = 0x55;
            right[index] = 0xaa;
        }
        assert_eq!(copy_element_prefix(&left), copy_element_prefix(&right));
        assert_eq!(copy_element_tail(&left), copy_element_tail(&right));
    }
}
