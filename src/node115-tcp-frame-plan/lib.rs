//! Selected node115 TCP frame policy over a supplied complete header.
//! This new scalar API performs no reads, allocation or decompression.
#![no_std]
#![forbid(unsafe_code)]

pub const CHUNK_BYTES: u64 = 4_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub payload_len: u32,
    pub flag: u8,
}

/// Five captured header bytes: big-endian length followed by an uninterpreted flag.
pub fn decode_header(bytes: &[u8; 5]) -> Header {
    Header {
        payload_len: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        flag: bytes[4],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub payload_len: u32,
    pub decompress_after_read: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverLimit;

/// Project the caller's length gate before its payload allocation.
/// A flag other than exactly one selects the plain path, including unknown tags.
pub fn admit(header: Header, maximum: u64) -> Result<Plan, OverLimit> {
    let length = u64::from(header.payload_len);
    if length > maximum {
        Err(OverLimit)
    } else {
        Ok(Plan {
            payload_len: header.payload_len,
            decompress_after_read: header.flag == 1,
        })
    }
}

/// Selected half-open payload read interval; None requests no further read.
/// Completed is the supplied native-width counter, not an observed I/O result.
/// On the read arm, completed < length <= u32::MAX, so the end cannot overflow.
pub fn next_chunk(payload_len: u32, completed: u64) -> Option<(u64, u64)> {
    let length = u64::from(payload_len);
    if completed >= length {
        return None;
    }
    let remaining = length - completed;
    let count = remaining.min(CHUNK_BYTES);
    Some((completed, completed + count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_limit_and_noncanonical_flag_keep_the_native_policy() {
        let header = decode_header(&[1, 2, 3, 4, 2]);
        assert_eq!(header.payload_len, 0x0102_0304);
        assert_eq!(admit(header, 0x0102_0303), Err(OverLimit));
        assert!(!admit(header, 0x0102_0304).unwrap().decompress_after_read);
        assert!(
            admit(decode_header(&[0, 0, 0, 0, 1]), 0)
                .unwrap()
                .decompress_after_read
        );
    }

    #[test]
    fn successive_intervals_cover_the_payload_without_a_final_empty_read() {
        let total = 8_000_001;
        let first = next_chunk(total, 0).unwrap();
        let second = next_chunk(total, first.1).unwrap();
        let third = next_chunk(total, second.1).unwrap();
        assert_eq!(
            (first, second, third),
            (
                (0, 4_000_000),
                (4_000_000, 8_000_000),
                (8_000_000, 8_000_001)
            )
        );
        assert_eq!(next_chunk(total, third.1), None);
        assert_eq!(next_chunk(total, u64::MAX), None);
    }
}
