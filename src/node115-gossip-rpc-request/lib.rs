#![no_std]
//! Logical prefix decoder for the selected Node115 GossipRpcRequest relation.
//! Variant names and field units are unknown. This does not reproduce native ABI.
extern crate node115_u64_reader_state;
pub use node115_u64_reader_state::Error as ReadError;
use node115_u64_reader_state::Reader;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Variant0 { first: u64, second: u64 },
    Variant1,
    Variant2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Read(ReadError), InvalidVariant { index: u32 } }
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<'a> {
    pub result: Result<Request, Error>,
    pub remaining: &'a [u8],
    pub charged: u64,
}

// Native u32 tag reader: logical charge4 regardless of encoded byte count.
fn read_tag(input: &mut &[u8], limit: Option<u64>, charged: &mut u64) -> Result<u32, ReadError> {
    if let Some(limit) = limit {
        let next = charged.checked_add(4).ok_or(ReadError::Limit)?;
        *charged = next;
        if next > limit { return Err(ReadError::Limit); }
    }
    let source = *input;
    let slow = source.len() <= 4;
    let Some(&marker) = source.first() else {
        return Err(ReadError::UnexpectedEnd { additional: 1 });
    };
    if slow { *input = &source[1..]; }
    if marker < 251 {
        *input = &source[1..];
        return Ok(u32::from(marker));
    }
    let width = match marker {
        251 => 3,
        252 => 5,
        _ => return Err(ReadError::Invalid {
            expected_raw: 2,
            found_raw: match marker { 253 => 3, 254 => 4, _ => 12 },
        }),
    };
    if source.len() < width {
        return Err(ReadError::UnexpectedEnd { additional: (width - source.len()) as u64 });
    }
    let mut bytes = [0; 4];
    bytes[..width - 1].copy_from_slice(&source[1..width]);
    *input = &source[width..];
    Ok(u32::from_le_bytes(bytes))
}

/// Decode one request prefix, retaining charge and remaining bytes on every exit.
/// `None`/`Some` represent canonical unlimited/limited context modes. No EOF check.
pub fn decode_prefix(mut input: &[u8], limit: Option<u64>, mut charged: u64) -> Outcome<'_> {
    let kind = match read_tag(&mut input, limit, &mut charged) {
        Ok(kind) => kind,
        Err(error) => return Outcome { result: Err(Error::Read(error)), remaining: input, charged },
    };
    if kind == 0 {
        // Byte-identical MIT dependency from commit45e91f8; no new reader credit.
        let mut reader = Reader::new(input, limit, charged);
        let result = (|| {
            let first = reader.read_u64().map_err(Error::Read)?;
            let second = reader.read_u64().map_err(Error::Read)?;
            Ok(Request::Variant0 { first, second })
        })();
        return Outcome { result, remaining: reader.remaining(), charged: reader.charged() };
    }
    let result = match kind {
        1 => Ok(Request::Variant1),
        2 => Ok(Request::Variant2),
        index => Err(Error::InvalidVariant { index }),
    };
    Outcome { result, remaining: input, charged }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unit_prefix_keeps_suffix() {
        assert_eq!(decode_prefix(&[1, 99], Some(4), 0), Outcome {
            result: Ok(Request::Variant1), remaining: &[99], charged: 4 });
    }
    #[test]
    fn limit_store_precedes_comparison_and_overflow_does_not_store() {
        assert_eq!(decode_prefix(&[0, 1, 2], Some(11), 0), Outcome {
            result: Err(Error::Read(ReadError::Limit)), remaining: &[1, 2], charged: 12 });
        assert_eq!(decode_prefix(&[1], Some(u64::MAX), u64::MAX - 3), Outcome {
            result: Err(Error::Read(ReadError::Limit)), remaining: &[1], charged: u64::MAX - 3 });
    }
    #[test]
    fn partial_and_fast_invalid_cursor_differ() {
        assert_eq!(decode_prefix(&[252, 0], None, 17), Outcome {
            result: Err(Error::Read(ReadError::UnexpectedEnd { additional: 3 })), remaining: &[0], charged: 17 });
        let bytes = [255, 0, 0, 0, 0];
        assert_eq!(decode_prefix(&bytes, None, 0).remaining, &bytes);
        assert_eq!(decode_prefix(&bytes[..4], None, 0).remaining, &bytes[1..4]);
    }
    #[test]
    fn nonminimal_tag_and_reused_reader_compose() {
        assert_eq!(decode_prefix(&[251, 0, 0, 251, 2, 0, 3, 99], Some(20), 0), Outcome {
            result: Ok(Request::Variant0 { first: 2, second: 3 }), remaining: &[99], charged: 20 });
    }
}
