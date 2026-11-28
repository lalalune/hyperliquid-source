//! Offline extraction of the selected #115 forwarded payload prefix.
#![no_std]
#![forbid(unsafe_code)]

pub use node115_u64_reader_state::Error as LengthError;
use node115_u64_reader_state::Reader;

#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub origin: &'a [u8; 20],
    pub payload: &'a [u8],
    pub remaining: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    IncompleteHeader,
    UnsupportedTag(u8),
    Length(LengthError),
    IncompletePayload,
}

/// Read one selected record. Other record variants and outer wire
/// transport are outside this adapter. The returned spans borrow the input.
pub fn decode_prefix(input: &[u8]) -> Result<Frame<'_>, Error> {
    let (origin, rest) = input
        .split_first_chunk::<20>()
        .ok_or(Error::IncompleteHeader)?;
    let (&tag, encoded) = rest.split_first().ok_or(Error::IncompleteHeader)?;
    if tag != 0 {
        return Err(Error::UnsupportedTag(tag));
    }
    let mut reader = Reader::new(encoded, None, 0);
    let len = reader.read_u64().map_err(Error::Length)?;
    let len = usize::try_from(len).map_err(|_| Error::IncompletePayload)?;
    let (payload, remaining) = reader
        .remaining()
        .split_at_checked(len)
        .ok_or(Error::IncompletePayload)?;
    Ok(Frame {
        origin,
        payload,
        remaining,
    })
}
