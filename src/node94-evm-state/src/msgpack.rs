use crate::{DecodeError, EncodeError};

pub(crate) fn write_map_len(out: &mut Vec<u8>, len: usize) -> Result<(), EncodeError> {
    if len <= 15 {
        out.push(0x80 | len as u8);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(0xde);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = u32::try_from(len).map_err(|_| EncodeError::LengthOverflow("map"))?;
        out.push(0xdf);
        out.extend_from_slice(&len.to_be_bytes());
    }
    Ok(())
}

pub(crate) fn write_array_len(out: &mut Vec<u8>, len: usize) -> Result<(), EncodeError> {
    if len <= 15 {
        out.push(0x90 | len as u8);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(0xdc);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = u32::try_from(len).map_err(|_| EncodeError::LengthOverflow("array"))?;
        out.push(0xdd);
        out.extend_from_slice(&len.to_be_bytes());
    }
    Ok(())
}

pub(crate) fn write_str(out: &mut Vec<u8>, value: &str) -> Result<(), EncodeError> {
    let bytes = value.as_bytes();
    if bytes.len() <= 31 {
        out.push(0xa0 | bytes.len() as u8);
    } else if let Ok(len) = u8::try_from(bytes.len()) {
        out.extend_from_slice(&[0xd9, len]);
    } else if let Ok(len) = u16::try_from(bytes.len()) {
        out.push(0xda);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = u32::try_from(bytes.len()).map_err(|_| EncodeError::LengthOverflow("string"))?;
        out.push(0xdb);
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn write_bin(out: &mut Vec<u8>, value: &[u8]) -> Result<(), EncodeError> {
    if let Ok(len) = u8::try_from(value.len()) {
        out.extend_from_slice(&[0xc4, len]);
    } else if let Ok(len) = u16::try_from(value.len()) {
        out.push(0xc5);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = u32::try_from(value.len()).map_err(|_| EncodeError::LengthOverflow("binary"))?;
        out.push(0xc6);
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(value);
    Ok(())
}

pub(crate) fn write_uint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0x7f => out.push(value as u8),
        0x80..=0xff => out.extend_from_slice(&[0xcc, value as u8]),
        0x100..=0xffff => {
            out.push(0xcd);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xce);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(0xcf);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

pub(crate) struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub(crate) fn finish(self) -> Result<(), DecodeError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes(self.input.len() - self.offset))
        }
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let value = *self
            .input
            .get(self.offset)
            .ok_or(DecodeError::UnexpectedEof)?;
        self.offset += 1;
        Ok(value)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DecodeError::IntegerOverflow)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(DecodeError::UnexpectedEof)?;
        self.offset = end;
        Ok(value)
    }

    pub(crate) fn map_len(&mut self) -> Result<usize, DecodeError> {
        match self.byte()? {
            marker @ 0x80..=0x8f => Ok((marker & 0x0f) as usize),
            0xde => {
                Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("length checked")) as usize)
            }
            0xdf => usize::try_from(u32::from_be_bytes(
                self.take(4)?.try_into().expect("length checked"),
            ))
            .map_err(|_| DecodeError::IntegerOverflow),
            marker => Err(DecodeError::InvalidMarker(marker)),
        }
    }

    pub(crate) fn array_len(&mut self) -> Result<usize, DecodeError> {
        match self.byte()? {
            marker @ 0x90..=0x9f => Ok((marker & 0x0f) as usize),
            0xdc => {
                Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("length checked")) as usize)
            }
            0xdd => usize::try_from(u32::from_be_bytes(
                self.take(4)?.try_into().expect("length checked"),
            ))
            .map_err(|_| DecodeError::IntegerOverflow),
            marker => Err(DecodeError::InvalidMarker(marker)),
        }
    }

    pub(crate) fn string(&mut self) -> Result<&'a str, DecodeError> {
        let marker = self.byte()?;
        let len = match marker {
            0xa0..=0xbf => (marker & 0x1f) as usize,
            0xd9 => self.byte()? as usize,
            0xda => u16::from_be_bytes(self.take(2)?.try_into().expect("length checked")) as usize,
            0xdb => usize::try_from(u32::from_be_bytes(
                self.take(4)?.try_into().expect("length checked"),
            ))
            .map_err(|_| DecodeError::IntegerOverflow)?,
            marker => return Err(DecodeError::InvalidMarker(marker)),
        };
        core::str::from_utf8(self.take(len)?).map_err(|_| DecodeError::NonCanonical("UTF-8 string"))
    }

    pub(crate) fn binary(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = match self.byte()? {
            0xc4 => self.byte()? as usize,
            0xc5 => u16::from_be_bytes(self.take(2)?.try_into().expect("length checked")) as usize,
            0xc6 => usize::try_from(u32::from_be_bytes(
                self.take(4)?.try_into().expect("length checked"),
            ))
            .map_err(|_| DecodeError::IntegerOverflow)?,
            marker => return Err(DecodeError::InvalidMarker(marker)),
        };
        self.take(len)
    }

    pub(crate) fn uint(&mut self) -> Result<u64, DecodeError> {
        let marker = self.byte()?;
        match marker {
            0x00..=0x7f => Ok(marker as u64),
            0xcc => Ok(self.byte()? as u64),
            0xcd => {
                Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("length checked")) as u64)
            }
            0xce => {
                Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("length checked")) as u64)
            }
            0xcf => Ok(u64::from_be_bytes(
                self.take(8)?.try_into().expect("length checked"),
            )),
            marker => Err(DecodeError::InvalidMarker(marker)),
        }
    }
}
