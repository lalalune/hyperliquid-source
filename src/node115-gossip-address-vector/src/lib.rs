#![no_std]
//! Complete selected response variant0 vector; logical fields, not native enum ABI.
extern crate alloc;
use alloc::vec::Vec;
pub use node115_u64_reader_state::Error as ReadError;
use node115_u64_reader_state::Reader;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Record {
    pub fixed: u64,
    pub value: u64,
    pub flag: bool,
}
const _: () = assert!(core::mem::size_of::<Record>() == 24);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Read(ReadError),
    InvalidVariant(u32),
    InvalidBool,
    Refund,
    Allocation,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<'a> {
    pub result: Result<Vec<Record>, Error>,
    pub remaining: &'a [u8],
    pub charged: u64,
}
// Unchanged MIT logical u32 reader from the existing Request component at base
// 05bc2de303c05525b71e7e257426e741bc66a390; no new reader credit.
fn read_tag(input: &mut &[u8], limit: Option<u64>, charged: &mut u64) -> Result<u32, ReadError> {
    if let Some(limit) = limit {
        let next = charged.checked_add(4).ok_or(ReadError::Limit)?;
        *charged = next;
        if next > limit {
            return Err(ReadError::Limit);
        }
    }
    let source = *input;
    let slow = source.len() <= 4;
    let Some(&marker) = source.first() else {
        return Err(ReadError::UnexpectedEnd { additional: 1 });
    };
    if slow {
        *input = &source[1..];
    }
    if marker < 251 {
        *input = &source[1..];
        return Ok(u32::from(marker));
    }
    let width = match marker {
        251 => 3,
        252 => 5,
        _ => {
            return Err(ReadError::Invalid {
                expected_raw: 2,
                found_raw: match marker {
                    253 => 3,
                    254 => 4,
                    _ => 12,
                },
            });
        }
    };
    if source.len() < width {
        return Err(ReadError::UnexpectedEnd {
            additional: (width - source.len()) as u64,
        });
    }
    let mut bytes = [0; 4];
    bytes[..width - 1].copy_from_slice(&source[1..width]);
    *input = &source[width..];
    Ok(u32::from_le_bytes(bytes))
}

fn scalar(
    input: &mut &[u8],
    limit: Option<u64>,
    charged: &mut u64,
    field5: bool,
) -> Result<u64, Error> {
    let mut reader = Reader::new(input, limit, *charged);
    let result = reader.read_u64();
    *input = reader.remaining();
    *charged = reader.charged();
    result.map_err(|e| {
        Error::Read(match e {
            ReadError::Invalid { found_raw, .. } if field5 => ReadError::Invalid {
                expected_raw: 5,
                found_raw,
            },
            other => other,
        })
    })
}
fn charge(n: u64, limit: Option<u64>, charged: &mut u64) -> Result<(), Error> {
    if let Some(limit) = limit {
        let next = charged
            .checked_add(n)
            .ok_or(Error::Read(ReadError::Limit))?;
        *charged = next;
        if next > limit {
            return Err(Error::Read(ReadError::Limit));
        }
    }
    Ok(())
}
fn decode(input: &mut &[u8], limit: Option<u64>, charged: &mut u64) -> Result<Vec<Record>, Error> {
    let n = scalar(input, limit, charged, false)?;
    if limit.is_some() {
        charge(
            n.checked_mul(24).ok_or(Error::Read(ReadError::Limit))?,
            limit,
            charged,
        )?;
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(n.min(0xaaaa) as usize)
        .map_err(|_| Error::Allocation)?;
    for _ in 0..n {
        if limit.is_some() {
            *charged = charged.checked_sub(24).ok_or(Error::Refund)?;
        }
        let tag = read_tag(input, limit, charged).map_err(Error::Read)?;
        if tag != 0 {
            return Err(Error::InvalidVariant(tag));
        }
        if input.len() < 4 {
            return Err(Error::Read(ReadError::UnexpectedEnd {
                additional: (4 - input.len()) as u64,
            }));
        }
        let fixed = u64::from(u32::from_le_bytes(input[..4].try_into().unwrap()));
        *input = &input[4..];
        charge(1, limit, charged)?;
        let Some((&flag, rest)) = input.split_first() else {
            return Err(Error::Read(ReadError::UnexpectedEnd { additional: 1 }));
        };
        *input = rest;
        if flag > 1 {
            return Err(Error::InvalidBool);
        }
        let value = scalar(input, limit, charged, true)?;
        if values.len() == values.capacity() {
            values.try_reserve(1).map_err(|_| Error::Allocation)?;
        }
        values.push(Record {
            fixed,
            value,
            flag: flag == 1,
        });
    }
    Ok(values)
}
/// Start at vector count, after outer response variant0 was selected.
/// On decode failure, initialized records are dropped; input/count remain advanced.
/// Fallible allocation is an explicit safe-adapter boundary, not native panic ABI.
pub fn decode_prefix(mut input: &[u8], limit: Option<u64>, mut charged: u64) -> Outcome<'_> {
    let result = decode(&mut input, limit, &mut charged);
    Outcome {
        result,
        remaining: input,
        charged,
    }
}
