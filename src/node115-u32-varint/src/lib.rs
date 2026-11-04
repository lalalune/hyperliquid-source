#![no_std]

/// Active error values of the selected u32 reader family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    UnexpectedEnd { additional: u64 },
    Limit,
    Invalid { found_raw: u8 },
}

/// Decode one little-endian u32 varint through the selected wrapper relation.
/// The raw mode and limit are separate from the mutable charged count.
#[inline(always)]
pub fn read_u32(
    remaining: &mut &[u8],
    mode: u32,
    limit: u64,
    charged: &mut u64,
) -> Result<u32, ReadError> {
    if mode == 1 {
        let next = charged.checked_add(4).ok_or(ReadError::Limit)?;
        *charged = next;
        if next > limit {
            return Err(ReadError::Limit);
        }
    }

    let input = *remaining;
    let Some((&marker, tail)) = input.split_first() else {
        return Err(ReadError::UnexpectedEnd { additional: 1 });
    };
    if input.len() <= 4 {
        *remaining = tail;
    }

    match marker {
        0..=250 => {
            *remaining = tail;
            Ok(u32::from(marker))
        }
        251 => {
            let Some((bytes, rest)) = tail.split_first_chunk::<2>() else {
                return Err(ReadError::UnexpectedEnd {
                    additional: 2 - tail.len() as u64,
                });
            };
            *remaining = rest;
            Ok(u32::from(u16::from_le_bytes(*bytes)))
        }
        252 => {
            let Some((bytes, rest)) = tail.split_first_chunk::<4>() else {
                return Err(ReadError::UnexpectedEnd {
                    additional: 4 - tail.len() as u64,
                });
            };
            *remaining = rest;
            Ok(u32::from_le_bytes(*bytes))
        }
        253 => Err(ReadError::Invalid { found_raw: 3 }),
        254 => Err(ReadError::Invalid { found_raw: 4 }),
        255 => Err(ReadError::Invalid { found_raw: 12 }),
    }
}

/// Synthetic output words contain tag, active payload, error fields, cursor
/// advance, remaining length and charged count.
///
/// # Safety
/// Input describes a valid immutable slice, including a non-null pointer at
/// length zero. Output holds seven aligned writable u64 words and is disjoint
/// from input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node115_u32_reader_probe(
    output: *mut u64,
    input: *const u8,
    length: usize,
    mode: u32,
    limit: u64,
    count: u64,
) {
    let mut remaining = unsafe { core::slice::from_raw_parts(input, length) };
    let mut charged = count;
    let (tag, payload, expected, found) = match read_u32(&mut remaining, mode, limit, &mut charged) {
        Ok(value) => (18, u64::from(value), 0, 0),
        Err(ReadError::UnexpectedEnd { additional }) => (0, additional, 0, 0),
        Err(ReadError::Limit) => (2, 0, 0, 0),
        Err(ReadError::Invalid { found_raw }) => (3, 0, 2, u64::from(found_raw)),
    };
    let cursor_advance = remaining.as_ptr().addr().wrapping_sub(input.addr());
    unsafe {
        output.write_volatile(tag);
        output.add(1).write_volatile(payload);
        output.add(2).write_volatile(expected);
        output.add(3).write_volatile(found);
        output.add(4).write_volatile(cursor_advance as u64);
        output.add(5).write_volatile(remaining.len() as u64);
        output.add(6).write_volatile(charged);
    }
}
