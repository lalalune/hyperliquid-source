#![no_std]
#![forbid(unsafe_code)]

//! Safe value projection of node94 `[0x3cd2460, 0x3cd2490)`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    Start,
    End,
}

fn read(image: &[u8], image_base: u64, address: u64) -> Option<u8> {
    let offset = usize::try_from(address.checked_sub(image_base)?).ok()?;
    image.get(offset).copied()
}

fn allowed(byte: u8) -> bool {
    byte & 0xc0 != 0x80
}

/// Return full numeric RAX/RDX, including the span on rejected gates.
///
/// The image represents a nonwrapping range of ordinary stable memory. Numeric
/// effective addresses wrap before their individual byte admission. Errors are
/// a new safe policy; they do not model original faults. A zero RAX can also be
/// a passing result, so this API does not assign it an Option-like meaning.
pub fn gate(
    image: &[u8],
    image_base: u64,
    base: u64,
    start: u64,
    end: u64,
    limit: u64,
) -> Result<Registers, AccessError> {
    if !image.is_empty() {
        let last = u64::try_from(image.len() - 1).map_err(|_| AccessError::ImageRange)?;
        image_base
            .checked_add(last)
            .ok_or(AccessError::ImageRange)?;
    }
    let rdx = end.wrapping_sub(start);
    let rejected = Registers { rax: 0, rdx };
    if end < start || start > limit {
        return Ok(rejected);
    }
    if start < limit {
        let byte = read(image, image_base, base.wrapping_add(start)).ok_or(AccessError::Start)?;
        if !allowed(byte) {
            return Ok(rejected);
        }
    }
    if end > limit {
        return Ok(rejected);
    }
    if end < limit {
        let byte = read(image, image_base, base.wrapping_add(end)).ok_or(AccessError::End)?;
        if !allowed(byte) {
            return Ok(rejected);
        }
    }
    Ok(Registers {
        rax: base.wrapping_add(start),
        rdx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_keeps_wrapped_span() {
        assert_eq!(
            gate(&[], 0, 0, 2, 1, 0),
            Ok(Registers {
                rax: 0,
                rdx: u64::MAX
            })
        );
    }

    #[test]
    fn first_read_precedes_end_limit() {
        assert_eq!(gate(&[], 0, 0, 0, 2, 1), Err(AccessError::Start));
        assert_eq!(
            gate(&[0x80], 0, 0, 0, 2, 1),
            Ok(Registers { rax: 0, rdx: 2 })
        );
    }

    #[test]
    fn skipped_endpoints_and_wrapped_zero_success() {
        assert_eq!(
            gate(&[], 0, u64::MAX, 1, 1, 1),
            Ok(Registers { rax: 0, rdx: 0 })
        );
        assert_eq!(
            gate(&[0x7f, 0xff], 7, 7, 0, 1, 2),
            Ok(Registers { rax: 7, rdx: 1 })
        );
    }
}
