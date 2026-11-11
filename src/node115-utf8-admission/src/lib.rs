//! Safe logical projection of the digest-bound node115 byte validator.
//! Output padding, raw pointers and the native Result layout are not exposed.
#![no_std]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid {
    pub valid_up_to: usize,
    pub error_len: Option<u8>,
}
/// Validate one complete byte span; a truncated final sequence has no error length.
pub fn validate(bytes: &[u8]) -> Result<(), Invalid> {
    let mut i = 0;
    while i < bytes.len() {
        let first = bytes[i];
        if first < 0x80 {
            i += 1;
            continue;
        }
        let width = match first {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => {
                return Err(Invalid {
                    valid_up_to: i,
                    error_len: Some(1),
                })
            }
        };
        for part in 1..width {
            if part >= bytes.len() - i {
                return Err(Invalid {
                    valid_up_to: i,
                    error_len: None,
                });
            }
            let next = bytes[i + part];
            let accepted = if part == 1 {
                match first {
                    0xe0 => (0xa0..=0xbf).contains(&next),
                    0xed => (0x80..=0x9f).contains(&next),
                    0xf0 => (0x90..=0xbf).contains(&next),
                    0xf4 => (0x80..=0x8f).contains(&next),
                    _ => (0x80..=0xbf).contains(&next),
                }
            } else {
                (0x80..=0xbf).contains(&next)
            };
            if !accepted {
                return Err(Invalid {
                    valid_up_to: i,
                    error_len: Some(part as u8),
                });
            }
        }
        i += width;
    }
    Ok(())
}
