//! Fresh-reader projection of the node115 FeeRateMapSerde decoder.
//!
//! This computes value bits and a coarse error/cursor/depth observation. It does
//! not implement the native reader/result ABI, diagnostics, allocation, unwinding
//! or cached-marker states. Correspondence assumes the ordinary callback/frame
//! contract and Intel SSE2 RN-even, masked exceptions, DAZ=0 and FTZ=0 described
//! in RE-005-node115-fee-rate-map-decode. This implementation uses no FP arithmetic.

/// The observed cache category is fresh at every admitted return or boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheState {
    Fresh,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerKind {
    Array,
    Map,
    Extension,
}

/// Active error classifications, excluding rendered and inactive native fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    MarkerEof,
    TruncatedRead,
    PayloadTooShort,
    UnexpectedMarker(u8),
    InvalidLength(u8),
    ExcessElements,
    InvalidType,
    InvalidUtf8,
    DepthLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeOutcome {
    Value([u64; 4]),
    Error(DecodeError),
    /// Safe-host refusal at a native depth-zero call site, not a native error.
    PanicBoundary(ContainerKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub outcome: DecodeOutcome,
    pub consumed: usize,
    pub depth_after: u16,
    pub cache: CacheState,
}

/// Decode one prefix from an initially fresh reader, leaving trailing data unread.
///
/// Arrays accept exactly four numeric values. A longer array fails after its
/// fourth value; a binary payload of at least four bytes instead succeeds using
/// the first four bytes and consumes the whole payload. Errors do not generally
/// restore the cursor or depth. Depth zero is refused only if a container guard
/// is actually reached, after reading its complete header.
///
/// The returned words preserve raw float64 payloads. Integer values are rounded
/// to binary64 with ties to even. Float32 values widen exactly; NaNs retain their
/// sign and shifted payload and acquire the binary64 quiet bit. No exception
/// flags or diagnostic floating-point activity are reproduced.
pub fn decode_prefix(input: &[u8], depth: u16) -> Observation {
    let mut reader = Reader {
        input,
        position: 0,
        depth,
    };
    let outcome = match reader.decode() {
        Ok(words) => DecodeOutcome::Value(words),
        Err(Failure::Error(error)) => DecodeOutcome::Error(error),
        Err(Failure::Panic(kind)) => DecodeOutcome::PanicBoundary(kind),
    };
    Observation {
        outcome,
        consumed: reader.position,
        depth_after: reader.depth,
        cache: CacheState::Fresh,
    }
}

enum Failure {
    Error(DecodeError),
    Panic(ContainerKind),
}

impl From<DecodeError> for Failure {
    fn from(error: DecodeError) -> Self {
        Self::Error(error)
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
    depth: u16,
}

impl Reader<'_> {
    fn marker(&mut self) -> Result<u8, DecodeError> {
        let marker = *self
            .input
            .get(self.position)
            .ok_or(DecodeError::MarkerEof)?;
        self.position += 1;
        Ok(marker)
    }

    // A short fixed-width read consumes the remaining suffix.
    fn fixed(&mut self, width: usize) -> Result<u64, DecodeError> {
        if self.input.len() - self.position < width {
            self.position = self.input.len();
            return Err(DecodeError::TruncatedRead);
        }
        let mut word = 0;
        for byte in &self.input[self.position..self.position + width] {
            word = (word << 8) | u64::from(*byte);
        }
        self.position += width;
        Ok(word)
    }

    // Unlike fixed(), a short declared payload is left entirely unread.
    fn payload(&mut self, length: u64) -> Result<&[u8], DecodeError> {
        if length > (self.input.len() - self.position) as u64 {
            return Err(DecodeError::PayloadTooShort);
        }
        let start = self.position;
        self.position += length as usize;
        Ok(&self.input[start..self.position])
    }

    fn enter(&mut self, kind: ContainerKind) -> Result<(), Failure> {
        if self.depth == 0 {
            return Err(Failure::Panic(kind));
        }
        self.depth -= 1;
        if self.depth == 0 {
            return Err(DecodeError::DepthLimit.into());
        }
        Ok(())
    }

    fn decode(&mut self) -> Result<[u64; 4], Failure> {
        let marker = self.marker()?;
        match marker {
            0x90..=0x9f | 0xdc..=0xdd => {
                let count = match marker {
                    0xdc => self.fixed(2)?,
                    0xdd => self.fixed(4)?,
                    _ => u64::from(marker & 15),
                };
                self.enter(ContainerKind::Array)?;
                let mut words = [0; 4];
                for (index, word) in words.iter_mut().enumerate() {
                    if count == index as u64 {
                        return Err(DecodeError::InvalidLength(index as u8).into());
                    }
                    *word = self.number()?;
                }
                // Only four successful reads reach this restoration, even for
                // an excess count. No fifth marker is read.
                self.depth += 1;
                if count == 4 {
                    Ok(words)
                } else {
                    Err(DecodeError::ExcessElements.into())
                }
            }
            0xc4..=0xc6 => {
                let length = self.fixed(1 << (marker - 0xc4))?;
                let bytes = self.payload(length)?;
                if bytes.len() < 4 {
                    return Err(DecodeError::InvalidLength(bytes.len() as u8).into());
                }
                Ok(core::array::from_fn(|index| {
                    unsigned_bits(u64::from(bytes[index]))
                }))
            }
            0x80..=0x8f | 0xde..=0xdf => {
                match marker {
                    0xde => {
                        self.fixed(2)?;
                    }
                    0xdf => {
                        self.fixed(4)?;
                    }
                    _ => {}
                }
                self.enter(ContainerKind::Map)?;
                Err(DecodeError::InvalidType.into())
            }
            0xc7..=0xc9 | 0xd4..=0xd8 => {
                if marker <= 0xc9 {
                    self.fixed(1 << (marker - 0xc7))?;
                }
                self.enter(ContainerKind::Extension)?;
                // The concrete visitor rejects before reading type or payload.
                self.depth += 1;
                Err(DecodeError::InvalidType.into())
            }
            0xa0..=0xbf | 0xd9..=0xdb => {
                let length = if marker <= 0xbf {
                    u64::from(marker & 31)
                } else {
                    self.fixed(1 << (marker - 0xd9))?
                };
                let bytes = self.payload(length)?;
                let error = if core::str::from_utf8(bytes).is_ok() {
                    DecodeError::InvalidType
                } else {
                    DecodeError::InvalidUtf8
                };
                Err(error.into())
            }
            0xc1 => Err(DecodeError::UnexpectedMarker(0xc1).into()),
            0x00..=0x7f | 0xc0 | 0xc2..=0xc3 | 0xca..=0xd3 | 0xe0..=0xff => {
                let width = numeric_width(marker);
                if width != 0 {
                    self.fixed(width)?;
                }
                // Diagnostic conversions/formatting are outside this projection.
                Err(DecodeError::InvalidType.into())
            }
        }
    }

    fn number(&mut self) -> Result<u64, DecodeError> {
        let marker = self.marker()?;
        Ok(match marker {
            0x00..=0x7f => unsigned_bits(u64::from(marker)),
            0xe0..=0xff => signed_bits(i64::from(marker as i8)),
            0xcc..=0xcf => unsigned_bits(self.fixed(numeric_width(marker))?),
            0xd0 => signed_bits(self.fixed(1)? as i8 as i64),
            0xd1 => signed_bits(self.fixed(2)? as i16 as i64),
            0xd2 => signed_bits(self.fixed(4)? as i32 as i64),
            0xd3 => signed_bits(self.fixed(8)? as i64),
            0xca => widen_binary32(self.fixed(4)? as u32),
            0xcb => self.fixed(8)?,
            0xc0 | 0xc2..=0xc3 => return Err(DecodeError::InvalidType),
            _ => {
                let category = match marker {
                    0x80..=0x8f => 0x80,
                    0x90..=0x9f => 0x90,
                    0xa0..=0xbf => 0xa0,
                    _ => marker,
                };
                return Err(DecodeError::UnexpectedMarker(category));
            }
        })
    }
}

fn numeric_width(marker: u8) -> usize {
    match marker {
        0xcc | 0xd0 => 1,
        0xcd | 0xd1 => 2,
        0xca | 0xce | 0xd2 => 4,
        0xcb | 0xcf | 0xd3 => 8,
        _ => 0,
    }
}

// Round the exact integer once, with ties to an even binary64 significand.
fn unsigned_bits(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    let exponent = 63 - value.leading_zeros();
    let significand = if exponent <= 52 {
        value << (52 - exponent)
    } else {
        let shift = exponent - 52;
        let quotient = value >> shift;
        let remainder = value & ((1 << shift) - 1);
        let half = 1 << (shift - 1);
        quotient + u64::from(remainder > half || (remainder == half && quotient & 1 != 0))
    };
    // A significand carry increments the encoded exponent by ordinary addition.
    ((u64::from(exponent) + 1023) << 52) + (significand - (1 << 52))
}

fn signed_bits(value: i64) -> u64 {
    unsigned_bits(value.unsigned_abs()) | (u64::from(value < 0) << 63)
}

fn widen_binary32(bits: u32) -> u64 {
    let sign = u64::from(bits >> 31) << 63;
    let exponent = (bits >> 23) & 255;
    let fraction = u64::from(bits & 0x7fffff);
    let magnitude = match exponent {
        0 if fraction == 0 => 0,
        0 => {
            let top = 63 - fraction.leading_zeros();
            ((u64::from(top) + 874) << 52) | ((fraction - (1 << top)) << (52 - top))
        }
        255 => 0x7ff0000000000000 | (fraction << 29) | if fraction == 0 { 0 } else { 1 << 51 },
        _ => ((u64::from(exponent) + 896) << 52) | (fraction << 29),
    };
    sign | magnitude
}
