//! Value-level model of the node #115 MessagePack numeric variant-id dispatch.
//!
//! Evidence: `research/work-items/RE-010-action-msgpack-number-identifier-115`,
//! bound to target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Copy {
    N1,
    N2,
    N3,
    N4,
    N5,
}

impl Copy {
    pub const fn variant_count(self) -> u16 {
        match self {
            Self::N1 => 79,
            Self::N2 => 92,
            Self::N3 => 16,
            Self::N4 => 114,
            Self::N5 => 18,
        }
    }

    pub const fn eof_error_address(self) -> u64 {
        match self {
            Self::N1 => 0x63f8470,
            Self::N2 | Self::N3 | Self::N4 | Self::N5 => 0x64622f0,
        }
    }

    #[cfg(test)]
    fn from_label(label: &str) -> Option<Self> {
        match label {
            "N1" => Some(Self::N1),
            "N2" => Some(Self::N2),
            "N3" => Some(Self::N3),
            "N4" => Some(Self::N4),
            "N5" => Some(Self::N5),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unexpected {
    Unit,
    Bool(bool),
    /// Two's-complement payload bits after sign extension to 64 bits.
    Signed(u64),
    /// IEEE-754 binary64 payload bits.
    Float(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultValue {
    Variant(u64),
    InvalidValue {
        unsigned: u64,
        variant_count: u16,
    },
    InvalidType(Unexpected),
    /// Static error identity only; message formatting is outside this model.
    UnexpectedEof {
        error_address: u64,
    },
    /// Non-scalar marker pass-through preserves both low-byte inputs.
    PassThrough {
        marker: u8,
        data: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decoded {
    pub value: ResultValue,
    /// Bytes consumed from the available payload slice.
    pub consumed: usize,
}

/// Decode one dispatcher input from its marker, marker-data byte and payload.
///
/// Marker zero represents the packet's FixPos arm with value in `data`; marker
/// `0xe0` represents FixNeg. Multi-byte scalar payloads are read big-endian.
/// Short payloads consume the available bytes and return the selected static
/// EOF error identity. The API does not parse an entire MessagePack stream.
pub fn decode(copy: Copy, marker: u8, data: u8, payload: &[u8]) -> Decoded {
    let count = copy.variant_count();
    if marker == 0 {
        return Decoded {
            value: visit_unsigned(u64::from(data), count),
            consumed: 0,
        };
    }
    if marker == 0xe0 {
        return Decoded {
            value: ResultValue::InvalidType(Unexpected::Signed(sign_extend(u64::from(data), 1))),
            consumed: 0,
        };
    }

    let (kind, width) = match marker {
        0xc0 => (Kind::Unit, 0),
        0xc2 => (Kind::Bool(false), 0),
        0xc3 => (Kind::Bool(true), 0),
        0xca => (Kind::Float32, 4),
        0xcb => (Kind::Float64, 8),
        0xcc => (Kind::Unsigned, 1),
        0xcd => (Kind::Unsigned, 2),
        0xce => (Kind::Unsigned, 4),
        0xcf => (Kind::Unsigned, 8),
        0xd0 => (Kind::Signed, 1),
        0xd1 => (Kind::Signed, 2),
        0xd2 => (Kind::Signed, 4),
        0xd3 => (Kind::Signed, 8),
        _ => {
            return Decoded {
                value: ResultValue::PassThrough { marker, data },
                consumed: 0,
            }
        }
    };

    if payload.len() < width {
        return Decoded {
            value: ResultValue::UnexpectedEof {
                error_address: copy.eof_error_address(),
            },
            consumed: payload.len(),
        };
    }
    let raw = payload
        .iter()
        .take(width)
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let value = match kind {
        Kind::Unit => ResultValue::InvalidType(Unexpected::Unit),
        Kind::Bool(value) => ResultValue::InvalidType(Unexpected::Bool(value)),
        Kind::Unsigned => visit_unsigned(raw, count),
        Kind::Signed => ResultValue::InvalidType(Unexpected::Signed(sign_extend(raw, width))),
        Kind::Float32 => {
            let value = f32::from_bits(raw as u32);
            ResultValue::InvalidType(Unexpected::Float(f64::from(value).to_bits()))
        }
        Kind::Float64 => ResultValue::InvalidType(Unexpected::Float(raw)),
    };
    Decoded {
        value,
        consumed: width,
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Unit,
    Bool(bool),
    Unsigned,
    Signed,
    Float32,
    Float64,
}

fn visit_unsigned(value: u64, count: u16) -> ResultValue {
    if value < u64::from(count) {
        ResultValue::Variant(value)
    } else {
        ResultValue::InvalidValue {
            unsigned: value,
            variant_count: count,
        }
    }
}

fn sign_extend(value: u64, width: usize) -> u64 {
    if width == 8 {
        value
    } else {
        let bits = width * 8;
        let mask = (1u64 << bits) - 1;
        let value = value & mask;
        if value & (1u64 << (bits - 1)) != 0 {
            value | !mask
        } else {
            value
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, Copy, Decoded, ResultValue, Unexpected};

    fn hex_bytes(text: &str) -> Vec<u8> {
        if text == "-" || text.is_empty() {
            return Vec::new();
        }
        assert_eq!(text.len() % 2, 0);
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap() as u8;
                let low = (pair[1] as char).to_digit(16).unwrap() as u8;
                (high << 4) | low
            })
            .collect()
    }

    fn render(decoded: Decoded) -> String {
        match decoded.value {
            ResultValue::Variant(index) => format!("ok:0x{index:x}"),
            ResultValue::InvalidValue {
                unsigned,
                variant_count: _,
            } => format!("invalid_value:Unsigned:0x{unsigned:x}:variant_index_text"),
            ResultValue::InvalidType(Unexpected::Unit) => "invalid_type:Unit:-:visitor".to_owned(),
            ResultValue::InvalidType(Unexpected::Bool(value)) => {
                format!("invalid_type:Bool:0x{}:visitor", u8::from(value))
            }
            ResultValue::InvalidType(Unexpected::Signed(bits)) => {
                format!("invalid_type:Signed:0x{bits:x}:visitor")
            }
            ResultValue::InvalidType(Unexpected::Float(bits)) => {
                format!("invalid_type:Float:0x{bits:x}:visitor")
            }
            ResultValue::UnexpectedEof { error_address } => {
                format!("eof:0x{error_address:x}")
            }
            ResultValue::PassThrough { marker, data } => {
                format!("passthrough:0x{marker:x}:0x{data:x}")
            }
        }
    }

    #[test]
    fn matches_all_frozen_dispatcher_cases() {
        let cases = include_str!(
            "../../../research/work-items/RE-010-action-msgpack-number-identifier-115/cases.tsv"
        );
        let mut count = 0;
        for row in cases.lines().skip(1) {
            let fields: Vec<_> = row.split('\t').collect();
            let copy = Copy::from_label(fields[0]).expect("known copy");
            let marker = u8::from_str_radix(fields[1].trim_start_matches("0x"), 16).unwrap();
            let data = u8::from_str_radix(fields[2].trim_start_matches("0x"), 16).unwrap();
            let payload = hex_bytes(fields[3]);
            let expected = fields[4];
            let consumed: usize = fields[5].parse().unwrap();
            assert_eq!(fields[6], "yes", "frozen case must be matched");
            let actual = decode(copy, marker, data, &payload);
            assert_eq!(render(actual), expected, "copy={} case={row}", fields[0]);
            assert_eq!(actual.consumed, consumed, "copy={} case={row}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 8_579);
    }

    #[test]
    fn copy_variant_counts_are_the_observed_dispatch_bounds() {
        assert_eq!(
            [
                Copy::N1.variant_count(),
                Copy::N2.variant_count(),
                Copy::N3.variant_count(),
                Copy::N4.variant_count(),
                Copy::N5.variant_count(),
            ],
            [79, 92, 16, 114, 18]
        );
    }
}
