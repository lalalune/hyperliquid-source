//! Selected TCP bincode error formatting and ownership with cached state 1.
//! Native decoder, arbitrary error variants, allocator and transport are excluded.

#[derive(Debug, PartialEq, Eq)]
pub enum Boundary {
    UnsupportedTag(u8),
    UnsupportedIntegerType(u8),
}
#[derive(Debug, PartialEq, Eq)]
pub struct BeforeFormat {
    pub boundary: Boundary,
    pub frame: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct OwnedError {
    message: String,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Released {
    pub string_len: usize,
    pub owner_bytes: usize,
}
impl OwnedError {
    pub fn message(&self) -> &str {
        &self.message
    }
    /// Logical lifetime event for the selected cached-state-1 destructor.
    pub fn release(self) -> Released {
        Released {
            string_len: self.message.len(),
            owner_bytes: 80,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    pub tag: u8,
    pub error: OwnedError,
}

const INTEGER_NAMES: [&str; 12] = [
    "U8", "U16", "U32", "U64", "U128", "Usize", "I8", "I16", "I32", "I64", "I128", "Isize",
];
/// The 24-byte slice is the selected prefix of a larger decoded enum; inactive
/// fields and other variants are not modeled. Cached backtrace state 1 is a
/// premise for the selected native ownership/destructor continuation.
/// Raw selected decoder layout: tag at byte0, tag0 u64 at +8; tag3 expected
/// and found type tags at +1/+2. Input must be a valid decoded value. The
/// native caller materializes the string and 80-byte owner before frame release.
pub fn convert(raw: &[u8; 24], frame: Vec<u8>) -> Result<Output, BeforeFormat> {
    let mut message = String::from("TcpRead::bincode err: ");
    match raw[0] {
        0 => {
            let n = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            message.push_str("UnexpectedEnd { additional: ");
            message.push_str(&n.to_string());
            message.push_str(" }");
        }
        1 => message.push_str("InvalidBytesLength"),
        2 => message.push_str("LimitExceeded"),
        3 => {
            let Some(expected) = INTEGER_NAMES.get(raw[1] as usize) else {
                return Err(BeforeFormat {
                    boundary: Boundary::UnsupportedIntegerType(raw[1]),
                    frame,
                });
            };
            let Some(found) = INTEGER_NAMES.get(raw[2] as usize) else {
                return Err(BeforeFormat {
                    boundary: Boundary::UnsupportedIntegerType(raw[2]),
                    frame,
                });
            };
            message.push_str("InvalidIntegerType { expected: ");
            message.push_str(expected);
            message.push_str(", found: ");
            message.push_str(found);
            message.push_str(" }");
        }
        tag => {
            return Err(BeforeFormat {
                boundary: Boundary::UnsupportedTag(tag),
                frame,
            })
        }
    }
    let error = OwnedError { message };
    drop(frame);
    Ok(Output { tag: 1, error })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_tags_literal_and_decimal_boundaries() {
        let mut raw = [0xa5; 24];
        raw[0] = 1;
        assert_eq!(
            convert(&raw, vec![]).unwrap().error.message(),
            "TcpRead::bincode err: InvalidBytesLength"
        );
        raw[0] = 2;
        assert_eq!(
            convert(&raw, vec![1]).unwrap().error.message(),
            "TcpRead::bincode err: LimitExceeded"
        );
        raw[0] = 0;
        for (n, want) in [
            (0, "0"),
            (1, "1"),
            (9, "9"),
            (10, "10"),
            (9999, "9999"),
            (10000, "10000"),
            (u64::MAX, "18446744073709551615"),
        ] {
            raw[8..16].copy_from_slice(&n.to_le_bytes());
            let out = convert(&raw, vec![1, 2, 3]).unwrap();
            assert_eq!(out.tag, 1);
            assert_eq!(
                out.error.message(),
                [
                    "TcpRead::bincode err: UnexpectedEnd { additional: ",
                    want,
                    " }"
                ]
                .concat()
            );
        }
    }
    #[test]
    fn raw_integer_pairs_exact_names() {
        let names = [
            "U8", "U16", "U32", "U64", "U128", "Usize", "I8", "I16", "I32", "I64", "I128", "Isize",
        ];
        for i in 0..12 {
            for j in 0..12 {
                let mut raw = [0; 24];
                raw[0] = 3;
                raw[1] = i as u8;
                raw[2] = j as u8;
                let out = convert(&raw, vec![]).unwrap();
                assert_eq!(
                    out.error.message(),
                    [
                        "TcpRead::bincode err: InvalidIntegerType { expected: ",
                        names[i],
                        ", found: ",
                        names[j],
                        " }"
                    ]
                    .concat()
                );
            }
        }
    }
    #[test]
    fn lifetime_and_explicit_unsupported_boundary() {
        let mut raw = [0; 24];
        raw[0] = 2;
        let out = convert(&raw, vec![5; 100]).unwrap();
        let len = out.error.message().len();
        assert_eq!(
            out.error.release(),
            Released {
                string_len: len,
                owner_bytes: 80
            }
        );
        raw[0] = 4;
        let e = convert(&raw, vec![9]).unwrap_err();
        assert_eq!(e.boundary, Boundary::UnsupportedTag(4));
        assert_eq!(e.frame, vec![9]);
        raw[0] = 3;
        raw[1] = 12;
        assert_eq!(
            convert(&raw, vec![]).unwrap_err().boundary,
            Boundary::UnsupportedIntegerType(12)
        );
    }
}
