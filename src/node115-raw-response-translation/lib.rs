//! Method-specific continuation after the separately credited JsonRpcResult
//! decoder. This module does not parse arbitrary JSON or operate a transport.
#[derive(Debug, Clone, PartialEq)]
pub enum Data {
    Null,
    Bool(bool),
    Signed(i64),
    Unsigned(u64),
    Float(f64),
    Array(Vec<Data>),
    String(String),
    Object,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Boundary {
    String,
    FiniteFloat,
    Object,
}
#[derive(Debug, PartialEq, Eq)]
pub struct BeforeHelper {
    pub boundary: Boundary,
    pub prefix: Vec<u8>,
}
fn decimal(mut n: u64, out: &mut Vec<u8>) {
    let mut digits = [0u8; 20];
    let mut at = 20;
    loop {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[at..]);
}
fn append(value: &Data, out: &mut Vec<u8>) -> Result<(), Boundary> {
    match value {
        Data::Null => out.extend_from_slice(b"null"),
        Data::Bool(true) => out.extend_from_slice(b"true"),
        Data::Bool(false) => out.extend_from_slice(b"false"),
        Data::Unsigned(n) => decimal(*n, out),
        Data::Signed(n) => {
            if *n < 0 {
                out.push(b'-');
            }
            decimal(n.unsigned_abs(), out);
        }
        Data::Float(n) if !n.is_finite() => out.extend_from_slice(b"null"),
        Data::Float(_) => return Err(Boundary::FiniteFloat),
        Data::Array(values) => {
            out.push(b'[');
            for (i, value) in values.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                append(value, out)?;
            }
            out.push(b']');
        }
        Data::String(_) => return Err(Boundary::String),
        Data::Object => return Err(Boundary::Object),
    }
    Ok(())
}
pub fn encode_selected(value: &Data) -> Result<Vec<u8>, BeforeHelper> {
    let mut out = Vec::new();
    match append(value, &mut out) {
        Ok(()) => Ok(out),
        Err(boundary) => Err(BeforeHelper {
            boundary,
            prefix: out,
        }),
    }
}
/// Raw native category tags; semantic enum names are not inferred.
pub fn category(code: i32) -> u32 {
    match code {
        -32700 => 0,
        -32007 => 1,
        -32600 => 2,
        -32601 => 3,
        -32602 => 5,
        -32603 => 6,
        _ => 7,
    }
}
#[derive(Debug, PartialEq)]
pub enum Decoded {
    Success([u8; 32]),
    Error {
        code: i32,
        message: Vec<u8>,
        data: Option<Data>,
    },
}
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    Success {
        tag: u64,
        hash: [u8; 32],
    },
    Error {
        tag: u64,
        category: u32,
        code: i32,
        message: Vec<u8>,
        data: Option<Vec<u8>>,
    },
}
#[derive(Debug, PartialEq, Eq)]
pub enum Finished<E> {
    Response(Response),
    DecodeError(E),
    BeforeTrailingError22 { cursor: usize },
    BeforeDataHelper(BeforeHelper),
    InvalidCursor,
}
/// 1700bd0 validates only trailing JSON whitespace after a successful decoder;
/// its existing error bypasses that check. The supplied decoded value is the
/// input premise of this continuation. Prior2127 covers related generic codec
/// work; decoder1707010 is not reimplemented or assumed equivalent to1751380.
pub fn finish_decoded<E>(
    input: &[u8],
    mut cursor: usize,
    decoded: Result<Decoded, E>,
) -> Finished<E> {
    let decoded = match decoded {
        Ok(v) => v,
        Err(error) => return Finished::DecodeError(error),
    };
    if cursor > input.len() {
        return Finished::InvalidCursor;
    }
    while cursor < input.len() {
        if matches!(input[cursor], b' ' | b'\t' | b'\r' | b'\n') {
            cursor += 1;
        } else {
            return Finished::BeforeTrailingError22 { cursor };
        }
    }
    match decoded {
        Decoded::Success(hash) => Finished::Response(Response::Success { tag: 3, hash }),
        Decoded::Error {
            code,
            message,
            data,
        } => {
            let data = match data {
                None => None,
                Some(value) => match encode_selected(&value) {
                    Ok(bytes) => Some(bytes),
                    Err(stop) => return Finished::BeforeDataHelper(stop),
                },
            };
            Finished::Response(Response::Error {
                tag: if data.is_some() { 1 } else { 2 },
                category: category(code),
                code,
                message,
                data,
            })
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn error(data: Option<Data>, code: i32) -> Result<Decoded, ()> {
        Ok(Decoded::Error {
            code,
            message: b"server message".to_vec(),
            data,
        })
    }
    #[test]
    fn code_map_exhaustive_short_range_and_full_width() {
        for code in -65536..=65536 {
            let special = [
                (-32700, 0),
                (-32007, 1),
                (-32600, 2),
                (-32601, 3),
                (-32602, 5),
                (-32603, 6),
            ];
            let expected = special.into_iter().find(|x| x.0 == code).map_or(7, |x| x.1);
            assert_eq!(category(code), expected);
        }
        assert_eq!(category(i32::MIN), 7);
        assert_eq!(category(i32::MAX), 7);
    }
    #[test]
    fn absent_and_null_are_distinct_and_message_code_preserved() {
        assert_eq!(
            finish_decoded(b"", 0, error(None, -32603)),
            Finished::Response(Response::Error {
                tag: 2,
                category: 6,
                code: -32603,
                message: b"server message".to_vec(),
                data: None
            })
        );
        assert_eq!(
            finish_decoded(b"", 0, error(Some(Data::Null), 37)),
            Finished::Response(Response::Error {
                tag: 1,
                category: 7,
                code: 37,
                message: b"server message".to_vec(),
                data: Some(b"null".to_vec())
            })
        );
    }
    #[test]
    fn selected_data_exact_bytes_and_integer_oracle() {
        for n in -10000..=10000i64 {
            assert_eq!(
                encode_selected(&Data::Signed(n)).unwrap(),
                n.to_string().as_bytes()
            );
        }
        for n in [0, 1, 99, 100, 9999, 10000, u64::MAX] {
            assert_eq!(
                encode_selected(&Data::Unsigned(n)).unwrap(),
                n.to_string().as_bytes()
            );
        }
        assert_eq!(
            encode_selected(&Data::Signed(i64::MIN)).unwrap(),
            b"-9223372036854775808"
        );
        let data = Data::Array(vec![
            Data::Bool(true),
            Data::Bool(false),
            Data::Array(vec![]),
            Data::Null,
            Data::Float(f64::INFINITY),
        ]);
        assert_eq!(
            encode_selected(&data).unwrap(),
            b"[true,false,[],null,null]"
        );
    }
    #[test]
    fn full_width_decimal_and_integrated_nested_data() {
        let mut n = 0x754fc5a193b2e618u64;
        for _ in 0..4096 {
            n = n
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            assert_eq!(
                encode_selected(&Data::Unsigned(n)).unwrap(),
                n.to_string().as_bytes()
            );
            assert_eq!(
                encode_selected(&Data::Signed(n as i64)).unwrap(),
                (n as i64).to_string().as_bytes()
            );
        }
        for bits in [
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            0x7ff0000000000001,
            0xffffffffffffffff,
        ] {
            assert_eq!(
                encode_selected(&Data::Float(f64::from_bits(bits))).unwrap(),
                b"null"
            );
        }
        let data = Data::Array(vec![
            Data::Signed(-1),
            Data::Array(vec![Data::Bool(false), Data::Unsigned(u64::MAX)]),
        ]);
        assert_eq!(
            finish_decoded(b"decoded \n", 7, error(Some(data), -32700)),
            Finished::Response(Response::Error {
                tag: 1,
                category: 0,
                code: -32700,
                message: b"server message".to_vec(),
                data: Some(b"[-1,[false,18446744073709551615]]".to_vec()),
            })
        );
    }
    #[test]
    fn stop_keeps_already_written_prefix() {
        let d = Data::Array(vec![Data::Unsigned(1), Data::Float(1.5)]);
        assert_eq!(
            encode_selected(&d),
            Err(BeforeHelper {
                boundary: Boundary::FiniteFloat,
                prefix: b"[1,".to_vec()
            })
        );
        assert_eq!(
            encode_selected(&Data::String("x".into()))
                .unwrap_err()
                .boundary,
            Boundary::String
        );
    }
    #[test]
    fn exact_whitespace_and_decode_error_precedence() {
        for b in 0..=255u8 {
            let got = finish_decoded(&[b], 0, error(None, 0));
            if matches!(b, 9 | 10 | 13 | 32) {
                assert!(matches!(got, Finished::Response(_)));
            } else {
                assert_eq!(got, Finished::BeforeTrailingError22 { cursor: 0 });
            }
        }
        let fail: Result<Decoded, _> = Err(99);
        assert_eq!(
            finish_decoded(b"junk", usize::MAX, fail),
            Finished::DecodeError(99)
        );
        assert_eq!(
            finish_decoded(b" \tX", 0, error(None, 0)),
            Finished::BeforeTrailingError22 { cursor: 2 }
        );
    }
    #[test]
    fn successful_hash_every_byte_and_end_cursor() {
        let hash = std::array::from_fn(|i| i as u8);
        assert_eq!(
            finish_decoded::<()>(b"parsed \r\n", 6, Ok(Decoded::Success(hash))),
            Finished::Response(Response::Success { tag: 3, hash })
        );
        assert_eq!(
            finish_decoded::<()>(b"", 1, Ok(Decoded::Success(hash))),
            Finished::InvalidCursor
        );
    }
}
