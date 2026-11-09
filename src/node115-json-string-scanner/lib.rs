//! Selected strict-mode byte scanner at 0x5c56b60. Caller has consumed the
//! opening quote. Valid cursor/storage and successful allocation are premises.
//! Error values stop before native error allocation/position formatting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output<'a> {
    Borrowed(&'a [u8]),
    Scratch(&'a [u8]),
}
fn error(code: u64) -> Error {
    Error { code }
}
fn hex4(input: &[u8], cursor: &mut usize) -> Result<u16, Error> {
    if input.len() - *cursor < 4 {
        *cursor = input.len();
        return Err(error(4));
    }
    let bytes = &input[*cursor..*cursor + 4];
    *cursor += 4;
    let mut value = 0u16;
    for &byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(error(12)),
        };
        value = (value << 4) | u16::from(digit);
    }
    Ok(value)
}
fn unicode(input: &[u8], cursor: &mut usize, scratch: &mut Vec<u8>) -> Result<(), Error> {
    let first = hex4(input, cursor)?;
    if (0xdc00..=0xdfff).contains(&first) {
        return Err(error(20));
    }
    let cp = if (0xd800..=0xdbff).contains(&first) {
        let Some(&slash) = input.get(*cursor) else {
            return Err(error(4));
        };
        *cursor += 1;
        if slash != b'\\' {
            return Err(error(23));
        }
        let Some(&u) = input.get(*cursor) else {
            return Err(error(4));
        };
        *cursor += 1;
        if u != b'u' {
            return Err(error(23));
        }
        let second = hex4(input, cursor)?;
        if !(0xdc00..=0xdfff).contains(&second) {
            return Err(error(20));
        }
        0x10000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
    } else {
        u32::from(first)
    };
    // Independently authored scalar encoding, checked against Rust's Unicode
    // encoder over every Unicode scalar in tests.
    if cp < 0x80 {
        scratch.push(cp as u8);
    } else if cp < 0x800 {
        scratch.extend_from_slice(&[(0xc0 | (cp >> 6)) as u8, (0x80 | (cp & 63)) as u8]);
    } else if cp < 0x10000 {
        scratch.extend_from_slice(&[
            (0xe0 | (cp >> 12)) as u8,
            (0x80 | ((cp >> 6) & 63)) as u8,
            (0x80 | (cp & 63)) as u8,
        ]);
    } else {
        scratch.extend_from_slice(&[
            (0xf0 | (cp >> 18)) as u8,
            (0x80 | ((cp >> 12) & 63)) as u8,
            (0x80 | ((cp >> 6) & 63)) as u8,
            (0x80 | (cp & 63)) as u8,
        ]);
    }
    Ok(())
}
/// Byte output deliberately does not assert that unescaped input is valid UTF-8.
/// Caller scratch is retained, including its exact prefix on malformed input.
pub fn scan<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    scratch: &'a mut Vec<u8>,
) -> Result<Output<'a>, Error> {
    assert!(*cursor <= input.len(), "valid native cursor premise");
    loop {
        let start = *cursor;
        while let Some(&b) = input.get(*cursor) {
            if b == b'"' || b == b'\\' || b < 0x20 {
                break;
            }
            *cursor += 1;
        }
        let Some(&special) = input.get(*cursor) else {
            return Err(error(4));
        };
        if special == b'"' {
            let end = *cursor;
            *cursor += 1;
            if scratch.is_empty() {
                return Ok(Output::Borrowed(&input[start..end]));
            }
            scratch.extend_from_slice(&input[start..end]);
            return Ok(Output::Scratch(scratch));
        }
        if special != b'\\' {
            *cursor += 1;
            return Err(error(16));
        }
        scratch.extend_from_slice(&input[start..*cursor]);
        *cursor += 1;
        let Some(&escaped) = input.get(*cursor) else {
            return Err(error(4));
        };
        *cursor += 1;
        let decoded = match escaped {
            b'"' => b'"',
            b'\\' => b'\\',
            b'/' => b'/',
            b'b' => 8,
            b'f' => 12,
            b'n' => 10,
            b'r' => 13,
            b't' => 9,
            b'u' => {
                unicode(input, cursor, scratch)?;
                continue;
            }
            _ => return Err(error(12)),
        };
        scratch.push(decoded);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn borrowed_and_existing_scratch_lifetimes() {
        let bytes = b"abc\"rest";
        let mut p = 0;
        let mut scratch = Vec::new();
        let out = scan(bytes, &mut p, &mut scratch).unwrap();
        assert!(matches!(out,Output::Borrowed(s) if s.as_ptr()==bytes.as_ptr() && s==b"abc"));
        assert_eq!(p, 4);
        let mut p = 0;
        let mut scratch = b"seed".to_vec();
        assert_eq!(
            scan(bytes, &mut p, &mut scratch),
            Ok(Output::Scratch(b"seedabc"))
        );
    }
    #[test]
    fn ordinary_escapes_and_raw_high_bytes() {
        let mut p = 0;
        let mut scratch = Vec::new();
        assert_eq!(
            scan(br#"a\"\\\/\b\f\n\r\tZ"tail"#, &mut p, &mut scratch),
            Ok(Output::Scratch(b"a\"\\/\x08\x0c\n\r\tZ"))
        );
        let bytes = [0xff, 0xc0, b'"'];
        let mut p = 0;
        let mut scratch = vec![];
        assert_eq!(
            scan(&bytes, &mut p, &mut scratch),
            Ok(Output::Borrowed(&bytes[..2]))
        );
    }
    #[test]
    fn all_unicode_scalars_against_standard_encoder() {
        let mut count = 0;
        for cp in 0..=0x10ffff {
            let Some(ch) = char::from_u32(cp) else {
                continue;
            };
            let mut native = if cp < 0x10000 {
                format!("{cp:04x}").into_bytes()
            } else {
                let n = cp - 0x10000;
                format!("{:04x}\\u{:04x}", 0xd800 + (n >> 10), 0xdc00 + (n & 1023)).into_bytes()
            };
            let mut p = 0;
            let mut out = vec![];
            unicode(&native, &mut p, &mut out).unwrap();
            let mut expected = [0; 4];
            assert_eq!(out, ch.encode_utf8(&mut expected).as_bytes());
            assert_eq!(p, native.len());
            native.clear();
            count += 1;
        }
        assert_eq!(count, 1_112_064);
    }
    #[test]
    fn malformed_cursor_and_partial_scratch() {
        for (input, code, cursor, scratch) in [
            (&b"abc"[..], 4, 3, &b""[..]),
            (&b"ab\x01tail"[..], 16, 3, &b""[..]),
            (&b"ab\\xrest"[..], 12, 4, &b"ab"[..]),
            (&b"ab\\"[..], 4, 3, &b"ab"[..]),
            (&b"ab\\u12"[..], 4, 6, &b"ab"[..]),
            (&b"ab\\uX123tail"[..], 12, 8, &b"ab"[..]),
            (&b"ab\\uDC00tail"[..], 20, 8, &b"ab"[..]),
            (&b"ab\\uD800Qrest"[..], 23, 9, &b"ab"[..]),
            (&b"ab\\uD800\\Qrest"[..], 23, 10, &b"ab"[..]),
            (&b"ab\\uD800\\u0041rest"[..], 20, 14, &b"ab"[..]),
            (&b"ab\\uD800"[..], 4, 8, &b"ab"[..]),
            (&b"ab\\uD800\\"[..], 4, 9, &b"ab"[..]),
            (&b"a\\nbc"[..], 4, 5, &b"a\n"[..]),
        ] {
            let mut p = 0;
            let mut out = vec![];
            assert_eq!(scan(input, &mut p, &mut out), Err(error(code)), "{input:?}");
            assert_eq!(p, cursor, "{input:?}");
            assert_eq!(out, scratch, "{input:?}");
        }
    }
    #[test]
    fn every_byte_and_special_offset() {
        for offset in 0..=32 {
            for byte in 0..=255u8 {
                let mut bytes = vec![b'a'; offset];
                bytes.push(byte);
                bytes.push(b'"');
                let mut p = 0;
                let mut scratch = vec![];
                let result = scan(&bytes, &mut p, &mut scratch);
                match byte {
                    0..=31 => {
                        assert_eq!(result, Err(error(16)));
                        assert_eq!(p, offset + 1);
                    }
                    b'"' => {
                        assert_eq!(result, Ok(Output::Borrowed(&bytes[..offset])));
                        assert_eq!(p, offset + 1);
                    }
                    b'\\' => {
                        assert_eq!(result, Err(error(4)));
                        assert_eq!(p, offset + 2);
                        assert_eq!(scratch.len(), offset + 1);
                    }
                    _ => {
                        assert_eq!(result, Ok(Output::Borrowed(&bytes[..offset + 1])));
                        assert_eq!(p, offset + 2);
                    }
                }
            }
        }
    }
}
