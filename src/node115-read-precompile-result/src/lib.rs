//! Exact variant-name mapping for node #115's ReadPrecompileResult visitors.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReadPrecompileResultKind {
    Ok = 0,
    OutOfGas = 1,
    Error = 2,
    UnexpectedError = 3,
}

pub const VARIANTS: [&str; 4] = ["Ok", "OutOfGas", "Error", "UnexpectedError"];

impl ReadPrecompileResultKind {
    /// Match the complete name exactly and return its declaration-order variant.
    pub fn from_bytes(input: &[u8]) -> Option<Self> {
        match input {
            b"Ok" => Some(Self::Ok),
            b"OutOfGas" => Some(Self::OutOfGas),
            b"Error" => Some(Self::Error),
            b"UnexpectedError" => Some(Self::UnexpectedError),
            _ => None,
        }
    }

    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        VARIANTS[self.tag() as usize]
    }

    /// Success word stored by the two observed name visitors.
    pub const fn visitor_word(self) -> u16 {
        0x09 | ((self.tag() as u16) << 8)
    }
}

#[cfg(test)]
mod tests {
    use super::{ReadPrecompileResultKind, VARIANTS};

    const CASES: &str =
        include_str!("../../../research/work-items/evm-call-outcome-codec-115/visitor-cases.tsv");

    fn columns(line: &str) -> Vec<&str> {
        line.split('\t').collect()
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |b: u8| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => panic!("invalid hex in committed evidence"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn matches_all_saved_visitor_rows() {
        let mut checked = 0;
        for line in CASES.lines().skip(1) {
            let row = columns(line);
            let input = if row[0] == "-" {
                Vec::new()
            } else {
                decode_hex(row[0])
            };
            let parsed = ReadPrecompileResultKind::from_bytes(&input);

            for column in [2, 3] {
                if let Some(kind) = parsed {
                    assert_eq!(row[column], format!("ok:0x{:x}", kind.visitor_word()));
                } else {
                    assert!(row[column].starts_with("err"));
                }
                checked += 1;
            }
            let expected_name = parsed.map(ReadPrecompileResultKind::name).unwrap_or("-");
            assert_eq!(row[4], expected_name, "input {}", row[0]);
        }
        assert_eq!(checked, 3_584);
    }

    #[test]
    fn names_and_declaration_order_match_the_packet() {
        for (tag, name) in VARIANTS.iter().enumerate() {
            let kind = ReadPrecompileResultKind::from_bytes(name.as_bytes()).unwrap();
            assert_eq!(kind.tag(), tag as u8);
            assert_eq!(kind.name(), *name);
        }
        assert_eq!(ReadPrecompileResultKind::from_bytes(b"ok"), None);
        assert_eq!(ReadPrecompileResultKind::from_bytes(b"Ok!"), None);
    }
}
