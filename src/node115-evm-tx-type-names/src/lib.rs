//! Exact name/tag mapping for node #115 EVM transaction-type visitors.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Node115EvmTransactionType {
    Legacy = 0,
    Eip2930 = 1,
    Eip1559 = 2,
    Eip4844 = 3,
    Eip7702 = 4,
}

pub const VARIANTS: [&str; 5] = ["Legacy", "Eip2930", "Eip1559", "Eip4844", "Eip7702"];

impl Node115EvmTransactionType {
    /// Match the complete byte sequence and return its declaration-order tag.
    pub fn from_bytes(input: &[u8]) -> Option<Self> {
        match input {
            b"Legacy" => Some(Self::Legacy),
            b"Eip2930" => Some(Self::Eip2930),
            b"Eip1559" => Some(Self::Eip1559),
            b"Eip4844" => Some(Self::Eip4844),
            b"Eip7702" => Some(Self::Eip7702),
            _ => None,
        }
    }

    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        VARIANTS[self.tag() as usize]
    }

    pub const fn tagged_word(self) -> u16 {
        0x09 | ((self.tag() as u16) << 8)
    }
}

#[cfg(test)]
mod tests {
    use super::Node115EvmTransactionType;
    use std::collections::BTreeMap;

    const CASES: &str =
        include_str!("../../../research/work-items/evm-tx-type-name-codec-115/visitor-cases.tsv");
    const FUNCTIONS: &str =
        include_str!("../../../research/work-items/evm-tx-type-name-codec-115/functions.tsv");

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
    fn matches_saved_visitor_acceptance_and_success_values() {
        let header = columns(CASES.lines().next().unwrap());
        let roles: BTreeMap<_, _> = FUNCTIONS
            .lines()
            .skip(1)
            .map(|line| {
                let row = columns(line);
                (row[1], row[0])
            })
            .collect();
        let mut checked = 0;
        for line in CASES.lines().skip(1) {
            let row = columns(line);
            let input = if row[0] == "-" {
                Vec::new()
            } else {
                decode_hex(row[0])
            };
            let parsed = Node115EvmTransactionType::from_bytes(&input);
            assert_eq!(
                parsed.map(Node115EvmTransactionType::name).unwrap_or("-"),
                row[10],
                "input {}",
                row[0]
            );

            for column in 2..10 {
                let expected = row[column];
                if let Some(kind) = parsed {
                    let result = if roles[header[column]].contains("_result") {
                        format!("ok:0x{:x}", kind.tag())
                    } else {
                        format!("ok:0x{:x}", kind.tagged_word())
                    };
                    assert_eq!(expected, result, "body {} input {}", header[column], row[0]);
                } else {
                    assert!(expected.starts_with("err"));
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 16_184);
    }

    #[test]
    fn exact_names_and_declaration_order_are_stable() {
        for (tag, name) in super::VARIANTS.iter().enumerate() {
            let kind = Node115EvmTransactionType::from_bytes(name.as_bytes()).unwrap();
            assert_eq!(kind.tag(), tag as u8);
        }
        assert_eq!(Node115EvmTransactionType::from_bytes(b"legacy"), None);
        assert_eq!(Node115EvmTransactionType::from_bytes(b"Eip1559x"), None);
    }
}
