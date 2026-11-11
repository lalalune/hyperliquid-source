//! Exact byte-name model for one node #115 seven-variant unit enum.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Node115AbstractionKind {
    Perp = 0,
    Spot = 1,
    Token = 2,
    Pdi = 3,
    ActivateDexAbstraction = 4,
    ActivateUnifiedAccount = 5,
    AllBoleTokens = 6,
}

pub const VARIANTS: [&str; 7] = [
    "Perp",
    "Spot",
    "Token",
    "Pdi",
    "ActivateDexAbstraction",
    "ActivateUnifiedAccount",
    "AllBoleTokens",
];

impl Node115AbstractionKind {
    /// Match a name byte-for-byte and return its declaration-order variant.
    pub fn from_bytes(input: &[u8]) -> Option<Self> {
        match input {
            b"Perp" => Some(Self::Perp),
            b"Spot" => Some(Self::Spot),
            b"Token" => Some(Self::Token),
            b"Pdi" => Some(Self::Pdi),
            b"ActivateDexAbstraction" => Some(Self::ActivateDexAbstraction),
            b"ActivateUnifiedAccount" => Some(Self::ActivateUnifiedAccount),
            b"AllBoleTokens" => Some(Self::AllBoleTokens),
            _ => None,
        }
    }

    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        VARIANTS[self.tag() as usize]
    }

    /// Output word used by the three observed tagged-word visitor copies.
    pub const fn tagged_word(self) -> u16 {
        0x09 | ((self.tag() as u16) << 8)
    }
}

#[cfg(test)]
mod tests {
    use super::Node115AbstractionKind;

    const CASES: &str = include_str!(
        "../../../research/work-items/RE-015-abstraction-kind-codec-115/visitor-cases.tsv"
    );

    fn columns(line: &str) -> Vec<&str> {
        line.split('\t').collect()
    }

    #[test]
    fn matches_all_saved_visitor_outcomes() {
        let mut checked = 0;
        for line in CASES.lines().skip(1) {
            let c = columns(line);
            let input = if c[0] == "-" {
                &[][..]
            } else {
                // Every packet input is lowercase hex, including malformed UTF-8.
                let bytes: Vec<u8> = c[0]
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        let digit = |b: u8| match b {
                            b'0'..=b'9' => b - b'0',
                            b'a'..=b'f' => b - b'a' + 10,
                            _ => panic!("invalid hex in committed evidence"),
                        };
                        digit(pair[0]) * 16 + digit(pair[1])
                    })
                    .collect();
                check_case(&c, &bytes);
                checked += 5;
                continue;
            };
            check_case(&c, input);
            checked += 5;
        }
        assert_eq!(checked, 37_640);
    }

    fn check_case(columns: &[&str], input: &[u8]) {
        let parsed = Node115AbstractionKind::from_bytes(input);
        assert_eq!(
            parsed.map(Node115AbstractionKind::name).unwrap_or("-"),
            columns[7],
            "input {}",
            columns[0]
        );

        for column in [2, 3, 4] {
            let actual = parsed.map(Node115AbstractionKind::tagged_word);
            assert_eq!(
                actual.is_some(),
                expected_outcome(columns[column]),
                "body column {column}"
            );
            if let Some(word) = actual {
                assert_eq!(columns[column], format!("ok:0x{word:x}"));
            }
        }
        for column in [5, 6] {
            let actual = parsed.map(Node115AbstractionKind::tag);
            assert_eq!(
                actual.is_some(),
                expected_outcome(columns[column]),
                "body column {column}"
            );
            if let Some(tag) = actual {
                assert_eq!(columns[column], format!("ok:0x{tag:x}"));
            }
        }
    }

    fn expected_outcome(value: &str) -> bool {
        value.starts_with("ok:")
    }

    #[test]
    fn declaration_order_and_exact_matching_are_stable() {
        let cases = [
            (b"Perp".as_slice(), 0),
            (b"Spot".as_slice(), 1),
            (b"Token".as_slice(), 2),
            (b"Pdi".as_slice(), 3),
            (b"ActivateDexAbstraction".as_slice(), 4),
            (b"ActivateUnifiedAccount".as_slice(), 5),
            (b"AllBoleTokens".as_slice(), 6),
        ];
        for (name, tag) in cases {
            assert_eq!(Node115AbstractionKind::from_bytes(name).unwrap().tag(), tag);
        }
        assert_eq!(Node115AbstractionKind::from_bytes(b"perp"), None);
        assert_eq!(Node115AbstractionKind::from_bytes(b"Perpx"), None);
    }
}
