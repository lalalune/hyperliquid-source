//! Exact name and success-result model for the node #115 bridge event visitors.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Node115BridgeEvent {
    Deposit = 0,
    InvalidatedWithdrawal = 1,
    RequestedWithdrawal = 2,
    FinalizedWithdrawal = 3,
    FinalizedValidatorSetUpdate = 4,
    RequestedValidatorSetUpdateEvent = 5,
}

pub const VARIANTS: [&str; 6] = [
    "Deposit",
    "InvalidatedWithdrawal",
    "RequestedWithdrawal",
    "FinalizedWithdrawal",
    "FinalizedValidatorSetUpdate",
    "RequestedValidatorSetUpdateEvent",
];

impl Node115BridgeEvent {
    /// Match the full byte string exactly and return its declaration-order tag.
    pub fn from_bytes(input: &[u8]) -> Option<Self> {
        match input {
            b"Deposit" => Some(Self::Deposit),
            b"InvalidatedWithdrawal" => Some(Self::InvalidatedWithdrawal),
            b"RequestedWithdrawal" => Some(Self::RequestedWithdrawal),
            b"FinalizedWithdrawal" => Some(Self::FinalizedWithdrawal),
            b"FinalizedValidatorSetUpdate" => Some(Self::FinalizedValidatorSetUpdate),
            b"RequestedValidatorSetUpdateEvent" => Some(Self::RequestedValidatorSetUpdateEvent),
            _ => None,
        }
    }

    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        VARIANTS[self.tag() as usize]
    }

    /// Success word written by the tagged-word visitor copies.
    pub const fn tagged_word(self) -> u16 {
        0x09 | ((self.tag() as u16) << 8)
    }
}

#[cfg(test)]
mod tests {
    use super::Node115BridgeEvent;

    const CASES: &str =
        include_str!("../../../research/work-items/bridge-event-name-codec-115/visitor-cases.tsv");
    const FUNCTIONS: &str =
        include_str!("../../../research/work-items/bridge-event-name-codec-115/functions.tsv");

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
    fn matches_all_saved_visitor_outcomes() {
        let header = columns(CASES.lines().next().unwrap());
        let roles: std::collections::BTreeMap<_, _> = FUNCTIONS
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
            let parsed = Node115BridgeEvent::from_bytes(&input);
            assert_eq!(
                parsed.map(Node115BridgeEvent::name).unwrap_or("-"),
                row[12],
                "input {}",
                row[0]
            );

            for column in 2..12 {
                let expected = row[column];
                if let Some(event) = parsed {
                    let result = if roles[header[column]].contains("_tagged") {
                        format!("ok:0x{:x}", event.tagged_word())
                    } else {
                        format!("ok:0x{:x}", event.tag())
                    };
                    assert_eq!(expected, result, "body {} input {}", header[column], row[0]);
                } else {
                    assert!(
                        expected.starts_with("err"),
                        "body {} input {}: expected error, got {expected}",
                        header[column],
                        row[0]
                    );
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 49_360);
    }

    #[test]
    fn declaration_order_and_exact_matching_are_stable() {
        let names = [
            b"Deposit".as_slice(),
            b"InvalidatedWithdrawal".as_slice(),
            b"RequestedWithdrawal".as_slice(),
            b"FinalizedWithdrawal".as_slice(),
            b"FinalizedValidatorSetUpdate".as_slice(),
            b"RequestedValidatorSetUpdateEvent".as_slice(),
        ];
        for (tag, name) in names.into_iter().enumerate() {
            assert_eq!(
                Node115BridgeEvent::from_bytes(name).unwrap().tag(),
                tag as u8
            );
        }
        assert_eq!(Node115BridgeEvent::from_bytes(b"deposit"), None);
        assert_eq!(Node115BridgeEvent::from_bytes(b"Depositx"), None);
    }
}
