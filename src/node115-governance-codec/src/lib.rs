//! Node #115 governance enum MessagePack codecs, from the RE-005 codec packet.

pub const TARGET_SHA256: &str = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VoteChoice {
    Yes = 0,
    No = 1,
    Abstain = 2,
}

impl VoteChoice {
    pub const fn from_tag(tag: u8) -> Self {
        match tag {
            0 => Self::Yes,
            1 => Self::No,
            _ => Self::Abstain,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Abstain => "abstain",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProposalCategory {
    Accelerated = 0,
    Constitutional = 1,
    Ecosystem = 2,
    Electoral = 3,
}

impl ProposalCategory {
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Accelerated),
            1 => Some(Self::Constitutional),
            2 => Some(Self::Ecosystem),
            3 => Some(Self::Electoral),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Accelerated => "accelerated",
            Self::Constitutional => "constitutional",
            Self::Ecosystem => "ecosystem",
            Self::Electoral => "electoral",
        }
    }
}

/// Encode the total vote serializer: every tag other than 0 and 1 selects abstain.
pub fn encode_vote(tag: u8) -> Vec<u8> {
    encode_name(VoteChoice::from_tag(tag).name())
}

/// Encode only the defined category jump-table arms (tags 0 through 3).
/// The captured target has no checked fallback for other tags, so they are not
/// assigned a reconstructed wire result here.
pub fn encode_category(tag: u8) -> Option<Vec<u8>> {
    ProposalCategory::from_tag(tag).map(|category| encode_name(category.name()))
}

/// Decode exact visitor names after the target's lossy UTF-8 conversion.
pub fn visit_vote(bytes: &[u8]) -> Option<VoteChoice> {
    match String::from_utf8_lossy(bytes).as_ref() {
        "yes" => Some(VoteChoice::Yes),
        "no" => Some(VoteChoice::No),
        "abstain" => Some(VoteChoice::Abstain),
        _ => None,
    }
}

/// Decode an exact category name after the target's lossy UTF-8 conversion.
pub fn visit_category(bytes: &[u8]) -> Option<ProposalCategory> {
    match String::from_utf8_lossy(bytes).as_ref() {
        "accelerated" => Some(ProposalCategory::Accelerated),
        "constitutional" => Some(ProposalCategory::Constitutional),
        "ecosystem" => Some(ProposalCategory::Ecosystem),
        "electoral" => Some(ProposalCategory::Electoral),
        _ => None,
    }
}

fn encode_name(name: &str) -> Vec<u8> {
    let bytes = name.as_bytes();
    debug_assert!(bytes.len() <= 31);
    let mut result = Vec::with_capacity(bytes.len() + 1);
    result.push(0xa0 | bytes.len() as u8); // MessagePack fixstr
    result.extend_from_slice(bytes);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERIALIZERS: &str = include_str!(
        "../../../research/work-items/action-wire-gov-vote-codec-115/serializer-cases.tsv"
    );
    const VISITORS: &str = include_str!(
        "../../../research/work-items/action-wire-gov-vote-codec-115/visitor-cases.tsv"
    );

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => panic!("invalid hex"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    fn expected_tag(cell: &str) -> Option<u8> {
        cell.strip_prefix("ok:0x").map(|value| {
            let result = u16::from_str_radix(value, 16).unwrap();
            if result == 0x9 || result >= 0x100 {
                (result >> 8) as u8
            } else {
                result as u8
            }
        })
    }

    #[test]
    fn serializers_match_all_saved_target_cases() {
        let mut checked = 0;
        for line in SERIALIZERS.lines().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            let tag: u8 = fields[2].parse().unwrap();
            let actual = match fields[1] {
                "vote" => Some(encode_vote(tag)),
                "category" => encode_category(tag),
                other => panic!("unknown codec {other}"),
            };
            assert_eq!(
                actual.unwrap(),
                decode_hex(fields[5]),
                "serializer case {checked}"
            );
            checked += 1;
        }
        assert_eq!(checked, 2_188);
    }

    #[test]
    fn all_eighteen_visitors_match_saved_target_cases() {
        let mut rows = 0;
        for line in VISITORS.lines().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            let input = if fields[0] == "-" {
                Vec::new()
            } else {
                decode_hex(fields[0])
            };
            for (visitor, cell) in fields[2..20].iter().enumerate() {
                let expected = expected_tag(cell);
                let actual = if visitor < 8 {
                    visit_vote(&input).map(|value| value as u8)
                } else {
                    visit_category(&input).map(|value| value as u8)
                };
                assert_eq!(actual, expected, "visitor cell {rows}:{visitor}");
            }
            rows += 1;
        }
        assert_eq!(rows, 3_252);
    }

    #[test]
    fn vote_dispatch_is_total_but_category_jump_table_is_bounded() {
        assert_eq!(VoteChoice::from_tag(255), VoteChoice::Abstain);
        assert_eq!(
            encode_vote(255),
            vec![0xa7, b'a', b'b', b's', b't', b'a', b'i', b'n']
        );
        assert!(encode_category(4).is_none());
        assert_eq!(visit_vote(b"Yes"), None);
        assert_eq!(visit_category(b"ecosystem "), None);
        assert_eq!(visit_vote(&[b'y', b'e', 0xff]), None);
    }
}
