//! Admission rule of the node #94 gossipPriorityBid wrapper, not its original ABI.
#![no_std]
#![forbid(unsafe_code)]

/// Numbers at or above this value are refused, inclusive of the value itself.
pub const VALUE_BOUND: u64 = 0x0ccc_cccc_cccc_cccc;
/// The longest admitted `ip` text; one more byte is refused before parsing.
pub const MAX_IP_BYTES: usize = 15;

/// Decoded action fields. `ip` is a borrow where the target owns a `String`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bid<'a> {
    pub slot_id: u64,
    pub ip: &'a str,
    pub max_gas: Option<u64>,
}

/// The wrapper's own refusals. Handler statuses pass through it untouched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// `reported` is the slot id for a slot refusal and the constant 1 for a gas refusal.
    InvalidNumber {
        reported: u64,
    },
    InvalidLength,
    FailedToParseIp,
}

impl Refusal {
    /// The target's status tag.
    pub const fn status(self) -> u16 {
        match self {
            Self::InvalidNumber { .. } => 0x13f,
            Self::InvalidLength => 0x143,
            Self::FailedToParseIp => 0xb9,
        }
    }
}

/// Handler arguments after admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admitted {
    pub slot_id: u64,
    /// `a<<8 | b<<16 | c<<24 | d<<32`; the low byte is always zero.
    pub ip_word: u64,
    pub max_gas: Option<u64>,
}

/// Apply the gates in target order: slot, gas, text length, full text parse.
pub fn admit(bid: &Bid<'_>) -> Result<Admitted, Refusal> {
    if bid.slot_id >= VALUE_BOUND {
        return Err(Refusal::InvalidNumber {
            reported: bid.slot_id,
        });
    }
    if matches!(bid.max_gas, Some(gas) if gas >= VALUE_BOUND) {
        return Err(Refusal::InvalidNumber { reported: 1 });
    }
    if bid.ip.len() > MAX_IP_BYTES {
        return Err(Refusal::InvalidLength);
    }
    let ip_word = parse_ipv4(bid.ip.as_bytes()).ok_or(Refusal::FailedToParseIp)?;
    Ok(Admitted {
        slot_id: bid.slot_id,
        ip_word,
        max_gas: bid.max_gas,
    })
}

/// Four dotted octets, each one to three digits below 256, without a leading zero.
fn parse_ipv4(text: &[u8]) -> Option<u64> {
    let mut word = 0;
    let mut rest = text;
    for index in 0..4 {
        if index > 0 {
            rest = rest.strip_prefix(b".")?;
        }
        let size = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if !(1..=3).contains(&size) || (size > 1 && rest[0] == b'0') {
            return None;
        }
        let octet = rest[..size]
            .iter()
            .fold(0, |value, byte| value * 10 + u64::from(byte - b'0'));
        if octet > 255 {
            return None;
        }
        word |= octet << (8 * index + 8);
        rest = &rest[size..];
    }
    rest.is_empty().then_some(word)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    const VECTORS: &str =
        include_str!("../../research/work-items/RE-010-gossip-priority-bid-path-94/vectors.tsv");

    fn number(text: &str) -> u64 {
        u64::from_str_radix(text.trim_start_matches("0x"), 16).unwrap()
    }

    /// The vectors come from the target's arm and wrapper instructions.
    #[test]
    fn matches_every_target_vector() {
        let mut checked = 0;
        for line in VECTORS.lines().skip(1) {
            let row: Vec<&str> = line.split('\t').collect();
            let max_gas = (row[1] != "-").then(|| number(row[1]));
            let bid = Bid {
                slot_id: number(row[0]),
                ip: row[2].trim_matches('"'),
                max_gas,
            };
            let got = admit(&bid);
            match row[7] {
                "handler" => {
                    let admitted = got.unwrap();
                    assert_eq!(admitted.slot_id, bid.slot_id);
                    assert_eq!(admitted.ip_word, number(row[8]));
                    assert_eq!(admitted.max_gas.is_some(), row[9] == "1");
                    if let Some(gas) = admitted.max_gas {
                        assert_eq!(gas, number(row[10]));
                    }
                }
                _ => {
                    let refusal = got.unwrap_err();
                    assert_eq!(u64::from(refusal.status()), number(row[5]));
                    if let Refusal::InvalidNumber { reported } = refusal {
                        assert_eq!(reported, number(row[6]));
                    }
                }
            }
            checked += 1;
        }
        assert_eq!(checked, 1568);
    }

    #[test]
    fn slot_refusal_wins_over_gas_refusal() {
        let bid = Bid {
            slot_id: VALUE_BOUND,
            ip: "1.2.3.4",
            max_gas: Some(u64::MAX),
        };
        assert_eq!(
            admit(&bid),
            Err(Refusal::InvalidNumber {
                reported: VALUE_BOUND
            })
        );
    }

    #[test]
    fn length_gate_runs_before_parsing() {
        let bid = Bid {
            slot_id: 0,
            ip: "1.2.3.4         ",
            max_gas: None,
        };
        assert_eq!(admit(&bid), Err(Refusal::InvalidLength));
    }
}
