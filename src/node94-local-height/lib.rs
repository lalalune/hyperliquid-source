//! Selected node #94 startup height decisions, recovered from static evidence.
//!
//! These are new Rust interfaces over raw words, not the original ABI. The
//! caller supplies the already-collected map values, with one pair per peer.
//! This module does not query peers, parse replies, or check state age.
#![no_std]
#![forbid(unsafe_code)]

/// The two unsigned words in each successful peer-map value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Heights {
    pub initial: u64,
    pub latest: u64,
}

/// Recover the selection at 0x226a53f..0x226a6b8.
///
/// One reply is sufficient only when exactly one peer was queried. Otherwise
/// at least two distinct map entries are needed. The selected pair is the
/// lexicographic maximum, not a pair of independently maximized fields.
pub fn select_heights(queried_peer_count: u64, values: &[Heights]) -> Option<Heights> {
    if values.is_empty() || (values.len() == 1 && queried_peer_count != 1) {
        return None;
    }
    let mut selected = values[0];
    for &candidate in &values[1..] {
        if candidate >= selected {
            selected = candidate;
        }
    }
    Some(selected)
}

/// Selected exits at 0x226ab0a..0x226ab88; not a complete startup outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeightDecision {
    Continue,
    TooFarBehind,
    StaleHardfork,
}

/// Classify the raw local height after the peer pair has been selected.
///
/// Equality at the saturated limit takes the first reason, including when
/// both local and latest are u64::MAX. The first reason has precedence.
pub fn classify(local: u64, peer: Heights) -> HeightDecision {
    if local.saturating_add(20_000) <= peer.latest {
        HeightDecision::TooFarBehind
    } else if local < peer.initial {
        HeightDecision::StaleHardfork
    } else {
        HeightDecision::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_pair_is_not_coordinatewise_maximum() {
        let values = [
            Heights {
                initial: 10,
                latest: 100_000,
            },
            Heights {
                initial: 11,
                latest: 12,
            },
        ];
        let selected = select_heights(2, &values).unwrap();
        assert_eq!(selected, values[1]);
        assert_eq!(classify(11, selected), HeightDecision::Continue);
    }

    #[test]
    fn single_peer_exception_and_empty_map() {
        let values = [Heights {
            initial: 1,
            latest: 2,
        }];
        assert_eq!(select_heights(1, &values), Some(values[0]));
        for count in [0, 2, u64::MAX] {
            assert_eq!(select_heights(count, &values), None);
        }
        assert_eq!(select_heights(1, &[]), None);
    }

    #[test]
    fn equality_saturation_and_reason_precedence() {
        assert_eq!(
            classify(
                100,
                Heights {
                    initial: 101,
                    latest: 20_100
                }
            ),
            HeightDecision::TooFarBehind
        );
        assert_eq!(
            classify(
                100,
                Heights {
                    initial: 101,
                    latest: 20_099
                }
            ),
            HeightDecision::StaleHardfork
        );
        assert_eq!(
            classify(
                100,
                Heights {
                    initial: 100,
                    latest: 20_099
                }
            ),
            HeightDecision::Continue
        );
        assert_eq!(
            classify(
                u64::MAX,
                Heights {
                    initial: 0,
                    latest: u64::MAX
                }
            ),
            HeightDecision::TooFarBehind
        );
        assert_eq!(
            classify(
                u64::MAX,
                Heights {
                    initial: 0,
                    latest: u64::MAX - 1
                }
            ),
            HeightDecision::Continue
        );
    }
}
