//! Numeric result projection of the three node94 threshold pointer leaves.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    Plain64,
    Gated36,
    Gated196,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}

/// Supplied byte snapshots at load_bias+0x599bb46 and +0x599fbd0.
/// None marks an unavailable read; unused bytes need not be supplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags {
    pub first: Option<u8>,
    pub second: Option<u8>,
}

/// Project full RAX/RDX using unsigned full-width index comparisons.
///
/// Values are numeric addresses, never dereferenced. The gated entries read
/// first before second, even when the index is too large. Missing required
/// snapshots produce a new API refusal; they do not model a target return.
pub fn select(
    member: Member,
    index: u64,
    load_bias: u64,
    incoming_rdx: u64,
    flags: Flags,
) -> Option<Registers> {
    let (bound, address) = match member {
        Member::Plain64 => {
            return Some(Registers {
                rax: if index <= 63 {
                    load_bias.wrapping_add(0x576a6c0)
                } else {
                    0
                },
                rdx: 0,
            });
        }
        Member::Gated36 => (35, 0x576c3a0),
        Member::Gated196 => (195, 0x576c300),
    };
    if flags.first? == 0 {
        return Some(Registers {
            rax: 0,
            rdx: incoming_rdx,
        });
    }
    let second = flags.second?;
    Some(Registers {
        rax: if second == 1 && index <= bound {
            load_bias.wrapping_add(address)
        } else {
            0
        },
        rdx: load_bias.wrapping_add(0x599fbd0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unneeded_flags_are_absent() {
        let absent = Flags {
            first: None,
            second: None,
        };
        assert_eq!(
            select(Member::Plain64, 63, 0, 9, absent),
            Some(Registers {
                rax: 0x576a6c0,
                rdx: 0
            })
        );
        assert_eq!(
            select(
                Member::Gated36,
                0,
                0,
                9,
                Flags {
                    first: Some(0),
                    second: None
                }
            ),
            Some(Registers { rax: 0, rdx: 9 })
        );
    }
    #[test]
    fn flags_precede_index_rejection() {
        assert_eq!(
            select(
                Member::Gated36,
                u64::MAX,
                0,
                9,
                Flags {
                    first: Some(1),
                    second: None
                }
            ),
            None
        );
        assert_eq!(
            select(
                Member::Gated196,
                u64::MAX,
                0,
                9,
                Flags {
                    first: Some(1),
                    second: Some(0)
                }
            ),
            Some(Registers {
                rax: 0,
                rdx: 0x599fbd0
            })
        );
    }
    #[test]
    fn second_is_exactly_one_and_addresses_wrap() {
        assert_eq!(
            select(
                Member::Gated196,
                195,
                u64::MAX,
                0,
                Flags {
                    first: Some(255),
                    second: Some(1)
                }
            ),
            Some(Registers {
                rax: 0x576c2ff,
                rdx: 0x599fbcf
            })
        );
        assert_eq!(
            select(
                Member::Gated36,
                35,
                0,
                0,
                Flags {
                    first: Some(2),
                    second: Some(2)
                }
            ),
            Some(Registers {
                rax: 0,
                rdx: 0x599fbd0
            })
        );
    }
}
