#![no_std]

//! Static texts for fifteen staking-related arms of the node #115 action-error
//! display table at `0x46ef710`. This is not the formatter ABI, the float
//! printer, stake accounting, or an integrated node.

/// IEEE-754 binary64 bits of the value embedded by discriminant 159.
/// The bits are exactly 300.0. The native printer that consumes them is not
/// reproduced here, so this crate does not claim the rendered decimal spelling.
pub const MANUAL_UNJAIL_INTERVAL_BITS: u64 = 0x4072_c000_0000_0000;

pub const MANUAL_UNJAIL_DISCRIMINANT: u16 = 159;
pub const JAILED_UNTIL_DISCRIMINANT: u16 = 160;

/// Length-prefixed literals and one `0xc0` argument marker from the native template.
pub const MANUAL_UNJAIL_TEMPLATE: &[u8] = &[
    0x24, b'C', b'a', b'n', b' ', b'o', b'n', b'l', b'y', b' ', b'm', b'a', b'n', b'u', b'a',
    b'l', b'l', b'y', b' ', b'u', b'n', b'j', b'a', b'i', b'l', b' ', b'o', b'n', b'c', b'e',
    b' ', b'e', b'v', b'e', b'r', b'y', b' ', 0xc0, 0x08, b' ', b's', b'e', b'c', b'o', b'n',
    b'd', b's', 0x00,
];

pub const JAILED_UNTIL_TEMPLATE: &[u8] = &[
    0x0d, b'J', b'a', b'i', b'l', b'e', b'd', b' ', b'u', b'n', b't', b'i', b'l', b' ', 0xc0, 0x00,
];

pub const MANUAL_UNJAIL_LITERALS: &[&str] = &[
    "Can only manually unjail once every ",
    " seconds",
];

pub const JAILED_UNTIL_LITERALS: &[&str] = &["Jailed until "];

pub struct StaticArm {
    pub discriminant: u16,
    pub text: &'static str,
}

/// Static `write` arms whose decoded text matches the staking selection.
/// Discriminants are the `u16` values consumed by the display jump table.
pub static STATIC_ARMS: &[StaticArm] = &[
    StaticArm { discriminant: 51, text: "Delegate amount cannot be zero." },
    StaticArm { discriminant: 184, text: "Insufficient delegatable balance for priority order" },
    StaticArm { discriminant: 267, text: "Insufficient balance to delegate" },
    StaticArm { discriminant: 268, text: "Validator has delegations disabled" },
    StaticArm { discriminant: 269, text: "Insufficient balance to undelegate" },
    StaticArm {
        discriminant: 270,
        text: "Cannot undelegate during lockup period after delegating or voting.",
    },
    StaticArm { discriminant: 273, text: "Insufficient delegations to propose" },
    StaticArm { discriminant: 278, text: "Insufficient delegations to vote" },
    StaticArm { discriminant: 282, text: "Insufficient stake" },
    StaticArm {
        discriminant: 306,
        text: "Validator commission must be between 0 and 100%. If commission increases, it cannot exceed 1%.",
    },
    StaticArm { discriminant: 324, text: "Cannot unregister validator with delegations" },
    StaticArm { discriminant: 325, text: "Self delegation insufficient" },
    StaticArm { discriminant: 358, text: "Invalid staker" },
];

pub fn manual_unjail_interval_seconds() -> f64 {
    f64::from_bits(MANUAL_UNJAIL_INTERVAL_BITS)
}

pub fn static_text(discriminant: u16) -> Option<&'static str> {
    STATIC_ARMS.iter().find(|arm| arm.discriminant == discriminant).map(|arm| arm.text)
}

pub fn is_selected_arm(discriminant: u16) -> bool {
    discriminant == MANUAL_UNJAIL_DISCRIMINANT
        || discriminant == JAILED_UNTIL_DISCRIMINANT
        || static_text(discriminant).is_some()
}
