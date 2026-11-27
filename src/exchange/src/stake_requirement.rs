//! Binary-verified node #115 exchange stake-requirement engine (`l1/src/exchange/stake_requirement.rs`, `RE-010`).
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//!
//! Static FDE provenance:
//! - `0x235a050..0x235a26e`: 4-variant `StakeRequirement` collector (`stake_requirement.rs:5:62`)
//! - `0x294ceb0..0x294cfbe`: per-variant count + optional `+1` + chain table multiply (`0x602d1c`, overflow -> `0xc5`)
//! - `0x2c58c70..0x2c59351`: 4-arm `StakeRequirement` counter (jump table `0x60aeec`, `stake_requirement.rs:64:30`)
//! - `0x292deb0..0x292dfee`: arm 0 HIP-3 perp DEX deployer counter (stride `0x510`, `hip3_disabled_state` at `+0x468`)
//! - `0x2c59360..0x2c59471`: 183-day (`0xf14280` sec) disabled cooldown check
//! - `0x420e470..0x420e75d`: arm 3 active outcome deployer validator (`"not an outcome deployer"` / `"not an active outcome deployer"`)
//! - `0x2c59480..0x2c5995b`: `check_stake_requirement` gate (`0x118`, `0x119` cap `0x77359400`, `0xc5`, `0x11a`, `0x1a2`)

/// Chain index into the #115 `.rodata` stake-requirement table (`Exchange+0xb9a`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Chain {
    Local = 0,
    Sandbox = 1,
    Testnet = 2,
    Mainnet = 3,
}

/// Four-variant `StakeRequirement` enum matching jump table `0x60aeec` (`0x2c58c70`)
/// and chain-multiplier table `0x602d1c` (`0x294ceb0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StakeRequirement {
    /// Arm 0 (`0x2c58c9f` -> `0x292deb0`): HIP-3 perp DEX deployer (`0x457d00`: 500,000 HYPE on Mainnet).
    Hip3PerpDex = 0,
    /// Arm 1 (`0x2c58e0f`): spot quote token deployer (`0x457b00`: 200,000 HYPE on Mainnet).
    SpotQuoteToken = 1,
    /// Arm 2 (`0x2c58cee`): 20-byte user set membership at `Exchange+0x3968` (`0x457f00`: 500,000 HYPE on Mainnet).
    UserSetMembership = 2,
    /// Arm 3 (`0x2c58dcd` -> `0x420e470`): active outcome deployer (`0x457d00`: 500,000 HYPE on Mainnet).
    OutcomeDeployer = 3,
}

impl StakeRequirement {
    /// All four variants in exact #115 iteration order (`0..4`).
    pub const ALL: [Self; 4] = [
        Self::Hip3PerpDex,
        Self::SpotQuoteToken,
        Self::UserSetMembership,
        Self::OutcomeDeployer,
    ];
}

/// Exact #115 `.rodata` stake amounts (in `1e-8` HYPE wei) indexed by
/// `[StakeRequirement as usize][Chain as usize]` from offset table `0x602d1c`:
/// - `req[0]` (`0x457d00`): `[100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000]`
/// - `req[1]` (`0x457b00`): `[50_000, 20_000_000_000_000, 5_000_000_000, 20_000_000_000_000]`
/// - `req[2]` (`0x457f00`): `[200_000, 50_000_000_000_000, 10_000_000_000, 50_000_000_000_000]`
/// - `req[3]` (`0x457d00`): `[100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000]`
pub const STAKE_REQUIREMENT_TABLE: [[u64; 4]; 4] = [
    [100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000],
    [50_000, 20_000_000_000_000, 5_000_000_000, 20_000_000_000_000],
    [200_000, 50_000_000_000_000, 10_000_000_000, 50_000_000_000_000],
    [100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000],
];

/// Disabled cooldown duration in seconds (`movl $0xf14280, %edx` in `0x2c59392` and `0x2c591a6`):
/// `15_811_200` seconds = `183 * 86_400` seconds (183 days).
pub const STAKE_COOLDOWN_SECONDS: u64 = 0x00f1_4280;

/// Pre-deploy aggregate account value cap (`cmpq $0x77359400, %rax` at `0x2c5965d`):
/// `2_000_000_000` ($2,000 in 1e6 USD units).
pub const PRE_DEPLOY_ACCOUNT_CAP: u64 = 0x7735_9400;

/// Status tags emitted by `0x294ceb0` and `0x2c59480`.
pub const TAG_OK: u16 = 0x1a2;
pub const TAG_STAKE_MULTIPLY_OVERFLOW: u16 = 0xc5;
pub const TAG_DISALLOWED_ACCOUNT: u16 = 0x118;
pub const TAG_ACCOUNT_CAP_EXCEEDED: u16 = 0x119;
pub const TAG_INSUFFICIENT_STAKE: u16 = 0x11a;

/// HIP-3 disabled-state tag observed at `PerpDex+0x468` in `0x292deb0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Hip3StakeStateTag {
    Active0 = 0,
    DisabledPendingCooldown = 1,
    Active2 = 2,
    Disabled = 3,
}

/// Perp DEX summary entry evaluated by arm 0 (`0x292deb0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hip3DexStakeEntry {
    pub is_hip3: bool,
    pub deployer: [u8; 20],
    pub state_tag: Hip3StakeStateTag,
    /// Disabled timestamp in whole seconds (used when `state_tag == DisabledPendingCooldown`).
    pub disabled_at_secs: Option<u64>,
}

/// Spot quote token summary entry evaluated by arm 1 (`0x2c58e0f..0x2c592a2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpotQuoteTokenStakeEntry {
    /// Flag in `Exchange+0x378` map: `false` counts as active immediately.
    pub is_disabled: bool,
    /// Optional disabled timestamp in `Exchange+0x358` map (in whole seconds).
    pub disabled_at_secs: Option<u64>,
}

/// User state snapshot evaluated by `0x2c58c70` and `0x2c59480`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserStakeSnapshot {
    pub user: [u8; 20],
    pub now_secs: u64,
    /// Flag at `user_states[user] + 0x14` (`0x2c59569`): if `true`, new deploys fail with `0x118`.
    pub account_disallowed_for_deploy: bool,
    /// Main account + sub-account values summed saturating in `0x2c595c8..0x2c5965d` (cap `0x77359400`).
    pub account_and_sub_account_values: Vec<u64>,
    pub perp_dexs: Vec<Hip3DexStakeEntry>,
    pub spot_quote_tokens: Vec<SpotQuoteTokenStakeEntry>,
    pub in_special_user_set: bool,
    pub is_active_outcome_deployer: bool,
    /// Active stake from `c_staking` (`Exchange+0xd88`, `0x64e7b50`).
    pub active_stake: Option<u64>,
}

/// Outcome of `check_stake_requirement` (`0x2c59480`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StakeCheckOutcome {
    Ok {
        tag: u16,
        total_required: u64,
    },
    Rejected {
        tag: u16,
        total_required: Option<u64>,
    },
}

/// Return the exact #115 stake amount per unit for `(req, chain)`.
pub const fn stake_unit_amount(req: StakeRequirement, chain: Chain) -> u64 {
    STAKE_REQUIREMENT_TABLE[req as usize][chain as usize]
}

/// Arm 0 (`0x292deb0` + `0x2c59360`): count active HIP-3 perp DEXs requiring stake for `user`.
pub fn count_hip3_perp_dex_units(
    user: [u8; 20],
    now_secs: u64,
    is_override: bool,
    dexs: &[Hip3DexStakeEntry],
) -> u64 {
    let mut count = 0u64;
    for dex in dexs {
        if !dex.is_hip3 || dex.deployer != user {
            continue;
        }
        let contributes = match dex.state_tag {
            Hip3StakeStateTag::Disabled => false,
            Hip3StakeStateTag::DisabledPendingCooldown => {
                if is_override {
                    false
                } else {
                    match dex.disabled_at_secs {
                        // `0x2c59360`: returns true iff `now > disabled_at + 183d`; `xorb $1` inverts.
                        Some(ts) => now_secs <= ts.saturating_add(STAKE_COOLDOWN_SECONDS),
                        None => true,
                    }
                }
            }
            Hip3StakeStateTag::Active0 | Hip3StakeStateTag::Active2 => true,
        };
        if contributes {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Arm 1 (`0x2c58e0f..0x2c592a2`): count active spot quote tokens requiring stake.
pub fn count_spot_quote_token_units(now_secs: u64, tokens: &[SpotQuoteTokenStakeEntry]) -> u64 {
    let mut count = 0u64;
    for tok in tokens {
        let contributes = if !tok.is_disabled {
            true
        } else {
            match tok.disabled_at_secs {
                // `0x2c59280..0x2c5929b`: `setle`/`setbe` contributes 1 iff `now <= disabled_at + 183d`.
                Some(ts) => now_secs <= ts.saturating_add(STAKE_COOLDOWN_SECONDS),
                None => true,
            }
        };
        if contributes {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Count stake units for a single `StakeRequirement` variant (`0x2c58c70`).
pub fn count_requirement_units(
    req: StakeRequirement,
    snapshot: &UserStakeSnapshot,
    is_override: bool,
) -> u64 {
    match req {
        StakeRequirement::Hip3PerpDex => count_hip3_perp_dex_units(
            snapshot.user,
            snapshot.now_secs,
            is_override,
            &snapshot.perp_dexs,
        ),
        StakeRequirement::SpotQuoteToken => {
            count_spot_quote_token_units(snapshot.now_secs, &snapshot.spot_quote_tokens)
        }
        StakeRequirement::UserSetMembership => u64::from(snapshot.in_special_user_set),
        StakeRequirement::OutcomeDeployer => u64::from(snapshot.is_active_outcome_deployer),
    }
}

/// Compute total required stake across all 4 variants (`0x235a050` + `0x294ceb0` + caller sum).
///
/// Returns `Err(TAG_STAKE_MULTIPLY_OVERFLOW)` (`0xc5`) if any per-variant multiplication
/// overflows `u64`, matching `jo 0x294cf8c` in `0x294ceb0`.
pub fn compute_total_required_stake(
    chain: Chain,
    snapshot: &UserStakeSnapshot,
    additional: Option<StakeRequirement>,
    is_override: bool,
) -> Result<u64, u16> {
    let mut total = 0u64;
    for req in StakeRequirement::ALL {
        let base_count = count_requirement_units(req, snapshot, is_override);
        let eff_count = if additional == Some(req) {
            base_count.saturating_add(1)
        } else {
            base_count
        };
        let unit = stake_unit_amount(req, chain);
        let req_stake = eff_count
            .checked_mul(unit)
            .ok_or(TAG_STAKE_MULTIPLY_OVERFLOW)?;
        total = total.saturating_add(req_stake);
    }
    Ok(total)
}

/// Reconstructs `Exchange::check_stake_requirement` (`0x2c59480`).
pub fn check_stake_requirement(
    chain: Chain,
    snapshot: &UserStakeSnapshot,
    additional: Option<StakeRequirement>,
) -> StakeCheckOutcome {
    // When `additional` is `Some(_)`, `0x2c5949d..0x2c5967b` enforces the pre-deploy account gates.
    if additional.is_some() {
        if snapshot.account_disallowed_for_deploy {
            return StakeCheckOutcome::Rejected {
                tag: TAG_DISALLOWED_ACCOUNT,
                total_required: None,
            };
        }
        let mut agg = 0u64;
        for &v in &snapshot.account_and_sub_account_values {
            agg = agg.saturating_add(v);
        }
        if agg > PRE_DEPLOY_ACCOUNT_CAP {
            return StakeCheckOutcome::Rejected {
                tag: TAG_ACCOUNT_CAP_EXCEEDED,
                total_required: None,
            };
        }
    }

    let total_required = match compute_total_required_stake(chain, snapshot, additional, false) {
        Ok(v) => v,
        Err(tag) => {
            return StakeCheckOutcome::Rejected {
                tag,
                total_required: None,
            };
        }
    };

    match snapshot.active_stake {
        Some(stake) if stake >= total_required => StakeCheckOutcome::Ok {
            tag: TAG_OK,
            total_required,
        },
        _ => StakeCheckOutcome::Rejected {
            tag: TAG_INSUFFICIENT_STAKE,
            total_required: Some(total_required),
        },
    }
}
