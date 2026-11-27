//! Node #115 HyperEVM dual-block gas limits, embedded system contracts, and
//! `CoreWriter` (`0x3333...3333`) v1 `RawAction(address,bytes)` frame parser.
//!
//! Grounded statically in node #115 (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`):
//! - Dual-block gas limits (`0x433dd2b..0x433dd3d` & `0x2a1e377..0x2a1e38f`):
//!   `SMALL_BLOCK_GAS_LIMIT = 3_000_000` (`0x2dc6c0`), `BIG_BLOCK_GAS_LIMIT = 30_000_000` (`0x1c9c380`).
//! - Dual-block builder cadence/bucket-guard constants (`0x2c71ff8` & `0x2c72512`):
//!   `build_small_evm_block_and_apply_l1_effects` `(0.03, 0.07)` (`0x4554f0`),
//!   `build_big_evm_block_and_apply_l1_effects` `(0.05, 0.05)` (`0x453520`).
//! - 3 system contracts installed in `0x434bda0..0x434be01` (`0x64fd8f8`/`0x64fd918`/`0x64fd938`):
//!   `CoreWriter` (`0x33*20`, 544 B), `HypeSystem` (`0x22*20`, 122 B), `WHype` (`0x55*20`, 2,041 B).
//! - `CoreWriter` v1 `RawAction(address,bytes)` parser (`0x38bf120..0x38c044c`, JT `0x79e340`):
//!   length `4..=1000`, `version == 1`, big-endian 24-bit `action_id` in `1..=17` with `14` rejected.
//! - Read precompile input decoder families across all 21 addresses `0x0800..=0x0814`.

/// Small-block gas limit observed in `0x433dd35` and `0x2a1e380` (`0x2dc6c0`).
pub const SMALL_BLOCK_GAS_LIMIT: u64 = 3_000_000;

/// Big-block gas limit observed in `0x433dd30` and `0x2a1e37b` (`0x1c9c380`).
pub const BIG_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Small-block builder label (`0x60ea04`, 42 bytes) and bucket-guard `f64` pair (`0x4554f0`).
pub const BUILD_SMALL_BLOCK_LABEL: &str = "build_small_evm_block_and_apply_l1_effects";
pub const SMALL_BLOCK_GUARD_PAIR: (f64, f64) = (0.03, 0.07);

/// Big-block builder label (`0x60ea2e`, 40 bytes) and bucket-guard `f64` pair (`0x453520`).
pub const BUILD_BIG_BLOCK_LABEL: &str = "build_big_evm_block_and_apply_l1_effects";
pub const BIG_BLOCK_GUARD_PAIR: (f64, f64) = (0.05, 0.05);

/// Dual-block execution lane selected by `using_big_blocks` (`byte [rax + 0x1c]` / `byte [rsp + 0x44]`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EvmBlockKind {
    Small,
    Big,
}

impl EvmBlockKind {
    /// Select lane from the boolean flag (`0 => Small`, `nonzero => Big`).
    #[must_use]
    pub const fn from_using_big_blocks(using_big_blocks: bool) -> Self {
        if using_big_blocks {
            Self::Big
        } else {
            Self::Small
        }
    }

    /// Exact gas limit selected by `cmovne` in `0x433dd3a` and `0x2a1e385`.
    #[must_use]
    pub const fn gas_limit(self) -> u64 {
        match self {
            Self::Small => SMALL_BLOCK_GAS_LIMIT,
            Self::Big => BIG_BLOCK_GAS_LIMIT,
        }
    }

    /// Exact bucket-guard `(f64, f64)` pair from `0x4554f0` / `0x453520`.
    #[must_use]
    pub const fn guard_pair(self) -> (f64, f64) {
        match self {
            Self::Small => SMALL_BLOCK_GUARD_PAIR,
            Self::Big => BIG_BLOCK_GUARD_PAIR,
        }
    }

    /// Exact `.rodata` builder label (`0x60ea04` / `0x60ea2e`).
    #[must_use]
    pub const fn builder_label(self) -> &'static str {
        match self {
            Self::Small => BUILD_SMALL_BLOCK_LABEL,
            Self::Big => BUILD_BIG_BLOCK_LABEL,
        }
    }
}

/// CoreWriter system contract address (`0x3333...3333`, `.rodata` `0x7cab27`).
pub const CORE_WRITER_ADDRESS: [u8; 20] = [0x33; 20];

/// Native HYPE deposit system contract address (`0x2222...2222`, `.rodata` `0x7caac9`).
pub const HYPE_SYSTEM_ADDRESS: [u8; 20] = [0x22; 20];

/// WHYPE wrapper system contract address (`0x5555...5555`, `.rodata` `0x7cab3b`).
pub const WHYPE_SYSTEM_ADDRESS: [u8; 20] = [0x55; 20];

/// Solidity event signature parsed by `0x38bf120` (`.rodata` `0x7a0b19`).
pub const CORE_WRITER_RAW_ACTION_EVENT: &str = "RawAction(address,bytes)";

/// Solidity event signature parsed by `0x3897560` (`.rodata` `0x7a0bab`).
pub const HYPE_RECEIVED_EVENT: &str = "Received(address,uint256)";

/// Metadata for each embedded HyperEVM system contract installed in `0x434bda0..0x434be01`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemContractSpec {
    pub name: &'static str,
    pub address: [u8; 20],
    pub bytecode_len: usize,
    pub bytecode_sha256_hex: &'static str,
}

/// All 3 HyperEVM system contracts installed in `0x434bda0` (`0x64fd8f8`/`0x64fd918`/`0x64fd938`).
pub const HYPER_EVM_SYSTEM_CONTRACTS: [SystemContractSpec; 3] = [
    SystemContractSpec {
        name: "CoreWriter",
        address: CORE_WRITER_ADDRESS,
        bytecode_len: 544,
        bytecode_sha256_hex: "fd053fae53aa5ff797c8de9d38f5180d3c280228ae2d669ef9a83ab7834dac83",
    },
    SystemContractSpec {
        name: "HypeSystem",
        address: HYPE_SYSTEM_ADDRESS,
        bytecode_len: 122,
        bytecode_sha256_hex: "89c9f51d82a9ec4b4f386d157c477ac7e396bff125e461f691be57bc5d2f816a",
    },
    SystemContractSpec {
        name: "WHype",
        address: WHYPE_SYSTEM_ADDRESS,
        bytecode_len: 2041,
        bytecode_sha256_hex: "f7d3c155f5cbc8c04736f97f628e0547f2c7cd6d7bc38acfaf74d7e975f81d6b",
    },
];

/// Exact CoreWriter `RawAction` byte-length limits observed at `0x38bf48c..0x38bf4af`.
pub const CORE_WRITER_MIN_RAW_LEN: usize = 4;
pub const CORE_WRITER_MAX_RAW_LEN: usize = 1000;

/// Only accepted CoreWriter wire version byte (`0x38bf508: cmp r13b, 1`).
pub const CORE_WRITER_VERSION_V1: u8 = 1;

/// Highest action ID in jump table `0x79e340` (`0x38bf512: dec rbx; cmp rbx, 0x10`).
pub const CORE_WRITER_MAX_ACTION_ID: u32 = 17;

/// All 16 active `CoreWriter` v1 action IDs in node #115 (`14` jumps directly to reject `0x38c0323`).
pub const CORE_WRITER_ACTIVE_ACTION_IDS: [u32; 16] =
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17];

/// Parsed 4-byte `CoreWriter` v1 frame header plus borrowed ABI payload bytes (`raw_data[4..]`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreWriterFrame<'a> {
    pub version: u8,
    pub action_id: u32,
    pub payload: &'a [u8],
}

/// Errors produced by `parse_core_writer_frame` matching `0x38bf48a..0x38bf531`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreWriterFrameError {
    /// Length outside `1..=1000` (`0x38bf48c..0x38bf4a1` -> `0x38c0332`).
    LengthOutOfRange(usize),
    /// Length in `1..=3`, shorter than the 4-byte header (`0x38bf4a7..0x38bf4af` -> `0x38bf65d`).
    HeaderTooShort(usize),
    /// Disabled by `disabled_core_writer_actions` (`0x38bf4e5..0x38bf502` -> `0x38c0323`).
    ActionDisabled { version: u8, action_id: u32 },
    /// Version byte != 1 (`0x38bf508..0x38bf50c` -> `0x38c0323`).
    UnsupportedVersion(u8),
    /// Action ID is 0, 14 (explicit reject slot), or > 17 (`0x38bf512..0x38bf531` -> `0x38c0323`).
    UnsupportedActionId(u32),
}

/// Returns true iff `action_id` is one of the 16 active jump-table slots in `0x79e340`.
#[must_use]
pub const fn is_core_writer_action_id_active(action_id: u32) -> bool {
    (action_id >= 1 && action_id <= 13) || (action_id >= 15 && action_id <= 17)
}

/// Parse and validate a `CoreWriter` `RawAction(address,bytes)` payload following the exact
/// check order observed in `0x38bf48a..0x38bf531`:
/// 1. `1 <= raw.len() <= 1000`
/// 2. `raw.len() >= 4`
/// 3. Decode `version = raw[0]` and big-endian 24-bit `action_id = raw[1..4]`
/// 4. Optional `is_disabled(version, action_id)` gate (`0x35be2f0`)
/// 5. `version == 1`
/// 6. `action_id` in active jump-table slots (`1..=13`, `15..=17`; `14` rejected).
pub fn parse_core_writer_frame<F>(
    raw: &[u8],
    is_disabled: F,
) -> Result<CoreWriterFrame<'_>, CoreWriterFrameError>
where
    F: Fn(u8, u32) -> bool,
{
    if raw.is_empty() || raw.len() > CORE_WRITER_MAX_RAW_LEN {
        return Err(CoreWriterFrameError::LengthOutOfRange(raw.len()));
    }
    if raw.len() < CORE_WRITER_MIN_RAW_LEN {
        return Err(CoreWriterFrameError::HeaderTooShort(raw.len()));
    }
    let version = raw[0];
    let action_id = u32::from_be_bytes([0, raw[1], raw[2], raw[3]]);
    if is_disabled(version, action_id) {
        return Err(CoreWriterFrameError::ActionDisabled { version, action_id });
    }
    if version != CORE_WRITER_VERSION_V1 {
        return Err(CoreWriterFrameError::UnsupportedVersion(version));
    }
    if !is_core_writer_action_id_active(action_id) {
        return Err(CoreWriterFrameError::UnsupportedActionId(action_id));
    }
    Ok(CoreWriterFrame {
        version,
        action_id,
        payload: &raw[4..],
    })
}

/// Encode a `CoreWriter` v1 frame (`[version, action_id_be24, payload...]`).
#[must_use]
pub fn encode_core_writer_frame(version: u8, action_id: u32, payload: &[u8]) -> Option<Vec<u8>> {
    if action_id > 0x00ff_ffff {
        return None;
    }
    let total = CORE_WRITER_MIN_RAW_LEN.checked_add(payload.len())?;
    if total > CORE_WRITER_MAX_RAW_LEN {
        return None;
    }
    let be = action_id.to_be_bytes();
    let mut out = Vec::with_capacity(total);
    out.push(version);
    out.extend_from_slice(&be[1..4]);
    out.extend_from_slice(payload);
    Some(out)
}

/// Input ABI decoder family statically observed in the prologue of each of the 21
/// HyperEVM read precompiles (`0x0800..=0x0814`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadPrecompileInputDecoder {
    /// No input decoder call (`0x0809` L1BlockNumber).
    Empty,
    /// `0x3896ec0` (348 B): 1-word (`>= 32` B) uint/index decoder.
    SingleWordUint,
    /// `0x3897020` (469 B): 2-word (`>= 64` B) `(address, uint)` decoder.
    AddressAndUint,
    /// `0x3897200` (318 B): 1-word (`>= 32` B) decoder (`0x0812`).
    SingleWord3897200,
    /// `0x38f9750` (213 B): generic `ethabi::decode` word decoder.
    GenericEthAbi,
}

/// Look up the observed input ABI decoder family for any of the 21 node #115 read precompiles.
#[must_use]
pub const fn read_precompile_input_decoder(suffix: u16) -> Option<ReadPrecompileInputDecoder> {
    match suffix {
        0x0809 => Some(ReadPrecompileInputDecoder::Empty),
        0x0806 | 0x0807 | 0x0808 | 0x080a | 0x080b | 0x080c | 0x080d | 0x080e | 0x0814 => {
            Some(ReadPrecompileInputDecoder::SingleWordUint)
        }
        0x0801 | 0x0811 => Some(ReadPrecompileInputDecoder::AddressAndUint),
        0x0812 => Some(ReadPrecompileInputDecoder::SingleWord3897200),
        0x0800 | 0x0802 | 0x0803 | 0x0804 | 0x0805 | 0x080f | 0x0810 | 0x0813 => {
            Some(ReadPrecompileInputDecoder::GenericEthAbi)
        }
        _ => None,
    }
}
