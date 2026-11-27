//! Node #115 HyperEVM read precompiles (`0x0800..=0x0814`) and scaled standard
//! Ethereum precompiles (`0x01`, `0x05..=0x0a`).
//!
//! Binary anchors:
//! - Private key dispatcher `0x38be030`, provider constructor `0x38be800`,
//!   enumerator `0x4200a50` (`RE-021-scaled-precompile-route-115`).
//! - All 21 read precompile callbacks (`0x38df640`..`0x38e93e0`) share the exact
//!   preamble `input.len() <= 0x7d0 (2000)` and `gas = 1000 + 33 * (in_len + out_len)`.
//! - Scaled precompile selector `0x46a0eb0` + gas scaler `0x2a6b07d..0x2a6b6e6`.
//! - Activation predicate `0x433dc40` (`tag == 1 && counter + 1 >= threshold`).

use node115_evm_precompile_outcome_names::ReadPrecompileOutcomeName;

/// Maximum admitted input length for all 21 HyperEVM read precompiles (`cmp rcx, 0x7d0`).
pub const READ_PRECOMPILE_MAX_INPUT_LEN: usize = 2000;

/// Base gas charged by all 21 HyperEVM read precompiles (`add ..., 0x3e8`).
pub const READ_PRECOMPILE_BASE_GAS: u64 = 1000;

/// Per-byte gas charged on input + output bytes by all 21 HyperEVM read precompiles
/// (`(len << 5) + len = 33 * len`).
pub const READ_PRECOMPILE_GAS_PER_BYTE: u64 = 33;

/// All 21 HyperEVM read precompile 16-bit address suffixes in the exact order
/// enumerated by `0x4200a50` (indices 6..=26) and dispatched by `0x38be030`.
pub const READ_PRECOMPILE_SUFFIXES: [u16; 21] = [
    0x0800, 0x0813, 0x0801, 0x0802, 0x0803, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0809, 0x080a,
    0x080b, 0x080c, 0x080d, 0x080e, 0x080f, 0x0810, 0x0811, 0x0812, 0x0814,
];

/// Seven scaled standard Ethereum precompiles `(last_byte, divisor)` observed in
/// `0x46a0eb0` (`RE-021-scaled-precompile-route-115`).
pub const SCALED_PRECOMPILES: [(u8, u64); 7] = [
    (0x01, 5),  // ecrecover
    (0x05, 10), // modexp
    (0x06, 10), // bn254_add
    (0x07, 10), // bn254_mul
    (0x08, 10), // bn254_pairing
    (0x09, 10), // blake2f
    (0x0a, 40), // kzg_point_evaluation
];

/// Build the 20-byte precompile address `0x0000...{suffix:04x}`.
pub const fn read_precompile_address(suffix: u16) -> [u8; 20] {
    let mut addr = [0u8; 20];
    let hi = (suffix >> 8) as u8;
    let lo = (suffix & 0xff) as u8;
    addr[18] = hi;
    addr[19] = lo;
    addr
}

/// Fixed output length (in bytes) proven directly from the post-output gas
/// immediate (`1000 + 33 * out_len`) of each fixed-size read precompile callback
/// in node #115. Returns `None` for dynamic-length read precompiles.
pub const fn read_precompile_fixed_output_len(suffix: u16) -> Option<usize> {
    match suffix {
        0x0800 | 0x0813 => Some(160), // +0x1888 = 6280 = 1000 + 33*160
        0x0801 | 0x0814 => Some(96),  // +0x1048 = 4168 = 1000 + 33*96
        0x0802 | 0x080e => Some(64),  // +0x0c28 = 3112 = 1000 + 33*64
        0x0803 | 0x0806 | 0x0807 | 0x0808 | 0x0809 | 0x0810 => Some(32), // +0x0808 = 2056
        0x0805 | 0x080f => Some(128), // +0x1468 = 5224 = 1000 + 33*128
        _ => None,
    }
}

/// Phase-1 preflight gas (`1000 + 33 * input_len`), returning `None` if
/// `input_len > 2000` (`cmp rcx, 0x7d0; ja out_of_gas`).
pub const fn read_precompile_preflight_gas(input_len: usize) -> Option<u64> {
    if input_len > READ_PRECOMPILE_MAX_INPUT_LEN {
        return None;
    }
    Some(READ_PRECOMPILE_BASE_GAS + READ_PRECOMPILE_GAS_PER_BYTE * (input_len as u64))
}

/// Phase-2 total gas (`1000 + 33 * (input_len + output_len)`), returning `None`
/// if `input_len > 2000` or arithmetic overflows `u64`.
pub const fn read_precompile_total_gas(input_len: usize, output_len: usize) -> Option<u64> {
    if input_len > READ_PRECOMPILE_MAX_INPUT_LEN {
        return None;
    }
    let Some(total_bytes) = (input_len as u64).checked_add(output_len as u64) else {
        return None;
    };
    let Some(byte_gas) = total_bytes.checked_mul(READ_PRECOMPILE_GAS_PER_BYTE) else {
        return None;
    };
    READ_PRECOMPILE_BASE_GAS.checked_add(byte_gas)
}

/// Outcome of executing a HyperEVM read precompile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadPrecompileOutput {
    Ok { gas_used: u64, bytes: Vec<u8> },
    OutOfGas,
    Error(String),
    UnexpectedError(String),
}

impl ReadPrecompileOutput {
    pub const fn outcome_name(&self) -> ReadPrecompileOutcomeName {
        match self {
            Self::Ok { .. } => ReadPrecompileOutcomeName::Ok,
            Self::OutOfGas => ReadPrecompileOutcomeName::OutOfGas,
            Self::Error(_) => ReadPrecompileOutcomeName::Error,
            Self::UnexpectedError(_) => ReadPrecompileOutcomeName::UnexpectedError,
        }
    }
}

/// Execute read precompile `0x0000...0809` (`L1BlockNumber`, node #115 VA `0x38e3b40`).
///
/// Checks `input.len() <= 2000`, `1000 + 33 * input.len() <= gas_limit`, encodes
/// `l1_block_number` as big-endian 32-byte ABI word (`zero24 || be64`), and checks
/// `1000 + 33 * (input.len() + 32) <= gas_limit` (`+0x808 = 2056`).
pub fn execute_l1_block_number_precompile(
    input: &[u8],
    gas_limit: u64,
    l1_block_number: u64,
) -> ReadPrecompileOutput {
    let Some(preflight) = read_precompile_preflight_gas(input.len()) else {
        return ReadPrecompileOutput::OutOfGas;
    };
    if preflight > gas_limit {
        return ReadPrecompileOutput::OutOfGas;
    }
    let Some(total_gas) = read_precompile_total_gas(input.len(), 32) else {
        return ReadPrecompileOutput::OutOfGas;
    };
    if total_gas > gas_limit {
        return ReadPrecompileOutput::OutOfGas;
    }
    let mut out = vec![0u8; 32];
    out[24..32].copy_from_slice(&l1_block_number.to_be_bytes());
    ReadPrecompileOutput::Ok {
        gas_used: total_gas,
        bytes: out,
    }
}

/// Return the gas divisor for a scaled standard precompile address (`0x46a0eb0`).
pub fn scaled_precompile_divisor(address: &[u8; 20]) -> Option<u64> {
    if address[..19] != [0u8; 19] {
        return None;
    }
    SCALED_PRECOMPILES
        .iter()
        .find_map(|&(last, div)| (last == address[19]).then_some(div))
}

/// Scaled precompile activation rule observed at `0x433dc40` (`0x433de33`, `0x433e5f3`):
/// returns `None` when `counter == u64::MAX`, else `Some(tag == 1 && counter + 1 >= threshold)`.
pub const fn is_scaled_precompile_active(tag: u32, counter: u64, threshold: u64) -> Option<bool> {
    let Some(next) = counter.checked_add(1) else {
        return None;
    };
    Some(tag == 1 && next >= threshold)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScaledPrecompileError {
    NotScaled,
    CallbackError,
}

/// Apply the node #115 scaled precompile gas adapter (`0x2a6b07d..0x2a6b6e6`):
/// passes `gas_limit / divisor` to `callback`, and on success multiplies the
/// returned `gas_used` by `divisor` saturating at `u64::MAX`.
pub fn run_scaled_precompile<T>(
    address: &[u8; 20],
    gas_limit: u64,
    callback: impl FnOnce(u64) -> Result<(u64, T), ()>,
) -> Result<(u64, T), ScaledPrecompileError> {
    let divisor = scaled_precompile_divisor(address).ok_or(ScaledPrecompileError::NotScaled)?;
    let scaled_limit = gas_limit / divisor;
    let (inner_cost, output) = callback(scaled_limit).map_err(|()| ScaledPrecompileError::CallbackError)?;
    let scaled_cost = inner_cost.saturating_mul(divisor);
    Ok((scaled_cost, output))
}
