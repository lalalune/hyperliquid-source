//! Node #115 `evm_rpc/src/evm_write_forwarder.rs` reconstruction.
//!
//! Grounded in `research/work-items/RE-011-evm-raw-forward-115`:
//! - Selector routing (`0x1748153`): `0|1` -> unsupported chain (`code=30000`),
//!   `2` -> `https://rpc.hyperliquid-testnet.xyz/evm`,
//!   `3..=255` -> `https://rpc.hyperliquid.xyz/evm`.
//! - Strict hex decoder (`0x167afd0`): tests odd length BEFORE checking prefix;
//!   strips lowercase `0x` only (`0X` fails at index 1); reports first bad byte
//!   and its 0-based index after stripped prefix.
//! - Outgoing encoder (`0x14500d0`): lowercase `0x`-prefixed hex.

use crate::method_router::JSONRPC_SERVER_ERROR;

pub const TESTNET_EVM_RPC_URL: &str = "https://rpc.hyperliquid-testnet.xyz/evm";
pub const MAINNET_EVM_RPC_URL: &str = "https://rpc.hyperliquid.xyz/evm";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardErrorKind {
    /// Kind `0`: selector 0 or 1 (`Unexpected error (code=30000)`).
    UnsupportedChain,
    /// Kind `1`: transport/send error (`Unable to send transaction.`).
    UnableToSend,
    /// Kind `2`: response decode error (`Invalid transaction response.`).
    InvalidResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardError {
    pub kind: ForwardErrorKind,
    pub jsonrpc_code: i32,
}

impl ForwardError {
    pub const fn new(kind: ForwardErrorKind) -> Self {
        Self {
            kind,
            jsonrpc_code: JSONRPC_SERVER_ERROR,
        }
    }

    pub const fn message(&self) -> &'static str {
        match self.kind {
            ForwardErrorKind::UnsupportedChain => "Unexpected error (code=30000)",
            ForwardErrorKind::UnableToSend => "Unable to send transaction.",
            ForwardErrorKind::InvalidResponse => "Invalid transaction response.",
        }
    }
}

/// Resolve the forwarding endpoint from the captured chain selector byte (`0x1748153`).
pub const fn forward_url_for_selector(selector: u8) -> Result<&'static str, ForwardError> {
    match selector {
        0 | 1 => Err(ForwardError::new(ForwardErrorKind::UnsupportedChain)),
        2 => Ok(TESTNET_EVM_RPC_URL),
        3..=255 => Ok(MAINNET_EVM_RPC_URL),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HexDecodeError {
    OddLength,
    InvalidCharacter { byte: u8, index: usize },
}

/// Strict hex decoder matching `0x167afd0` (`RE-011-evm-raw-forward-115`):
/// 1. Rejects odd input length BEFORE stripping `0x` (e.g. `"0x0"` -> `OddLength`).
/// 2. Strips only lowercase `"0x"` (so `"0X"` fails at index 1 with `b'X'`).
/// 3. Validates every byte in order and reports the first offending byte with
///    0-based index relative to the slice after any stripped prefix.
pub fn decode_raw_tx_hex(input: &[u8]) -> Result<Vec<u8>, HexDecodeError> {
    if !input.len().is_multiple_of(2) {
        return Err(HexDecodeError::OddLength);
    }
    let digits = input.strip_prefix(b"0x").unwrap_or(input);
    let mut out = Vec::with_capacity(digits.len() / 2);
    for (pair_idx, pair) in digits.chunks_exact(2).enumerate() {
        let hi = decode_nibble(pair[0]).ok_or(HexDecodeError::InvalidCharacter {
            byte: pair[0],
            index: pair_idx * 2,
        })?;
        let lo = decode_nibble(pair[1]).ok_or(HexDecodeError::InvalidCharacter {
            byte: pair[1],
            index: pair_idx * 2 + 1,
        })?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

const fn decode_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Lowercase `0x`-prefixed hex encoder matching `0x14500d0`.
pub fn encode_raw_tx_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Construct the forwarded `eth_sendRawTransaction` JSON-RPC 2.0 request body (`0x17480e0`).
pub fn build_send_raw_tx_json_rpc(raw_tx: &[u8]) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":1}}"#,
        encode_raw_tx_hex(raw_tx)
    )
}
