//! Node #115 `l1/src/bridge_request.rs` reconstruction.
//!
//! Covers all 8 `BridgeRequest` variants dispatched by `0x4526230` (jump table
//! `0x7d3708`) and the outer EIP-712 `Agent` payload builder at `0x4526e40`
//! (`bridge_request.rs:83:78`).

use global_constants::{ChainDisplay, ChainName};
use node115_bridge_preimage::inner_digest as bridge_preimage_digest;
use node115_bridge_request_abi::encode_request_withdrawal;
use node115_token_id::keccak256;

/// Arbitrum One chain ID written by `0x4526e40` when `chain == ChainName::Mainnet` (tag 3).
pub const ARB_MAINNET_CHAIN_ID: u64 = 0xa4b1; // 42161

/// Arbitrum Sepolia chain ID written by `0x4526e40` for all non-Mainnet chains.
pub const ARB_SEPOLIA_CHAIN_ID: u64 = 0x66eee; // 421614

/// Single-byte `"a"` (`0x61`) source field written at `+0x00` by `0x4526e40`.
pub const BRIDGE_AGENT_SOURCE: &str = "a";

/// Two-variant role enum formatted by `0x457cf20` for `BridgeRequest` tag 0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BridgeRole {
    Locker = 0,
    Finalizer = 1,
}

impl BridgeRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Locker => "Locker",
            Self::Finalizer => "Finalizer",
        }
    }
}

/// Complete 8-variant `BridgeRequest` enum matching jump table `0x7d3708` in
/// node #115 `0x4526230`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeRequest {
    /// Tag 0 (`0x4526257` -> `0x44e82d0`):
    /// ABI tuple `(string "modify{Locker|Finalizer}", (address,), bool, uint64)`.
    ModifyRole {
        role: BridgeRole,
        user: [u8; 20],
        active: bool,
        nonce: u64,
    },
    /// Tag 1 (`0x45266ac` -> `0x44e6980`):
    /// ABI tuple `(string "changeDisputePeriodSeconds", uint64, uint64)`.
    ChangeDisputePeriodSeconds {
        dispute_period_seconds: u64,
        nonce: u64,
    },
    /// Tag 2 (`0x45263bb` -> `0x44e6980`):
    /// ABI tuple `(string "changeBlockDurationMillis", uint64, uint64)`.
    ChangeBlockDurationMillis {
        block_duration_millis: u64,
        nonce: u64,
    },
    /// Tag 3 (`0x45264fc` -> `0x44e6980`):
    /// ABI tuple `(string "changeLockerThreshold", uint64, uint64)`.
    ChangeLockerThreshold { locker_threshold: u64, nonce: u64 },
    /// Tag 4 (`0x45263aa` -> `0x3676390` -> `0x3b5eaf0` -> `0x44e8f00`):
    /// ABI tuple `(string "updateValidatorSet", uint64 epoch, address[] hot, address[] cold, uint64[] powers)`.
    UpdateValidatorSet {
        epoch: u64,
        hot_addresses: Vec<[u8; 20]>,
        cold_addresses: Vec<[u8; 20]>,
        powers: Vec<u64>,
    },
    /// Tag 5 (`0x45267ed` -> `0x44e96a0`):
    /// ABI tuple `(string "requestWithdrawal", address, address, uint64, uint64)` (224 bytes).
    RequestWithdrawal {
        user: [u8; 20],
        destination: [u8; 20],
        usd: u64,
        nonce: u64,
    },
    /// Tag 6 (`0x452695a` -> `0x44ea040`):
    /// ABI tuple `(string "unlock", uint64 epoch, address[] hot, address[] cold, uint64[] powers, uint64 nonce)`.
    Unlock {
        epoch: u64,
        hot_addresses: Vec<[u8; 20]>,
        cold_addresses: Vec<[u8; 20]>,
        powers: Vec<u64>,
        nonce: u64,
    },
    /// Tag 7 (`0x4526640` -> `0x44e6c40`):
    /// ABI tuple `(string "invalidateWithdrawals", bytes32[] messages, uint64 nonce)`.
    InvalidateWithdrawals { messages: Vec<[u8; 32]>, nonce: u64 },
}

/// Output constructed by `0x4526e40` (`bridge_request.rs:83:78`):
/// EIP-712 `Agent { source: "a", connection_id }` bound to the Arbitrum chain ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeAgentPayload {
    pub source: &'static str,
    pub connection_id: [u8; 32],
    pub arb_chain_id: u64,
}

/// Select the Arbitrum EIP-712 chain ID matching `0x4526e40` (`cmp bpl, 3`).
#[inline]
pub const fn arb_chain_id_for(chain: ChainName) -> u64 {
    match chain {
        ChainName::Mainnet => ARB_MAINNET_CHAIN_ID,
        _ => ARB_SEPOLIA_CHAIN_ID,
    }
}

/// Format the Bridge2 contract lookup key `"Bridge2{Chain}"` (`0x4526e81`).
pub fn bridge2_contract_lookup_key(chain: ChainName) -> String {
    format!("Bridge2{}", ChainDisplay(chain))
}

impl BridgeRequest {
    /// Discriminant index `0..=7` matching jump table `0x7d3708` in `0x4526230`.
    pub const fn tag(&self) -> u8 {
        match self {
            Self::ModifyRole { .. } => 0,
            Self::ChangeDisputePeriodSeconds { .. } => 1,
            Self::ChangeBlockDurationMillis { .. } => 2,
            Self::ChangeLockerThreshold { .. } => 3,
            Self::UpdateValidatorSet { .. } => 4,
            Self::RequestWithdrawal { .. } => 5,
            Self::Unlock { .. } => 6,
            Self::InvalidateWithdrawals { .. } => 7,
        }
    }

    /// Solidity ABI encoding matching `0x169e350` (`ethabi::encode`) for all 8 tags.
    pub fn abi_encode(&self) -> Vec<u8> {
        match self {
            Self::ModifyRole {
                role,
                user,
                active,
                nonce,
            } => {
                let label = format!("modify{}", role.as_str());
                abi_encode_tokens(&[
                    AbiToken::String(label.as_bytes()),
                    AbiToken::Address(*user),
                    AbiToken::Bool(*active),
                    AbiToken::Uint64(*nonce),
                ])
            }
            Self::ChangeDisputePeriodSeconds {
                dispute_period_seconds,
                nonce,
            } => abi_encode_tokens(&[
                AbiToken::String(b"changeDisputePeriodSeconds"),
                AbiToken::Uint64(*dispute_period_seconds),
                AbiToken::Uint64(*nonce),
            ]),
            Self::ChangeBlockDurationMillis {
                block_duration_millis,
                nonce,
            } => abi_encode_tokens(&[
                AbiToken::String(b"changeBlockDurationMillis"),
                AbiToken::Uint64(*block_duration_millis),
                AbiToken::Uint64(*nonce),
            ]),
            Self::ChangeLockerThreshold {
                locker_threshold,
                nonce,
            } => abi_encode_tokens(&[
                AbiToken::String(b"changeLockerThreshold"),
                AbiToken::Uint64(*locker_threshold),
                AbiToken::Uint64(*nonce),
            ]),
            Self::UpdateValidatorSet {
                epoch,
                hot_addresses,
                cold_addresses,
                powers,
            } => abi_encode_tokens(&[
                AbiToken::String(b"updateValidatorSet"),
                AbiToken::Uint64(*epoch),
                AbiToken::AddressArray(hot_addresses),
                AbiToken::AddressArray(cold_addresses),
                AbiToken::Uint64Array(powers),
            ]),
            Self::RequestWithdrawal {
                user,
                destination,
                usd,
                nonce,
            } => encode_request_withdrawal(user, destination, *usd, *nonce).to_vec(),
            Self::Unlock {
                epoch,
                hot_addresses,
                cold_addresses,
                powers,
                nonce,
            } => abi_encode_tokens(&[
                AbiToken::String(b"unlock"),
                AbiToken::Uint64(*epoch),
                AbiToken::AddressArray(hot_addresses),
                AbiToken::AddressArray(cold_addresses),
                AbiToken::Uint64Array(powers),
                AbiToken::Uint64(*nonce),
            ]),
            Self::InvalidateWithdrawals { messages, nonce } => abi_encode_tokens(&[
                AbiToken::String(b"invalidateWithdrawals"),
                AbiToken::Bytes32Array(messages),
                AbiToken::Uint64(*nonce),
            ]),
        }
    }

    /// Inner Keccak-256 hash produced by `0x4526230`.
    pub fn inner_hash(&self) -> [u8; 32] {
        keccak256(&self.abi_encode())
    }

    /// Outer EIP-712 `Agent` payload produced by `0x4526e40`:
    /// `connection_id = keccak256(zero12 || bridge_contract || inner_hash)`.
    pub fn to_agent_payload(
        &self,
        chain: ChainName,
        bridge_contract: &[u8; 20],
    ) -> BridgeAgentPayload {
        let inner = self.inner_hash();
        let connection_id = bridge_preimage_digest(bridge_contract, &inner);
        BridgeAgentPayload {
            source: BRIDGE_AGENT_SOURCE,
            connection_id,
            arb_chain_id: arb_chain_id_for(chain),
        }
    }
}

enum AbiToken<'a> {
    Address([u8; 20]),
    Bool(bool),
    Uint64(u64),
    String(&'a [u8]),
    AddressArray(&'a [[u8; 20]]),
    Uint64Array(&'a [u64]),
    Bytes32Array(&'a [[u8; 32]]),
}

impl AbiToken<'_> {
    fn is_dynamic(&self) -> bool {
        matches!(
            self,
            Self::String(_)
                | Self::AddressArray(_)
                | Self::Uint64Array(_)
                | Self::Bytes32Array(_)
        )
    }

    fn encode_tail(&self, out: &mut Vec<u8>) {
        match self {
            Self::String(bytes) => {
                push_u64_word(out, bytes.len() as u64);
                out.extend_from_slice(bytes);
                let rem = bytes.len() % 32;
                if rem != 0 {
                    out.resize(out.len() + (32 - rem), 0);
                }
            }
            Self::AddressArray(addrs) => {
                push_u64_word(out, addrs.len() as u64);
                for addr in *addrs {
                    push_address_word(out, addr);
                }
            }
            Self::Uint64Array(vals) => {
                push_u64_word(out, vals.len() as u64);
                for &v in *vals {
                    push_u64_word(out, v);
                }
            }
            Self::Bytes32Array(items) => {
                push_u64_word(out, items.len() as u64);
                for item in *items {
                    out.extend_from_slice(item);
                }
            }
            _ => {}
        }
    }
}

fn abi_encode_tokens(tokens: &[AbiToken<'_>]) -> Vec<u8> {
    let head_len = tokens.len() * 32;
    let mut head = Vec::with_capacity(head_len);
    let mut tail = Vec::new();

    for token in tokens {
        if token.is_dynamic() {
            push_u64_word(&mut head, (head_len + tail.len()) as u64);
            token.encode_tail(&mut tail);
        } else {
            match token {
                AbiToken::Address(addr) => push_address_word(&mut head, addr),
                AbiToken::Bool(b) => push_u64_word(&mut head, u64::from(*b)),
                AbiToken::Uint64(v) => push_u64_word(&mut head, *v),
                _ => unreachable!(),
            }
        }
    }

    head.extend_from_slice(&tail);
    head
}

fn push_u64_word(out: &mut Vec<u8>, value: u64) {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&value.to_be_bytes());
    out.extend_from_slice(&word);
}

fn push_address_word(out: &mut Vec<u8>, addr: &[u8; 20]) {
    let mut word = [0u8; 32];
    word[12..32].copy_from_slice(addr);
    out.extend_from_slice(&word);
}
