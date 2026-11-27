//! Node #115 `EthEventId` and deposit vote action wire codecs.
//!
//! Grounded in `research/work-items/bridge-eth-event-wire-115`:
//! - `EthEventId`: 5 fields (`b`, `t`, `e`, `i`, `h`), map/array head `0x85`/`0x95`,
//!   `e` from the 6-variant `Node115BridgeEvent`, `h` as `0x` + 64 lowercase hex digits.
//! - Flat action: `{type: "VoteEthDepositAction", user, usd, ethId}` (`0x84`/`0x94`).
//! - Nested action: `{type: "l1ValidatorVoteBridgeDeposit", action: {user, usd, ethId}}` (`0x82`/`0x92`).

use node115_bridge_event_name_decoder::Node115BridgeEvent;

/// Bridge Ethereum event identifier (`EthEventId`), 5 wire fields `b, t, e, i, h`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthEventId {
    /// Block number (`b`).
    pub block_number: u64,
    /// Transaction timestamp / index word (`t`).
    pub t: u64,
    /// Six-variant event type (`e`).
    pub event_type: Node115BridgeEvent,
    /// Log index (`i`).
    pub log_index: u64,
    /// 32-byte transaction hash (`h`), serialized as `"0x"` + 64 lowercase hex digits.
    pub tx_hash: [u8; 32],
}

/// Deposit vote action payload (`VoteEthDepositAction` / `l1ValidatorVoteBridgeDeposit`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteEthDepositAction {
    pub user: [u8; 20],
    pub usd: u64,
    pub eth_id: EthEventId,
}

impl EthEventId {
    /// Format `h` as `"0x"` followed by 64 lowercase hexadecimal digits.
    pub fn tx_hash_hex(&self) -> String {
        encode_0x_hex(&self.tx_hash)
    }

    /// Encode `EthEventId` as MessagePack (`named = true` emits `0x85` map with
    /// keys `b, t, e, i, h`; `named = false` emits `0x95` 5-element array).
    pub fn encode_msgpack(&self, named: bool, out: &mut Vec<u8>) {
        if named {
            out.push(0x85);
            put_str(out, b"b");
            put_uint(out, self.block_number);
            put_str(out, b"t");
            put_uint(out, self.t);
            put_str(out, b"e");
            put_str(out, self.event_type.name().as_bytes());
            put_str(out, b"i");
            put_uint(out, self.log_index);
            put_str(out, b"h");
            put_str(out, self.tx_hash_hex().as_bytes());
        } else {
            out.push(0x95);
            put_uint(out, self.block_number);
            put_uint(out, self.t);
            put_str(out, self.event_type.name().as_bytes());
            put_uint(out, self.log_index);
            put_str(out, self.tx_hash_hex().as_bytes());
        }
    }

    /// Encode `EthEventId` as compact JSON matching `bridge-eth-event-wire-115`.
    pub fn to_json_string(&self) -> String {
        format!(
            r#"{{"b":{},"t":{},"e":"{}","i":{},"h":"{}"}}"#,
            self.block_number,
            self.t,
            self.event_type.name(),
            self.log_index,
            self.tx_hash_hex()
        )
    }
}

impl VoteEthDepositAction {
    /// Format `user` as `"0x"` followed by 40 lowercase hexadecimal digits.
    pub fn user_hex(&self) -> String {
        encode_0x_hex(&self.user)
    }

    /// Encode flat `VoteEthDepositAction` as MessagePack (`0x84` named / `0x94` compact).
    pub fn encode_flat_msgpack(&self, named: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(192);
        if named {
            out.push(0x84);
            put_str(&mut out, b"type");
            put_str(&mut out, b"VoteEthDepositAction");
            put_str(&mut out, b"user");
            put_str(&mut out, self.user_hex().as_bytes());
            put_str(&mut out, b"usd");
            put_uint(&mut out, self.usd);
            put_str(&mut out, b"ethId");
            self.eth_id.encode_msgpack(true, &mut out);
        } else {
            out.push(0x94);
            put_str(&mut out, b"VoteEthDepositAction");
            put_str(&mut out, self.user_hex().as_bytes());
            put_uint(&mut out, self.usd);
            self.eth_id.encode_msgpack(false, &mut out);
        }
        out
    }

    /// Encode nested `l1ValidatorVoteBridgeDeposit` as MessagePack (`0x82` named / `0x92` compact).
    pub fn encode_nested_msgpack(&self, named: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(224);
        if named {
            out.push(0x82);
            put_str(&mut out, b"type");
            put_str(&mut out, b"l1ValidatorVoteBridgeDeposit");
            put_str(&mut out, b"action");
            out.push(0x83);
            put_str(&mut out, b"user");
            put_str(&mut out, self.user_hex().as_bytes());
            put_str(&mut out, b"usd");
            put_uint(&mut out, self.usd);
            put_str(&mut out, b"ethId");
            self.eth_id.encode_msgpack(true, &mut out);
        } else {
            out.push(0x92);
            put_str(&mut out, b"l1ValidatorVoteBridgeDeposit");
            out.push(0x93);
            put_str(&mut out, self.user_hex().as_bytes());
            put_uint(&mut out, self.usd);
            self.eth_id.encode_msgpack(false, &mut out);
        }
        out
    }

    /// Encode flat `VoteEthDepositAction` as JSON matching `0x290cb40`.
    pub fn to_flat_json_string(&self) -> String {
        format!(
            r#"{{"type":"VoteEthDepositAction","user":"{}","usd":{},"ethId":{}}}"#,
            self.user_hex(),
            self.usd,
            self.eth_id.to_json_string()
        )
    }
}

pub fn encode_0x_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn put_str(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len();
    if len < 32 {
        out.push(0xa0 | (len as u8));
    } else if len < 256 {
        out.push(0xd9);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(0xda);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0xdb);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

fn put_uint(out: &mut Vec<u8>, value: u64) {
    if value < 0x80 {
        out.push(value as u8);
    } else if value < 0x100 {
        out.push(0xcc);
        out.push(value as u8);
    } else if value < 0x1_0000 {
        out.push(0xcd);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        out.push(0xce);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&value.to_be_bytes());
    }
}
