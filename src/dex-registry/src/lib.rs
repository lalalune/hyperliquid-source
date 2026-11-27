//! Integrated node #115 DEX registry and HIP-3 metadata/state codecs.
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

#![forbid(unsafe_code)]

pub mod registry;
pub mod schema;
pub mod sub_deployers;

pub use node115_date_time_display as date_time_display;
pub use node115_hip3_disabled_record as disabled_record;
pub use node115_hip3_disabled_state_codec as disabled_state_codec;

/// Pinned SHA-256 digest of Linux x86-64 node #115 (`artifacts/node/115/hl-node`).
pub const TARGET_SHA256: &str =
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

/// 20-byte account / deployer address.
pub type Address = [u8; 20];

/// Formats a 20-byte address as `"0x"` followed by 40 lowercase ASCII hex digits,
/// matching the shared hex formatter `0x2eabb50` behind GOT slot `0x64e4d08`.
pub fn format_address_hex(addr: &Address) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for &b in addr {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Minimal shortest-form MessagePack primitives shared by the HIP-3 codecs.
pub mod msgpack {
    pub fn write_str(out: &mut Vec<u8>, s: &[u8]) {
        let len = s.len();
        if len < 32 {
            out.push(0xa0 | (len as u8));
        } else if len <= u8::MAX as usize {
            out.push(0xd9);
            out.push(len as u8);
        } else if len <= u16::MAX as usize {
            out.push(0xda);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0xdb);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
        out.extend_from_slice(s);
    }

    pub fn write_u64(out: &mut Vec<u8>, v: u64) {
        if v < 0x80 {
            out.push(v as u8);
        } else if v <= u8::MAX as u64 {
            out.push(0xcc);
            out.push(v as u8);
        } else if v <= u16::MAX as u64 {
            out.push(0xcd);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= u32::MAX as u64 {
            out.push(0xce);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            out.push(0xcf);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }

    pub fn write_array_len(out: &mut Vec<u8>, len: usize) {
        if len < 16 {
            out.push(0x90 | (len as u8));
        } else if len <= u16::MAX as usize {
            out.push(0xdc);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0xdd);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }

    pub fn write_map_len(out: &mut Vec<u8>, len: usize) {
        if len < 16 {
            out.push(0x80 | (len as u8));
        } else if len <= u16::MAX as usize {
            out.push(0xde);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0xdf);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
}
