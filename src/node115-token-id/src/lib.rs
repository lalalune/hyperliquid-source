#![forbid(unsafe_code)]
//! Token id derivation of node #115 (Linux x86-64, SHA-256 `a6e2897c...c5301`).
//!
//! The registration caller `0x3c48b40` builds the pair `(&TokenSpec, index)` at `0x3c48f70..0x3c48f91`
//! and calls `0x38d2ce0`, which serializes the pair with `0x41d4b30` and hashes it with a fresh
//! Keccak-256 state. The caller keeps the first 16 digest bytes (`0x3c48f96`) as the token id.
//!
//! Serialized form (all widths verified against the bytes, see the evidence packet):
//! `[ {"name": str, "szDecimals": uint, "weiDecimals": uint}, index ]` as MessagePack, array of
//! two (`0x92`), map of three (`0x83`, the named-field mode is the byte at writer `+0xb`, set to 1
//! by `0x41d4b30`), strings shortest form fixstr/str8/str16/str32 (`0x41c6110`), unsigned
//! values shortest form (`0x3d517e0` and its three width bodies).
//!
//! Scope: id generation and the duplicate-id / index gates around it ([`TokenIds`]). Not covered:
//! the other registration gates, the native map and token record layouts, allocation failure.

mod keccak;
mod registry;

pub use keccak::{keccak256, Keccak256};
pub use registry::{RegisterError, TokenIds, MAX_INDEX};

pub const ID_LEN: usize = 16;

/// The three fields `0x3c453f0` writes, in order: `name`, `szDecimals`, `weiDecimals`
/// (String at +8/+0x10 of the record, u8 at +0x18, u8 at +0x19).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenSpec<'a> {
    pub name: &'a str,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// `0x41c6110` tests the length as 32 bits; names of 2^32 bytes or more are not modelled.
    NameTooLong,
}

/// The exact bytes `0x38d2ce0` passes to the hash update.
pub fn preimage(spec: &TokenSpec<'_>, index: u64) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(48 + spec.name.len());
    out.push(0x92);
    out.push(0x83);
    put_str(&mut out, b"name")?;
    put_str(&mut out, spec.name.as_bytes())?;
    put_str(&mut out, b"szDecimals")?;
    put_uint(&mut out, u64::from(spec.sz_decimals));
    put_str(&mut out, b"weiDecimals")?;
    put_uint(&mut out, u64::from(spec.wei_decimals));
    put_uint(&mut out, index);
    Ok(out)
}

/// The full 32-byte value `0x38d2ce0` returns.
pub fn digest(spec: &TokenSpec<'_>, index: u64) -> Result<[u8; 32], Error> {
    Ok(keccak256(&preimage(spec, index)?))
}

/// The 16-byte id the caller keeps: the first 16 digest bytes.
pub fn token_id(spec: &TokenSpec<'_>, index: u64) -> Result<[u8; ID_LEN], Error> {
    let full = digest(spec, index)?;
    let mut id = [0; ID_LEN];
    id.copy_from_slice(&full[..ID_LEN]);
    Ok(id)
}

fn str_header(len: usize) -> Result<([u8; 5], usize), Error> {
    let len = u64::try_from(len).map_err(|_| Error::NameTooLong)?;
    let be = len.to_be_bytes();
    Ok(if len < 0x20 {
        ([0xa0 | len as u8, 0, 0, 0, 0], 1)
    } else if len < 0x100 {
        ([0xd9, be[7], 0, 0, 0], 2)
    } else if len < 0x1_0000 {
        ([0xda, be[6], be[7], 0, 0], 3)
    } else if len <= u64::from(u32::MAX) {
        ([0xdb, be[4], be[5], be[6], be[7]], 5)
    } else {
        return Err(Error::NameTooLong);
    })
}

fn put_str(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let (header, n) = str_header(bytes.len())?;
    out.extend_from_slice(&header[..n]);
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_uint(out: &mut Vec<u8>, value: u64) {
    let be = value.to_be_bytes();
    if value < 0x80 {
        out.push(be[7]);
    } else if value < 0x100 {
        out.extend_from_slice(&[0xcc, be[7]]);
    } else if value < 0x1_0000 {
        out.extend_from_slice(&[0xcd, be[6], be[7]]);
    } else if value <= u64::from(u32::MAX) {
        out.extend_from_slice(&[0xce, be[4], be[5], be[6], be[7]]);
    } else {
        out.push(0xcf);
        out.extend_from_slice(&be);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_length_limit_is_32_bits() {
        assert_eq!(str_header(u32::MAX as usize), Ok(([0xdb, 0xff, 0xff, 0xff, 0xff], 5)));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(str_header(u32::MAX as usize + 1), Err(Error::NameTooLong));
    }
}
