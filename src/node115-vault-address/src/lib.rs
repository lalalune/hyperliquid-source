//! Node #115 `createVault`: the vault address derived from the creator and the request.
//!
//! Static reconstruction of what the node hashes to name a new vault, read from the pinned instructions in
//! `research/work-items/RE-005-node115-vault-address-derivation`; nothing here was observed from a running node,
//! and no behavioural equivalence with the node is claimed. Role names (`creator`, the request fields, "vault
//! address") are inferred from key literals, offsets and position; what the 20 creator bytes are in the dispatcher
//! (the action's signing user?) was not traced.
//!
//! * [`derive_vault_address`] is the entry function `0x46dba10`: it builds the pair
//!   `["0x" + lower-case hex of the 20 creator bytes, {"name", "description", "initialUsd", "nonce"}]` as
//!   MessagePack (named map, shortest forms), hashes it with Keccak-256 and keeps the **first 20** digest bytes.
//!   The request's `maxUsdcFee` is never an input: the entry stores option tag 0 in the copy it serializes.
//!   Within this model it applies no name or amount limit of its own (the real caller does, next item); the model
//!   covers strings shorter than 2^32 bytes and assumes no allocation failure and no unwind.
//! * [`caller_address`] adds the two checks the only analysed caller `0x2bdd3b0` makes around that call: a name of
//!   101 bytes or more is rejected **before** anything is hashed (error tag `0x158`); after the address exists,
//!   `initialUsd` and then `maxUsdcFee` (when present) are rejected from `0x0ccccccccccccccc` upwards (error tag
//!   `0x154`). **`Ok` means only that these two checks passed. It is not "the vault was created"**: what the
//!   caller does with an accepted address (probes of three containers, the creation call `0x2c3c800`) is not
//!   modelled.
//!
//! Not modelled: allocation failure, unwind, the native result record layout, strings of 2^32 bytes or more, and
//! the order of this caller's other checks (the state gate at `+0x7d0`). Only valid UTF-8 names and descriptions
//! are representable, as in the node's `String` fields.

mod keccak;

pub use keccak::{keccak256, Keccak256};

/// Length of the creator and of the derived address in bytes.
pub const ADDRESS_LEN: usize = 20;
/// Success word the entry function writes at the start of its result (`0x46dbb34`).
pub const ENTRY_SUCCESS_WORD: u16 = 0x1a2;
/// Error tag of the caller for a name that is too long (`0x2bdd448`, `0x54a4638`).
pub const NAME_REJECT_TAG: u16 = 0x158;
/// Error tag of the caller for an amount at or above [`AMOUNT_BOUND`] (`0x2bdd4f0`).
pub const AMOUNT_REJECT_TAG: u16 = 0x154;
/// Longest name the caller lets through to the derivation: it rejects `len >= 0x65` (`0x2bdd428`).
pub const NAME_LEN_LIMIT: usize = 100;
/// The caller rejects `initialUsd` / `maxUsdcFee` that are not below this (`0x2bdd49b`: `floor(2^64 / 20)`).
pub const AMOUNT_BOUND: u64 = 0x0ccc_cccc_cccc_cccc;

/// The fields of the `createVault` request that the analysed code reads (names from the key literals).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateVaultRequest {
    /// `maxUsdcFee`: ignored by the derivation, checked by the caller.
    pub max_usdc_fee: Option<u64>,
    pub name: String,
    pub description: String,
    pub initial_usd: u64,
    pub nonce: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// A string of 2^32 bytes or more: the string writer's length tests are 32-bit and this is not modelled.
    StringTooLong,
}

/// Why the analysed caller stops before it hands the address on.
#[derive(Debug, PartialEq, Eq)]
pub enum CallerReject {
    /// Tag [`NAME_REJECT_TAG`], decided before the digest is computed.
    NameTooLong { len: usize },
    /// Tag [`AMOUNT_REJECT_TAG`], decided after the address was derived; the first offending value.
    AmountTooLarge { value: u64 },
    Derivation(Error),
}

impl CallerReject {
    pub fn tag(&self) -> Option<u16> {
        match self {
            CallerReject::NameTooLong { .. } => Some(NAME_REJECT_TAG),
            CallerReject::AmountTooLarge { .. } => Some(AMOUNT_REJECT_TAG),
            CallerReject::Derivation(_) => None,
        }
    }
}

fn put_str_header(out: &mut Vec<u8>, len: usize) -> Result<(), Error> {
    let len = len as u64;
    if len < 0x20 {
        out.push(0xa0 | len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0xd9, len as u8]);
    } else if len < 0x1_0000 {
        out.extend_from_slice(&[0xda, (len >> 8) as u8, len as u8]);
    } else if len <= u64::from(u32::MAX) {
        out.extend_from_slice(&[0xdb, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    } else {
        return Err(Error::StringTooLong);
    }
    Ok(())
}

fn put_str(out: &mut Vec<u8>, text: &[u8]) -> Result<(), Error> {
    put_str_header(out, text.len())?;
    out.extend_from_slice(text);
    Ok(())
}

fn put_uint(out: &mut Vec<u8>, value: u64) {
    let be = value.to_be_bytes();
    if value < 0x80 {
        out.push(value as u8);
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

fn creator_text(creator: &[u8; ADDRESS_LEN]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(2 + 2 * ADDRESS_LEN);
    text.push_str("0x");
    for byte in creator {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    text
}

/// The MessagePack bytes the digest entry hashes (pair serializer `0x41d4c70`, creator `0x41d3a50`, map `0x46c9450`).
pub fn address_preimage(creator: &[u8; ADDRESS_LEN], request: &CreateVaultRequest) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.push(0x92);
    put_str(&mut out, creator_text(creator).as_bytes())?;
    out.push(0x84);
    put_str(&mut out, b"name")?;
    put_str(&mut out, request.name.as_bytes())?;
    put_str(&mut out, b"description")?;
    put_str(&mut out, request.description.as_bytes())?;
    put_str(&mut out, b"initialUsd")?;
    put_uint(&mut out, request.initial_usd);
    put_str(&mut out, b"nonce")?;
    put_uint(&mut out, request.nonce);
    Ok(out)
}

/// Keccak-256 of [`address_preimage`] (the 32 bytes `0x38d2ef0` returns).
pub fn address_digest(creator: &[u8; ADDRESS_LEN], request: &CreateVaultRequest) -> Result<[u8; 32], Error> {
    Ok(keccak256(&address_preimage(creator, request)?))
}

/// The entry function `0x46dba10`: the first 20 digest bytes. `max_usdc_fee` has no influence.
pub fn derive_vault_address(creator: &[u8; ADDRESS_LEN], request: &CreateVaultRequest) -> Result<[u8; ADDRESS_LEN], Error> {
    let digest = address_digest(creator, request)?;
    let mut address = [0; ADDRESS_LEN];
    address.copy_from_slice(&digest[..ADDRESS_LEN]);
    Ok(address)
}

/// The analysed caller `0x2bdd3b0` up to the point where it hands the address to its state probes.
///
/// `Ok(address)` means only that the name-length and amount checks passed; it does not mean a vault was created.
pub fn caller_address(creator: &[u8; ADDRESS_LEN], request: &CreateVaultRequest) -> Result<[u8; ADDRESS_LEN], CallerReject> {
    if request.name.len() > NAME_LEN_LIMIT {
        return Err(CallerReject::NameTooLong { len: request.name.len() });
    }
    let address = derive_vault_address(creator, request).map_err(CallerReject::Derivation)?;
    if request.initial_usd >= AMOUNT_BOUND {
        return Err(CallerReject::AmountTooLarge { value: request.initial_usd });
    }
    if let Some(fee) = request.max_usdc_fee {
        if fee >= AMOUNT_BOUND {
            return Err(CallerReject::AmountTooLarge { value: fee });
        }
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn string_length_limit_is_32_bits() {
        let mut out = Vec::new();
        put_str_header(&mut out, u32::MAX as usize).unwrap();
        assert_eq!(out, [0xdb, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(put_str_header(&mut out, u32::MAX as usize + 1), Err(Error::StringTooLong));
    }
}
