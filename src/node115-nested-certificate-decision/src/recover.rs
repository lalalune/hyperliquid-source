//! The recovery wrapper `0x1536a90` (slot `0x64e0ad8`): from a 65 byte signature and a 32 byte digest to the
//! 20 byte address, around three calls into the curve library that is compiled into the node.
//!
//! What the wrapper does (relations-digest.tsv RC1..RC9): reads the signature as `r` (bytes 0..32), `s` (bytes
//! 32..64) and `v` (byte 64); passes `r` and `s` byte reversed to the compact signature parser behind slot
//! `0x64df9d8`; maps `v` to a recovery id (0 and 27 give 0, 1 and 28 give 1, 2..=26 and 29..=34 are error kind
//! 6 without any curve call, from 35 on the id is `(!v) & 1`); recovers the public key through slot
//! `0x64df9e0`; serializes it uncompressed through slot `0x64df9e8`; and returns bytes 12..32 of the Keccak-256
//! of the 64 bytes after the format byte. A failing parse or recovery is error kind 3.
//!
//! **Boundary.** The three slots point into `0x632b660`, `0x632b7b0` and `0x632b480`, which this crate does
//! not reconstruct: their argument-check texts and the group constants around them are those of the public
//! secp256k1 library (relations-digest.tsv SP1, SS1, SR1; data-pins.tsv), which is how they are named. This
//! crate states the three calls as the trait [`Secp256k1`]; an implementation of it, not this crate, decides
//! whether a signature is valid on the curve. Serializing the key is folded into the trait: it returns the
//! 64 bytes `X || Y` that follow the format byte.

use crate::keccak::keccak256;
use crate::sigmap::{Address, Signature};

/// The curve routine behind slots `0x64df9d8` + `0x64df9e0` + `0x64df9e8`.
pub trait Secp256k1 {
    /// `r` and `s` big endian, recovery id 0..=3, digest. `None` when parsing or recovery reports failure.
    /// `Some` holds the uncompressed public key without its leading `0x04`.
    fn recover(&self, r: &[u8; 32], s: &[u8; 32], recovery_id: u8, digest: &[u8; 32]) -> Option<[u8; 64]>;
}

/// The two error kinds the wrapper builds with `0x14cca30`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverError {
    /// Kind 6: `v` is not one of the accepted values; the curve routine is not called.
    BadRecoveryByte,
    /// Kind 3: the curve routine reported failure.
    CurveFailure,
}

impl RecoverError {
    pub fn kind(self) -> u8 {
        match self {
            RecoverError::BadRecoveryByte => 6,
            RecoverError::CurveFailure => 3,
        }
    }
}

/// RC2..RC5: the recovery id for the byte `v`.
pub fn recovery_id(v: u8) -> Option<u8> {
    match v {
        0 | 27 => Some(0),
        1 | 28 => Some(1),
        2..=26 | 29..=34 => None,
        _ => Some(!v & 1),
    }
}

fn reversed<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (o, b) in out.iter_mut().zip(bytes.iter().rev()) {
        *o = *b;
    }
    out
}

/// RC1..RC9.
pub fn recover_address<C: Secp256k1>(curve: &C, signature: &Signature, digest: &[u8; 32]) -> Result<Address, RecoverError> {
    let id = recovery_id(signature[64]).ok_or(RecoverError::BadRecoveryByte)?;
    let r: [u8; 32] = reversed(&signature[0..32]);
    let s: [u8; 32] = reversed(&signature[32..64]);
    let key = curve.recover(&r, &s, id, digest).ok_or(RecoverError::CurveFailure)?;
    let mut address = [0u8; 20];
    address.copy_from_slice(&keccak256(&key)[12..32]);
    Ok(address)
}
