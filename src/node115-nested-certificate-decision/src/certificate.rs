//! The two records `0x595fd20` and `0x595f880` read: the certificate (input) and the context.

use crate::sigmap::SigMap;

/// The input record, split at native offsets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// `+0x00..+0x20`: the signature collection.
    pub sigs: SigMap,
    /// Words at `+0x20` and `+0x28`.
    pub pair: [u64; 2],
    pub f30: u64,
    pub f38: u64,
    /// `+0x40`: also the round the verifier asks the stake-set provider about.
    pub f40: u64,
    /// `+0x48..+0x68`: the first 32 bytes of every signed frame.
    pub hash: [u8; 32],
}

/// The context words this flow reads itself: `+0x50`, `+0x58` (compared with the certificate pair) and
/// `+0x88` (the double behind the quorum fraction, as raw bits). The provider reads more of the native
/// context and is a boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub pair: [u64; 2],
    pub quorum_fraction_bits: u64,
}
