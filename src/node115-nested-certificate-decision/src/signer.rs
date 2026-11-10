//! Per-signature check `0x57e8bd0` (slot `0x64e64b8`) and the seam where its two primitives plug in:
//! [`crate::primitives::NodePrimitives`] is the reconstruction (digest builder and recovery wrapper around an
//! injected curve routine); tests can also supply their own [`SignaturePrimitives`].

use crate::sigmap::{Address, Signature};
use crate::stake::StakeSet;

/// The 0x5c bytes the verifier builds on its stack for each signature and hands to the digest builder
/// as the message content: the 32 bytes at certificate `+0x48`, the pair at `+0x20/+0x28`, the words at
/// `+0x30`, `+0x38`, `+0x40`, then the signer address (frame offsets `+0x00`, `+0x20`, `+0x30`, `+0x38`,
/// `+0x40`, `+0x48`; relations-digest.tsv FB1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteFrame {
    pub hash: [u8; 32],
    pub pair: [u64; 2],
    pub f30: u64,
    pub f38: u64,
    pub f40: u64,
    pub signer: Address,
}

/// The two routines the check calls: the digest builder `0x57e8d40` and the recovery routine behind slot
/// `0x64e0ad8`. [`crate::primitives::NodePrimitives`] reconstructs both (the curve routine under the recovery
/// wrapper stays injected); any other implementation, such as a test's recording stand-in, is an assumption
/// about them. `variant` is the first word of the message (the verifier passes 1).
pub trait SignaturePrimitives {
    fn digest(&self, variant: u64, frame: &VoteFrame) -> [u8; 32];
    /// `None` when native recovery returns its error result.
    fn recover(&self, signature: &Signature, digest: &[u8; 32]) -> Option<Address>;
}

/// True iff `address` is in the stake map and recovery over the digest of `frame` yields `address`.
/// The digest is not computed for a non-member, and recovery is not run if the digest is.
pub fn signer_check<P: SignaturePrimitives>(
    primitives: &P,
    variant: u64,
    frame: &VoteFrame,
    address: &Address,
    signature: &Signature,
    set: &StakeSet,
) -> bool {
    if !set.stakes.contains(address) {
        return false;
    }
    let digest = primitives.digest(variant, frame);
    primitives.recover(signature, &digest).as_ref() == Some(address)
}
