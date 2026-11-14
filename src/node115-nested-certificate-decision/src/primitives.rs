//! The reconstructed signature primitives: the digest builder `0x57e8d40` ([`crate::digest`]) and the
//! recovery wrapper `0x1536a90` ([`crate::recover`]) behind [`SignaturePrimitives`], with the curve routine as
//! the one injected part.

use crate::digest::{VARIANT, digest};
use crate::recover::{Secp256k1, recover_address};
use crate::signer::{SignaturePrimitives, VoteFrame};
use crate::sigmap::{Address, Signature};

/// Real digest and real wrapper around an injected curve routine.
pub struct NodePrimitives<C> {
    pub curve: C,
}

impl<C: Secp256k1> SignaturePrimitives for NodePrimitives<C> {
    /// # Panics
    /// If `variant` is not 1: only the variant-1 arm of the message serializer was read, and the verifier
    /// never passes another.
    fn digest(&self, variant: u64, frame: &VoteFrame) -> [u8; 32] {
        assert_eq!(variant, VARIANT, "only message variant 1 was read");
        digest(frame)
    }

    fn recover(&self, signature: &Signature, digest: &[u8; 32]) -> Option<Address> {
        recover_address(&self.curve, signature, digest).ok()
    }
}
