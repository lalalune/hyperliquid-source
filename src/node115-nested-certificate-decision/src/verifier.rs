//! The certificate verifier `0x595f880`: stake set for the round, signer collection, quorum, then one
//! signature check per entry.

use crate::certificate::{Certificate, Context};
use crate::collect::{Collected, collect_signers};
use crate::quorum::quorum;
use crate::signer::{SignaturePrimitives, VoteFrame, signer_check};
use crate::sigmap::Address;
use crate::stake::StakeSet;

/// Why the verifier stopped. The tag is the first byte of the native 0x48 byte result record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Tag `0x28`, round at `+8`: the provider `0x595e5c0` has no stake set for the round (its only
    /// result tags are `0x2e` and `0x28`; see [`crate::history`]).
    NoStakeSet { round: u64 },
    /// Tag `0x2c`, address at `+1`: the first certificate key (in visiting order) absent from the stake map.
    UnknownSigner { address: Address },
    /// Tag `0x07`: the quorum `0x595bc40` is false.
    QuorumNotReached,
    /// Tag `0x02`: a signature check is false.
    BadSignature,
}

impl Rejection {
    pub fn tag(&self) -> u8 {
        match self {
            Rejection::NoStakeSet { .. } => 0x28,
            Rejection::UnknownSigner { .. } => 0x2c,
            Rejection::QuorumNotReached => 0x07,
            Rejection::BadSignature => 0x02,
        }
    }
}

/// Tag `0x2e` (only byte 0 written) or one of the rejections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Rejected(Rejection),
}

/// What `0x595f880` asks of the stake-set provider `0x595e5c0` (slot `0x64e64b0`): the set for a round,
/// or `None` for its tag `0x28`. [`crate::history::StakeHistory`] is the reconstruction; the trait lets a
/// test stand in for the state.
pub trait StakeSetProvider {
    fn stake_set(&self, ctx: &Context, round: u64) -> Option<&StakeSet>;
}

/// The reconstructed verifier. Order of effects: provider(`f40`), collector, quorum, then for each entry
/// in visiting order the signature check with variant 1, stopping at the first failure.
pub fn verify<P: StakeSetProvider, S: SignaturePrimitives>(
    cert: &Certificate,
    ctx: &Context,
    provider: &P,
    primitives: &S,
) -> Verdict {
    let round = cert.f40;
    let Some(set) = provider.stake_set(ctx, round) else {
        return Verdict::Rejected(Rejection::NoStakeSet { round });
    };
    let signers = match collect_signers(set, &cert.sigs) {
        Collected::Signers(s) => s,
        Collected::UnknownSigner(address) => return Verdict::Rejected(Rejection::UnknownSigner { address }),
    };
    if !quorum(ctx.quorum_fraction_bits, set, &signers) {
        return Verdict::Rejected(Rejection::QuorumNotReached);
    }
    for (key, signature) in cert.sigs.entries() {
        let frame = VoteFrame {
            hash: cert.hash,
            pair: cert.pair,
            f30: cert.f30,
            f38: cert.f38,
            f40: cert.f40,
            signer: *key,
        };
        if !signer_check(primitives, 1, &frame, key, signature, set) {
            return Verdict::Rejected(Rejection::BadSignature);
        }
    }
    Verdict::Accepted
}
