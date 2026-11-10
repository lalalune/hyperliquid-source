//! The nested certificate decision `0x595fd20..0x596000d`.
//!
//! It compares the certificate pair (`+0x20`, `+0x28`) with the context pair (`+0x50`, `+0x58`) and maps
//! the result to one of the output tags `0x00`, `0x05`, `0x06`, `0x2d`, `0x2e`, to a forwarded verifier
//! result, or to a diagnostic call that never returns. [`decide`] is the decision core with its two
//! callees injected (this is how the 621-case corpus of round 1 drives it); [`decide_nested`] wires in
//! the reconstructed equality helper and verifier.

use crate::certificate::{Certificate, Context};
use crate::equality::sig_maps_equal;
use crate::sigmap::SigMap;
use crate::signer::SignaturePrimitives;
use crate::verifier::{StakeSetProvider, Verdict, verify};

/// Output tag when the pairs match and `f30` is below the second pair word.
pub const TAG_BEHIND: u8 = 0x05;
/// Output tag when the pairs match, `f30` equals the second pair word and the empty-shape test fails.
pub const TAG_UNEQUAL: u8 = 0x06;
/// Output tag of the pair-mismatch record (payload: certificate pair, context pair).
pub const TAG_MISMATCH: u8 = 0x00;
/// Output tag of the three-word ordering failure.
pub const TAG_OUT_OF_ORDER: u8 = 0x2d;
/// The verifier's continue tag, also written by the empty-shape success path.
pub const TAG_CONTINUE: u8 = 0x2e;

/// What the decision needs to know about a verifier result: its tag byte. `0x2e` means continue; any
/// other result is a rejection that the `A > C` arm drops (natively tags `0x10`, `0x13`, `0x20` free a
/// payload there; the reconstructed verifier cannot produce them).
pub trait VerifierResult {
    fn tag(&self) -> u8;
}

impl VerifierResult for Verdict {
    fn tag(&self) -> u8 {
        match self {
            Verdict::Accepted => TAG_CONTINUE,
            Verdict::Rejected(r) => r.tag(),
        }
    }
}

/// What `0x595fd20` leaves in its output record.
#[derive(Debug, PartialEq, Eq)]
pub enum Output<V> {
    /// Tag `0x05`.
    Behind,
    /// Tag `0x06`.
    Unequal,
    /// Tag `0x00` with payload words `cert`, `ctx` at output `+8..+0x28`. A verifier result produced on the
    /// way (`A > C`) has been dropped.
    Mismatch { cert: [u64; 2], ctx: [u64; 2] },
    /// Tag `0x2d` with payload words at output `+8`, `+0x10`, `+0x18`.
    OutOfOrder { f30: u64, f38: u64, f40: u64 },
    /// Tag `0x2e` from the empty-shape path.
    Continue,
    /// The verifier result written straight into the output.
    Forwarded(V),
    /// The verifier accepted although the certificate pair is ahead of the context pair: the native code
    /// calls a no-return function with the message "observed qc for newer hardfork, crashing.
    /// current=.., observed=.., qc=.." and has no normal return.
    Diverges { current: [u64; 2], observed: [u64; 2] },
}

impl<V: VerifierResult> Output<V> {
    /// The native tag byte, or `None` when the function does not return.
    pub fn tag(&self) -> Option<u8> {
        Some(match self {
            Output::Behind => TAG_BEHIND,
            Output::Unequal => TAG_UNEQUAL,
            Output::Mismatch { .. } => TAG_MISMATCH,
            Output::OutOfOrder { .. } => TAG_OUT_OF_ORDER,
            Output::Continue => TAG_CONTINUE,
            Output::Forwarded(v) => v.tag(),
            Output::Diverges { .. } => return None,
        })
    }
}

/// The record the native code builds on the stack for the equality helper: the empty-shape twin of the
/// certificate. Words `+0x00..+0x20` are `0, 8, 0, 0` (an empty ring: capacity 0, dangling buffer, head 0,
/// length 0), then the pair, then the second pair word three times, then 32 zero bytes.
pub fn empty_reference(cert: &Certificate) -> Certificate {
    let b = cert.pair[1];
    Certificate { sigs: SigMap::empty_ring(), pair: cert.pair, f30: b, f38: b, f40: b, hash: [0; 32] }
}

/// Decision core. `equals_reference(cert, reference)` stands for `0x4e08870`, `verify(cert, ctx)` for
/// `0x595f880`; each runs at most once, exactly where the native code calls it.
pub fn decide<V: VerifierResult>(
    cert: &Certificate,
    ctx: &Context,
    equals_reference: impl FnOnce(&Certificate, &Certificate) -> bool,
    verify: impl FnOnce(&Certificate, &Context) -> V,
) -> Output<V> {
    let [a, b] = cert.pair;
    let [c, d] = ctx.pair;
    if a == c && b == d {
        if cert.f30 < b {
            return Output::Behind;
        }
        if cert.f30 == b {
            if cert.f38 != b || cert.f40 != b || cert.hash != [0; 32] {
                return Output::Unequal;
            }
            return if equals_reference(cert, &empty_reference(cert)) { Output::Continue } else { Output::Unequal };
        }
        // f30 > b: the three words must satisfy b <= f40 <= f38 < f30.
        if cert.f38 < cert.f30 && b <= cert.f40 && cert.f40 <= cert.f38 {
            return Output::Forwarded(verify(cert, ctx));
        }
        return Output::OutOfOrder { f30: cert.f30, f38: cert.f38, f40: cert.f40 };
    }
    if a > c {
        let result = verify(cert, ctx);
        if result.tag() == TAG_CONTINUE {
            return Output::Diverges { current: ctx.pair, observed: cert.pair };
        }
        drop(result);
    }
    Output::Mismatch { cert: cert.pair, ctx: ctx.pair }
}

/// The whole nested certificate decision: [`decide`] with the reconstructed helper (`0x4e08870` over the
/// signature collections) and verifier (`0x595f880`). Only the stake-set provider and the signature
/// primitives are supplied from outside.
pub fn decide_nested<P: StakeSetProvider, S: SignaturePrimitives>(
    cert: &Certificate,
    ctx: &Context,
    provider: &P,
    primitives: &S,
) -> Output<Verdict> {
    decide(
        cert,
        ctx,
        |c, reference| sig_maps_equal(&c.sigs, &reference.sigs),
        |c, x| verify(c, x, provider, primitives),
    )
}
