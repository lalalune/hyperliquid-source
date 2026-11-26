//! Selected variant-0 block serialization and its caller decision.
//! Logical normalized inputs; no native ABI or real signature verification.
use node115_nested_certificate_decision::keccak::keccak256;
use node115_nested_certificate_decision::sigmap::Signature;
use node115_nested_certificate_decision::signer::SignaturePrimitives;
use node115_nested_certificate_decision::verifier::StakeSetProvider;
use node115_nested_certificate_decision::{Certificate, Context, Output, Verdict, decide_nested};
use node115_varint_buffer_writer::write_u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeoutRow {
    pub key: [u8; 20],
    pub value: u64,
    pub signature: Signature,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parent {
    Simple(Certificate),
    Composite {
        primary: Certificate,
        round: u64,
        timeout_rows: Vec<TimeoutRow>,
        optional: Option<Certificate>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub address: [u8; 20],
    pub hashes: Vec<[u8; 32]>,
    pub timestamp: Timestamp,
    pub parent: Parent,
}

fn u64v(out: &mut Vec<u8>, n: u64) {
    write_u64(out, n).expect("host allocation failure");
}
fn signature(out: &mut Vec<u8>, sig: &Signature) {
    for part in sig[..64].chunks_exact(8) {
        u64v(out, u64::from_le_bytes(part.try_into().unwrap()));
    }
    out.push(sig[64]);
}
fn certificate(out: &mut Vec<u8>, cert: &Certificate) {
    for n in [cert.pair[0], cert.pair[1], cert.f30, cert.f38, cert.f40] {
        u64v(out, n);
    }
    out.extend_from_slice(&cert.hash);
    let entries = cert.sigs.entries();
    u64v(out, entries.len() as u64);
    for (key, sig) in entries {
        out.extend_from_slice(key);
        signature(out, sig);
    }
}
/// Serialize the selected logical variant 0. Timestamp fields must be the
/// correctly projected native seconds/nanos; timeout rows are supplied in
/// native iterator order. Native allocation/error ABI is not modeled.
pub fn serialize_variant_zero(block: &Block) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(&block.address);
    u64v(&mut out, block.hashes.len() as u64);
    for hash in &block.hashes {
        out.extend_from_slice(hash);
    }
    let secs = block.timestamp.seconds;
    u64v(&mut out, ((secs as u64) << 1) ^ ((secs >> 63) as u64));
    u64v(&mut out, u64::from(block.timestamp.nanos));
    match &block.parent {
        Parent::Simple(cert) => {
            u64v(&mut out, 0);
            certificate(&mut out, cert);
        }
        Parent::Composite {
            primary,
            round,
            timeout_rows,
            optional,
        } => {
            u64v(&mut out, 1);
            u64v(&mut out, *round);
            certificate(&mut out, primary);
            u64v(&mut out, timeout_rows.len() as u64);
            for row in timeout_rows {
                out.extend_from_slice(&row.key);
                u64v(&mut out, row.value);
                signature(&mut out, &row.signature);
            }
            match optional {
                None => out.push(0),
                Some(cert) => {
                    out.push(1);
                    certificate(&mut out, cert);
                }
            }
        }
    }
    out
}
/// Domain-separated variant-0 digest; uses the prior Keccak implementation.
pub fn block_digest(block: &Block) -> [u8; 32] {
    let mut preimage = b"Hyperliquid Consensus Payload".to_vec();
    preimage.extend_from_slice(&serialize_variant_zero(block));
    keccak256(&preimage)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision<F> {
    FrontRejected(F),
    Nested(Output<Verdict>),
    ParentDigestMismatch,
    BlockDigestMismatch,
    RoundMismatch,
    Continue,
}
impl<F> Decision<F> {
    /// Known native caller tag. Front-end failures retain their supplied value;
    /// a nested no-return path has no return tag.
    pub fn raw_tag(&self) -> Option<u8> {
        match self {
            Self::FrontRejected(_) => None,
            Self::Nested(value) => value.tag(),
            Self::ParentDigestMismatch => Some(0x1d),
            Self::BlockDigestMismatch => Some(0x1e),
            Self::RoundMismatch => Some(0x1f),
            Self::Continue => Some(0x2e),
        }
    }
}
/// Apply the selected caller. The supplied front-end receives the same block,
/// nested certificate and context; it must implement the prior native front
/// check. Nested verification reuses the existing implementation and its
/// explicit stake-provider / signature-primitive dependencies.
#[allow(clippy::too_many_arguments)] // Retain the selected caller's independent inputs.
pub fn decide<F, P: StakeSetProvider, S: SignaturePrimitives>(
    block: &Block,
    nested: &Certificate,
    ctx: &Context,
    expected_parent: [u8; 32],
    caller_round: u64,
    front: impl FnOnce(&Block, &Certificate, &Context) -> Result<(), F>,
    provider: &P,
    primitives: &S,
) -> Decision<F> {
    if let Err(error) = front(block, nested, ctx) {
        return Decision::FrontRejected(error);
    }
    let result = decide_nested(nested, ctx, provider, primitives);
    if result.tag() != Some(0x2e) {
        return Decision::Nested(result);
    }
    let (hash, round) = match &block.parent {
        Parent::Simple(cert) => (cert.hash, cert.f30),
        Parent::Composite {
            primary,
            round,
            optional,
            ..
        } => (optional.as_ref().unwrap_or(primary).hash, *round),
    };
    if hash != expected_parent {
        return Decision::ParentDigestMismatch;
    }
    if block_digest(block) != nested.hash {
        return Decision::BlockDigestMismatch;
    }
    if round.saturating_add(1) != caller_round.saturating_add(1) {
        return Decision::RoundMismatch;
    }
    Decision::Continue
}
