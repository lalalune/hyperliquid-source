//! Successful wire encoding selected by node115 `232b860 -> 2cd6de0`.
//!
//! Names below identify wire variants/offsets, not unproven protocol semantics.
//! This models typed live values, not invalid raw enum tags or native allocation
//! failure/lifetime behavior. See RE-017-node115-greeting-encoder-source.

pub use node115_nested_certificate_decision::sigmap::{Address, SigMap, SigRow, Signature};
pub use node115_varint_buffer_writer::Error;
use node115_varint_buffer_writer::write_u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedPart {
    pub at_800: u64,
    pub at_808: u64,
    pub bytes: [u8; 2048],
}

/// The inner wire discriminant is 0, 1, or 2. Hashes are copied as raw bytes.
pub enum Detail {
    Signatures {
        first: [u8; 32],
        left: Vec<Signature>,
        right: Vec<Signature>,
        last: [u8; 32],
    },
    Maps {
        first: [u8; 32],
        left: SigMap,
        right: SigMap,
        last: [u8; 32],
    },
    Fixed(Box<[FixedPart; 3]>),
}

pub enum Greeting {
    Kind0 {
        blob: Vec<u8>,
        at_98: u64,
        detail: Box<Detail>,
    },
    /// Wire order is +18, +8, +10, unlike the native field order.
    Kind1 {
        at_18: u64,
        at_8: u64,
        at_10: u64,
    },
    Kind2,
    Kind3,
    Kind4,
    Kind5,
}

/// Encode a typed greeting with live, valid containers. Ring geometry and
/// ordering must satisfy SigMap's contract (prefer its checked constructor).
/// All 256 recovery-byte values are preserved; this is not a crypto verifier.
/// The Error is the reused host varint writer's allocation error. Other Vec
/// allocations follow Rust's normal behavior, not native error-union semantics.
pub fn encode(value: &Greeting) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    match value {
        Greeting::Kind0 {
            blob,
            at_98,
            detail,
        } => {
            out.push(0);
            write_u64(&mut out, blob.len() as u64)?;
            out.extend_from_slice(blob);
            write_u64(&mut out, *at_98)?;
            match detail.as_ref() {
                Detail::Signatures {
                    first,
                    left,
                    right,
                    last,
                } => {
                    out.push(0);
                    out.extend_from_slice(first);
                    signatures(&mut out, left)?;
                    signatures(&mut out, right)?;
                    out.extend_from_slice(last);
                }
                Detail::Maps {
                    first,
                    left,
                    right,
                    last,
                } => {
                    out.push(1);
                    out.extend_from_slice(first);
                    map(&mut out, left)?;
                    map(&mut out, right)?;
                    out.extend_from_slice(last);
                }
                Detail::Fixed(parts) => {
                    out.push(2);
                    for part in parts.iter() {
                        write_u64(&mut out, part.at_800)?;
                        write_u64(&mut out, part.at_808)?;
                        out.extend_from_slice(&part.bytes);
                    }
                }
            }
        }
        Greeting::Kind1 { at_18, at_8, at_10 } => {
            out.push(1);
            for n in [at_18, at_8, at_10] {
                write_u64(&mut out, *n)?;
            }
        }
        Greeting::Kind2 => out.push(2),
        Greeting::Kind3 => out.push(3),
        Greeting::Kind4 => out.push(4),
        Greeting::Kind5 => out.push(5),
    }
    Ok(out)
}

fn signature(out: &mut Vec<u8>, sig: &Signature) -> Result<(), Error> {
    for word in sig[..64].chunks_exact(8) {
        write_u64(out, u64::from_le_bytes(word.try_into().unwrap()))?;
    }
    out.push(sig[64]);
    Ok(())
}

fn signatures(out: &mut Vec<u8>, values: &[Signature]) -> Result<(), Error> {
    write_u64(out, values.len() as u64)?;
    for sig in values {
        signature(out, sig)?;
    }
    Ok(())
}

fn map(out: &mut Vec<u8>, value: &SigMap) -> Result<(), Error> {
    let entries = value.entries();
    write_u64(out, entries.len() as u64)?;
    for (key, sig) in entries {
        out.extend_from_slice(key);
        signature(out, sig)?;
    }
    Ok(())
}
