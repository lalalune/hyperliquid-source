//! Safe logical reconstruction of node #115's final LZ4 literal emitter.
//!
//! Evidence: RE-012-lz4-literal-encoder-115. Errors stand for captured failure
//! boundaries, not native panic payloads or an assertion about catchability.
//! Input and sink must not alias; Rust borrows establish that domain condition.
#![no_std]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Safe API rejects a descriptor the original pointer ABI does not validate.
    Domain,
    /// Native checked end minus anchor borrows, before any output access.
    Anchor,
    Token,
    Extension,
    Literals,
}

/// Append one final literal sequence, preserving all earlier successful writes.
///
/// `end` is an exclusive input count; bytes beyond it are ignored. `used` is
/// the caller's initialized sink prefix length. On a captured failure boundary
/// it records the last completed store, with that written prefix retained.
/// The scalar extension loop preserves logical output and failure state of the
/// target's grouped-255 optimization; store granularity is not reproduced.
/// Domain errors are checked first and leave the sink and `used` untouched.
pub fn encode(
    input: &[u8],
    anchor: usize,
    end: usize,
    sink: &mut [u8],
    used: &mut usize,
) -> Result<(), Error> {
    if *used > sink.len() || end > input.len() {
        return Err(Error::Domain);
    }
    let count = end.checked_sub(anchor).ok_or(Error::Anchor)?;
    if *used >= sink.len() {
        return Err(Error::Token);
    }
    sink[*used] = (count.min(15) as u8) << 4;
    *used += 1;
    if count >= 15 {
        let mut excess = count - 15;
        while excess >= 255 {
            if *used == sink.len() {
                return Err(Error::Extension);
            }
            sink[*used] = 255;
            *used += 1;
            excess -= 255;
        }
        if *used >= sink.len() {
            return Err(Error::Extension);
        }
        sink[*used] = excess as u8;
        *used += 1;
    }
    // The native helper checks whole-copy capacity before copying any literal.
    let next = used.checked_add(count).ok_or(Error::Literals)?;
    if next > sink.len() {
        return Err(Error::Literals);
    }
    sink[*used..next].copy_from_slice(&input[anchor..end]);
    *used = next;
    Ok(())
}
