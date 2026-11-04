#![no_std]
//! Complete conditional match-sequence emitter in both node115 LZ4 compressors.
//! Native pointer/Vec/panic ABI and match selection are outside this API.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Safe adapter check, not an error supplied by the native pointer ABI.
    Domain,
    Token,
    LiteralExtension,
    Literals,
    Offset,
    MatchExtension,
}

fn byte(sink: &mut [u8], used: &mut usize, value: u8, error: Error) -> Result<(), Error> {
    if *used >= sink.len() {
        return Err(error);
    }
    sink[*used] = value;
    *used += 1;
    Ok(())
}

fn excess(
    sink: &mut [u8],
    used: &mut usize,
    mut remaining: u64,
    error: Error,
) -> Result<(), Error> {
    while remaining >= 255 {
        byte(sink, used, 255, error)?;
        remaining -= 255;
    }
    // Including zero when the amount is an exact multiple of 255.
    byte(sink, used, remaining as u8, error)
}

/// Emit token, literal-length extension, literals, LE16 offset, match extension.
///
/// `additional_match` is the forward helper's result beyond the initial four
/// matched bytes, not total match length. `distance` represents the caller's
/// already-selected u16 distance, including zero if supplied; this stage does
/// not validate the match. Input/output cannot alias under the Rust borrows.
/// Successful writes remain visible when a later stage returns an error.
/// Whole literal and two-byte offset capacity checks are atomic logical stages;
/// extension bytes commit individually. No complete-operation rollback occurs.
pub fn emit(
    literals: &[u8],
    additional_match: u64,
    distance: u16,
    sink: &mut [u8],
    used: &mut usize,
) -> Result<(), Error> {
    if *used > sink.len() {
        return Err(Error::Domain);
    }
    let token = ((literals.len().min(15) as u8) << 4) | additional_match.min(15) as u8;
    byte(sink, used, token, Error::Token)?;
    if literals.len() >= 15 {
        excess(
            sink,
            used,
            (literals.len() - 15) as u64,
            Error::LiteralExtension,
        )?;
    }
    let next = used.checked_add(literals.len()).ok_or(Error::Literals)?;
    if next > sink.len() {
        return Err(Error::Literals);
    }
    sink[*used..next].copy_from_slice(literals);
    *used = next;
    let after_offset = used.checked_add(2).ok_or(Error::Offset)?;
    if after_offset > sink.len() {
        return Err(Error::Offset);
    }
    sink[*used..after_offset].copy_from_slice(&distance.to_le_bytes());
    *used = after_offset;
    if additional_match >= 15 {
        excess(sink, used, additional_match - 15, Error::MatchExtension)?;
    }
    Ok(())
}
