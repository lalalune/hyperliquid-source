#![forbid(unsafe_code)]
//! Construct the proved bytes of an already admitted Visor move request.
//!
//! This is a chosen safe value API, not the original ABI. It performs no
//! preflight, process, shell, filesystem or network operation. See the evidence
//! packet for the native storage/allocator/ordinary-return premises.

use std::collections::TryReserveError;

/// The sufficient combined-input bound used by the native value proof.
pub const MAX_COMBINED_INPUT_BYTES: u64 = (1_u64 << 61) - 2;

/// Refusal outside the chosen proof domain, not a captured error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LengthOutsideProofDomain;

/// Errors of this safe API; only the NUL condition is a target result projection.
#[derive(Debug)]
pub enum EncodeError {
    /// The native mode-zero construction would report an embedded NUL.
    /// This does not reproduce the opaque native error object's value/layout.
    EmbeddedNul,
    /// Chosen safe refusal of an unsupported length/index domain.
    LengthOutsideProofDomain,
    /// Host Rust allocation failure, not an original allocator result.
    AllocationFailure(TryReserveError),
}

/// Owned request bytes. This is not the target's capacity/pointer/length ABI.
#[derive(Debug, PartialEq, Eq)]
pub struct MoveRequest {
    command: Vec<u8>,
}

impl MoveRequest {
    pub fn command_bytes(&self) -> &[u8] {
        &self.command
    }

    /// The observed raw option byte; it does not guarantee quiet wrapping.
    pub fn option_byte(&self) -> u8 {
        1
    }
}

/// Return the sufficient output bound without creating slices or allocating.
///
/// This companion is a newly chosen admission API, not another recovered
/// native function. Giant length cases can be checked without unsafe inputs.
pub fn admitted_output_bound(
    source_len: u64,
    destination_len: u64,
) -> Result<u64, LengthOutsideProofDomain> {
    let sum = source_len
        .checked_add(destination_len)
        .ok_or(LengthOutsideProofDomain)?;
    if sum > MAX_COMBINED_INPUT_BYTES {
        return Err(LengthOutsideProofDomain);
    }
    Ok(4 * sum + 4)
}

/// Encode source and destination after the opaque preflight admitted them.
///
/// Valid `str` supplies canonical UTF-8. Empty/all-W operands are omitted;
/// retained operands preserve every original byte, including surrounding W.
/// The exact captured W set is used, not the host Unicode whitespace version.
/// A NUL returns `EmbeddedNul`. All other supported inputs produce the proved
/// bytes on successful host allocation. Length/NUL precheck order and fallible
/// host allocation are chosen API policies, not native failure timing.
pub fn encode_admitted_move(source: &str, destination: &str) -> Result<MoveRequest, EncodeError> {
    let source_len =
        u64::try_from(source.len()).map_err(|_| EncodeError::LengthOutsideProofDomain)?;
    let destination_len =
        u64::try_from(destination.len()).map_err(|_| EncodeError::LengthOutsideProofDomain)?;
    let bound = admitted_output_bound(source_len, destination_len)
        .map_err(|_| EncodeError::LengthOutsideProofDomain)?;
    let capacity = usize::try_from(bound).map_err(|_| EncodeError::LengthOutsideProofDomain)?;
    if source.as_bytes().contains(&0) || destination.as_bytes().contains(&0) {
        return Err(EncodeError::EmbeddedNul);
    }

    let mut command = Vec::new();
    command
        .try_reserve_exact(capacity)
        .map_err(EncodeError::AllocationFailure)?;
    command.extend_from_slice(b"mv");
    for input in [source, destination] {
        if input.chars().all(is_target_whitespace) {
            continue;
        }
        command.push(b' ');
        append_quoted(&mut command, input.as_bytes());
    }
    debug_assert!(command.len() <= capacity);
    Ok(MoveRequest { command })
}

fn is_target_whitespace(c: char) -> bool {
    matches!(
        c as u32,
        0x09..=0x0d | 0x20 | 0x85 | 0xa0 | 0x1680 | 0x2000..=0x200a
            | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000
    )
}

fn admission(byte: u8) -> u8 {
    let raw = matches!(
        byte,
        b'+' | b'-' | b'.' | b'/' | b'0'..=b'9' | b':' | b'@'
            | b'A'..=b'Z' | b']' | b'_' | b'a'..=b'z'
    );
    let single = !matches!(byte, b'\'' | b'\\' | b'^');
    let double = !matches!(byte, b'!' | b'$' | b'^' | b'`');
    u8::from(raw) | (u8::from(single) << 1) | (u8::from(double) << 2)
}

fn append_quoted(output: &mut Vec<u8>, input: &[u8]) {
    let mut consumed = 0;
    while consumed < input.len() {
        let remaining = &input[consumed..];
        let leading_caret = remaining[0] == b'^';
        let mut mask = if leading_caret { 2 } else { 7 };
        let mut length = usize::from(leading_caret);
        while length < remaining.len() {
            let candidate = mask & admission(remaining[length]);
            if candidate == 0 {
                break;
            }
            mask = candidate;
            length += 1;
        }
        // A non-caret first byte has an admitted quote mode; a leading caret
        // is consumed exceptionally. Thus every chunk has positive length.
        debug_assert!(length > 0 && mask != 0);
        let chunk = &remaining[..length];
        if mask & 1 != 0 {
            output.extend_from_slice(chunk);
        } else if mask & 2 != 0 {
            output.push(b'\'');
            output.extend_from_slice(chunk);
            output.push(b'\'');
        } else {
            output.push(b'"');
            for &byte in chunk {
                if matches!(byte, b'"' | b'$' | b'\\' | b'`') {
                    output.push(b'\\');
                }
                output.push(byte);
            }
            output.push(b'"');
        }
        consumed += length;
    }
}
