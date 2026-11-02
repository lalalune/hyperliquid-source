#![no_std]
#![forbid(unsafe_code)]
//! Snapshot-value projection of node94's three-path unsigned clamp.

/// Values left in the original RAX and RCX data registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rcx: u64,
}

/// A field required on the chosen path was not supplied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable;

/// Clamp copied little-endian qword field values with path-sensitive admission.
///
/// `tag` represents the word at the original object address; `first`, `second`
/// and `cap` represent its +16, +24 and +40 fields. `None` means unavailable.
/// Only required fields are checked, in original load order. The cap is
/// required on every admitted path, even when the numeric result is zero.
///
/// Values must correspond to stable ordinary target loads. This does not
/// dereference original pointers or model faults, access traces, MMIO,
/// concurrency, flags, return control or the original calling convention.
pub fn clamp(
    tag: u64,
    first: Option<u64>,
    second: Option<u64>,
    cap: Option<u64>,
) -> Result<Registers, Unavailable> {
    let candidate = if tag == 0 {
        second.ok_or(Unavailable)?
    } else if tag as u32 == 1 {
        let first = first.ok_or(Unavailable)?;
        let second = second.ok_or(Unavailable)?;
        first.saturating_sub(second)
    } else {
        0
    };
    let cap = cap.ok_or(Unavailable)?;
    Ok(Registers {
        rax: candidate.min(cap),
        rcx: cap,
    })
}
