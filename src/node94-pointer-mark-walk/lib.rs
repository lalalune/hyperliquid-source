#![no_std]
//! State projection of node94 [0x50e69f0, 0x50e6a82).
//!
//! IDs name snapshot cells; they are never dereferenced as native pointers.
//! Link/entry/count cells remain immutable and do not overlap stamp cells.
//! Shared stamp IDs preserve state sharing across links and entries. The mark
//! is the once-loaded scalar, and tail_heads represents a valid forward array
//! span. This is not the original pointer ABI or a claim about its return RAX.

pub const SENTINEL: u64 = 0x00ff_ffff_ffff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Link {
    pub id: u64,
    pub next: u64,
    pub node: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stamp {
    pub id: u64,
    pub value: u64,
}

/// New safe-API refusal reasons, not recovered target return variants.
/// Except InvalidMap, errors retain the writes preceding the refused access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    InvalidMap,
    MissingEntry(u64),
    MissingLink(u64),
    MissingNode(u64),
    NonterminatingCycle(u64),
}

fn link(links: &[Link], id: u64) -> Result<Link, Refusal> {
    links
        .iter()
        .find(|record| record.id == id)
        .copied()
        .ok_or(Refusal::MissingLink(id))
}

/// Mark each reached sentinel-valued payload and stop an entry at its first
/// non-sentinel payload or its head. Entries 0..7 always use inline_heads;
/// later entries use tail_heads, regardless of base_count. The outer count is
/// base_count + tail_heads.len() modulo 2^64.
///
/// Each map must have unique, nonzero IDs. Unused malformed maps are rejected
/// before writes; missing cells are refused only when their reads are reached.
/// A cycle with mark == SENTINEL may not terminate in the target. This API
/// detects it after a bounded prefix and returns NonterminatingCycle(entry).
/// With another mark, revisiting a previously marked payload stops normally.
pub fn mark(
    links: &[Link],
    stamps: &mut [Stamp],
    inline_heads: &[u64; 8],
    tail_heads: &[u64],
    base_count: u64,
    mark: u64,
) -> Result<(), Refusal> {
    for (i, record) in links.iter().enumerate() {
        if record.id == 0 || links[..i].iter().any(|other| other.id == record.id) {
            return Err(Refusal::InvalidMap);
        }
    }
    for (i, record) in stamps.iter().enumerate() {
        if record.id == 0 || stamps[..i].iter().any(|other| other.id == record.id) {
            return Err(Refusal::InvalidMap);
        }
    }
    let count = base_count.wrapping_add(tail_heads.len() as u64);
    let mut entry = 0;
    while entry != count {
        let head = if entry < 8 {
            inline_heads[entry as usize]
        } else {
            *usize::try_from(entry - 8)
                .ok()
                .and_then(|index| tail_heads.get(index))
                .ok_or(Refusal::MissingEntry(entry))?
        };
        let mut current = link(links, head)?.next;
        for steps in 0..=links.len() {
            if current == head {
                break;
            }
            let current_link = link(links, current)?;
            let stamp = stamps
                .iter_mut()
                .find(|record| record.id == current_link.node)
                .ok_or(Refusal::MissingNode(current_link.node))?;
            if stamp.value != SENTINEL {
                break;
            }
            // Resolve the reached cells and test the gate before refusing a
            // cycle: an already marked payload can close a finite walk.
            if steps == links.len() {
                return Err(Refusal::NonterminatingCycle(entry));
            }
            let next = current_link.next;
            stamp.value = mark;
            current = next;
        }
        entry += 1;
    }
    Ok(())
}
