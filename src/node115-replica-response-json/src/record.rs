//! Assemble one line of the selected native replica JSON shape offline.

use std::io::{self, Write};

use crate::{fixed_hex, write_response, Response};

pub struct Bundle<A> {
    pub reference: [u8; 32],
    pub signed_actions: Vec<A>,
    pub broadcaster: [u8; 20],
    pub broadcaster_nonce: u64,
}

pub struct Header<'a> {
    /// Already formatted native clock text, as supplied by the caller.
    pub time: &'a str,
    pub round: u64,
    pub parent_round: u64,
    pub hardfork_version: u64,
    pub hardfork_round: u64,
    pub proposer: [u8; 20],
}

pub struct Record<'a, A, R> {
    pub header: Header<'a>,
    pub bundles: &'a [Bundle<A>],
    pub responses: Response<'a, R>,
    pub height: u64,
}

fn write_array<W: Write, T>(
    out: &mut W,
    items: &[T],
    mut write_item: impl FnMut(&mut W, &T) -> io::Result<()>,
) -> io::Result<()> {
    out.write_all(b"[")?;
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.write_all(b",")?;
        }
        write_item(out, item)?;
    }
    out.write_all(b"]")
}

/// Write one native-shaped line with caller-supplied action and response entries.
///
/// The two callbacks supply complete JSON values. Their I/O errors stop the
/// operation after the already written prefix. The clock's calendar semantics
/// are supplied by the caller. This encoder checks it can be quoted literally.
pub fn write_record<W: Write, A, R>(
    out: &mut W,
    record: Record<'_, A, R>,
    mut write_action: impl FnMut(&mut W, &A) -> io::Result<()>,
    write_outcome: impl FnMut(&mut W, &R) -> io::Result<()>,
) -> io::Result<()> {
    let header = record.header;
    if header.time.is_empty()
        || !header
            .time
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'T' | b':' | b'.'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected unescaped replica clock text",
        ));
    }
    write!(
        out,
        "{{\"abci_block\":{{\"time\":\"{}\",\"signed_action_bundles\":",
        header.time
    )?;
    write_array(out, record.bundles, |out, bundle| {
        out.write_all(b"[")?;
        fixed_hex(out, &bundle.reference)?;
        out.write_all(b",{\"signed_actions\":")?;
        write_array(out, &bundle.signed_actions, &mut write_action)?;
        out.write_all(b",\"broadcaster\":")?;
        fixed_hex(out, &bundle.broadcaster)?;
        write!(
            out,
            ",\"broadcaster_nonce\":{}}}]",
            bundle.broadcaster_nonce
        )
    })?;
    write!(
        out,
        ",\"round\":{},\"parent_round\":{},\"hardfork\":{{\"version\":{},\"round\":{}}},\"proposer\":",
        header.round, header.parent_round, header.hardfork_version, header.hardfork_round,
    )?;
    fixed_hex(out, &header.proposer)?;
    out.write_all(b"},\"resps\":")?;
    write_response(out, record.responses, write_outcome)?;
    writeln!(out, ",\"height\":{}}}", record.height)
}
