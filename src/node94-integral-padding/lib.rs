#![no_std]
#![forbid(unsafe_code)]
//! Independent safe callback/header projection of node94 integral padding.

use core::cell::Cell;

/// Chosen live proxy for the observed formatter fields, not its native layout.
pub struct Context {
    pub tailword: Cell<u64>,
    pub data: Cell<u64>,
    pub table: Cell<u64>,
}

/// Logical dispatch identities. Table IDs must be unique and remain valid.
pub struct Table {
    pub id: u64,
    pub char_method: Cell<u64>,
    pub str_method: Cell<u64>,
}

#[derive(Clone, Copy)]
pub enum Operation<'a> {
    Char(u32),
    Str(&'a [u8]),
}

pub struct Request<'a> {
    pub data: u64,
    pub table: u64,
    pub method: u64,
    pub operation: Operation<'a>,
}

fn dispatch<C, F>(ctx: &Context, tables: &[Table], data: u64, table: u64,
                  operation: Operation<'_>, writer: &mut C, sink: &mut F) -> u8
where F: FnMut(&mut C, &Context, &[Table], Request<'_>) -> u8 {
    let selected = tables.iter().find(|t| t.id == table).expect("valid logical table ID");
    let method = match operation {
        Operation::Char(_) => selected.char_method.get(),
        Operation::Str(_) => selected.str_method.get(),
    };
    sink(writer, ctx, tables, Request { data, table, method, operation })
}

// Real independently authored implementation of the closed84-byte prefix
// helper relation; enabled empty prefixes still make a Str request.
fn write_prefix<C, F>(ctx: &Context, tables: &[Table], data: u64, table: u64,
                     sign: Option<u32>, prefix: Option<&[u8]>, writer: &mut C, sink: &mut F) -> u8
where F: FnMut(&mut C, &Context, &[Table], Request<'_>) -> u8 {
    if let Some(sign) = sign {
        if dispatch(ctx, tables, data, table, Operation::Char(sign), writer, sink) != 0 {
            return 1;
        }
    }
    if let Some(prefix) = prefix {
        dispatch(ctx, tables, data, table, Operation::Str(prefix), writer, sink)
    } else {
        0
    }
}

// Real independent scalar implementation of the closed1483-byte count helper.
// For valid UTF8, non-continuation bytes correspond one-to-one to scalars.
fn prefix_count(prefix: &[u8]) -> usize {
    prefix.iter().filter(|&&b| b < 128 || b >= 192).count()
}

/// Project normal requests/header effects of VA15723b0..15728bf and its two
/// actual fixed helpers. The callback may mutate the supplied Cells.
///
/// Layout uses the initial tailword: flags32,width16,precision16. The initial
/// data/table identities stay cached throughout the invocation; method Cells
/// in that table are loaded on each dispatch. Padding invokes individual Char
/// requests, even when a client losslessly compresses identical observations.
///
/// No padding forwards the final digit callback's raw u8; earlier failures and
/// every padded failure normalize to1. Zero padding changes the low DWORD to
/// `(flags & 0x9fe00000) | 0x20000030`. Only complete success restores the full
/// original QWORD, overriding callback header mutations. Errors retain the
/// current header; data/table/method mutations are never restored here.
///
/// This chosen safe token/Cell API excludes invalid logical table IDs, mutated
/// inputs/code/frame, faults/unwind/concurrency, original private ABI/pointer
/// identity and the opaque writer's rendering. Char arguments are raw u32.
pub fn pad_integral<C, F>(ctx: &Context, tables: &[Table], sign_raw: u32,
                          prefix: &str, digits: &[u8], writer: &mut C, sink: &mut F) -> u8
where F: FnMut(&mut C, &Context, &[Table], Request<'_>) -> u8 {
    let initial = ctx.tailword.get();
    let flags = initial as u32;
    let width = ((initial >> 32) & 0xffff) as usize;
    let sign = if sign_raw == 0 { Some(45) }
               else if flags & (1 << 21) != 0 { Some(43) }
               else { None };
    let prefix = if flags & (1 << 23) != 0 { Some(prefix.as_bytes()) } else { None };
    let length = digits.len() + usize::from(sign.is_some()) + prefix.map_or(0, prefix_count);
    let data = ctx.data.get();
    let table = ctx.table.get();
    if length >= width {
        if write_prefix(ctx, tables, data, table, sign, prefix, writer, sink) != 0 {
            return 1;
        }
        return dispatch(ctx, tables, data, table, Operation::Str(digits), writer, sink);
    }
    let padding = width - length;
    if flags & (1 << 24) != 0 {
        ctx.tailword.set((initial & 0xffff_ffff_0000_0000) | u64::from((flags & 0x9fe0_0000) | 0x2000_0030));
        if write_prefix(ctx, tables, data, table, sign, prefix, writer, sink) != 0 {
            return 1;
        }
        for _ in 0..padding {
            if dispatch(ctx, tables, data, table, Operation::Char(48), writer, sink) != 0 {
                return 1;
            }
        }
        if dispatch(ctx, tables, data, table, Operation::Str(digits), writer, sink) != 0 {
            return 1;
        }
        ctx.tailword.set(initial);
        return 0;
    }
    let before = match (flags >> 29) & 3 {
        0 => 0,
        2 => padding / 2,
        _ => padding,
    };
    let fill = flags & 0x1f_ffff;
    for _ in 0..before {
        if dispatch(ctx, tables, data, table, Operation::Char(fill), writer, sink) != 0 {
            return 1;
        }
    }
    if write_prefix(ctx, tables, data, table, sign, prefix, writer, sink) != 0 {
        return 1;
    }
    if dispatch(ctx, tables, data, table, Operation::Str(digits), writer, sink) != 0 {
        return 1;
    }
    for _ in 0..(padding - before) {
        if dispatch(ctx, tables, data, table, Operation::Char(fill), writer, sink) != 0 {
            return 1;
        }
    }
    0
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
#[path = "input_only_driver.rs"]
mod input_driver;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_pre_source_request_and_mutation_vectors() {
        let inputs = include_str!(concat!(env!("NODE94_PADDING_FIXTURES"), "/inputs.tsv"));
        let expected = include_str!(concat!(env!("NODE94_PADDING_FIXTURES"), "/expected.jsonl"));
        assert_eq!(inputs.lines().count(), 11150);
        assert_eq!(expected.lines().count(), 11150);
        for (given, wanted) in inputs.lines().zip(expected.lines()) {
            assert_eq!(input_driver::run_line(given), wanted, "{}", given.split('\t').next().unwrap());
        }
    }

    #[test]
    fn writer_borrow_and_context_identity_survive_live_mutations() {
        let initial = (4_u64 << 32) | (1 << 24);
        let ctx = Context { tailword: Cell::new(initial), data: Cell::new(7), table: Cell::new(1) };
        let tables = [Table { id: 1, char_method: Cell::new(11), str_method: Cell::new(12) },
                      Table { id: 2, char_method: Cell::new(21), str_method: Cell::new(22) }];
        let mut writer = 0_usize;
        let original_writer = &writer as *const usize;
        let original_context = &ctx as *const Context;
        let status = pad_integral(&ctx, &tables, 1, "", b"x", &mut writer, &mut |w, c, t, r| {
            assert!(core::ptr::eq(original_writer, w as *const usize));
            assert!(core::ptr::eq(original_context, c as *const Context));
            assert_eq!((r.data, r.table), (7, 1));
            if *w == 0 {
                c.data.set(99);
                c.table.set(2);
                c.tailword.set(u64::MAX);
                t[0].char_method.set(31);
                t[0].str_method.set(32);
                assert_eq!(r.method, 11);
            } else {
                assert_eq!(r.method, if matches!(r.operation, Operation::Char(_)) { 31 } else { 32 });
            }
            *w += 1;
            0
        });
        assert_eq!(status, 0);
        assert_eq!(writer, 4);
        assert_eq!(ctx.tailword.get(), initial);
        assert_eq!((ctx.data.get(), ctx.table.get()), (99, 2));
    }
}
