#![no_std]
#![forbid(unsafe_code)]
//! Native-grounded normal Unicode precision/padding request relation.

use core::cell::Cell;

pub struct Context {
    pub tailword: Cell<u64>,
    pub data: Cell<u64>,
    pub table: Cell<u64>,
}

pub struct Table {
    pub id: u64,
    pub char_method: Cell<u64>,
    pub str_method: Cell<u64>,
}

#[derive(Clone, Copy)]
pub enum Operation<'a> { Char(u32), Str(&'a [u8]) }

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

// Equivalent scalar implementation of the credited short/long byte-count
// theorem: a valid UTF8 scalar has exactly one non-continuation byte.
fn count_scalars(text: &str) -> usize {
    text.as_bytes().iter().filter(|&&byte| byte & 0xc0 != 0x80).count()
}

/// Normal request/Cell/lowAL projection of VA1573450..1573889.
/// See README for the safe token domain and excluded original ABI/rendering.
pub fn pad_str<C, F>(ctx: &Context, tables: &[Table], text: &str,
                     writer: &mut C, sink: &mut F) -> u8
where F: FnMut(&mut C, &Context, &[Table], Request<'_>) -> u8 {
    let initial = ctx.tailword.get();
    let flags = initial as u32;
    let data = ctx.data.get();
    let table = ctx.table.get();
    if flags & 0x1800_0000 == 0 {
        return dispatch(ctx, tables, data, table, Operation::Str(text.as_bytes()), writer, sink);
    }
    let (selected, count) = if flags & (1 << 28) != 0 {
        let precision = (initial >> 48) as usize;
        let mut cut = 0;
        let mut scalars = 0;
        for ch in text.chars().take(precision) {
            cut += ch.len_utf8();
            scalars += 1;
        }
        (&text[..cut], scalars)
    } else {
        (text, count_scalars(text))
    };
    let width = ((initial >> 32) & 0xffff) as usize;
    if count >= width {
        return dispatch(ctx, tables, data, table, Operation::Str(selected.as_bytes()), writer, sink);
    }
    let padding = width - count;
    let before = match (flags >> 29) & 3 {
        1 => padding,
        2 => padding / 2,
        _ => 0,
    };
    let fill = flags & 0x1f_ffff;
    for _ in 0..before {
        if dispatch(ctx, tables, data, table, Operation::Char(fill), writer, sink) != 0 {
            return 1;
        }
    }
    if dispatch(ctx, tables, data, table, Operation::Str(selected.as_bytes()), writer, sink) != 0 {
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
    fn independent_pre_source_complete_transcripts() {
        let inputs = include_str!(concat!(env!("NODE94_STRING_PAD_FIXTURES"), "/inputs.tsv"));
        let expected = include_str!(concat!(env!("NODE94_STRING_PAD_FIXTURES"), "/expected.jsonl"));
        assert_eq!(inputs.lines().count(), 26054);
        assert_eq!(expected.lines().count(), 26054);
        for (given, wanted) in inputs.lines().zip(expected.lines()) {
            assert_eq!(input_driver::run_line(given), wanted, "{}", given.split('\t').next().unwrap());
        }
    }

    #[test]
    fn borrowed_writer_context_and_live_methods_remain_observable() {
        let initial = (1_u64 << 28) | (5_u64 << 32) | (1_u64 << 48) | 32;
        let ctx = Context { tailword: Cell::new(initial), data: Cell::new(7), table: Cell::new(1) };
        let tables = [Table { id: 1, char_method: Cell::new(11), str_method: Cell::new(12) },
                      Table { id: 2, char_method: Cell::new(21), str_method: Cell::new(22) }];
        let original_ctx = &ctx as *const Context;
        let mut writer = 0_usize;
        let original_writer = &writer as *const usize;
        let status = pad_str(&ctx, &tables, "éZ", &mut writer, &mut |w, c, t, request| {
            assert!(core::ptr::eq(original_ctx, c as *const Context));
            assert!(core::ptr::eq(original_writer, w as *const usize));
            assert_eq!((request.data, request.table), (7, 1));
            if *w == 0 {
                assert!(matches!(request.operation, Operation::Str(s) if s == "é".as_bytes()));
                assert_eq!(request.method, 12);
                c.tailword.set(u64::MAX);
                c.data.set(99); c.table.set(2);
                t[0].char_method.set(31); t[0].str_method.set(32);
            } else {
                assert!(matches!(request.operation, Operation::Char(32)));
                assert_eq!(request.method, 31);
            }
            *w += 1;
            0
        });
        assert_eq!(status, 0);
        assert_eq!(writer, 5);
        assert_eq!((ctx.tailword.get(), ctx.data.get(), ctx.table.get()), (u64::MAX, 99, 2));
    }
}
