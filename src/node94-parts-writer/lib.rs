#![no_std]
#![forbid(unsafe_code)]
//! Normal byte-request relation of the actual node94 649-byte parts writer.

use core::cell::Cell;

pub struct Table {
    pub id: u64,
    pub write_method: Cell<u64>,
}

pub struct ByteView<'a> {
    pub token: u64,
    pub bytes: &'a [u8],
}

/// Chosen raw value projection, not the recovered original descriptor ABI.
pub struct Descriptor<'a> {
    pub prefix_token: u64,
    pub prefix_len: u64,
    pub part_count: u64,
    pub records: &'a [[u64; 3]],
}

pub struct Request<'a> {
    pub data: u64,
    pub table: u64,
    pub method: u64,
    pub bytes: &'a [u8],
}

fn current_method(tables: &[Table], table: u64) -> u64 {
    tables.iter().find(|t| t.id == table).expect("valid reached method table").write_method.get()
}

fn bytes<'a>(views: &[ByteView<'a>], token: u64, len: u64) -> &'a [u8] {
    let view = views.iter().find(|v| v.token == token).expect("valid requested view");
    &view.bytes[..len as usize]
}

fn request<C, F>(writer: &mut C, tables: &[Table], data: u64, table: u64,
                 method: u64, bytes: &[u8], sink: &mut F) -> u8
where F: FnMut(&mut C, &[Table], Request<'_>) -> u8 {
    sink(writer, tables, Request { data, table, method, bytes })
}

/// Complete normal request/effect projection under README's valid lazy domain.
pub fn write_parts<C, F>(data: u64, table: u64, desc: &Descriptor<'_>,
                         views: &[ByteView<'_>], tables: &[Table],
                         writer: &mut C, sink: &mut F) -> u8
where F: FnMut(&mut C, &[Table], Request<'_>) -> u8 {
    if desc.prefix_len != 0 {
        let prefix = bytes(views, desc.prefix_token, desc.prefix_len);
        let method = current_method(tables, table);
        if request(writer, tables, data, table, method, prefix, sink) != 0 {
            return 1;
        }
    }
    for words in &desc.records[..desc.part_count as usize] {
        match words[0] as u16 {
            0 => {
                let mut remaining = words[1];
                if remaining == 0 { continue; }
                let method = current_method(tables, table);
                const ZERO_BLOCK: [u8; 64] = [b'0'; 64];
                while remaining > 64 {
                    if request(writer, tables, data, table, method, &ZERO_BLOCK, sink) != 0 {
                        return 1;
                    }
                    remaining -= 64;
                }
                if request(writer, tables, data, table, method, &ZERO_BLOCK[..remaining as usize], sink) != 0 {
                    return 1;
                }
            }
            1 => {
                let mut value = (words[0] >> 16) as u16;
                let mut buffer = [0_u8; 5];
                let mut start = buffer.len();
                loop {
                    start -= 1;
                    buffer[start] = b'0' + (value % 10) as u8;
                    value /= 10;
                    if value == 0 { break; }
                }
                let method = current_method(tables, table);
                if request(writer, tables, data, table, method, &buffer[start..], sink) != 0 {
                    return 1;
                }
            }
            _ => {
                let payload = bytes(views, words[1], words[2]);
                let method = current_method(tables, table);
                if request(writer, tables, data, table, method, payload, sink) != 0 {
                    return 1;
                }
            }
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
    fn independent_pre_source_raw_transcripts() {
        let given = include_str!(concat!(env!("NODE94_PARTS_FIXTURES"), "/inputs.tsv"));
        let wanted = include_str!(concat!(env!("NODE94_PARTS_FIXTURES"), "/expected.jsonl"));
        assert_eq!(given.lines().count(), 69359);
        assert_eq!(wanted.lines().count(), 69359);
        for (input, expected) in given.lines().zip(wanted.lines()) {
            assert_eq!(input_driver::run_line(input), expected, "{}", input.split('\t').next().unwrap());
        }
    }

    #[test]
    fn no_requests_resolve_no_method_or_view() {
        let records = [[0xffff_ffff_1234_0000, 0, u64::MAX]];
        let desc = Descriptor { prefix_token: u64::MAX, prefix_len: 0, part_count: 1, records: &records };
        let mut state = 77;
        assert_eq!(write_parts(0, u64::MAX, &desc, &[], &[], &mut state,
                              &mut |_, _, _| panic!("no actual request")), 0);
        assert_eq!(state, 77);
    }

    #[test]
    fn zero_run_caches_method_then_numeral_reloads_and_error_stops_lazily() {
        let records = [[0, 129, 0], [1 | (65535_u64 << 16), u64::MAX, u64::MAX], [2, 99, 1]];
        let desc = Descriptor { prefix_token: 99, prefix_len: 0, part_count: 3, records: &records };
        let tables = [Table { id: 1, write_method: Cell::new(11) }];
        let mut state = 0_usize;
        let original = &state as *const usize;
        let status = write_parts(7, 1, &desc, &[], &tables, &mut state, &mut |w, t, r| {
            assert!(core::ptr::eq(original, w as *const usize));
            assert_eq!((r.data, r.table), (7, 1));
            if *w < 3 {
                assert_eq!(r.method, 11);
                assert_eq!(r.bytes.len(), if *w == 2 { 1 } else { 64 });
                assert!(r.bytes.iter().all(|&b| b == b'0'));
                t[0].write_method.set(22);
            } else {
                assert_eq!(r.method, 22);
                assert_eq!(r.bytes, b"65535");
            }
            *w += 1;
            if *w == 4 { 255 } else { 0 }
        });
        assert_eq!(status, 1);
        assert_eq!(state, 4);
        assert_eq!(tables[0].write_method.get(), 22);
    }
}
