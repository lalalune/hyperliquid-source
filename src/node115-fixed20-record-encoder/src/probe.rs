//! Real allocator-failure controls for independently authored Rust only.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{self, BufRead};

#[derive(Clone, Copy)]
struct State {
    armed: bool,
    fail: usize,
    requests: usize,
}
thread_local! { static STATE: Cell<State> = const { Cell::new(State { armed:false, fail:0, requests:0 }) }; }
struct ControlledSystem;
fn refuse() -> bool {
    STATE
        .try_with(|state| {
            let mut s = state.get();
            if !s.armed {
                return false;
            }
            s.requests += 1;
            let refusal = s.fail != 0 && s.requests == s.fail;
            state.set(s);
            refusal
        })
        .unwrap_or(false)
}
// Every successful request/deallocation is delegated to the real System
// allocator. Only a selected alloc/realloc during the library call returns
// null, which the library's actual Vec::try_reserve must handle safely.
unsafe impl GlobalAlloc for ControlledSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuse() {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if refuse() {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if refuse() {
            std::ptr::null_mut()
        } else {
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: ControlledSystem = ControlledSystem;

use node115_fixed20_record_encoder::{Record, SizeBoundary, WriteBoundary, count, write};
use node115_varint_buffer_writer::Error as ScalarError;
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let p: Vec<_> = line.split('\t').collect();
        let words: Vec<u64> = p[1].split(',').map(|x| x.parse().unwrap()).collect();
        let prefix: Vec<u8> = p[2]
            .as_bytes()
            .chunks_exact(2)
            .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
            .collect();
        let record = Record {
            words: words.try_into().unwrap(),
            prefix: prefix.try_into().unwrap(),
        };
        let state: u64 = p[3].parse().unwrap();
        let used: usize = p[4].parse().unwrap();
        let fail: usize = p[5].parse().unwrap();
        let seed: usize = p[6].parse().unwrap();
        if p[0] == "s" {
            let mut counter = state;
            let status = match count(&record, &mut counter) {
                Ok(()) => "ok".into(),
                Err(SizeBoundary::Field(i)) => format!("field:{i}"),
                Err(SizeBoundary::Prefix) => "prefix".into(),
            };
            println!("{status}|{counter}");
            continue;
        }
        let cap = state as usize;
        assert!(used <= cap);
        let mut vector = Vec::with_capacity(cap);
        vector.extend((0..used).map(|i| ((seed + 13 * i) % 256) as u8));
        assert_eq!(vector.capacity(), cap);
        STATE.with(|s| {
            s.set(State {
                armed: true,
                fail,
                requests: 0,
            })
        });
        let result = write(&record, &mut vector);
        let requests = STATE.with(|s| {
            let mut state = s.get();
            state.armed = false;
            s.set(state);
            state.requests
        });
        let status = match result {
            Ok(()) => "ok".into(),
            Err(WriteBoundary::Prefix) => "prefix".into(),
            Err(WriteBoundary::Field { index, stage }) => format!(
                "field:{index}:{}",
                match stage {
                    ScalarError::PrefixGrowth => "prefix",
                    ScalarError::PayloadGrowth => "payload",
                }
            ),
        };
        let hex = if vector.is_empty() {
            "-".into()
        } else {
            vector
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<String>()
        };
        println!(
            "{status}|{}|{}|{requests}|{hex}",
            vector.capacity(),
            vector.len()
        );
    }
}
