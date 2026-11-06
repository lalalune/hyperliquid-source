//! Real allocator-failure controls for independently authored Rust only.
use node115_owned_cstring::{Error, convert};
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

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let p: Vec<_> = line.split('\t').collect();
        let align: usize = p[0].parse().unwrap();
        let fail: usize = p[1].parse().unwrap();
        let input: Vec<u8> = if p[2] == "-" {
            vec![]
        } else {
            p[2].as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect()
        };
        let mut backing = vec![0xa5; align];
        backing.extend_from_slice(&input);
        let source = &backing[align..];
        STATE.with(|s| {
            s.set(State {
                armed: true,
                fail,
                requests: 0,
            })
        });
        let result = convert(source);
        let requests = STATE.with(|s| {
            let mut x = s.get();
            x.armed = false;
            s.set(x);
            x.requests
        });
        let (value, len, cap) = match result {
            Ok(bytes) => {
                assert_eq!(bytes.last(), Some(&0));
                assert_eq!(
                    std::ffi::CString::new(source).unwrap().as_bytes_with_nul(),
                    bytes
                );
                (
                    format!(
                        "ok:{}",
                        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    ),
                    bytes.len(),
                    bytes.capacity(),
                )
            }
            Err(Error::InteriorNul { position, bytes }) => {
                assert_eq!(
                    std::ffi::CString::new(source).unwrap_err().nul_position(),
                    position
                );
                (
                    format!(
                        "nul:{position}:{}",
                        if bytes.is_empty() {
                            "-".into()
                        } else {
                            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                        }
                    ),
                    bytes.len(),
                    bytes.capacity(),
                )
            }
            Err(Error::Allocation) => ("allocation".into(), 0, 0),
        };
        assert_eq!(source, input);
        println!("{value}|{len}|{cap}|{requests}");
    }
}
