#![no_std]
//! Normal-return command program/argument state, not native ABI or execution.
extern crate alloc;
use alloc::{vec, vec::Vec};
use core::ptr;
use node115_owned_cstring::{Error, convert};
fn converted(input: &[u8]) -> (Vec<u8>, bool) {
    match convert(input) {
        Ok(bytes) => (bytes, false),
        Err(Error::InteriorNul { .. }) => (b"<string-with-nul>\0".to_vec(), true),
        Err(Error::Allocation) => panic!("conversion allocation boundary"),
    }
}
/// All storage/pointers are genuinely owned; no OS/process callback exists.
/// Allocation failure and original panic/unwind state are outside normal scope.
pub struct Command {
    program: Vec<u8>,
    arguments: Vec<Vec<u8>>,
    argv: Vec<*const u8>,
    kind: u8,
    saw_nul: bool,
}
impl Command {
    pub fn new(input: &[u8]) -> Self {
        // Classification precedes conversion, including an invalid-NUL placeholder.
        let kind = if input.first() == Some(&b'/') {
            2
        } else if input.contains(&b'/') {
            1
        } else {
            0
        };
        let (program, saw_nul) = converted(input);
        let argv0 = program.clone();
        let argv = vec![argv0.as_ptr(), ptr::null()];
        let arguments = vec![argv0];
        Self {
            program,
            arguments,
            argv,
            kind,
            saw_nul,
        }
    }
    pub fn push_argument(&mut self, input: &[u8]) {
        let (value, bad) = converted(input);
        if bad {
            self.saw_nul = true;
        }
        let pointer = value.as_ptr();
        self.arguments.push(value);
        let last = self.argv.len() - 1;
        self.argv[last] = pointer;
        self.argv.push(ptr::null());
    }
    pub fn program_with_nul(&self) -> &[u8] {
        &self.program
    }
    pub fn arguments_with_nul(&self) -> &[Vec<u8>] {
        &self.arguments
    }
    pub fn argv(&self) -> &[*const u8] {
        &self.argv
    }
    pub fn program_kind_raw(&self) -> u8 {
        self.kind
    }
    pub fn saw_nul(&self) -> bool {
        self.saw_nul
    }
}
