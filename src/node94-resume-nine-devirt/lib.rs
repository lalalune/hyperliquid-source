#![no_std]
#![forbid(unsafe_code)]
/// Ordinary byte-view reads/writes and an opaque virtual-call boundary.
/// This API does not execute target code or establish its native ABI/faults.
pub trait Memory {
    type Error;
    fn load_u64(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn store_u64(&mut self, address: u64, value: u64) -> Result<(), Self::Error>;
    fn invoke(&mut self, target: u64, args: [u64; 4]) -> Result<u64, Self::Error>;
}
/// Node94 [0x514b620,0x514b685), including the field-read semantics of
/// known getter [0x4fa7e80,0x4fa7e89). Incoming RDX is `object`, RSI is
/// `output`; the virtual branch must retain the original output address.
pub fn devirtualized_getter<M: Memory>(
    memory: &mut M,
    object: u64,
    output: u64,
    entry_rcx: u64,
) -> Result<u64, M::Error> {
    let element = memory.load_u64(object.wrapping_add(0x1200))?;
    let sentinel = object.wrapping_add(0x11e0);
    let value = if element == sentinel {
        0
    } else {
        let table = memory.load_u64(element)?;
        let function = memory.load_u64(table)?;
        let known_getter = memory.load_u64(0x5778020)?;
        if function == known_getter {
            memory.load_u64(element.wrapping_add(8))?
        } else {
            memory.invoke(function, [element, output, sentinel, entry_rcx])?
        }
    };
    memory.store_u64(output, value)?;
    Ok(1)
}
