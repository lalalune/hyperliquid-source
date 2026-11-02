#![no_std]
#![forbid(unsafe_code)]
/// Ordered byte-view primitives. A refused store must not change the image;
/// that safe-API refusal contract does not reconstruct native fault behavior.
pub trait Memory {
    type Error;
    fn load_u64(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn read_16(&mut self, address: u64) -> Result<[u8; 16], Self::Error>;
    fn write_16(&mut self, address: u64, value: [u8; 16]) -> Result<(), Self::Error>;
}
#[derive(Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rsi: u64,
}
/// Complete node94 FDE 0x5454710..0x545472e. Preserve all source bytes
/// before any destination write, including partially overlapping spans.
pub fn copy_16<M: Memory>(memory: &mut M, rdx: u64, rsi: u64) -> Result<Registers, M::Error> {
    let dest = memory.load_u64(rdx.wrapping_add(8))?;
    let middle = memory.load_u64(rsi.wrapping_add(0x10))?;
    let q = memory.load_u64(middle.wrapping_add(8))?;
    let chunk = memory.read_16(q.wrapping_sub(0x10))?;
    memory.write_16(dest, chunk)?;
    Ok(Registers {
        rax: 1,
        rdx: q,
        rsi,
    })
}
