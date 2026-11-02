#![no_std]
#![forbid(unsafe_code)]
/// Explicit reads over an ordinary view, not native ABI or hardware faults.
pub trait Read {
    type Error;
    fn load_u64(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn load_u8(&mut self, address: u64) -> Result<u8, Self::Error>;
}
/// Node94 [0x53d1f90,0x53d1fab): do not read the gate when the qword is zero.
pub fn gated_byte<M: Read>(memory: &mut M, base: u64) -> Result<u8, M::Error> {
    if memory.load_u64(base.wrapping_add(0xb0))? == 0 {
        return Ok(0);
    }
    Ok(u8::from(memory.load_u8(base.wrapping_add(0xb8))? == 0))
}
