#![no_std]
#![forbid(unsafe_code)]
/// Reads of an ordinary byte view, not native pointers or hardware faults.
pub trait Read {
    type Error;
    fn load_u8(&mut self, address: u64) -> Result<u8, Self::Error>;
}
/// Complete node94 FDE 0x51647b0..0x51647c4; clean full-RAX result.
pub fn tiny_gate<M: Read>(memory: &mut M, base: u64) -> Result<u64, M::Error> {
    let first = memory.load_u8(base.wrapping_add(0x58))?;
    if first == 0 {
        return Ok(0);
    }
    Ok(u64::from(memory.load_u8(base.wrapping_add(0x68))? == 0))
}
/// Complete node94 FDE 0x51c09f0..0x51c0a07; nonzero first byte is returned
/// unchanged, not normalized to bool. The fallback read is conditional.
pub fn fallback_gate<M: Read>(memory: &mut M, base: u64) -> Result<u64, M::Error> {
    let first = memory.load_u8(base.wrapping_add(0xd0))?;
    if first != 0 {
        return Ok(u64::from(first));
    }
    Ok(u64::from(memory.load_u8(base.wrapping_add(0xf8))?))
}
