#![no_std]
#![forbid(unsafe_code)]
/// Explicit ordinary byte-view operations, not native fault delivery or ABI.
pub trait Memory {
    type Error;
    fn load_u64(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn store_u64(&mut self, address: u64, value: u64) -> Result<(), Self::Error>;
}
/// Node94 [0x5172fa0,0x5172fc0). Clear only a nonzero flag qword,
/// copy field+0x50 only when it differs from field+0x58, return raw RAX.
pub fn flag_clear_field_sync<M: Memory>(memory: &mut M, base: u64) -> Result<u64, M::Error> {
    if memory.load_u64(base)? != 0 {
        memory.store_u64(base, 0)?;
    }
    let value = memory.load_u64(base.wrapping_add(0x50))?;
    if value != memory.load_u64(base.wrapping_add(0x58))? {
        memory.store_u64(base.wrapping_add(0x58), value)?;
    }
    Ok(value)
}
