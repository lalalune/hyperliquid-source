#![no_std]
#![forbid(unsafe_code)]
/// Ordinary byte-view operations and the unresolved helper boundary.
pub trait Memory {
    type Error;
    fn load_u64(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn store_u64(&mut self, address: u64, value: u64) -> Result<(), Self::Error>;
    fn store_u8(&mut self, address: u64, value: u8) -> Result<(), Self::Error>;
    fn invoke(&mut self, target: u64, args: [u64; 4]) -> Result<u64, Self::Error>;
}
/// Raw registers at the caller's return, without an application-level meaning.
#[derive(Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}
/// Node94 [0x5172e20,0x5172e49). Preserve the opaque callback's side
/// effects and the cache-store/reload/link-read/byte-store sequence.
pub fn refresh<M: Memory>(
    memory: &mut M,
    object: u64,
    entry_rsi: u64,
    entry_rdx: u64,
    entry_rcx: u64,
) -> Result<Registers, M::Error> {
    let before = memory.load_u64(object.wrapping_add(8))?;
    let returned = memory.invoke(0x5172b00, [before, entry_rsi, entry_rdx, entry_rcx])?;
    memory.store_u64(object.wrapping_add(0x20), returned)?;
    let second = memory.load_u64(object.wrapping_add(8))?;
    let sentinel = second.wrapping_add(0x18);
    let flag = u8::from(memory.load_u64(sentinel)? != sentinel);
    memory.store_u8(object.wrapping_add(0x28), flag)?;
    Ok(Registers {
        rax: (second & !0xff) | u64::from(flag),
        rdx: sentinel,
    })
}
