#![no_std]
#![forbid(unsafe_code)]
/// Ordinary byte-view reads; this is not the captured native calling ABI.
pub trait Read {
    type Error;
    fn load_u64(&mut self, address: u64) -> Result<u64, Self::Error>;
}
#[derive(Debug, PartialEq, Eq)]
pub struct Pair {
    pub rax: u64,
    pub rdx: u64,
}
/// Node94 [0x502b460,0x502b477): load both fields from the same full pointer,
/// RDX first, then RAX. No write, chained field dereference or outgoing call.
pub fn pair_load<M: Read>(memory: &mut M, object: u64) -> Result<Pair, M::Error> {
    let base = memory.load_u64(object.wrapping_add(0x28))?;
    let rdx = memory.load_u64(base.wrapping_add(0x198))?;
    let rax = memory.load_u64(base.wrapping_add(0x190))?;
    Ok(Pair { rax, rdx })
}
