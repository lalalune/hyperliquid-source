#![no_std]
#![forbid(unsafe_code)]
/// Byte-view operations and an explicit opaque call. This does not implement
/// the helper at 0x51c4000 or assert its native ABI, ownership or side effects.
pub trait Context {
    type Error;
    fn load_u32(&mut self, address: u64) -> Result<u32, Self::Error>;
    fn load_u64(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn invoke(&mut self, target: u64, args: [u64; 4]) -> Result<u64, Self::Error>;
}
/// Node94 [0x51c96d0,0x51c9701): preserve the outgoing argument projection,
/// then reload the base after the opaque call before signed scaling.
pub fn count_scale<C: Context>(
    view: &mut C,
    state: u64,
    context: u64,
    rdx: u64,
) -> Result<u32, C::Error> {
    let count = u64::from(view.load_u32(state)?);
    let base = view.load_u64(state.wrapping_add(8))?;
    let end = base.wrapping_add(count.wrapping_mul(80));
    let returned = view.invoke(0x51c4000, [base, end, rdx, context])?;
    let post_base = view.load_u64(state.wrapping_add(8))?;
    let difference = returned.wrapping_sub(post_base) as i64;
    Ok(((difference >> 4) as u32).wrapping_mul(0xcccccccd))
}
