#![no_std]
#![forbid(unsafe_code)]
/// Ordinary view reads and a normal-return callback, not a native ABI/fault model.
pub trait View {
    type Error;
    fn read_u64(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn read_u8(&mut self, address: u64) -> Result<u8, Self::Error>;
    fn tagged_call(&mut self, target: u64, tag: u16) -> Result<u64, Self::Error>;
}
/// Node94 [0x3bde0b0,0x3bde10b): reconstruct the full RAX continuation,
/// not merely its boolean AL. The fast path is conditional on callback return.
pub fn record_flag_scan<V: View>(view: &mut V, object: u64) -> Result<u64, V::Error> {
    let count = view.read_u64(object.wrapping_add(0x10))?;
    if count >= 10001 {
        let returned = view.tagged_call(0x3c1ada0, 0x0143)?;
        return Ok((returned & !0xff) | 1);
    }
    let mut pointer = view.read_u64(object.wrapping_add(8))?;
    let prefix = (count << 4) & !0xff;
    for _ in 0..count {
        if view.read_u8(pointer.wrapping_add(0x4e))? == 0 {
            return Ok(prefix);
        }
        pointer = pointer.wrapping_add(0x50);
    }
    Ok(prefix | 1)
}
