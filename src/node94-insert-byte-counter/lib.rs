#![no_std]
#![forbid(unsafe_code)]
/// Read/write and opaque external-call operations on an ordinary view.
/// The qword read/write pair is not a hardware atomicity or fault-order claim.
pub trait View {
    type Error;
    fn read_u8(&mut self, address: u64) -> Result<u8, Self::Error>;
    fn read_u64(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn write_u64(&mut self, address: u64, value: u64) -> Result<(), Self::Error>;
    fn insert(&mut self, target: u64, args: [u64; 4]) -> Result<(), Self::Error>;
}
/// Node94 [0x4fd6030,0x4fd607c). Keep lazy unsigned byte reads, external
/// argument projection, post-call wrapping counter increment and full RAX.
pub fn insert_byte_counter<V: View>(
    view: &mut V,
    object: u64,
    second: u64,
    third: u64,
    fourth: u64,
) -> Result<u64, V::Error> {
    let header = object.wrapping_add(8);
    let flag = if second != 0 || third == header {
        1
    } else {
        let third_byte = view.read_u8(third.wrapping_add(0x20))?;
        let fourth_byte = view.read_u8(fourth.wrapping_add(0x20))?;
        u64::from(fourth_byte < third_byte)
    };
    view.insert(0x5660550, [flag, fourth, third, header])?;
    let counter = view.read_u64(object.wrapping_add(0x28))?;
    view.write_u64(object.wrapping_add(0x28), counter.wrapping_add(1))?;
    Ok(fourth)
}
