#![no_std]
#![forbid(unsafe_code)]
//! Owned scalar relation for three qualified node115 leaf entries.
/// Raw field words, with no original ABI, units or business status names.
pub fn select(a: [u32; 3], b: [u32; 3], t: u64, x: u64, c: u64) -> u8 {
    let left = (a[0] as i32, a[1], a[2]);
    let right = (b[0] as i32, b[1], b[2]);
    if left >= right && t >= c {
        2
    } else {
        u8::from(t >= x.saturating_add(5000))
    }
}
