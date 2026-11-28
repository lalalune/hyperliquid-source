#![no_std]

#[no_mangle]
pub extern "C" fn rotate_add(value: u64) -> u64 {
    value.rotate_left(7).wrapping_add(21)
}
