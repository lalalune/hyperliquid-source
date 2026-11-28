#![no_std]

#[repr(align(64))]
struct Aligned([u8; 64]);

extern "C" {
    fn observe_buffer(ptr: *const u8);
}

#[no_mangle]
pub extern "C" fn aligned_buffer() {
    let buffer = Aligned([0; 64]);
    // The external declaration keeps the stack address observable in this object-only fixture.
    unsafe { observe_buffer(buffer.0.as_ptr()) }
}
