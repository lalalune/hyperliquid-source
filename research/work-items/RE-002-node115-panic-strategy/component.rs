#![no_std]
struct Guard<'a>(&'a mut u32);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        *self.0 += 1;
    }
}
#[inline(never)]
#[no_mangle]
pub fn dependency_operation(callback: fn(), progress: &mut u32) {
    let _guard = Guard(progress);
    callback();
}
