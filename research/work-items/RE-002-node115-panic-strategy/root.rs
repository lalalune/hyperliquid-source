extern crate component;
struct Guard<'a>(&'a mut u32);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        *self.0 += 1;
    }
}
#[no_mangle]
#[inline(never)]
pub fn root_operation(callback: fn(), progress: &mut u32) {
    let _guard = Guard(progress);
    callback();
}
fn main() {
    let mut value = 0;
    let cb = std::hint::black_box((|| {}) as fn());
    component::dependency_operation(cb, &mut value);
    root_operation(cb, &mut value);
    std::hint::black_box(value);
}
