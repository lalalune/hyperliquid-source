extern crate hl_bincode_varint;
fn main() {
    let mut counter = u64::MAX - 1;
    let _ = hl_bincode_varint::count_u64(251, &mut counter);
}
