use std::io::{self, BufRead};
#[path = "lib.rs"] mod implementation;
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let bytes: Vec<u8> = line.as_bytes().chunks_exact(2).map(|x| {
            u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap()
        }).collect();
        match implementation::validate(&bytes) {
            Ok(()) => println!("ok"),
            Err(e) => println!("{}:{}", e.valid_up_to, e.error_len.map_or(-1, i32::from)),
        }
    }
}
