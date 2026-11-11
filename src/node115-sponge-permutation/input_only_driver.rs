use node115_sponge_permutation::permute;
use std::io::{self, BufRead};
pub fn evaluate_line(line: &str) -> String {
    assert_eq!(line.len(), 400);
    let mut bytes = [0; 200];
    for (i, value) in bytes.iter_mut().enumerate() {
        *value = u8::from_str_radix(&line[2 * i..2 * i + 2], 16).unwrap();
    }
    let mut state = [0; 25];
    for (word, chunk) in state.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    permute(&mut state);
    let mut output = String::with_capacity(400);
    for word in state {
        for byte in word.to_le_bytes() {
            output.push_str(&format!("{byte:02x}"));
        }
    }
    output
}
fn main() {
    for line in io::stdin().lock().lines() {
        println!("{}", evaluate_line(&line.unwrap()));
    }
}
