use node115_elf_build_id::build_id;
use std::io::{self, BufRead};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return vec![];
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn result(file: &[u8], headers: &[[u8; 64]]) -> String {
    match build_id(file, headers) {
        None => "N".to_owned(),
        Some(bytes) => format!(
            "S:{}:{}:{}",
            bytes.as_ptr() as usize - file.as_ptr() as usize,
            bytes.len(),
            if bytes.is_empty() {
                "-".into()
            } else {
                hex(bytes)
            }
        ),
    }
}
fn main() {
    if let Some(path) = std::env::args().nth(1) {
        // Harness-only ELF header loading, not a reconstructed Object parser.
        let file = std::fs::read(path).unwrap();
        let offset = u64::from_le_bytes(file[40..48].try_into().unwrap()) as usize;
        let width = u16::from_le_bytes(file[58..60].try_into().unwrap()) as usize;
        let count = u16::from_le_bytes(file[60..62].try_into().unwrap()) as usize;
        assert_eq!(width, 64);
        let headers: Vec<[u8; 64]> = file[offset..offset + width * count]
            .chunks_exact(64)
            .map(|v| v.try_into().unwrap())
            .collect();
        println!("{}", result(&file, &headers));
        return;
    }
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (file, records) = line.split_once('\t').unwrap();
        let file = unhex(file);
        let raw = unhex(records);
        let headers: Vec<[u8; 64]> = raw
            .chunks_exact(64)
            .map(|h| h.try_into().unwrap())
            .collect();
        assert_eq!(raw.len() % 64, 0);
        println!("{}", result(&file, &headers));
    }
}
