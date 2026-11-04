extern crate node115_lz4_decode;
use node115_lz4_decode::{decode, DecodeError};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (limit, hex) = line.split_once(' ').unwrap();
        let bytes: Vec<u8> = if hex == "-" { vec![] } else {
            hex.as_bytes().chunks_exact(2).map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(),16).unwrap()).collect()
        };
        match decode(&bytes,limit.parse().unwrap()) {
            Ok(v) => {let h:String=v.iter().map(|b|format!("{b:02x}")).collect();println!("O {}",if h.is_empty(){"-"}else{&h});},
            Err(e) => println!("{}",match e {
                DecodeError::Header=>"E header",DecodeError::Limit=>"E limit",DecodeError::Input=>"E input",DecodeError::Literal=>"E literal",DecodeError::Output=>"E output",DecodeError::ZeroOffset=>"E zero",DecodeError::History=>"E history",DecodeError::ExtensionOverflow=>"P extension",DecodeError::Allocation=>"LOCAL allocation"
            }),
        }
    }
}
