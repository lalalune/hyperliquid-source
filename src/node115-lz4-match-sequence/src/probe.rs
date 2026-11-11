use node115_lz4_match_sequence::{Error, emit};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<_> = line.split('\t').collect();
        let n: usize = v[0].parse().unwrap();
        let seed: usize = v[1].parse().unwrap();
        let extra: u64 = v[2].parse().unwrap();
        let offset: u16 = v[3].parse().unwrap();
        let cap: usize = v[4].parse().unwrap();
        let mut used: usize = v[5].parse().unwrap();
        let literals: Vec<_> = (0..n).map(|i| ((i * 17 + seed) % 256) as u8).collect();
        let mut sink: Vec<_> = (0..cap)
            .map(|i| {
                if i < used {
                    ((i * 13 + seed) % 256) as u8
                } else {
                    0xcc
                }
            })
            .collect();
        let status = match emit(&literals, extra, offset, &mut sink, &mut used) {
            Ok(()) => "ok",
            Err(Error::Domain) => "domain",
            Err(Error::Token) => "token",
            Err(Error::LiteralExtension) => "literal-extension",
            Err(Error::Literals) => "literals",
            Err(Error::Offset) => "offset",
            Err(Error::MatchExtension) => "match-extension",
        };
        let hex = if sink.is_empty() {
            "-".into()
        } else {
            sink.iter().map(|x| format!("{x:02x}")).collect::<String>()
        };
        println!("{status}:{used}:{hex}");
    }
}
