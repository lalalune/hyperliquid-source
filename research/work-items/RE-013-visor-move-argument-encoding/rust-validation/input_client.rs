#![forbid(unsafe_code)]
use std::io::{self, BufRead, Write};
use visor_move_request::{admitted_output_bound, encode_admitted_move, EncodeError};

fn bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex input width");
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("lowercase hex input"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn main() {
    let length_mode = std::env::args().nth(1).as_deref() == Some("lengths");
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 3, "input-only fields");
        if length_mode {
            let first: u64 = fields[1].parse().expect("first length");
            let second: u64 = fields[2].parse().expect("second length");
            match admitted_output_bound(first, second) {
                Ok(bound) => writeln!(output, "{}\tok\t{}", fields[0], bound).unwrap(),
                Err(_) => writeln!(output, "{}\tdomain", fields[0]).unwrap(),
            }
            continue;
        }
        let first = bytes(fields[1]);
        let second = bytes(fields[2]);
        let first = std::str::from_utf8(&first).expect("canonical first input");
        let second = std::str::from_utf8(&second).expect("canonical second input");
        match encode_admitted_move(first, second) {
            Ok(request) => {
                write!(output, "{}\tok\t{}\t", fields[0], request.option_byte()).unwrap();
                for byte in request.command_bytes() {
                    write!(output, "{byte:02x}").unwrap();
                }
                writeln!(output).unwrap();
            }
            Err(EncodeError::EmbeddedNul) => writeln!(output, "{}\tnul", fields[0]).unwrap(),
            Err(EncodeError::LengthOutsideProofDomain) => {
                writeln!(output, "{}\tdomain", fields[0]).unwrap()
            }
            Err(EncodeError::AllocationFailure(_)) => {
                writeln!(output, "{}\tallocation", fields[0]).unwrap()
            }
        }
    }
}
