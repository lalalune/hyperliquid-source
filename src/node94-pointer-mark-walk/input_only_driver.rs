//! Reads synthetic input only; no expected results or target bytes are linked.
use node94_pointer_mark_walk::{mark, Link, Refusal, Stamp};
use std::io::{BufRead, Write};

fn number(text: &str) -> u64 {
    u64::from_str_radix(text, 16).expect("hex u64")
}

fn numbers(text: &str) -> Vec<u64> {
    if text == "-" {
        Vec::new()
    } else {
        text.split(',').map(number).collect()
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("input file");
    let input = std::io::BufReader::new(std::fs::File::open(path).expect("input file"));
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in input.lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 6);
        let inline: [u64; 8] = numbers(fields[2]).try_into().expect("eight heads");
        let tail = numbers(fields[3]);
        let links = if fields[4] == "-" {
            Vec::new()
        } else {
            fields[4]
                .split(';')
                .map(|row| {
                    let values = numbers(row);
                    assert_eq!(values.len(), 3);
                    Link {
                        id: values[0],
                        next: values[1],
                        node: values[2],
                    }
                })
                .collect()
        };
        let mut stamps = if fields[5] == "-" {
            Vec::new()
        } else {
            fields[5]
                .split(';')
                .map(|row| {
                    let values = numbers(row);
                    assert_eq!(values.len(), 2);
                    Stamp {
                        id: values[0],
                        value: values[1],
                    }
                })
                .collect()
        };
        match mark(
            &links,
            &mut stamps,
            &inline,
            &tail,
            number(fields[0]),
            number(fields[1]),
        ) {
            Ok(()) => write!(out, "ok"),
            Err(Refusal::InvalidMap) => write!(out, "map"),
            Err(Refusal::MissingEntry(id)) => write!(out, "entry:{id:016x}"),
            Err(Refusal::MissingLink(id)) => write!(out, "link:{id:016x}"),
            Err(Refusal::MissingNode(id)) => write!(out, "node:{id:016x}"),
            Err(Refusal::NonterminatingCycle(id)) => write!(out, "cycle:{id:016x}"),
        }
        .expect("status output");
        write!(out, "|").expect("separator output");
        for (i, stamp) in stamps.iter().enumerate() {
            if i != 0 {
                write!(out, ",").expect("value separator");
            }
            write!(out, "{:016x}", stamp.value).expect("value output");
        }
        writeln!(out).expect("newline output");
    }
}
