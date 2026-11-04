use node115_packed_date_difference::{difference, Difference, Words};
use std::io::{self, BufRead};

fn main() {
    let mut rows = 0_u64;
    let mut mismatches = 0_u64;
    for line in io::stdin().lock().lines() {
        let line = line.expect("frozen ASCII row");
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 9);
        let u = |i: usize| fields[i].parse::<u32>().expect("frozen u32");
        let left = Words {
            date_word: u(0),
            seconds_word: u(1),
            nanos_word: u(2),
        };
        let right = Words {
            date_word: u(3),
            seconds_word: u(4),
            nanos_word: u(5),
        };
        let expected = match fields[6] {
            "0" => None,
            "1" => Some(Difference {
                seconds: fields[7].parse().expect("frozen i64"),
                nanos: u(8),
            }),
            _ => panic!("frozen state"),
        };
        let actual = difference(left, right);
        if actual != expected {
            mismatches += 1;
            if mismatches <= 4 {
                eprintln!("row {rows}: expected {expected:?}, got {actual:?}");
            }
        }
        rows += 1;
        if rows.is_multiple_of(131_072) {
            println!("$ checked {rows}");
        }
    }
    println!("rows={rows} mismatches={mismatches}");
    if mismatches != 0 {
        std::process::exit(1);
    }
}
