use node115_bootstrap_progress::{after_window, completion_check, initial, LastRecord, Plan};
use std::io::{self, BufRead};

fn number(value: &str) -> u64 {
    value.parse().expect("frozen u64")
}

fn main() {
    let mut rows = 0u64;
    let mut mismatches = 0u64;
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        let matches = match fields[0] {
            "I" | "N" => {
                assert_eq!(fields.len(), 7);
                let step = if fields[0] == "I" {
                    initial(number(fields[1]), number(fields[2]))
                } else {
                    after_window(number(fields[1]), number(fields[2]))
                };
                let (code, first, last) = match step.plan {
                    Plan::SpanExit => ("S", 0, 0),
                    Plan::ReversedContinuation => ("R", 0, 0),
                    Plan::Window { first, last } => ("W", first, last),
                };
                step.lower == number(fields[3])
                    && code == fields[4]
                    && first == number(fields[5])
                    && last == number(fields[6])
            }
            "C" => {
                assert_eq!(fields.len(), 9);
                let record = match fields[1] {
                    "0" => None,
                    "1" => Some(LastRecord {
                        tag: number(fields[3]),
                        at_60: number(fields[4]),
                        at_b0: number(fields[5]),
                    }),
                    _ => panic!("frozen last-record flag"),
                };
                let check = completion_check(number(fields[2]), record, number(fields[6]));
                check.expected == number(fields[7])
                    && u64::from(check.matches_target) == number(fields[8])
            }
            _ => panic!("frozen operation"),
        };
        if !matches {
            mismatches += 1;
            if mismatches <= 4 {
                eprintln!("mismatch row {}: {}", rows + 1, line);
            }
        }
        rows += 1;
        if rows.is_multiple_of(131_072) {
            println!("checked {rows}");
        }
    }
    println!("rows={rows} mismatches={mismatches}");
    if mismatches != 0 {
        std::process::exit(1);
    }
}
