// SPDX-License-Identifier: MIT
// Input-only native client: stdin contains inputs; expected outputs are never read.
mod lib;
use lib::*;
use std::fmt::Write;
use std::io::{self, BufRead};
type Tokens<'a> = std::str::SplitWhitespace<'a>;
fn number(t: &mut Tokens<'_>) -> u64 {
    t.next().unwrap().parse().unwrap()
}
fn hex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), 2 * N);
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}
fn key(t: &mut Tokens<'_>) -> Key {
    hex(t.next().unwrap())
}
fn keys(t: &mut Tokens<'_>) -> Vec<Key> {
    (0..number(t)).map(|_| key(t)).collect()
}
fn rows(t: &mut Tokens<'_>) -> Vec<Row> {
    (0..number(t)).map(|_| (key(t), number(t))).collect()
}
fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}
fn index(x: Option<usize>) -> String {
    x.map_or_else(|| "-1".into(), |n| n.to_string())
}
fn show_schedule(v: Schedule) -> String {
    let mut s = format!("{} {}", encode(&v.image), v.events.len());
    for e in v.events {
        write!(
            s,
            " {:016x} {} {}",
            e.bits,
            u8::from(e.key.is_some()),
            e.key.map_or_else(|| "-".into(), |k| encode(&k))
        )
        .unwrap();
    }
    write!(s, " {}", v.keys.len()).unwrap();
    for k in v.keys {
        write!(s, " {}", encode(&k)).unwrap();
    }
    s
}
fn evaluate(line: &str) -> String {
    let mut t = line.split_whitespace();
    let op = t.next().unwrap();
    let s = match op {
        "H" => {
            let b = number(&mut t);
            let r = number(&mut t);
            let rs = (0..number(&mut t))
                .map(|_| number(&mut t))
                .collect::<Vec<_>>();
            let (q, i) = history(b, &rs, r).unwrap();
            format!("H {q} {}", index(i))
        }
        "E" => {
            let a = event_bits(
                number(&mut t),
                number(&mut t),
                number(&mut t),
                number(&mut t),
            )
            .unwrap();
            format!("E {:016x} {:016x} {:016x}", a[0], a[1], a[2])
        }
        "Q" => {
            let mut es = (0..number(&mut t))
                .map(|_| {
                    let bits = u64::from_str_radix(t.next().unwrap(), 16).unwrap();
                    let tag = number(&mut t);
                    let k = key(&mut t);
                    Event {
                        bits,
                        key: if tag == 1 { Some(k) } else { None },
                    }
                })
                .collect::<Vec<_>>();
            es.sort_by(event_order);
            let mut s = "Q".to_owned();
            for e in es {
                write!(
                    s,
                    " {:016x} {} {}",
                    e.bits,
                    u8::from(e.key.is_some()),
                    e.key.map_or_else(|| "-".into(), |k| encode(&k))
                )
                .unwrap();
            }
            s
        }
        "P" | "S" => {
            let a = keys(&mut t);
            let b = keys(&mut t);
            let rs = rows(&mut t);
            if op == "S" {
                let r = number(&mut t);
                let image = hex(t.next().unwrap());
                match schedule(&a, &b, &rs, r, image) {
                    Ok(v) => format!("S {}", show_schedule(v)),
                    Err(e) => panic!("{e:?}"),
                }
            } else {
                match prepare(&a, &b, &rs) {
                    Err(e) => panic!("{e:?}"),
                    Ok(p) => {
                        let mut s = format!("P {} {} {}", p.total, p.threshold, p.adjusted.len());
                        for (k, w) in p.adjusted {
                            write!(s, " {} {w}", encode(&k)).unwrap();
                        }
                        write!(s, " {}", p.fallback.len()).unwrap();
                        for (w, k) in p.fallback {
                            write!(s, " {w} {}", encode(&k)).unwrap();
                        }
                        s
                    }
                }
            }
        }
        "G" => {
            let stake = number(&mut t);
            let execution = number(&mut t);
            let base = number(&mut t);
            let query = number(&mut t);
            let counter = number(&mut t);
            let rs = (0..number(&mut t))
                .map(|_| number(&mut t))
                .collect::<Vec<_>>();
            let (q, i) = history(base, &rs, query).unwrap();
            let (limit, counter, warning) = diagnostic(stake, execution, query, counter);
            format!("G {limit} {q} {} {counter} {}", index(i), u8::from(warning))
        }
        "R" => {
            let head = number(&mut t) as usize;
            let count = number(&mut t) as usize;
            let query = number(&mut t);
            let physical = (0..number(&mut t))
                .map(|_| number(&mut t))
                .collect::<Vec<_>>();
            let (n, i) = ring_history(&physical, head, count, query).unwrap();
            format!("R {n} {}", index(i))
        }
        "F" => {
            let selected = number(&mut t);
            let query = number(&mut t);
            let b1 = number(&mut t);
            let b2 = number(&mut t);
            let execution = number(&mut t);
            let counter = number(&mut t);
            let scratch = hex(t.next().unwrap());
            let first = History {
                base: b1,
                snapshots: (0..number(&mut t))
                    .map(|_| (number(&mut t), keys(&mut t)))
                    .collect(),
            };
            let second = History {
                base: b2,
                snapshots: (0..number(&mut t))
                    .map(|_| (number(&mut t), rows(&mut t)))
                    .collect(),
            };
            let extra = keys(&mut t);
            let image = hex(t.next().unwrap());
            match from_histories(
                &first, &second, &extra, selected, query, execution, counter, scratch, image,
            )
            .unwrap()
            {
                HistoryResult::Missing {
                    first: (q, i),
                    second,
                    counter,
                    image,
                } => {
                    let tail =
                        second.map_or_else(|| "- -".into(), |(q, i)| format!("{q} {}", index(i)));
                    format!("F {q} {} {tail} {counter} {}", index(i), encode(&image))
                }
                HistoryResult::Selected {
                    first: (q, i),
                    second: (q2, i2),
                    counter,
                    schedule,
                } => format!(
                    "F {q} {} {q2} {} {counter} {}",
                    index(i),
                    index(i2),
                    show_schedule(schedule)
                ),
            }
        }
        _ => panic!("unknown command"),
    };
    assert!(t.next().is_none());
    s
}
fn main() {
    for line in io::stdin().lock().lines() {
        println!("{}", evaluate(&line.unwrap()));
    }
}
