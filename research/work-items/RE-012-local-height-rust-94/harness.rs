extern crate node94_local_height;
use node94_local_height::{classify, select_heights, HeightDecision, Heights};
use std::io::{self, BufRead};

// This runner receives input words only, never expected decisions.
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut words = line.split_whitespace();
        match words.next().unwrap() {
            "S" => {
                let count = words.next().unwrap().parse().unwrap();
                let raw: Vec<u64> = words.map(|w| w.parse().unwrap()).collect();
                assert_eq!(raw.len() % 2, 0);
                let values: Vec<_> = raw.chunks_exact(2)
                    .map(|p| Heights { initial: p[0], latest: p[1] }).collect();
                match select_heights(count, &values) {
                    None => println!("N"),
                    Some(h) => println!("S {} {}", h.initial, h.latest),
                }
            }
            "G" => {
                let raw: Vec<u64> = words.map(|w| w.parse().unwrap()).collect();
                assert_eq!(raw.len(), 3);
                let h = Heights { initial: raw[1], latest: raw[2] };
                let code = match classify(raw[0], h) {
                    HeightDecision::Continue => 0,
                    HeightDecision::TooFarBehind => 1,
                    HeightDecision::StaleHardfork => 2,
                };
                println!("G {}", code);
            }
            _ => panic!("invalid input kind"),
        }
    }
}
