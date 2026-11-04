use node115_exchange_freeze_prelude::{basic, secondary, Selection};
use std::io::{self, BufRead};
use std::num::NonZeroU64;

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 6, "inputs only");
        let lane: u8 = f[0].parse().unwrap();
        let args = (
            f[1].parse().unwrap(),
            f[2].parse().unwrap(),
            f[3].parse().unwrap(),
            f[4].parse().unwrap(),
        );
        let answer = match lane {
            0 => basic(args.0, args.1, args.2, args.3),
            1 | 2 => secondary(
                args.0,
                args.1,
                args.2,
                args.3,
                NonZeroU64::new(f[5].parse().unwrap()).expect("qualified positive cadence"),
            ),
            _ => panic!("unknown lane"),
        };
        match answer {
            Selection::PastTargetBoundary => println!("X"),
            Selection::SentinelHandoff => println!("R"),
            Selection::SkipContinuation => println!("K"),
            Selection::Prepare {
                requested,
                freeze_equal,
            } => println!("P\t{}\t{}", u8::from(requested), u8::from(freeze_equal)),
        }
    }
}
