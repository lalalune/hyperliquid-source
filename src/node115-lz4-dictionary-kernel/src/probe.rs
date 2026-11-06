use node115_lz4_dictionary_kernel::{self as kernel, BeforeProbe, Verdict};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<_> = line.split('\t').collect();
        let pattern: Vec<u8> = v[1]
            .as_bytes()
            .chunks_exact(2)
            .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
            .collect();
        let n: usize = v[2].parse().unwrap();
        let pos: usize = v[3].parse().unwrap();
        let origin: u64 = v[4].parse().unwrap();
        let old: u64 = v[5].parse().unwrap();
        let source: Vec<u8> = (0..n).map(|i| pattern[i % pattern.len()]).collect();
        let result = if v[0] == "s" {
            let mut table = [0xa5a5_u16; 4096];
            let bucket = if pos.checked_add(4).is_some_and(|x| x <= n) {
                Some(kernel::small_bucket(
                    source[pos..pos + 4].try_into().unwrap(),
                ))
            } else {
                None
            };
            if let Some(b) = bucket {
                table[b] = old as u16;
            }
            let before = table;
            let result = kernel::small_probe(&mut table, &source, pos, origin);
            for i in 0..4096 {
                if result.is_err() || Some(i) != bucket {
                    assert_eq!(table[i], before[i]);
                }
            }
            if let Ok(p) = result {
                assert_eq!(u64::from(table[p.bucket]), p.stored);
            }
            result
        } else {
            let mut table = [0xa5a5_a5a5_u32; 4096];
            let bucket = if pos.checked_add(8).is_some_and(|x| x <= n) {
                Some(kernel::large_bucket(
                    source[pos..pos + 8].try_into().unwrap(),
                ))
            } else {
                None
            };
            if let Some(b) = bucket {
                table[b] = old as u32;
            }
            let before = table;
            let result = kernel::large_probe(&mut table, &source, pos, origin);
            for i in 0..4096 {
                if result.is_err() || Some(i) != bucket {
                    assert_eq!(table[i], before[i]);
                }
            }
            if let Ok(p) = result {
                assert_eq!(u64::from(table[p.bucket]), p.stored);
            }
            result
        };
        match result {
            Err(BeforeProbe::InvalidPosition) => println!("-,-,-,precondition"),
            Err(BeforeProbe::AbsoluteOverflow) => println!("-,-,-,absolute-overflow"),
            Ok(p) => {
                let s = match p.verdict {
                    Verdict::CandidateAhead => "candidate-ahead".into(),
                    Verdict::BeforeOrigin => "before-origin".into(),
                    Verdict::TooFar => "too-far".into(),
                    Verdict::Different => "different".into(),
                    Verdict::Match {
                        candidate,
                        distance,
                    } => format!("match:{candidate}:{distance}"),
                };
                println!("{},{},{},{}", p.bucket, p.previous, p.stored, s);
            }
        }
    }
}
