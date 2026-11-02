use projection::{cap_code, counted_peers, peer_limit};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let words: Vec<u64> = line
            .unwrap()
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        let mut p = words.into_iter();
        let present = p.next().unwrap() != 0;
        let option = p.next().unwrap();
        let incoming = (
            p.next().unwrap().try_into().unwrap(),
            p.next().unwrap().try_into().unwrap(),
        );
        let n = p.next().unwrap();
        let allowed: Vec<u32> = (0..n)
            .map(|_| p.next().unwrap().try_into().unwrap())
            .collect();
        let n = p.next().unwrap();
        let peers: Vec<(u8, u32)> = (0..n)
            .map(|_| {
                (
                    p.next().unwrap().try_into().unwrap(),
                    p.next().unwrap().try_into().unwrap(),
                )
            })
            .collect();
        assert!(p.next().is_none());
        let (limit, clipped) = peer_limit(if present { Some(option) } else { None });
        println!(
            "{} {} {} {}",
            limit,
            u8::from(clipped),
            counted_peers(&peers, &allowed),
            cap_code(&peers, &allowed, limit, incoming)
        );
    }
}
