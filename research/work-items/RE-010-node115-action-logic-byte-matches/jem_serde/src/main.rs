#![forbid(unsafe_code)]
#![allow(dead_code)]

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::collections::{BTreeMap, VecDeque};
use std::hint::black_box;
use std::io::BufReader;

use serde::Deserialize;

#[derive(Deserialize)]
struct NonceSetDe(VecDeque<u64>);

#[derive(Deserialize)]
#[serde(from = "NonceSetDe")]
struct NonceSet(VecDeque<u64>);

impl From<NonceSetDe> for NonceSet {
    fn from(NonceSetDe(nonces): NonceSetDe) -> Self {
        assert!(nonces.iter().is_sorted_by(|a, b| a < b), "nonce invariant");
        Self(nonces)
    }
}

#[derive(Deserialize)]
struct Holder {
    a: BTreeMap<u64, NonceSet>,
    b: Vec<NonceSet>,
}

fn force_de<'de, D: serde::Deserializer<'de>>(d: D) -> Result<NonceSet, D::Error> {
    let f: fn(D) -> Result<NonceSet, D::Error> = NonceSet::deserialize;
    black_box(f)(d)
}

fn main() {
    let js = black_box("{}");
    let jb = black_box(b"{}".as_slice());
    let mp = black_box(&[0x80u8][..]);
    let _ = black_box(serde_json::from_str::<Holder>(js));
    let _ = black_box(serde_json::from_slice::<Holder>(jb));
    let _ = black_box(serde_json::from_reader::<_, Holder>(std::io::Cursor::new(jb)));
    if let Ok(f) = std::fs::File::open("/dev/null") {
        let _ = black_box(serde_json::from_reader::<_, Holder>(BufReader::new(f)));
    }
    let _ = black_box(serde_json::from_value::<Holder>(black_box(serde_json::Value::Null)));
    let _ = black_box(rmp_serde::from_slice::<Holder>(mp));
    let _ = black_box(rmp_serde::from_read::<_, Holder>(std::io::Cursor::new(mp)));
    if let Ok(f) = std::fs::File::open("/dev/null") {
        let _ = black_box(rmp_serde::from_read::<_, Holder>(BufReader::new(f)));
    }
    let mut de1 = rmp_serde::Deserializer::from_read_ref(mp);
    let _ = black_box(force_de(&mut de1));
    if let Ok(f) = std::fs::File::open("/dev/null") {
        let mut de2 = rmp_serde::Deserializer::new(BufReader::new(f));
        let _ = black_box(force_de(&mut de2));
    }
    let mut de3 = rmp_serde::Deserializer::new(std::io::Cursor::new(mp));
    let _ = black_box(force_de(&mut de3));
    let mut de4 = rmp_serde::Deserializer::from_read_ref(mp).with_human_readable();
    let _ = black_box(force_de(&mut de4));
    let mut j1 = serde_json::Deserializer::from_str(js);
    let _ = black_box(force_de(&mut j1));
    let mut j2 = serde_json::Deserializer::from_slice(jb);
    let _ = black_box(force_de(&mut j2));
    if let Ok(f) = std::fs::File::open("/dev/null") {
        let mut j3 = serde_json::Deserializer::from_reader(BufReader::new(f));
        let _ = black_box(force_de(&mut j3));
    }
}
