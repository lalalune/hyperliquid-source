//! Replays the frozen corpus (`gen_oracle.py`: hand SipHash checked against the paper vector and CPython,
//! dict cache) through the crate. A pass means the crate agrees with that oracle on these inputs; it is not
//! a comparison with the node. The 20-byte parser in the row tests is a stand-in (40 chars of `[0-9a-f]`),
//! not the node's parser at `0x150d640`.
use node115_shortstring_intern::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn corpus() -> String {
    let path = match std::env::var_os("SHORTSTRING_CORPUS") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../research/work-items/RE-001-node115-shortstring-intern-cid-key/corpus.txt"),
    };
    std::fs::read_to_string(&path).expect("corpus.txt")
}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn name_of(s: &str) -> String {
    String::from_utf8(unhex(s)).expect("corpus names are UTF-8")
}

fn lines<'a>(text: &'a str, tag: &'static str) -> impl Iterator<Item = Vec<&'a str>> {
    text.lines().filter(move |l| l.split(' ').next() == Some(tag)).map(|l| l.split(' ').collect())
}

fn fill_name(n: usize) -> String {
    format!("cache-fill-{n:08}")
}

/// fill counts the corpus asks for -> a cache after that many `key_for(cache-fill-N)` calls
fn snapshots(text: &str) -> BTreeMap<usize, KeyCache> {
    let mut want: Vec<usize> = lines(text, "CACHE").chain(lines(text, "ROWS")).map(|f| f[2].parse().unwrap()).collect();
    want.sort();
    want.dedup();
    let mut out = BTreeMap::new();
    let mut cache = KeyCache::new();
    let mut n = 0;
    for &w in &want {
        while n < w {
            cache.key_for(&fill_name(n));
            n += 1;
        }
        out.insert(w, cache.clone());
    }
    out
}

#[test]
fn sip13_zero_key_matches_corpus_for_whole_byte_by_byte_and_split_writes() {
    let text = corpus();
    let mut n = 0;
    for f in lines(&text, "SIP") {
        let msg = unhex(f[1]);
        let want = u64::from_str_radix(f[2], 16).unwrap();
        let mut whole = SipHasher13::new_zero_key();
        whole.write(&msg);
        assert_eq!(whole.finish(), want, "whole {}", f[1]);
        let mut bytes = SipHasher13::new_zero_key();
        for b in &msg {
            bytes.write(&[*b]);
        }
        assert_eq!(bytes.finish(), want, "byte by byte {}", f[1]);
        for cut in [0, 1, 3, 5, 7, 8, 9, msg.len() / 2, msg.len()] {
            let cut = cut.min(msg.len());
            let mut two = SipHasher13::new_zero_key();
            two.write(&msg[..cut]);
            two.write(&msg[cut..]);
            assert_eq!(two.finish(), want, "split {cut} {}", f[1]);
        }
        n += 1;
    }
    assert_eq!(n, 48);
}

#[test]
fn name_to_key_and_generated_letters_match_corpus_on_a_fresh_cache() {
    let text = corpus();
    let mut n = 0;
    for f in lines(&text, "KEY") {
        let name = name_of(f[1]);
        let want = u128::from_str_radix(f[3], 16).unwrap();
        let got = KeyCache::new().key_for(&name);
        assert_eq!(got.key, want, "key for {}", f[1]);
        if f[2] == "-" {
            assert_eq!(got.path, Path::Short, "{}", f[1]);
            assert!(name.len() <= 16);
        } else {
            assert_eq!(got.path, Path::MissInserted, "{}", f[1]);
            assert_eq!(generated_name(name.as_bytes()), f[2].as_bytes(), "letters for {}", f[1]);
        }
        n += 1;
    }
    assert_eq!(n, 263);
    // the key space is ten capital letters, so different names can share a key: a long name and the
    // short name made of its generated letters (a corpus line, not a claim about the node)
    let f = lines(&text, "COLLIDE").next().unwrap();
    let (long, short) = (name_of(f[1]), name_of(f[2]));
    let want = u128::from_str_radix(f[3], 16).unwrap();
    assert_ne!(long, short);
    assert!(long.len() > 16 && short.len() <= 16);
    let (l, s) = (KeyCache::new().key_for(&long), KeyCache::new().key_for(&short));
    assert_eq!((l.key, l.path), (want, Path::MissInserted));
    assert_eq!((s.key, s.path), (want, Path::Short));
}

#[test]
fn first_20000_fill_names_give_20000_distinct_keys_like_the_corpus_observation() {
    let text = corpus();
    let f = lines(&text, "DISTINCT").next().unwrap();
    let count: usize = f[2].parse().unwrap();
    let mut keys = std::collections::HashSet::new();
    let mut cache = KeyCache::new();
    for n in 0..count {
        keys.insert(cache.key_for(&fill_name(n)).key);
    }
    assert_eq!(keys.len(), f[3].parse::<usize>().unwrap());
}

#[test]
fn cache_paths_and_sizes_match_corpus_around_the_99999_100000_limit() {
    let text = corpus();
    let snaps = snapshots(&text);
    let mut probes = 0;
    for f in lines(&text, "CACHE") {
        let mut cache = snaps[&f[2].parse::<usize>().unwrap()].clone();
        for (i, p) in f[3..].iter().enumerate() {
            let parts: Vec<&str> = p.split(':').collect();
            let got = cache.key_for(&name_of(parts[0]));
            let path = match got.path {
                Path::Short => "short",
                Path::Hit => "hit",
                Path::MissInserted => "miss_inserted",
                Path::MissNotInserted => "miss_not_inserted",
            };
            assert_eq!((path, cache.len()), (parts[1], parts[2].parse().unwrap()), "{} probe {i}", f[1]);
            probes += 1;
        }
    }
    assert_eq!(probes, 47);
}

fn standin_parse20(t: &str) -> Result<[u8; 20], ()> {
    if t.len() != 40 || !t.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err(());
    }
    let mut out = [0u8; 20];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap();
    }
    Ok(out)
}

#[test]
fn rows_intern_each_name_before_the_standin_parse_matches_corpus() {
    let text = corpus();
    let snaps = snapshots(&text);
    let mut scenarios = 0;
    for f in lines(&text, "ROWS") {
        let mut cache = snaps[&f[2].parse::<usize>().unwrap()].clone();
        let items: Vec<(String, String)> = if f[3] == "-" {
            Vec::new()
        } else {
            f[3].split(',')
                .map(|it| {
                    let (n, t) = it.split_once('/').unwrap();
                    (name_of(n), name_of(t))
                })
                .collect()
        };
        let got = build_rows(&mut cache, items.iter().map(|(n, t)| (n.as_str(), t.as_str())), standin_parse20);
        assert_eq!(f[4], "=>");
        match (got, f[5]) {
            (Ok(rows), "OK") => {
                let want: Vec<String> = rows.iter().map(|r| format!("{:032x}:{}", r.key, hex(&r.value))).collect();
                let want = if want.is_empty() { "-".to_string() } else { want.join(",") };
                assert_eq!(want, f[6], "{}", f[1]);
                assert_eq!(cache.len(), f[7].parse::<usize>().unwrap(), "{}", f[1]);
            }
            (Err(e), "ERR") => {
                assert_eq!(e.index, f[6].parse::<usize>().unwrap(), "{}", f[1]);
                assert_eq!(cache.len(), f[7].parse::<usize>().unwrap(), "{}", f[1]);
            }
            (got, want) => panic!("{}: got {got:?}, corpus {want}", f[1]),
        }
        scenarios += 1;
    }
    assert_eq!(scenarios, 10);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn three_scouting_values_computed_by_cpython_siphash13() {
    // SCOUT.md: values from CPython (PYTHONHASHSEED=0, siphash13, cutoff 0), not from this crate
    let mut c = KeyCache::new();
    assert_eq!(c.key_for("abcdefghijklmnop").key, 0x706f6e6d6c6b6a696867666564636261);
    assert_eq!(generated_name(b"abcdefghijklmnopq"), *b"XGOKOCQCLX");
    assert_eq!(c.key_for("abcdefghijklmnopq").key, 0x584c4351434f4b4f4758);
    assert_eq!(generated_name(b"HyperliquidShortString"), *b"SPHUYUDMKY");
    assert_eq!(c.key_for("HyperliquidShortString").key, 0x594b4d44555955485053);
}

#[test]
fn short_names_never_touch_the_cache_and_length_counts_bytes() {
    let mut c = KeyCache::new();
    assert_eq!(c.key_for("").key, 0);
    for s in ["a", "abcdefghijklmnop"] {
        assert_eq!(c.key_for(s).path, Path::Short);
    }
    assert!(c.is_empty());
    // 8 two-byte characters = 16 bytes (short); 9 = 18 bytes (long)
    assert_eq!(c.key_for(&"é".repeat(8)).path, Path::Short);
    assert_eq!(c.key_for(&"é".repeat(9)).path, Path::MissInserted);
    assert_eq!(c.len(), 1);
}

#[test]
fn fold_overflow_domain_is_the_prior_packets_rule() {
    // RE-001-node115-shortstring-le-u128-fold: fits iff every byte at index >= 16 is zero
    let mut b = [0u8; 17];
    b[0] = 1;
    assert_eq!(fold_le_u128(&b), Ok(1));
    b[16] = 1;
    assert_eq!(fold_le_u128(&b), Err(FoldOverflow));
    assert_eq!(fold_le_u128(&[0xff; 16]), Ok(u128::MAX));
}

#[test]
fn generated_letters_are_ten_capital_letters() {
    for n in 17..80 {
        let g = generated_name(&vec![b'x'; n]);
        assert!(g.iter().all(|c| c.is_ascii_uppercase()), "{n}");
    }
}
