use node115_token_id::{digest, keccak256, preimage, token_id, Keccak256, RegisterError, TokenIds, TokenSpec, MAX_INDEX};

// Frozen oracle output (generated before this crate existed, see ORACLE_FROZEN.txt).
const CORPUS: &str = include_str!("../../../research/work-items/RE-005-node115-token-id-derivation/corpus.tsv");
const WRONG: &str = include_str!("../../../research/work-items/RE-005-node115-token-id-derivation/wrong-variants.tsv");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn name_of(spec: &str) -> String {
    if let Some(h) = spec.strip_prefix("hex:") {
        String::from_utf8(unhex(h)).unwrap()
    } else {
        let (byte, count) = spec.strip_prefix("rep:").unwrap().split_once('*').unwrap();
        String::from_utf8(vec![unhex(byte)[0]; count.parse().unwrap()]).unwrap()
    }
}

struct Row {
    case: String,
    group: String,
    name: String,
    sz: u8,
    wei: u8,
    index: u64,
    len: usize,
    pre_hex: String,
    digest: Vec<u8>,
    id: Vec<u8>,
}

fn rows() -> Vec<Row> {
    CORPUS
        .lines()
        .skip(1)
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 11, "{line}");
            Row {
                case: f[0].into(),
                group: f[1].into(),
                name: name_of(f[2]),
                sz: f[3].parse().unwrap(),
                wei: f[4].parse().unwrap(),
                index: f[5].parse().unwrap(),
                len: f[6].parse().unwrap(),
                pre_hex: f[8].into(),
                digest: unhex(f[9]),
                id: unhex(f[10]),
            }
        })
        .collect()
}

fn spec(r: &Row) -> TokenSpec<'_> {
    TokenSpec { name: &r.name, sz_decimals: r.sz, wei_decimals: r.wei }
}

#[test]
fn corpus_matches_frozen_oracle() {
    let rows = rows();
    assert_eq!(rows.len(), 104);
    for group in ["anchor", "index", "decimals", "name-length", "name-utf8", "block-boundary", "pair-base", "pair-index"] {
        assert!(rows.iter().any(|r| r.group == group), "{group}");
    }
    for r in &rows {
        let pre = preimage(&spec(r), r.index).unwrap();
        assert_eq!(pre.len(), r.len, "{}", r.case);
        if r.pre_hex != "-" {
            assert_eq!(pre, unhex(&r.pre_hex), "{}", r.case);
        }
        assert_eq!(digest(&spec(r), r.index).unwrap().to_vec(), r.digest, "{}", r.case);
        assert_eq!(token_id(&spec(r), r.index).unwrap().to_vec(), r.id, "{}", r.case);
    }
}

#[test]
fn wrong_implementations_are_not_confused_with_the_node() {
    let rows = rows();
    let mut checked = 0;
    for line in WRONG.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let r = rows.iter().find(|r| r.case == f[0]).unwrap();
        let id = token_id(&spec(r), r.index).unwrap();
        assert_ne!(id.to_vec(), unhex(f[2]), "{} {}", f[0], f[1]);
        checked += 1;
    }
    assert_eq!(checked, 703);
}

#[test]
fn changing_one_field_changes_the_id() {
    let rows = rows();
    let pair_ids: Vec<&Vec<u8>> = rows.iter().filter(|r| r.group.starts_with("pair-")).map(|r| &r.id).collect();
    assert_eq!(pair_ids.len(), 8);
    for (i, a) in pair_ids.iter().enumerate() {
        for b in &pair_ids[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn scout_anchor_by_hand() {
    let spec = TokenSpec { name: "X", sz_decimals: 6, wei_decimals: 8 };
    let want = b"\x92\x83\xa4name\xa1X\xaaszDecimals\x06\xabweiDecimals\x08\x00";
    assert_eq!(preimage(&spec, 0).unwrap(), want.to_vec());
    assert_eq!(token_id(&spec, 0).unwrap().to_vec(), unhex("9058f4586f457c793b70c2871d15c2d5"));
    // index changes only the last byte(s) of the preimage
    assert_eq!(preimage(&spec, 127).unwrap().last(), Some(&0x7f));
    assert_eq!(preimage(&spec, 128).unwrap()[34..], [0xcc, 0x80]);
}

#[test]
fn keccak256_published_vectors_and_chunking() {
    assert_eq!(keccak256(b"").to_vec(), unhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
    assert_eq!(keccak256(b"abc").to_vec(), unhex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"));
    let msg: Vec<u8> = (0..420u32).map(|i| (i * 31 + 7) as u8).collect();
    for n in [0usize, 1, 135, 136, 137, 271, 272, 273, 420] {
        let whole = keccak256(&msg[..n]);
        let mut bytewise = Keccak256::new();
        for b in &msg[..n] {
            bytewise.update(std::slice::from_ref(b));
        }
        assert_eq!(bytewise.finalize(), whole, "{n}");
        let mut split = Keccak256::new();
        split.update(&msg[..n / 3]);
        split.update(&msg[n / 3..n]);
        assert_eq!(split.finalize(), whole, "{n}");
    }
}

// Scope of the registry tests below: only the two checks the crate selected from the caller tail
// of `0x3c48b40` (index limit at `0x3c48f23`, duplicate-id membership at `0x3c48fa8..0x3c48fdf`) and
// the order between them (limit first, no id derived or stored when it fires). They do not
// reproduce registration success or rejection order. The caller rejects earlier, for a nonzero
// index (state word `+0x28`), a `szDecimals` above 5 or a `weiDecimals` below `szDecimals + 5`
// (`0x3c48c4c..0x3c48c9b`), and has a further early return at `0x3c48f0e..0x3c48f1e` (not analysed);
// none of that is modelled. The inputs below are chosen to pass the decimals check, so that each
// one is a state the caller would carry to the two selected checks; nothing here says which
// (spec, index) sequences a real node produces (where `+0x28` is incremented is an open question).

/// The decimals pre-check of the caller, kept in the test only so the inputs can be checked
/// against it. It is not part of the crate API.
fn passes_caller_decimals_precheck(sz: u8, wei: u8, index: u64) -> bool {
    index == 0 || (sz <= 5 && u16::from(wei) >= u16::from(sz) + 5)
}

fn reachable_spec(name: &str, sz: u8, wei: u8, index: u64) -> TokenSpec<'_> {
    assert!(passes_caller_decimals_precheck(sz, wei, index), "{name} sz={sz} wei={wei} index={index}");
    TokenSpec { name, sz_decimals: sz, wei_decimals: wei }
}

#[test]
fn decimals_precheck_helper_rejects_the_former_example() {
    // `AAA, sz=5, wei=8, index=1` was used by an earlier draft of the registry test; the caller
    // rejects it (8 < 5 + 5) before the two selected checks, so it must not be used for them.
    assert!(!passes_caller_decimals_precheck(5, 8, 1));
    assert!(passes_caller_decimals_precheck(5, 8, 0)); // index 0 skips the check
    assert!(passes_caller_decimals_precheck(3, 8, 1)); // 8 >= 3 + 5
    assert!(passes_caller_decimals_precheck(5, 10, 1));
    assert!(!passes_caller_decimals_precheck(6, 255, 1)); // szDecimals above 5
    assert!(!passes_caller_decimals_precheck(0, 4, 1)); // 4 < 0 + 5
}

#[test]
fn selected_check_index_limit_runs_before_id_derivation() {
    let mut ids = TokenIds::new();
    let a = reachable_spec("AAA", 3, 8, 1);
    ids.register(&a, 1).unwrap();
    assert_eq!(ids.len(), 1);
    for index in [MAX_INDEX + 1, u64::MAX] {
        let over = reachable_spec("AAA", 3, 8, index);
        assert_eq!(ids.register(&over, index), Err(RegisterError::TooManyTokens), "{index}");
        // nothing derived or stored when the limit fires
        assert!(!ids.contains(&token_id(&over, index).unwrap()), "{index}");
    }
    assert_eq!(RegisterError::TooManyTokens.message(), "too many tokens");
    assert_eq!(ids.len(), 1);
    let last = ids.register(&a, MAX_INDEX).unwrap();
    assert!(ids.contains(&last));
    assert_eq!(ids.len(), 2);
    assert_eq!(MAX_INDEX, 99_998);
}

#[test]
fn selected_check_duplicate_id_is_key_membership() {
    let mut ids = TokenIds::new();
    let a = reachable_spec("AAA", 3, 8, 0);
    let b = reachable_spec("BBB", 3, 8, 0);
    let first = ids.register(&a, 0).unwrap();
    assert_eq!(first, token_id(&a, 0).unwrap());
    assert_eq!(ids.register(&a, 0), Err(RegisterError::TokenIdAlreadyExists));
    assert_eq!(RegisterError::TokenIdAlreadyExists.message(), "token_id already exists");
    // same spec, next index: different id, so not a duplicate
    let a1 = reachable_spec("AAA", 3, 8, 1);
    ids.register(&a1, 1).unwrap();
    // other spec, same index: different id
    ids.register(&b, 0).unwrap();
    assert_eq!(ids.len(), 3);
    // a rejected duplicate leaves the set unchanged
    assert_eq!(ids.register(&a1, 1), Err(RegisterError::TokenIdAlreadyExists));
    assert_eq!(ids.len(), 3);
}
