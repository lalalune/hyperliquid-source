use node115_vault_address::{
    address_digest, address_preimage, caller_address, derive_vault_address, keccak256, CallerReject, CreateVaultRequest, Keccak256,
    AMOUNT_BOUND, AMOUNT_REJECT_TAG, NAME_LEN_LIMIT, NAME_REJECT_TAG,
};

// Frozen oracle output (generated before this crate existed, see ORACLE_FROZEN.txt).
const CORPUS: &str = include_str!("../../../research/work-items/RE-005-node115-vault-address-derivation/corpus.tsv");
const WRONG: &str = include_str!("../../../research/work-items/RE-005-node115-vault-address-derivation/wrong-variants.tsv");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn text_of(spec: &str) -> String {
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
    creator: [u8; 20],
    request: CreateVaultRequest,
    caller_outcome: String,
    len: usize,
    pre_hex: String,
    digest: Vec<u8>,
    address: [u8; 20],
}

fn rows() -> Vec<Row> {
    CORPUS
        .lines()
        .skip(1)
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 14, "{line}");
            Row {
                case: f[0].into(),
                group: f[1].into(),
                creator: unhex(f[2]).try_into().unwrap(),
                request: CreateVaultRequest {
                    max_usdc_fee: if f[7] == "-" { None } else { Some(f[7].parse().unwrap()) },
                    name: text_of(f[3]),
                    description: text_of(f[4]),
                    initial_usd: f[5].parse().unwrap(),
                    nonce: f[6].parse().unwrap(),
                },
                caller_outcome: f[8].into(),
                len: f[9].parse().unwrap(),
                pre_hex: f[11].into(),
                digest: unhex(f[12]),
                address: unhex(f[13]).try_into().unwrap(),
            }
        })
        .collect()
}

// Pins of the packet; the `key_order` entry was extracted from the ELF bytes by `verify_target.py`, not typed by hand.
const PINS: &str = include_str!("../../../research/work-items/RE-005-node115-vault-address-derivation/pins.json");

fn pinned_keys() -> Vec<String> {
    let at = PINS.find("\"keys\": [").expect("key_order entry in pins.json") + "\"keys\": [".len();
    let list = &PINS[at..at + PINS[at..].find(']').unwrap()];
    list.split('"').skip(1).step_by(2).map(str::to_string).collect()
}

/// Keys of the request map of a preimage: skips the outer array header and the creator string, then reads
/// (key string, value) pairs; values are strings or unsigned integers.
fn preimage_keys(pre: &[u8]) -> Vec<String> {
    fn str_at(b: &[u8]) -> (&[u8], &[u8]) {
        let (len, head) = match b[0] {
            m @ 0xa0..=0xbf => (usize::from(m & 0x1f), 1),
            0xd9 => (usize::from(b[1]), 2),
            0xda => (usize::from(u16::from_be_bytes([b[1], b[2]])), 3),
            0xdb => (u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize, 5),
            m => panic!("not a string marker: {m:#x}"),
        };
        (&b[head..head + len], &b[head + len..])
    }
    fn uint_end(b: &[u8]) -> &[u8] {
        match b[0] {
            0x00..=0x7f => &b[1..],
            0xcc => &b[2..],
            0xcd => &b[3..],
            0xce => &b[5..],
            0xcf => &b[9..],
            m => panic!("not an unsigned marker: {m:#x}"),
        }
    }
    assert_eq!(pre[0], 0x92);
    let (_creator, rest) = str_at(&pre[1..]);
    let count = usize::from(rest[0] & 0x0f);
    assert_eq!(rest[0] & 0xf0, 0x80);
    let mut rest = &rest[1..];
    let mut keys = Vec::new();
    for _ in 0..count {
        let (key, after) = str_at(rest);
        keys.push(String::from_utf8(key.to_vec()).unwrap());
        rest = if matches!(after[0], 0xa0..=0xbf | 0xd9..=0xdb) { str_at(after).1 } else { uint_end(after) };
    }
    assert!(rest.is_empty());
    keys
}

fn base() -> (CreateVaultRequest, [u8; 20]) {
    let request = CreateVaultRequest { max_usdc_fee: None, name: "v".into(), description: String::new(), initial_usd: 1, nonce: 2 };
    (request, [0; 20])
}

#[test]
fn corpus_matches_frozen_oracle() {
    // Fixed expected values (the frozen oracle, same author's reading of the bytes); not a comparison with the node.
    let rows = rows();
    assert_eq!(rows.len(), 135);
    for group in ["anchor", "initial-usd", "nonce", "creator", "name-length", "description-length", "utf8-name", "utf8-description",
                  "block-boundary", "caller-check", "fee-invariance", "pair-name", "pair-swap-usd-nonce"] {
        assert!(rows.iter().any(|r| r.group == group), "{group}");
    }
    for r in &rows {
        let pre = address_preimage(&r.creator, &r.request).unwrap();
        assert_eq!(pre.len(), r.len, "{}", r.case);
        if r.pre_hex != "-" {
            assert_eq!(pre, unhex(&r.pre_hex), "{}", r.case);
        }
        assert_eq!(address_digest(&r.creator, &r.request).unwrap().to_vec(), r.digest, "{}", r.case);
        // the modelled entry applies no name/amount limit, so it derives an address for rows the caller rejects too
        assert_eq!(derive_vault_address(&r.creator, &r.request).unwrap(), r.address, "{}", r.case);
        let want = match caller_address(&r.creator, &r.request) {
            Ok(address) => {
                assert_eq!(address, r.address, "{}", r.case);
                "ok".to_string()
            }
            Err(CallerReject::NameTooLong { .. }) => "name_too_long".to_string(),
            Err(CallerReject::AmountTooLarge { value }) => format!("amount_too_large:{value}"),
            Err(other) => panic!("{}: {other:?}", r.case),
        };
        assert_eq!(want, r.caller_outcome, "{}", r.case);
    }
}

#[test]
fn crate_address_differs_from_every_frozen_wrong_variant_address() {
    // Compares the crate with the frozen oracle's addresses of deliberately wrong implementations (fixed expected
    // values). Nothing here is compared with a running node.
    let rows = rows();
    let mut checked = 0;
    for line in WRONG.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 3, "{line}");
        let row = rows.iter().find(|r| r.case == f[0]).unwrap();
        let wrong = unhex(f[2]);
        let ours = derive_vault_address(&row.creator, &row.request).unwrap();
        assert_ne!(ours.to_vec(), wrong, "{} {}", f[0], f[1]);
        checked += 1;
    }
    assert_eq!(checked, 1428);
}

#[test]
fn max_usdc_fee_has_no_influence_on_the_derivation() {
    for r in rows() {
        let without = CreateVaultRequest { max_usdc_fee: None, ..r.request.clone() };
        for fee in [None, Some(0), Some(1), Some(u64::MAX), Some(AMOUNT_BOUND)] {
            let with = CreateVaultRequest { max_usdc_fee: fee, ..r.request.clone() };
            assert_eq!(address_preimage(&r.creator, &with), address_preimage(&r.creator, &without), "{}", r.case);
            assert_eq!(derive_vault_address(&r.creator, &with), derive_vault_address(&r.creator, &without), "{}", r.case);
        }
    }
    // and the frozen corpus has twelve fee values for one request with a single address
    let same: Vec<_> = rows().into_iter().filter(|r| r.group == "fee-invariance").collect();
    assert_eq!(same.len(), 12);
    assert!(same.iter().all(|r| r.address == same[0].address));
}

#[test]
fn one_field_changed_addresses_are_all_distinct() {
    let rows = rows();
    let fee_free: Vec<_> = rows.iter().filter(|r| r.request.max_usdc_fee.is_none()).collect();
    let mut seen = std::collections::BTreeMap::new();
    for r in &fee_free {
        assert!(seen.insert(derive_vault_address(&r.creator, &r.request).unwrap(), &r.case).is_none(), "{}", r.case);
    }
    assert!(rows.iter().filter(|r| r.group.starts_with("pair-")).count() >= 10);
}

#[test]
fn request_map_keys_follow_the_order_extracted_from_the_binary() {
    let pinned = pinned_keys();
    assert_eq!(pinned.len(), 5, "{pinned:?}");
    assert_eq!(pinned[4], "maxUsdcFee"); // the optional field comes last in the writer and is never reached from the entry
    for r in rows().iter().filter(|r| r.len <= 600) {
        let keys = preimage_keys(&address_preimage(&r.creator, &r.request).unwrap());
        assert_eq!(keys, pinned[..4], "{}", r.case);
    }
}

#[test]
fn scout_anchor_by_hand() {
    // creator 00 x 20, name "v", description "", initialUsd 1, nonce 2: 85 bytes, from the MessagePack rules by hand.
    let mut want = vec![0x92, 0xd9, 0x2a];
    want.extend_from_slice(b"0x");
    want.extend_from_slice(&[b'0'; 40]);
    want.extend_from_slice(&[0x84, 0xa4]);
    want.extend_from_slice(b"name");
    want.extend_from_slice(&[0xa1, b'v', 0xab]);
    want.extend_from_slice(b"description");
    want.extend_from_slice(&[0xa0, 0xaa]);
    want.extend_from_slice(b"initialUsd");
    want.extend_from_slice(&[0x01, 0xa5]);
    want.extend_from_slice(b"nonce");
    want.push(0x02);
    assert_eq!(want.len(), 85);
    let (request, creator) = base();
    assert_eq!(address_preimage(&creator, &request).unwrap(), want);
    // digest value recorded by the scout (Node/OpenSSL keccak-256)
    assert_eq!(address_digest(&creator, &request).unwrap().to_vec(), unhex("91378d2649be144c8abfa4d4b7626d5413ceb45ee2038e0a306c1e6cdd4c676c"));
    assert_eq!(derive_vault_address(&creator, &request).unwrap().to_vec(), unhex("91378d2649be144c8abfa4d4b7626d5413ceb45e"));
}

#[test]
fn keccak256_published_vectors_and_chunking() {
    assert_eq!(keccak256(b"").to_vec(), unhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
    assert_eq!(keccak256(b"abc").to_vec(), unhex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"));
    assert_eq!(
        keccak256(b"The quick brown fox jumps over the lazy dog").to_vec(),
        unhex("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15")
    );
    // incremental absorption equals one-shot at and around the rate multiples
    for len in [0usize, 1, 135, 136, 137, 271, 272, 273, 408, 500] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
        let mut chunked = Keccak256::new();
        for piece in data.chunks(61) {
            chunked.update(piece);
        }
        assert_eq!(chunked.finalize(), keccak256(&data), "{len}");
    }
}

#[test]
fn caller_name_limit_and_its_precedence_over_the_amount_check() {
    let (mut request, creator) = base();
    request.name = "n".repeat(NAME_LEN_LIMIT);
    assert_eq!(caller_address(&creator, &request).unwrap(), derive_vault_address(&creator, &request).unwrap());
    request.name = "n".repeat(NAME_LEN_LIMIT + 1);
    let reject = caller_address(&creator, &request).unwrap_err();
    assert_eq!(reject, CallerReject::NameTooLong { len: 101 });
    assert_eq!(reject.tag(), Some(NAME_REJECT_TAG));
    // the entry function by itself still derives an address for that name (entry-only input, see README)
    assert!(derive_vault_address(&creator, &request).is_ok());
    // name wins over a bad amount because it is decided before the address exists
    request.initial_usd = AMOUNT_BOUND;
    assert_eq!(caller_address(&creator, &request).unwrap_err(), CallerReject::NameTooLong { len: 101 });
    // multi-byte names are measured in bytes: 34 characters of 3 bytes = 102 bytes
    request.initial_usd = 1;
    request.name = "日".repeat(34);
    assert_eq!(caller_address(&creator, &request).unwrap_err(), CallerReject::NameTooLong { len: 102 });
}

#[test]
fn caller_amount_bound_and_which_value_is_reported_first() {
    let (mut request, creator) = base();
    request.initial_usd = AMOUNT_BOUND - 1;
    assert!(caller_address(&creator, &request).is_ok());
    request.initial_usd = AMOUNT_BOUND;
    let reject = caller_address(&creator, &request).unwrap_err();
    assert_eq!(reject, CallerReject::AmountTooLarge { value: AMOUNT_BOUND });
    assert_eq!(reject.tag(), Some(AMOUNT_REJECT_TAG));
    // the first offending value is reported: initialUsd before maxUsdcFee
    request.max_usdc_fee = Some(AMOUNT_BOUND + 5);
    assert_eq!(caller_address(&creator, &request).unwrap_err(), CallerReject::AmountTooLarge { value: AMOUNT_BOUND });
    request.initial_usd = 1;
    assert_eq!(caller_address(&creator, &request).unwrap_err(), CallerReject::AmountTooLarge { value: AMOUNT_BOUND + 5 });
    request.max_usdc_fee = Some(AMOUNT_BOUND - 1);
    assert!(caller_address(&creator, &request).is_ok());
    // the bound is floor(2^64 / 20): twenty times it fits a u64, twenty times the next integer does not
    assert!(AMOUNT_BOUND.checked_mul(20).is_some() && (AMOUNT_BOUND + 1).checked_mul(20).is_none());
    // nonce has no bound in this caller
    request.max_usdc_fee = None;
    request.nonce = u64::MAX;
    assert!(caller_address(&creator, &request).is_ok());
}
