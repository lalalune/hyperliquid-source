//! Drives the reconstructed flow with the frozen corpora `cases-*.tsv` (expected values from
//! `gen_flow_corpus.py`, fixed before this crate's flow code was written; see `ORACLE_FROZEN.txt`).
//!
//! The signature primitives are a test-only toy (FNV based digest, XOR "recovery"); it is the same toy
//! the generator uses. A passing case therefore says "given these primitives the flow decides this",
//! never that a real signature verifies. Signatures are materialized here from the case's spec token with
//! this harness' own frame builder, so a frame built differently inside the crate fails the case.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::fs;

use node115_nested_certificate_decision::collect::{Collected, collect_signers};
use node115_nested_certificate_decision::equality::sig_maps_equal;
use node115_nested_certificate_decision::history::{Rounds, StakeHistory};
use node115_nested_certificate_decision::quorum::quorum;
use node115_nested_certificate_decision::signer::{SignaturePrimitives, VoteFrame, signer_check};
use node115_nested_certificate_decision::sigmap::{Address, SigMap, SigRow, Signature};
use node115_nested_certificate_decision::stake::{StakeMap, StakeSet};
use node115_nested_certificate_decision::{
    Certificate, Context, Output, Rejection, StakeSetProvider, Verdict, VerifierResult, decide_nested, verify,
};
use node115_stake_predicate::Row;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../research/work-items/RE-008-node115-nested-certificate-decision/");

// ---- toy primitives (test only) ----------------------------------------------------------------

fn fnv(seed: u64, data: &[u8]) -> u64 {
    let mut h = 0xCBF2_9CE4_8422_2325u64 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for &b in data {
        h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

fn toy_digest(variant: u64, f: &VoteFrame) -> [u8; 32] {
    let mut data = variant.to_le_bytes().to_vec();
    data.extend_from_slice(&f.hash);
    for w in [f.pair[0], f.pair[1], f.f30, f.f38, f.f40] {
        data.extend_from_slice(&w.to_le_bytes());
    }
    data.extend_from_slice(&f.signer);
    let mut out = [0u8; 32];
    for k in 0..4 {
        out[8 * k..8 * k + 8].copy_from_slice(&fnv(k as u64, &data).to_le_bytes());
    }
    out
}

struct Toy<'a> {
    log: &'a RefCell<Vec<String>>,
    last_signer: Cell<Address>,
}

impl SignaturePrimitives for Toy<'_> {
    fn digest(&self, variant: u64, frame: &VoteFrame) -> [u8; 32] {
        self.last_signer.set(frame.signer);
        self.log.borrow_mut().push(format!("D:{variant}:{}", kt(&frame.signer)));
        toy_digest(variant, frame)
    }

    fn recover(&self, signature: &Signature, digest: &[u8; 32]) -> Option<Address> {
        self.log.borrow_mut().push(format!("R:{}", kt(&self.last_signer.get())));
        if signature[64] >= 4 {
            return None;
        }
        let mut a = [0u8; 20];
        for i in 0..20 {
            a[i] = signature[i] ^ digest[i];
        }
        Some(a)
    }
}

struct Provider<'a> {
    set: Option<StakeSet>,
    log: &'a RefCell<Vec<String>>,
}

impl StakeSetProvider for Provider<'_> {
    fn stake_set(&self, _ctx: &Context, round: u64) -> Option<&StakeSet> {
        self.log.borrow_mut().push(format!("P:{round:x}"));
        self.set.as_ref()
    }
}

// ---- parsing -----------------------------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The generator's pool key for a first byte (see `pool_key` in `gen_flow_corpus.py`).
fn pool_key(first: u8) -> Address {
    let mut k = [0u8; 20];
    k[0] = first;
    for n in 0..18 {
        k[1 + n] = ((usize::from(first) * 37 + 11 * n) & 0xFF) as u8;
    }
    k
}

/// Key token as the corpora write it: `K<first byte>` for a pool key, else 40 hex digits.
fn kt(a: &Address) -> String {
    if *a == pool_key(a[0]) { format!("K{:02x}", a[0]) } else { hex(a) }
}

fn unkey(s: &str) -> Address {
    match s.strip_prefix('K') {
        Some(first) => pool_key(u8::from_str_radix(first, 16).unwrap()),
        None => unhex(s),
    }
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    assert_eq!(s.len(), 2 * N, "{s}");
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn u(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}

fn header(s: &str) -> (char, usize, usize, &str) {
    let (head, body) = s.split_once('=').unwrap();
    if head == "T" {
        return ('T', 0, 0, body);
    }
    let (cap, hd) = head[1..].split_once('.').unwrap();
    ('R', cap.parse().unwrap(), hd.parse().unwrap(), body)
}

fn items(body: &str) -> Vec<&str> {
    if body.is_empty() { Vec::new() } else { body.split(',').collect() }
}

/// Places logical entries into a physical ring of `cap` slots starting at `head`.
fn ring_layout<T: Clone>(entries: Vec<T>, cap: usize, head: usize, filler: T) -> Vec<T> {
    let mut rows = vec![filler; cap];
    for (i, e) in entries.into_iter().enumerate() {
        rows[(head + i) % cap] = e;
    }
    rows
}

fn stake_map(s: &str) -> StakeMap {
    let (form, cap, head, body) = header(s);
    let entries: Vec<Row> = items(body)
        .iter()
        .map(|it| {
            let (k, w) = it.split_once(':').unwrap();
            Row { key: unkey(k), weight: u(w) }
        })
        .collect();
    if form == 'T' {
        return StakeMap::tree(entries.iter().map(|r| (r.key, r.weight)));
    }
    let len = entries.len();
    let rows = ring_layout(entries, cap, head, Row { key: [0xFF; 20], weight: 7 });
    StakeMap::ring(rows, head, len).expect("sorted ring")
}

fn key_set(s: &str) -> BTreeSet<Address> {
    if s == "-" { BTreeSet::new() } else { s.split(',').map(unkey).collect() }
}

fn stake_set(s: &str) -> Option<StakeSet> {
    if s == "N" {
        return None;
    }
    let parts: Vec<&str> = s.split('/').collect();
    assert_eq!(parts[0], "S");
    let validators = key_set(parts[2]);
    Some(StakeSet { stakes: stake_map(parts[1]), validators, validator_count: u(parts[3]) })
}

fn make_sig(spec: &str, key: &Address, dg: &[u8; 32]) -> Signature {
    if let Some(rest) = spec.strip_prefix('F') {
        let (byte, pos) = rest.split_once(':').unwrap_or((rest, ""));
        let mut s = [u8::from_str_radix(byte, 16).unwrap(); 65];
        if !pos.is_empty() {
            s[pos.parse::<usize>().unwrap()] ^= 1;
        }
        return s;
    }
    let mut s = [0u8; 65];
    for i in 20..64 {
        s[i] = ((usize::from(key[0]) * 3 + i * 5) & 0xFF) as u8;
    }
    if spec == "E" {
        s[64] = 7;
        return s;
    }
    let target: Address = if spec == "V" { *key } else { unkey(&spec[1..]) };
    for i in 0..20 {
        s[i] = target[i] ^ dg[i];
    }
    s
}

/// `frame_of(key)` builds the frame the signatures are made for (the harness' own builder).
fn sig_map(s: &str, frame_of: &dyn Fn(&Address) -> VoteFrame) -> SigMap {
    let (form, cap, head, body) = header(s);
    let entries: Vec<SigRow> = items(body)
        .iter()
        .map(|it| {
            let (k, spec) = it.split_once('~').unwrap();
            let key: Address = unkey(k);
            let dg = toy_digest(1, &frame_of(&key));
            SigRow { key, sig: make_sig(spec, &key, &dg) }
        })
        .collect();
    if form == 'T' {
        return SigMap::tree(entries);
    }
    let len = entries.len();
    let filler = SigRow { key: [0xFF; 20], sig: [0xEE; 65] };
    SigMap::ring(ring_layout(entries, cap, head, filler), head, len).expect("ring fits")
}

fn rows(path: &str, cols: usize) -> Vec<Vec<String>> {
    let text = fs::read_to_string(format!("{DIR}{path}")).expect("corpus");
    text.lines()
        .skip(1)
        .map(|l| {
            let f: Vec<String> = l.split('\t').map(str::to_string).collect();
            assert_eq!(f.len(), cols, "{l}");
            f
        })
        .collect()
}

fn finish(name: &str, total: usize, bad: &[String], expected_total: usize) {
    println!("CORPUS {name} cases={total} mismatches={}", bad.len());
    for b in bad.iter().take(10) {
        println!("MISMATCH {b}");
    }
    assert_eq!(total, expected_total);
    assert!(bad.is_empty(), "{} mismatches", bad.len());
}

// ---- the reconstructed provider under the whole flow (hand-derived expectations, written with the crate) ----

#[test]
fn history_provider_drives_the_whole_decision() {
    let set = |firsts: &[u8]| {
        let keys: Vec<Address> = firsts.iter().map(|&f| pool_key(f)).collect();
        StakeSet {
            stakes: StakeMap::tree(keys.iter().map(|k| (*k, 10))),
            validators: keys.iter().copied().collect(),
            validator_count: keys.len() as u64,
        }
    };
    let run = |base: u64, execution: u64, round: u64| {
        let history = StakeHistory::new(
            Rounds::tree([(100, set(&[0x10, 0x11])), (4000, set(&[0x12, 0x13]))]),
            base,
            execution,
            0,
        );
        let hash = [0x42u8; 32];
        let frame_of = |k: &Address| VoteFrame { hash, pair: [1, 5], f30: 9, f38: 8, f40: round, signer: *k };
        let cert = Certificate { sigs: sig_map("T=K10~V,K11~V", &frame_of), pair: [1, 5], f30: 9, f38: 8, f40: round, hash };
        let ctx = Context { pair: [1, 5], quorum_fraction_bits: 0 };
        let log = RefCell::new(Vec::new());
        let toy = Toy { log: &log, last_signer: Cell::new([0; 20]) };
        let verdict = verify(&cert, &ctx, &history, &toy);
        // The same certificate through the whole decision: ordered path (5 <= round <= 8 only for small rounds).
        let decided = decide_nested(&cert, &ctx, &history, &toy);
        (verdict, decided.tag(), history.warnings.get())
    };
    let signer = pool_key(0x10);
    // base 100, round 500: q = 100, the first set holds both signers.
    assert_eq!(run(100, 0, 500).0, Verdict::Accepted);
    // base 4000, round 4100: q = 4000, the second set lacks the first signer.
    assert_eq!(run(4000, 0, 4100).0, Verdict::Rejected(Rejection::UnknownSigner { address: signer }));
    // base 50, round 500: q = 50, nothing stored at or below it.
    assert_eq!(run(50, 0, 500).0, Verdict::Rejected(Rejection::NoStakeSet { round: 500 }));
    // base 100, round 100000: warning (limit 2100), q = 99800, the second set; counter counts verify and decide.
    let (verdict, _, warnings) = run(100, 0, 100_000);
    assert_eq!(verdict, Verdict::Rejected(Rejection::UnknownSigner { address: signer }));
    assert_eq!(warnings, 1, "decide_nested stops at 0x2d for this round, so only verify queried the provider");
    // Round 6 satisfies 5 <= round <= 8 < 9: the decision reaches the verifier and forwards its tag 0x2e.
    let (verdict, tag, warnings) = run(100, 0, 6);
    assert_eq!((verdict, tag, warnings), (Verdict::Accepted, Some(0x2e), 0));
}

// ---- corpora -----------------------------------------------------------------------------------

#[test]
fn equality_corpus() {
    // Equality cases carry fill signatures only, so the frame is never used to make a signature.
    let frame =|k: &Address| VoteFrame { hash: [0; 32], pair: [0; 2], f30: 0, f38: 0, f40: 0, signer: *k };
    let mut bad = Vec::new();
    let all = rows("cases-equal.tsv", 5);
    for f in &all {
        let (a, b) = (sig_map(&f[2], &frame), sig_map(&f[3], &frame));
        let want = f[4] == "T";
        if sig_maps_equal(&a, &b) != want || sig_maps_equal(&b, &a) != want {
            bad.push(format!("{} {}", f[0], f[1]));
        }
    }
    finish("equality", all.len(), &bad, 225);
}

#[test]
fn collector_corpus() {
    let frame = |k: &Address| VoteFrame { hash: [0; 32], pair: [0; 2], f30: 0, f38: 0, f40: 0, signer: *k };
    let mut bad = Vec::new();
    let all = rows("cases-collect.tsv", 5);
    for f in &all {
        let set = StakeSet { stakes: stake_map(&f[3]), validators: BTreeSet::new(), validator_count: 0 };
        let got = match collect_signers(&set, &sig_map(&f[2], &frame)) {
            Collected::UnknownSigner(a) => format!("2c:{}", kt(&a)),
            Collected::Signers(s) => format!("2e:{}", s.iter().map(kt).collect::<Vec<_>>().join(",")),
        };
        if got != f[4] {
            bad.push(format!("{} {} got {got}", f[0], f[1]));
        }
    }
    finish("collector", all.len(), &bad, 54);
}

#[test]
fn signer_check_corpus() {
    let mut bad = Vec::new();
    let all = rows("cases-signer.tsv", 14);
    for f in &all {
        let set = StakeSet { stakes: stake_map(&f[2]), validators: BTreeSet::new(), validator_count: 0 };
        let addr: Address = unkey(&f[10]);
        let variant: u64 = f[9].parse().unwrap();
        let frame = VoteFrame {
            hash: [unhex::<1>(&f[3])[0]; 32],
            pair: [u(&f[4]), u(&f[5])],
            f30: u(&f[6]),
            f38: u(&f[7]),
            f40: u(&f[8]),
            signer: addr,
        };
        let sig = make_sig(&f[11], &addr, &toy_digest(variant, &frame));
        let log = RefCell::new(Vec::new());
        let toy = Toy { log: &log, last_signer: Cell::new([0; 20]) };
        let got = signer_check(&toy, variant, &frame, &addr, &sig, &set);
        let joined = if log.borrow().is_empty() { "-".to_string() } else { log.borrow().join(" ") };
        if got != (f[12] == "T") || joined != f[13] {
            bad.push(format!("{} {} got {got} {joined}", f[0], f[1]));
        }
    }
    finish("signer_check", all.len(), &bad, 144);
}

#[test]
fn quorum_corpus() {
    let mut bad = Vec::new();
    let all = rows("cases-quorum.tsv", 8);
    for f in &all {
        let set = StakeSet { stakes: stake_map(&f[2]), validators: key_set(&f[3]), validator_count: u(&f[4]) };
        let signers = key_set(&f[5]);
        if quorum(u(&f[6]), &set, &signers) != (f[7] == "T") {
            bad.push(format!("{} {}", f[0], f[1]));
        }
    }
    finish("quorum", all.len(), &bad, 934);
}

fn render<V>(out: &Output<V>, as_tag: &dyn Fn(&V) -> (String, String)) -> (String, String) {
    let w = |a: u64| format!("{a:x}");
    match out {
        Output::Behind => ("05".into(), "-".into()),
        Output::Unequal => ("06".into(), "-".into()),
        Output::Continue => ("2e".into(), "-".into()),
        Output::Mismatch { cert, ctx } => {
            ("00".into(), format!("{}:{}:{}:{}", w(cert[0]), w(cert[1]), w(ctx[0]), w(ctx[1])))
        }
        Output::OutOfOrder { f30, f38, f40 } => ("2d".into(), format!("{}:{}:{}", w(*f30), w(*f38), w(*f40))),
        Output::Diverges { current, observed } => {
            ("DIVERGE".into(), format!("{}:{}:{}:{}", w(current[0]), w(current[1]), w(observed[0]), w(observed[1])))
        }
        Output::Forwarded(v) => as_tag(v),
    }
}

/// The tag text comes from `tag()` (the byte the native record starts with), the payload from the variant.
fn verdict_text(v: &Verdict) -> (String, String) {
    let payload = match v {
        Verdict::Rejected(Rejection::NoStakeSet { round }) => format!("{round:x}"),
        Verdict::Rejected(Rejection::UnknownSigner { address }) => kt(address),
        _ => "-".to_string(),
    };
    (format!("{:02x}", v.tag()), payload)
}

#[test]
fn verifier_and_decision_corpus() {
    flow_corpus("cases-flow.tsv", "flow", 471);
}

/// Certificates of more than 64 signatures (a multi-leaf tree natively) plus empty certificates; the rows
/// carry the call log, so a wrong signature handed to the check, or a wrong visiting order, changes it.
#[test]
fn tree_signature_corpus() {
    flow_corpus("cases-tree.tsv", "tree", 43);
}

fn flow_corpus(file: &str, name: &str, expected_total: usize) {
    let mut bad = Vec::new();
    let all = rows(file, 17);
    let mut per_entry = [0usize; 2];
    for f in &all {
        let (a, b, c, d, e) = (u(&f[5]), u(&f[6]), u(&f[7]), u(&f[8]), u(&f[9]));
        let hash: [u8; 32] = match f[4].len() {
            1 => [0; 32],
            2 => [unhex::<1>(&f[4])[0]; 32],
            _ => unhex(&f[4]),
        };
        let frame_of = |k: &Address| VoteFrame { hash, pair: [a, b], f30: c, f38: d, f40: e, signer: *k };
        let cert = Certificate { sigs: sig_map(&f[3], &frame_of), pair: [a, b], f30: c, f38: d, f40: e, hash };
        let ctx = Context { pair: [u(&f[10]), u(&f[11])], quorum_fraction_bits: u(&f[12]) };
        let log = RefCell::new(Vec::new());
        let provider = Provider { set: stake_set(&f[13]), log: &log };
        let toy = Toy { log: &log, last_signer: Cell::new([0; 20]) };
        let (tag, payload) = if f[2] == "V" {
            per_entry[0] += 1;
            verdict_text(&verify(&cert, &ctx, &provider, &toy))
        } else {
            per_entry[1] += 1;
            render(&decide_nested(&cert, &ctx, &provider, &toy), &verdict_text)
        };
        let joined = if log.borrow().is_empty() { "-".to_string() } else { log.borrow().join(" ") };
        if tag != f[14] || payload != f[15] || joined != f[16] {
            bad.push(format!("{} {} got {tag} {payload} [{joined}]", f[0], f[1]));
        }
    }
    println!("entries verify={} decision={}", per_entry[0], per_entry[1]);
    finish(name, all.len(), &bad, expected_total);
}
