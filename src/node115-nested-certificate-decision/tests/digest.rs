//! The digest side of the per-signature check: hasher, message encoding, digest builder, recovery wrapper, and
//! the whole verifier with the real digest. Expected values are the frozen corpora `cases-keccak.tsv`,
//! `cases-digest.tsv`, `cases-recover.tsv`, `cases-primitives.tsv` (generator `gen_digest_corpus.py`, fixed
//! before the Rust of `keccak.rs`, `digest.rs`, `recover.rs` and `primitives.rs` existed; see `ORACLE_FROZEN.txt`
//! FREEZE 4), plus one preimage derived by hand from the disassembly.
//!
//! The curve routine is a stand-in everywhere here (it returns a key the case names, or fails); nothing in
//! this file verifies a real signature.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;

use node115_nested_certificate_decision::digest::{PREFIX, digest, preimage, put_varint, serialize_message};
use node115_nested_certificate_decision::keccak::{Hasher, keccak256};
use node115_nested_certificate_decision::primitives::NodePrimitives;
use node115_nested_certificate_decision::recover::{RecoverError, Secp256k1, recover_address, recovery_id};
use node115_nested_certificate_decision::signer::{VoteFrame, signer_check};
use node115_nested_certificate_decision::sigmap::{Address, SigMap, SigRow, Signature};
use node115_nested_certificate_decision::stake::{StakeMap, StakeSet};
use node115_nested_certificate_decision::{Certificate, Context, Rejection, StakeSetProvider, Verdict, verify};

// The sibling file starts with `#![no_std]`, which is only meaningful at a crate root; the lint says so.
#[allow(unused_attributes)]
#[path = "../../node115-sponge-permutation/lib.rs"]
mod sponge_reference;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../research/work-items/RE-008-node115-nested-certificate-decision/");

fn unhex_vec(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    assert_eq!(s.len() % 2, 0, "{s}");
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    unhex_vec(s).try_into().unwrap_or_else(|v: Vec<u8>| panic!("{} bytes, wanted {N}", v.len()))
}

fn word(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}

fn rows(name: &str) -> Vec<Vec<String>> {
    let text = fs::read_to_string(format!("{DIR}{name}")).unwrap();
    text.lines().skip(1).map(|l| l.split('\t').map(str::to_owned).collect()).collect()
}

fn ramp(n: usize) -> Vec<u8> {
    (0..n).map(|i| (7 * i + 3) as u8).collect()
}

fn report(name: &str, cases: usize, mismatches: &[String]) {
    println!("CORPUS {name} cases={cases} mismatches={}", mismatches.len());
    for m in mismatches.iter().take(5) {
        println!("  MISMATCH {m}");
    }
    assert!(mismatches.is_empty(), "{name}: {} mismatches", mismatches.len());
}

#[test]
fn hasher_matches_the_keccak_corpus_and_public_vectors() {
    let table = rows("cases-keccak.tsv");
    assert_eq!(table.len(), 347);
    let mut bad = Vec::new();
    for r in &table {
        let delim = u8::from_str_radix(&r[2], 16).unwrap();
        let data = if r[3] == "ramp" { ramp(r[4].parse().unwrap()) } else { unhex_vec(&r[4]) };
        let want: [u8; 32] = unhex(&r[5]);
        let mut whole = Hasher::with_delimiter(delim);
        whole.update(&data);
        if whole.finalize() != want {
            bad.push(format!("{} one-shot", r[0]));
        }
        if delim == 0x01 && keccak256(&data) != want {
            bad.push(format!("{} keccak256()", r[0]));
        }
        // the same bytes in pieces: offsets inside a block, on the block edge and across it
        for piece in [1usize, 7, 135, 136, 137] {
            let mut h = Hasher::with_delimiter(delim);
            for chunk in data.chunks(piece) {
                h.update(chunk);
            }
            if h.finalize() != want {
                bad.push(format!("{} in pieces of {piece}", r[0]));
            }
        }
    }
    report("keccak", table.len(), &bad);
}

#[test]
fn keccak_f_agrees_with_the_sponge_permutation_crate() {
    // node115-sponge-permutation compared the original instructions of 0x5cda380 on 262 whole states; this
    // checks this crate's permutation against that Rust function on states that exercise every lane.
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut bad = Vec::new();
    for case in 0..300 {
        let mut a = [0u64; 25];
        match case {
            0 => {}
            1 => a = [u64::MAX; 25],
            c if c < 27 => a[c - 2] = 1u64 << (c % 64),
            _ => a.iter_mut().for_each(|l| *l = next()),
        }
        let mut b = a;
        node115_nested_certificate_decision::keccak::keccak_f(&mut a);
        sponge_reference::permute(&mut b);
        if a != b {
            bad.push(format!("state {case}"));
        }
    }
    report("permutation", 300, &bad);
}

fn frame_of(r: &[String]) -> VoteFrame {
    VoteFrame {
        signer: unhex(&r[2]),
        pair: [word(&r[3]), word(&r[4])],
        f30: word(&r[5]),
        f38: word(&r[6]),
        f40: word(&r[7]),
        hash: unhex(&r[8]),
    }
}

#[test]
fn digest_builder_matches_the_corpus() {
    let table = rows("cases-digest.tsv");
    assert_eq!(table.len(), 279);
    let mut bad = Vec::new();
    for r in &table {
        let frame = frame_of(r);
        let pre = preimage(&frame);
        if pre != unhex_vec(&r[9]) {
            bad.push(format!("{} {} preimage", r[0], r[1]));
        }
        if digest(&frame) != unhex::<32>(&r[10]) {
            bad.push(format!("{} {} digest", r[0], r[1]));
        }
        if keccak256(&pre) != unhex::<32>(&r[10]) {
            bad.push(format!("{} {} keccak of preimage", r[0], r[1]));
        }
    }
    report("digest", table.len(), &bad);
}

#[test]
fn a_preimage_derived_by_hand_from_the_disassembly() {
    // prefix, tag byte 1, 20 signer bytes, five varints, 32 hash bytes (relations-digest.tsv DB5, MS2, VS1)
    let frame = VoteFrame { signer: [0x11; 20], pair: [1, 2], f30: 3, f38: 4, f40: 5, hash: [0x22; 32] };
    let mut want = b"Hyperliquid Consensus Payload".to_vec();
    want.push(0x01);
    want.extend_from_slice(&[0x11; 20]);
    want.extend_from_slice(&[1, 2, 3, 4, 5]);
    want.extend_from_slice(&[0x22; 32]);
    assert_eq!(preimage(&frame), want);
    assert_eq!(want.len(), 29 + 1 + 20 + 5 + 32);
    assert_eq!(&want[..29], PREFIX);
    // one word per encoding class, each in its own position
    let frame = VoteFrame { signer: [0; 20], pair: [250, 251], f30: 65535, f38: 65536, f40: 1 << 32, hash: [0; 32] };
    let mut tail = Vec::new();
    tail.push(250);
    tail.extend_from_slice(&[0xfb, 251, 0]);
    tail.extend_from_slice(&[0xfb, 0xff, 0xff]);
    tail.extend_from_slice(&[0xfc, 0, 0, 1, 0]);
    tail.extend_from_slice(&[0xfd, 0, 0, 0, 0, 1, 0, 0, 0]);
    let msg = serialize_message(&frame);
    assert_eq!(&msg[21..21 + tail.len()], &tail[..]);
    let mut one = Vec::new();
    put_varint(&mut one, u64::MAX);
    assert_eq!(one, [0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
}

/// Stand-in curve routine: returns the key the case names (or fails) and records its arguments.
struct Curve {
    key: Option<[u8; 64]>,
    calls: RefCell<Vec<(Vec<u8>, Vec<u8>, u8, [u8; 32])>>,
}

impl Secp256k1 for Curve {
    fn recover(&self, r: &[u8; 32], s: &[u8; 32], id: u8, digest: &[u8; 32]) -> Option<[u8; 64]> {
        self.calls.borrow_mut().push((r.to_vec(), s.to_vec(), id, *digest));
        self.key
    }
}

#[test]
fn recovery_wrapper_matches_the_corpus() {
    let table = rows("cases-recover.tsv");
    assert_eq!(table.len(), 370);
    let mut bad = Vec::new();
    for r in &table {
        let sig: Signature = unhex(&r[2]);
        let msg: [u8; 32] = unhex(&r[3]);
        let key = r[4].strip_prefix("pub:").map(unhex::<64>);
        let curve = Curve { key, calls: RefCell::new(Vec::new()) };
        let got = recover_address(&curve, &sig, &msg);
        let calls = curve.calls.borrow();
        if calls.len().to_string() != r[5] {
            bad.push(format!("{} {} calls {}", r[0], r[1], calls.len()));
        }
        let args = calls
            .first()
            .map(|(a, b, id, m)| {
                assert_eq!(m, &msg);
                format!("{}:{}:{id}", hex(a), hex(b))
            })
            .unwrap_or_else(|| "-".to_owned());
        if args != r[6] {
            bad.push(format!("{} {} args", r[0], r[1]));
        }
        let result = match got {
            Ok(a) => format!("addr:{}", hex(&a)),
            Err(e) => format!("err{}", e.kind()),
        };
        if result != r[7] {
            bad.push(format!("{} {} result {result}", r[0], r[1]));
        }
    }
    report("recover", table.len(), &bad);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn recovery_id_rules_and_error_kinds() {
    let ids: Vec<Option<u8>> = (0..=255u8).map(recovery_id).collect();
    assert_eq!(ids[0], Some(0));
    assert_eq!(ids[1], Some(1));
    assert!(ids[2..=26].iter().all(Option::is_none));
    assert_eq!((ids[27], ids[28]), (Some(0), Some(1)));
    assert!(ids[29..=34].iter().all(Option::is_none));
    assert_eq!((ids[35], ids[36], ids[37], ids[254], ids[255]), (Some(0), Some(1), Some(0), Some(1), Some(0)));
    assert_eq!(RecoverError::BadRecoveryByte.kind(), 6);
    assert_eq!(RecoverError::CurveFailure.kind(), 3);
}

// ---- whole certificates with the real digest ---------------------------------------------------------

/// Answers only for the (digest, r, s, id) the oracle derived for an entry; anything else makes recovery fail.
struct Table(HashMap<[u8; 32], ([u8; 32], [u8; 32], u8, [u8; 64])>);

impl Secp256k1 for Table {
    fn recover(&self, r: &[u8; 32], s: &[u8; 32], id: u8, digest: &[u8; 32]) -> Option<[u8; 64]> {
        let (er, es, eid, key) = self.0.get(digest)?;
        (er == r && es == s && *eid == id).then_some(*key)
    }
}

struct Fixed(StakeSet);

impl StakeSetProvider for Fixed {
    fn stake_set(&self, _ctx: &Context, _round: u64) -> Option<&StakeSet> {
        Some(&self.0)
    }
}

struct Cert {
    words: [u64; 5],
    hash: [u8; 32],
    entries: Vec<(Address, Signature, [u8; 32], [u8; 32], [u8; 32], u8, [u8; 64])>,
}

fn certificates() -> Vec<Cert> {
    let mut certs: Vec<Cert> = Vec::new();
    let table = rows("cases-primitives.tsv");
    assert_eq!(table.len(), 13);
    for r in &table {
        let n: usize = r[1].parse().unwrap();
        if certs.len() == n {
            certs.push(Cert { words: [word(&r[5]), word(&r[6]), word(&r[7]), word(&r[8]), word(&r[9])], hash: unhex(&r[10]), entries: Vec::new() });
        }
        certs[n].entries.push((unhex(&r[2]), unhex(&r[4]), unhex(&r[11]), unhex(&r[13]), unhex(&r[14]), r[12].parse().unwrap(), unhex(&r[3])));
    }
    certs
}

fn run(cert: &Cert, words: [u64; 5], hash: [u8; 32], sigs: Vec<(Address, Signature)>) -> Verdict {
    let keys: Vec<Address> = cert.entries.iter().map(|e| e.0).collect();
    let set = Fixed(StakeSet {
        stakes: StakeMap::tree(keys.iter().map(|k| (*k, 10))),
        validators: keys.iter().copied().collect(),
        validator_count: keys.len() as u64,
    });
    let curve = Table(cert.entries.iter().map(|e| (e.2, (e.3, e.4, e.5, e.6))).collect());
    let rows: Vec<SigRow> = sigs.into_iter().map(|(key, sig)| SigRow { key, sig }).collect();
    let len = rows.len();
    let c = Certificate { sigs: SigMap::ring(rows, 0, len).unwrap(), pair: [words[0], words[1]], f30: words[2], f38: words[3], f40: words[4], hash };
    let ctx = Context { pair: [words[0], words[1]], quorum_fraction_bits: 0 };
    verify(&c, &ctx, &set, &NodePrimitives { curve })
}

#[test]
fn the_verifier_accepts_certificates_signed_over_the_real_digest() {
    let mut bad = Vec::new();
    let certs = certificates();
    for (i, cert) in certs.iter().enumerate() {
        let sigs: Vec<(Address, Signature)> = cert.entries.iter().map(|e| (e.0, e.1)).collect();
        let verdict = run(cert, cert.words, cert.hash, sigs.clone());
        if verdict != Verdict::Accepted {
            bad.push(format!("certificate {i} not accepted: {verdict:?}"));
        }
        // the digest binds every field: changing any one makes the first signature fail
        for k in 0..5 {
            let mut w = cert.words;
            w[k] ^= 1;
            if run(cert, w, cert.hash, sigs.clone()) != Verdict::Rejected(Rejection::BadSignature) {
                bad.push(format!("certificate {i}: word {k} not bound"));
            }
        }
        for k in 0..32 {
            let mut h = cert.hash;
            h[k] ^= 0x80;
            if run(cert, cert.words, h, sigs.clone()) != Verdict::Rejected(Rejection::BadSignature) {
                bad.push(format!("certificate {i}: hash byte {k} not bound"));
            }
        }
        // a recovery byte outside the accepted set is refused before the curve routine is asked
        let mut broken = sigs.clone();
        broken[0].1[64] = 29;
        if run(cert, cert.words, cert.hash, broken) != Verdict::Rejected(Rejection::BadSignature) {
            bad.push(format!("certificate {i}: v = 29 accepted"));
        }
        // a signature of one signer presented under another signer's address fails
        if sigs.len() > 1 {
            let mut swapped = sigs.clone();
            let first = swapped[0].1;
            swapped[0].1 = swapped[1].1;
            swapped[1].1 = first;
            if run(cert, cert.words, cert.hash, swapped) != Verdict::Rejected(Rejection::BadSignature) {
                bad.push(format!("certificate {i}: swapped signatures accepted"));
            }
        }
    }
    report("primitives", certs.len(), &bad);
}

#[test]
fn signer_check_with_the_real_digest_names_the_frame() {
    let certs = certificates();
    let cert = &certs[0];
    let (signer, sig, dig, r, s, id, key) = cert.entries[0];
    let frame = VoteFrame { signer, pair: [cert.words[0], cert.words[1]], f30: cert.words[2], f38: cert.words[3], f40: cert.words[4], hash: cert.hash };
    let prim = NodePrimitives { curve: Table(HashMap::from([(dig, (r, s, id, key))])) };
    let set = StakeSet { stakes: StakeMap::tree([(signer, 10)]), validators: [signer].into_iter().collect(), validator_count: 1 };
    assert!(signer_check(&prim, 1, &frame, &signer, &sig, &set));
    let mut other = frame.clone();
    other.signer[19] ^= 1;
    assert!(!signer_check(&prim, 1, &other, &signer, &sig, &set), "signer byte is part of the digest");
    let mut other = frame.clone();
    other.f38 += 1;
    assert!(!signer_check(&prim, 1, &other, &signer, &sig, &set));
}

#[test]
#[should_panic(expected = "only message variant 1 was read")]
fn another_message_variant_is_refused_loudly() {
    use node115_nested_certificate_decision::signer::SignaturePrimitives;
    let prim = NodePrimitives { curve: Curve { key: None, calls: RefCell::new(Vec::new()) } };
    let frame = VoteFrame { signer: [0; 20], pair: [0; 2], f30: 0, f38: 0, f40: 0, hash: [0; 32] };
    let _ = prim.digest(2, &frame);
}
