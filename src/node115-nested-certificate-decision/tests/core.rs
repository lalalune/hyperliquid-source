//! Drives the decision core `decide` (callees injected) with the fixed 621-case corpus `cases.tsv` of
//! round 1. Expected values come from `gen_corpus.py` (written from the disassembly), never from this
//! crate. Injected callee results are assumed outcomes, as in round 1.

use std::cell::Cell;
use std::fs;
use std::rc::Rc;

use node115_nested_certificate_decision::sigmap::{SigMap, SigRow};
use node115_nested_certificate_decision::{Certificate, Context, Output, VerifierResult, decide, empty_reference};

const CORPUS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../research/work-items/RE-008-node115-nested-certificate-decision/cases.tsv"
);

/// A verifier result chosen by the corpus: any tag with a payload word.
struct Fake<R> {
    tag: u8,
    payload: R,
}

impl<R> VerifierResult for Fake<R> {
    fn tag(&self) -> u8 {
        self.tag
    }
}

fn words(s: &str) -> Vec<u64> {
    if s == "-" {
        return Vec::new();
    }
    s.split(':').map(|w| u64::from_str_radix(w, 16).unwrap()).collect()
}

fn one(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}

/// The corpus' `head` words only mattered as "some collection"; a one-row ring stands for it.
fn some_collection() -> SigMap {
    SigMap::ring(vec![SigRow { key: [1; 20], sig: [2; 65] }], 0, 1).unwrap()
}

/// Returns a description of the first difference, or `None` when the case matches.
fn run_case(f: &[&str]) -> Option<String> {
    let mut hash = [0u8; 32];
    for (i, b) in hash.iter_mut().enumerate() {
        *b = u8::from_str_radix(&f[8][2 * i..2 * i + 2], 16).unwrap();
    }
    let cert = Certificate {
        sigs: some_collection(),
        pair: [one(f[3]), one(f[4])],
        f30: one(f[5]),
        f38: one(f[6]),
        f40: one(f[7]),
        hash,
    };
    let ctx = Context { pair: [one(f[9]), one(f[10])], quorum_fraction_bits: 0 };
    let helper_result = f[11] == "T";
    let verdict_spec = f[12].to_string();

    let obs = Rc::new(Cell::new((0u32, 0u32, true)));
    let helper_ref = Rc::new(Cell::new(None::<Certificate>));
    let (o1, o2, r1) = (obs.clone(), obs.clone(), helper_ref.clone());
    let (cp, xp) = (&cert as *const Certificate, &ctx as *const Context);
    let out: Output<Fake<u64>> = decide(
        &cert,
        &ctx,
        move |c, reference| {
            let (h, v, ok) = o1.get();
            o1.set((h + 1, v, ok && std::ptr::eq(c, cp)));
            r1.set(Some(reference.clone()));
            helper_result
        },
        move |c, x| {
            let (h, v, ok) = o2.get();
            o2.set((h, v + 1, ok && std::ptr::eq(c, cp) && std::ptr::eq(x, xp)));
            if verdict_spec == "A" {
                Fake { tag: 0x2e, payload: 0 }
            } else {
                let p: Vec<&str> = verdict_spec.split(':').collect();
                Fake { tag: u8::from_str_radix(p[1], 16).unwrap(), payload: one(p[2]) }
            }
        },
    );
    let (hc, vc, ok) = obs.get();
    let want_hc: u32 = f[15].parse().unwrap();
    let want_vc: u32 = f[16].parse().unwrap();
    if hc != want_hc || vc != want_vc {
        return Some(format!("calls helper={hc} verifier={vc}"));
    }
    if !ok {
        return Some("callee argument identity".into());
    }
    let seen_ref = helper_ref.take();
    if f[17] == "-" {
        if seen_ref.is_some() {
            return Some("unexpected helper reference".into());
        }
    } else {
        // Corpus words: collection words 0, 8, 0, 0 (empty ring), pair, three copies of B, 32 zero bytes.
        let w = words(f[17]);
        let want = Certificate {
            sigs: SigMap::empty_ring(),
            pair: [w[4], w[5]],
            f30: w[6],
            f38: w[7],
            f40: w[8],
            hash: [0; 32],
        };
        if (w[0], w[1], w[2], w[3]) != (0, 8, 0, 0) || seen_ref.as_ref() != Some(&want) || want != empty_reference(&cert)
        {
            return Some("helper reference record".into());
        }
    }
    let (got_tag, got_words) = match &out {
        Output::Mismatch { cert, ctx } => ("00".to_string(), vec![cert[0], cert[1], ctx[0], ctx[1]]),
        Output::OutOfOrder { f30, f38, f40 } => ("2d".to_string(), vec![*f30, *f38, *f40]),
        Output::Forwarded(v) if v.tag != 0x2e => (format!("{:02x}", v.tag), vec![v.payload]),
        Output::Diverges { current, observed } => {
            ("DIVERGE".to_string(), vec![current[0], current[1], observed[0], observed[1]])
        }
        other => (format!("{:02x}", other.tag().unwrap()), Vec::new()),
    };
    if got_tag != f[13] || got_words != words(f[14]) {
        return Some(format!("output {} {:x?}", got_tag, got_words));
    }
    None
}

#[test]
fn corpus_matches_oracle() {
    let text = fs::read_to_string(CORPUS).expect("corpus");
    let mut total = 0;
    let mut bad = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 18, "{line}");
        total += 1;
        if let Some(why) = run_case(&f) {
            println!("MISMATCH {} {} {}", f[0], f[1], why);
            bad.push(f[0].to_string());
        }
    }
    println!("CORPUS core cases={} mismatches={}", total, bad.len());
    assert_eq!(total, 621);
    assert!(bad.is_empty(), "{} mismatches", bad.len());
}

#[test]
fn dropped_verifier_result_is_not_returned_and_is_dropped_once() {
    struct Probe(Rc<Cell<u32>>);
    impl Drop for Probe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let cert = Certificate { sigs: SigMap::empty_ring(), pair: [5, 1], f30: 0, f38: 0, f40: 0, hash: [0; 32] };
    let ctx = Context { pair: [4, 1], quorum_fraction_bits: 0 };
    let d = drops.clone();
    let out = decide(&cert, &ctx, |_, _| unreachable!(), move |_, _| Fake { tag: 0x13, payload: Probe(d) });
    assert!(matches!(out, Output::Mismatch { cert: [5, 1], ctx: [4, 1] }));
    assert_eq!(drops.get(), 1);
}
