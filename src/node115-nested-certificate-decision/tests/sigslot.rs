//! Which signature the verifier hands to the per-entry check, on the tree path (more than 64 signatures)
//! and on the ring path, and what an empty certificate does.
//!
//! Background: an independent trace found that `relations.tsv` V5 had the signature pointer wrong for tree
//! entries (native: the value slot `leaf+8+72*i` returned in rdx by `0x513b200`, not key address + 0x18).
//! This crate is value-level and was already handing each entry its own signature; these tests pin that
//! down with a primitive that records what it is given, instead of a toy that only says valid or not.
//! Nothing here runs target code.

use std::cell::{Cell, RefCell};

use node115_nested_certificate_decision::signer::{SignaturePrimitives, VoteFrame};
use node115_nested_certificate_decision::sigmap::{Address, SigMap, SigRow, Signature};
use node115_nested_certificate_decision::stake::{StakeMap, StakeSet};
use node115_nested_certificate_decision::{Certificate, Context, Rejection, StakeSetProvider, Verdict, verify};

/// Distinct keys whose lexicographic order is the order of `i`.
fn key(i: usize) -> Address {
    let mut k = [0u8; 20];
    k[0] = (i >> 8) as u8;
    k[1] = i as u8;
    for (n, b) in k.iter_mut().enumerate().skip(2) {
        *b = (i * 31 + n * 17) as u8;
    }
    k
}

/// 65 bytes that name `owner` in the first 20 bytes and differ for every owner.
fn sig_for(owner: &Address) -> Signature {
    let mut s = [0u8; 65];
    for n in 0..20 {
        s[n] = owner[n] ^ 0xA5;
    }
    for n in 20..65 {
        s[n] = owner[1].wrapping_mul(7).wrapping_add((n as u8).wrapping_mul(3));
    }
    s
}

fn owner_of(s: &Signature) -> Address {
    let mut a = [0u8; 20];
    for n in 0..20 {
        a[n] = s[n] ^ 0xA5;
    }
    a
}

/// Records every (signer the digest was built for, signature received) pair; "recovery" returns the owner
/// named inside the signature, so a check passes only if the entry carries a signature made for its key.
struct Spy {
    last: Cell<Address>,
    seen: RefCell<Vec<(Address, Signature)>>,
}

impl Spy {
    fn new() -> Self {
        Spy { last: Cell::new([0; 20]), seen: RefCell::new(Vec::new()) }
    }
}

impl SignaturePrimitives for Spy {
    fn digest(&self, _variant: u64, frame: &VoteFrame) -> [u8; 32] {
        self.last.set(frame.signer);
        [0; 32]
    }

    fn recover(&self, signature: &Signature, _digest: &[u8; 32]) -> Option<Address> {
        self.seen.borrow_mut().push((self.last.get(), *signature));
        Some(owner_of(signature))
    }
}

struct Fixed(StakeSet);

impl StakeSetProvider for Fixed {
    fn stake_set(&self, _ctx: &Context, _round: u64) -> Option<&StakeSet> {
        Some(&self.0)
    }
}

fn set_of(keys: &[Address]) -> Fixed {
    Fixed(StakeSet {
        stakes: StakeMap::tree(keys.iter().map(|k| (*k, 10))),
        validators: keys.iter().copied().collect(),
        validator_count: keys.len() as u64,
    })
}

fn run(sigs: SigMap, provider: &Fixed) -> (Verdict, Vec<(Address, Signature)>) {
    let cert = Certificate { sigs, pair: [1, 5], f30: 9, f38: 8, f40: 6, hash: [0x42; 32] };
    let ctx = Context { pair: [1, 5], quorum_fraction_bits: 0 };
    let spy = Spy::new();
    let verdict = verify(&cert, &ctx, provider, &spy);
    (verdict, spy.seen.into_inner())
}

fn tree_of(keys: &[Address], carries: impl Fn(usize) -> Signature) -> SigMap {
    // inserted in reverse: the visiting order must come from the keys, not from the insertion order
    SigMap::tree(keys.iter().enumerate().rev().map(|(i, k)| SigRow { key: *k, sig: carries(i) }))
}

#[test]
fn tree_path_hands_every_entry_its_own_signature_in_key_order() {
    for n in [65usize, 70, 100] {
        let keys: Vec<Address> = (0..n).map(|i| key(3 * i + 1)).collect();
        let sigs = tree_of(&keys, |i| sig_for(&keys[i]));
        assert!(matches!(sigs, SigMap::Tree(_)));
        let (verdict, seen) = run(sigs, &set_of(&keys));
        assert_eq!(verdict, Verdict::Accepted, "n={n}");
        assert_eq!(seen.len(), n);
        for (i, (signer, signature)) in seen.iter().enumerate() {
            assert_eq!(*signer, keys[i], "n={n} entry {i}: key order");
            assert_eq!(*signature, sig_for(&keys[i]), "n={n} entry {i}: the entry's own signature");
        }
    }
}

#[test]
fn a_wrong_value_on_the_tree_path_is_refused_where_it_sits() {
    let n = 70;
    let keys: Vec<Address> = (0..n).map(|i| key(3 * i + 1)).collect();
    let provider = set_of(&keys);
    // entry p carries the signature made for the next key, as a one-slot shift would hand it over
    for p in [0usize, 10, 11, 21, 22, 32, 63, 64, 68, 69] {
        let sigs = tree_of(&keys, |i| if i == p { sig_for(&keys[(p + 1) % n]) } else { sig_for(&keys[i]) });
        let (verdict, seen) = run(sigs, &provider);
        assert_eq!(verdict, Verdict::Rejected(Rejection::BadSignature), "p={p}");
        assert_eq!(seen.len(), p + 1, "p={p}: entries after the failing one are never checked");
        assert_eq!(seen[p].0, keys[p]);
        assert_eq!(seen[p].1, sig_for(&keys[(p + 1) % n]));
    }
}

#[test]
fn ring_of_64_hands_every_row_its_own_signature_in_ring_order() {
    let n = 64;
    let keys: Vec<Address> = (0..n).map(|i| key(3 * i + 1)).collect();
    // logical order starts at key 17 and wraps; physical ring has 66 slots and the head sits at slot 5
    let logical: Vec<Address> = (0..n).map(|j| keys[(j + 17) % n]).collect();
    let (cap, head) = (66usize, 5usize);
    let filler = SigRow { key: [0xFF; 20], sig: [0xEE; 65] };
    let mut rows = vec![filler; cap];
    for (j, k) in logical.iter().enumerate() {
        rows[(head + j) % cap] = SigRow { key: *k, sig: sig_for(k) };
    }
    let sigs = SigMap::ring(rows, head, n).expect("ring fits");
    let (verdict, seen) = run(sigs, &set_of(&keys));
    assert_eq!(verdict, Verdict::Accepted);
    assert_eq!(seen.len(), n);
    for (j, (signer, signature)) in seen.iter().enumerate() {
        assert_eq!(*signer, logical[j], "ring order from the head, entry {j}");
        assert_eq!(*signature, sig_for(&logical[j]));
    }
}

/// The arithmetic of the pinned instructions `0x513b3c1..0x513b3d3` (relations.tsv T1): key address
/// `leaf + (i + 4i)*4 + 0x320`, value address `leaf + (i + 8i)*8 + 8`. Reading 65 bytes at key address +
/// 0x18 (what the first V5 text said) does not give the entry's signature.
#[test]
fn tree_signature_slot_is_not_key_address_plus_0x18() {
    let key_at = |i: usize| (i + 4 * i) * 4 + 0x320;
    let value_at = |i: usize| (i + 8 * i) * 8 + 8;
    // eleven slots tile the leaf as the code around it expects: the u16 length at 0x3fe (0x513b2e3) and the
    // edges from 0x400 (0x513b270)
    assert_eq!(value_at(11), 0x320);
    assert_eq!(key_at(11), 0x3fc);
    let mut leaf = vec![0u8; 0x400 + 12 * 8];
    for i in 0..11 {
        let owner = key(i);
        leaf[key_at(i)..key_at(i) + 20].copy_from_slice(&owner);
        leaf[value_at(i)..value_at(i) + 65].copy_from_slice(&sig_for(&owner));
    }
    for i in 0..11 {
        let wrong = key_at(i) + 0x18;
        assert_ne!(wrong, value_at(i));
        assert!(value_at(i) + 65 <= key_at(0), "the 65 signature bytes lie in the value array");
        assert_ne!(&leaf[wrong..wrong + 65], &sig_for(&key(i))[..], "slot {i}");
    }
}

#[test]
fn an_empty_certificate_is_refused_before_any_signature_check() {
    let keys: Vec<Address> = (0..5).map(|i| key(i + 1)).collect();
    let empties = [SigMap::empty_ring(), SigMap::tree(std::iter::empty())];
    for sigs in empties {
        // stake set with stake: signed 0 is not above two thirds of anything
        let (verdict, seen) = run(sigs.clone(), &set_of(&keys));
        assert_eq!(verdict, Verdict::Rejected(Rejection::QuorumNotReached));
        assert!(seen.is_empty());
        // zero total stake as well: 3*0 > 2*0 is false
        let (verdict, seen) = run(sigs, &set_of(&[]));
        assert_eq!(verdict, Verdict::Rejected(Rejection::QuorumNotReached));
        assert!(seen.is_empty());
    }
}
