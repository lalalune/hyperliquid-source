use node115_certificate_caller::{
    Block, Decision, Parent, Timestamp, block_digest, decide, serialize_variant_zero,
};
use node115_nested_certificate_decision::sigmap::{SigMap, SigRow, Signature};
use node115_nested_certificate_decision::signer::{SignaturePrimitives, VoteFrame};
use node115_nested_certificate_decision::stake::{StakeMap, StakeSet};
use node115_nested_certificate_decision::verifier::StakeSetProvider;
use node115_nested_certificate_decision::{Certificate, Context};
use std::collections::BTreeSet;

fn cert(hash: [u8; 32]) -> Certificate {
    Certificate {
        sigs: SigMap::empty_ring(),
        pair: [0, 0],
        f30: 0,
        f38: 0,
        f40: 0,
        hash,
    }
}
fn block() -> Block {
    Block {
        address: [0; 20],
        hashes: vec![],
        timestamp: Timestamp {
            seconds: 0,
            nanos: 0,
        },
        parent: Parent::Simple(cert([0; 32])),
    }
}

#[test]
fn simple_variant_zero_has_exact_structural_bytes() {
    let b = block();
    let bytes = serialize_variant_zero(&b);
    assert_eq!(bytes.len(), 63);
    assert!(bytes.iter().all(|b| *b == 0));
    assert_ne!(block_digest(&b), [0; 32]);
}

#[test]
fn composite_encodes_timeout_row_and_optional_certificate() {
    let mut b = block();
    b.address = [0x11; 20];
    b.hashes.push([0x22; 32]);
    b.timestamp = Timestamp {
        seconds: -1,
        nanos: 7,
    };
    let mut sig = [0u8; 65];
    sig[0] = 9;
    sig[64] = 3;
    b.parent = Parent::Composite {
        primary: cert([0x33; 32]),
        round: 4,
        timeout_rows: vec![node115_certificate_caller::TimeoutRow {
            key: [0x44; 20],
            value: 5,
            signature: sig,
        }],
        optional: Some(cert([0x55; 32])),
    };
    let mut expected = vec![0];
    expected.extend([0x11; 20]);
    expected.push(1);
    expected.extend([0x22; 32]);
    expected.extend([1, 7, 1, 4]);
    expected.extend([0; 5]);
    expected.extend([0x33; 32]);
    expected.push(0);
    expected.push(1);
    expected.extend([0x44; 20]);
    expected.push(5);
    expected.push(9);
    expected.extend([0; 7]);
    expected.push(3);
    expected.push(1);
    expected.extend([0; 5]);
    expected.extend([0x55; 32]);
    expected.push(0);
    assert_eq!(serialize_variant_zero(&b), expected);
}

struct Provider(StakeSet);
impl StakeSetProvider for Provider {
    fn stake_set(&self, _: &Context, _: u64) -> Option<&StakeSet> {
        Some(&self.0)
    }
}
struct Primitives;
impl SignaturePrimitives for Primitives {
    fn digest(&self, _: u64, _: &VoteFrame) -> [u8; 32] {
        [0; 32]
    }
    fn recover(&self, _: &Signature, _: &[u8; 32]) -> Option<[u8; 20]> {
        Some([7; 20])
    }
}
fn nested(hash: [u8; 32]) -> Certificate {
    Certificate {
        sigs: SigMap::tree([SigRow {
            key: [7; 20],
            sig: [0; 65],
        }]),
        pair: [0, 0],
        f30: 1,
        f38: 0,
        f40: 0,
        hash,
    }
}
fn provider() -> Provider {
    Provider(StakeSet {
        stakes: StakeMap::tree([([7; 20], 1)]),
        validators: BTreeSet::from([[7; 20]]),
        validator_count: 1,
    })
}

#[test]
fn caller_preserves_gate_order_and_saturating_round() {
    let mut b = block();
    if let Parent::Simple(ref mut c) = b.parent {
        c.f30 = u64::MAX;
    }
    let c = nested(block_digest(&b));
    let ctx = Context {
        pair: [0, 0],
        quorum_fraction_bits: 0,
    };
    let p = provider();
    assert_eq!(
        decide(
            &b,
            &c,
            &ctx,
            [9; 32],
            0,
            |_, _, _| Err("front"),
            &p,
            &Primitives
        ),
        Decision::FrontRejected("front")
    );
    assert_eq!(
        decide::<(), _, _>(&b, &c, &ctx, [9; 32], 0, |_, _, _| Ok(()), &p, &Primitives),
        Decision::ParentDigestMismatch
    );
    assert_eq!(
        decide::<(), _, _>(
            &b,
            &c,
            &ctx,
            [0; 32],
            u64::MAX - 1,
            |_, _, _| Ok(()),
            &p,
            &Primitives
        ),
        Decision::Continue
    );
    assert_eq!(
        decide::<(), _, _>(&b, &c, &ctx, [0; 32], 3, |_, _, _| Ok(()), &p, &Primitives),
        Decision::RoundMismatch
    );
    let mut changed = c.clone();
    changed.hash[0] ^= 1;
    assert_eq!(
        decide::<(), _, _>(
            &b,
            &changed,
            &ctx,
            [0; 32],
            3,
            |_, _, _| Ok(()),
            &p,
            &Primitives
        ),
        Decision::BlockDigestMismatch
    );
}

#[test]
fn signature_words_use_compact_boundaries_and_raw_recovery() {
    let mut b = block();
    let words = [250_u64, 251, 65_535, 65_536, 1_u64 << 32, 0, 1, 2];
    let mut sig = [0u8; 65];
    for (index, word) in words.into_iter().enumerate() {
        sig[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    sig[64] = 0xff;
    if let Parent::Simple(ref mut c) = b.parent {
        c.sigs = SigMap::tree([SigRow {
            key: [0xab; 20],
            sig,
        }]);
    }
    let bytes = serialize_variant_zero(&b);
    let mut expected = vec![0; 62]; // through certificate hash
    expected.push(1);
    expected.extend([0xab; 20]);
    expected.extend([
        250, 251, 251, 0, 251, 255, 255, 252, 0, 0, 1, 0, 253, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 255,
    ]);
    assert_eq!(bytes, expected);
}

#[test]
fn nested_no_return_is_not_collapsed_to_a_caller_error() {
    let b = block();
    let mut c = nested(block_digest(&b));
    c.pair = [1, 0];
    let ctx = Context {
        pair: [0, 0],
        quorum_fraction_bits: 0,
    };
    let p = provider();
    let result = decide::<(), _, _>(&b, &c, &ctx, [9; 32], 0, |_, _, _| Ok(()), &p, &Primitives);
    assert!(matches!(
        result,
        Decision::Nested(node115_nested_certificate_decision::Output::Diverges { .. })
    ));
    assert_eq!(result.raw_tag(), None);
}

#[test]
fn composite_optional_parent_controls_hash_but_not_round() {
    let mut b = block();
    b.parent = Parent::Composite {
        primary: cert([3; 32]),
        round: 9,
        timeout_rows: vec![],
        optional: Some(cert([4; 32])),
    };
    let ctx = Context {
        pair: [0, 0],
        quorum_fraction_bits: 0,
    };
    let p = provider();
    let c = nested(block_digest(&b));
    assert_eq!(
        decide::<(), _, _>(&b, &c, &ctx, [3; 32], 9, |_, _, _| Ok(()), &p, &Primitives).raw_tag(),
        Some(0x1d)
    );
    assert_eq!(
        decide::<(), _, _>(&b, &c, &ctx, [4; 32], 9, |_, _, _| Ok(()), &p, &Primitives).raw_tag(),
        Some(0x2e)
    );
    if let Parent::Composite {
        ref mut optional, ..
    } = b.parent
    {
        *optional = None;
    }
    let c = nested(block_digest(&b));
    assert_eq!(
        decide::<(), _, _>(&b, &c, &ctx, [3; 32], 9, |_, _, _| Ok(()), &p, &Primitives).raw_tag(),
        Some(0x2e)
    );
}
