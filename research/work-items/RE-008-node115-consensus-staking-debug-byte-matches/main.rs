#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Live ThinLTO `#[derive(Debug)]` compiled-byte reconstruction for 35
//! non-visitor first-party `consensus` (28 FDEs, 8,384 B) and `staking`
//! (7 FDEs, 2,057 B) `.text` FDEs in Linux x86-64 node #115 (`hl-node`).
//!
//! Zero external dependencies; compiled with:
//! `rustc --edition=2021 --crate-name consensus_staking_dbg -C opt-level=3 -C overflow-checks=yes -C lto=thin -C save-temps`

use core::fmt;
use std::hint::black_box;
use std::sync::Arc;

struct Opaque8([u64; 1]);
impl fmt::Debug for Opaque8 {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(f.write_str("o8"))
    }
}

struct Opaque16([u64; 2]);
impl fmt::Debug for Opaque16 {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(f.write_str("o16"))
    }
}

struct Opaque32Align1([u8; 32]);
impl fmt::Debug for Opaque32Align1 {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(f.write_str("o32a1"))
    }
}

struct Opaque304([u64; 38]);
impl fmt::Debug for Opaque304 {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(f.write_str("o304"))
    }
}

struct Opaque376([u64; 47]);
impl fmt::Debug for Opaque376 {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(f.write_str("o376"))
    }
}

/// 32-byte signatures container whose internal enum niche consumes
/// `0x8000_0000_0000_0000`, so the enclosing `Cert` enum receives
/// discriminant `0x8000_0000_0000_0001` at offset `+0x0` (observed in
/// node #115 `<&Cert as Debug>::fmt` at `0x5941570`).
enum SigMap {
    Many(Vec<u8>, u64),
    Empty([u8; 24]),
}
impl fmt::Debug for SigMap {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        black_box(f.write_str("sm"))
    }
}

// ---- consensus types (28 FDEs / 8,384 B) ----

#[derive(Debug)]
struct Round(u64);

#[derive(Debug)]
struct CommittedRound(u64);

#[derive(Debug)]
struct BlockHash([u8; 32]);

#[derive(Debug)]
struct ConsensusTxHash([u8; 32]);

#[derive(Debug)]
struct Qc {
    hardfork: Opaque16,
    round: Round,
    certified_parent_round: Round,
    committed_round: CommittedRound,
    block_hash: Opaque32Align1,
    signatures: SigMap,
}

#[derive(Debug)]
struct Tc {
    round: Round,
    high_qc: Qc,
    signatures: SigMap,
}

#[derive(Debug)]
enum Cert {
    Qc(Qc),
    Tc {
        tc: Tc,
        higher_qc: Option<Qc>,
    },
}

#[derive(Debug)]
struct CommitProof {
    child: Opaque376,
    grandchild_qc: Opaque8,
}

#[derive(Debug)]
struct ClientBlock {
    proof: Opaque8,
    txs: Opaque8,
}

#[derive(Debug)]
struct Proof {
    signed_block: Opaque376,
    commit_proof: Opaque8,
}

#[derive(Debug)]
struct Signed {
    signature: Opaque8,
    content: Opaque304,
}

// ---- staking types (7 FDEs / 2,057 B) ----

#[derive(Debug)]
enum NodeIp {
    Ip(u64),
}

#[inline(never)]
fn sink(p: &dyn fmt::Debug) {
    let mut s = String::new();
    let _ = fmt::write(&mut s, format_args!("{p:?}"));
    black_box(s);
}

fn mk_qc() -> Qc {
    Qc {
        hardfork: Opaque16([0; 2]),
        round: Round(1),
        certified_parent_round: Round(2),
        committed_round: CommittedRound(3),
        block_hash: Opaque32Align1([0; 32]),
        signatures: SigMap::Many(Vec::new(), 0),
    }
}

fn main() {
    let r = black_box(Round(1));
    let cr = black_box(CommittedRound(2));
    let bh = black_box(BlockHash([0; 32]));
    let th = black_box(ConsensusTxHash([0; 32]));
    let qc = black_box(mk_qc());
    let tc = black_box(Tc {
        round: Round(1),
        high_qc: mk_qc(),
        signatures: SigMap::Many(Vec::new(), 0),
    });
    let c1 = black_box(Cert::Qc(mk_qc()));
    let c2 = black_box(Cert::Tc {
        tc: Tc {
            round: Round(1),
            high_qc: mk_qc(),
            signatures: SigMap::Many(Vec::new(), 0),
        },
        higher_qc: Some(mk_qc()),
    });
    let cp = black_box(CommitProof {
        child: Opaque376([0; 47]),
        grandchild_qc: Opaque8([0]),
    });
    let cb = black_box(ClientBlock {
        proof: Opaque8([0]),
        txs: Opaque8([0]),
    });
    let pr = black_box(Arc::new(Proof {
        signed_block: Opaque376([0; 47]),
        commit_proof: Opaque8([0]),
    }));
    let sg = black_box(Signed {
        signature: Opaque8([0]),
        content: Opaque304([0; 38]),
    });
    let ip = black_box(NodeIp::Ip(1));

    sink(&r);
    sink(&(&r));
    sink(&cr);
    sink(&(&cr));
    sink(&bh);
    sink(&(&bh));
    sink(&th);
    sink(&(&th));
    sink(&qc);
    sink(&(&qc));
    sink(&tc);
    sink(&c1);
    sink(&(&c1));
    sink(&c2);
    sink(&(&c2));
    sink(&cp);
    sink(&(&cp));
    sink(&cb);
    sink(&(&cb));
    sink(&pr);
    sink(&sg);
    sink(&ip);
    sink(&(&ip));
}
