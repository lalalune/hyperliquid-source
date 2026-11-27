#![forbid(unsafe_code)]
//! Standalone `#![forbid(unsafe_code)]`, zero-dependency ThinLTO reproduction
//! harness for 22 non-visitor first-party `#[derive(Debug)]` FDEs (6,785 B)
//! in Linux x86-64 node #115 (`storage` & `abci`).
//!
//! Compile profile (matching node #115):
//! `rustc --edition=2021 -C opt-level=3 -C overflow-checks=yes -C lto=thin -C save-temps`

use core::fmt;

pub struct MediumInner {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}

impl fmt::Debug for MediumInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediumInner")
            .field("a", &self.a)
            .field("b", &self.b)
            .field("c", &self.c)
            .field("d", &self.d)
            .finish()
    }
}

pub struct MediumErr {
    pub x: u64,
    pub y: u64,
    pub z: u64,
    pub w: u64,
}

impl fmt::Debug for MediumErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediumErr")
            .field("x", &self.x)
            .field("y", &self.y)
            .field("z", &self.z)
            .field("w", &self.w)
            .finish()
    }
}

/// 16-bit niche `Ok` type matching `Result<_, _>::fmt` at `0x2772da0` (`cmp word ptr [rax], 2`).
#[repr(u16)]
pub enum OkNiche {
    A(MediumInner) = 0,
    B(MediumInner) = 1,
}

impl fmt::Debug for OkNiche {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(m) | Self::B(m) => m.fmt(f),
        }
    }
}

/// Storage marker/data write error (`0x25eaba0`, `0x3d525a0`, `0x57d0ec0`, 326 B each).
#[derive(Debug)]
#[repr(C)]
pub enum DbWriteError {
    InvalidMarkerWrite(MediumInner),
    InvalidDataWrite(MediumInner),
}

/// ABCI state digest wrapper (`0x2787d20`, `0x2e36f90`, `0x56599b0`, `0x5aaa250`,
/// `0x5b555e0` = 293 B; `&AbciDigest` `0x53d55c0` = 296 B).
#[derive(Debug)]
pub struct AbciDigest(pub MediumInner);

/// L1 hash wrapper (`0x4545400`, `0x564b200`, `0x5a8aed0`, 293 B each).
#[derive(Debug)]
pub struct L1Hash(pub MediumInner);

/// ABCI `Context` system-nonce wrapper (`0x2787580`, 293 B).
#[derive(Debug)]
pub struct SystemNonce(pub MediumInner);

/// Hardfork descriptor (`0x2787940`, `0x2cd5190`, `0x2e33800`, `0x59675e0`, `0x5aa9630` = 221 B;
/// `&Hardfork` `0x2772400`, `0x4d9ab80` = 221 B).
#[derive(Debug)]
pub struct Hardfork {
    pub version: u64,
    pub round: RoundField,
}

#[derive(Debug)]
pub struct RoundField(pub u64);

#[derive(Debug)]
pub struct TimeField(pub [u32; 3]);

#[derive(Debug)]
pub struct SysNonceField(pub u64);

/// Exact 13-field `l1::context::Context` (`0x27726a0`, 810 B).
#[derive(Debug)]
pub struct Context {
    pub hardfork_height: u64,
    pub hardfork: Hardfork,
    pub height: u64,
    pub tx_index: Option<u64>,
    pub round: RoundField,
    pub time: TimeField,
    pub prev_time: TimeField,
    pub next_oid: u64,
    pub next_lid: u64,
    pub next_twap_id: u64,
    pub system_nonce: SysNonceField,
    pub use_system_nonce: bool,
    pub maybe_operate_with_abstraction_reentrancy_counter: u64,
}

#[inline(never)]
pub fn fmt_dyn(x: &dyn fmt::Debug) -> String {
    format!("{x:?}")
}

#[inline(never)]
pub fn fmt_all(
    w: &DbWriteError,
    d: &AbciDigest,
    h: &L1Hash,
    sn: &SystemNonce,
    hf: &Hardfork,
    c: &Context,
    r: &Result<OkNiche, MediumErr>,
) -> String {
    let s1 = fmt_dyn(d);
    let s2 = fmt_dyn(h);
    let s3 = fmt_dyn(sn);
    let s4 = fmt_dyn(hf);
    let s5 = format!("{:?} {:?} {:?} {:?} {:?}", w, d, hf, c, r);
    format!("{s1}{s2}{s3}{s4}{s5}")
}

fn main() {
    let m = || MediumInner {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
    };
    let e = MediumErr {
        x: 5,
        y: 6,
        z: 7,
        w: 8,
    };
    let w = DbWriteError::InvalidMarkerWrite(m());
    let d = AbciDigest(m());
    let h = L1Hash(m());
    let sn = SystemNonce(m());
    let hf = Hardfork {
        version: 115,
        round: RoundField(2),
    };
    let c = Context {
        hardfork_height: 1,
        hardfork: Hardfork {
            version: 115,
            round: RoundField(2),
        },
        height: 3,
        tx_index: Some(4),
        round: RoundField(5),
        time: TimeField([1, 2, 3]),
        prev_time: TimeField([4, 5, 6]),
        next_oid: 8,
        next_lid: 9,
        next_twap_id: 10,
        system_nonce: SysNonceField(11),
        use_system_nonce: true,
        maybe_operate_with_abstraction_reentrancy_counter: 12,
    };
    let r: Result<OkNiche, MediumErr> = if std::env::args().len() > 1 {
        Ok(OkNiche::A(m()))
    } else {
        Err(e)
    };
    println!("{}", fmt_all(&w, &d, &h, &sn, &hf, &c, &r).len());
}
