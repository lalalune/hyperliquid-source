#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Pure-Rust (zero external dependencies) reconstruction of 11 first-party
//! Linux x86-64 node #115 `consensus` (8 FDEs / `963 B`) and `staking`
//! (3 FDEs / `213 B`) PIC `fmt::Debug` FDEs (`1,176 B` total):
//! - `MsgKind::fmt` (`0x581fd50`, `232 B`, `consensus`)
//! - `ConsensusCounter::fmt` (`0x582ad40`, `211 B`, `consensus`)
//! - `<&Block as Debug>::fmt` (`0x5941bb0`, `168 B`, `consensus`)
//! - `Validator::fmt` (`0x581f7a0`, `68 B`, `consensus`)
//! - `<&Validator as Debug>::fmt` (`0x57d15e0`, `0x292c660`, `2 x 71 B`, `consensus`)
//! - `<&Broadcaster as Debug>::fmt` (`0x57d1540`, `0x241ebc0`, `2 x 71 B`, `consensus`)
//! - `<&CValidator as Debug>::fmt` (`0x53d52c0`, `0x241fce0`, `2 x 71 B`, `staking`)
//! - `<&CSigner as Debug>::fmt` (`0x53d5310`, `71 B`, `staking`)
//!
//! Compiled live under `rustc +1.95.0 --edition=2021 --crate-type=rlib
//! -C opt-level=3 -C overflow-checks=yes -C relocation-model=pic -C lto=off --emit=obj`.

use core::fmt;
use core::num::{NonZeroU32, NonZeroU64};

pub enum MsgKind {
    ExternalTx,
    Tx,
    Block,
    Vote,
    Timeout,
    Tc,
    Heartbeat,
    HeartbeatAck,
    RpcResponse,
    RpcFailed,
}

impl fmt::Debug for MsgKind {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExternalTx => f.write_str("ExternalTx"),
            Self::Tx => f.write_str("Tx"),
            Self::Block => f.write_str("Block"),
            Self::Vote => f.write_str("Vote"),
            Self::Timeout => f.write_str("Timeout"),
            Self::Tc => f.write_str("Tc"),
            Self::Heartbeat => f.write_str("Heartbeat"),
            Self::HeartbeatAck => f.write_str("HeartbeatAck"),
            Self::RpcResponse => f.write_str("RpcResponse"),
            Self::RpcFailed => f.write_str("RpcFailed"),
        }
    }
}

pub enum ConsensusCounter {
    CommittedBlocks,
    CommittedTxs,
    CommittedTxBytes,
    DroppedTxs,
    RpcRequestsRegistered,
    RpcRequestsSent,
    RoundQc,
    RoundTc,
    RoundCatchUp,
}

impl fmt::Debug for ConsensusCounter {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommittedBlocks => f.write_str("CommittedBlocks"),
            Self::CommittedTxs => f.write_str("CommittedTxs"),
            Self::CommittedTxBytes => f.write_str("CommittedTxBytes"),
            Self::DroppedTxs => f.write_str("DroppedTxs"),
            Self::RpcRequestsRegistered => f.write_str("RpcRequestsRegistered"),
            Self::RpcRequestsSent => f.write_str("RpcRequestsSent"),
            Self::RoundQc => f.write_str("RoundQc"),
            Self::RoundTc => f.write_str("RoundTc"),
            Self::RoundCatchUp => f.write_str("RoundCatchUp"),
        }
    }
}

pub struct Opaque24(Vec<u8>);
impl fmt::Debug for Opaque24 {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("o24")
    }
}

pub struct Opaque248(NonZeroU64, [u64; 30]);
impl fmt::Debug for Opaque248 {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("o248")
    }
}

pub struct Opaque12(NonZeroU32, u32, u32);
impl fmt::Debug for Opaque12 {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("o12")
    }
}

pub struct Opaque20([u8; 20]);
impl fmt::Debug for Opaque20 {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("o20")
    }
}

#[derive(Debug)]
pub struct Block {
    pub proposer: Opaque20,
    pub tx_hashes: Opaque24,
    pub time: Opaque12,
    pub parent: Opaque248,
}

#[inline(never)]
pub fn fmt_ref_block(b: &&Block, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <&Block as fmt::Debug>::fmt(b, f)
}

#[derive(Clone, Copy)]
pub struct Addr([u8; 20]);
impl fmt::Display for Addr {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("addr")
    }
}

pub struct Validator(pub Addr);
impl fmt::Debug for Validator {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = self.0;
        write!(f, "Validator({a})")
    }
}

#[inline(never)]
pub fn fmt_ref_validator(v: &&Validator, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let a = v.0;
    write!(f, "Validator({a})")
}

pub struct Broadcaster(pub Addr);
#[inline(never)]
pub fn fmt_ref_broadcaster(v: &&Broadcaster, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let a = v.0;
    write!(f, "Broadcaster({a})")
}

pub struct CValidator(pub Addr);
#[inline(never)]
pub fn fmt_ref_cvalidator(v: &&CValidator, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let a = v.0;
    write!(f, "CValidator({a})")
}

pub struct CSigner(pub Addr);
#[inline(never)]
pub fn fmt_ref_csigner(v: &&CSigner, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let a = v.0;
    write!(f, "CSigner({a})")
}
