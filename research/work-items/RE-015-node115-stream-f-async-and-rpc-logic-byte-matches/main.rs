#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Independently authored node #115 Stream F (`evm-rpc` + `info-api`) pure first-party
//! business-logic harness:
//! - `evm_rpc/src/evm_store.rs:452` (`0x232df90`, 94 B): `resolve_block_number`
//! - `info_server/src/abci_state_info_handler.rs:81-82` (`0x29781a0..0x297acb9`, 37 FDEs / 6,996 B):
//!   `AbciStateInfoHandler` `async fn` `Future::poll` state machines dispatching synchronous
//!   ABCI-state queries under `with_abci_state` (`#[track_caller]`).

use core::future::Future;
use core::num::NonZeroU64;
use core::pin::Pin;

// ---------------------------------------------------------------------------
// 1. evm_rpc/src/evm_store.rs:452 — resolve_block_number (0x232df90, 94 B)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct EvmStore {
    _pad: [u8; 0x28],
    pub hash_index: u64,
}

#[derive(Clone, Copy)]
pub enum BlockNumberOrTag {
    Latest,
    Finalized,
    Safe,
    Earliest,
    Pending,
    Number(u64),
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct RpcBlockHash {
    pub require_canonical: Option<bool>,
    pub block_hash: [u8; 32],
}

#[derive(Clone, Copy)]
pub enum BlockId {
    Hash(RpcBlockHash),
    Number(BlockNumberOrTag),
}

#[inline(never)]
#[track_caller]
fn lookup_hash(idx: &u64, mut hash: [u8; 32]) -> Option<u64> {
    hash[0] ^= 1;
    let _ = std::hint::black_box((idx, &mut hash, core::panic::Location::caller()));
    std::hint::black_box(None)
}

#[inline(never)]
pub fn resolve_block_number(store: &EvmStore, block: &Option<BlockId>, latest: u64) -> Option<u64> {
    match block {
        Some(BlockId::Hash(h)) => {
            let hash = h.block_hash;
            lookup_hash(&store.hash_index, hash)
        }
        Some(BlockId::Number(tag)) => match *tag {
            BlockNumberOrTag::Latest | BlockNumberOrTag::Finalized | BlockNumberOrTag::Safe => {
                Some(latest)
            }
            BlockNumberOrTag::Earliest => Some(0),
            BlockNumberOrTag::Pending => None,
            BlockNumberOrTag::Number(n) => Some(n),
        },
        None => Some(latest),
    }
}

// ---------------------------------------------------------------------------
// 2. info_server/src/abci_state_info_handler.rs:81-82 — async Future::poll
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct InnerState {
    _pad0: [u8; 0x10],
    pub meta: u64,
    _pad1: [u8; 0x128],
    pub lock: u64,
}

pub struct AbciStateInfoHandler {
    pub inner: Box<InnerState>,
}

#[derive(Clone, Copy)]
pub struct ReqCtx {
    pub a: u64,
    pub b: u64,
}

#[derive(Clone, Copy)]
pub enum LocalMeta {
    Ctx(ReqCtx),
    Other(u64),
}

pub trait StateOp {
    type Output;
    fn run(self, state: &u64) -> Self::Output;
}

#[inline(never)]
#[track_caller]
fn with_abci_state<O: StateOp>(lock: &u64, op: O, flag: bool) -> O::Output {
    let loc = core::panic::Location::caller();
    if std::hint::black_box(flag) {
        panic!("abci {:?}", loc);
    }
    std::hint::black_box(op.run(std::hint::black_box(lock)))
}

pub struct Op0<'a, R, const T: usize> {
    pub meta: &'a u64,
    pub local: &'a LocalMeta,
    pub _p: core::marker::PhantomData<R>,
}

impl<'a, R: Default, const T: usize> StateOp for Op0<'a, R, T> {
    type Output = R;
    #[inline(never)]
    fn run(self, s: &u64) -> R {
        std::hint::black_box((s, self.meta, self.local, T));
        std::hint::black_box(R::default())
    }
}

pub struct OpArg<'a, A, R, const T: usize> {
    pub meta: &'a u64,
    pub local: &'a LocalMeta,
    pub arg: A,
    pub _p: core::marker::PhantomData<R>,
}

impl<'a, A, R: Default, const T: usize> StateOp for OpArg<'a, A, R, T> {
    type Output = R;
    #[inline(never)]
    fn run(self, s: &u64) -> R {
        std::hint::black_box((s, self.meta, self.local, &self.arg, T));
        std::hint::black_box(R::default())
    }
}

#[inline(always)]
fn run_0<R: Default, const T: usize>(inner: &InnerState, ctx: ReqCtx) -> R {
    let meta = &inner.meta;
    let local = LocalMeta::Ctx(ctx);
    with_abci_state(
        &inner.lock,
        Op0::<R, T> {
            meta,
            local: &local,
            _p: core::marker::PhantomData,
        },
        false,
    )
}

#[inline(always)]
fn run_a<A: Copy, R: Default, const T: usize>(inner: &InnerState, ctx: ReqCtx, arg: A) -> R {
    let meta = &inner.meta;
    let local = LocalMeta::Ctx(ctx);
    with_abci_state(
        &inner.lock,
        OpArg::<A, R, T> {
            meta,
            local: &local,
            arg,
            _p: core::marker::PhantomData,
        },
        false,
    )
}

// Query argument layouts (User [u8; 20], Option<User> 21B, 40B pair, 24B/48B enum args)
#[derive(Clone, Copy, Default)]
pub struct A20(pub [u8; 20]);
#[derive(Clone, Copy, Default)]
pub struct A40(pub [u64; 5]);
#[derive(Clone, Copy)]
pub enum E21 {
    A([u8; 20]),
    B,
}
impl Default for E21 {
    fn default() -> Self {
        Self::B
    }
}
#[derive(Clone, Copy)]
pub enum E24 {
    A(u64, u64),
    B(u64),
}
impl Default for E24 {
    fn default() -> Self {
        Self::B(0)
    }
}
#[derive(Clone, Copy)]
pub enum E48 {
    A([u64; 5]),
    B(u64),
}
impl Default for E48 {
    fn default() -> Self {
        Self::B(0)
    }
}

// Response payload layouts (niche-bearing & plain)
#[derive(Clone, Copy)]
pub struct R8N(pub NonZeroU64);
impl Default for R8N {
    fn default() -> Self {
        Self(NonZeroU64::MIN)
    }
}
#[derive(Clone, Copy)]
pub struct R24N(pub NonZeroU64, pub [u64; 2]);
impl Default for R24N {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 2])
    }
}
#[derive(Clone, Copy)]
pub struct R32N(pub NonZeroU64, pub [u64; 3]);
impl Default for R32N {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 3])
    }
}
#[derive(Clone, Copy)]
pub struct R48N(pub NonZeroU64, pub [u64; 5]);
impl Default for R48N {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 5])
    }
}
#[derive(Clone, Copy)]
#[repr(align(16))]
pub struct R112A(pub NonZeroU64, pub [u64; 13]);
impl Default for R112A {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 13])
    }
}
#[derive(Clone, Copy)]
pub struct R288N(pub NonZeroU64, pub [u64; 35]);
impl Default for R288N {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 35])
    }
}
#[derive(Clone, Copy, Default)]
pub struct P32(pub [u64; 4]);

impl AbciStateInfoHandler {
    async fn q0_dir<R: Default, const T: usize>(&self, ctx: ReqCtx) -> R {
        let inner = &*self.inner;
        let meta = &inner.meta;
        let local = LocalMeta::Ctx(ctx);
        with_abci_state(
            &inner.lock,
            Op0::<R, T> {
                meta,
                local: &local,
                _p: core::marker::PhantomData,
            },
            false,
        )
    }

    async fn q0_hlp<R: Default, const T: usize>(&self, ctx: ReqCtx) -> R {
        run_0::<R, T>(&self.inner, ctx)
    }

    async fn qa_dir<A: Copy, R: Default, const T: usize>(&self, ctx: ReqCtx, arg: A) -> R {
        let inner = &*self.inner;
        let meta = &inner.meta;
        let local = LocalMeta::Ctx(ctx);
        with_abci_state(
            &inner.lock,
            OpArg::<A, R, T> {
                meta,
                local: &local,
                arg,
                _p: core::marker::PhantomData,
            },
            false,
        )
    }

    async fn qa_hlp<A: Copy, R: Default, const T: usize>(&self, ctx: ReqCtx, arg: A) -> R {
        run_a::<A, R, T>(&self.inner, ctx, arg)
    }

    #[inline(never)]
    fn anti0<R: Default, const T: usize>(&self, ctx: ReqCtx) -> R {
        with_abci_state(
            &self.inner.lock,
            Op0::<R, T> {
                meta: &self.inner.meta,
                local: &LocalMeta::Other(ctx.a),
                _p: core::marker::PhantomData,
            },
            true,
        )
    }

    #[inline(never)]
    fn antia<A: Copy, R: Default, const T: usize>(&self, ctx: ReqCtx, arg: A) -> R {
        with_abci_state(
            &self.inner.lock,
            OpArg::<A, R, T> {
                meta: &self.inner.meta,
                local: &LocalMeta::Other(ctx.a),
                arg,
                _p: core::marker::PhantomData,
            },
            true,
        )
    }
}

pub fn main() {
    let store = std::hint::black_box(EvmStore {
        _pad: [0; 0x28],
        hash_index: 0,
    });
    let bid = std::hint::black_box(None);
    let _ = std::hint::black_box(resolve_block_number(
        &store,
        &bid,
        std::hint::black_box(123u64),
    ));
    let _ = std::hint::black_box(lookup_hash(
        &store.hash_index,
        std::hint::black_box([7u8; 32]),
    ));

    let h = AbciStateInfoHandler {
        inner: Box::new(InnerState {
            _pad0: [0; 0x10],
            meta: 0,
            _pad1: [0; 0x128],
            lock: 0,
        }),
    };
    let ctx = std::hint::black_box(ReqCtx { a: 1, b: 2 });

    macro_rules! reg0 {
        ($fn:ident, $R:ty, $T:literal) => {
            let _: Pin<Box<dyn Future<Output = $R> + '_>> =
                std::hint::black_box(Box::pin(h.$fn::<$R, $T>(ctx)));
            if std::hint::black_box(false) {
                let _ = std::hint::black_box(h.anti0::<$R, $T>(ctx));
            }
        };
    }
    macro_rules! rega {
        ($fn:ident, $A:ty, $R:ty, $T:literal) => {
            let _: Pin<Box<dyn Future<Output = $R> + '_>> =
                std::hint::black_box(Box::pin(h.$fn::<$A, $R, $T>(ctx, <$A>::default())));
            if std::hint::black_box(false) {
                let _ = std::hint::black_box(h.antia::<$A, $R, $T>(ctx, <$A>::default()));
            }
        };
    }

    // 0-arg async queries (121 B, 148 B x5, 150 B x5, 158 B)
    reg0!(q0_dir, u64, 1);
    reg0!(q0_dir, R32N, 2);
    reg0!(q0_hlp, R24N, 3);
    reg0!(q0_dir, P32, 4);
    reg0!(q0_dir, R48N, 5);

    // 20-byte User arg queries (144 B x2, 177 B x6, 185 B, 191 B, 193 B x2, 247 B)
    rega!(qa_dir, A20, R8N, 10);
    rega!(qa_hlp, A20, R24N, 11);
    rega!(qa_dir, A20, R32N, 12);
    rega!(qa_dir, A20, R288N, 13);
    rega!(qa_dir, A20, P32, 14);
    rega!(qa_dir, A20, R112A, 15);

    // 21-byte Option<User>, 40-byte pair, and 24B/48B enum arg queries
    // (146 B, 160 B, 249 B x6, 267 B x4)
    rega!(qa_dir, E21, R8N, 20);
    rega!(qa_dir, A40, u64, 21);
    rega!(qa_dir, E24, R112A, 22);
    rega!(qa_dir, E48, R112A, 23);
}
