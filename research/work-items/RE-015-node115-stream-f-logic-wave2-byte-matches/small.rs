#![forbid(unsafe_code)]
#![allow(dead_code)]

use core::fmt;
use core::future::Future;
use core::num::NonZeroU64;
use core::pin::Pin;

// --- bridge (0x457cf20..0x457cf52, 50 B): <BridgeRole as Display>::fmt ---
pub enum BridgeRole {
    Locker,
    Finalizer,
}

impl fmt::Display for BridgeRole {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locker => f.write_str("Locker"),
            Self::Finalizer => f.write_str("Finalizer"),
        }
    }
}

// --- evm (0x4493250..0x449326a, 26 B): l1/src/evm/evm_state.rs:183:9 unreachable!() ---
#[inline(never)]
#[cold]
pub fn evm_unreachable() -> ! {
    unreachable!()
}

// --- info_server/src/abci_state_info_handler.rs:81-82 remaining 16 inner async Future::poll FDEs ---
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

pub struct OpArg2<'a, A, R, const T: usize> {
    pub meta: &'a u64,
    pub arg: A,
    pub local: &'a LocalMeta,
    pub _p: core::marker::PhantomData<R>,
}

impl<'a, A, R: Default, const T: usize> StateOp for OpArg2<'a, A, R, T> {
    type Output = R;
    #[inline(never)]
    fn run(self, s: &u64) -> R {
        std::hint::black_box((s, self.meta, &self.arg, self.local, T));
        std::hint::black_box(R::default())
    }
}

#[derive(Clone, Copy, Default)]
pub struct A20(pub [u8; 20]);
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
pub enum E32 {
    A([u64; 3]),
    B(u64),
}
impl Default for E32 {
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
#[derive(Clone, Copy)]
pub enum E64 {
    A([u64; 7]),
    B(u64),
}
impl Default for E64 {
    fn default() -> Self {
        Self::B(0)
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
pub struct R40N(pub NonZeroU64, pub [u64; 4]);
impl Default for R40N {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 4])
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
pub struct R56N(pub NonZeroU64, pub [u64; 6]);
impl Default for R56N {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 6])
    }
}
#[derive(Clone, Copy)]
pub struct R80N(pub NonZeroU64, pub [u64; 9]);
impl Default for R80N {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 9])
    }
}
#[derive(Clone, Copy)]
pub struct R96N(pub NonZeroU64, pub [u64; 11]);
impl Default for R96N {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 11])
    }
}
#[derive(Clone, Copy)]
pub struct R104N(pub NonZeroU64, pub [u64; 12]);
impl Default for R104N {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 12])
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
#[repr(align(16))]
pub struct R128A(pub NonZeroU64, pub [u64; 15]);
impl Default for R128A {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 15])
    }
}
#[derive(Clone, Copy)]
pub struct R168N(pub NonZeroU64, pub [u64; 20]);
impl Default for R168N {
    fn default() -> Self {
        Self(NonZeroU64::MIN, [0; 20])
    }
}

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

    async fn qa2_dir<A: Copy, R: Default, const T: usize>(&self, ctx: ReqCtx, arg: A) -> R {
        let inner = &*self.inner;
        let meta = &inner.meta;
        let local = LocalMeta::Ctx(ctx);
        with_abci_state(
            &inner.lock,
            OpArg2::<A, R, T> {
                meta,
                arg,
                local: &local,
                _p: core::marker::PhantomData,
            },
            false,
        )
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

    #[inline(never)]
    fn antia2<A: Copy, R: Default, const T: usize>(&self, ctx: ReqCtx, arg: A) -> R {
        with_abci_state(
            &self.inner.lock,
            OpArg2::<A, R, T> {
                meta: &self.inner.meta,
                arg,
                local: &LocalMeta::Other(ctx.a),
                _p: core::marker::PhantomData,
            },
            true,
        )
    }
}

pub fn main() {
    let mut s = String::new();
    let _ = fmt::write(&mut s, format_args!("{}", std::hint::black_box(BridgeRole::Locker)));
    let _ = std::hint::black_box(s);
    if std::hint::black_box(false) {
        evm_unreachable();
    }

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
    macro_rules! rega2 {
        ($A:ty, $R:ty, $T:literal) => {
            let _: Pin<Box<dyn Future<Output = $R> + '_>> =
                std::hint::black_box(Box::pin(h.qa2_dir::<$A, $R, $T>(ctx, <$A>::default())));
            if std::hint::black_box(false) {
                let _ = std::hint::black_box(h.antia2::<$A, $R, $T>(ctx, <$A>::default()));
            }
        };
    }

    reg0!(q0_dir, R80N, 1);
    rega!(qa_dir, A20, E21, 2);
    rega!(qa_dir, E48, R128A, 3);
    rega2!(u64, R96N, 4);
    rega2!((u64, bool), R96N, 5);
    rega2!(Option<u64>, R96N, 6);
    rega!(qa_dir, A20, R56N, 7);
    rega!(qa_dir, E21, R168N, 9);
    rega2!(bool, R48N, 11);
    rega2!(u8, R48N, 12);
    rega!(qa_dir, E64, (), 13);
    rega!(qa_dir, A20, R40N, 14);
    rega2!(u8, R56N, 16);
    rega2!(bool, R56N, 17);
    rega2!(u64, R112A, 18);
    rega2!(u64, R32N, 19);
    rega!(qa_dir, A20, R104N, 20);
    rega!(qa_dir, E32, R128A, 21);
    rega!(qa_dir, A20, R80N, 22);
}
