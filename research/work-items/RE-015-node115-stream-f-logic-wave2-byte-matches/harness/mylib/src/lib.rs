#![forbid(unsafe_code)]
#![allow(dead_code)]

use core::future::Future;
use core::num::NonZeroU64;
use core::pin::Pin;

#[repr(C)]
pub struct InnerState {
    _pad0: [u8; 0x10],
    pub meta: u64,
    _pad1: [u8; 0x128],
    pub lock: u64,
}
impl Default for InnerState {
    fn default() -> Self {
        Self {
            _pad0: [0; 0x10],
            meta: 0,
            _pad1: [0; 0x128],
            lock: 0,
        }
    }
}

pub struct AbciStateInfoHandler {
    pub inner: Box<InnerState>,
}

#[derive(Clone, Copy)]
pub struct ReqCtxN(pub NonZeroU64, pub u64);
impl Default for ReqCtxN {
    fn default() -> Self {
        Self(NonZeroU64::MIN, 0)
    }
}

static DUMMY_CTX: u8 = 0;
#[derive(Clone, Copy)]
pub struct ReqCtxPP(pub &'static u8, pub &'static u8);
impl Default for ReqCtxPP {
    fn default() -> Self {
        Self(&DUMMY_CTX, &DUMMY_CTX)
    }
}

#[derive(Clone, Copy)]
pub enum LocalMeta<'a> {
    Ctx(&'a str),
    Ctx2(ReqCtxN),
    Ctx3(ReqCtxPP),
    Other(u64),
}

pub trait StateOp {
    type Output;
    fn run(self, s: &u64) -> Self::Output;
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
    pub local: &'a LocalMeta<'a>,
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
    pub local: &'a LocalMeta<'a>,
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

struct NoopGuard(bool);
impl Drop for NoopGuard {
    #[inline(always)]
    fn drop(&mut self) {}
}

// --- Argument types ---
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

// 64 B with NonNull niche + non-inlined Drop (for 0x297dfe0)
pub struct S64Drop(pub String, pub [u64; 5]);
impl Default for S64Drop {
    fn default() -> Self {
        Self(String::new(), [0; 5])
    }
}
impl Drop for S64Drop {
    #[inline(never)]
    fn drop(&mut self) {
        std::hint::black_box(&mut self.1);
    }
}

// 16 B (u64 @ 0, bool @ 8)
#[derive(Clone, Copy, Default)]
pub struct A9B(pub u64, pub bool);

// --- Niche helper enums ---
#[derive(Clone, Copy, Default)]
#[repr(u8)]
pub enum Tag5u8 {
    #[default]
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
}

#[derive(Clone, Copy)]
pub enum E4T5 {
    V0(u16),
    V1(u16),
    V2(u16),
    V3(u16),
    V4(u16),
}
impl Default for E4T5 {
    fn default() -> Self {
        Self::V0(0)
    }
}

macro_rules! def_enum_419 {
    ($($v:ident),* $(,)?) => {
        #[derive(Clone, Copy)]
        #[repr(u16)]
        pub enum Tag419 { $($v),* }
        impl Default for Tag419 { fn default() -> Self { Self::V000 } }
    };
}
def_enum_419!(
    V000,V001,V002,V003,V004,V005,V006,V007,V008,V009,V010,V011,V012,V013,V014,V015,V016,V017,V018,V019,
    V020,V021,V022,V023,V024,V025,V026,V027,V028,V029,V030,V031,V032,V033,V034,V035,V036,V037,V038,V039,
    V040,V041,V042,V043,V044,V045,V046,V047,V048,V049,V050,V051,V052,V053,V054,V055,V056,V057,V058,V059,
    V060,V061,V062,V063,V064,V065,V066,V067,V068,V069,V070,V071,V072,V073,V074,V075,V076,V077,V078,V079,
    V080,V081,V082,V083,V084,V085,V086,V087,V088,V089,V090,V091,V092,V093,V094,V095,V096,V097,V098,V099,
    V100,V101,V102,V103,V104,V105,V106,V107,V108,V109,V110,V111,V112,V113,V114,V115,V116,V117,V118,V119,
    V120,V121,V122,V123,V124,V125,V126,V127,V128,V129,V130,V131,V132,V133,V134,V135,V136,V137,V138,V139,
    V140,V141,V142,V143,V144,V145,V146,V147,V148,V149,V150,V151,V152,V153,V154,V155,V156,V157,V158,V159,
    V160,V161,V162,V163,V164,V165,V166,V167,V168,V169,V170,V171,V172,V173,V174,V175,V176,V177,V178,V179,
    V180,V181,V182,V183,V184,V185,V186,V187,V188,V189,V190,V191,V192,V193,V194,V195,V196,V197,V198,V199,
    V200,V201,V202,V203,V204,V205,V206,V207,V208,V209,V210,V211,V212,V213,V214,V215,V216,V217,V218,V219,
    V220,V221,V222,V223,V224,V225,V226,V227,V228,V229,V230,V231,V232,V233,V234,V235,V236,V237,V238,V239,
    V240,V241,V242,V243,V244,V245,V246,V247,V248,V249,V250,V251,V252,V253,V254,V255,V256,V257,V258,V259,
    V260,V261,V262,V263,V264,V265,V266,V267,V268,V269,V270,V271,V272,V273,V274,V275,V276,V277,V278,V279,
    V280,V281,V282,V283,V284,V285,V286,V287,V288,V289,V290,V291,V292,V293,V294,V295,V296,V297,V298,V299,
    V300,V301,V302,V303,V304,V305,V306,V307,V308,V309,V310,V311,V312,V313,V314,V315,V316,V317,V318,V319,
    V320,V321,V322,V323,V324,V325,V326,V327,V328,V329,V330,V331,V332,V333,V334,V335,V336,V337,V338,V339,
    V340,V341,V342,V343,V344,V345,V346,V347,V348,V349,V350,V351,V352,V353,V354,V355,V356,V357,V358,V359,
    V360,V361,V362,V363,V364,V365,V366,V367,V368,V369,V370,V371,V372,V373,V374,V375,V376,V377,V378,V379,
    V380,V381,V382,V383,V384,V385,V386,V387,V388,V389,V390,V391,V392,V393,V394,V395,V396,V397,V398,V399,
    V400,V401,V402,V403,V404,V405,V406,V407,V408,V409,V410,V411,V412,V413,V414,V415,V416,V417,V418
);

// --- Return types ---
#[derive(Clone, Copy)]
pub struct R8N(pub NonZeroU64);
impl Default for R8N {
    fn default() -> Self {
        Self(NonZeroU64::MIN)
    }
}

#[derive(Default)]
pub struct R24V0(pub Vec<u8>);
#[derive(Default)]
pub struct R48V0(pub Vec<u8>, pub [u64; 3]);

#[derive(Clone, Copy, Default)]
pub struct P32(pub [u64; 4]);

#[derive(Default)]
pub struct R32V1(pub Option<(Vec<u8>, u64)>);
#[derive(Default)]
pub struct R48V1(pub Option<(Vec<u8>, [u64; 3])>);
#[derive(Default)]
pub struct R96V1(pub Option<(Vec<u8>, [u64; 9])>);
#[derive(Default)]
pub enum R32V2 {
    #[default]
    B,
    C,
    A(Vec<u8>, u64),
}
#[derive(Default)]
pub enum R96V2 {
    #[default]
    B,
    C,
    A(Vec<u8>, [u64; 9]),
}

#[repr(C, align(16))]
pub struct R112T419 {
    pub t: Tag419,
    pub d: [u64; 13],
}
impl Default for R112T419 {
    fn default() -> Self {
        Self {
            t: Tag419::V000,
            d: [0; 13],
        }
    }
}
impl Drop for R112T419 {
    #[inline(always)]
    fn drop(&mut self) {}
}

#[derive(Clone, Copy, Default)]
pub struct R21T5 {
    pub t: Tag5u8,
    pub d: [u8; 20],
}

#[derive(Clone, Copy)]
pub enum R40E2 {
    A([u64; 4]),
    B(u64),
}
impl Default for R40E2 {
    fn default() -> Self {
        Self::B(0)
    }
}

#[derive(Clone, Copy)]
pub enum R56E2 {
    A([u64; 6]),
    B(u64),
}
impl Default for R56E2 {
    fn default() -> Self {
        Self::B(0)
    }
}

#[derive(Clone, Copy)]
pub enum R56E3 {
    A([u64; 6]),
    B(u64),
    C(u64),
}
impl Default for R56E3 {
    fn default() -> Self {
        Self::B(0)
    }
}

#[derive(Clone, Copy)]
pub enum R80E3 {
    A([u64; 9]),
    B(u64),
    C(u64),
}
impl Default for R80E3 {
    fn default() -> Self {
        Self::B(0)
    }
}

#[derive(Clone, Copy)]
pub enum R104E2 {
    A([u64; 12]),
    B(u64),
}
impl Default for R104E2 {
    fn default() -> Self {
        Self::B(0)
    }
}

#[repr(align(16))]
pub enum R128E2 {
    A([u64; 14]),
    B(u64),
}
impl Default for R128E2 {
    fn default() -> Self {
        Self::B(0)
    }
}
impl Drop for R128E2 {
    #[inline(always)]
    fn drop(&mut self) {}
}

#[repr(u128)]
pub enum R128U128E2 {
    A([u64; 14]),
    B(u64),
}
impl Default for R128U128E2 {
    fn default() -> Self {
        Self::B(0)
    }
}
impl Drop for R128U128E2 {
    #[inline(always)]
    fn drop(&mut self) {}
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct R80Off40E2 {
    pub head: [u64; 8],
    pub tail: R16E2,
}
#[derive(Clone, Copy)]
pub enum R16E2 {
    A(u64),
    B(u64),
}
impl Default for R16E2 {
    fn default() -> Self {
        Self::B(0)
    }
}
impl Default for R80Off40E2 {
    fn default() -> Self {
        Self {
            head: [0; 8],
            tail: R16E2::B(0),
        }
    }
}

#[derive(Clone, Copy)]
pub enum R168E2 {
    A([u64; 20]),
    B(u64),
}
impl Default for R168E2 {
    fn default() -> Self {
        Self::B(0)
    }
}

#[derive(Clone, Copy)]
pub enum R288E2 {
    A([u64; 35]),
    B(u64),
}
impl Default for R288E2 {
    fn default() -> Self {
        Self::B(0)
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct R216OffC0E4 {
    pub head: [u64; 24],
    pub tail: R24E4,
}
#[derive(Clone, Copy)]
pub enum R24E4 {
    V0([u64; 2]),
    V1(u64),
    V2(u64),
    V3(u64),
}
impl Default for R24E4 {
    fn default() -> Self {
        Self::V0([0; 2])
    }
}
impl Default for R216OffC0E4 {
    fn default() -> Self {
        Self {
            head: [0; 24],
            tail: R24E4::V0([0; 2]),
        }
    }
}

#[derive(Default)]
pub struct RUnit;
impl Drop for RUnit {
    #[inline(always)]
    fn drop(&mut self) {}
}

macro_rules! def_w0 {
    ($name:ident, $inner:ident, $R:ty, $T:literal) => {
        fn $inner<'a>(&'a self, ctx: &'a str) -> Pin<Box<dyn Future<Output = $R> + Send + 'a>> {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<$R> {
                    #[allow(unreachable_code)]
                    return __ret;
                }
                let __self = self;
                let ctx = ctx;
                let __ret: $R = {
                    let inner = &__self.inner;
                    let meta = &inner.meta;
                    let local = LocalMeta::Ctx(ctx);
                    with_abci_state(
                        &inner.lock,
                        Op0::<$R, $T> {
                            meta,
                            local: &local,
                            _p: core::marker::PhantomData,
                        },
                        false,
                    )
                };
                #[allow(unreachable_code)]
                __ret
            })
        }
        #[inline(never)]
        pub fn $name<'a>(&'a self, ctx: &'a str) -> Pin<Box<dyn Future<Output = $R> + Send + 'a>> {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<$R> {
                    #[allow(unreachable_code)]
                    return __ret;
                }
                let __self = self;
                let _g = NoopGuard(false);
                let ctx = ctx;
                let __ret: $R = { __self.$inner(ctx).await };
                #[allow(unreachable_code)]
                __ret
            })
        }
    };
}

macro_rules! def_wa {
    ($name:ident, $inner:ident, $A:ty, $R:ty, $T:literal) => {
        fn $inner<'a>(
            &'a self,
            arg: $A,
            ctx: &'a str,
        ) -> Pin<Box<dyn Future<Output = $R> + Send + 'a>> {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<$R> {
                    #[allow(unreachable_code)]
                    return __ret;
                }
                let __self = self;
                let arg = arg;
                let ctx = ctx;
                let __ret: $R = {
                    let inner = &__self.inner;
                    let meta = &inner.meta;
                    let local = LocalMeta::Ctx(ctx);
                    with_abci_state(
                        &inner.lock,
                        OpArg::<$A, $R, $T> {
                            meta,
                            local: &local,
                            arg,
                            _p: core::marker::PhantomData,
                        },
                        false,
                    )
                };
                #[allow(unreachable_code)]
                __ret
            })
        }
        #[inline(never)]
        pub fn $name<'a>(
            &'a self,
            ctx: &'a str,
            arg: $A,
        ) -> Pin<Box<dyn Future<Output = $R> + Send + 'a>> {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<$R> {
                    #[allow(unreachable_code)]
                    return __ret;
                }
                let __self = self;
                let _g = NoopGuard(false);
                let arg = arg;
                let ctx = ctx;
                let __ret: $R = { __self.$inner(arg, ctx).await };
                #[allow(unreachable_code)]
                __ret
            })
        }
    };
}

macro_rules! def_wa_str_sc {
    ($name:ident, $inner:ident, $A:ty, $R:ty, $T:literal) => {
        fn $inner<'a>(
            arg: $A,
            ctx: ReqCtxPP,
            this: &'a AbciStateInfoHandler,
        ) -> Pin<Box<dyn Future<Output = $R> + Send + 'a>> {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<$R> {
                    #[allow(unreachable_code)]
                    return __ret;
                }
                let arg = arg;
                let ctx = ctx;
                let __self = this;
                let __ret: $R = {
                    let inner = &__self.inner;
                    let meta = &inner.meta;
                    let local = LocalMeta::Ctx3(ctx);
                    with_abci_state(
                        &inner.lock,
                        OpArg::<$A, $R, $T> {
                            meta,
                            local: &local,
                            arg,
                            _p: core::marker::PhantomData,
                        },
                        false,
                    )
                };
                #[allow(unreachable_code)]
                __ret
            })
        }
        #[inline(never)]
        pub fn $name<'a>(
            arg: $A,
            ctx: ReqCtxPP,
            this: &'a AbciStateInfoHandler,
        ) -> Pin<Box<dyn Future<Output = $R> + Send + 'a>> {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<$R> {
                    #[allow(unreachable_code)]
                    return __ret;
                }
                let __ret: $R = { Self::$inner(arg, ctx, this).await };
                #[allow(unreachable_code)]
                __ret
            })
        }
    };
}

macro_rules! def_wa_str_pp {
    ($name:ident, $inner:ident, $A:ty, $R:ty, $T:literal) => {
        fn $inner<'a>(
            arg: $A,
            ctx: ReqCtxPP,
            this: &'a AbciStateInfoHandler,
        ) -> Pin<Box<dyn Future<Output = $R> + Send + 'a>> {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<$R> {
                    #[allow(unreachable_code)]
                    return __ret;
                }
                let arg = arg;
                let ctx = ctx;
                let __self = this;
                let __ret: $R = {
                    let inner = &__self.inner;
                    let meta = &inner.meta;
                    let local = LocalMeta::Ctx3(ctx);
                    with_abci_state(
                        &inner.lock,
                        OpArg::<$A, $R, $T> {
                            meta,
                            local: &local,
                            arg,
                            _p: core::marker::PhantomData,
                        },
                        false,
                    )
                };
                #[allow(unreachable_code)]
                __ret
            })
        }
        #[inline(never)]
        pub fn $name<'a>(
            arg: $A,
            ctx: ReqCtxPP,
            this: &'a AbciStateInfoHandler,
        ) -> Pin<Box<dyn Future<Output = $R> + Send + 'a>> {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<$R> {
                    #[allow(unreachable_code)]
                    return __ret;
                }
                let arg = arg;
                let ctx = ctx;
                let __self = this;
                let __ret: $R = { Self::$inner(arg, ctx, __self).await };
                #[allow(unreachable_code)]
                __ret
            })
        }
    };
}

macro_rules! def_wa_ord {
    ($name:ident, $inner:ident, $A:ty, $R:ty, $T:literal) => {
        fn $inner<'a>(
            arg: $A,
            ctx: ReqCtxN,
            this: &'a AbciStateInfoHandler,
        ) -> Pin<Box<dyn Future<Output = $R> + Send + 'a>> {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<$R> {
                    #[allow(unreachable_code)]
                    return __ret;
                }
                let arg = arg;
                let ctx = ctx;
                let __self = this;
                let __ret: $R = {
                    let inner = &__self.inner;
                    let meta = &inner.meta;
                    let local = LocalMeta::Ctx2(ctx);
                    with_abci_state(
                        &inner.lock,
                        OpArg::<$A, $R, $T> {
                            meta,
                            local: &local,
                            arg,
                            _p: core::marker::PhantomData,
                        },
                        false,
                    )
                };
                #[allow(unreachable_code)]
                __ret
            })
        }
        #[inline(never)]
        pub fn $name<'a>(
            arg: $A,
            ctx: ReqCtxN,
            this: &'a AbciStateInfoHandler,
        ) -> Pin<Box<dyn Future<Output = $R> + Send + 'a>> {
            Box::pin(async move {
                if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<$R> {
                    #[allow(unreachable_code)]
                    return __ret;
                }
                let _g = NoopGuard(false);
                let arg = arg;
                let ctx = ctx;
                let __self = this;
                let __ret: $R = { Self::$inner(arg, ctx, __self).await };
                #[allow(unreachable_code)]
                __ret
            })
        }
    };
}

impl AbciStateInfoHandler {
    def_w0!(w0_u64, q0_u64, u64, 1);
    def_w0!(w0_r24v0, q0_r24v0, R24V0, 2);
    def_w0!(w0_r32v1, q0_r32v1, R32V1, 3);
    def_w0!(w0_r48v1, q0_r48v1, R48V1, 4);

    def_wa!(wa_a20_e4t5, qa_a20_e4t5, A20, E4T5, 10);
    def_wa!(wa_a20_r24v0, qa_a20_r24v0, A20, R24V0, 11);
    def_wa!(wa_a20_r32v1, qa_a20_r32v1, A20, R32V1, 12);
    def_wa!(wa_a20_p32, qa_a20_p32, A20, P32, 13);
    def_wa!(wa_a20_r21t5, qa_a20_r21t5, A20, R21T5, 14);
    def_wa!(wa_a20_r40e2, qa_a20_r40e2, A20, R40E2, 15);
    def_wa!(wa_a20_r56e2, qa_a20_r56e2, A20, R56E2, 16);
    def_wa!(wa_a20_r80e3, qa_a20_r80e3, A20, R80E3, 17);
    def_wa!(wa_a20_r104e2, qa_a20_r104e2, A20, R104E2, 18);
    def_wa!(wa_a20_r112t419, qa_a20_r112t419, A20, R112T419, 19);
    def_wa!(wa_a20_r288e2, qa_a20_r288e2, A20, R288E2, 20);

    def_wa!(wa_e21_r8n, qa_e21_r8n, E21, R8N, 30);
    def_wa!(wa_e21_r168e2, qa_e21_r168e2, E21, R168E2, 31);
    def_wa!(wa_a40_u64, qa_a40_u64, A40, u64, 32);
    def_wa!(wa_bool_r48v0, qa_bool_r48v0, bool, R48V0, 34);

    fn qa_u8_r56e3<'a>(
        &'a self,
        arg: u8,
        ctx: &'a str,
    ) -> Pin<Box<dyn Future<Output = R56E3> + Send + 'a>> {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<R56E3> {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __self = self;
            let arg = arg;
            let ctx = ctx;
            let __ret: R56E3 = {
                let inner = &__self.inner;
                let meta = &inner.meta;
                let local = LocalMeta::Ctx(ctx);
                with_abci_state(
                    &inner.lock,
                    OpArg::<u8, R56E3, 35> {
                        meta,
                        local: &local,
                        arg,
                        _p: core::marker::PhantomData,
                    },
                    false,
                )
            };
            #[allow(unreachable_code)]
            __ret
        })
    }
    #[inline(never)]
    pub fn wa_bool_u8_r56e3<'a>(
        &'a self,
        ctx: &'a str,
        arg: bool,
    ) -> Pin<Box<dyn Future<Output = R56E3> + Send + 'a>> {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<R56E3> {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __self = self;
            let _g = NoopGuard(false);
            let arg = arg as u8;
            let ctx = ctx;
            let __ret: R56E3 = { __self.qa_u8_r56e3(arg, ctx).await };
            #[allow(unreachable_code)]
            __ret
        })
    }

    def_wa!(wa_u64_r32v2, qa_u64_r32v2, u64, R32V2, 40);
    def_wa!(wa_u64_r96v1, qa_u64_r96v1, u64, R96V1, 41);
    def_wa!(wa_u64_r112t419, qa_u64_r112t419, u64, R112T419, 42);
    def_wa!(wa_u64b_r96v2, qa_u64b_r96v2, (u64, bool), R96V2, 43);

    def_wa_str_pp!(wa_str_r112t419, qa_str_r112t419, String, R112T419, 50);
    def_wa_str_sc!(wa_str24_r112t419, qa_str24_r112t419, (String, [u64; 3]), R112T419, 51);
    def_wa_str_sc!(wa_str24_r128e2, qa_str24_r128e2, (String, [u64; 3]), R128E2, 52);
    def_wa_str_sc!(wa_s64d_unit, qa_s64d_unit, S64Drop, RUnit, 53);
    def_wa_ord!(wa_a9b_r80e2, qa_a9b_r80e2, A9B, R80Off40E2, 54);
    def_wa_ord!(wa_a9b_r216e4, qa_a9b_r216e4, A9B, R216OffC0E4, 55);
    def_wa_str_sc!(wa_str8_r128u128, qa_str8_r128u128, (String, u64), R128U128E2, 56);

    #[inline(never)]
    pub fn anti_all(&self) {
        let l = LocalMeta::Other(1);
        macro_rules! a0 {
            ($R:ty, $T:literal) => {
                let _ = std::hint::black_box(with_abci_state(
                    &self.inner.lock,
                    Op0::<$R, $T> {
                        meta: &self.inner.meta,
                        local: &l,
                        _p: core::marker::PhantomData,
                    },
                    true,
                ));
            };
        }
        macro_rules! aa {
            ($A:ty, $R:ty, $T:literal) => {
                let _ = std::hint::black_box(with_abci_state(
                    &self.inner.lock,
                    OpArg::<$A, $R, $T> {
                        meta: &self.inner.meta,
                        local: &l,
                        arg: <$A>::default(),
                        _p: core::marker::PhantomData,
                    },
                    true,
                ));
            };
        }
        a0!(u64, 1);
        a0!(R24V0, 2);
        a0!(R32V1, 3);
        a0!(R48V1, 4);
        aa!(A20, E4T5, 10);
        aa!(A20, R24V0, 11);
        aa!(A20, R32V1, 12);
        aa!(A20, P32, 13);
        aa!(A20, R21T5, 14);
        aa!(A20, R40E2, 15);
        aa!(A20, R56E2, 16);
        aa!(A20, R80E3, 17);
        aa!(A20, R104E2, 18);
        aa!(A20, R112T419, 19);
        aa!(A20, R288E2, 20);
        aa!(E21, R8N, 30);
        aa!(E21, R168E2, 31);
        aa!(A40, u64, 32);
        aa!(bool, R48V0, 34);
        aa!(u8, R56E3, 35);
        aa!(u64, R32V2, 40);
        aa!(u64, R96V1, 41);
        aa!(u64, R112T419, 42);
        aa!((u64, bool), R96V2, 43);
        aa!(String, R112T419, 50);
        aa!((String, [u64; 3]), R112T419, 51);
        aa!((String, [u64; 3]), R128E2, 52);
        aa!(S64Drop, RUnit, 53);
        aa!(A9B, R80Off40E2, 54);
        aa!(A9B, R216OffC0E4, 55);
        aa!((String, u64), R128U128E2, 56);
    }
}
