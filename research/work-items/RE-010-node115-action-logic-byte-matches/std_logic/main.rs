#![forbid(unsafe_code)]
#![allow(dead_code, non_camel_case_types)]

use std::hint::black_box;
use std::panic::Location;
use std::sync::LazyLock;

use e2b_lib::*;

// ============================================================================
// 1. l1-shared: hyperliquidity_funding_cost (0x38bcb80..0x38bcbee, 110 B)
// ============================================================================
#[repr(C)]
pub struct HlOrder {
    pub a: u64,
    pub b: u64,
    pub sz: u64,
}

#[repr(C)]
pub struct HlFundingArgs<'a> {
    pub orders: &'a Vec<HlOrder>,
    pub n_levels: &'a usize,
    pub px: &'a u64,
}

#[inline(never)]
pub fn e2b_hyperliquidity_funding_cost(args: &HlFundingArgs<'_>) -> Option<u64> {
    let mut total: u64 = 0;
    for order in args.orders.iter().take(*args.n_levels) {
        let cost = order.sz.checked_mul(*args.px)?;
        if cost >= i64::MAX as u64 {
            return None;
        }
        total = total.checked_add(cost)?;
    }
    Some(total)
}

// ============================================================================
// 2. l1-shared: ChainExt::chain_config (0x46f3fc0..0x46f40b0, 240 B)
// ============================================================================
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Chain {
    Local = 0,
    Sandbox = 1,
    Testnet = 2,
    Mainnet = 3,
}

pub struct ChainCfg([u8; 64]);

static SANDBOX_CFG: LazyLock<ChainCfg> = LazyLock::new(|| {
    if black_box(false) {
        panic!("s");
    }
    ChainCfg([1; 64])
});
static MAINNET_CFG: LazyLock<ChainCfg> = LazyLock::new(|| {
    if black_box(false) {
        panic!("m");
    }
    ChainCfg([2; 64])
});
static TESTNET_CFG: LazyLock<ChainCfg> = LazyLock::new(|| {
    if black_box(false) {
        panic!("t");
    }
    ChainCfg([3; 64])
});

#[inline(never)]
pub fn e2b_chain_ext_config(chain: Chain) -> &'static ChainCfg {
    match chain {
        Chain::Local => panic!("invalid chain"),
        Chain::Sandbox => &*SANDBOX_CFG,
        Chain::Testnet => &*TESTNET_CFG,
        Chain::Mainnet => &*MAINNET_CFG,
    }
}

// ============================================================================
// 3 & 4. l1-shared: nonce_set expanded address allowlists (2 x 347 B)
// ============================================================================
const EXPANDED_B: [[u8; 20]; 8] = [
    [0x2e, 0x3d, 0x94, 0xf0, 0x56, 0x27, 0x03, 0xb2, 0x5c, 0x83, 0x30, 0x8a, 0x05, 0x04, 0x6d, 0xda, 0xf9, 0xa8, 0xdd, 0x14],
    [0xb0, 0xa5, 0x5f, 0x13, 0xd2, 0x2f, 0x66, 0xe6, 0xd4, 0x95, 0xac, 0x98, 0x11, 0x38, 0x41, 0xb2, 0x32, 0x6e, 0x95, 0x40],
    [0x5e, 0x17, 0x7e, 0x5e, 0x39, 0xc0, 0xf4, 0xe4, 0x21, 0xf5, 0x86, 0x5a, 0x6d, 0x8b, 0xee, 0xd8, 0xd9, 0x21, 0xcb, 0x70],
    [0x2e, 0xd5, 0xc4, 0x48, 0x4e, 0xa3, 0xff, 0x8b, 0x57, 0xd5, 0xf2, 0xfb, 0x15, 0x2a, 0x40, 0xd9, 0xf2, 0xb6, 0x83, 0x08],
    [0x6a, 0x87, 0x50, 0xa4, 0xcc, 0xcf, 0xfd, 0xb3, 0x94, 0xa7, 0xbb, 0xe9, 0xd4, 0xd0, 0xdc, 0xef, 0x23, 0xfb, 0x14, 0x17],
    [0xd0, 0x76, 0x1c, 0x28, 0x19, 0x45, 0xec, 0x08, 0x4d, 0x32, 0x44, 0x15, 0xbb, 0x06, 0x06, 0xbe, 0x2c, 0x8d, 0xf3, 0x82],
    [0xcb, 0xf4, 0xdf, 0xba, 0x8c, 0xdf, 0x95, 0x58, 0xe8, 0x15, 0x53, 0xb0, 0x8f, 0x0d, 0x7c, 0x91, 0x0b, 0x8c, 0x4e, 0x90],
    [0x4f, 0xbe, 0x63, 0x4d, 0x33, 0x28, 0xb1, 0xd5, 0x6f, 0x10, 0x5b, 0x88, 0x7e, 0xd2, 0x5d, 0xcb, 0x2c, 0x71, 0xb8, 0x8d],
];

const EXPANDED_A: [[u8; 20]; 8] = [
    [0x01, 0x04, 0x61, 0xc1, 0x4e, 0x14, 0x6a, 0xc3, 0x5f, 0xe4, 0x22, 0x71, 0xbd, 0xc1, 0x13, 0x4e, 0xe3, 0x1c, 0x70, 0x3a],
    [0x31, 0xca, 0x83, 0x95, 0xcf, 0x83, 0x7d, 0xe0, 0x8b, 0x24, 0xda, 0x3f, 0x66, 0x0e, 0x77, 0x76, 0x1d, 0xfb, 0x97, 0x4b],
    [0x76, 0x84, 0x84, 0xf7, 0xe2, 0xeb, 0xb6, 0x75, 0xc5, 0x78, 0x38, 0x36, 0x6c, 0x02, 0xae, 0x99, 0xba, 0x2a, 0x9b, 0x08],
    [0xc6, 0x4c, 0xc0, 0x0b, 0x46, 0x10, 0x1b, 0xd4, 0x0a, 0xa1, 0xc3, 0x12, 0x11, 0x95, 0xe8, 0x5c, 0x0b, 0x09, 0x18, 0xd8],
    [0x07, 0xbe, 0xd5, 0xc0, 0x83, 0x06, 0xe0, 0x26, 0x79, 0x7e, 0x5e, 0xa9, 0x3c, 0x29, 0x3a, 0xbc, 0x56, 0x73, 0xc2, 0xad],
    [0x93, 0xe2, 0x55, 0x1d, 0x82, 0x1d, 0xda, 0x10, 0x80, 0xa3, 0x72, 0xf0, 0xb0, 0x4b, 0x86, 0x46, 0x83, 0x20, 0x33, 0x3d],
    [0xa1, 0x50, 0x99, 0xa3, 0x0b, 0xbf, 0x2e, 0x68, 0x94, 0x2d, 0x6f, 0x4c, 0x43, 0xd7, 0x0d, 0x04, 0xfa, 0xea, 0xb0, 0xa0],
    [0xdf, 0xc2, 0x4b, 0x07, 0x7b, 0xc1, 0x42, 0x5a, 0xd1, 0xde, 0xa7, 0x5b, 0xcb, 0x6f, 0x81, 0x58, 0xe1, 0x0d, 0xf3, 0x03],
];

#[inline(never)]
pub fn e2b_nonce_set_expanded_set_b(user: &[u8; 20]) -> bool {
    user == &EXPANDED_B[0]
        || user == &EXPANDED_B[1]
        || user == &EXPANDED_B[2]
        || user == &EXPANDED_B[3]
        || user == &EXPANDED_B[4]
        || user == &EXPANDED_B[5]
        || user == &EXPANDED_B[6]
        || user == &EXPANDED_B[7]
}

#[inline(never)]
pub fn e2b_nonce_set_expanded_set_a(user: &[u8; 20]) -> bool {
    user == &EXPANDED_A[0]
        || user == &EXPANDED_A[1]
        || user == &EXPANDED_A[2]
        || user == &EXPANDED_A[3]
        || user == &EXPANDED_A[4]
        || user == &EXPANDED_A[5]
        || user == &EXPANDED_A[6]
        || user == &EXPANDED_A[7]
}

// ============================================================================
// 5..10. action-wire: Withdraw3Action / VaultTransferAction send_to_exchange
// (6 x 184 B = 1,104 B)
// ============================================================================
#[repr(C)]
pub struct WireAddr(pub [u8; 20]);

#[repr(u8)]
pub enum ActionResultWrap {
    V0 = 0, V1 = 1, V2 = 2, V3 = 3, V4 = 4, V5 = 5, V6 = 6, V7 = 7,
    V8 = 8, V9 = 9, V10 = 10, V11 = 11, V12 = 12, V13 = 13,
    Ok = 14,
    Err(ActionError) = 15,
}

#[inline(never)]
pub fn inner_transfer_opt2(
    ctx: &mut u64,
    dst: &[u8; 20],
    flag0: u64,
    flag1: u64,
    out_tag: &mut Option<[u64; 2]>,
    src_addr: &WireAddr,
    arg: &u64,
    loc: &'static Location<'static>,
) -> Result<(), ActionError> {
    black_box((ctx, dst, flag0, flag1, out_tag, src_addr, arg, loc));
    if black_box(false) {
        Err(ActionError::Kind0(ErrPayload96([black_box(1); 12])))
    } else {
        Ok(())
    }
}

#[inline(never)]
pub fn e2b_withdraw3_or_vault_transfer_send(
    arg: &u64,
    user: &WireAddr,
    ctx: &mut u64,
) -> ActionResultWrap {
    let mut out_tag: Option<[u64; 2]> = None;
    let dst = user.0;
    match inner_transfer_opt2(ctx, &dst, 0, 0, &mut out_tag, user, arg, Location::caller()) {
        Ok(()) => ActionResultWrap::Ok,
        Err(e) => ActionResultWrap::Err(e),
    }
}

// ============================================================================
// 11..14. action-wire: Action & BatchModifyAction delayed-action methods (299 B)
// ============================================================================
#[repr(u64)]
pub enum Inner134 {
    I00([u64; 32]), I01, I02, I03, I04, I05, I06, I07, I08, I09, I0a, I0b, I0c, I0d, I0e, I0f,
    I10, I11, I12, I13, I14, I15, I16, I17, I18, I19, I1a, I1b, I1c, I1d, I1e, I1f,
    I20, I21, I22, I23, I24, I25, I26, I27, I28, I29, I2a, I2b, I2c, I2d, I2e, I2f,
    I30, I31, I32, I33, I34, I35, I36, I37, I38, I39, I3a, I3b, I3c, I3d, I3e, I3f,
    I40, I41, I42, I43, I44, I45, I46, I47, I48, I49, I4a, I4b, I4c, I4d, I4e, I4f,
    I50, I51, I52, I53, I54, I55, I56, I57, I58, I59, I5a, I5b, I5c, I5d, I5e, I5f,
    I60, I61, I62, I63, I64, I65, I66, I67, I68, I69, I6a, I6b, I6c, I6d, I6e, I6f,
    I70, I71, I72, I73, I74, I75, I76, I77, I78, I79, I7a, I7b, I7c, I7d, I7e, I7f,
    I80, I81, I82, I83, I84, I85,
}

#[repr(C)]
pub struct WrapperAct {
    pub pad: [u64; 2],
    pub count: usize,
    pub inner: Box<Action>,
}

pub enum Action {
    A86, A87,
    A88(OrderAction),
    A89(CancelAction),
    A8a(CancelAction),
    A8b, A8c, A8d, A8e, A8f, A90, A91,
    A92(SingleModifyAction),
    A93,
    A94(Vec<ModifyWire56>),
    A95, A96, A97, A98, A99,
    Inner(Inner134),
    A9b, A9c, A9d, A9e,
    A9f, Aa0, Aa1, Aa2, Aa3, Aa4, Aa5, Aa6, Aa7, Aa8, Aa9,
    Aaa(Flag55Action),
    Aab, Aac, Aad, Aae, Aaf, Ab0, Ab1, Ab2, Ab3, Ab4, Ab5, Ab6, Ab7, Ab8, Ab9,
    Aba(WrapperAct),
    Abb, Abc, Abd, Abe, Abf, Ac0, Ac1, Ac2, Ac3, Ac4, Ac5, Ac6, Ac7, Ac8, Ac9,
    Aca, Acb, Acc, Acd, Ace, Acf, Ad0, Ad1, Ad2, Ad3, Ad4, Ad5, Ad6, Ad7, Ad8, Ad9,
    Ada, Adb, Adc, Add, Ade, Adf, Ae0, Ae1,
}

#[inline(never)]
pub fn e2b_action_delay_priority(a: &Action) -> u8 {
    match a {
        Action::Aba(w) => e2b_action_delay_priority(&w.inner),
        Action::A86 | Action::A88(_) | Action::A89(_) | Action::A8a(_) | Action::A90
        | Action::A92(_) | Action::A94(_) | Action::A98 | Action::Aa2 | Action::Aa9
        | Action::Aaa(_) | Action::Aab | Action::Aac | Action::Aad | Action::Ace
        | Action::Ad0 | Action::Ad4 | Action::Ad5 | Action::Adf => 0,
        Action::A8d | Action::A93 | Action::Ab0 | Action::Ab1 | Action::Ab2 => 1,
        Action::A87 | Action::A8b | Action::A8c | Action::A8e | Action::A8f | Action::A91
        | Action::A95 | Action::A96 | Action::A97 | Action::A99 | Action::Inner(_) | Action::A9b
        | Action::A9c | Action::A9d | Action::A9e | Action::A9f | Action::Aa0 | Action::Aa1
        | Action::Aa3 | Action::Aa4 | Action::Aa5 | Action::Aa6 | Action::Aa7 | Action::Aa8
        | Action::Aae | Action::Aaf | Action::Ab3 | Action::Ab4 | Action::Ab5 | Action::Ab6
        | Action::Ab7 | Action::Ab8 | Action::Ab9 | Action::Abb | Action::Abc | Action::Abd
        | Action::Abe | Action::Abf | Action::Ac0 | Action::Ac1 | Action::Ac2 | Action::Ac3
        | Action::Ac4 | Action::Ac5 | Action::Ac6 | Action::Ac7 | Action::Ac8 | Action::Ac9
        | Action::Aca | Action::Acb | Action::Acc | Action::Acd | Action::Acf | Action::Ad1
        | Action::Ad2 | Action::Ad3 | Action::Ad6 | Action::Ad7 | Action::Ad8 | Action::Ad9
        | Action::Ada | Action::Adb | Action::Adc | Action::Add | Action::Ade | Action::Ae0
        | Action::Ae1 => 2,
    }
}

#[inline(never)]
pub fn e2b_action_is_not_exempt(a: &Action) -> bool {
    match a {
        Action::A87 | Action::A91 | Action::Aa3 | Action::Aa8 | Action::Aae
        | Action::Ab6 | Action::Ab7 | Action::Ab8 | Action::Ab9 | Action::Abb
        | Action::Abc | Action::Ac3 | Action::Ac4 | Action::Ac5 | Action::Acb
        | Action::Acf | Action::Ad1 | Action::Ad2 | Action::Ad3 | Action::Adb => false,
        Action::A86 | Action::A88(_) | Action::A89(_) | Action::A8a(_) | Action::A8b | Action::A8c
        | Action::A8d | Action::A8e | Action::A8f | Action::A90 | Action::A92(_) | Action::A93
        | Action::A94(_) | Action::A95 | Action::A96 | Action::A97 | Action::A98 | Action::A99
        | Action::Inner(_) | Action::A9b | Action::A9c | Action::A9d | Action::A9e | Action::A9f
        | Action::Aa0 | Action::Aa1 | Action::Aa2 | Action::Aa4 | Action::Aa5 | Action::Aa6
        | Action::Aa7 | Action::Aa9 | Action::Aaa(_) | Action::Aab | Action::Aac | Action::Aad
        | Action::Aaf | Action::Ab0 | Action::Ab1 | Action::Ab2 | Action::Ab3 | Action::Ab4
        | Action::Ab5 | Action::Aba(_) | Action::Abd | Action::Abe | Action::Abf | Action::Ac0
        | Action::Ac1 | Action::Ac2 | Action::Ac6 | Action::Ac7 | Action::Ac8 | Action::Ac9
        | Action::Aca | Action::Acc | Action::Acd | Action::Ace | Action::Ad0 | Action::Ad4
        | Action::Ad5 | Action::Ad6 | Action::Ad7 | Action::Ad8 | Action::Ad9 | Action::Ada
        | Action::Adc | Action::Add | Action::Ade | Action::Adf | Action::Ae0 | Action::Ae1 => true,
    }
}

#[inline(never)]
pub fn local_batch_alo(it: &mut std::slice::Iter<'_, ModifyWire56>) -> bool {
    black_box(it);
    black_box(false)
}

#[inline(never)]
pub fn e2b_action_is_alo_only(a: &Action) -> bool {
    match a {
        Action::Aba(w) => e2b_action_is_alo_only(&w.inner),
        Action::A88(oa) => ext_order_is_alo_only(oa),
        Action::A92(m) => ((m.f21 ^ 2) | m.f18) == 0,
        Action::A94(v) => {
            let mut it = v.iter();
            local_batch_alo(&mut it)
        }
        Action::A86 | Action::A87 | Action::A89(_) | Action::A8a(_) | Action::A8b | Action::A8c
        | Action::A8d | Action::A8e | Action::A8f | Action::A90 | Action::A91 | Action::A93
        | Action::A95 | Action::A96 | Action::A97 | Action::A98 | Action::A99 | Action::Inner(_)
        | Action::A9b | Action::A9c | Action::A9d | Action::A9e | Action::A9f | Action::Aa0
        | Action::Aa1 | Action::Aa2 | Action::Aa3 | Action::Aa4 | Action::Aa5 | Action::Aa6
        | Action::Aa7 | Action::Aa8 | Action::Aa9 | Action::Aaa(_) | Action::Aab | Action::Aac
        | Action::Aad | Action::Aae | Action::Aaf | Action::Ab0 | Action::Ab1 | Action::Ab2
        | Action::Ab3 | Action::Ab4 | Action::Ab5 | Action::Ab6 | Action::Ab7 | Action::Ab8
        | Action::Ab9 | Action::Abb | Action::Abc | Action::Abd | Action::Abe | Action::Abf
        | Action::Ac0 | Action::Ac1 | Action::Ac2 | Action::Ac3 | Action::Ac4 | Action::Ac5
        | Action::Ac6 | Action::Ac7 | Action::Ac8 | Action::Ac9 | Action::Aca | Action::Acb
        | Action::Acc | Action::Acd | Action::Ace | Action::Acf | Action::Ad0 | Action::Ad1
        | Action::Ad2 | Action::Ad3 | Action::Ad4 | Action::Ad5 | Action::Ad6 | Action::Ad7
        | Action::Ad8 | Action::Ad9 | Action::Ada | Action::Adb | Action::Adc | Action::Add
        | Action::Ade | Action::Adf | Action::Ae0 | Action::Ae1 => false,
    }
}

#[repr(C)]
pub struct BatchModifyAction {
    pub modifies: Vec<ModifyWire56>,
    pub pad: [u8; 0x38],
    pub grouping_tag: u32,
    pub grouping_val: u32,
}

#[inline(never)]
pub fn local_batch_modify_delay_inner(
    cfg: &DelayConfig,
    group_val: u32,
    it: std::slice::Iter<'_, ModifyWire56>,
) -> Result<f64, ActionError> {
    black_box((cfg, group_val, it));
    if black_box(false) {
        Err(ActionError::Kind0(ErrPayload96([black_box(1); 12])))
    } else {
        Ok(black_box(0.0))
    }
}

#[inline(never)]
pub fn e2b_batch_modify_delay_secs(
    b: &BatchModifyAction,
    cfg: &DelayConfig,
) -> Result<f64, ActionError> {
    let group_val = if b.grouping_tag == 3 { b.grouping_val } else { 0 };
    local_batch_modify_delay_inner(cfg, group_val, b.modifies.iter())
}

fn main() {
    let orders = black_box(Vec::<HlOrder>::new());
    let n = black_box(3usize);
    let px = black_box(10u64);
    let f_hl: fn(&HlFundingArgs<'_>) -> Option<u64> = e2b_hyperliquidity_funding_cost;
    let _ = black_box(black_box(f_hl)(&HlFundingArgs {
        orders: &orders,
        n_levels: &n,
        px: &px,
    }));

    let f_ce: fn(Chain) -> &'static ChainCfg = e2b_chain_ext_config;
    let _ = black_box(black_box(f_ce)(black_box(Chain::Mainnet)));

    let f_eb: fn(&[u8; 20]) -> bool = e2b_nonce_set_expanded_set_b;
    let f_ea: fn(&[u8; 20]) -> bool = e2b_nonce_set_expanded_set_a;
    let _ = black_box((black_box(f_eb)(black_box(&[0; 20])), black_box(f_ea)(black_box(&[0; 20]))));

    let mut ctx = black_box(0u64);
    let mut out_tag: Option<[u64; 2]> = black_box(Some([1, 2]));
    let _ = black_box(inner_transfer_opt2(
        &mut ctx,
        black_box(&[1; 20]),
        black_box(1),
        black_box(2),
        &mut out_tag,
        black_box(&WireAddr([2; 20])),
        black_box(&3),
        Location::caller(),
    ));
    let f_w3: fn(&u64, &WireAddr, &mut u64) -> ActionResultWrap = e2b_withdraw3_or_vault_transfer_send;
    let _ = black_box(black_box(f_w3)(black_box(&1), black_box(&WireAddr([0; 20])), &mut ctx));

    let act = black_box(Action::A86);
    let mut dummy_slice = black_box(Vec::<ModifyWire56>::new());
    let mut dummy_it = dummy_slice.iter();
    let f_ba: fn(&mut std::slice::Iter<'_, ModifyWire56>) -> bool = local_batch_alo;
    let _ = black_box(black_box(f_ba)(&mut dummy_it));
    let _ = black_box(&mut dummy_slice);

    let f_dp: fn(&Action) -> u8 = e2b_action_delay_priority;
    let f_ne: fn(&Action) -> bool = e2b_action_is_not_exempt;
    let f_ao: fn(&Action) -> bool = e2b_action_is_alo_only;
    let _ = black_box((black_box(f_dp)(&act), black_box(f_ne)(&act), black_box(f_ao)(&act)));

    let cfg = black_box(DelayConfig { pad: [0; 5], default_delay: 1.0 });
    let bm = black_box(BatchModifyAction {
        modifies: Vec::new(),
        pad: [0; 0x38],
        grouping_tag: 0,
        grouping_val: 0,
    });
    let f_bmi: fn(&DelayConfig, u32, std::slice::Iter<'_, ModifyWire56>) -> Result<f64, ActionError> =
        local_batch_modify_delay_inner;
    let _ = black_box(black_box(f_bmi)(&cfg, black_box(7), bm.modifies.iter()));
    let f_bm: fn(&BatchModifyAction, &DelayConfig) -> Result<f64, ActionError> =
        e2b_batch_modify_delay_secs;
    let _ = black_box(black_box(f_bm)(&bm, &cfg));
}
