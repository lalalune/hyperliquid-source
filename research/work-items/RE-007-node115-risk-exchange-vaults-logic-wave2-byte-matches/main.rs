#![forbid(unsafe_code)]
#![allow(dead_code, unused_variables, clippy::all)]

use std::collections::{BTreeMap, VecDeque};
use std::hint::black_box;

pub enum SmallMap<K, V> {
    Small(VecDeque<(K, V)>),
    Large(BTreeMap<K, V>),
}

impl<K: Ord, V> SmallMap<K, V> {
    #[inline(always)]
    fn get_with(
        &self,
        k: &K,
        bsearch: fn(&VecDeque<(K, V)>, &K) -> Result<usize, usize>,
    ) -> Option<&V> {
        match self {
            SmallMap::Small(vd) => bsearch(vd, k)
                .ok()
                .and_then(|idx| vd.get(idx))
                .map(|(_, v)| v),
            SmallMap::Large(bm) => bm.get(k),
        }
    }

    #[inline(always)]
    fn get_mut_with(
        &mut self,
        k: &K,
        bsearch: fn(&VecDeque<(K, V)>, &K) -> Result<usize, usize>,
    ) -> Option<&mut V> {
        match self {
            SmallMap::Small(vd) => bsearch(vd, k)
                .ok()
                .and_then(|idx| vd.get_mut(idx))
                .map(|(_, v)| v),
            SmallMap::Large(bm) => bm.get_mut(k),
        }
    }
}

// ==================== 1. risk: BoleUserState::leg_shares (0x3692f30..0x3693028, 248 B) ====================
#[repr(C)]
pub struct BoleLegState32 {
    pub legs: [(u64, u64); 2],
}

#[inline(never)]
fn vd_bsearch_leg32(vd: &VecDeque<(usize, BoleLegState32)>, k: &usize) -> Result<usize, usize> {
    black_box((vd, k));
    black_box(Err(0))
}

#[inline(never)]
pub fn risk_bole_leg_shares_248(
    map: &SmallMap<usize, BoleLegState32>,
    token: usize,
    is_borrow: bool,
) -> u64 {
    map.get_with(&token, vd_bsearch_leg32)
        .map_or(0, |st| st.legs[(!is_borrow) as usize].1)
}

// ==================== 2. risk: SpotUserState::balance (0x3c00800..0x3c008fd, 253 B) ====================
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct Balance24 {
    pub total: u64,
    pub hold: u64,
    pub entry_ntl: u64,
}

#[inline(never)]
fn vd_bsearch_bal24(vd: &VecDeque<(usize, Balance24)>, k: &usize) -> Result<usize, usize> {
    black_box((vd, k));
    black_box(Err(0))
}

#[inline(never)]
pub fn risk_spot_user_balance_253(
    balances: &SmallMap<usize, Balance24>,
    token: usize,
) -> Balance24 {
    balances
        .get_with(&token, vd_bsearch_bal24)
        .copied()
        .unwrap_or_default()
}

// ==================== 3. risk: Clearinghouse::user_field48 (0x447e7c0..0x447e804, 68 B) ====================
#[repr(C)]
pub struct UserSt48 {
    pub _p0: [u8; 0x48],
    pub field48: u64,
}

#[repr(C)]
pub struct ChA8 {
    pub _p0: [u8; 0xa8],
    pub user_states: u64,
}

#[inline(never)]
fn get_user_state_a8<'a>(us: &'a u64, user: &[u8; 20]) -> Option<&'a UserSt48> {
    black_box((us, user));
    black_box(None)
}

#[inline(never)]
pub fn risk_ch_user_field48_68(ch: &ChA8, user: &[u8; 20]) -> u64 {
    if stubs::is_special_user(user) {
        return 0;
    }
    get_user_state_a8(&ch.user_states, user).map_or(0, |u| u.field48)
}

// ==================== 4-6. exchange: Exchange<A>::spot_deploy_set_token_annotation (3x 335 B) ====================
// Targets: 0x2c543a0..0x2c544ef, 0x55c61c0..0x55c630f, 0x55c6310..0x55c645f
#[repr(C)]
pub struct ExchSpotDeployAnnot {
    pub _p0: [u8; 0x60],
    pub time_60: u64,
    pub _p1: [u8; 0x28],
    pub spot_ch_90: u64,
}

#[inline(never)]
pub fn exch_spot_deploy_set_token_annotation_335(
    ex: &mut ExchSpotDeployAnnot,
    token: u64,
    req: u64,
) -> Result<(), stubs::L1Err> {
    let payload = stubs::validate_token_annotation(req, &ex.time_60)?;
    stubs::apply_token_annotation(&mut ex.spot_ch_90, token, payload)
}

// ==================== 7-9. exchange: Exchange<A>::spot_deploy_set_deploy_state_flag (3x 293 B) ====================
// Targets: 0x2c56810..0x2c56935, 0x55cabc0..0x55cace5, 0x55cacf0..0x55cae15
#[repr(C)]
pub struct DeployState160 {
    pub _p0: [u8; 0x98],
    pub flag: bool,
    pub _p1: [u8; 0xa0 - 0x99],
}

#[repr(C)]
pub struct ExchSpotDeployFlag {
    pub _p0: [u8; 0x398],
    pub deploy_states: SmallMap<usize, DeployState160>,
}

#[inline(never)]
fn vd_bsearch_dep160(vd: &VecDeque<(usize, DeployState160)>, k: &usize) -> Result<usize, usize> {
    black_box((vd, k));
    black_box(Err(0))
}

#[inline(never)]
pub fn exch_spot_deploy_set_deploy_state_flag_293(
    ex: &mut ExchSpotDeployFlag,
    token: usize,
    val: bool,
) -> Result<(), stubs::L1Err> {
    let st = ex
        .deploy_states
        .get_mut_with(&token, vd_bsearch_dep160)
        .ok_or(stubs::L1Err::Tag101)?;
    st.flag = val;
    Ok(())
}

// ==================== 10-11. exchange: Exchange<A>::counted_exchange_entry_dispatch (2x 233 B) ====================
// Targets: 0x2c766e0..0x2c767c9, 0x560dca0..0x560dd89
#[repr(C)]
pub struct ExchCountedDispatch {
    pub _p0: [u8; 0x60],
    pub time_60: stubs::Time12,
    pub _p1: [u8; 0xb40 - 0x6c],
    pub attempts_b40: u64,
    pub successes_b48: u64,
    pub _p2: [u8; 0x3af0 - 0xb50],
    pub entries_3af0: u64,
}

#[inline(never)]
pub fn exch_counted_exchange_entry_dispatch_233(
    ex: &mut ExchCountedDispatch,
    arg3: u64,
    key: u64,
    arg5: u64,
) -> Result<(), stubs::L1Err> {
    ex.attempts_b40 = ex.attempts_b40.saturating_add(1);
    let handle = stubs::lookup_exchange_entry(&mut ex.entries_3af0, key);
    stubs::dispatch_exchange_entry(handle, ex.time_60, arg3, arg5, false)?;
    ex.successes_b48 = ex.successes_b48.saturating_add(1);
    Ok(())
}

fn main() {
    black_box(vd_bsearch_leg32 as fn(&VecDeque<(usize, BoleLegState32)>, &usize) -> Result<usize, usize>);
    black_box(vd_bsearch_bal24 as fn(&VecDeque<(usize, Balance24)>, &usize) -> Result<usize, usize>);
    black_box(vd_bsearch_dep160 as fn(&VecDeque<(usize, DeployState160)>, &usize) -> Result<usize, usize>);
    black_box(get_user_state_a8 as for<'a> fn(&'a u64, &[u8; 20]) -> Option<&'a UserSt48>);

    black_box(risk_bole_leg_shares_248 as fn(&SmallMap<usize, BoleLegState32>, usize, bool) -> u64);
    black_box(risk_spot_user_balance_253 as fn(&SmallMap<usize, Balance24>, usize) -> Balance24);
    black_box(risk_ch_user_field48_68 as fn(&ChA8, &[u8; 20]) -> u64);
    black_box(
        exch_spot_deploy_set_token_annotation_335
            as fn(&mut ExchSpotDeployAnnot, u64, u64) -> Result<(), stubs::L1Err>,
    );
    black_box(
        exch_spot_deploy_set_deploy_state_flag_293
            as fn(&mut ExchSpotDeployFlag, usize, bool) -> Result<(), stubs::L1Err>,
    );
    black_box(
        exch_counted_exchange_entry_dispatch_233
            as fn(&mut ExchCountedDispatch, u64, u64, u64) -> Result<(), stubs::L1Err>,
    );
}
