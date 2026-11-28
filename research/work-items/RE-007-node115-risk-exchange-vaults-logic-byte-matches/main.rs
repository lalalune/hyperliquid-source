#![forbid(unsafe_code)]
#![allow(dead_code, unused_variables, clippy::all)]

use std::collections::{BTreeMap, VecDeque};
use std::hint::black_box;
use std::sync::LazyLock;

// ==================== 1 & 2. VAULTS: SubAccountTracker (l1/src/sub_account.rs) ====================
#[repr(C)]
pub struct MapEntry {
    pub hash: u64,
    pub key: [u8; 20],
    pub val: [u8; 20],
}

#[repr(C)]
pub struct SafeTracker {
    pub _pad: [u64; 9],
    pub entries: Vec<MapEntry>,
    pub _pad2: [u64; 4],
    pub seed0: u64,
    pub seed1: u64,
}

#[inline(never)]
fn hash_user(s0: u64, s1: u64, u: &[u8; 20]) -> u64 {
    black_box((s0, s1, u));
    black_box(0)
}

#[inline(never)]
fn safe_map_find(entries: &Vec<MapEntry>, h: u64, u: &[u8; 20]) -> Option<usize> {
    black_box((entries, h, u));
    black_box(None)
}

// 0x366b040..0x366b0c6 (134 B): SubAccountTracker::is_sub_account
#[inline(never)]
pub fn vault_is_sub_account_134(t: &SafeTracker, user: &[u8; 20]) -> bool {
    match t.entries.len() {
        0 => false,
        1 => *user == t.entries[0].key,
        _ => {
            let h = hash_user(t.seed0, t.seed1, user);
            safe_map_find(&t.entries, h, user).is_some()
        }
    }
}

#[inline(always)]
fn get_index_of(t: &SafeTracker, user: &[u8; 20]) -> Option<usize> {
    match t.entries.len() {
        0 => None,
        1 => (*user == t.entries[0].key).then_some(0),
        _ => {
            let h = hash_user(t.seed0, t.seed1, user);
            safe_map_find(&t.entries, h, user)
        }
    }
}

// 0x366af60..0x366b035 (213 B): SubAccountTracker::master_lookup
#[inline(never)]
pub fn vault_master_lookup_213(t: &SafeTracker, user: &[u8; 20]) -> Option<[u8; 20]> {
    get_index_of(t, user).map(|idx| t.entries[idx].val)
}

// ==================== 3 & 4. RISK: Clearinghouse rate scalers (l1/src/clearinghouse/clearinghouse.rs) ====================
#[repr(C)]
pub struct ClearinghouseRate {
    pub _pad: [u64; 0x4e0 / 8],
    pub rate: f64,
}

// 0x44811d0..0x44812b0 (224 B): Clearinghouse::scale_u64_by_rate
#[inline(never)]
pub fn risk_ch_scale_u64_rate_224(h: &ClearinghouseRate, val: u64) -> u64 {
    if val > (u64::MAX / 100) {
        return val;
    }
    let v = (val as f64) * h.rate;
    let min = i64::MIN as f64;
    let max = (i64::MAX as f64).next_down();
    let c = if !v.is_finite() {
        0.0
    } else if v < min || v > max {
        v.clamp(min, max)
    } else {
        v
    };
    let i = c as i64;
    let i = if i.abs() > 0x147ae147ae147ae_i64 {
        i.clamp(-0x147ae147ae147ae_i64, 0x147ae147ae147ae_i64)
    } else {
        i
    };
    if i > 0 { i as u64 } else { 0 }
}

// 0x44812b0..0x4481374 (196 B): Clearinghouse::scale_i64_by_rate
#[inline(never)]
pub fn risk_ch_scale_i64_rate_196(h: &ClearinghouseRate, val: i64) -> i64 {
    let v = (val as f64) * h.rate;
    let min = i64::MIN as f64;
    let max = (i64::MAX as f64).next_down();
    let c = if !v.is_finite() {
        0.0
    } else if v < min || v > max {
        v.clamp(min, max)
    } else {
        v
    };
    let i = c as i64;
    if i.abs() > 0x147ae147ae147ae_i64 {
        i.clamp(-0x147ae147ae147ae_i64, 0x147ae147ae147ae_i64)
    } else {
        i
    }
}

// ==================== SHARED L1Err (418 variants, Ok niche = 0x1a2) ====================
#[repr(u16)]
pub enum L1Err {
    Pad([u128; 6]) = 0,
    V1 = 1, V2 = 2, V3 = 3, V4 = 4, V5 = 5, V6 = 6, V7 = 7, V8 = 8, V9 = 9,
    V10 = 10, V11 = 11, V12 = 12, V13 = 13, V14 = 14, V15 = 15, V16 = 16, V17 = 17, V18 = 18, V19 = 19,
    V20 = 20, V21 = 21, V22 = 22, V23 = 23, V24 = 24, V25 = 25, V26 = 26, V27 = 27, V28 = 28, V29 = 29,
    V30 = 30, V31 = 31, V32 = 32, V33 = 33, V34 = 34, V35 = 35, V36 = 36, V37 = 37, V38 = 38, V39 = 39,
    V40 = 40, V41 = 41, V42 = 42, V43 = 43, V44 = 44, V45 = 45, V46 = 46, V47 = 47, V48 = 48, V49 = 49,
    V50 = 50, V51 = 51, V52 = 52, V53 = 53, V54 = 54, V55 = 55, V56 = 56, V57 = 57, V58 = 58, V59 = 59,
    V60 = 60, V61 = 61, V62 = 62, V63 = 63, V64 = 64, V65 = 65, V66 = 66, V67 = 67, V68 = 68, V69 = 69,
    V70 = 70, V71 = 71, V72 = 72, V73 = 73, V74 = 74, V75 = 75, V76 = 76, V77 = 77, V78 = 78, V79 = 79,
    V80 = 80, V81 = 81, V82 = 82, V83 = 83, V84 = 84, V85 = 85, V86 = 86, V87 = 87, V88 = 88, V89 = 89,
    V90 = 90, V91 = 91, V92 = 92, V93 = 93, V94 = 94, V95 = 95, V96 = 96, V97 = 97, V98 = 98,
    OracleDev(f64) = 0x63,
    V100 = 100, V101 = 101, V102 = 102, V103 = 103, V104 = 104, V105 = 105, V106 = 106, V107 = 107, V108 = 108, V109 = 109,
    V110 = 110, V111 = 111, V112 = 112, V113 = 113, V114 = 114, V115 = 115, V116 = 116, V117 = 117, V118 = 118, V119 = 119,
    V120 = 120, V121 = 121, V122 = 122, V123 = 123, V124 = 124, V125 = 125, V126 = 126, V127 = 127, V128 = 128, V129 = 129,
    V130 = 130, V131 = 131, V132 = 132, V133 = 133, V134 = 134, V135 = 135, V136 = 136, V137 = 137, V138 = 138, V139 = 139,
    V140 = 140, V141 = 141, V142 = 142, V143 = 143, V144 = 144, V145 = 145, V146 = 146, V147 = 147, V148 = 148, V149 = 149,
    V150 = 150, V151 = 151, V152 = 152, V153 = 153, V154 = 154, V155 = 155, V156 = 156, V157 = 157, V158 = 158, V159 = 159,
    V160 = 160, V161 = 161, V162 = 162, V163 = 163, V164 = 164, V165 = 165, V166 = 166, V167 = 167, V168 = 168, V169 = 169,
    V170 = 170, V171 = 171, V172 = 172, V173 = 173, V174 = 174, V175 = 175, V176 = 176, V177 = 177, V178 = 178, V179 = 179,
    V180 = 180, V181 = 181, V182 = 182, V183 = 183, V184 = 184, V185 = 185, V186 = 186, V187 = 187, V188 = 188, V189 = 189,
    V190 = 190, V191 = 191, V192 = 192, V193 = 193, V194 = 194, V195 = 195, V196 = 196, V197 = 197, V198 = 198, V199 = 199,
    V200 = 200, V201 = 201, V202 = 202, V203 = 203, V204 = 204, V205 = 205, V206 = 206, V207 = 207, V208 = 208, V209 = 209,
    V210 = 210, V211 = 211, V212 = 212, V213 = 213, V214 = 214, V215 = 215, V216 = 216, V217 = 217, V218 = 218, V219 = 219,
    V220 = 220, V221 = 221, V222 = 222, V223 = 223, V224 = 224, V225 = 225, V226 = 226, V227 = 227, V228 = 228, V229 = 229,
    V230 = 230, V231 = 231, V232 = 232, V233 = 233, V234 = 234, V235 = 235, V236 = 236, V237 = 237, V238 = 238, V239 = 239,
    V240 = 240, V241 = 241, V242 = 242, V243 = 243, V244 = 244, V245 = 245, V246 = 246, V247 = 247, V248 = 248,
    Msg(&'static str) = 0xf9,
    BadTok = 0xfa,
    V251 = 251, V252 = 252, V253 = 253, V254 = 254, V255 = 255, V256 = 256, V257 = 257, V258 = 258, V259 = 259,
    V260 = 260, V261 = 261, V262 = 262, V263 = 263, V264 = 264, V265 = 265, V266 = 266, V267 = 267, V268 = 268, V269 = 269,
    V270 = 270, V271 = 271, V272 = 272, V273 = 273, V274 = 274, V275 = 275, V276 = 276, V277 = 277, V278 = 278, V279 = 279,
    V280 = 280, V281 = 281, V282 = 282, V283 = 283, V284 = 284, V285 = 285, V286 = 286, V287 = 287, V288 = 288, V289 = 289,
    V290 = 290, V291 = 291, V292 = 292, V293 = 293, V294 = 294, V295 = 295, V296 = 296, V297 = 297, V298 = 298, V299 = 299,
    V300 = 300, V301 = 301, V302 = 302, V303 = 303, V304 = 304, V305 = 305, V306 = 306, V307 = 307, V308 = 308, V309 = 309,
    V310 = 310, V311 = 311, V312 = 312, V313 = 313, V314 = 314, V315 = 315, V316 = 316, V317 = 317, V318 = 318, V319 = 319,
    V320 = 320, V321 = 321, V322 = 322, V323 = 323, V324 = 324, V325 = 325, V326 = 326, V327 = 327, V328 = 328, V329 = 329,
    V330 = 330, V331 = 331, V332 = 332, V333 = 333, V334 = 334, V335 = 335, V336 = 336, V337 = 337, V338 = 338, V339 = 339,
    V340 = 340, V341 = 341, V342 = 342, V343 = 343, V344 = 344, V345 = 345, V346 = 346, V347 = 347, V348 = 348, V349 = 349,
    V350 = 350, V351 = 351, V352 = 352, V353 = 353, V354 = 354, V355 = 355, V356 = 356, V357 = 357, V358 = 358, V359 = 359,
    V360 = 360, V361 = 361, V362 = 362, V363 = 363, V364 = 364, V365 = 365, V366 = 366, V367 = 367, V368 = 368, V369 = 369,
    V370 = 370, V371 = 371, V372 = 372, V373 = 373, V374 = 374, V375 = 375, V376 = 376, V377 = 377, V378 = 378, V379 = 379,
    V380 = 380, V381 = 381, V382 = 382, V383 = 383, V384 = 384, V385 = 385, V386 = 386, V387 = 387, V388 = 388, V389 = 389,
    V390 = 390, V391 = 391, V392 = 392, V393 = 393, V394 = 394, V395 = 395, V396 = 396, V397 = 397, V398 = 398, V399 = 399,
    V400 = 400, V401 = 401, V402 = 402, V403 = 403, V404 = 404, V405 = 405, V406 = 406, V407 = 407, V408 = 408, V409 = 409,
    V410 = 410, V411 = 411, V412 = 412, V413 = 413, V414 = 414, V415 = 415, V416 = 416, V417 = 417,
}

// ==================== 5..10. RISK: SpotClearinghouse & Clearinghouse ====================
pub enum SmallMap<K, V> {
    Small(VecDeque<(K, V)>),
    Large(BTreeMap<K, V>),
}

impl<K: Ord, V> SmallMap<K, V> {
    #[inline(always)]
    fn contains_with(&self, k: &K, bsearch: fn(&VecDeque<(K, V)>, &K) -> Result<usize, usize>) -> bool {
        match self {
            SmallMap::Small(vd) => bsearch(vd, k).is_ok(),
            SmallMap::Large(bm) => bm.contains_key(k),
        }
    }
}

#[inline(never)]
fn vd_bsearch_u64(vd: &VecDeque<(usize, u64)>, k: &usize) -> Result<usize, usize> {
    black_box((vd, k));
    black_box(Err(0))
}

#[repr(C)]
pub struct SpotChGenesis {
    pub _pad0: [u8; 0x38],
    pub n_tokens: usize,
    pub _pad1: [u8; 0x510 - 0x40],
    pub genesis: SmallMap<usize, u64>,
}

// 0x3bfa810..0x3bfa90d (253 B): SpotClearinghouse::validate_token_before_genesis
#[inline(never)]
pub fn risk_validate_token_before_genesis_253(sc: &SpotChGenesis, token: usize) -> Result<usize, L1Err> {
    if token >= sc.n_tokens {
        return Err(L1Err::BadTok);
    }
    let tok = token;
    if tok == 0 || sc.genesis.contains_with(&tok, vd_bsearch_u64) {
        return Err(L1Err::Msg("genesis already happened"));
    }
    Ok(tok)
}

#[repr(C)]
pub struct SpotUserEntry {
    pub _p0: [u8; 0x58],
    pub key: [u8; 20],
    pub _p1: [u8; 4],
}

#[repr(C)]
pub struct SpotChUsers {
    pub _pad0: [u8; 0x370],
    pub entries: Vec<SpotUserEntry>,
    pub table: [u64; 4],
    pub seed0: u64,
    pub seed1: u64,
}

#[inline(never)]
fn table_find_ref<'a>(
    table: &'a [u64; 4],
    h: u64,
    pred: &(&[u8; 20], &[SpotUserEntry]),
) -> Option<&'a usize> {
    black_box((table, h, pred));
    black_box(None)
}

// 0x3bfcf60..0x3bfd012 (178 B): SpotClearinghouse::has_user_state
#[inline(never)]
pub fn risk_spot_has_user_state_178(sc: &SpotChUsers, user: &[u8; 20]) -> bool {
    match sc.entries.len() {
        0 => false,
        1 => *user == sc.entries[0].key,
        _ => {
            let h = hash_user(sc.seed0, sc.seed1, user);
            let pred = (user, sc.entries.as_slice());
            table_find_ref(&sc.table, h, &pred).is_some()
        }
    }
}

#[repr(u8)]
pub enum BalRes {
    Ok(u64) = 0,
    Err1(u8, u8, u8) = 1,
    Err2 = 2,
}

#[repr(u8)]
pub enum SpotChkErr {
    E0 = 0, E1 = 1, E2 = 2, E3 = 3, E4 = 4, E5 = 5, E6 = 6, E7 = 7,
    Eight = 8,
    Nine = 9,
}

#[inline(never)]
fn get_bal_sret(sc: &SpotChUsers, user: &[u8; 20], is_b: bool) -> BalRes {
    black_box((sc, user, is_b));
    black_box(BalRes::Err2)
}

// 0x3bf48e0..0x3bf4948 (104 B): SpotClearinghouse::check_zero_balances
#[inline(never)]
pub fn risk_spot_check_zero_balances_104(sc: &SpotChUsers, user: &[u8; 20]) -> Result<(), SpotChkErr> {
    let a = match get_bal_sret(sc, user, false) {
        BalRes::Ok(v) => v,
        _ => return Err(SpotChkErr::Eight),
    };
    if a != 0 {
        return Err(SpotChkErr::Nine);
    }
    let b = match get_bal_sret(sc, user, true) {
        BalRes::Ok(v) => v,
        _ => return Err(SpotChkErr::Eight),
    };
    if b != 0 {
        Err(SpotChkErr::Nine)
    } else {
        Ok(())
    }
}

#[repr(C)]
pub struct SpotUserState80 {
    pub data: [u64; 10],
}

impl Default for SpotUserState80 {
    #[inline(never)]
    fn default() -> Self {
        black_box(Self { data: [0; 10] })
    }
}

#[repr(C)]
pub struct SpotChUS {
    pub _pad0: [u8; 0x370],
    pub user_states: u64,
}

#[inline(never)]
fn get_spot_us<'a>(us: &'a u64, user: &[u8; 20]) -> Option<&'a SpotUserState80> {
    black_box((us, user));
    black_box(None)
}

static EMPTY_SPOT_US: LazyLock<SpotUserState80> = LazyLock::new(SpotUserState80::default);

// 0x3bf4c30..0x3bf4ca2 (114 B): SpotClearinghouse::user_state
#[inline(never)]
pub fn risk_spot_user_state_114<'a>(sc: &'a SpotChUS, user: &[u8; 20]) -> &'a SpotUserState80 {
    get_spot_us(&sc.user_states, user).unwrap_or(&EMPTY_SPOT_US)
}

static LOC_SAT: u8 = 0;

#[repr(C)]
pub struct SpotChBurn {
    pub head: u64,
    pub _pad: [u8; 0x530 - 8],
    pub burned_map: u64,
}

#[repr(C)]
pub struct MapEntry48 {
    pub data: [u64; 6],
}

#[inline(never)]
fn decrease_token_balance(sc: &mut SpotChBurn, user: &[u8; 20], token: usize, flag: bool, wei: u64, meta: &u64) {
    black_box((sc, user, token, flag, wei, meta));
}

#[inline(never)]
fn map_entry_48(m: &mut u64, token: usize) -> MapEntry48 {
    black_box((m, token));
    black_box(MapEntry48 { data: [0; 6] })
}

#[inline(never)]
fn entry_or_default<'a>(e: &'a mut MapEntry48) -> &'a mut u64 {
    black_box(&mut e.data[0])
}

#[inline(always)]
fn sat_add_log(a: u64, b: u64) -> u64 {
    match a.checked_add(b) {
        Some(v) => v,
        None => {
            stubs::bug_log(0, &LOC_SAT);
            a.saturating_add(b)
        }
    }
}

// 0x3bfa340..0x3bfa3f4 (180 B): SpotClearinghouse::burn_user_token
#[inline(never)]
pub fn risk_spot_burn_user_token_180(
    sc: &mut SpotChBurn,
    user: &[u8; 20],
    token: usize,
    wei: u64,
    meta: &u64,
) -> bool {
    if wei != 0 {
        if !stubs::can_hold_token(&sc.head, user, token, wei) {
            return false;
        }
        decrease_token_balance(sc, user, token, true, wei, meta);
    }
    let mut entry = map_entry_48(&mut sc.burned_map, token);
    let slot = entry_or_default(&mut entry);
    *slot = sat_add_log(*slot, wei);
    true
}

// 0x4488300..0x44883e3 (227 B): Clearinghouse::check_oracle_price_deviation
#[inline(never)]
pub fn risk_check_oracle_price_deviation_227(
    _a: usize,
    _b: usize,
    ctx: &u64,
    px_a: u64,
    px_b: u64,
    max_dev: f64,
) -> Result<(), L1Err> {
    if stubs::bypass_oracle_check(ctx) {
        return Ok(());
    }
    let diff = (px_a as f64) / (px_b as f64) - 1.0;
    if diff.abs() < max_dev {
        return Ok(());
    }
    if max_dev < 1.0 && diff > 0.0 && 1.0 / (1.0 - max_dev) - 1.0 >= diff {
        return Ok(());
    }
    Err(L1Err::OracleDev(max_dev * 100.0))
}

fn main() {
    black_box(hash_user as fn(u64, u64, &[u8; 20]) -> u64);
    black_box(safe_map_find as fn(&Vec<MapEntry>, u64, &[u8; 20]) -> Option<usize>);
    black_box(vd_bsearch_u64 as fn(&VecDeque<(usize, u64)>, &usize) -> Result<usize, usize>);
    black_box(table_find_ref as for<'a> fn(&'a [u64; 4], u64, &(&[u8; 20], &[SpotUserEntry])) -> Option<&'a usize>);
    black_box(get_bal_sret as fn(&SpotChUsers, &[u8; 20], bool) -> BalRes);
    black_box(get_spot_us as for<'a> fn(&'a u64, &[u8; 20]) -> Option<&'a SpotUserState80>);
    black_box(decrease_token_balance as fn(&mut SpotChBurn, &[u8; 20], usize, bool, u64, &u64));
    black_box(map_entry_48 as fn(&mut u64, usize) -> MapEntry48);
    black_box(entry_or_default as for<'a> fn(&'a mut MapEntry48) -> &'a mut u64);

    black_box(vault_master_lookup_213 as fn(&SafeTracker, &[u8; 20]) -> Option<[u8; 20]>);
    black_box(vault_is_sub_account_134 as fn(&SafeTracker, &[u8; 20]) -> bool);
    black_box(risk_ch_scale_u64_rate_224 as fn(&ClearinghouseRate, u64) -> u64);
    black_box(risk_ch_scale_i64_rate_196 as fn(&ClearinghouseRate, i64) -> i64);
    black_box(risk_spot_check_zero_balances_104 as fn(&SpotChUsers, &[u8; 20]) -> Result<(), SpotChkErr>);
    black_box(risk_spot_user_state_114 as for<'a> fn(&'a SpotChUS, &[u8; 20]) -> &'a SpotUserState80);
    black_box(risk_spot_burn_user_token_180 as fn(&mut SpotChBurn, &[u8; 20], usize, u64, &u64) -> bool);
    black_box(risk_validate_token_before_genesis_253 as fn(&SpotChGenesis, usize) -> Result<usize, L1Err>);
    black_box(risk_spot_has_user_state_178 as fn(&SpotChUsers, &[u8; 20]) -> bool);
    black_box(risk_check_oracle_price_deviation_227 as fn(usize, usize, &u64, u64, u64, f64) -> Result<(), L1Err>);
}
