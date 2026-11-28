#![forbid(unsafe_code)]

use core::hint::black_box;

#[inline(never)]
pub fn bypass_oracle_check(ctx: &u64) -> bool {
    black_box(*ctx != 0)
}

#[inline(never)]
pub fn bug_log(code: u32, loc: &'static u8) {
    black_box((code, loc));
}

#[inline(never)]
pub fn can_hold_token(sc: &u64, user: &[u8; 20], token: usize, wei: u64) -> bool {
    black_box((sc, user, token, wei));
    black_box(false)
}
