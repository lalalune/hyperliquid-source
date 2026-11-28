#![forbid(unsafe_code)]

use core::hint::black_box;

#[repr(u16)]
pub enum L1Err {
    Pad([u128; 6]) = 0,
    Tag101 = 0x101,
    Tag1a1 = 0x1a1,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Time12 {
    pub a: i32,
    pub b: u32,
    pub c: u32,
}

#[repr(C)]
pub struct AnnotationPayload112 {
    pub data: [u64; 14],
}

#[inline(never)]
pub fn is_special_user(user: &[u8; 20]) -> bool {
    black_box(user);
    black_box(false)
}

#[inline(never)]
pub fn validate_token_annotation(arg: u64, time: &u64) -> Result<AnnotationPayload112, L1Err> {
    black_box((arg, time));
    black_box(Err(L1Err::Tag1a1))
}

#[inline(never)]
pub fn apply_token_annotation(
    spot_ch: &mut u64,
    token: u64,
    payload: AnnotationPayload112,
) -> Result<(), L1Err> {
    black_box((spot_ch, token, payload));
    black_box(Ok(()))
}

#[inline(never)]
pub fn lookup_exchange_entry(entries: &mut u64, key: u64) -> u64 {
    black_box((entries, key));
    black_box(0)
}

#[inline(never)]
pub fn dispatch_exchange_entry(
    handle: u64,
    time: Time12,
    arg3: u64,
    arg5: u64,
    flag: bool,
) -> Result<(), L1Err> {
    black_box((handle, time, arg3, arg5, flag));
    black_box(Ok(()))
}
