#![forbid(unsafe_code)]

use core::hint::black_box;
use core::panic::Location;

#[inline(never)]
pub fn bug_log(kind: u32, loc: &'static Location<'static>) {
    black_box((kind, loc));
}

#[inline(never)]
pub fn fetch_mid_raw(meta_hdr: &[u8; 0x10], spot: usize, spot_books: &[u64; 4]) -> u64 {
    black_box((meta_hdr, spot, spot_books));
    black_box(1u64)
}

#[inline(never)]
pub fn spot_mark_px(sc: *const (), token: usize, extra: usize) -> u64 {
    black_box((sc, token, extra));
    black_box(1u64)
}

#[inline(never)]
pub fn wei_to_usdc_ntl(
    wei: u64,
    token: usize,
    px: u64,
    round_up: bool,
    meta: *const (),
) -> Option<u64> {
    black_box((wei, token, px, round_up, meta));
    black_box(Some(1u64))
}

pub struct UnwindDrop(pub u64);

impl Drop for UnwindDrop {
    #[inline(never)]
    fn drop(&mut self) {
        if black_box(self.0) == 0xdead_beef {
            panic!("drop");
        }
    }
}

#[repr(C, u64)]
pub enum InnerDiff2c0 {
    V0(UnwindDrop) = 0,
    V1(UnwindDrop) = 1,
    Modify {
        old_sz: u64,
        new_sz: u64,
        limit_px: i64,
        asset: usize,
        oid: u64,
        user: [u8; 20],
        side: u8,
    } = 2,
    Big([u8; 0x2b0], UnwindDrop) = 3,
}

#[repr(C, u64)]
pub enum OuterDiff2c8 {
    A(UnwindDrop) = 0,
    B(UnwindDrop) = 1,
    Inner(InnerDiff2c0) = 2,
}

#[repr(C, u64)]
pub enum InnerDiff2b0 {
    V0(UnwindDrop) = 0,
    V1(UnwindDrop) = 1,
    Modify {
        old_sz: u64,
        new_sz: u64,
        limit_px: i64,
        asset: usize,
        oid: u64,
        user: [u8; 20],
        side: u8,
    } = 2,
    Big([u8; 0x2a0], UnwindDrop) = 3,
}

#[repr(C, u64)]
pub enum OuterDiff2b8 {
    A(UnwindDrop) = 0,
    B(UnwindDrop) = 1,
    Inner(InnerDiff2b0) = 2,
}

const _: [(); 0x2c8] = [(); core::mem::size_of::<OuterDiff2c8>()];
const _: [(); 0x2b8] = [(); core::mem::size_of::<OuterDiff2b8>()];

#[inline(never)]
pub fn force_push_2c8(v: &mut Vec<OuterDiff2c8>, x: OuterDiff2c8) {
    v.push(x);
}

#[inline(never)]
pub fn force_push_2b8(v: &mut Vec<OuterDiff2b8>, x: OuterDiff2b8) {
    v.push(x);
}
