#![no_std]
#![forbid(unsafe_code)]
/// Only values observed after the opaque call at 0x555e874 returns. In
/// particular, RSI is not assumed equal to the incoming caller argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostCall {
    pub rax: u64,
    pub rdx: u64,
    pub rsi: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
}
/// Node94 continuation 0x555e879..0x555e898 within the complete FDE
/// 0x555e870..0x555e898. No helper implementation, ABI or invocation is supplied.
pub fn continue_after_call(post: PostCall) -> Registers {
    let mut out = Registers {
        rax: 0,
        rcx: post.rax,
        rdx: post.rdx,
        rsi: post.rsi,
    };
    if post.rax > u64::MAX - 119 {
        return out;
    }
    let value = post.rsi as u32 as i32;
    let low = post.rdx as u32 as i32;
    if value < low {
        return out;
    }
    out.rdx = ((post.rdx as i64) >> 32) as u64;
    out.rax = u64::from(value <= out.rdx as u32 as i32);
    out
}
