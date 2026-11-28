#![forbid(unsafe_code)]
#![allow(dead_code, non_camel_case_types)]

use std::hint::black_box;

#[repr(align(16))]
pub struct ErrPayload96(pub [u64; 12]);

#[repr(u16)]
pub enum ActionError {
    Kind0(ErrPayload96) = 0,
    Kind1(ErrPayload96) = 1,
    TooManyOrders(*const OrderAction) = 0x158,
    Other = 417,
}

#[repr(C)]
pub struct DelayConfig {
    pub pad: [u64; 5],
    pub default_delay: f64,
}

#[repr(C)]
pub struct OrderWire80 {
    pub pad0: [u8; 0x18],
    pub reduce_only_alt: u8,
    pub pad1: [u8; 8],
    pub tif: u8,
    pub pad2: [u8; 0x2c],
    pub reduce_only: u8,
    pub pad3: u8,
}

#[repr(C)]
pub struct OrderAction {
    pub orders: Vec<OrderWire80>,
    pub grouping: u8,
}

#[repr(C)]
pub struct ModifyWire56 {
    pub pad0: [u8; 0x36],
    pub reduce_only: u8,
    pub pad1: u8,
}

#[repr(C)]
pub struct SingleModifyAction {
    pub pad0: [u8; 0x18],
    pub f18: u8,
    pub pad1: [u8; 8],
    pub f21: u8,
    pub pad2: [u8; 0x2c],
    pub f4e: bool,
}

#[repr(C)]
pub struct CancelAction {
    pub cap: usize,
    pub ptr: *const u8,
    pub len: usize,
    pub flag: u8,
}

#[repr(C)]
pub struct Flag55Action {
    pub pad0: [u8; 0x4d],
    pub flag: bool,
}

#[inline(never)]
pub fn ext_order_is_alo_only(oa: &OrderAction) -> bool {
    black_box(oa);
    black_box(false)
}
