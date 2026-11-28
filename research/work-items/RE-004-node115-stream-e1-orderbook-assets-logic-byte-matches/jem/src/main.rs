//! Node #115 Stream E1 (`assets`) jemalloc-backed ThinLTO compiled-byte reference
//! source (3 strictly disjoint pure business-logic FDEs = 618 B, 0 non-reloc diffs):
//! - `SpotMeta::set_full_name` (`0x2c54190`, `0x55c5da0`, `0x55c5e70` — 3 x 206 B = 618 B)
//!
//! Compiled offline with locked `tikv-jemallocator = "=0.6.0"`,
//! `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `RUSTFLAGS="-C save-temps"`.

#![forbid(unsafe_code)]
#![allow(dead_code)]

use core::hint::black_box;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[repr(C)]
pub struct TokenInfoFullName {
    _pad0: [u8; 0x30],
    pub name: String,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
    _pad1: [u8; 6],
    pub spots: Vec<usize>,
    pub full_name: Option<String>,
    _pad2: [u8; 0x158 - 0x80],
}

#[repr(C)]
pub struct ExchangeSpotMeta {
    _pad0: [u8; 0xa8],
    pub token_infos: Vec<TokenInfoFullName>,
}

// Node #115 `UserError` has 418 variants (`0..418`), placing `InvalidInput(&'static str)`
// at discriminant `0x00ee` (238) and `Result::<(), UserError>::Ok(())` at `0x01a2` (418).
macro_rules! define_user_error {
    ($($v:ident),* $(,)?) => {
        pub enum UserError {
            $($v,)*
            InvalidInput(&'static str),
            Big([u64; 4]),
            Small(u8),
            T0, T1, T2, T3, T4, T5, T6, T7, T8, T9,
            T10, T11, T12, T13, T14, T15, T16, T17, T18, T19,
            T20, T21, T22, T23, T24, T25, T26, T27, T28, T29,
            T30, T31, T32, T33, T34, T35, T36, T37, T38, T39,
            T40, T41, T42, T43, T44, T45, T46, T47, T48, T49,
            T50, T51, T52, T53, T54, T55, T56, T57, T58, T59,
            T60, T61, T62, T63, T64, T65, T66, T67, T68, T69,
            T70, T71, T72, T73, T74, T75, T76, T77, T78, T79,
            T80, T81, T82, T83, T84, T85, T86, T87, T88, T89,
            T90, T91, T92, T93, T94, T95, T96, T97, T98, T99,
            T100, T101, T102, T103, T104, T105, T106, T107, T108, T109,
            T110, T111, T112, T113, T114, T115, T116, T117, T118, T119,
            T120, T121, T122, T123, T124, T125, T126, T127, T128, T129,
            T130, T131, T132, T133, T134, T135, T136, T137, T138, T139,
            T140, T141, T142, T143, T144, T145, T146, T147, T148, T149,
            T150, T151, T152, T153, T154, T155, T156, T157, T158, T159,
            T160, T161, T162, T163, T164, T165, T166, T167, T168, T169,
            T170, T171, T172, T173, T174, T175, T176,
        }
    };
}

define_user_error!(
    V0, V1, V2, V3, V4, V5, V6, V7, V8, V9,
    V10, V11, V12, V13, V14, V15, V16, V17, V18, V19,
    V20, V21, V22, V23, V24, V25, V26, V27, V28, V29,
    V30, V31, V32, V33, V34, V35, V36, V37, V38, V39,
    V40, V41, V42, V43, V44, V45, V46, V47, V48, V49,
    V50, V51, V52, V53, V54, V55, V56, V57, V58, V59,
    V60, V61, V62, V63, V64, V65, V66, V67, V68, V69,
    V70, V71, V72, V73, V74, V75, V76, V77, V78, V79,
    V80, V81, V82, V83, V84, V85, V86, V87, V88, V89,
    V90, V91, V92, V93, V94, V95, V96, V97, V98, V99,
    V100, V101, V102, V103, V104, V105, V106, V107, V108, V109,
    V110, V111, V112, V113, V114, V115, V116, V117, V118, V119,
    V120, V121, V122, V123, V124, V125, V126, V127, V128, V129,
    V130, V131, V132, V133, V134, V135, V136, V137, V138, V139,
    V140, V141, V142, V143, V144, V145, V146, V147, V148, V149,
    V150, V151, V152, V153, V154, V155, V156, V157, V158, V159,
    V160, V161, V162, V163, V164, V165, V166, V167, V168, V169,
    V170, V171, V172, V173, V174, V175, V176, V177, V178, V179,
    V180, V181, V182, V183, V184, V185, V186, V187, V188, V189,
    V190, V191, V192, V193, V194, V195, V196, V197, V198, V199,
    V200, V201, V202, V203, V204, V205, V206, V207, V208, V209,
    V210, V211, V212, V213, V214, V215, V216, V217, V218, V219,
    V220, V221, V222, V223, V224, V225, V226, V227, V228, V229,
    V230, V231, V232, V233, V234, V235, V236, V237,
);

#[inline(never)]
pub fn e1_spot_meta_set_full_name(
    exch: &mut ExchangeSpotMeta,
    token: usize,
    full_name: String,
) -> Result<(), UserError> {
    let info = exch.token_infos.get_mut(token).unwrap();
    if info.full_name.is_some() {
        return Err(UserError::InvalidInput("full name already set"));
    }
    if full_name.is_empty() || full_name.len() > 50 {
        return Err(UserError::InvalidInput(
            "token full name must be between 1 and 50 characters long",
        ));
    }
    info.full_name = Some(full_name);
    Ok(())
}

fn main() {
    let f1: fn(&mut ExchangeSpotMeta, usize, String) -> Result<(), UserError> =
        e1_spot_meta_set_full_name;
    black_box(f1);
}
