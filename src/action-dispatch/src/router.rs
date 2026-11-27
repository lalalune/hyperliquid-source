//! Central 92-arm action router (`0x2bda7c0`, jump table `0x609f00`).
//!
//! Anchored to `research/work-items/action-dispatch-router-115`
//! (10,396 byte-executed cases, 49/49 negative controls, 0 mismatches).

use action_wire::variants::{tag_to_index, ActionVariantInfo, ACTION_VARIANTS};

/// Feature-flag query ID passed to slot `0x64e1028` for gated order-flow indices (`0x32` = 50).
pub const ROUTER_FEATURE_FLAG_ID: u32 = 50;

/// Bitmask (`0x501d`) of router indices `<= 0x0e` gated by [`ROUTER_FEATURE_FLAG_ID`]:
/// indices `0` (`noop`), `2` (`batchModify`), `3` (`cancel`), `4` (`cancelByCloid`),
/// `12` (`modify`), `14` (`order`).
pub const FLAG_50_GATE_MASK: u16 = 0x501d;

/// Nanoseconds sentinel stored in `ebp` when latency timing is skipped (`1_000_000_000`).
pub const TIMER_SKIPPED_SENTINEL: u32 = 0x3b9a_ca00;

/// Argument-passing shape observed in each of the 92 router arms (`arms.tsv`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgShape {
    /// No 4th argument loaded (indices 0, 5, 64, 72).
    None,
    /// Passes the tag pointer directly in `rcx` (niche index 20 `VoteGlobal`).
    TagPointer,
    /// Passes `tag_pointer + 8` in `rcx` (80 standard arms).
    TagPointerPlus8,
    /// Loads value arguments from fixed payload offsets (indices 18, 22, 28, 35, 61, 65, 78).
    PayloadLoads {
        rcx_offset: u8,
        rcx_bytes: u8,
        r8: Option<(u8, u8)>,
    },
}

/// One arm of the 92-entry action router at `0x2bda7c0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouterArm {
    pub index: usize,
    pub canonical_tag: u64,
    pub handler_va: u64,
    pub arg_shape: ArgShape,
    pub gated_by_flag_50: bool,
}

impl RouterArm {
    pub const fn variant(&self) -> &'static ActionVariantInfo {
        &ACTION_VARIANTS[self.index]
    }
}

/// Complete 92-arm dispatch table read from node #115 `0x2bda7c0` / `0x609f00` (`arms.tsv`).
pub const ROUTER_ARMS: [RouterArm; 92] = [
    RouterArm { index: 0, canonical_tag: 0x86, handler_va: 0x2c11290, arg_shape: ArgShape::None, gated_by_flag_50: true },
    RouterArm { index: 1, canonical_tag: 0x87, handler_va: 0x2c05c70, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 2, canonical_tag: 0x88, handler_va: 0x2c12050, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: true },
    RouterArm { index: 3, canonical_tag: 0x89, handler_va: 0x2c0ede0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: true },
    RouterArm { index: 4, canonical_tag: 0x8a, handler_va: 0x2c1fd40, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: true },
    RouterArm { index: 5, canonical_tag: 0x8b, handler_va: 0x2c03ed0, arg_shape: ArgShape::None, gated_by_flag_50: false },
    RouterArm { index: 6, canonical_tag: 0x8c, handler_va: 0x2c182b0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 7, canonical_tag: 0x8d, handler_va: 0x2c0da60, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 8, canonical_tag: 0x8e, handler_va: 0x2c1c240, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 9, canonical_tag: 0x8f, handler_va: 0x2c08ad0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 10, canonical_tag: 0x90, handler_va: 0x2c18c40, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 11, canonical_tag: 0x91, handler_va: 0x2c1d070, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 12, canonical_tag: 0x92, handler_va: 0x2c09ff0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: true },
    RouterArm { index: 13, canonical_tag: 0x93, handler_va: 0x2c07730, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 14, canonical_tag: 0x94, handler_va: 0x2c168e0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: true },
    RouterArm { index: 15, canonical_tag: 0x95, handler_va: 0x2c0d190, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 16, canonical_tag: 0x96, handler_va: 0x2c06da0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 17, canonical_tag: 0x97, handler_va: 0x2c0f350, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 18, canonical_tag: 0x98, handler_va: 0x2c06530, arg_shape: ArgShape::PayloadLoads { rcx_offset: 8, rcx_bytes: 8, r8: Some((16, 8)) }, gated_by_flag_50: false },
    RouterArm { index: 19, canonical_tag: 0x99, handler_va: 0x2c08600, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 20, canonical_tag: 0x9a, handler_va: 0x2c1da50, arg_shape: ArgShape::TagPointer, gated_by_flag_50: false },
    RouterArm { index: 21, canonical_tag: 0x9b, handler_va: 0x2c13570, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 22, canonical_tag: 0x9c, handler_va: 0x2c1df30, arg_shape: ArgShape::PayloadLoads { rcx_offset: 16, rcx_bytes: 8, r8: Some((24, 8)) }, gated_by_flag_50: false },
    RouterArm { index: 23, canonical_tag: 0x9d, handler_va: 0x2c143d0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 24, canonical_tag: 0x9e, handler_va: 0x2c04e30, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 25, canonical_tag: 0x9f, handler_va: 0x2c1aee0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 26, canonical_tag: 0xa0, handler_va: 0x2c1b320, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 27, canonical_tag: 0xa1, handler_va: 0x2c0e9a0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 28, canonical_tag: 0xa2, handler_va: 0x2c12c10, arg_shape: ArgShape::PayloadLoads { rcx_offset: 8, rcx_bytes: 4, r8: None }, gated_by_flag_50: false },
    RouterArm { index: 29, canonical_tag: 0xa3, handler_va: 0x2c09980, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 30, canonical_tag: 0xa4, handler_va: 0x2c1edc0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 31, canonical_tag: 0xa5, handler_va: 0x2c03970, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 32, canonical_tag: 0xa6, handler_va: 0x2c057b0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 33, canonical_tag: 0xa7, handler_va: 0x2c186f0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 34, canonical_tag: 0xa8, handler_va: 0x2c060b0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 35, canonical_tag: 0xa9, handler_va: 0x2c0a610, arg_shape: ArgShape::PayloadLoads { rcx_offset: 8, rcx_bytes: 8, r8: Some((16, 4)) }, gated_by_flag_50: false },
    RouterArm { index: 36, canonical_tag: 0xaa, handler_va: 0x2c1f370, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 37, canonical_tag: 0xab, handler_va: 0x2c13e70, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 38, canonical_tag: 0xac, handler_va: 0x2c09400, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 39, canonical_tag: 0xad, handler_va: 0x2c11af0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 40, canonical_tag: 0xae, handler_va: 0x2c17dc0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 41, canonical_tag: 0xaf, handler_va: 0x2c103b0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 42, canonical_tag: 0xb0, handler_va: 0x2c0df40, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 43, canonical_tag: 0xb1, handler_va: 0x2c1a3f0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 44, canonical_tag: 0xb2, handler_va: 0x2c0ab50, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 45, canonical_tag: 0xb3, handler_va: 0x2c14de0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 46, canonical_tag: 0xb4, handler_va: 0x2c07c10, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 47, canonical_tag: 0xb5, handler_va: 0x2c08130, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 48, canonical_tag: 0xb6, handler_va: 0x2c1e440, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 49, canonical_tag: 0xb7, handler_va: 0x2c1f910, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 50, canonical_tag: 0xb8, handler_va: 0x2c19100, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 51, canonical_tag: 0xb9, handler_va: 0x2c1b7d0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 52, canonical_tag: 0xba, handler_va: 0x2c12690, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 53, canonical_tag: 0xbb, handler_va: 0x2c08f00, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 54, canonical_tag: 0xbc, handler_va: 0x2c0b030, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 55, canonical_tag: 0xbd, handler_va: 0x2c15220, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 56, canonical_tag: 0xbe, handler_va: 0x2c0ba40, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 57, canonical_tag: 0xbf, handler_va: 0x2c10d70, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 58, canonical_tag: 0xc0, handler_va: 0x2c19a40, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 59, canonical_tag: 0xc1, handler_va: 0x2c139b0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 60, canonical_tag: 0xc2, handler_va: 0x2c172e0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 61, canonical_tag: 0xc3, handler_va: 0x2c16460, arg_shape: ArgShape::PayloadLoads { rcx_offset: 40, rcx_bytes: 8, r8: None }, gated_by_flag_50: false },
    RouterArm { index: 62, canonical_tag: 0xc4, handler_va: 0x2c17820, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 63, canonical_tag: 0xc5, handler_va: 0x2c1cbd0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 64, canonical_tag: 0xc6, handler_va: 0x2c116b0, arg_shape: ArgShape::None, gated_by_flag_50: false },
    RouterArm { index: 65, canonical_tag: 0xc7, handler_va: 0x2c1d590, arg_shape: ArgShape::PayloadLoads { rcx_offset: 8, rcx_bytes: 4, r8: None }, gated_by_flag_50: false },
    RouterArm { index: 66, canonical_tag: 0xc8, handler_va: 0x2c0b5a0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 67, canonical_tag: 0xc9, handler_va: 0x2c068b0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 68, canonical_tag: 0xca, handler_va: 0x2c1c680, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 69, canonical_tag: 0xcb, handler_va: 0x2c1a930, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 70, canonical_tag: 0xcc, handler_va: 0x2c13070, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 71, canonical_tag: 0xcd, handler_va: 0x2c0c520, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 72, canonical_tag: 0xce, handler_va: 0x2c1e920, arg_shape: ArgShape::None, gated_by_flag_50: false },
    RouterArm { index: 73, canonical_tag: 0xcf, handler_va: 0x2c1bcb0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 74, canonical_tag: 0xd0, handler_va: 0x2c07260, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 75, canonical_tag: 0xd1, handler_va: 0x2c04350, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 76, canonical_tag: 0xd2, handler_va: 0x2c048a0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 77, canonical_tag: 0xd3, handler_va: 0x2c0e420, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 78, canonical_tag: 0xd4, handler_va: 0x2c15660, arg_shape: ArgShape::PayloadLoads { rcx_offset: 8, rcx_bytes: 4, r8: None }, gated_by_flag_50: false },
    RouterArm { index: 79, canonical_tag: 0xd5, handler_va: 0x2c19f20, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 80, canonical_tag: 0xd6, handler_va: 0x2c16020, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 81, canonical_tag: 0xd7, handler_va: 0x2c0fdb0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 82, canonical_tag: 0xd8, handler_va: 0x2c0cb20, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 83, canonical_tag: 0xd9, handler_va: 0x2c0d630, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 84, canonical_tag: 0xda, handler_va: 0x2c05370, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 85, canonical_tag: 0xdb, handler_va: 0x2c149b0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 86, canonical_tag: 0xdc, handler_va: 0x2c16eb0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 87, canonical_tag: 0xdd, handler_va: 0x2c19610, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 88, canonical_tag: 0xde, handler_va: 0x2c108a0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 89, canonical_tag: 0xdf, handler_va: 0x2c0bfa0, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 90, canonical_tag: 0xe0, handler_va: 0x2c15b40, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
    RouterArm { index: 91, canonical_tag: 0xe1, handler_va: 0x2c0f810, arg_shape: ArgShape::TagPointerPlus8, gated_by_flag_50: false },
];

/// Returns `true` iff `index` is gated by feature flag 50 (`index <= 14 && (0x501d >> index) & 1 != 0`).
pub const fn is_gated_by_flag_50(index: usize) -> bool {
    index <= 0x0e && ((FLAG_50_GATE_MASK >> index) & 1) != 0
}

/// Resolves a raw tag word to its [`RouterArm`].
pub const fn arm_for_tag(tag: u64) -> Option<&'static RouterArm> {
    match tag_to_index(tag) {
        Some(idx) => Some(&ROUTER_ARMS[idx]),
        None => None,
    }
}

/// Recorded start/end clock reading emitted by `0x2bda7c0` when timing is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatencySpan {
    pub start: (u64, u32),
    pub end: (u64, u32),
}

/// Result of routing one action tag through [`route_action`] (`0x2bda7c0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoutedOutcome<R> {
    pub arm: &'static RouterArm,
    pub queried_flag_50: bool,
    pub latency: Option<LatencySpan>,
    pub output: R,
}

/// Executes node #115's central action router prologue/dispatch/epilogue (`0x2bda7c0`).
pub fn route_action<F, C, H, R>(
    tag: u64,
    flag_50: F,
    mut read_clock: C,
    handler: H,
) -> Option<RoutedOutcome<R>>
where
    F: FnOnce(u32) -> bool,
    C: FnMut() -> (u64, u32),
    H: FnOnce(&'static RouterArm) -> R,
{
    let arm = arm_for_tag(tag)?;
    let (queried_flag_50, timer_start) = if is_gated_by_flag_50(arm.index) {
        if flag_50(ROUTER_FEATURE_FLAG_ID) {
            (true, Some(read_clock()))
        } else {
            (true, None)
        }
    } else {
        (false, Some(read_clock()))
    };

    let output = handler(arm);

    let latency = match timer_start {
        Some(start) if start.1 != TIMER_SKIPPED_SENTINEL => {
            let end = read_clock();
            Some(LatencySpan { start, end })
        }
        _ => None,
    };

    Some(RoutedOutcome {
        arm,
        queried_flag_50,
        latency,
        output,
    })
}
