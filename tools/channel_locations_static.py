#!/usr/bin/env python3
"""Static node #94 `net_utils/src/channel.rs` panic Locations, checked from authenticated bytes.

Question: what do the `net_utils/channel.rs` seeds do with the source
Locations they carry?  The can1357 lead (`net_utils/channel.rs`) says nine
`Receiver<T>::recv` futures "unwrap the `Option<T>` at `channel.rs:93:47`",
that `Sender::send` unwraps, and that the request/response future
`0x474bfa0` awaits a Tokio oneshot and "unwraps at `channel.rs:117:30`".

In the binary the path string occurs once, and seven RELATIVE-backed
Locations point at it: five copies of 93:47 and two of 117:30.  Every
`.text` reference to a 93:47 copy is `lea rdi, Location` directly followed
by a call through the slot of rustc's "`async fn` resumed after completion"
or "`async fn` resumed after panicking" panic, one of each in each of 21
FDEs.  So 93:47 is the body of an `async fn` in `channel.rs`, not an unwrap.
117:30 is the caller Location of three outlined copies and one inlined copy
of Tokio's `#[track_caller]` blocking path: it is passed to the
"Cannot block the current thread from within a runtime" expect and to a
`Result::unwrap`.  The outlined copies drive a future whose own resume
panics carry Tokio `sync/mpsc/unbounded.rs:167:47`; their callers
`0x432e4d0`, `0x432f680` and `0x474bfa0` are plain functions that return
when the result is the None value.  No other channel.rs Location exists, so
no `send` or `recv` unwrap in this file carries a channel.rs Location.

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; call, branch and RIP-relative
targets, the panic message strings, the Locations, RELATIVE slots and a
whole-`.text` census of references to the Locations and of the callers of
the blocking helpers are decoded here.  Nothing from the binary is executed.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = 'artifacts/node/94/hl-node'
PATH_VA = 0x1e9781
PATH = b'/home/ubuntu/hl/code_Mainnet/net_utils/src/channel.rs'
LOCATIONS = {
    0x56973b8: (93, 47), 0x56a0aa0: (93, 47), 0x571edd0: (93, 47), 0x572fcc8: (93, 47), 0x573e268: (93, 47),
    0x56a0a88: (117, 30), 0x572fcb0: (117, 30),
}
COMPLETION_SLOT = 0x576f040
PANICKING_SLOT = 0x576f038
CONST_PANICS = {
    COMPLETION_SLOT: (0x157b540, 0x25d282, b'`async fn` resumed after completion'),
    PANICKING_SLOT: (0x157b560, 0x25d2a5, b'`async fn` resumed after panicking'),
}
PANIC_FMT_SLOT = 0x576e098
EXPECT_SLOT = 0x576e468
UNWRAP_SLOT = 0x576e048
PANIC_SLOTS = {COMPLETION_SLOT, PANICKING_SLOT, PANIC_FMT_SLOT, EXPECT_SLOT, UNWRAP_SLOT}
SAMPLER_NEW_SLOT = 0x5776560
SAMPLER_NEW = 0x3d22aa0
BLOCK_MESSAGE = (b'Cannot block the current thread from within a runtime. This happens because a function '
                 b'attempted to block the current thread while the thread is being used to drive asynchronous tasks.')
UNWRAP_MESSAGE = b'called `Result::unwrap()` on an `Err` value'
TOKIO_RECV = (0x571e8c0, '/tokio-1.44.2/src/sync/mpsc/unbounded.rs:167:47')

# FDE -> (93:47 Location, the two `lea rdi, Location` references)
RESUME = {
    0x1fd5b30: (0x56973b8, (0x1fd5bbd, 0x1fd5bcc)), 0x1fd5ec0: (0x56973b8, (0x1fd5f5b, 0x1fd5f6a)),
    0x20312d0: (0x56973b8, (0x2032111, 0x203211e)), 0x204c220: (0x56973b8, (0x204c460, 0x204c46d)),
    0x22713f0: (0x56a0aa0, (0x22714a5, 0x22714b4)), 0x2271820: (0x56a0aa0, (0x22718e6, 0x22718f5)),
    0x438cb90: (0x571edd0, (0x438cf6b, 0x438cf7a)), 0x438e060: (0x571edd0, (0x438e420, 0x438e42f)),
    0x4391840: (0x571edd0, (0x4391c5d, 0x4391c6f)), 0x4399360: (0x571edd0, (0x439974e, 0x4399760)),
    0x4399e80: (0x571edd0, (0x439a256, 0x439a268)),
    0x47b05f0: (0x572fcc8, (0x47b06fc, 0x47b070b)), 0x47b0db0: (0x572fcc8, (0x47b0e8c, 0x47b0e9b)),
    0x47b12d0: (0x572fcc8, (0x47b13ac, 0x47b13bb)), 0x47b1930: (0x572fcc8, (0x47b1a0a, 0x47b1a19)),
    0x47b3b80: (0x572fcc8, (0x47b3c40, 0x47b3c4f)), 0x47b3f50: (0x572fcc8, (0x47b403f, 0x47b404e)),
    0x47b6f90: (0x572fcc8, (0x47b7080, 0x47b708f)), 0x47b75e0: (0x572fcc8, (0x47b76bf, 0x47b76ce)),
    0x4b31030: (0x573e268, (0x4b310f3, 0x4b31102)), 0x4b3c560: (0x573e268, (0x4b3c5ea, 0x4b3c5f9)),
}
# caller of the blocking helper: 117:30 site, helper, None test and its return path, optional sampler name
BLOCKING = {
    'slow': dict(fde=0x432e4d0, site=0x432e590, call=0x432e597, helper=0x437f970, test=0x432e59c, branch=0x432e5a4,
                 test_hex='4c39a424f8000000', none=0x432e833, ret=0x432e898,
                 sampler=(0x432e4e4, 0x6f10d8, b'node_slow', 0x432e4f3, 0x20a940, 0.5, 0x432e4fb, 0x432e503)),
    'plain': dict(fde=0x432f680, site=0x432f6c2, call=0x432f6c9, helper=0x437f580, test=0x432f6ce, branch=0x432f6d6,
                  test_hex='83bc24000300000b', none=0x432f92e, ret=0x432f95c, sampler=None),
    'fast': dict(fde=0x474bfa0, site=0x474c0d5, call=0x474c0dc, helper=0x437fdb0, test=0x474c0e1, branch=0x474c0ea,
                 test_hex='4883bc24b004000000', none=0x474dc2e, ret=0x474dc5c,
                 sampler=(0x474bfcc, 0x6fb7d1, b'node_fast', 0x474bfdb, 0x20aa00, 0.25, 0x474bfe3, 0x474bfe8)),
}
# blocking helper: save / restore of the caller Location, the expect, the unwrap and the inlined recv resume panics
HELPERS = {
    0x437f970: dict(save=0x437f9be, restore=0x437f9ca, expect=0x437fa66, resave=0x437fa90, r8=0x437faa7,
                    unwrap=0x437faaa, unwrap_call=0x437fac2, msg=0x6f1438, umsg=0x6f0ebd, resume=(0x437fd4c, 0x437fd5b)),
    0x437f580: dict(save=0x437f5ce, restore=0x437f5da, expect=0x437f676, resave=0x437f6a0, r8=0x437f6b7,
                    unwrap=0x437f6ba, unwrap_call=0x437f6d2, msg=0x6f1438, umsg=0x6f0ebd, resume=(0x437f90e, 0x437f91d)),
    0x437fdb0: dict(save=0x437fdfb, restore=0x437fe07, expect=0x437fea3, resave=0x437fecd, r8=0x437fee4,
                    unwrap=0x437fee7, unwrap_call=0x437feff, msg=0x6f1438, umsg=0x6f0ebd, resume=(0x4380139, 0x4380148)),
}
INLINE = dict(fde=0x2017c80, expect=0x201889d, loc_rdx=0x20188a4, len_b8=0x20188ab, expect_call=0x20188b0,
              unwrap=0x20188bb, loc_r8=0x20188c9, len_2b=0x20188d8, unwrap_call=0x20188dd,
              msg=0x3f487e, umsg=0x3f47e8, location=0x56a0a88)
LEAD_SEEDS = [0x47b05f0, 0x47b12d0, 0x47b1930, 0x47b3b80, 0x47b3f50, 0x47b6f90, 0x47b75e0, 0x4b31030, 0x4b3c560,
              0x474bfa0, 0x1fd5b30, 0x1fd5ec0, 0x2017c80, 0x20312d0, 0x432e4d0, 0x432f680, 0x438cb90, 0x4391840,
              0x4399360]

WINDOWS = {
    'resume_1fd5b30': (0x1fd5b30, 0x1fd5bbd,
        '488d3df4176c03ff156e947903eb2b488d3de5176c03ff1567947903'),
    'resume_1fd5ec0': (0x1fd5ec0, 0x1fd5f5b,
        '488d3d56146c03ff15d0907903eb2b488d3d47146c03ff15c9907903'),
    'resume_20312d0': (0x20312d0, 0x2032111,
        '488d3da0526603ff1522cf7303488d3d93526603ff150dcf7303'),
    'resume_204c220': (0x204c220, 0x204c460,
        '488d3d51af6403ff15cb2b7203488d3d44af6403ff15c62b7203'),
    'resume_22713f0': (0x22713f0, 0x22714a5,
        '488d3df4f54203ff1586db4f03eb49488d3de5f54203ff157fdb4f03'),
    'resume_2271820': (0x2271820, 0x22718e6,
        '488d3db3f14203ff1545d74f03eb49488d3da4f14203ff153ed74f03'),
    'resume_438cb90': (0x438cb90, 0x438cf6b,
        '488d3d5e1e3901ff15c0203e01eb2b488d3d4f1e3901ff15b9203e01'),
    'resume_438e060': (0x438e060, 0x438e420,
        '488d3da9093901ff150b0c3e01eb2b488d3d9a093901ff15040c3e01'),
    'resume_4391840': (0x4391840, 0x4391c5d,
        '488d3d6cd13801ff15ced33d01e91d060000488d3d5ad13801ff15c4d33d01'),
    'resume_4399360': (0x4399360, 0x439974e,
        '488d3d7b563801ff15dd583d01e9fb050000488d3d69563801ff15d3583d01'),
    'resume_4399e80': (0x4399e80, 0x439a256,
        '488d3d734b3801ff15d54d3d01e9d9040000488d3d614b3801ff15cb4d3d01'),
    'resume_47b05f0': (0x47b05f0, 0x47b06fc,
        '488d3dc5f5f700ff152fe9fb00eb45488d3db6f5f700ff1528e9fb00'),
    'resume_47b0db0': (0x47b0db0, 0x47b0e8c,
        '488d3d35eef700ff159fe1fb00eb2b488d3d26eef700ff1598e1fb00'),
    'resume_47b12d0': (0x47b12d0, 0x47b13ac,
        '488d3d15e9f700ff157fdcfb00eb45488d3d06e9f700ff1578dcfb00'),
    'resume_47b1930': (0x47b1930, 0x47b1a0a,
        '488d3db7e2f700ff1521d6fb00eb2b488d3da8e2f700ff151ad6fb00'),
    'resume_47b3b80': (0x47b3b80, 0x47b3c40,
        '488d3d81c0f700ff15ebb3fb00eb2b488d3d72c0f700ff15e4b3fb00'),
    'resume_47b3f50': (0x47b3f50, 0x47b403f,
        '488d3d82bcf700ff15ecaffb00eb2b488d3d73bcf700ff15e5affb00'),
    'resume_47b6f90': (0x47b6f90, 0x47b7080,
        '488d3d418cf700ff15ab7ffb00eb45488d3d328cf700ff15a47ffb00'),
    'resume_47b75e0': (0x47b75e0, 0x47b76bf,
        '488d3d0286f700ff156c79fb00eb45488d3df385f700ff156579fb00'),
    'resume_4b31030': (0x4b31030, 0x4b310f3,
        '488d3d6ed1c000ff1538dfc300eb49488d3d5fd1c000ff1531dfc300'),
    'resume_4b3c560': (0x4b3c560, 0x4b3c5ea,
        '488d3d771cc000ff15412ac300eb2b488d3d681cc000ff153a2ac300'),
    'const_completion': (0x157b540, 0x157b540,
        '554889e54889fa488d3d341dcefebe47000000ff153f2b1f04'),
    'const_panicking': (0x157b560, 0x157b560,
        '554889e54889fa488d3d371dcefebe45000000ff151f2b1f04'),
    'slow_call': (0x432e4d0, 0x432e4d0,
        '554157415641554154534881ec980900004989fd488d35ed2b3cfc488dac24b0010000f20f100545c4edfbba09000000'
        '4889efff155780440149bc00000000000000804c89a4245001000048b80000000000c0924048898424b8000000c78424'
        'c000000000000000498d45504889442458498d858000000048894424504c8d742460488b05cf0344014883c050488944'
        '2448eb126666662e0f1f8400000000004d89f44989de488b4424584889442460c644247000488dbc24f80000004c89f6'
        '488d1519174001e8d41305004c39a424f80000000f8489020000'),
    'slow_none': (0x432e4d0, 0x432e833,
        '488bb424500100004c39e674324885f67410488bbc245801000031d2ff15bbf74301488bb424900100004885f6741048'
        '8bbc249801000031d2ff159ef74301488dbc24b0010000e8811502004c89efe8594502004881c4980900005b415c415d'
        '415e415f5dc3'),
    'plain_call': (0x432f680, 0x432f680,
        '554157415641554154534881ec780700004889fb488d4770488904244c8da42400030000488b2d35e943010f1f440000'
        '48895c2408c6442418004c89e7488d742408488d15e7054001e8b2fe040083bc24000300000b0f8452020000'),
    'plain_none': (0x432f680, 0x432f92e,
        '4889dfe8aa2c02004883c3204889dfe82eb90000488b3c24e8252d02004881c4780700005b415c415d415e415f5dc3'),
    'fast_call': (0x474bfa0, 0x474bfa0,
        '554157415641554154534881ec680e00004d89c44989cf4989d589b4249c0100004889fd4c898424f0010000488d35fe'
        'f7fafb488dbc2480060000f20f10051deaabfbba09000000ff1572a50201488d853806000048898424e0010000488d85'
        'f005000048898424c8010000488d85fc05000048898424d0010000488d85600200004889842450030000488d85c00500'
        '004889842470010000488d85400500004889842448030000488d857006000048898424d8010000498b07498b4f084889'
        '8c24c00100004889442478488d8080000000488984244003000048c784248000000000000000c744244c00000000c744'
        '247000000000c744246c000000004c89a424780100004c896c24204c897c241848896c24384c89ac24a0000000c68424'
        'b000000000488dbc24b0040000488db424a0000000488d15d43bfe00e8cf3cc3ff4883bc24b0040000000f843e1b0000'),
    'fast_none': (0x474bfa0, 0x474dc2e,
        '488dbc2480060000e86589feff4c89ffe8bdcbfeff4c89efe8c598fdff4881c4680e00005b415c415d415e415f5dc3'),
    'block_slow': (0x437f970, 0x437f970,
        '554157415641554154534881eca800000049c7c6d8eeffff64488b0425000000004c01f0488944240864410fb6464883'
        'f801743283f8027439488d058071bf004989fc488b7c24084889f34889c64989d7ff1519f83e014c89e74c89fa4889de'
        '6441c64648016441807e46020f858400000064488b042500000000488d80e8fbffff64803c25f0fbffff014889442410'
        '757648897c2428488b00f048ff000f8e540300004883c010488d0db15a3d0148894c24184889442420488d4424184889'
        '442430488944243848c7442440000000004c8b3e4c8b6608440fb66e1064410fb65e4883fb010f848400000083fb0275'
        '67e98e000000488d3dcb1937fcbeb8000000ff15f0e93e0164488b0425000000004989fc488db8e8fbffff4889f331f6'
        '4989d7e8286fbf004c89e74889de4885c00f855bffffff4d89f8488d3d0c1437fc488d0d90d23901488d542450be2b00'
        '0000ff1580e53e01'),
    'block_slow_resume': (0x437f970, 0x437fd4c,
        '488d3d6deb3901ff15dff23e01eb0d488d3d5eeb3901ff15d8f23e01'),
    'block_plain': (0x437f580, 0x437f580,
        '554157415641554154534881ecd801000049c7c6d8eeffff64488b0425000000004c01f0488944241064410fb6464883'
        'f801743283f8027439488d057075bf004989fc488b7c24104889f34889c64989d7ff1509fc3e014c89e74c89fa4889de'
        '6441c64648016441807e46020f858400000064488b042500000000488d80e8fbffff64803c25f0fbffff014889442418'
        '757648897c2430488b00f048ff000f8e060300004883c010488d0da15e3d0148894c24204889442428488d4424204889'
        '442438488944244048c7442448000000004c8b3e4c8b6608440fb66e1064410fb65e4883fb010f848400000083fb0275'
        '67e98e000000488d3dbb1d37fcbeb8000000ff15e0ed3e0164488b0425000000004989fc488db8e8fbffff4889f331f6'
        '4989d7e81873bf004c89e74889de4885c00f855bffffff4d89f8488d3dfc1737fc488d0d80d63901488d542458be2b00'
        '0000ff1570e93e01'),
    'block_plain_resume': (0x437f580, 0x437f90e,
        '488d3dabef3901ff151df73e01eb0d488d3d9cef3901ff1516f73e01'),
    'block_fast': (0x437fdb0, 0x437fdb0,
        '554157415641554154534883ec7849c7c6d8eeffff64488b0425000000004c01f0488944240864410fb6464883f80174'
        '3283f8027439488d05436dbf004989fc488b7c24084889f34889c64989d7ff15dcf33e014c89e74c89fa4889de6441c6'
        '4648016441807e46020f858400000064488b042500000000488d80e8fbffff64803c25f0fbffff014889442410757648'
        '897c2428488b00f048ff000f8e040300004883c010488d0d74563d0148894c24184889442420488d4424184889442458'
        '488944246048c7442468000000004c8b3e4c8b6608440fb66e1064410fb65e4883fb010f848400000083fb027567e98e'
        '000000488d3d8e1537fcbeb8000000ff15b3e53e0164488b0425000000004989fc488db8e8fbffff4889f331f64989d7'
        'e8eb6abf004c89e74889de4885c00f855bffffff4d89f8488d3dcf0f37fc488d0d53ce3901488d542430be2b000000ff'
        '1543e13e01'),
    'block_fast_resume': (0x437fdb0, 0x4380139,
        '488d3d80e73901ff15f2ee3e01eb0d488d3d71e73901ff15ebee3e01'),
    'inline_select': (0x2017c80, 0x201889d,
        '488d3ddabf3dfe488d15dd816803beb8000000ff15b25b7503e9a3010000488d3d26bf3dfe488d0defc66a034c8d05b8'
        '816803488d9424487c0000be2b000000ff1565577503'),
}

# va: (instruction length, target) for every rel8/rel32 branch, call and RIP-relative operand in the windows.
OPERANDS = {
    0x157b547: (7, 0x25d282),  # const_completion: lea
    0x157b553: (6, 0x576e098),  # const_completion: call
    0x157b567: (7, 0x25d2a5),  # const_panicking: lea
    0x157b573: (6, 0x576e098),  # const_panicking: call
    0x1fd5bbd: (7, 0x56973b8),  # resume_1fd5b30: lea
    0x1fd5bc4: (6, 0x576f038),  # resume_1fd5b30: call
    0x1fd5bca: (2, 0x1fd5bf7),  # resume_1fd5b30: jmp
    0x1fd5bcc: (7, 0x56973b8),  # resume_1fd5b30: lea
    0x1fd5bd3: (6, 0x576f040),  # resume_1fd5b30: call
    0x1fd5f5b: (7, 0x56973b8),  # resume_1fd5ec0: lea
    0x1fd5f62: (6, 0x576f038),  # resume_1fd5ec0: call
    0x1fd5f68: (2, 0x1fd5f95),  # resume_1fd5ec0: jmp
    0x1fd5f6a: (7, 0x56973b8),  # resume_1fd5ec0: lea
    0x1fd5f71: (6, 0x576f040),  # resume_1fd5ec0: call
    0x201889d: (7, 0x3f487e),  # inline_select: lea
    0x20188a4: (7, 0x56a0a88),  # inline_select: lea
    0x20188b0: (6, 0x576e468),  # inline_select: call
    0x20188b6: (5, 0x2018a5e),  # inline_select: jmp
    0x20188bb: (7, 0x3f47e8),  # inline_select: lea
    0x20188c2: (7, 0x56c4fb8),  # inline_select: lea
    0x20188c9: (7, 0x56a0a88),  # inline_select: lea
    0x20188dd: (6, 0x576e048),  # inline_select: call
    0x2032111: (7, 0x56973b8),  # resume_20312d0: lea
    0x2032118: (6, 0x576f040),  # resume_20312d0: call
    0x203211e: (7, 0x56973b8),  # resume_20312d0: lea
    0x2032125: (6, 0x576f038),  # resume_20312d0: call
    0x204c460: (7, 0x56973b8),  # resume_204c220: lea
    0x204c467: (6, 0x576f038),  # resume_204c220: call
    0x204c46d: (7, 0x56973b8),  # resume_204c220: lea
    0x204c474: (6, 0x576f040),  # resume_204c220: call
    0x22714a5: (7, 0x56a0aa0),  # resume_22713f0: lea
    0x22714ac: (6, 0x576f038),  # resume_22713f0: call
    0x22714b2: (2, 0x22714fd),  # resume_22713f0: jmp
    0x22714b4: (7, 0x56a0aa0),  # resume_22713f0: lea
    0x22714bb: (6, 0x576f040),  # resume_22713f0: call
    0x22718e6: (7, 0x56a0aa0),  # resume_2271820: lea
    0x22718ed: (6, 0x576f038),  # resume_2271820: call
    0x22718f3: (2, 0x227193e),  # resume_2271820: jmp
    0x22718f5: (7, 0x56a0aa0),  # resume_2271820: lea
    0x22718fc: (6, 0x576f040),  # resume_2271820: call
    0x432e4e4: (7, 0x6f10d8),  # slow_call: lea
    0x432e4f3: (8, 0x20a940),  # slow_call: movsd
    0x432e503: (6, 0x5776560),  # slow_call: call
    0x432e552: (7, 0x576e928),  # slow_call: mov
    0x432e562: (2, 0x432e576),  # slow_call: jmp
    0x432e590: (7, 0x572fcb0),  # slow_call: lea
    0x432e597: (5, 0x437f970),  # slow_call: call
    0x432e5a4: (6, 0x432e833),  # slow_call: je
    0x432e83e: (2, 0x432e872),  # slow_none: je
    0x432e843: (2, 0x432e855),  # slow_none: je
    0x432e84f: (6, 0x576e010),  # slow_none: call
    0x432e860: (2, 0x432e872),  # slow_none: je
    0x432e86c: (6, 0x576e010),  # slow_none: call
    0x432e87a: (5, 0x434fe00),  # slow_none: call
    0x432e882: (5, 0x4352de0),  # slow_none: call
    0x432f6a4: (7, 0x576dfe0),  # plain_call: mov
    0x432f6c2: (7, 0x572fcb0),  # plain_call: lea
    0x432f6c9: (5, 0x437f580),  # plain_call: call
    0x432f6d6: (6, 0x432f92e),  # plain_call: je
    0x432f931: (5, 0x43525e0),  # plain_none: call
    0x432f93d: (5, 0x433b270),  # plain_none: call
    0x432f946: (5, 0x4352670),  # plain_none: call
    0x437f5b2: (2, 0x437f5e6),  # block_plain: je
    0x437f5b7: (2, 0x437f5f2),  # block_plain: je
    0x437f5b9: (7, 0x4f76b30),  # block_plain: lea
    0x437f5d1: (6, 0x576f1e0),  # block_plain: call
    0x437f5ec: (6, 0x437f676),  # block_plain: jne
    0x437f610: (2, 0x437f688),  # block_plain: jne
    0x437f61e: (6, 0x437f92a),  # block_plain: jle
    0x437f628: (7, 0x57554d0),  # block_plain: lea
    0x437f666: (6, 0x437f6f0),  # block_plain: je
    0x437f66f: (2, 0x437f6d8),  # block_plain: jne
    0x437f671: (5, 0x437f704),  # block_plain: jmp
    0x437f676: (7, 0x6f1438),  # block_plain: lea
    0x437f682: (6, 0x576e468),  # block_plain: call
    0x437f6a3: (5, 0x4f769c0),  # block_plain: call
    0x437f6b1: (6, 0x437f612),  # block_plain: jne
    0x437f6ba: (7, 0x6f0ebd),  # block_plain: lea
    0x437f6c1: (7, 0x571cd48),  # block_plain: lea
    0x437f6d2: (6, 0x576e048),  # block_plain: call
    0x437f90e: (7, 0x571e8c0),  # block_plain_resume: lea
    0x437f915: (6, 0x576f038),  # block_plain_resume: call
    0x437f91b: (2, 0x437f92a),  # block_plain_resume: jmp
    0x437f91d: (7, 0x571e8c0),  # block_plain_resume: lea
    0x437f924: (6, 0x576f040),  # block_plain_resume: call
    0x437f9a2: (2, 0x437f9d6),  # block_slow: je
    0x437f9a7: (2, 0x437f9e2),  # block_slow: je
    0x437f9a9: (7, 0x4f76b30),  # block_slow: lea
    0x437f9c1: (6, 0x576f1e0),  # block_slow: call
    0x437f9dc: (6, 0x437fa66),  # block_slow: jne
    0x437fa00: (2, 0x437fa78),  # block_slow: jne
    0x437fa0e: (6, 0x437fd68),  # block_slow: jle
    0x437fa18: (7, 0x57554d0),  # block_slow: lea
    0x437fa56: (6, 0x437fae0),  # block_slow: je
    0x437fa5f: (2, 0x437fac8),  # block_slow: jne
    0x437fa61: (5, 0x437faf4),  # block_slow: jmp
    0x437fa66: (7, 0x6f1438),  # block_slow: lea
    0x437fa72: (6, 0x576e468),  # block_slow: call
    0x437fa93: (5, 0x4f769c0),  # block_slow: call
    0x437faa1: (6, 0x437fa02),  # block_slow: jne
    0x437faaa: (7, 0x6f0ebd),  # block_slow: lea
    0x437fab1: (7, 0x571cd48),  # block_slow: lea
    0x437fac2: (6, 0x576e048),  # block_slow: call
    0x437fd4c: (7, 0x571e8c0),  # block_slow_resume: lea
    0x437fd53: (6, 0x576f038),  # block_slow_resume: call
    0x437fd59: (2, 0x437fd68),  # block_slow_resume: jmp
    0x437fd5b: (7, 0x571e8c0),  # block_slow_resume: lea
    0x437fd62: (6, 0x576f040),  # block_slow_resume: call
    0x437fddf: (2, 0x437fe13),  # block_fast: je
    0x437fde4: (2, 0x437fe1f),  # block_fast: je
    0x437fde6: (7, 0x4f76b30),  # block_fast: lea
    0x437fdfe: (6, 0x576f1e0),  # block_fast: call
    0x437fe19: (6, 0x437fea3),  # block_fast: jne
    0x437fe3d: (2, 0x437feb5),  # block_fast: jne
    0x437fe4b: (6, 0x4380155),  # block_fast: jle
    0x437fe55: (7, 0x57554d0),  # block_fast: lea
    0x437fe93: (6, 0x437ff1d),  # block_fast: je
    0x437fe9c: (2, 0x437ff05),  # block_fast: jne
    0x437fe9e: (5, 0x437ff31),  # block_fast: jmp
    0x437fea3: (7, 0x6f1438),  # block_fast: lea
    0x437feaf: (6, 0x576e468),  # block_fast: call
    0x437fed0: (5, 0x4f769c0),  # block_fast: call
    0x437fede: (6, 0x437fe3f),  # block_fast: jne
    0x437fee7: (7, 0x6f0ebd),  # block_fast: lea
    0x437feee: (7, 0x571cd48),  # block_fast: lea
    0x437feff: (6, 0x576e048),  # block_fast: call
    0x4380139: (7, 0x571e8c0),  # block_fast_resume: lea
    0x4380140: (6, 0x576f038),  # block_fast_resume: call
    0x4380146: (2, 0x4380155),  # block_fast_resume: jmp
    0x4380148: (7, 0x571e8c0),  # block_fast_resume: lea
    0x438014f: (6, 0x576f040),  # block_fast_resume: call
    0x438cf6b: (7, 0x571edd0),  # resume_438cb90: lea
    0x438cf72: (6, 0x576f038),  # resume_438cb90: call
    0x438cf78: (2, 0x438cfa5),  # resume_438cb90: jmp
    0x438cf7a: (7, 0x571edd0),  # resume_438cb90: lea
    0x438cf81: (6, 0x576f040),  # resume_438cb90: call
    0x438e420: (7, 0x571edd0),  # resume_438e060: lea
    0x438e427: (6, 0x576f038),  # resume_438e060: call
    0x438e42d: (2, 0x438e45a),  # resume_438e060: jmp
    0x438e42f: (7, 0x571edd0),  # resume_438e060: lea
    0x438e436: (6, 0x576f040),  # resume_438e060: call
    0x4391c5d: (7, 0x571edd0),  # resume_4391840: lea
    0x4391c64: (6, 0x576f038),  # resume_4391840: call
    0x4391c6a: (5, 0x439228c),  # resume_4391840: jmp
    0x4391c6f: (7, 0x571edd0),  # resume_4391840: lea
    0x4391c76: (6, 0x576f040),  # resume_4391840: call
    0x439974e: (7, 0x571edd0),  # resume_4399360: lea
    0x4399755: (6, 0x576f038),  # resume_4399360: call
    0x439975b: (5, 0x4399d5b),  # resume_4399360: jmp
    0x4399760: (7, 0x571edd0),  # resume_4399360: lea
    0x4399767: (6, 0x576f040),  # resume_4399360: call
    0x439a256: (7, 0x571edd0),  # resume_4399e80: lea
    0x439a25d: (6, 0x576f038),  # resume_4399e80: call
    0x439a263: (5, 0x439a741),  # resume_4399e80: jmp
    0x439a268: (7, 0x571edd0),  # resume_4399e80: lea
    0x439a26f: (6, 0x576f040),  # resume_4399e80: call
    0x474bfcc: (7, 0x6fb7d1),  # fast_call: lea
    0x474bfdb: (8, 0x20aa00),  # fast_call: movsd
    0x474bfe8: (6, 0x5776560),  # fast_call: call
    0x474c0d5: (7, 0x572fcb0),  # fast_call: lea
    0x474c0dc: (5, 0x437fdb0),  # fast_call: call
    0x474c0ea: (6, 0x474dc2e),  # fast_call: je
    0x474dc36: (5, 0x47365a0),  # fast_none: call
    0x474dc3e: (5, 0x473a800),  # fast_none: call
    0x474dc46: (5, 0x4727510),  # fast_none: call
    0x47b06fc: (7, 0x572fcc8),  # resume_47b05f0: lea
    0x47b0703: (6, 0x576f038),  # resume_47b05f0: call
    0x47b0709: (2, 0x47b0750),  # resume_47b05f0: jmp
    0x47b070b: (7, 0x572fcc8),  # resume_47b05f0: lea
    0x47b0712: (6, 0x576f040),  # resume_47b05f0: call
    0x47b0e8c: (7, 0x572fcc8),  # resume_47b0db0: lea
    0x47b0e93: (6, 0x576f038),  # resume_47b0db0: call
    0x47b0e99: (2, 0x47b0ec6),  # resume_47b0db0: jmp
    0x47b0e9b: (7, 0x572fcc8),  # resume_47b0db0: lea
    0x47b0ea2: (6, 0x576f040),  # resume_47b0db0: call
    0x47b13ac: (7, 0x572fcc8),  # resume_47b12d0: lea
    0x47b13b3: (6, 0x576f038),  # resume_47b12d0: call
    0x47b13b9: (2, 0x47b1400),  # resume_47b12d0: jmp
    0x47b13bb: (7, 0x572fcc8),  # resume_47b12d0: lea
    0x47b13c2: (6, 0x576f040),  # resume_47b12d0: call
    0x47b1a0a: (7, 0x572fcc8),  # resume_47b1930: lea
    0x47b1a11: (6, 0x576f038),  # resume_47b1930: call
    0x47b1a17: (2, 0x47b1a44),  # resume_47b1930: jmp
    0x47b1a19: (7, 0x572fcc8),  # resume_47b1930: lea
    0x47b1a20: (6, 0x576f040),  # resume_47b1930: call
    0x47b3c40: (7, 0x572fcc8),  # resume_47b3b80: lea
    0x47b3c47: (6, 0x576f038),  # resume_47b3b80: call
    0x47b3c4d: (2, 0x47b3c7a),  # resume_47b3b80: jmp
    0x47b3c4f: (7, 0x572fcc8),  # resume_47b3b80: lea
    0x47b3c56: (6, 0x576f040),  # resume_47b3b80: call
    0x47b403f: (7, 0x572fcc8),  # resume_47b3f50: lea
    0x47b4046: (6, 0x576f038),  # resume_47b3f50: call
    0x47b404c: (2, 0x47b4079),  # resume_47b3f50: jmp
    0x47b404e: (7, 0x572fcc8),  # resume_47b3f50: lea
    0x47b4055: (6, 0x576f040),  # resume_47b3f50: call
    0x47b7080: (7, 0x572fcc8),  # resume_47b6f90: lea
    0x47b7087: (6, 0x576f038),  # resume_47b6f90: call
    0x47b708d: (2, 0x47b70d4),  # resume_47b6f90: jmp
    0x47b708f: (7, 0x572fcc8),  # resume_47b6f90: lea
    0x47b7096: (6, 0x576f040),  # resume_47b6f90: call
    0x47b76bf: (7, 0x572fcc8),  # resume_47b75e0: lea
    0x47b76c6: (6, 0x576f038),  # resume_47b75e0: call
    0x47b76cc: (2, 0x47b7713),  # resume_47b75e0: jmp
    0x47b76ce: (7, 0x572fcc8),  # resume_47b75e0: lea
    0x47b76d5: (6, 0x576f040),  # resume_47b75e0: call
    0x4b310f3: (7, 0x573e268),  # resume_4b31030: lea
    0x4b310fa: (6, 0x576f038),  # resume_4b31030: call
    0x4b31100: (2, 0x4b3114b),  # resume_4b31030: jmp
    0x4b31102: (7, 0x573e268),  # resume_4b31030: lea
    0x4b31109: (6, 0x576f040),  # resume_4b31030: call
    0x4b3c5ea: (7, 0x573e268),  # resume_4b3c560: lea
    0x4b3c5f1: (6, 0x576f038),  # resume_4b3c560: call
    0x4b3c5f7: (2, 0x4b3c624),  # resume_4b3c560: jmp
    0x4b3c5f9: (7, 0x573e268),  # resume_4b3c560: lea
    0x4b3c600: (6, 0x576f040),  # resume_4b3c560: call
}


class EvidenceError(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        rela = next((s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4), None)
        require(rela is not None and rela['size'] % 24 == 0, 'no well-formed .rela.dyn')
        self.relative = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)
        text = [s for s in self.secs if s['name'] == '.text']
        require(len(text) == 1, 'no single .text section')
        self.text = text[0]

    def offset(self, va, size=1):
        hits = [s for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, f'VA {va:#x}+{size} is not in exactly one file-backed section')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, start):
        hits = [f for f in self.fdes if f[0] == start]
        require(len(hits) == 1, f'{start:#x} is not exactly one FDE start')
        return hits[0]

    def containing(self, va):
        hits = [f for f in self.fdes if f[0] <= va < f[1]]
        require(len(hits) == 1, f'{va:#x} is not inside exactly one FDE')
        return hits[0][0]

    def target(self, va, length):
        if length == 2:
            return va + 2 + struct.unpack('<b', self.read(va + 1, 1))[0]
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]


def windows(img):
    out = {}
    for name, (fde, va, hexs) in WINDOWS.items():
        raw = bytes.fromhex(hexs)
        start, end = img.fde(fde)
        require(start <= va and va + len(raw) <= end, f'{name} window {va:#x} is outside FDE {fde:#x}')
        require(img.read(va, len(raw)) == raw, f'{name} at {va:#x}: bytes changed')
        out[name] = [hex(va), hex(va + len(raw))]
    return out


def windowed(va, size):
    return any(va >= w[1] and va + size <= w[1] + len(bytes.fromhex(w[2])) for w in WINDOWS.values())


def window_of(va):
    hits = [n for n, w in WINDOWS.items() if w[1] <= va < w[1] + len(bytes.fromhex(w[2]))]
    require(len(hits) == 1, f'{va:#x} is not in exactly one window')
    return hits[0]


def check_operands(img):
    out = {}
    for va, (n, want) in OPERANDS.items():
        require(windowed(va, n), f'operand at {va:#x} is outside every window')
        got = img.target(va, n)
        require(got == want, f'operand at {va:#x} goes to {got:#x}, not {want:#x}')
        out[hex(va)] = hex(got)
    return out


def op(img, va, prefix, target):
    """An instruction `prefix` + rel32/disp32 at `va` whose decoded target must be `target`."""
    raw = bytes.fromhex(prefix)
    n = len(raw) + 4
    require(windowed(va, n), f'instruction at {va:#x} is outside every window')
    require(img.read(va, len(raw)) == raw, f'instruction at {va:#x} is not {prefix}')
    require(OPERANDS.get(va) == (n, target), f'operand table at {va:#x} does not pin {target:#x}')
    got = img.target(va, n)
    require(got == target, f'operand at {va:#x} goes to {got:#x}, not {target:#x}')


def exact(img, va, hexs):
    raw = bytes.fromhex(hexs)
    require(windowed(va, len(raw)), f'instruction at {va:#x} is outside every window')
    require(img.read(va, len(raw)) == raw, f'instruction at {va:#x} is not {hexs}')


def location(img, va):
    ptr = img.relative.get(va)
    require(ptr is not None, f'Location {va:#x} has no RELATIVE file pointer')
    n, line, col = struct.unpack('<QII', img.read(va + 8, 16))
    require(0 < n < 256, f'Location {va:#x} has length {n}')
    path = img.read(ptr, n)
    require(all(0x20 <= c < 0x7f for c in path), f'Location {va:#x} path is not text')
    return path, line, col


def check_locations(img):
    require(img.data.count(PATH[PATH.index(b'/net_utils/'):]) == 1, 'channel.rs path is not unique in the file')
    require(img.read(PATH_VA, len(PATH)) == PATH, f'path string at {PATH_VA:#x} changed')
    found = {}
    for slot, addend in img.relative.items():
        if addend == PATH_VA:
            path, line, col = location(img, slot)
            require(path == PATH, f'Location {slot:#x} has a different length or path')
            found[slot] = (line, col)
    require(found == LOCATIONS, f'channel.rs Locations are {sorted((hex(k), v) for k, v in found.items())}')
    held = sorted(hex(s) for s, a in img.relative.items() if a in LOCATIONS)
    require(not held, f'RELATIVE slots {held} hold a channel.rs Location')
    path, line, col = location(img, TOKIO_RECV[0])
    require(f'{path.decode()}:{line}:{col}'.endswith(TOKIO_RECV[1]), f'Location {TOKIO_RECV[0]:#x} changed')
    return {hex(k): f'{line}:{col}' for k, (line, col) in sorted(LOCATIONS.items())}


def census(img):
    """Every RIP-relative disp32 in .text that resolves to a channel.rs Location, and every e8 call to a helper."""
    t = img.text
    raw = img.read(t['address'], t['size'])
    base = t['address']
    refs = {}
    for m in re.finditer(rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', raw):
        p = m.start() + 1
        if p + 4 > len(raw):
            continue
        tgt = base + p + 4 + struct.unpack_from('<i', raw, p)[0]
        if tgt in LOCATIONS:
            start = p - 3
            require(raw[start] in (0x48, 0x4c) and raw[start + 1] == 0x8d,
                    f'reference to Location {tgt:#x} at {base + p:#x} is not a REX.W lea')
            refs[base + start] = tgt
    calls = {h: [] for h in HELPERS}
    for m in re.finditer(rb'\xe8', raw):
        p = m.start()
        if p + 5 > len(raw):
            continue
        tgt = base + p + 5 + struct.unpack_from('<i', raw, p + 1)[0]
        if tgt in calls:
            calls[tgt].append(base + p)
    held = sorted(hex(s) for s, a in img.relative.items() if a in HELPERS)
    require(not held, f'RELATIVE slots {held} hold a blocking helper')
    return refs, calls


def check_const_panics(img):
    out = {}
    for slot, (fn, msg_va, msg) in CONST_PANICS.items():
        require(img.relative.get(slot) == fn, f'slot {slot:#x} no longer holds {fn:#x}')
        exact(img, fn, '554889e54889fa')
        op(img, fn + 7, '488d3d', msg_va)
        exact(img, fn + 14, 'be' + struct.pack('<I', 2 * len(msg) + 1).hex())
        op(img, fn + 19, 'ff15', PANIC_FMT_SLOT)
        require(img.read(msg_va, len(msg)) == msg, f'message at {msg_va:#x} changed')
        out[hex(slot)] = dict(function=hex(fn), message=msg.decode(), esi=2 * len(msg) + 1)
    return out


def check_resume(img, refs):
    seen = set()
    out = {}
    for fde, (loc, pair) in RESUME.items():
        require(LOCATIONS.get(loc) == (93, 47), f'{fde:#x}: {loc:#x} is not a 93:47 Location')
        slots = []
        for ref in pair:
            require(img.containing(ref) == fde, f'{ref:#x} is not inside FDE {fde:#x}')
            op(img, ref, '488d3d', loc)
            slot = img.target(ref + 7, 6)
            op(img, ref + 7, 'ff15', slot)
            slots.append(slot)
            seen.add(ref)
        require(sorted(slots) == sorted((COMPLETION_SLOT, PANICKING_SLOT)),
                f'{fde:#x}: 93:47 goes to {[hex(s) for s in slots]}, not one completion and one panicking panic')
        out[hex(fde)] = dict(location=hex(loc), refs=[hex(r) for r in pair],
                             panics=['completion' if s == COMPLETION_SLOT else 'panicking' for s in slots])
    census_9347 = {r for r, l in refs.items() if LOCATIONS[l] == (93, 47)}
    require(census_9347 == seen, f'93:47 references outside the resume pairs: {sorted(hex(r) for r in census_9347 ^ seen)}')
    return out


def check_helper(img, helper):
    h = HELPERS[helper]
    exact(img, h['save'], '4989d7')
    exact(img, h['restore'], '4c89fa')
    op(img, h['expect'], '488d3d', h['msg'])
    exact(img, h['expect'] + 7, 'beb8000000')
    op(img, h['expect'] + 12, 'ff15', EXPECT_SLOT)
    exact(img, h['resave'], '4989d7')
    exact(img, h['r8'], '4d89f8')
    op(img, h['unwrap'], '488d3d', h['umsg'])
    exact(img, h['unwrap_call'] - 5, 'be2b000000')
    op(img, h['unwrap_call'], 'ff15', UNWRAP_SLOT)
    require(img.read(h['msg'], len(BLOCK_MESSAGE)) == BLOCK_MESSAGE, f'{helper:#x}: blocking message changed')
    require(img.read(h['umsg'], len(UNWRAP_MESSAGE)) == UNWRAP_MESSAGE, f'{helper:#x}: unwrap message changed')
    slots = []
    for ref in h['resume']:
        op(img, ref, '488d3d', TOKIO_RECV[0])
        slot = img.target(ref + 7, 6)
        op(img, ref + 7, 'ff15', slot)
        slots.append(slot)
    require(sorted(slots) == sorted((COMPLETION_SLOT, PANICKING_SLOT)), f'{helper:#x}: recv resume panics changed')
    start, end = img.fde(helper)
    return dict(fde=[hex(start), hex(end)], caller_location='rdx, kept in r15',
                expect=hex(h['expect']), unwrap=hex(h['unwrap_call']), future_resume=TOKIO_RECV[1])


def check_blocking(img, calls):
    out = {}
    for name, b in BLOCKING.items():
        require(img.containing(b['site']) == b['fde'], f'{name}: site outside {b["fde"]:#x}')
        op(img, b['site'], '488d15', 0x572fcb0)
        op(img, b['call'], 'e8', b['helper'])
        require(calls[b['helper']] == [b['call']], f'{name}: helper {b["helper"]:#x} callers are '
                f'{[hex(c) for c in calls[b["helper"]]]}')
        exact(img, b['test'], b['test_hex'])
        op(img, b['branch'], '0f84', b['none'])
        none = window_of(b['none'])
        start = WINDOWS[none][1]
        end = start + len(bytes.fromhex(WINDOWS[none][2]))
        require(start == b['none'] and end == b['ret'] + 1, f'{name}: None window is not {b["none"]:#x}..ret')
        exact(img, b['ret'], 'c3')
        bad = [hex(va) for va, (n, tgt) in OPERANDS.items() if start <= va < end and (tgt in PANIC_SLOTS or tgt in LOCATIONS)]
        require(not bad, f'{name}: None path reaches a panic at {bad}')
        rec = dict(caller=hex(b['fde']), site=hex(b['site']), helper=hex(b['helper']),
                   none=f'{b["none"]:#x}..{b["ret"]:#x} returns, no panic')
        if b['sampler']:
            lea, sva, s, mv, fva, fval, ln, call = b['sampler']
            op(img, lea, '488d35', sva)
            require(img.read(sva, len(s)) == s, f'{name}: sampler name changed')
            op(img, mv, 'f20f1005', fva)
            require(struct.unpack('<d', img.read(fva, 8))[0] == fval, f'{name}: sampler f64 changed')
            exact(img, ln, 'ba' + struct.pack('<I', len(s)).hex())
            op(img, call, 'ff15', SAMPLER_NEW_SLOT)
            require(img.relative.get(SAMPLER_NEW_SLOT) == SAMPLER_NEW, 'sampler constructor slot changed')
            rec['sampler'] = dict(constructor=hex(SAMPLER_NEW), name=s.decode(), f64=fval)
        out[name] = rec
    return out


def check_inline(img):
    i = INLINE
    require(img.containing(i['expect']) == i['fde'], 'inline copy moved')
    op(img, i['expect'], '488d3d', i['msg'])
    op(img, i['loc_rdx'], '488d15', i['location'])
    exact(img, i['len_b8'], 'beb8000000')
    op(img, i['expect_call'], 'ff15', EXPECT_SLOT)
    op(img, i['unwrap'], '488d3d', i['umsg'])
    op(img, i['loc_r8'], '4c8d05', i['location'])
    exact(img, i['len_2b'], 'be2b000000')
    op(img, i['unwrap_call'], 'ff15', UNWRAP_SLOT)
    require(img.read(i['msg'], len(BLOCK_MESSAGE)) == BLOCK_MESSAGE, 'inline blocking message changed')
    require(img.read(i['umsg'], len(UNWRAP_MESSAGE)) == UNWRAP_MESSAGE, 'inline unwrap message changed')
    return dict(fde=hex(i['fde']), expect=hex(i['expect_call']), unwrap=hex(i['unwrap_call']), location=hex(i['location']))


def check_117(refs):
    sites = {r for r, l in refs.items() if LOCATIONS[l] == (117, 30)}
    want = {b['site'] for b in BLOCKING.values()} | {INLINE['loc_rdx'], INLINE['loc_r8']}
    require(sites == want, f'117:30 references are {sorted(hex(s) for s in sites)}')


def lead(resume):
    async_fdes = {int(k, 16) for k in resume}
    blocking = {b['fde'] for b in BLOCKING.values()} | {INLINE['fde']}
    seeds = set(LEAD_SEEDS)
    require(seeds <= async_fdes | blocking, 'a lead seed has no channel.rs Location')
    return dict(seeds_with_93_47=sorted(hex(s) for s in seeds & async_fdes),
                seeds_with_117_30=sorted(hex(s) for s in seeds & blocking),
                not_seeds_with_93_47=sorted(hex(s) for s in async_fdes - seeds))


# ---- models -------------------------------------------------------------------------------------------------


class Panic(Exception):
    pass


def blocking_recv(queue, senders, in_runtime=False, parker=True):
    """The 117:30 path: Tokio `future::block_on(UnboundedReceiver::recv())`, panics carry channel.rs:117:30."""
    if in_runtime:
        raise Panic('Cannot block the current thread from within a runtime @ channel.rs:117:30')
    if not parker:
        raise Panic('called `Result::unwrap()` on an `Err` value @ channel.rs:117:30')
    if queue:
        return queue.pop(0)
    if senders == 0:
        return None
    return 'blocked'


def receive_loop(queue, senders):
    """The callers: handle messages until the None value, then return."""
    handled = []
    while True:
        item = blocking_recv(queue, senders)
        if item is None:
            return handled
        if item == 'blocked':
            return handled + ['blocked']
        handled.append(item)


def lead_recv(queue, senders):
    """The lead's `Receiver::recv`: `rx.recv().await.unwrap()` with the panic at channel.rs:93:47."""
    if queue:
        return queue.pop(0)
    if senders == 0:
        raise Panic('called `Option::unwrap()` on a `None` value @ channel.rs:93:47')
    return 'blocked'


def analyse(data):
    img = Image(data)
    wins = windows(img)
    ops = check_operands(img)
    locs = check_locations(img)
    refs, calls = census(img)
    consts = check_const_panics(img)
    resume = check_resume(img, refs)
    check_117(refs)
    helpers = {hex(h): check_helper(img, h) for h in HELPERS}
    blocking = check_blocking(img, calls)
    inline = check_inline(img)
    return dict(
        target=TARGET,
        path=dict(va=hex(PATH_VA), text=PATH.decode()),
        locations=locs,
        const_panics=consts,
        async_fn_93_47=resume,
        blocking_117_30=dict(callers=blocking, helpers=helpers, inline=inline),
        census=dict(scanned='.text, every disp32 after a RIP-relative ModRM byte; every e8 rel32; RELATIVE slots',
                    references=len(refs), references_93_47=sum(LOCATIONS[l] == (93, 47) for l in refs.values()),
                    references_117_30=sum(LOCATIONS[l] == (117, 30) for l in refs.values()),
                    helper_callers={hex(h): [hex(c) for c in v] for h, v in calls.items()}),
        lead=lead(resume),
        windows=wins,
        operands=ops,
    )


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--json', action='store_true')
    a = p.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == TARGET)
    path = ROOT / TARGET
    check(path, identity)
    rec = dict(analyse(path.read_bytes()), target_sha256=identity['sha256'])
    if a.json:
        print(json.dumps(rec, indent=2, sort_keys=True))
        return 0
    c = rec['census']
    print(f'channel.rs Locations: {len(rec["locations"])} ({c["references"]} lea references)')
    print(f'93:47: async fn resume panics in {len(rec["async_fn_93_47"])} FDEs, one completion and one panicking each')
    print('117:30: Tokio blocking path caller Location (expect + Result::unwrap) in '
          f'{", ".join(b["caller"] for b in rec["blocking_117_30"]["callers"].values())} and {rec["blocking_117_30"]["inline"]["fde"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
