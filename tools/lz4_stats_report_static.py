#!/usr/bin/env python3
"""Static node #94 LZ4 stats report loops `0x3d21990` / `0x3d12780`, checked from authenticated bytes.

Question: what does the `net_utils/tcp/lz4_stats.rs` report path do every
300 s, and where does it go?  The can1357 lead (`net_utils/tcp/lz4_stats.rs`
`report_once`, `drain_snapshots`, `report_task_tick`) builds one inbound and
one outbound report from the drained snapshots, keeps output bytes and an
elapsed time in each snapshot, and emits `tcp_lz4_stats` tracing text.

In the binary both loops (one wrapped in a tracing span, one in a
tokio-metrics instrumented future) sleep 300.0 s, lock the global table
behind the parking_lot mutex `0x5786530`, and collect rows with `0x3d2ba50`.
Every entry's three counters are swapped to zero and added to three totals
with overflow panics before the filter, so the totals cover every entry and
both directions.  The rows (key, counter 0, counter 2, counter 1 / counter
0) go to the block-times reporter `0x3d1dde0` when there are any, and one
total row (total 0, total 2, total 1 / total 0) goes to `0x3d1e500` when
total 0 is non-zero.  Both writers return before any file work when the
writer slot is None, rotate `{root}/{date}` or `{root}/hourly/{date}/{hour}`
and call the writer helper at most once.  The reporter is built from
`tcp_lz4_stats` by `0x1402050`.

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; call, branch and RIP-relative
targets, two packed format templates, string literals, f64 constants, six
panic Locations, RELATIVE slots and the callers of every function in scope
are decoded here.  Nothing from the binary is executed.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = 'artifacts/node/94/hl-node'
REPORT = 0x3d21990
METRICS = 0x3d12780
COLLECT = 0x3d2ba50
DRAIN = 0x3d230c0
ROWS_WRITER = 0x3d1dde0
TOTAL_WRITER = 0x3d1e500
ENTRY = 0x3d27940
ENTRY_SLOT = 0x5786520
MUTEX = 0x5786530
ONCE = 0x5786568
TABLE = {0x5786538: 'ctrl', 0x5786540: 'bucket_mask', 0x5786550: 'items'}
PERIOD = 300.0
LOCATIONS = {
    0x5719410: '/net_utils/src/tcp/lz4_stats.rs:81:42',
    0x57199c0: '/net_utils/src/tcp/lz4_stats.rs:96:21',
    0x57199d8: '/net_utils/src/tcp/lz4_stats.rs:97:21',
    0x57199f0: '/net_utils/src/tcp/lz4_stats.rs:98:21',
    0x566aac8: '/base/src/time.rs:62:44',
    0x5666dd8: '/base/src/hour.rs:12:13',
}
TEMPLATES = {
    0x1e938e: (2, [None, '/', None]),
    0x1e9393: (3, [None, '/hourly/', None, '/', None]),
}

WINDOWS = {
    'report': (REPORT, 0x3d21990,
        '415741564154534881ec880000004989f74889fb488b0f4883f9027426488d7318488b7b08488b4310f6c1017412488b'
        '481048ffc94883e1f04801cf4883c710ff50604c8d73280fb6837801000085c00f843002000083f8030f848000000048'
        '8d3d1a7a9f01ff153cd6a4010f0b'),
    'report_loop': (REPORT, 0x3d21a6f,
        '488dbbd80000004c89fee8b2cdffff84c00f85ad01000080bb7001000003751580bb6801000003750c488dbbf0000000'
        'e8cce7ffff48c74424080000000048c74424100000000048c7442418000000008b05a34aa60185c00f85ad010000b101'
        '31c0f00fb00d574aa6010f85db010000488b05524aa601488b0d534aa6014801c148ffc1660f6f00660fd7d0f7d2488b'
        '354c4aa60148894424484883c010488944245048894c245866895424604889742468488d4424084889442470488d4424'
        '104889442478488d4424184889842480000000488d7c2420488d742448e8ff9e000031c9b001f00fb00dd349a6010f85'
        '6e0100004c8b6424304d85e47412488d7c2448488d5424204c89f6e861c2ffff488b4424084885c0746df20f10442410'
        'f20f100de9224efc0f14c1660f2815fe124efc660f5cc2660f28d8660f15d8f20f58d866480f6ec0660f62c1660f5cc2'
        '660f28c8660f15c8f20f58c8f20f5ed9488b4c2418488944244848894c2450f20f115c2458488d7c2438488d5424484c'
        '89f6e80ac9ffff4d85e4751b488b7424204885f67411488b7c242848c1e60531d2ff15fac3a40148b80000000000c072'
        '40488983d8000000c6837001000000e93cfeffffc6837801000003488b0b4883f9027426488d7318488b7b08488b4310'
        'f6c1017412488b481048ffc94883e1f04801cf4883c710ff5068b0014881c4880000005b415c415e415fc3488d05af48'
        'a6014889442438488d4424384889442448488d3dd148a601488d0d5a749f014c8d057b749f01488d542448be01000000'
        'ff1503cca401e913feffff488d3d6f48a601ba00ca9a3bff1564d2a401e90efeffff488d3d5848a60131f6ff1558d2a4'
        '01e97efeffff'),
    'metrics_loop': (METRICS, 0x3d12afc,
        '488dbbb8000000488db42498000000e8d0c3ffff84c00f85db01000080bb5001000003751580bb4801000003750c488d'
        'bbd0000000e8dacbffff48c78424800000000000000048c78424880000000000000048c7842490000000000000008b05'
        '083aa70185c00f85b0020000b10131c0f00fb00dbc39a7010f85de020000488b05b739a701488b0db839a7014801c148'
        'ffc1660f6f00660fd7d0f7d2488b35b139a70148894424304883c010488944243848894c244066895424484889742450'
        '488d8424800000004889442458488d8424880000004889442460488d8424900000004889442468488d7c2408488d7424'
        '30e85e8e010031c9b001f00fb00d3239a7010f856b0200004c8b6424184d85e47428488b4424184889442440f30f6f44'
        '2408660f7f442430488d7c2420488d5424304c89f6e8aab10000488b8424800000004885c07473f20f10842488000000'
        'f20f100d2c124ffc0f14c1660f281541024ffc660f5cc2660f28d8660f15d8f20f58d866480f6ec0660f62c1660f5cc2'
        '660f28c8660f15c8f20f58c8f20f5ed9488b8c2490000000488944243048894c2438f20f115c2440488d7c2420488d54'
        '24304c89f6e84ab800004d85e4751b488b7424084885f67411488b7c241048c1e60531d2ff153ab3a50148b800000000'
        '00c07240488983b8000000c6835001000000e909feffff'),
    'metrics_slow': (METRICS, 0x3d12e18,
        '488d051137a7014889442420488d4424204889442430488d3d3337a701488d0d3c5ca0014c8d055d5ca001488d542430'
        'be01000000ff1565baa501e910fdffff488d3dd136a701ba00ca9a3bff15c6c0a501e90bfdffff488d3dba36a70131f6'
        'ff15bac0a501'),
    'collect': (COLLECT, 0x3d2ba50,
        '554157415641554154534881ecd80000004889f34989fe488d5640488d7c2430e84b76ffff0fb66c24364080fd02751c'
        '49c7060000000049c746080800000049c7461000000000e9a20100004c897424280fb744243466894424048b44243089'
        '04240f104424370f294424700f104424400f11442479bf80000000ff150725a4014885c00f84790100004989c60fb744'
        '240466418946048b042441890641886e060f28442470410f1146070f10442479410f11461048c7442410040000004c89'
        '74241848c7442420010000000f10030f104b100f1053200f105b300f295c24600f295424500f294c24400f2944243041'
        'bc01000000bb270000004c8dbc24bf000000488d6c2430eb470f1f80000000000fb744240c664189441efd8b44240841'
        '89441ef945886c1eff0f28842490000000410f11041e0f10842499000000410f11441e0949ffc44c896424204883c320'
        '488dbc24b80000004889ee488d542470e80b75ffff440fb6ac24be0000004180fd0274630fb78424bc00000066894424'
        '0c8b8424b800000089442408410f1007410f104f090f298424900000000f118c24990000004c3b6424100f8560ffffff'
        'ba01000000b90800000041b820000000488d7c24104c89e6e8e3cfffff4c8b742418e939ffffff488b4424204c8b7424'
        '28498946100f10442410410f11064c89f04881c4d80000005b415c415d415e415f5dc3'),
    'drain_entry': (DRAIN, 0x3d23159,
        '4a8b5cfad84e8b64fae04531f64d877424104e8b64fae84531ed4d876c24104e8b64faf04531ff4d877c24104c8b274d'
        '01f40f82e00000004c89274d8b214d01ec0f82de0000004d89214d8b224d01fc0f82b50000004d89224d85f6400f94c5'
        '4989dc49c1ec304180fc020f94c14008e974174885c00f852bffffff41b402488b3c24eb7041b402eb6b66490f6ec5f3'
        '0f7e0d900c4efc660f62c1660f2815a4fc4dfc660f5cc2660f28d8660f15d8f20f58d866490f6ec6660f62c1660f5cc2'
        '660f28c8660f15c8f20f58c8f20f5ed94889d848c1e838488b3c24891f48c1eb2066895f048847074c8977084c897f10'
        'f20f115f18448867064889f84883c4085b415c415d415e415f5dc3488d3d85679f01ff15a7aea401488d3d48679f01ff'
        '159aaea401488d3d53679f01ff158daea401'),
    'rows_writer': (ROWS_WRITER, 0x3d1dde0,
        '554157415641554154534881eca80000004989d64989f74889fbff15a00aa501498b46104889842488000000410f1006'
        '0f114424788b430889442470488b03488944246831c0493b47480f804d0200008b43043d00100e000f83720200003d90'
        '5f01000f838e0200008b2b4d8d77484180bfa8000000010f85ff00000089c041bdc5b3a2914c0fafe849c1ed2b4538af'
        'a9000000750d413baf980000000f8490010000410f104708896c240444886c24030f11442458488d4424584889442408'
        '488d0509fc7bfd4889442410488d4424044889442418488b05a30ba5014889442420488d4424034889442428488b054d'
        '0ca5014889442430488d35b4b44cfc488dbc2490000000488d542408ff154e01a5014c8d642408488db424900000004c'
        '89e7ff15b80ba5014c89f7e8302200000f10442448410f1146400f104424080f104c24180f105424280f105c2438410f'
        '115e30410f115620410f114e10410f11064189af9800000041c687a8000000014588afa9000000e9b7000000413baf98'
        '0000000f84aa000000410f104708896c24040f11442458488d4424584889442408488d0528fb7bfd4889442410488d44'
        '24044889442418488b05c20aa5014889442420488d35e4b34cfc488dbc2490000000488d542408ff158300a5014c8d64'
        '2408488db424900000004c89e7ff15ed0aa5014c89f7e8652100000f10442448410f1146400f104424080f104c24180f'
        '105424280f105c2438410f115e30410f115620410f114e10410f11064189af980000004c89742408488d742410488b03'
        '48894424108b430889442418488d5424684c89f7e8d76500008b4308418987a4000000488b034989879c0000004180bf'
        'aa000000007426488b05ba0ea5010fb60084c0741848b8000000000000008049390674094c89f7ff152b0aa501488b74'
        '24784885f67414488bbc248000000048c1e60531d2ff1575ffa4014889d84881c4a80000005b415c415d415e415f5dc3'
        '488d3df3bc4ffc488d0d82cb94014c8d0503ca9401488d542408be2b000000ff1573ffa401eb19488d3d4b8e4ffc488d'
        '15f38c9401be1c000000ff151800a5010f0b'),
    'total_writer': (TOTAL_WRITER, 0x3d1e500,
        '554157415641554154534881eca80000004989d64989f74889fbff158003a5018b430889442470488b03488944246849'
        '8b46104889842488000000410f10060f1144247831c0493b47480f804b0200008b43043d00100e000f83520200003d90'
        '5f01000f836c0200008b2b4d8d77484180bfa8000000010f85ff00000089c041bdc5b3a2914c0fafe849c1ed2b4538af'
        'a9000000750d413baf980000000f848e010000410f104708896c240444886c24030f11442458488d4424584889442408'
        '488d05e9f47bfd4889442410488d4424044889442418488b058304a5014889442420488d4424034889442428488b052d'
        '05a5014889442430488d3594ad4cfc488dbc2490000000488d542408ff152efaa4014c8d6424084c89e7488db4249000'
        '0000ff159804a5014c89f7e8101b00000f10442448410f1146400f104424080f104c24180f105424280f105c2438410f'
        '115e30410f115620410f114e10410f11064189af9800000041c687a8000000014588afa9000000e9b5000000413baf98'
        '0000000f84a8000000410f104708896c24040f11442458488d4424584889442408488d0508f47bfd4889442410488d44'
        '24044889442418488b05a203a5014889442420488d35c4ac4cfc4c8dac2490000000488d5424084c89efff1560f9a401'
        '4c8d6424084c89e74c89eeff15cf03a5014c89f7e8471a00000f10442448410f1146400f104424080f104c24180f1054'
        '24280f105c2438410f115e30410f115620410f114e10410f11064189af980000004c89742408488d742410488b034889'
        '4424108b430889442418488d5424684c89f7e8d95900008b4308418987a4000000488b034989879c0000004180bfaa00'
        '0000007426488b059c07a5010fb60084c0741848b8000000000000008049390674094c89f7ff150d03a5014889d84881'
        'c4a80000005b415c415d415e415f5dc3488d3df3b54ffc488d0d82c494014c8d0503c39401488d542408be2b000000ff'
        '1573f8a401488d3d4d874ffc488d15f5859401be1c000000ff151af9a401'),
    'entry': (ENTRY, 0x3d27940,
        '4881ec78010000488d7c2418488d35085789fcba0d000000ff15b275a401488d05035789fc488944240848c744241009'
        '000000c684246801000000c684247001000001488d7c2408e8237dffff4881c478010000c3'),
}

FACTS = {
    0x3d2199e: ('4989f7', 'cx'),
    0x3d219a1: ('4889fb', 'self'),
    0x3d219a4: ('488b0f', 'span tag [self]'),
    0x3d219a7: ('4883f902', 'tag 2 is no span'),
    0x3d219ab: ('7426', 'no span skips enter'),
    0x3d219d0: ('ff5060', 'span enter [vtable+0x60]'),
    0x3d219d3: ('4c8d7328', 'reporter self+0x28'),
    0x3d219d7: ('0fb68378010000', 'state byte +0x178'),
    0x3d219e0: ('0f8430020000', 'state 0 starts'),
    0x3d219e6: ('83f803', 'state 3'),
    0x3d219e9: ('0f8480000000', 'state 3 resumes'),
    0x3d219ef: ('488d3d1a7a9f01', 'resumed Location'),
    0x3d219f6: ('ff153cd6a401', 'panic'),
    0x3d21a6f: ('488dbbd8000000', 'sleep self+0xd8'),
    0x3d21a76: ('4c89fe', 'cx'),
    0x3d21a79: ('e8b2cdffff', 'poll sleep'),
    0x3d21a7e: ('84c0', 'poll result'),
    0x3d21a80: ('0f85ad010000', 'Pending'),
    0x3d21a86: ('80bb7001000003', 'sleep state +0x170'),
    0x3d21a8f: ('80bb6801000003', 'sleep state +0x168'),
    0x3d21a9f: ('e8cce7ffff', 'drop sleep'),
    0x3d21aa4: ('48c744240800000000', 'total0 = 0'),
    0x3d21aad: ('48c744241000000000', 'total1 = 0'),
    0x3d21ab6: ('48c744241800000000', 'total2 = 0'),
    0x3d21abf: ('8b05a34aa601', 'once state 0x5786568'),
    0x3d21ac7: ('0f85ad010000', 'not initialised'),
    0x3d21ad1: ('f00fb00d574aa601', 'lock 0x5786530'),
    0x3d21ad9: ('0f85db010000', 'contended'),
    0x3d21adf: ('488b05524aa601', 'table ctrl'),
    0x3d21ae6: ('488b0d534aa601', 'bucket mask'),
    0x3d21afd: ('488b354c4aa601', 'items'),
    0x3d21b21: ('488d442408', '&total0'),
    0x3d21b2b: ('488d442410', '&total1'),
    0x3d21b35: ('488d442418', '&total2'),
    0x3d21b26: ('4889442470', 'iter+0x28'),
    0x3d21b30: ('4889442478', 'iter+0x30'),
    0x3d21b3a: ('4889842480000000', 'iter+0x38'),
    0x3d21b4c: ('e8ff9e0000', 'collect'),
    0x3d21b55: ('f00fb00dd349a601', 'unlock'),
    0x3d21b5d: ('0f856e010000', 'waiters'),
    0x3d21b63: ('4c8b642430', 'rows len'),
    0x3d21b6b: ('7412', 'no rows skips'),
    0x3d21b77: ('4c89f6', 'reporter'),
    0x3d21b7a: ('e861c2ffff', 'rows writer'),
    0x3d21b7f: ('488b442408', 'total0'),
    0x3d21b87: ('746d', 'total0 == 0 skips'),
    0x3d21b89: ('f20f10442410', 'total1'),
    0x3d21bcb: ('f20f5ed9', 'total1 / total0'),
    0x3d21bcf: ('488b4c2418', 'total2'),
    0x3d21bd4: ('4889442448', 'row +0x00 total0'),
    0x3d21bd9: ('48894c2450', 'row +0x08 total2'),
    0x3d21bde: ('f20f115c2458', 'row +0x10 ratio'),
    0x3d21bf1: ('e80ac9ffff', 'total writer'),
    0x3d21bf9: ('751b', 'rows were moved'),
    0x3d21c10: ('ff15fac3a401', 'free empty Vec'),
    0x3d21c16: ('48b80000000000c07240', '300.0'),
    0x3d21c20: ('488983d8000000', 'sleep seconds'),
    0x3d21c27: ('c6837001000000', 'sleep state 0'),
    0x3d21c2e: ('e93cfeffff', 'loop'),
    0x3d21c33: ('c6837801000003', 'state 3'),
    0x3d21c66: ('ff5068', 'span exit [vtable+0x68]'),
    0x3d21c69: ('b001', 'Pending'),
    0x3d21c79: ('c3', 'ret'),
    0x3d21caf: ('ff1503cca401', 'once'),
    0x3d21cb5: ('e913feffff', 'back'),
    0x3d21cc1: ('ba00ca9a3b', 'no timeout'),
    0x3d21cc6: ('ff1564d2a401', 'lock_slow'),
    0x3d21cda: ('ff1558d2a401', 'unlock_slow'),
    0x3d12b0b: ('e8d0c3ffff', 'poll sleep'),
    0x3d12b12: ('0f85db010000', 'Pending'),
    0x3d12b31: ('e8dacbffff', 'drop sleep'),
    0x3d12b36: ('48c784248000000000000000', 'total0 = 0'),
    0x3d12b42: ('48c784248800000000000000', 'total1 = 0'),
    0x3d12b4e: ('48c784249000000000000000', 'total2 = 0'),
    0x3d12b5a: ('8b05083aa701', 'once state'),
    0x3d12b62: ('0f85b0020000', 'not initialised'),
    0x3d12b6c: ('f00fb00dbc39a701', 'lock'),
    0x3d12b74: ('0f85de020000', 'contended'),
    0x3d12bed: ('e85e8e0100', 'collect'),
    0x3d12bf6: ('f00fb00d3239a701', 'unlock'),
    0x3d12c04: ('4c8b642418', 'rows len'),
    0x3d12c0c: ('7428', 'no rows skips'),
    0x3d12c31: ('e8aab10000', 'rows writer'),
    0x3d12c36: ('488b842480000000', 'total0'),
    0x3d12c41: ('7473', 'total0 == 0 skips'),
    0x3d12c43: ('f20f10842488000000', 'total1'),
    0x3d12c88: ('f20f5ed9', 'total1 / total0'),
    0x3d12c8c: ('488b8c2490000000', 'total2'),
    0x3d12cb1: ('e84ab80000', 'total writer'),
    0x3d12cd0: ('ff153ab3a501', 'free empty Vec'),
    0x3d12cd6: ('48b80000000000c07240', '300.0'),
    0x3d12ce0: ('488983b8000000', 'sleep seconds'),
    0x3d12ce7: ('c6835001000000', 'sleep state 0'),
    0x3d12cee: ('e909feffff', 'loop'),
    0x3d12e4d: ('ff1565baa501', 'once'),
    0x3d12e5f: ('ba00ca9a3b', 'no timeout'),
    0x3d12e64: ('ff15c6c0a501', 'lock_slow'),
    0x3d12e78: ('ff15bac0a501', 'unlock_slow'),
    0x3d2ba67: ('488d5640', 'totals at iter+0x40'),
    0x3d2ba70: ('e84b76ffff', 'first drain'),
    0x3d2ba75: ('0fb66c2436', 'tag byte 6'),
    0x3d2ba7a: ('4080fd02', '2 is None'),
    0x3d2ba7e: ('751c', 'first row'),
    0x3d2ba80: ('49c70600000000', 'empty cap 0'),
    0x3d2ba87: ('49c7460808000000', 'dangling 8'),
    0x3d2ba8f: ('49c7461000000000', 'len 0'),
    0x3d2bac6: ('bf80000000', '0x80 bytes'),
    0x3d2bacb: ('ff150725a401', 'alloc'),
    0x3d2bb05: ('48c744241004000000', 'cap 4'),
    0x3d2bb13: ('48c744242001000000', 'len 1'),
    0x3d2bb9c: ('4883c320', 'stride 0x20'),
    0x3d2bbb0: ('e80b75ffff', 'next drain'),
    0x3d2bbbe: ('4180fd02', '2 is None'),
    0x3d2bbc2: ('7463', 'end'),
    0x3d2bbf5: ('4c3b642410', 'len == cap'),
    0x3d2bc0a: ('41b820000000', 'element 0x20'),
    0x3d2bc18: ('e8e3cfffff', 'grow'),
    0x3d2bc31: ('49894610', 'len'),
    0x3d2bc3a: ('410f1106', 'cap and ptr'),
    0x3d23166: ('4d87742410', 'counter 0 = xchg 0'),
    0x3d23173: ('4d876c2410', 'counter 1 = xchg 0'),
    0x3d23180: ('4d877c2410', 'counter 2 = xchg 0'),
    0x3d23188: ('4d01f4', 'total0 += counter 0'),
    0x3d2318b: ('0f82e0000000', 'carry panics'),
    0x3d23197: ('4d01ec', 'total1 += counter 1'),
    0x3d2319a: ('0f82de000000', 'carry panics'),
    0x3d231a6: ('4d01fc', 'total2 += counter 2'),
    0x3d231a9: ('0f82b5000000', 'carry panics'),
    0x3d231b2: ('4d85f6', 'counter 0 == 0'),
    0x3d231b5: ('400f94c5', 'sete'),
    0x3d231bc: ('49c1ec30', 'key >> 48'),
    0x3d231c0: ('4180fc02', 'byte 6 == 2'),
    0x3d231c7: ('4008e9', 'either'),
    0x3d231ca: ('7417', 'neither: emit'),
    0x3d231cc: ('4885c0', 'items left'),
    0x3d231cf: ('0f852bffffff', 'next entry'),
    0x3d231d5: ('41b402', 'None'),
    0x3d231e3: ('66490f6ec5', 'xmm0 = counter 1'),
    0x3d2320c: ('66490f6ec6', 'xmm0 = counter 0'),
    0x3d23225: ('f20f5ed9', 'counter 1 / counter 0'),
    0x3d23234: ('891f', 'row key low 4'),
    0x3d2323a: ('66895f04', 'row key u16'),
    0x3d2323e: ('884707', 'row byte 7'),
    0x3d23241: ('4c897708', 'row +0x08 counter 0'),
    0x3d23245: ('4c897f10', 'row +0x10 counter 2'),
    0x3d23249: ('f20f115f18', 'row +0x18 ratio'),
    0x3d2324e: ('44886706', 'row byte 6'),
    0x3d23264: ('488d3d85679f01', 'total2 Location'),
    0x3d2326b: ('ff15a7aea401', 'panic'),
    0x3d23271: ('488d3d48679f01', 'total0 Location'),
    0x3d23278: ('ff159aaea401', 'panic'),
    0x3d2327e: ('488d3d53679f01', 'total1 Location'),
    0x3d23285: ('ff158daea401', 'panic'),
    0x3d1ddfa: ('ff15a00aa501', 'wall clock now'),
    0x3d1de00: ('498b4610', 'Vec len'),
    0x3d1de0c: ('410f1006', 'Vec cap and ptr'),
    0x3d1de24: ('31c0', 'zero'),
    0x3d1de26: ('493b4748', 'writer +0x48'),
    0x3d1de2a: ('0f804d020000', 'None frees and returns'),
    0x3d1de33: ('3d00100e00', 'secs vs 921600'),
    0x3d1de38: ('0f8372020000', 'unwrap panic'),
    0x3d1de3e: ('3d905f0100', 'secs vs 90000'),
    0x3d1de43: ('0f838e020000', 'hour assert'),
    0x3d1de4f: ('4180bfa800000001', 'hour tag +0xa8'),
    0x3d1de57: ('0f85ff000000', 'daily'),
    0x3d1de5f: ('41bdc5b3a291', '/3600 magic'),
    0x3d1de6d: ('4538afa9000000', 'hour +0xa9'),
    0x3d1de76: ('413baf98000000', 'date +0x98'),
    0x3d1ded8: ('488d35b4b44cfc', 'hourly template'),
    0x3d1df02: ('ff15b80ba501', 'open'),
    0x3d1dfa3: ('488d35e4b34cfc', 'daily template'),
    0x3d1dfcd: ('ff15ed0aa501', 'open'),
    0x3d1e034: ('e8d7650000', 'serialize rows'),
    0x3d1e03c: ('418987a4000000', 'now frac +0xa4'),
    0x3d1e046: ('4989879c000000', 'now +0x9c'),
    0x3d1e04d: ('4180bfaa00000000', 'flag +0xaa'),
    0x3d1e057: ('488b05ba0ea501', 'global flag'),
    0x3d1e072: ('7409', 'writer absent'),
    0x3d1e077: ('ff152b0aa501', 'writer helper'),
    0x3d1e07d: ('488b742478', 'cap'),
    0x3d1e095: ('ff1575ffa401', 'free rows'),
    0x3d1e0af: ('c3', 'ret'),
    0x3d1e0b0: ('488d3df3bc4ffc', 'unwrap message'),
    0x3d1e0be: ('4c8d0503ca9401', 'time.rs Location'),
    0x3d1e0cf: ('ff1573ffa401', 'unwrap_failed'),
    0x3d1e0d7: ('488d3d4b8e4ffc', 'assert message'),
    0x3d1e0de: ('488d15f38c9401', 'hour.rs Location'),
    0x3d1e0ea: ('ff151800a501', 'panic'),
    0x3d1e51a: ('ff158003a501', 'wall clock now'),
    0x3d1e52f: ('498b4610', 'row +0x10'),
    0x3d1e53b: ('410f1006', 'row +0x00'),
    0x3d1e544: ('31c0', 'zero'),
    0x3d1e546: ('493b4748', 'writer +0x48'),
    0x3d1e54a: ('0f804b020000', 'None returns'),
    0x3d1e553: ('3d00100e00', 'secs vs 921600'),
    0x3d1e558: ('0f8352020000', 'unwrap panic'),
    0x3d1e55e: ('3d905f0100', 'secs vs 90000'),
    0x3d1e563: ('0f836c020000', 'hour assert'),
    0x3d1e56f: ('4180bfa800000001', 'hour tag +0xa8'),
    0x3d1e577: ('0f85ff000000', 'daily'),
    0x3d1e57f: ('41bdc5b3a291', '/3600 magic'),
    0x3d1e58d: ('4538afa9000000', 'hour +0xa9'),
    0x3d1e596: ('413baf98000000', 'date +0x98'),
    0x3d1e5f8: ('488d3594ad4cfc', 'hourly template'),
    0x3d1e622: ('ff159804a501', 'open'),
    0x3d1e62b: ('e8101b0000', 'drop old'),
    0x3d1e661: ('4189af98000000', 'date'),
    0x3d1e668: ('41c687a800000001', 'hour tag 1'),
    0x3d1e670: ('4588afa9000000', 'hour'),
    0x3d1e67c: ('413baf98000000', 'date +0x98'),
    0x3d1e683: ('0f84a8000000', 'same day'),
    0x3d1e6c3: ('488d35c4ac4cfc', 'daily template'),
    0x3d1e6eb: ('ff15cf03a501', 'open'),
    0x3d1e72a: ('4189af98000000', 'date'),
    0x3d1e752: ('e8d9590000', 'serialize total'),
    0x3d1e75a: ('418987a4000000', 'now frac +0xa4'),
    0x3d1e764: ('4989879c000000', 'now +0x9c'),
    0x3d1e76b: ('4180bfaa00000000', 'flag +0xaa'),
    0x3d1e773: ('7426', 'zero skips'),
    0x3d1e775: ('488b059c07a501', 'global flag'),
    0x3d1e781: ('7418', 'zero skips'),
    0x3d1e790: ('7409', 'writer absent'),
    0x3d1e795: ('ff150d03a501', 'writer helper'),
    0x3d1e7af: ('c3', 'ret'),
    0x3d1e7b0: ('488d3df3b54ffc', 'unwrap message'),
    0x3d1e7be: ('4c8d0503c39401', 'time.rs Location'),
    0x3d1e7cf: ('ff1573f8a401', 'unwrap_failed'),
    0x3d1e7d5: ('488d3d4d874ffc', 'assert message'),
    0x3d1e7dc: ('488d15f5859401', 'hour.rs Location'),
    0x3d1e7e8: ('ff151af9a401', 'panic'),
    0x3d2794c: ('488d35085789fc', 'tcp_lz4_stats'),
    0x3d27953: ('ba0d000000', 'length 13'),
    0x3d27958: ('ff15b275a401', 'reporter new'),
    0x3d2795e: ('488d05035789fc', 'lz4_stats'),
    0x3d2796a: ('48c744241009000000', 'length 9'),
    0x3d27973: ('c684246801000000', 'byte +0x168 = 0'),
    0x3d2797b: ('c684247001000001', 'byte +0x170 = 1'),
    0x3d27988: ('e8237dffff', 'run'),
}

# va: (instruction length, target) for every rel8/rel32 branch, call and RIP-relative operand in the windows.
OPERANDS = {
    0x3d12b0b: (5, 0x3d0eee0),  # metrics_loop: call
    0x3d12b12: (6, 0x3d12cf3),  # metrics_loop: jne
    0x3d12b1f: (2, 0x3d12b36),  # metrics_loop: jne
    0x3d12b28: (2, 0x3d12b36),  # metrics_loop: jne
    0x3d12b31: (5, 0x3d0f710),  # metrics_loop: call
    0x3d12b5a: (6, 0x5786568),  # metrics_loop: mov
    0x3d12b62: (6, 0x3d12e18),  # metrics_loop: jne
    0x3d12b6c: (8, 0x5786530),  # metrics_loop: lock
    0x3d12b74: (6, 0x3d12e58),  # metrics_loop: jne
    0x3d12b7a: (7, 0x5786538),  # metrics_loop: mov
    0x3d12b81: (7, 0x5786540),  # metrics_loop: mov
    0x3d12b98: (7, 0x5786550),  # metrics_loop: mov
    0x3d12bed: (5, 0x3d2ba50),  # metrics_loop: call
    0x3d12bf6: (8, 0x5786530),  # metrics_loop: lock
    0x3d12bfe: (6, 0x3d12e6f),  # metrics_loop: jne
    0x3d12c0c: (2, 0x3d12c36),  # metrics_loop: je
    0x3d12c31: (5, 0x3d1dde0),  # metrics_loop: call
    0x3d12c41: (2, 0x3d12cb6),  # metrics_loop: je
    0x3d12c4c: (8, 0x203e80),  # metrics_loop: movsd
    0x3d12c57: (8, 0x202ea0),  # metrics_loop: movapd
    0x3d12cb1: (5, 0x3d1e500),  # metrics_loop: call
    0x3d12cb9: (2, 0x3d12cd6),  # metrics_loop: jne
    0x3d12cc3: (2, 0x3d12cd6),  # metrics_loop: je
    0x3d12cd0: (6, 0x576e010),  # metrics_loop: call
    0x3d12cee: (5, 0x3d12afc),  # metrics_loop: jmp
    0x3d12e18: (7, 0x5786530),  # metrics_slow: lea
    0x3d12e2e: (7, 0x5786568),  # metrics_slow: lea
    0x3d12e35: (7, 0x5718a78),  # metrics_slow: lea
    0x3d12e3c: (7, 0x5718aa0),  # metrics_slow: lea
    0x3d12e4d: (6, 0x576e8b8),  # metrics_slow: call
    0x3d12e53: (5, 0x3d12b68),  # metrics_slow: jmp
    0x3d12e58: (7, 0x5786530),  # metrics_slow: lea
    0x3d12e64: (6, 0x576ef30),  # metrics_slow: call
    0x3d12e6a: (5, 0x3d12b7a),  # metrics_slow: jmp
    0x3d12e6f: (7, 0x5786530),  # metrics_slow: lea
    0x3d12e78: (6, 0x576ef38),  # metrics_slow: call
    0x3d1ddfa: (6, 0x576e8a0),  # rows_writer: call
    0x3d1de2a: (6, 0x3d1e07d),  # rows_writer: jo
    0x3d1de38: (6, 0x3d1e0b0),  # rows_writer: jae
    0x3d1de43: (6, 0x3d1e0d7),  # rows_writer: jae
    0x3d1de57: (6, 0x3d1df5c),  # rows_writer: jne
    0x3d1de74: (2, 0x3d1de83),  # rows_writer: jne
    0x3d1de7d: (6, 0x3d1e013),  # rows_writer: je
    0x3d1dea0: (7, 0x14ddab0),  # rows_writer: lea
    0x3d1deb6: (7, 0x576ea60),  # rows_writer: mov
    0x3d1decc: (7, 0x576eb20),  # rows_writer: mov
    0x3d1ded8: (7, 0x1e9393),  # rows_writer: lea
    0x3d1deec: (6, 0x576e040),  # rows_writer: call
    0x3d1df02: (6, 0x576eac0),  # rows_writer: call
    0x3d1df0b: (5, 0x3d20140),  # rows_writer: call
    0x3d1df57: (5, 0x3d1e013),  # rows_writer: jmp
    0x3d1df63: (6, 0x3d1e013),  # rows_writer: je
    0x3d1df81: (7, 0x14ddab0),  # rows_writer: lea
    0x3d1df97: (7, 0x576ea60),  # rows_writer: mov
    0x3d1dfa3: (7, 0x1e938e),  # rows_writer: lea
    0x3d1dfb7: (6, 0x576e040),  # rows_writer: call
    0x3d1dfcd: (6, 0x576eac0),  # rows_writer: call
    0x3d1dfd6: (5, 0x3d20140),  # rows_writer: call
    0x3d1e034: (5, 0x3d24610),  # rows_writer: call
    0x3d1e055: (2, 0x3d1e07d),  # rows_writer: je
    0x3d1e057: (7, 0x576ef18),  # rows_writer: mov
    0x3d1e063: (2, 0x3d1e07d),  # rows_writer: je
    0x3d1e072: (2, 0x3d1e07d),  # rows_writer: je
    0x3d1e077: (6, 0x576eaa8),  # rows_writer: call
    0x3d1e085: (2, 0x3d1e09b),  # rows_writer: je
    0x3d1e095: (6, 0x576e010),  # rows_writer: call
    0x3d1e0b0: (7, 0x219daa),  # rows_writer: lea
    0x3d1e0b7: (7, 0x566ac40),  # rows_writer: lea
    0x3d1e0be: (7, 0x566aac8),  # rows_writer: lea
    0x3d1e0cf: (6, 0x576e048),  # rows_writer: call
    0x3d1e0d5: (2, 0x3d1e0f0),  # rows_writer: jmp
    0x3d1e0d7: (7, 0x216f29),  # rows_writer: lea
    0x3d1e0de: (7, 0x5666dd8),  # rows_writer: lea
    0x3d1e0ea: (6, 0x576e108),  # rows_writer: call
    0x3d1e51a: (6, 0x576e8a0),  # total_writer: call
    0x3d1e54a: (6, 0x3d1e79b),  # total_writer: jo
    0x3d1e558: (6, 0x3d1e7b0),  # total_writer: jae
    0x3d1e563: (6, 0x3d1e7d5),  # total_writer: jae
    0x3d1e577: (6, 0x3d1e67c),  # total_writer: jne
    0x3d1e594: (2, 0x3d1e5a3),  # total_writer: jne
    0x3d1e59d: (6, 0x3d1e731),  # total_writer: je
    0x3d1e5c0: (7, 0x14ddab0),  # total_writer: lea
    0x3d1e5d6: (7, 0x576ea60),  # total_writer: mov
    0x3d1e5ec: (7, 0x576eb20),  # total_writer: mov
    0x3d1e5f8: (7, 0x1e9393),  # total_writer: lea
    0x3d1e60c: (6, 0x576e040),  # total_writer: call
    0x3d1e622: (6, 0x576eac0),  # total_writer: call
    0x3d1e62b: (5, 0x3d20140),  # total_writer: call
    0x3d1e677: (5, 0x3d1e731),  # total_writer: jmp
    0x3d1e683: (6, 0x3d1e731),  # total_writer: je
    0x3d1e6a1: (7, 0x14ddab0),  # total_writer: lea
    0x3d1e6b7: (7, 0x576ea60),  # total_writer: mov
    0x3d1e6c3: (7, 0x1e938e),  # total_writer: lea
    0x3d1e6da: (6, 0x576e040),  # total_writer: call
    0x3d1e6eb: (6, 0x576eac0),  # total_writer: call
    0x3d1e6f4: (5, 0x3d20140),  # total_writer: call
    0x3d1e752: (5, 0x3d24130),  # total_writer: call
    0x3d1e773: (2, 0x3d1e79b),  # total_writer: je
    0x3d1e775: (7, 0x576ef18),  # total_writer: mov
    0x3d1e781: (2, 0x3d1e79b),  # total_writer: je
    0x3d1e790: (2, 0x3d1e79b),  # total_writer: je
    0x3d1e795: (6, 0x576eaa8),  # total_writer: call
    0x3d1e7b0: (7, 0x219daa),  # total_writer: lea
    0x3d1e7b7: (7, 0x566ac40),  # total_writer: lea
    0x3d1e7be: (7, 0x566aac8),  # total_writer: lea
    0x3d1e7cf: (6, 0x576e048),  # total_writer: call
    0x3d1e7d5: (7, 0x216f29),  # total_writer: lea
    0x3d1e7dc: (7, 0x5666dd8),  # total_writer: lea
    0x3d1e7e8: (6, 0x576e108),  # total_writer: call
    0x3d219ab: (2, 0x3d219d3),  # report: je
    0x3d219bc: (2, 0x3d219d0),  # report: je
    0x3d219e0: (6, 0x3d21c16),  # report: je
    0x3d219e9: (6, 0x3d21a6f),  # report: je
    0x3d219ef: (7, 0x5719410),  # report: lea
    0x3d219f6: (6, 0x576f038),  # report: call
    0x3d21a79: (5, 0x3d1e830),  # report_loop: call
    0x3d21a80: (6, 0x3d21c33),  # report_loop: jne
    0x3d21a8d: (2, 0x3d21aa4),  # report_loop: jne
    0x3d21a96: (2, 0x3d21aa4),  # report_loop: jne
    0x3d21a9f: (5, 0x3d20270),  # report_loop: call
    0x3d21abf: (6, 0x5786568),  # report_loop: mov
    0x3d21ac7: (6, 0x3d21c7a),  # report_loop: jne
    0x3d21ad1: (8, 0x5786530),  # report_loop: lock
    0x3d21ad9: (6, 0x3d21cba),  # report_loop: jne
    0x3d21adf: (7, 0x5786538),  # report_loop: mov
    0x3d21ae6: (7, 0x5786540),  # report_loop: mov
    0x3d21afd: (7, 0x5786550),  # report_loop: mov
    0x3d21b4c: (5, 0x3d2ba50),  # report_loop: call
    0x3d21b55: (8, 0x5786530),  # report_loop: lock
    0x3d21b5d: (6, 0x3d21cd1),  # report_loop: jne
    0x3d21b6b: (2, 0x3d21b7f),  # report_loop: je
    0x3d21b7a: (5, 0x3d1dde0),  # report_loop: call
    0x3d21b87: (2, 0x3d21bf6),  # report_loop: je
    0x3d21b8f: (8, 0x203e80),  # report_loop: movsd
    0x3d21b9a: (8, 0x202ea0),  # report_loop: movapd
    0x3d21bf1: (5, 0x3d1e500),  # report_loop: call
    0x3d21bf9: (2, 0x3d21c16),  # report_loop: jne
    0x3d21c03: (2, 0x3d21c16),  # report_loop: je
    0x3d21c10: (6, 0x576e010),  # report_loop: call
    0x3d21c2e: (5, 0x3d21a6f),  # report_loop: jmp
    0x3d21c41: (2, 0x3d21c69),  # report_loop: je
    0x3d21c52: (2, 0x3d21c66),  # report_loop: je
    0x3d21c7a: (7, 0x5786530),  # report_loop: lea
    0x3d21c90: (7, 0x5786568),  # report_loop: lea
    0x3d21c97: (7, 0x57190f8),  # report_loop: lea
    0x3d21c9e: (7, 0x5719120),  # report_loop: lea
    0x3d21caf: (6, 0x576e8b8),  # report_loop: call
    0x3d21cb5: (5, 0x3d21acd),  # report_loop: jmp
    0x3d21cba: (7, 0x5786530),  # report_loop: lea
    0x3d21cc6: (6, 0x576ef30),  # report_loop: call
    0x3d21ccc: (5, 0x3d21adf),  # report_loop: jmp
    0x3d21cd1: (7, 0x5786530),  # report_loop: lea
    0x3d21cda: (6, 0x576ef38),  # report_loop: call
    0x3d21ce0: (5, 0x3d21b63),  # report_loop: jmp
    0x3d2318b: (6, 0x3d23271),  # drain_entry: jb
    0x3d2319a: (6, 0x3d2327e),  # drain_entry: jb
    0x3d231a9: (6, 0x3d23264),  # drain_entry: jb
    0x3d231ca: (2, 0x3d231e3),  # drain_entry: je
    0x3d231cf: (6, 0x3d23100),  # drain_entry: jne
    0x3d231dc: (2, 0x3d2324e),  # drain_entry: jmp
    0x3d231e1: (2, 0x3d2324e),  # drain_entry: jmp
    0x3d231e8: (8, 0x203e80),  # drain_entry: movq
    0x3d231f4: (8, 0x202ea0),  # drain_entry: movapd
    0x3d23264: (7, 0x57199f0),  # drain_entry: lea
    0x3d2326b: (6, 0x576e118),  # drain_entry: call
    0x3d23271: (7, 0x57199c0),  # drain_entry: lea
    0x3d23278: (6, 0x576e118),  # drain_entry: call
    0x3d2327e: (7, 0x57199d8),  # drain_entry: lea
    0x3d23285: (6, 0x576e118),  # drain_entry: call
    0x3d2794c: (7, 0x5bd05b),  # entry: lea
    0x3d27958: (6, 0x576ef10),  # entry: call
    0x3d2795e: (7, 0x5bd068),  # entry: lea
    0x3d27988: (5, 0x3d1f6b0),  # entry: call
    0x3d2ba70: (5, 0x3d230c0),  # collect: call
    0x3d2ba7e: (2, 0x3d2ba9c),  # collect: jne
    0x3d2ba97: (5, 0x3d2bc3e),  # collect: jmp
    0x3d2bacb: (6, 0x576dfd8),  # collect: call
    0x3d2bad4: (6, 0x3d2bc53),  # collect: je
    0x3d2bb57: (2, 0x3d2bba0),  # collect: jmp
    0x3d2bbb0: (5, 0x3d230c0),  # collect: call
    0x3d2bbc2: (2, 0x3d2bc27),  # collect: je
    0x3d2bbfa: (6, 0x3d2bb60),  # collect: jne
    0x3d2bc18: (5, 0x3d28c00),  # collect: call
    0x3d2bc22: (5, 0x3d2bb60),  # collect: jmp
}

SLOTS = {
    0x576e8a0: (0x151cba0, 'wall clock now'),
    0x576e040: (0x1344760, 'format to String'),
    0x576e010: (0x54c8cb0, 'dealloc'),
    0x576dfd8: (0x54c06b0, 'alloc'),
    0x576e8b8: (0x4ee3b20, 'once slot'),
    0x576ef30: (0x4e0f640, 'mutex lock_slow'),
    0x576ef38: (0x4e0f2c0, 'mutex unlock_slow'),
    0x576f038: (0x157b560, 'resumed-state panic'),
    0x576e118: (0x157b480, 'add overflow panic'),
    0x576ef10: (0x1402050, 'block-times reporter new'),
    0x576ea60: (0x1454a00, 'date Display'),
    0x576eb20: (0x13d95e0, 'hour Display'),
    0x576eac0: (0x13d1720, 'open writer'),
    0x576eaa8: (0x13d1880, 'writer helper'),
    0x576ef18: (0x5788312, 'global flag byte'),
    0x576e048: (0x157aa10, 'Result::unwrap failed'),
    0x576e108: (0x157b7f0, 'panic'),
    ENTRY_SLOT: (ENTRY, 'entry point'),
}
TEXT = {
    0x5bd05b: b'tcp_lz4_stats',
    0x5bd068: b'lz4_stats',
    0x219daa: b'called `Result::unwrap()` on an `Err` value',
    0x216f29: b'assertion failed: hour <= 24',
    0x203e80: bytes.fromhex('0000304300003045'),
}
F64 = {0x202ea0: 2.0 ** 52, 0x202ea8: 2.0 ** 84}
SECS_UNWRAP = 921600
SECS_HOUR = 90000


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
        self.relative, self.glob_dat = {}, {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
            elif info & 0xffffffff == 6:
                self.glob_dat[where] = info >> 32
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)

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
        return hits[0]

    def target(self, va, length):
        if length == 2:
            return va + 2 + struct.unpack('<b', self.read(va + 1, 1))[0]
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]

    def symbol(self, slot):
        index = self.glob_dat.get(slot)
        if index is None:
            return None
        secs = {s['name']: s for s in self.secs}
        name = secs['.dynstr']['offset'] + struct.unpack_from('<I', self.data, secs['.dynsym']['offset'] + index * 24)[0]
        return self.data[name:self.data.index(b'\0', name)].decode()


def windows(img):
    out = {}
    for name, (fde, va, hexs) in WINDOWS.items():
        raw = bytes.fromhex(hexs)
        start, end = img.fde(fde)
        require(start <= va and va + len(raw) <= end, f'{name} window {va:#x} is outside FDE {fde:#x}')
        require(img.read(va, len(raw)) == raw, f'{name} at {va:#x}: bytes changed')
        out[name] = va
    return out


def windowed(va, size):
    return any(va >= w[1] and va + size <= w[1] + len(bytes.fromhex(w[2])) for w in WINDOWS.values())


def facts(img):
    out = {}
    for va, (hx, what) in FACTS.items():
        raw = bytes.fromhex(hx)
        require(windowed(va, len(raw)), f'fact {what} at {va:#x} is outside every window')
        require(img.read(va, len(raw)) == raw, f'fact {what} at {va:#x}: bytes changed')
        out[va] = raw
    return out


def location(img, va):
    ptr = img.relative.get(va)
    require(ptr is not None, f'Location {va:#x} has no RELATIVE file pointer')
    n, line, col = struct.unpack('<QII', img.read(va + 8, 16))
    require(0 < n < 256, f'Location {va:#x} has length {n}')
    path = img.read(ptr, n)
    require(all(0x20 <= c < 0x7f for c in path), f'Location {va:#x} path is not text')
    return f'{path.decode()}:{line}:{col}'


def template(img, va, args):
    """Decode a rustc packed format template with `args` placeholders: literal-length bytes and 0xc0 placeholders.

    A template ends at a 0x00 byte or once its last placeholder and trailing literal are read; the
    daily path template `0x1e938e` runs straight into the hourly one, so the count comes from the
    argument array built at the call site.
    """
    pieces, pos = [], va
    for _ in range(64):
        b = img.read(pos, 1)[0]
        if b == 0xc0:
            pieces.append(None)
            n = img.read(pos + 1, 1)[0]
            pos += 2
        elif b == 0:
            require(pieces.count(None) == args, f'template {va:#x} ends with {pieces.count(None)} placeholders')
            return pieces, pos
        elif b < 0x80:
            n = b
            pos += 1
        else:
            raise EvidenceError(f'template {va:#x}: unexpected byte {b:#x} at {pos:#x}')
        if n:
            lit = img.read(pos, n)
            require(all(0x20 <= c < 0x7f for c in lit), f'template {va:#x}: literal at {pos:#x} not text')
            pieces.append(lit.decode())
            pos += n
        if pieces.count(None) == args:
            return pieces, pos
    raise EvidenceError(f'template {va:#x}: no terminator')


def check_operands(img):
    out = {}
    for va, (n, want) in OPERANDS.items():
        require(windowed(va, n), f'operand at {va:#x} is outside every window')
        got = img.target(va, n)
        require(got == want, f'operand at {va:#x} goes to {got:#x}, not {want:#x}')
        out[hex(va)] = hex(got)
    for slot, (want, what) in SLOTS.items():
        got = img.symbol(slot) if isinstance(want, str) else img.relative.get(slot)
        require(got == want, f'{what} slot {slot:#x} holds {got}')
    for va, want in TEXT.items():
        require(img.read(va, len(want)) == want, f'string at {va:#x} changed')
    locs = {}
    for va, tail in LOCATIONS.items():
        got = location(img, va)
        require(got.endswith(tail), f'Location {va:#x} is {got}')
        locs[hex(va)] = got
    consts = {}
    for va, want in F64.items():
        got = struct.unpack('<d', img.read(va, 8))[0]
        require(got == want, f'f64 at {va:#x} is {got}, not {want}')
        consts[hex(va)] = got
    temps = {}
    for va, (args, want) in TEMPLATES.items():
        got, end = template(img, va, args)
        require(got == want, f'template {va:#x} is {got}')
        temps[hex(va)] = dict(pieces=got, end=hex(end))
    require(int(temps[hex(0x1e938e)]['end'], 16) == 0x1e9393, 'daily template no longer abuts the hourly one')
    return dict(targets=out, locations=locs, f64=consts, templates=temps)


def imm32(raw):
    return struct.unpack('<I', raw[-4:])[0]


def disp32(raw):
    return struct.unpack('<i', raw[-4:])[0]



def rsp(reg, d):
    """ModRM + SIB + displacement for `[rsp+d]` with ModRM.reg = `reg`."""
    if d < 0x80:
        return bytes([0x44 | reg << 3, 0x24, d])
    return bytes([0x84 | reg << 3, 0x24]) + struct.pack('<I', d)


LOOPS = {
    'report': dict(fde=REPORT, totals=(0x8, 0x10, 0x18), poll=(0x3d21a79, 0x3d1e830), pending=(0x3d21a80, 0x3d21c33),
                   zero=(0x3d21aa4, 0x3d21aad, 0x3d21ab6), once=0x3d21abf, lock=0x3d21ad1, collect=0x3d21b4c,
                   unlock=0x3d21b55, len_skip=0x3d21b6b, rows=0x3d21b7a, load=(0x3d21b7f, 0x3d21b89, 0x3d21bcf),
                   total_skip=0x3d21b87, div=0x3d21bcb, total=0x3d21bf1, free=0x3d21c10, reload=0x3d21c16,
                   store=(0x3d21c20, 0xd8), reset=(0x3d21c27, 0x170), loop=(0x3d21c2e, 0x3d21a6f),
                   slow=dict(once=0x3d21caf, lock_slow=0x3d21cc6, unlock_slow=0x3d21cda, no_timeout=0x3d21cc1)),
    'metrics': dict(fde=METRICS, totals=(0x80, 0x88, 0x90), poll=(0x3d12b0b, 0x3d0eee0), pending=(0x3d12b12, 0x3d12cf3),
                    zero=(0x3d12b36, 0x3d12b42, 0x3d12b4e), once=0x3d12b5a, lock=0x3d12b6c, collect=0x3d12bed,
                    unlock=0x3d12bf6, len_skip=0x3d12c0c, rows=0x3d12c31, load=(0x3d12c36, 0x3d12c43, 0x3d12c8c),
                    total_skip=0x3d12c41, div=0x3d12c88, total=0x3d12cb1, free=0x3d12cd0, reload=0x3d12cd6,
                    store=(0x3d12ce0, 0xb8), reset=(0x3d12ce7, 0x150), loop=(0x3d12cee, 0x3d12afc),
                    slow=dict(once=0x3d12e4d, lock_slow=0x3d12e64, unlock_slow=0x3d12e78, no_timeout=0x3d12e5f)),
}


def check_loop(f, name):
    o, L = OPERANDS, LOOPS[name]
    t0, t1, t2 = L['totals']
    for va, d in zip(L['zero'], L['totals']):
        require(f[va] == b'\x48\xc7' + rsp(0, d) + b'\0\0\0\0', f'{name}: total at rsp+{d:#x} is not zeroed at {va:#x}')
    require(o[L['poll'][0]][1] == L['poll'][1] and o[L['pending'][0]][1] == L['pending'][1], f'{name}: sleep poll changed')
    require(o[L['once']][1] == ONCE and o[L['lock']][1] == o[L['unlock']][1] == MUTEX, f'{name}: lock changed')
    require(f[L['lock']][:4] == bytes.fromhex('f00fb00d') and f[L['unlock']][:4] == bytes.fromhex('f00fb00d'),
            f'{name}: lock is not a lock cmpxchg byte')
    require(o[L['collect']][1] == COLLECT and L['lock'] < L['collect'] < L['unlock'] < L['rows'],
            f'{name}: rows are not collected under the lock')
    require(o[L['rows']][1] == ROWS_WRITER and o[L['len_skip']][1] == L['rows'] + 5, f'{name}: rows writer is not skipped on no rows')
    require(f[L['load'][0]] == b'\x48\x8b' + rsp(0, t0) and f[L['load'][1]] == b'\xf2\x0f\x10' + rsp(0, t1) and
            f[L['load'][2]] == b'\x48\x8b' + rsp(1, t2), f'{name}: total row loads changed')
    require(o[L['total_skip']][1] == L['total'] + 5 and f[L['div']] == bytes.fromhex('f20f5ed9') and
            o[L['total']][1] == TOTAL_WRITER, f'{name}: total row is not total1 / total0 gated on total0')
    require(o[L['free']][1] == 0x576e010, f'{name}: empty Vec is not freed')
    raw = f[L['reload']]
    require(raw[:2] == bytes.fromhex('48b8') and struct.unpack('<d', raw[2:10])[0] == PERIOD, f'{name}: period is not 300.0')
    store, off = L['store']
    require(disp32(f[store]) == off and f[L['reset'][0]][-1] == 0 and disp32(f[L['reset'][0]][:-1]) == L['reset'][1],
            f'{name}: sleep is not re-armed')
    require(o[L['loop'][0]][1] == L['loop'][1], f'{name}: does not loop back to the sleep')
    s = L['slow']
    require(o[s['once']][1] == 0x576e8b8 and o[s['lock_slow']][1] == 0x576ef30 and o[s['unlock_slow']][1] == 0x576ef38 and
            imm32(f[s['no_timeout']]) == 1_000_000_000, f'{name}: slow paths changed')
    return dict(period=PERIOD, sleep_poll=hex(L['poll'][1]), totals=[hex(d) for d in L['totals']],
                rows=f'{ROWS_WRITER:#x} when len != 0', total=f'{TOTAL_WRITER:#x}(total0, total2, total1/total0) when total0 != 0')


def check_report_head(f):
    o = OPERANDS
    require(f[0x3d219a7] == bytes.fromhex('4883f902') and o[0x3d219ab] == (2, 0x3d219d3), 'span None no longer skips the enter')
    require(f[0x3d219d0] == bytes.fromhex('ff5060') and f[0x3d21c66] == bytes.fromhex('ff5068'), 'span enter/exit slots changed')
    require(disp32(f[0x3d219d7]) == 0x178 and o[0x3d219e0][1] == 0x3d21c16 and o[0x3d219e9][1] == 0x3d21a6f,
            'state dispatch changed')
    require(o[0x3d219ef][1] == 0x5719410 and o[0x3d219f6][1] == 0x576f038, 'resumed-state panic changed')
    require(f[0x3d21c33] == bytes.fromhex('c6837801000003') and f[0x3d21c69] == bytes.fromhex('b001'), 'Pending exit changed')
    return dict(span='[self] != 2: enter [vtable+0x60] on entry, exit [vtable+0x68] on Pending',
                state='byte +0x178: 0 arms 300.0 and sleeps, 3 resumes the sleep, else panics lz4_stats.rs:81:42')


def check_collect(f):
    o = OPERANDS
    require(f[0x3d2ba67] == bytes.fromhex('488d5640') and o[0x3d2ba70][1] == o[0x3d2bbb0][1] == DRAIN,
            'collect no longer drains with the totals at iter+0x40')
    require(f[0x3d2ba7a] == bytes.fromhex('4080fd02') and f[0x3d2bbbe] == bytes.fromhex('4180fd02') and
            o[0x3d2bbc2][1] == 0x3d2bc27, 'row tag 2 is no longer the end')
    require([imm32(f[va]) for va in (0x3d2ba80, 0x3d2ba87, 0x3d2ba8f)] == [0, 8, 0], 'empty Vec changed')
    require(imm32(f[0x3d2bac6]) == 0x80 and imm32(f[0x3d2bb05]) == 4 and imm32(f[0x3d2bb13]) == 1, 'first allocation changed')
    require(f[0x3d2bb9c] == bytes.fromhex('4883c320') and imm32(f[0x3d2bc0a]) == 0x20 and o[0x3d2bc18][1] == 0x3d28c00,
            'row stride changed')
    return dict(rows='Vec of 0x20-byte rows, first capacity 4', end='row byte 6 == 2')


DRAIN_ADDS = [(0x3d23188, 0x3d2318b, 0x57199c0), (0x3d23197, 0x3d2319a, 0x57199d8), (0x3d231a6, 0x3d231a9, 0x57199f0)]


def check_drain(f):
    o = OPERANDS
    xchg = [0x3d23166, 0x3d23173, 0x3d23180]
    require(all(f[va][:2] == bytes.fromhex('4d87') and f[va][-1] == 0x10 for va in xchg), 'counters are not swapped')
    panics = []
    for add, jb, loc in DRAIN_ADDS:
        target = o[jb][1]
        require(f[add][:2] == bytes.fromhex('4d01') and f[jb][:2] == bytes.fromhex('0f82') and
                OPERANDS[target][1] == loc and OPERANDS[target + 7][1] == 0x576e118, f'total add at {add:#x} changed')
        panics.append(location_tail(loc))
    require(max(a for a, _, _ in DRAIN_ADDS) < 0x3d231b2, 'totals are no longer added before the filter')
    require(f[0x3d231b2] == bytes.fromhex('4d85f6') and f[0x3d231bc] == bytes.fromhex('49c1ec30') and
            f[0x3d231c0] == bytes.fromhex('4180fc02') and o[0x3d231ca][1] == 0x3d231e3 and o[0x3d231cf][1] == 0x3d23100,
            'filter is not counter0 == 0 or key byte 6 == 2')
    require(f[0x3d231e3] == bytes.fromhex('66490f6ec5') and f[0x3d2320c] == bytes.fromhex('66490f6ec6') and
            f[0x3d23225] == bytes.fromhex('f20f5ed9'), 'ratio is not counter1 / counter0')
    require(f[0x3d23241] == bytes.fromhex('4c897708') and f[0x3d23245] == bytes.fromhex('4c897f10') and
            f[0x3d23249] == bytes.fromhex('f20f115f18') and f[0x3d2324e] == bytes.fromhex('44886706'), 'row layout changed')
    return dict(order='swap three counters, add each to its total (carry panics), then filter',
                skip='counter0 == 0 or key byte 6 == 2', row='+0 key u32, +4 key u16, +6 key byte 6, +7 key byte 7, '
                '+8 counter0, +0x10 counter2, +0x18 counter1/counter0', overflow=panics)


WRITERS = {
    'rows': dict(fde=ROWS_WRITER, now=0x3d1ddfa, cmp=0x3d1de26, none=(0x3d1de2a, 0x3d1e07d), secs=(0x3d1de33, 0x3d1de3e),
                 panics=(0x3d1de38, 0x3d1de43), tag=0x3d1de4f, templates=(0x3d1ded8, 0x3d1dfa3), opens=(0x3d1df02, 0x3d1dfcd),
                 serialize=(0x3d1e034, 0x3d24610), store=0x3d1e046, flag=0x3d1e04d, glob=0x3d1e057, helper=0x3d1e077,
                 end=0x3d1e0f2),
    'total': dict(fde=TOTAL_WRITER, now=0x3d1e51a, cmp=0x3d1e546, none=(0x3d1e54a, 0x3d1e79b), secs=(0x3d1e553, 0x3d1e55e),
                  panics=(0x3d1e558, 0x3d1e563), tag=0x3d1e56f, templates=(0x3d1e5f8, 0x3d1e6c3), opens=(0x3d1e622, 0x3d1e6eb),
                  serialize=(0x3d1e752, 0x3d24130), store=0x3d1e764, flag=0x3d1e76b, glob=0x3d1e775, helper=0x3d1e795,
                  end=0x3d1e7ee),
}


def check_writer(f, name):
    o, W = OPERANDS, WRITERS[name]
    require(o[W['now']][1] == 0x576e8a0 and f[W['cmp']] == bytes.fromhex('493b4748') and o[W['none'][0]][1] == W['none'][1],
            f'{name}: writer None no longer returns first')
    require([imm32(f[va]) for va in W['secs']] == [SECS_UNWRAP, SECS_HOUR], f'{name}: second-of-day checks changed')
    unwrap, hour = [o[va][1] for va in W['panics']]
    require(o[unwrap][1] == 0x219daa and o[unwrap + 14][1] == 0x566aac8 and o[hour][1] == 0x216f29 and
            o[hour + 7][1] == 0x5666dd8, f'{name}: panic blocks changed')
    require(f[W['tag']] == bytes.fromhex('4180bfa800000001'), f'{name}: hourly tag is not [+0xa8] == 1')
    require([o[va][1] for va in W['templates']] == [0x1e9393, 0x1e938e] and all(o[va][1] == 0x576eac0 for va in W['opens']),
            f'{name}: rotation changed')
    require(o[W['serialize'][0]][1] == W['serialize'][1] and f[W['store']] == bytes.fromhex('4989879c000000'),
            f'{name}: row write or time store changed')
    require(f[W['flag']] == bytes.fromhex('4180bfaa00000000') and o[W['glob']][1] == 0x576ef18 and o[W['helper']][1] == 0x576eaa8,
            f'{name}: writer helper gate changed')
    helpers = [va for va, (_, t) in OPERANDS.items() if W['fde'] <= va < W['end'] and t == 0x576eaa8]
    require(helpers == [W['helper']], f'{name}: writer helper is called from {[hex(v) for v in helpers]}')
    return dict(none=('free the rows and return' if name == 'rows' else 'return') + f" at {W['none'][1]:#x}", serializer=hex(W['serialize'][1]),
                helper='once, only when [+0xaa], byte 0x5788312 and the writer are all set')


def check_entry(f):
    o = OPERANDS
    require(o[0x3d2794c][1] == 0x5bd05b and imm32(f[0x3d27953]) == 13 and o[0x3d27958][1] == 0x576ef10,
            'reporter is not built from tcp_lz4_stats')
    require(o[0x3d2795e][1] == 0x5bd068 and imm32(f[0x3d2796a]) == 9 and o[0x3d27988][1] == 0x3d1f6b0, 'run call changed')
    return dict(reporter='0x1402050("tcp_lz4_stats")', name='"lz4_stats"', run='0x3d1f6b0')


CALLERS = {REPORT: [0x3d1323c], METRICS: [0x3cfdcd6], COLLECT: [0x3d12bed, 0x3d21b4c], DRAIN: [0x3d2ba70, 0x3d2bbb0],
           ROWS_WRITER: [0x3d12c31, 0x3d21b7a], TOTAL_WRITER: [0x3d12cb1, 0x3d21bf1], ENTRY: []}


def check_callers(img):
    text = next((x for x in img.secs if x['name'] == '.text'), None)
    require(text is not None, 'no .text section')
    code = img.data[text['offset']:text['offset'] + text['size']]
    direct = {fn: [] for fn in CALLERS}
    pos = code.find(b'\xe8')
    while 0 <= pos < len(code) - 4:
        t = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
        if t in direct:
            direct[t].append(text['address'] + pos)
        pos = code.find(b'\xe8', pos + 1)
    out = {}
    for fn, want in CALLERS.items():
        require(direct[fn] == want, f'{fn:#x} is called from {[hex(v) for v in direct[fn]]}')
        slots = [s for s, p in img.relative.items() if p == fn]
        require(slots == ([ENTRY_SLOT] if fn == ENTRY else []), f'{fn:#x} RELATIVE slots are {[hex(s) for s in slots]}')
        out[hex(fn)] = {hex(v): hex(img.containing(v)[0]) for v in want}
    out[hex(ENTRY)] = dict(slot=hex(ENTRY_SLOT))
    return dict(direct=out, scanned='.text, every e8 rel32; RELATIVE slots')


def drain(entries):
    """0x3d2ba50 over (byte6, counter0, counter1, counter2) entries: rows and the three totals."""
    totals, rows = [0, 0, 0], []
    for tag, *counters in entries:
        for i, c in enumerate(counters):
            totals[i] += c
            if totals[i] >= 2 ** 64:
                raise OverflowError(location_tail(DRAIN_ADDS[i][2]))
        if counters[0] and tag != 2:
            rows.append(dict(tag=tag, input=counters[0], samples=counters[2], ratio=counters[1] / counters[0]))
    return rows, totals


def tick(entries):
    """One 300 s tick: the writer calls made, in order."""
    rows, (t0, t1, t2) = drain(entries)
    calls = []
    if rows:
        calls.append(('rows', rows))
    if t0:
        calls.append(('total', dict(input=t0, samples=t2, ratio=t1 / t0)))
    return calls


def append(state, now, global_flag=False):
    """0x3d1dde0 / 0x3d1e500 on reporter state: rotated path and writer-helper calls."""
    out = dict(path=None, written=False, helper_calls=0)
    if not state['writer']:
        return out
    if now[1] >= SECS_UNWRAP:
        raise ValueError(location_tail(0x566aac8))
    if now[1] >= SECS_HOUR:
        raise ValueError(location_tail(0x5666dd8))
    if state['hourly']:
        hour = now[1] // 3600
        if state['hour'] != hour or state['day'] != now[0]:
            out['path'] = f"{state['root']}/hourly/{now[0]}/{hour}"
            state['day'], state['hour'] = now[0], hour
    elif state['day'] != now[0]:
        out['path'] = f"{state['root']}/{now[0]}"
        state['day'] = now[0]
    out['written'] = True
    state['last'] = tuple(now)
    out['helper_calls'] = 1 if state['flush_flag'] and global_flag else 0
    return out


def location_tail(va):
    return LOCATIONS[va].lstrip('/')


def analyse(data):
    img = Image(data)
    win = windows(img)
    f = facts(img)
    return dict(target=TARGET, fdes=[hex(v) for v in (REPORT, METRICS, COLLECT, DRAIN, ROWS_WRITER, TOTAL_WRITER, ENTRY)],
                windows={k: hex(v) for k, v in win.items()}, operands=check_operands(img),
                report=dict(head=check_report_head(f), loop=check_loop(f, 'report')), metrics=check_loop(f, 'metrics'),
                collect=check_collect(f), drain=check_drain(f),
                writers={k: check_writer(f, k) for k in WRITERS}, entry=check_entry(f), callers=check_callers(img))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--json', action='store_true')
    a = p.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == TARGET)
    path = ROOT / TARGET
    check(path, identity)
    result = dict(analyse(path.read_bytes()), target_sha256=identity['sha256'])
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    print(f"every {PERIOD} s: {result['drain']['order']}; skip {result['drain']['skip']}")
    print(f"rows -> {result['report']['loop']['rows']}; total -> {result['report']['loop']['total']}")
    print(f"writers: {result['writers']['total']['helper']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
