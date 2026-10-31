#!/usr/bin/env python3
"""Static node #94 ABCI latency sampler `0x3d22aa0` / `0x3d22920` / `0x3d22500`, checked from authenticated bytes.

Question: what do the `net_utils/abci_latency_sampler.rs` constructor,
begin-block and commit paths sample and write?  The can1357 lead
(`net_utils/abci_latency_sampler.rs`) skips a sample when the wall clock runs
backwards, caps the row's `apply_duration`, takes a block-times root and an
hourly flag in the constructor, and flushes only on `flush_on_commit`.

In the binary every duration goes through the shared helper `0x1447130`,
which returns 0.0 when `now` is earlier (after formatting and dropping a
`Time Sub` message) and otherwise whole microseconds as f64 seconds.  Begin
samples `min(60, now - last begin)` and the uncapped node backlog; commit
samples `min(60, apply)`, returns before any file work when the writer slot is
`None`, panics on a second-of-day of 921600 / 90000 or more, rotates
`{root}/{date}` or `{root}/hourly/{date}/{hour}`, writes the uncapped apply
time in the row, stores the commit wall time and calls the writer helper
once, or twice under `+0x7ca` and a global flag.  The constructor takes only
a prefix and one f64, which lands in the third sampler.

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; call, branch and RIP-relative
targets, seven packed format templates, string literals, four f64 constants,
five panic Locations, RELATIVE and GLOB_DAT slots and the callers of the three
entry points are decoded here.  Nothing from the binary is executed.
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
CTOR = 0x3d22aa0
BEGIN = 0x3d22920
COMMIT = 0x3d22500
ELAPSED = 0x1447130
ROW_WRITER = 0x3d24ff0
ROW_SERIALIZE = 0x3d22e10
WRITER_HELPER = 0x13d1880
ENTRY_SLOTS = {0x5776560: CTOR, 0x5776558: BEGIN, 0x5776550: COMMIT}
ENTRY_CALLS = {CTOR: [0x432e503, 0x474bfe8], BEGIN: [0x432e621, 0x474c625], COMMIT: [0x4678b5f, 0x474d4af]}
SOURCE = 0x5bcd1b
LOCATIONS = {
    0x57193b8: '/net_utils/src/abci_latency_sampler.rs:55:41',
    0x57193d0: '/net_utils/src/abci_latency_sampler.rs:58:34',
    0x57193a0: '/net_utils/src/abci_latency_sampler.rs:67:48',
    0x566aac8: '/base/src/time.rs:62:44',
    0x5666dd8: '/base/src/hour.rs:12:13',
}
F64 = {0x20abf8: 60.0, 0x20ae60: 1e6, 0x20a730: 1.0, 0x20af58: 0.06}
TEMPLATES = {
    0x1fe9cf: (1, [None, '_block_duration']),
    0x1ddb69: (1, [None, '_backlog_from_node']),
    0x1ef953: (1, [None, '_begin_block_to_commit']),
    0x1f245b: (1, [None, '_block_times']),
    0x1e938e: (2, [None, '/', None]),
    0x1e9393: (3, [None, '/hourly/', None, '/', None]),
    0x1f9cb6: (2, ['Time Sub ', None, ' ', None]),
}

WINDOWS = {
    'elapsed': (ELAPSED, 0x1447130,
        '534883ec508b460889442408488b06488904248b5e1039070f9cc00f85830000008b47043b4424040f92c075778b4708'
        '3b4424087272ff15347932044885c0400f98c685d20f9fc14020f10fb6f14801c64869c640420f00660f57c070408db2'
        '003665c484c90f44f24863ce4869c9d34d62104889ca48c1ea3f48c1f92601d14863c94801c80f90c1f6c10175100f57'
        'c0f2480f2ac0f20f5e05923cdcfe4883c4505bc384c0748e48897c2418488d05ccd6000048894424204889e148894c24'
        '284889442430488d35b92adbfe488d7c2438488d542418ff15336e3204f6c301740a8b058039330485c07525488b7424'
        '38660f57c04885f674a4488b7c244031d2ff15d96d3204660f57c04883c4505bc3488d05383933044889442410488d44'
        '24104889442418488d3d3a393304488d0d032d22044c8d05e42c2204488d542418be01000000ff153c763204eb9e'),
    'commit': (COMMIT, 0x3d22500,
        '554157415641554154534881ecc80000004989f64889fb488d7c2414ff157ec3a40183bbd0070000000f845803000048'
        '8d83d00700008b4808898c24b8000000488b0048898424b0000000488b83dc07000048898424bc0000008b83e4070000'
        '898424c40000008b83e407000089442428488b83dc070000488944242048b801000000420000004889442430488d0588'
        'a789fc488944243848c7442440420000008b44241c89842490000000488b4424144889842488000000488dbc24880000'
        '00488d742420ff15f4c2a401660f28c8f20f11442470488dbbc0040000f20f100513864efcf20f5dc1488d15b06d9f01'
        'be01000000ff15b5c9a4014c89b424a0000000f20f10442470f20f118424a800000031c0483b83680700000f80660200'
        '008b4424183d00100e000f83690200003d905f01000f83830200004c8db3680700008b6c241480bbc8070000010f85fe'
        '00000089c041bdc5b3a2914c0fafe849c1ed2b4438abc9070000750c3babb80700000f84900100000f10832807000089'
        '6c241044886c240f0f11442478488d4424784889442420488d0512b47bfd4889442428488d4424104889442430488b05'
        'acc3a4014889442438488d44240f4889442440488b0556c4a4014889442448488d35bd6c4cfc4c8da42488000000488d'
        '5424204c89e7ff1554b9a4014c8d7c24204c89ff4c89e6ff15c3c3a4014c89f7e83bdaffff0f10442460410f1146400f'
        '10442420660f104c24300f105424400f105c2450410f115e30410f11562066410f114e10410f110689abb8070000c683'
        'c8070000014488abc9070000e9b70000003babb80700000f84ab0000000f108328070000896c24100f11442478488d44'
        '24784889442420488d0532b37bfd4889442428488d4424104889442430488b05ccc2a4014889442438488d35ee6b4cfc'
        '4c8da42488000000488d5424204c89e7ff158ab8a4014c8d7c24204c89ff4c89e6ff15f9c2a4014c89f7e871d9ffff0f'
        '10442460410f1146400f10442420660f104c24300f105424400f105c2450410f115e30410f11562066410f114e10410f'
        '110689abb807000049bf00000000000000804c89742420488d742428488b44241448894424288b44241c89442430488d'
        '9424a00000004c89f7e8b22700008b44241c8983c4070000488b442414488983bc07000080bbca07000000741c488b05'
        'b4c6a4010fb60084c0740e4d393e74174c89f7ff152fc2a4014d393e74094c89f7ff1521c2a4014881c4c80000005b41'
        '5c415d415e415f5dc3488d3d0a754ffc488d0d998394014c8d051a829401488d542420be2b000000ff158ab7a401488d'
        '3d64464ffc488d150c459401be1c000000ff1531b8a401eb00'),
    'begin': (BEGIN, 0x3d22920,
        '5541574156534883ec6889d54889f34989fe488d7c240cff1563bfa4014183bed0070000000f8482000000418b86e407'
        '000089442448498b86dc070000488944244048b801000000360000004889442450488d05a3a389fc488944245848c744'
        '2460420000008b44241489442420488b44240c4889442418488d7c2418488d742440ff1518bfa401f20f100d48824efc'
        'f20f5dc8488d15fd699f01be010000004c89f7660f28c1ff15e3c5a4014d8dbed00700004084ed74714981c660020000'
        '8b430889442448488b03488944244048b8010000003a0000004889442450488d0516a389fc488944245848c744246042'
        '0000008b44241489442420488b44240c4889442418488d7c2418488d742440ff158bbea401488d1594699f01be010000'
        '004c89f7ff1566c5a4018b430889442430488b034889442428488b44240c48894424348b4424148944243c488b442428'
        '4989078b442430418947088b4424344189470c488b442438498947104883c4685b415e415f5dc3'),
    'ctor': (CTOR, 0x3d22aa0,
        '554157415641554154534881ecd8090000f20f114424184989fc48897424384889542440488d5c243848895c24584c8d'
        '35eb0c00004c89742460488d35eebe4dfc488d7c2420488d542458ff154fb5a401488b542428488b4c2430488dbc2418'
        '050000f20f1005257c4efc31f64889542410ff15b0c4a40148899c24b80200004c89b424c0020000488d353ab04bfc48'
        '8d7c2458488d9424b8020000ff15feb4a4014c8b7c24584c8b6c2460488b4c2468488dbc2478070000f20f1005cf7b4e'
        'fcbe010000004c89ea4c893c244c896c2408ff1550c4a40148899c24b80200004c89b424c0020000488d35c4cd4cfc48'
        '8d7c2458488d9424b8020000ff159eb4a4014c8b6c2458488b6c2460488b4c2468488d7c2458f20f10059a834efc31f6'
        '4889eaff15ffc3a40148c744245801000000f20f10442418f20f11442460488dbc24b8020000488d742458ba60020000'
        'ff15eab3a40148895c24484c89742450488d3554f84cfc488d7c2458488d542448ff1529b4a401488b5c24584c8b7424'
        '60488b542468488d7c24584c89f6ff15dcc2a401488db424180500004c8b3d9db3a401ba600200004c89e741ffd7498d'
        'bc2460020000488db42478070000ba6002000041ffd7498dbc24c0040000488db424b8020000ba6002000041ffd741c7'
        '8424d007000000000000498dbc2420070000488d742458bab000000041ffd74885db740e4c89f74889de31d2ff155eb3'
        'a4014d85ed488b1c24740e4889ef4c89ee31d2ff1547b3a4014885db7410488b7c24084889de31d2ff1532b3a401488b'
        '7424204885f6740d488b7c241031d2ff151bb3a4014c89e04881c4d80900005b415c415d415e415f5dc3'),
    'writer_helper': (WRITER_HELPER, 0x13d1880,
        '4157415641545350e8d3fbffff4889c7e89b1c0f004889c383e00383f801740c4883c4085b415c415e415fc3'),
    'row_writer': (ROW_WRITER, 0x3d24ff0,
        '415741564154534883ec284889d34989f64989ffbf80000000ff15c98fa4014885c00f841101000048c7442408800000'
        '00488944241048c744241800000000488d4424084889442420488d7424204889dfe8caddffff4889c34885c07419488b'
        '7424084885f67421488b7c241031d2ff15ab8fa401eb12488b742408488b5c24104889f048f7d8714a488b034883f801'
        '741c4885c07520488b73104885f67417488b7b0831d2ff15748fa401eb09488d7b08e8f9030000be280000004889df31'
        'd2ff15598fa4014883c4285b415c415e415fc34c8b642418488974240848895c24104c896424184c89e04c39e67424c6'
        '04030a49ffc44c89ff4c89f64889da4c89e1e8a9c16afd488b7424084885f675abebb4488d7c2408ba01000000b90100'
        '000041b801000000e8238b6cfd488b5c2410488b442418ebb6'),
    'row_serialize': (ROW_SERIALIZE, 0x3d22e10,
        '41574156534883ec304889fb4c8b36498b46104939060f8409010000498b4e08c604017b48ffc04989461066c7442408'
        '00014889742410488d35d09c89fc488d7c2408ba060000004889d9e8703600004885c00f85c2000000807c2408000f85'
        '9f000000488d4b10488d35de9e89fc488d7c2408ba0a000000e8423200004885c00f8594000000807c2408007575488d'
        '4b1c488d35be9e89fc488d7c2408ba15000000e8183200004885c0756e807c240800754f4883c308488d35ad9e89fc48'
        '8d7c2408ba0e0000004889d9e88f3300004885c0'),
}

FACTS = {
    0x1447135: ('8b4608', 'earlier frac'),
    0x144713c: ('488b06', 'earlier date and secs'),
    0x1447143: ('8b5e10', 'callsite flag word [rsi+0x10]'),
    0x1447146: ('3907', 'now.date vs earlier.date'),
    0x1447148: ('0f9cc0', 'now.date < earlier.date (signed)'),
    0x144714b: ('0f8583000000', 'dates differ'),
    0x1447154: ('3b442404', 'now.secs vs earlier.secs'),
    0x1447158: ('0f92c0', 'now.secs < earlier.secs (unsigned)'),
    0x144715b: ('7577', 'secs differ'),
    0x1447160: ('3b442408', 'now.frac vs earlier.frac'),
    0x1447164: ('7272', 'now.frac < earlier.frac: error arm'),
    0x14471d4: ('84c0', 'earlier field was larger?'),
    0x14471d6: ('748e', 'now is later: compute'),
    0x1447166: ('ff1534793204', 'signed_duration_since'),
    0x144716f: ('400f98c6', 'secs < 0'),
    0x1447175: ('0f9fc1', 'nanos > 0'),
    0x1447181: ('4869c640420f00', 'secs * 1_000_000'),
    0x1447188: ('660f57c0', 'result 0.0'),
    0x144718c: ('7040', 'overflow returns 0.0'),
    0x144718e: ('8db2003665c4', 'nanos - 1e9'),
    0x1447196: ('0f44f2', 'borrow only when secs < 0'),
    0x144719c: ('4869c9d34d6210', 'nanos / 1000 multiply'),
    0x14471aa: ('48c1f926', 'shift 38'),
    0x14471b6: ('0f90c1', 'add overflow'),
    0x14471bc: ('7510', 'overflow returns 0.0'),
    0x14471c1: ('f2480f2ac0', 'micros to f64'),
    0x14471c6: ('f20f5e05923cdcfe', 'divide by 1e6'),
    0x14471d3: ('c3', 'ret'),
    0x14471dd: ('488d05ccd60000', 'time Display'),
    0x14471f6: ('488d35b92adbfe', 'Time Sub template'),
    0x1447207: ('ff15336e3204', 'format to String'),
    0x144720d: ('f6c301', 'callsite flag bit 0'),
    0x1447212: ('8b0580393304', 'dword 0x577ab98'),
    0x144721a: ('7525', 'non-zero calls the once slot'),
    0x1447221: ('660f57c0', 'result 0.0'),
    0x1447231: ('ff15d96d3204', 'free the message'),
    0x1447237: ('660f57c0', 'result 0.0'),
    0x1447240: ('c3', 'ret'),
    0x1447241: ('488d0538393304', '0x577ab80'),
    0x1447257: ('488d3d3a393304', '0x577ab98'),
    0x1447276: ('ff153c763204', 'once slot'),
    0x144727c: ('eb9e', 'back to drop'),
    0x3d2292a: ('89d5', 'came_from_node in ebp'),
    0x3d2292c: ('4889f3', 'block_time ptr'),
    0x3d2292f: ('4989fe', 'self'),
    0x3d22937: ('ff1563bfa401', 'wall clock now'),
    0x3d2293d: ('4183bed007000000', 'last_times tag [self+0x7d0]'),
    0x3d22945: ('0f8482000000', 'None skips block_duration'),
    0x3d2294b: ('418b86e4070000', 'last begin wall frac [+0x7e4]'),
    0x3d22956: ('498b86dc070000', 'last begin wall [+0x7dc]'),
    0x3d22962: ('48b80100000036000000', 'callsite {1, line 54}'),
    0x3d22971: ('488d05a3a389fc', 'callsite file'),
    0x3d2297d: ('48c744246042000000', 'callsite file length 0x42'),
    0x3d229a2: ('ff1518bfa401', 'elapsed(now, last begin wall)'),
    0x3d229a8: ('f20f100d48824efc', '60.0'),
    0x3d229b0: ('f20f5dc8', 'min(60, elapsed)'),
    0x3d229b4: ('488d15fd699f01', 'record Location 55:41'),
    0x3d229bb: ('be01000000', 'esi 1'),
    0x3d229c0: ('4c89f7', 'sampler self+0x000'),
    0x3d229c7: ('ff15e3c5a401', 'record'),
    0x3d229d4: ('4084ed', 'came_from_node'),
    0x3d229d7: ('7471', 'false skips backlog'),
    0x3d229d9: ('4981c660020000', 'sampler self+0x260'),
    0x3d229e0: ('8b4308', 'block_time frac'),
    0x3d229e7: ('488b03', 'block_time date and secs'),
    0x3d229ef: ('48b8010000003a000000', 'callsite {1, line 58}'),
    0x3d22a2f: ('ff158bbea401', 'elapsed(now, block_time)'),
    0x3d22a35: ('488d1594699f01', 'record Location 58:34'),
    0x3d22a3c: ('be01000000', 'esi 1'),
    0x3d22a44: ('ff1566c5a401', 'record, no min'),
    0x3d22a70: ('498907', 'store block_time date/secs at +0x7d0'),
    0x3d22a77: ('41894708', 'store block_time frac at +0x7d8'),
    0x3d22a7f: ('4189470c', 'store now date at +0x7dc'),
    0x3d22a88: ('49894710', 'store now secs/frac at +0x7e0'),
    0x3d22a96: ('c3', 'ret'),
    0x3d22511: ('4989f6', 'height'),
    0x3d22514: ('4889fb', 'self'),
    0x3d2251c: ('ff157ec3a401', 'wall clock now'),
    0x3d22522: ('83bbd007000000', 'last_times tag'),
    0x3d22529: ('0f8458030000', 'None returns'),
    0x3d22539: ('898c24b8000000', 'row block_time frac'),
    0x3d22543: ('48898424b0000000', 'row block_time'),
    0x3d2254b: ('488b83dc070000', 'begin wall'),
    0x3d22552: ('48898424bc000000', 'row begin wall'),
    0x3d22560: ('898424c4000000', 'row begin wall frac'),
    0x3d2257d: ('48b80100000042000000', 'callsite {1, line 66}'),
    0x3d2258c: ('488d0588a789fc', 'callsite file'),
    0x3d225c6: ('ff15f4c2a401', 'elapsed(now, begin wall)'),
    0x3d225d0: ('f20f11442470', 'raw elapsed saved'),
    0x3d225d6: ('488dbbc0040000', 'sampler self+0x4c0'),
    0x3d225dd: ('f20f100513864efc', '60.0'),
    0x3d225e5: ('f20f5dc1', 'min(60, elapsed)'),
    0x3d225e9: ('488d15b06d9f01', 'record Location 67:48'),
    0x3d225f0: ('be01000000', 'esi 1'),
    0x3d225f5: ('ff15b5c9a401', 'record'),
    0x3d225fb: ('4c89b424a0000000', 'row height'),
    0x3d22603: ('f20f10442470', 'raw elapsed'),
    0x3d22609: ('f20f118424a8000000', 'row apply_duration = raw'),
    0x3d22612: ('31c0', 'zero'),
    0x3d22614: ('483b8368070000', '0 - writer tag overflows only for i64::MIN'),
    0x3d2261b: ('0f8066020000', 'no writer returns'),
    0x3d22621: ('8b442418', 'now.secs'),
    0x3d22625: ('3d00100e00', 'secs vs 921600'),
    0x3d2262a: ('0f8369020000', 'unwrap panic'),
    0x3d22630: ('3d905f0100', 'secs vs 90000'),
    0x3d22635: ('0f8383020000', 'hour assert panic'),
    0x3d2263b: ('4c8db368070000', 'writer at +0x768'),
    0x3d22642: ('8b6c2414', 'now.date'),
    0x3d22646: ('80bbc807000001', 'hour tag [+0x7c8] == 1'),
    0x3d2264d: ('0f85fe000000', 'not 1: daily branch'),
    0x3d22655: ('41bdc5b3a291', 'divide by 3600 magic'),
    0x3d2265f: ('49c1ed2b', 'shift 43'),
    0x3d22663: ('4438abc9070000', 'hour vs [+0x7c9]'),
    0x3d2266a: ('750c', 'hour changed rotates'),
    0x3d2266c: ('3babb8070000', 'date vs [+0x7b8]'),
    0x3d22672: ('0f8490010000', 'same period'),
    0x3d22678: ('0f108328070000', 'root [+0x728]'),
    0x3d22697: ('488d0512b47bfd', 'root Display'),
    0x3d226ad: ('488b05acc3a401', 'date Display slot'),
    0x3d226c3: ('488b0556c4a401', 'hour Display slot'),
    0x3d226cf: ('488d35bd6c4cfc', 'hourly template'),
    0x3d226e6: ('ff1554b9a401', 'format path'),
    0x3d226f7: ('ff15c3c3a401', 'open writer'),
    0x3d22700: ('e83bdaffff', 'drop old writer'),
    0x3d22734: ('410f1106', 'store writer'),
    0x3d22738: ('89abb8070000', 'store date'),
    0x3d2273e: ('c683c807000001', 'hour tag 1'),
    0x3d22745: ('4488abc9070000', 'store hour'),
    0x3d22751: ('3babb8070000', 'date vs [+0x7b8]'),
    0x3d22757: ('0f84ab000000', 'same day'),
    0x3d22799: ('488d35ee6b4cfc', 'daily template'),
    0x3d227b0: ('ff158ab8a401', 'format path'),
    0x3d227c1: ('ff15f9c2a401', 'open writer'),
    0x3d227ca: ('e871d9ffff', 'drop old writer'),
    0x3d227fe: ('410f1106', 'store writer'),
    0x3d22802: ('89abb8070000', 'store date'),
    0x3d22808: ('49bf0000000000000080', 'writer None niche'),
    0x3d22817: ('488d742428', '&now copy'),
    0x3d2282e: ('488d9424a0000000', '&row'),
    0x3d22839: ('e8b2270000', 'write row'),
    0x3d22842: ('8983c4070000', 'store now frac at +0x7c4'),
    0x3d2284d: ('488983bc070000', 'store now at +0x7bc'),
    0x3d22854: ('80bbca07000000', 'flag [+0x7ca]'),
    0x3d2285b: ('741c', 'zero skips first call'),
    0x3d2285d: ('488b05b4c6a401', 'global flag pointer'),
    0x3d22864: ('0fb600', 'global flag byte'),
    0x3d22869: ('740e', 'zero skips first call'),
    0x3d2286b: ('4d393e', 'writer present?'),
    0x3d2286e: ('7417', 'absent returns'),
    0x3d22873: ('ff152fc2a401', 'first writer call'),
    0x3d22879: ('4d393e', 'writer present?'),
    0x3d2287c: ('7409', 'absent returns'),
    0x3d22881: ('ff1521c2a401', 'second writer call'),
    0x3d22898: ('c3', 'ret'),
    0x3d22899: ('488d3d0a754ffc', 'unwrap message'),
    0x3d228a0: ('488d0d99839401', 'error Debug vtable'),
    0x3d228a7: ('4c8d051a829401', 'time.rs Location'),
    0x3d228b3: ('be2b000000', 'length 0x2b'),
    0x3d228b8: ('ff158ab7a401', 'unwrap_failed'),
    0x3d228be: ('488d3d64464ffc', 'assert message'),
    0x3d228c5: ('488d150c459401', 'hour.rs Location'),
    0x3d228cc: ('be1c000000', 'length 0x1c'),
    0x3d228d1: ('ff1531b8a401', 'panic'),
    0x3d22ab1: ('f20f11442418', 'f64 argument'),
    0x3d22ab7: ('4989fc', 'out'),
    0x3d22aba: ('4889742438', 'prefix ptr'),
    0x3d22abf: ('4889542440', 'prefix len'),
    0x3d22ace: ('4c8d35eb0c0000', 'str Display'),
    0x3d22ada: ('488d35eebe4dfc', '_block_duration template'),
    0x3d22aeb: ('ff154fb5a401', 'format'),
    0x3d22b03: ('f20f1005257c4efc', '1.0'),
    0x3d22b0b: ('31f6', 'esi 0'),
    0x3d22b12: ('ff15b0c4a401', 'sampler new'),
    0x3d22b28: ('488d353ab04bfc', '_backlog_from_node template'),
    0x3d22b59: ('f20f1005cf7b4efc', '1.0'),
    0x3d22b61: ('be01000000', 'esi 1'),
    0x3d22b72: ('ff1550c4a401', 'sampler new'),
    0x3d22b88: ('488d35c4cd4cfc', '_begin_block_to_commit template'),
    0x3d22bb6: ('f20f10059a834efc', '0.06'),
    0x3d22bbe: ('31f6', 'esi 0'),
    0x3d22bc3: ('ff15ffc3a401', 'sampler new'),
    0x3d22bc9: ('48c744245801000000', 'third sampler word 0 = 1'),
    0x3d22bd2: ('f20f10442418', 'f64 argument'),
    0x3d22bd8: ('f20f11442460', 'third sampler word 1 = argument'),
    0x3d22beb: ('ba60020000', '0x260'),
    0x3d22bf0: ('ff15eab3a401', 'memcpy'),
    0x3d22c00: ('488d3554f84cfc', '_block_times template'),
    0x3d22c11: ('ff1529b4a401', 'format'),
    0x3d22c2e: ('ff15dcc2a401', 'reporter new'),
    0x3d22c48: ('4c89e7', 'out'),
    0x3d22c4b: ('41ffd7', 'sampler 0 to +0x000'),
    0x3d22c4e: ('498dbc2460020000', '+0x260'),
    0x3d22c63: ('41ffd7', 'sampler 1'),
    0x3d22c66: ('498dbc24c0040000', '+0x4c0'),
    0x3d22c7b: ('41ffd7', 'sampler 2'),
    0x3d22c7e: ('41c78424d007000000000000', 'last_times None'),
    0x3d22c8a: ('498dbc2420070000', '+0x720'),
    0x3d22c97: ('bab0000000', '0xb0'),
    0x3d22c9c: ('41ffd7', 'reporter'),
    0x3d22cf5: ('4c89e0', 'return out'),
    0x3d25004: ('bf80000000', '0x80'),
    0x3d25009: ('ff15c98fa401', 'allocate'),
    0x3d25041: ('e8caddffff', 'serialize row'),
    0x3d250df: ('c604030a', 'newline'),
    0x3d250e9: ('4c89f6', '&now'),
    0x3d250f2: ('e8a9c16afd', 'append line'),
    0x3d22e30: ('c604017b', '{'),
    0x3d22e47: ('488d35d09c89fc', 'height'),
    0x3d22e53: ('ba06000000', 'length 6'),
    0x3d22e58: ('4889d9', 'row+0x00'),
    0x3d22e5b: ('e870360000', 'u64 field'),
    0x3d22e74: ('488d4b10', 'row+0x10'),
    0x3d22e78: ('488d35de9e89fc', 'block_time'),
    0x3d22e84: ('ba0a000000', 'length 10'),
    0x3d22e89: ('e842320000', 'time field'),
    0x3d22e9e: ('488d4b1c', 'row+0x1c'),
    0x3d22ea2: ('488d35be9e89fc', 'begin_block_wall_time'),
    0x3d22eae: ('ba15000000', 'length 21'),
    0x3d22eb3: ('e818320000', 'time field'),
    0x3d22ec4: ('4883c308', 'row+0x08'),
    0x3d22ec8: ('488d35ad9e89fc', 'apply_duration'),
    0x3d22ed4: ('ba0e000000', 'length 14'),
    0x3d22edc: ('e88f330000', 'f64 field'),
    0x13d1888: ('e8d3fbffff', 'buffer access'),
    0x13d1890: ('e89b1c0f00', 'flush buffer'),
    0x13d189b: ('83f801', 'io::Error tag 1'),
    0x13d18ab: ('c3', 'ret'),
}

# va: (instruction length, target) for every rel8/rel32 branch, call and RIP-relative operand in the windows.
OPERANDS = {
    0x13d1888: (5, 0x13d1460),  # writer_helper: call
    0x13d1890: (5, 0x14c3530),  # writer_helper: call
    0x13d189e: (2, 0x13d18ac),  # writer_helper: je
    0x144714b: (6, 0x14471d4),  # elapsed: jne
    0x144715b: (2, 0x14471d4),  # elapsed: jne
    0x1447164: (2, 0x14471d8),  # elapsed: jb
    0x1447166: (6, 0x576eaa0),  # elapsed: call
    0x144718c: (2, 0x14471ce),  # elapsed: jo
    0x14471bc: (2, 0x14471ce),  # elapsed: jne
    0x14471c6: (8, 0x20ae60),  # elapsed: divsd
    0x14471d6: (2, 0x1447166),  # elapsed: je
    0x14471dd: (7, 0x14548b0),  # elapsed: lea
    0x14471f6: (7, 0x1f9cb6),  # elapsed: lea
    0x1447207: (6, 0x576e040),  # elapsed: call
    0x1447210: (2, 0x144721c),  # elapsed: je
    0x1447212: (6, 0x577ab98),  # elapsed: mov
    0x144721a: (2, 0x1447241),  # elapsed: jne
    0x1447228: (2, 0x14471ce),  # elapsed: je
    0x1447231: (6, 0x576e010),  # elapsed: call
    0x1447241: (7, 0x577ab80),  # elapsed: lea
    0x1447257: (7, 0x577ab98),  # elapsed: lea
    0x144725e: (7, 0x5669f68),  # elapsed: lea
    0x1447265: (7, 0x5669f50),  # elapsed: lea
    0x1447276: (6, 0x576e8b8),  # elapsed: call
    0x144727c: (2, 0x144721c),  # elapsed: jmp
    0x3d2251c: (6, 0x576e8a0),  # commit: call
    0x3d22529: (6, 0x3d22887),  # commit: je
    0x3d2258c: (7, 0x5bcd1b),  # commit: lea
    0x3d225c6: (6, 0x576e8c0),  # commit: call
    0x3d225dd: (8, 0x20abf8),  # commit: movsd
    0x3d225e9: (7, 0x57193a0),  # commit: lea
    0x3d225f5: (6, 0x576efb0),  # commit: call
    0x3d2261b: (6, 0x3d22887),  # commit: jo
    0x3d2262a: (6, 0x3d22899),  # commit: jae
    0x3d22635: (6, 0x3d228be),  # commit: jae
    0x3d2264d: (6, 0x3d22751),  # commit: jne
    0x3d2266a: (2, 0x3d22678),  # commit: jne
    0x3d22672: (6, 0x3d22808),  # commit: je
    0x3d22697: (7, 0x14ddab0),  # commit: lea
    0x3d226ad: (7, 0x576ea60),  # commit: mov
    0x3d226c3: (7, 0x576eb20),  # commit: mov
    0x3d226cf: (7, 0x1e9393),  # commit: lea
    0x3d226e6: (6, 0x576e040),  # commit: call
    0x3d226f7: (6, 0x576eac0),  # commit: call
    0x3d22700: (5, 0x3d20140),  # commit: call
    0x3d2274c: (5, 0x3d22808),  # commit: jmp
    0x3d22757: (6, 0x3d22808),  # commit: je
    0x3d22777: (7, 0x14ddab0),  # commit: lea
    0x3d2278d: (7, 0x576ea60),  # commit: mov
    0x3d22799: (7, 0x1e938e),  # commit: lea
    0x3d227b0: (6, 0x576e040),  # commit: call
    0x3d227c1: (6, 0x576eac0),  # commit: call
    0x3d227ca: (5, 0x3d20140),  # commit: call
    0x3d22839: (5, 0x3d24ff0),  # commit: call
    0x3d2285b: (2, 0x3d22879),  # commit: je
    0x3d2285d: (7, 0x576ef18),  # commit: mov
    0x3d22869: (2, 0x3d22879),  # commit: je
    0x3d2286e: (2, 0x3d22887),  # commit: je
    0x3d22873: (6, 0x576eaa8),  # commit: call
    0x3d2287c: (2, 0x3d22887),  # commit: je
    0x3d22881: (6, 0x576eaa8),  # commit: call
    0x3d22899: (7, 0x219daa),  # commit: lea
    0x3d228a0: (7, 0x566ac40),  # commit: lea
    0x3d228a7: (7, 0x566aac8),  # commit: lea
    0x3d228b8: (6, 0x576e048),  # commit: call
    0x3d228be: (7, 0x216f29),  # commit: lea
    0x3d228c5: (7, 0x5666dd8),  # commit: lea
    0x3d228d1: (6, 0x576e108),  # commit: call
    0x3d228d7: (2, 0x3d228d9),  # commit: jmp
    0x3d22937: (6, 0x576e8a0),  # begin: call
    0x3d22945: (6, 0x3d229cd),  # begin: je
    0x3d22971: (7, 0x5bcd1b),  # begin: lea
    0x3d229a2: (6, 0x576e8c0),  # begin: call
    0x3d229a8: (8, 0x20abf8),  # begin: movsd
    0x3d229b4: (7, 0x57193b8),  # begin: lea
    0x3d229c7: (6, 0x576efb0),  # begin: call
    0x3d229d7: (2, 0x3d22a4a),  # begin: je
    0x3d229fe: (7, 0x5bcd1b),  # begin: lea
    0x3d22a2f: (6, 0x576e8c0),  # begin: call
    0x3d22a35: (7, 0x57193d0),  # begin: lea
    0x3d22a44: (6, 0x576efb0),  # begin: call
    0x3d22ace: (7, 0x3d237c0),  # ctor: lea
    0x3d22ada: (7, 0x1fe9cf),  # ctor: lea
    0x3d22aeb: (6, 0x576e040),  # ctor: call
    0x3d22b03: (8, 0x20a730),  # ctor: movsd
    0x3d22b12: (6, 0x576efc8),  # ctor: call
    0x3d22b28: (7, 0x1ddb69),  # ctor: lea
    0x3d22b3c: (6, 0x576e040),  # ctor: call
    0x3d22b59: (8, 0x20a730),  # ctor: movsd
    0x3d22b72: (6, 0x576efc8),  # ctor: call
    0x3d22b88: (7, 0x1ef953),  # ctor: lea
    0x3d22b9c: (6, 0x576e040),  # ctor: call
    0x3d22bb6: (8, 0x20af58),  # ctor: movsd
    0x3d22bc3: (6, 0x576efc8),  # ctor: call
    0x3d22bf0: (6, 0x576dfe0),  # ctor: call
    0x3d22c00: (7, 0x1f245b),  # ctor: lea
    0x3d22c11: (6, 0x576e040),  # ctor: call
    0x3d22c2e: (6, 0x576ef10),  # ctor: call
    0x3d22c3c: (7, 0x576dfe0),  # ctor: mov
    0x3d22ca2: (2, 0x3d22cb2),  # ctor: je
    0x3d22cac: (6, 0x576e010),  # ctor: call
    0x3d22cb9: (2, 0x3d22cc9),  # ctor: je
    0x3d22cc3: (6, 0x576e010),  # ctor: call
    0x3d22ccc: (2, 0x3d22cde),  # ctor: je
    0x3d22cd8: (6, 0x576e010),  # ctor: call
    0x3d22ce6: (2, 0x3d22cf5),  # ctor: je
    0x3d22cef: (6, 0x576e010),  # ctor: call
    0x3d22e26: (6, 0x3d22f35),  # row_serialize: je
    0x3d22e47: (7, 0x5bcb1e),  # row_serialize: lea
    0x3d22e5b: (5, 0x3d264d0),  # row_serialize: call
    0x3d22e63: (6, 0x3d22f2b),  # row_serialize: jne
    0x3d22e6e: (6, 0x3d22f13),  # row_serialize: jne
    0x3d22e78: (7, 0x5bcd5d),  # row_serialize: lea
    0x3d22e89: (5, 0x3d260d0),  # row_serialize: call
    0x3d22e91: (6, 0x3d22f2b),  # row_serialize: jne
    0x3d22e9c: (2, 0x3d22f13),  # row_serialize: jne
    0x3d22ea2: (7, 0x5bcd67),  # row_serialize: lea
    0x3d22eb3: (5, 0x3d260d0),  # row_serialize: call
    0x3d22ebb: (2, 0x3d22f2b),  # row_serialize: jne
    0x3d22ec2: (2, 0x3d22f13),  # row_serialize: jne
    0x3d22ec8: (7, 0x5bcd7c),  # row_serialize: lea
    0x3d22edc: (5, 0x3d26270),  # row_serialize: call
    0x3d25009: (6, 0x576dfd8),  # row_writer: call
    0x3d25012: (6, 0x3d25129),  # row_writer: je
    0x3d25041: (5, 0x3d22e10),  # row_writer: call
    0x3d2504c: (2, 0x3d25067),  # row_writer: je
    0x3d25056: (2, 0x3d25079),  # row_writer: je
    0x3d2505f: (6, 0x576e010),  # row_writer: call
    0x3d25065: (2, 0x3d25079),  # row_writer: jmp
    0x3d25077: (2, 0x3d250c3),  # row_writer: jno
    0x3d25080: (2, 0x3d2509e),  # row_writer: je
    0x3d25085: (2, 0x3d250a7),  # row_writer: jne
    0x3d2508e: (2, 0x3d250a7),  # row_writer: je
    0x3d25096: (6, 0x576e010),  # row_writer: call
    0x3d2509c: (2, 0x3d250a7),  # row_writer: jmp
    0x3d250a2: (5, 0x3d254a0),  # row_writer: call
    0x3d250b1: (6, 0x576e010),  # row_writer: call
    0x3d250dd: (2, 0x3d25103),  # row_writer: je
    0x3d250f2: (5, 0x13d12a0),  # row_writer: call
    0x3d250ff: (2, 0x3d250ac),  # row_writer: jne
    0x3d25101: (2, 0x3d250b7),  # row_writer: jmp
    0x3d25118: (5, 0x13edc40),  # row_writer: call
    0x3d25127: (2, 0x3d250df),  # row_writer: jmp
}

SLOTS = {
    0x576e8a0: (0x151cba0, 'wall clock now'),
    0x576e8c0: (ELAPSED, 'elapsed seconds'),
    0x576eaa0: (0x151d1b0, 'signed_duration_since'),
    0x576e040: (0x1344760, 'format to String'),
    0x576e8b8: (0x4ee3b20, 'once slot'),
    0x576e010: (0x54c8cb0, 'dealloc'),
    0x576efb0: (0x14027b0, 'sampler record'),
    0x576efc8: (0x1403c30, 'sampler new'),
    0x576ef10: (0x1402050, 'block-times reporter new'),
    0x576ea60: (0x1454a00, 'date Display'),
    0x576eb20: (0x13d95e0, 'hour Display'),
    0x576eac0: (0x13d1720, 'open writer'),
    0x576eaa8: (WRITER_HELPER, 'writer helper'),
    0x576ef18: (0x5788312, 'global flag byte'),
    0x576e048: (0x157aa10, 'Result::unwrap failed'),
    0x576e108: (0x157b7f0, 'panic'),
    0x576dfe0: ('memcpy', 'memcpy'),
}
SLOTS.update({slot: (fn, 'entry point') for slot, fn in ENTRY_SLOTS.items()})

TEXT = {
    SOURCE: b'/home/ubuntu/hl/code_Mainnet/net_utils/src/abci_latency_sampler.rs',
    0x219daa: b'called `Result::unwrap()` on an `Err` value',
    0x216f29: b'assertion failed: hour <= 24',
    0x5bcb1e: b'height',
    0x5bcd5d: b'block_time',
    0x5bcd67: b'begin_block_wall_time',
    0x5bcd7c: b'apply_duration',
}
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


def callsite(f, va):
    """`movabs rax, imm64` building the `{1, line}` head of the elapsed call's source tag."""
    raw = f[va]
    require(raw[:2] == bytes.fromhex('48b8'), f'{va:#x} is not movabs rax')
    flag, line = struct.unpack('<II', raw[2:10])
    require(flag == 1, f'callsite at {va:#x} has flag {flag}')
    return line


def check_elapsed(f):
    o = OPERANDS
    require(f[0x1447146] == bytes.fromhex('3907') and f[0x1447148] == bytes.fromhex('0f9cc0'),
            'date is not compared signed first')
    require(f[0x1447154] == bytes.fromhex('3b442404') and f[0x1447158] == bytes.fromhex('0f92c0'),
            'secs are not compared unsigned second')
    require(f[0x1447160] == bytes.fromhex('3b442408') and o[0x1447164] == (2, 0x14471d8),
            'a smaller now.frac no longer takes the error arm')
    require(o[0x144714b][1] == o[0x144715b][1] == 0x14471d4 and o[0x14471d6] == (2, 0x1447166),
            'differing date or secs no longer route on the comparison flag')
    require(f[0x1447143] == bytes.fromhex('8b5e10') and f[0x144720d] == bytes.fromhex('f6c301'),
            'callsite flag is not [rsi+0x10] bit 0')
    require(o[0x14471f6][1] == 0x1f9cb6 and o[0x1447207][1] == 0x576e040, 'error arm does not format Time Sub')
    require(o[0x1447212][1] == 0x577ab98 and o[0x144721a] == (2, 0x1447241) and o[0x1447276][1] == 0x576e8b8,
            'once slot gate changed')
    require(o[0x144727c] == (2, 0x144721c) and f[0x1447221] == bytes.fromhex('660f57c0') and
            o[0x1447228] == (2, 0x14471ce) and f[0x1447237] == bytes.fromhex('660f57c0') and
            f[0x1447240] == b'\xc3', 'error arm no longer returns 0.0')
    require(o[0x1447166][1] == 0x576eaa0, 'later now does not call signed_duration_since')
    require(imm32(f[0x1447181]) == 1_000_000 and o[0x144718c] == (2, 0x14471ce) and f[0x1447188] == bytes.fromhex('660f57c0'),
            'secs * 1e6 overflow no longer returns 0.0')
    require(imm32(f[0x144718e]) == (-1_000_000_000) & 0xffffffff, 'nanos borrow changed')
    require(imm32(f[0x144719c]) == 0x10624dd3 and f[0x14471aa] == bytes.fromhex('48c1f926'),
            'nanos are not divided by 1000')
    require(all((n * 0x10624dd3) >> 38 == n // 1000 for n in range(0, 1_000_000_000, 9973)),
            'magic constant is not a truncating divide by 1000')
    require(o[0x14471bc] == (2, 0x14471ce) and f[0x14471c1] == bytes.fromhex('f2480f2ac0') and
            o[0x14471c6][1] == 0x20ae60, 'micros are not converted and divided by 1e6')
    return dict(order='(date i32 signed, secs u32, frac u32) lexicographic',
                earlier='formats "Time Sub {} {}", calls the once slot when [rsi+0x10]&1 and dword 0x577ab98 != 0, '
                        'drops the message, returns 0.0',
                later='signed_duration_since, whole microseconds (secs*1e6 + nanos/1000), f64 / 1e6; overflow returns 0.0')


def check_begin(f):
    o = OPERANDS
    require(f[0x3d2292a] == bytes.fromhex('89d5') and f[0x3d229d4] == bytes.fromhex('4084ed') and
            o[0x3d229d7] == (2, 0x3d22a4a), 'backlog is not gated on came_from_node')
    require(o[0x3d22937][1] == 0x576e8a0 and disp32(f[0x3d2293d][:-1]) == 0x7d0 and o[0x3d22945] == (6, 0x3d229cd),
            'block_duration is not gated on last_times')
    require(disp32(f[0x3d2294b]) == 0x7e4 and disp32(f[0x3d22956]) == 0x7dc, 'block_duration does not use the last begin wall time')
    lines = dict(block_duration=callsite(f, 0x3d22962), backlog=callsite(f, 0x3d229ef))
    require(lines == dict(block_duration=54, backlog=58), f'elapsed callsite lines are {lines}')
    require(o[0x3d22971][1] == o[0x3d229fe][1] == SOURCE and imm32(f[0x3d2297d]) == 0x42, 'callsite file changed')
    require(o[0x3d229a2][1] == o[0x3d22a2f][1] == 0x576e8c0, 'begin no longer calls the elapsed helper')
    require(o[0x3d229a8][1] == 0x20abf8 and f[0x3d229b0] == bytes.fromhex('f20f5dc8'), 'block_duration is not min(60, x)')
    require(o[0x3d229b4][1] == 0x57193b8 and f[0x3d229c0] == bytes.fromhex('4c89f7') and o[0x3d229c7][1] == 0x576efb0,
            'block_duration is not recorded on sampler +0x000')
    require(imm32(f[0x3d229d9]) == 0x260 and o[0x3d22a35][1] == 0x57193d0 and o[0x3d22a44][1] == 0x576efb0,
            'backlog is not recorded on sampler +0x260')
    code = bytes.fromhex(WINDOWS['begin'][2])
    require(b'\xf2\x0f\x5d' not in code[0x3d22a2f - BEGIN:0x3d22a44 - BEGIN], 'backlog gained a min')
    require(f[0x3d22a70] == bytes.fromhex('498907') and f[0x3d22a7f] == bytes.fromhex('4189470c') and
            f[0x3d22a88] == bytes.fromhex('49894710'), 'last_times store changed')
    return dict(block_duration='min(60, elapsed(now, [+0x7dc])) to +0x000 when [+0x7d0] != 0',
                backlog='elapsed(now, block_time) to +0x260 when came_from_node; no cap',
                store='[+0x7d0] = block_time, [+0x7dc] = now', callsite_lines=lines)


def check_commit(f):
    o = OPERANDS
    require(o[0x3d2251c][1] == 0x576e8a0 and o[0x3d22529] == (6, 0x3d22887), 'no last_times no longer returns')
    require(callsite(f, 0x3d2257d) == 66 and o[0x3d2258c][1] == SOURCE and o[0x3d225c6][1] == 0x576e8c0,
            'apply elapsed callsite changed')
    require(f[0x3d225d0] == bytes.fromhex('f20f11442470') and f[0x3d22603] == bytes.fromhex('f20f10442470') and
            f[0x3d22609] == bytes.fromhex('f20f118424a8000000'), 'row apply_duration is not the raw elapsed value')
    require(o[0x3d225dd][1] == 0x20abf8 and f[0x3d225e5] == bytes.fromhex('f20f5dc1') and
            imm32(f[0x3d225d6]) == 0x4c0 and o[0x3d225e9][1] == 0x57193a0 and o[0x3d225f5][1] == 0x576efb0,
            'commit sample is not min(60, apply) on +0x4c0')
    require(f[0x3d22612] == bytes.fromhex('31c0') and disp32(f[0x3d22614]) == 0x768 and o[0x3d2261b] == (6, 0x3d22887),
            'missing writer no longer returns after the sample')
    require(imm32(f[0x3d22625]) == SECS_UNWRAP and o[0x3d2262a] == (6, 0x3d22899) and
            imm32(f[0x3d22630]) == SECS_HOUR and o[0x3d22635] == (6, 0x3d228be), 'second-of-day checks changed')
    require(o[0x3d22899][1] == 0x219daa and o[0x3d228a7][1] == 0x566aac8 and imm32(f[0x3d228b3]) == 0x2b and
            o[0x3d228b8][1] == 0x576e048, 'secs >= 921600 is not the time.rs unwrap panic')
    require(o[0x3d228be][1] == 0x216f29 and o[0x3d228c5][1] == 0x5666dd8 and imm32(f[0x3d228cc]) == 0x1c and
            o[0x3d228d1][1] == 0x576e108, 'secs >= 90000 is not the hour.rs assert')
    require(f[0x3d22646][-1] == 1 and disp32(f[0x3d22646][:-1]) == 0x7c8 and o[0x3d2264d] == (6, 0x3d22751),
            'hourly branch is not [+0x7c8] == 1')
    require(imm32(f[0x3d22655]) == 0x91a2b3c5 and f[0x3d2265f] == bytes.fromhex('49c1ed2b'), 'hour is not secs / 3600')
    require(all((s * 0x91a2b3c5) >> 43 == s // 3600 for s in range(0, SECS_UNWRAP, 7)), 'magic is not exact below 921600')
    require(o[0x3d2266a] == (2, 0x3d22678) and o[0x3d22672] == (6, 0x3d22808) and o[0x3d22757] == (6, 0x3d22808),
            'rotation conditions changed')
    require(o[0x3d226cf][1] == 0x1e9393 and o[0x3d22799][1] == 0x1e938e, 'path templates changed')
    require(o[0x3d22697][1] == 0x14ddab0 and o[0x3d226ad][1] == 0x576ea60 and o[0x3d226c3][1] == 0x576eb20,
            'path argument formatters changed')
    require(o[0x3d226f7][1] == o[0x3d227c1][1] == 0x576eac0 and o[0x3d22700][1] == o[0x3d227ca][1] == 0x3d20140,
            'rotation no longer opens a writer and drops the old one')
    require(f[0x3d2273e] == bytes.fromhex('c683c807000001') and disp32(f[0x3d22745]) == 0x7c9 and
            disp32(f[0x3d22738]) == disp32(f[0x3d22802]) == 0x7b8, 'rotation bookkeeping changed')
    require(o[0x3d22839][1] == ROW_WRITER and disp32(f[0x3d2282e]) == 0xa0, 'row writer call changed')
    require(disp32(f[0x3d2284d]) == 0x7bc and disp32(f[0x3d22842]) == 0x7c4, 'commit wall time is not stored at +0x7bc')
    require(f[0x3d22854][-1] == 0 and disp32(f[0x3d22854][:-1]) == 0x7ca and o[0x3d2285b] == (2, 0x3d22879) and
            o[0x3d2285d][1] == 0x576ef18 and o[0x3d22869] == (2, 0x3d22879), 'first writer call is not gated on +0x7ca and the flag')
    require(o[0x3d22873][1] == o[0x3d22881][1] == 0x576eaa8 and o[0x3d2287c] == (2, 0x3d22887) and
            o[0x3d2286e] == (2, 0x3d22887), 'writer helper calls changed')
    return dict(sample='min(60, elapsed(now, [+0x7dc])) to +0x4c0', no_writer='return after the sample',
                secs_checks={str(SECS_UNWRAP): location_tail(0x566aac8), str(SECS_HOUR): location_tail(0x5666dd8)},
                rotation=dict(hourly='[+0x7c8] == 1 and ([+0x7c9] != hour or [+0x7b8] != date)', daily='[+0x7b8] != date'),
                row=dict(apply_duration='raw elapsed (no cap)', writer=hex(ROW_WRITER)),
                commit_time='[+0x7bc] = now', writer_helper='once, plus once more first when [+0x7ca] and byte 0x5788312')


def location_tail(va):
    return LOCATIONS[va].lstrip('/')


def check_ctor(f):
    o = OPERANDS
    require(f[0x3d22ab1] == bytes.fromhex('f20f11442418') and f[0x3d22aba] == bytes.fromhex('4889742438') and
            f[0x3d22abf] == bytes.fromhex('4889542440'), 'constructor arguments changed')
    names = [(0x3d22ada, 0x3d22b03, 0x3d22b0b, 0x3d22b12), (0x3d22b28, 0x3d22b59, 0x3d22b61, 0x3d22b72),
             (0x3d22b88, 0x3d22bb6, 0x3d22bbe, 0x3d22bc3)]
    samplers = []
    for name, const, flag, call in names:
        require(o[call][1] == 0x576efc8, f'sampler new at {call:#x} changed')
        esi = 0 if f[flag] == bytes.fromhex('31f6') else imm32(f[flag])
        samplers.append(dict(name=TEMPLATES[o[name][1]][1][1], constant=F64[o[const][1]], esi=esi))
    require([(s['constant'], s['esi']) for s in samplers] == [(1.0, 0), (1.0, 1), (0.06, 0)], f'samplers are {samplers}')
    require(f[0x3d22bc9] == bytes.fromhex('48c744245801000000') and f[0x3d22bd2] == bytes.fromhex('f20f10442418') and
            f[0x3d22bd8] == bytes.fromhex('f20f11442460') and o[0x3d22bf0][1] == 0x576dfe0,
            'third sampler no longer takes the f64 argument')
    require(o[0x3d22c00][1] == 0x1f245b and o[0x3d22c2e][1] == 0x576ef10, 'reporter construction changed')
    require(imm32(f[0x3d22c4e]) == 0x260 and imm32(f[0x3d22c66]) == 0x4c0 and imm32(f[0x3d22c8a]) == 0x720 and
            imm32(f[0x3d22c97]) == 0xb0, 'field layout changed')
    require(f[0x3d22c7e] == bytes.fromhex('41c78424d007000000000000'), 'last_times is not cleared')
    return dict(arguments='rdi out, rsi/rdx prefix, xmm0 f64', samplers=samplers,
                f64_argument='third sampler words 0/1 = {1, argument}', reporter='"{prefix}_block_times" -> +0x720 (0xb0 bytes)',
                last_times='[+0x7d0] = 0')


def check_row(f):
    o = OPERANDS
    keys = [(0x3d22e47, 0x3d22e53, 0), (0x3d22e78, 0x3d22e84, 0x10), (0x3d22ea2, 0x3d22eae, 0x1c), (0x3d22ec8, 0x3d22ed4, 8)]
    row = []
    for lea, length, _ in keys:
        text = TEXT[o[lea][1]]
        require(imm32(f[length]) == len(text), f'key at {lea:#x} length changed')
        row.append(text.decode())
    require(f[0x3d22e58] == bytes.fromhex('4889d9') and f[0x3d22e74] == bytes.fromhex('488d4b10') and
            f[0x3d22e9e] == bytes.fromhex('488d4b1c') and f[0x3d22ec4] == bytes.fromhex('4883c308'),
            'row field offsets changed')
    require(o[0x3d22e5b][1] == 0x3d264d0 and o[0x3d22e89][1] == o[0x3d22eb3][1] == 0x3d260d0 and
            o[0x3d22edc][1] == 0x3d26270, 'field serializers changed')
    require(o[0x3d25041][1] == ROW_SERIALIZE and imm32(f[0x3d25004]) == 0x80 and f[0x3d250df] == bytes.fromhex('c604030a') and
            f[0x3d250e9] == bytes.fromhex('4c89f6') and o[0x3d250f2][1] == 0x13d12a0, 'row line write changed')
    require(o[0x13d1888][1] == 0x13d1460 and o[0x13d1890][1] == 0x14c3530, 'writer helper callees changed')
    return dict(keys=row, offsets=dict(height=0, block_time=0x10, begin_block_wall_time=0x1c, apply_duration=8),
                line='JSON object ("{" then four keyed fields) + "\\n", appended by 0x13d12a0(writer, &now, bytes, len)')


def check_callers(img):
    text = next((x for x in img.secs if x['name'] == '.text'), None)
    require(text is not None, 'no .text section')
    code = img.data[text['offset']:text['offset'] + text['size']]
    direct = {fn: [] for fn in (CTOR, BEGIN, COMMIT, ROW_WRITER, ROW_SERIALIZE)}
    pos = code.find(b'\xe8')
    while 0 <= pos < len(code) - 4:
        t = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
        if t in direct:
            direct[t].append(text['address'] + pos)
        pos = code.find(b'\xe8', pos + 1)
    require(not direct[CTOR] and not direct[BEGIN] and not direct[COMMIT], 'an entry point gained a direct call')
    require(direct[ROW_WRITER] == [0x3d22839] and direct[ROW_SERIALIZE] == [0x3d25041], 'row writer callers changed')
    for fn in (CTOR, BEGIN, COMMIT):
        require([s for s, p in img.relative.items() if p == fn] == [k for k, v in ENTRY_SLOTS.items() if v == fn],
                f'{fn:#x} RELATIVE slots changed')
    indirect = {slot: [] for slot in ENTRY_SLOTS}
    pos = code.find(b'\xff\x15')
    while 0 <= pos < len(code) - 5:
        t = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
        if t in indirect:
            indirect[t].append(text['address'] + pos)
        pos = code.find(b'\xff\x15', pos + 1)
    out = {}
    for slot, fn in ENTRY_SLOTS.items():
        require(indirect[slot] == ENTRY_CALLS[fn], f'{fn:#x} is called from {[hex(v) for v in indirect[slot]]}')
        out[hex(fn)] = dict(slot=hex(slot), calls={hex(v): hex(img.containing(v)[0]) for v in indirect[slot]})
    return dict(entry=out, scanned='.text, every e8 rel32 and ff15 rip32')


def elapsed(now, earlier):
    """0x1447130 on (day, secs, nanos) triples: 0.0 when now < earlier, else whole microseconds as seconds."""
    if tuple(now) < tuple(earlier):
        return 0.0
    secs = (now[0] - earlier[0]) * 86400 + now[1] - earlier[1]
    nanos = now[2] - earlier[2]
    if nanos < 0:
        secs, nanos = secs - 1, nanos + 1_000_000_000
    micros = secs * 1_000_000 + nanos // 1000
    if not -2 ** 63 <= micros < 2 ** 63:
        return 0.0
    return micros / 1e6


def new_state(writer=True, hourly=False, day=None, hour=None, flush_flag=False, root='root'):
    return dict(last=None, writer=writer, hourly=hourly, day=day, hour=hour, flush_flag=flush_flag,
                root=root, last_commit=None)


def begin(state, block_time, came_from_node, now):
    """0x3d22920: list of (sampler offset, value) recorded, then last_times = (block_time, now)."""
    samples = []
    if state['last'] is not None:
        samples.append((0x000, min(60.0, elapsed(now, state['last'][1]))))
    if came_from_node:
        samples.append((0x260, elapsed(now, block_time)))
    state['last'] = (tuple(block_time), tuple(now))
    return samples


def commit(state, height, now, global_flag=False):
    """0x3d22500: samples, rotated path, row and writer-helper calls for one commit."""
    out = dict(samples=[], path=None, row=None, writer_calls=0)
    if state['last'] is None:
        return out
    block_time, begin_wall = state['last']
    apply = elapsed(now, begin_wall)
    out['samples'].append((0x4c0, min(60.0, apply)))
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
    out['row'] = dict(height=height, block_time=block_time, begin_block_wall_time=begin_wall, apply_duration=apply)
    state['last_commit'] = tuple(now)
    out['writer_calls'] = 2 if state['flush_flag'] and global_flag else 1
    return out


def analyse(data):
    img = Image(data)
    win = windows(img)
    f = facts(img)
    return dict(target=TARGET, fdes=[hex(v) for v in (CTOR, BEGIN, COMMIT, ELAPSED, ROW_WRITER, ROW_SERIALIZE, WRITER_HELPER)],
                windows={k: hex(v) for k, v in win.items()}, operands=check_operands(img),
                elapsed=check_elapsed(f), begin=check_begin(f), commit=check_commit(f), ctor=check_ctor(f),
                row=check_row(f), callers=check_callers(img))


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
    print(f"elapsed: earlier now -> 0.0; later -> {result['elapsed']['later']}")
    print(f"commit: no writer -> {result['commit']['no_writer']}; row apply -> {result['commit']['row']['apply_duration']}")
    print(f"ctor samplers: {result['ctor']['samplers']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
