#!/usr/bin/env python3
"""Static node #94 instrumented accept loops `0x203f3e0` / `0x2041c60`, checked from authenticated bytes.

Question: `0x203f3e0` and `0x2041c60` are `node/connections.rs` accept loops
that poll the accept wrapper `0x2048f10`.  What does each poll record, and
what happens on an accept error?  The can1357 lead
(`node/connections.rs` `accept_*_stream_connections`) has no instrumentation
and returns on the first accept error (`accept().await?`).

Each loop is wrapped in a tokio-metrics 0.3.1 instrumented future: every poll
reads the monotonic clock, updates first-poll, idle, scheduling-delay and
poll-duration counters on the task monitor `[[state]+0x30]`, and splits the
delay and poll time against two Duration thresholds at monitor `+0xa0` and
`+0x90`.  On an accept error the loop prints the same stdout line as
`0x22c0d30` and polls again; `0x2048f10` rejects IPv6 peers with `ip not v4`.

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; call, branch and RIP-relative
targets, the packed format template, string literals, the io::Error jump
table, four panic Locations, a waker vtable, RELATIVE and GLOB_DAT slots are
decoded here.  Nothing from the binary is executed.
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
LOOP_A = 0x203f3e0
LOOP_B = 0x2041c60
TWIN = LOOP_B - LOOP_A
ACCEPT = 0x2048f10
SELECT = 0x2032ae0
KIND_FMT = 0x4b6f890
PRINT = 0x4edba50
SPAWN_V = 0x225e860
SPAWN_G = 0x225e3b0
ACCEPT4 = 0x3cd6220
NOW = 0x4ee3800
SINCE = 0x4ee3730
TEMPLATE = 0x1fb0d4
TS_FORMAT = 0x3c42d1
JUMP_TABLE = 0x3c3d58
WAKER_VTABLE = 0x5691688
LAZY_PREFIX = 0x577ab50
SPAWN_CALL = 0x203ffe3
LOCATIONS = {
    0x5691708: '/tokio-metrics-0.3.1/src/task.rs:2483:23',
    0x5692c80: '/node/src/connections.rs:186:84',
    0x5753120: '/library/std/src/time.rs:429:33',
    0x56932e8: '/tokio-1.44.2/src/io/poll_evented.rs:288:26',
}

WINDOWS = {
    'entry_a': (LOOP_A, 0x203f3e0,
        '554157415641554154534881ecf80500004889fb4c8b26bf01000000e8ff43ea024989c689d54c8b2b498b4538488944'
        '2428418b45408944240480bb30020000004c89e80f859a000000c68330020000014c89b4247002000089ac2478020000'
        '488b44242848898424300400008b44240489842438040000488dbc2490000000488db42470020000488d942430040000'
        'e8bb42ea02b800ca9a3b48f7a424980000008b8c24a00000004801c84883d20031c948f7daba000000004819d24809c2'
        '80bc249000000000480f45d1498b4530f048015058488b03488b4030f048ff4018488b03'),
    'timing_a': (LOOP_A, 0x203f4c4,
        '31c94887481048398b280200007324498b4530f048ff40204889c8482b83280200000f825f050000498b5530f0480142'
        '60eb094885c90f8421010000498b4530f048ff40284889c848c1e80949bf535a9ba02fb8440049f7e748c1ea0b488b44'
        '24284801d00f80d20400004869d200ca9a3b4829d1034c240481f900ca9a3b720f48ffc00f80b304000081c1003665c4'
        '4c89b4247002000089ac24780200004889842430040000898c2438040000488dbc2490000000488db42470020000488d'
        '942430040000e8a141ea02b800ca9a3b48f7a424980000008b8c24a00000004801c84883d20031f648f7dab900000000'
        '4819c94809c180bc249000000000480f45ce4889c848c1e80949f7e748c1ea0b498b4530483b90a000000075214869d2'
        '00ca9a3b4889ce4829d639b0a8000000760eba80000000be48000000eb0c72f2ba88000000be40000000f048ff0430f0'
        '48010c10498b4530f0480148684c896c2448'),
    'resume_a': (LOOP_A, 0x203f6d7,
        '4c8d7308488b034883c010488d0d9f1f650348894c24604889442468488d4424604889442470488944247848c7842480'
        '00000000000000bf01000000e8e840ea024889c50fb6832202000085c08954243c741683f8030f845f040000488d3d46'
        '356503ff15f8f87203'),
    'loop_a': (LOOP_A, 0x203fb84,
        '4c89b350010000c68318020000004c8dab500100004c8da42490000000488d5424704c89e74c89eee85f9300004c8bbc'
        '24900000004983ff030f84bf0000004c8bac2498000000488db424a0000000488dbc2430040000baa8000000ff15fae3'
        '720380bb18020000030f854302000080bb10020000030f853602000080bb98010000030f852902000080bb0802000003'
        '0f851c02000080bb00020000030f850f02000048896c2410488babc0010000488d7d18b10131c0f00fb04d180f85f903'
        '0000488d83c8010000488b93c80100004885d20f848c010000488b8bd001000048894a084885c90f8492010000488b10'
        '4889110f57c00f1100e98b010000'),
    'pending_a': (LOOP_A, 0x203fc82,
        'c6832202000003bf01000000e86d3bea024989c64189d4488984247002000089942478020000488b4424284889842430'
        '0400008b44240489842438040000488dbc2490000000488db42470020000488d942430040000e8533aea02b800ca9a3b'
        '48f7a424980000008b8c24a00000004801c84883d2004531ff48f7dab9000000004819c94809c180bc24900000000049'
        '0f45cf48898b280200004c89b424700200004489a424780200004889ac24300400008b44243c89842438040000488dbc'
        '2490000000488db42470020000488d942430040000e8d439ea0280bc249000000000b8000000007510448bbc24a00000'
        '00488b842498000000488b4c2448488b4930483b81900000007515443bb998000000730ebe70000000bf30000000eb0c'
        '72f2be78000000bf38000000ba00ca9a3b48f7e24589f84901c04883d20031c048f7da4819c04c09c0f048ff0439f048'
        '010431b0014881c4f80500005b415c415d415e415f5dc3'),
    'dispatch_a': (LOOP_A, 0x203fe36,
        '4183ff020f85450100004c896c2408488d7c2430ff1550ea72038b442430898424dc000000c78424d000000001000000'
        '488b44243448898424d400000049bf00000000000000804c89bc2490000000488d05454438fe48898424b000000048c7'
        '8424b80000001600000048c78424c00000000800000048c78424c8000000000000008b05aaac730385c00f8533010000'
        '0f10058bac73030f11442450488d83200200004c89a42470020000488d0df8b1930048898c2478020000488d4c245048'
        '898c2480020000488d0d8c74170048898c24880200004889842490020000488b05cd3673034889842498020000488d44'
        '240848898424a0020000488b05b9e5720348898424a8020000488d3d8eb11bfe488db42470020000ff1514ea7203488b'
        'b424900000004c39fe74154885f67410488bbc249800000031d2ff159ae07203488b7c2408488b07ff10e9fffbffff48'
        '8dbc24a0000000488db42430040000ba88000000ff1540e072034c89bc24900000004c89ac2498000000488db3c80000'
        '00488dbc2470020000e84c832700488d9424b8040000488dbb80000000488db42490000000488d8c2470020000e878e8'
        '2100e997fbffff'),
    'overflow_a': (LOOP_A, 0x203fa4b, '488d3db61c6503ff15f8e67203'),
    'add_overflow_a': (LOOP_A, 0x203fa01, '488d3d52ea78fe488d1511377103be28000000ff154eea7203'),
    'entry_b': (LOOP_B, 0x2041c60,
        '554157415641554154534881ecf80500004889fb4c8b26bf01000000e87f1bea024989c689d54c8b2b498b4538488944'
        '2428418b45408944240480bb30020000004c89e80f859a000000c68330020000014c89b4247002000089ac2478020000'
        '488b44242848898424300400008b44240489842438040000488dbc2490000000488db42470020000488d942430040000'
        'e83b1aea02b800ca9a3b48f7a424980000008b8c24a00000004801c84883d20031c948f7daba000000004819d24809c2'
        '80bc249000000000480f45d1498b4530f048015058488b03488b4030f048ff4018488b03'),
    'timing_b': (LOOP_B, 0x2041d44,
        '31c94887481048398b280200007324498b4530f048ff40204889c8482b83280200000f825f050000498b5530f0480142'
        '60eb094885c90f8421010000498b4530f048ff40284889c848c1e80949bf535a9ba02fb8440049f7e748c1ea0b488b44'
        '24284801d00f80d20400004869d200ca9a3b4829d1034c240481f900ca9a3b720f48ffc00f80b304000081c1003665c4'
        '4c89b4247002000089ac24780200004889842430040000898c2438040000488dbc2490000000488db42470020000488d'
        '942430040000e82119ea02b800ca9a3b48f7a424980000008b8c24a00000004801c84883d20031f648f7dab900000000'
        '4819c94809c180bc249000000000480f45ce4889c848c1e80949f7e748c1ea0b498b4530483b90a000000075214869d2'
        '00ca9a3b4889ce4829d639b0a8000000760eba80000000be48000000eb0c72f2ba88000000be40000000f048ff0430f0'
        '48010c10498b4530f0480148684c896c2448'),
    'resume_b': (LOOP_B, 0x2041f57,
        '4c8d7308488b034883c010488d0d1ff7640348894c24604889442468488d4424604889442470488944247848c7842480'
        '00000000000000bf01000000e86818ea024889c50fb6832202000085c08954243c741683f8030f845f040000488d3dc6'
        '0c6503ff1578d07203'),
    'loop_b': (LOOP_B, 0x2042404,
        '4c89b350010000c68318020000004c8dab500100004c8da42490000000488d5424704c89e74c89eee8df6a00004c8bbc'
        '24900000004983ff030f84bf0000004c8bac2498000000488db424a0000000488dbc2430040000baa8000000ff157abb'
        '720380bb18020000030f854302000080bb10020000030f853602000080bb98010000030f852902000080bb0802000003'
        '0f851c02000080bb00020000030f850f02000048896c2410488babc0010000488d7d18b10131c0f00fb04d180f85f903'
        '0000488d83c8010000488b93c80100004885d20f848c010000488b8bd001000048894a084885c90f8492010000488b10'
        '4889110f57c00f1100e98b010000'),
    'pending_b': (LOOP_B, 0x2042502,
        'c6832202000003bf01000000e8ed12ea024989c64189d4488984247002000089942478020000488b4424284889842430'
        '0400008b44240489842438040000488dbc2490000000488db42470020000488d942430040000e8d311ea02b800ca9a3b'
        '48f7a424980000008b8c24a00000004801c84883d2004531ff48f7dab9000000004819c94809c180bc24900000000049'
        '0f45cf48898b280200004c89b424700200004489a424780200004889ac24300400008b44243c89842438040000488dbc'
        '2490000000488db42470020000488d942430040000e85411ea0280bc249000000000b8000000007510448bbc24a00000'
        '00488b842498000000488b4c2448488b4930483b81900000007515443bb998000000730ebe70000000bf30000000eb0c'
        '72f2be78000000bf38000000ba00ca9a3b48f7e24589f84901c04883d20031c048f7da4819c04c09c0f048ff0439f048'
        '010431b0014881c4f80500005b415c415d415e415f5dc3'),
    'dispatch_b': (LOOP_B, 0x20426b6,
        '4183ff020f85450100004c896c2408488d7c2430ff15d0c172038b442430898424dc000000c78424d000000001000000'
        '488b44243448898424d400000049bf00000000000000804c89bc2490000000488d05c51b38fe48898424b000000048c7'
        '8424b80000001600000048c78424c00000000800000048c78424c8000000000000008b052a84730385c00f8533010000'
        '0f10050b8473030f11442450488d83200200004c89a42470020000488d0d7889930048898c2478020000488d4c245048'
        '898c2480020000488d0d0c4c170048898c24880200004889842490020000488b054d0e73034889842498020000488d44'
        '240848898424a0020000488b0539bd720348898424a8020000488d3d0e891bfe488db42470020000ff1594c17203488b'
        'b424900000004c39fe74154885f67410488bbc249800000031d2ff151ab87203488b7c2408488b07ff10e9fffbffff48'
        '8dbc24a0000000488db42430040000ba88000000ff15c0b772034c89bc24900000004c89ac2498000000488db3c80000'
        '00488dbc2470020000e8cc5a2700488d9424b8040000488dbb80000000488db42490000000488d8c2470020000e848bb'
        '2100e997fbffff'),
    'overflow_b': (LOOP_B, 0x20422cb, '488d3d36f46403ff1578be7203'),
    'add_overflow_b': (LOOP_B, 0x2042281, '488d3dd2c178fe488d15910e7103be28000000ff15cec17203'),
    'accept': (ACCEPT, 0x2049370,
        '488b7340837e18ff0f84360400004883c618488dbc2408010000e891cec80180bc2408010000000f84390100004c8bb4'
        '24100100004c89742438c7442430010000004489f183e103b810000000488d1594a937fe48630c8a4801d1ffe1b80f00'
        '000041803c060d744ce9c70100004c89f048b900000000ffffffff4821c848b9000000000b0000004839c87428e9a301'
        '00004c89f048b900000000ffffffff4821c848b9000000000d0000004839c80f8580010000'),
    'would_block': (ACCEPT, 0x2049425,
        '488b4330488b4b500fb65358488b7010488b869000000083e1334881f13f00ff00662e0f1f84000000000089c7c1ef10'
        '4038fa750f89c721cff0480fb1be9000000075e7'),
    'accepted': (ACCEPT, 0x20494d6,
        '8bac240c0100000f108424100100000f114424380f108424200100000f114424484c8b7c24380f104424400f29442460'
        '488b44245048894424700f298424d000000048898424e0000000488b442410c60001488d3d71ca7003ff15735b720349'
        '89d0896c24304c8d0d5dca7003488dbc2408010000488d742430ba030000004889c1e823daf202488b8424080100004c'
        '8bb424100100004883f8020f85b30000008b7c2430ff1587517203eb2a488d35f77c78feba38000000bf28000000ff15'
        'c65872034989c6488b442428c60001488b442410c60001488b442418c600014c89f7e8133b84004989c441bd02000000'
        '488bac24980000004c896d004c896508488d7d10488db424a0010000ba88000000ff15f349720366c785980000000000'
        '4489b59a000000664489bd9e0000000f288424b00000000f1185a0000000488b8424c0000000488985b0000000b001e9'
        'd3000000'),
    'v4_check': (ACCEPT, 0x204962a,
        '488b8c24180100008b5424300f288424d00000000f298424f0000000488bb424e00000004889b42400010000488b7424'
        '18c6060148894c24708954247848894424604c897424684d89fe49c1ee1041f6c7010f8493000000488d3d5cb537febe'
        '09000000e81d3484004989c4488d7c2460e820cd84008b7c247883ffff7406ff1559507203488d7c2460e81784f7ff41'
        'bd02000000e902ffffff'),
    'poll_pending': (ACCEPT, 0x20496ec, '488b84249800000048c70003000000b0038883c80000004881c4280200005b415c415d415e415f5dc3'),
    'closed': (ACCEPT, 0x20497b4, '488d3d2d9b6403ff15af4c72030f0b'),
    'kind_fmt': (KIND_FMT, 0x4b6f890,
        '4889f0803f017515488d352f76b9fbba060000004889c7ff2553e7bf00488d351176b9fbba090000004889c7ff253ee7'
        'bf00'),
    'print_label': (PRINT, 0x4edba50, '554889e54156534883ec404889f34989fe488d05a3178ffb488945b048c745b806000000'),
    'label_g': (SPAWN_G, 0x225e460, '488d35678a4afe488dbc2410610000ba06000000ff1586fb5003'),
    'task_g': (SPAWN_G, 0x225e4a6, '488d050b9417fe488984245031000048c784245831000018000000'),
    'flag_g': (SPAWN_G, 0x225e5ac, '66c78424a80200000100'),
    'label_v': (SPAWN_V, 0x225e910, '488d35ae854afe488dbc2410610000ba09000000ff15d6f65003'),
    'task_v': (SPAWN_V, 0x225e956, '488d055b8f17fe488984245031000048c784245831000018000000'),
    'flag_v': (SPAWN_V, 0x225ea5c, '66c78424a80200000000'),
}

FACTS = {
    0x203f3f7: ('bf01000000', 'clock id 1'),
    0x203f3fc: ('e8ff43ea02', 'now at poll entry'),
    0x203f409: ('498b4538', 'created secs = [task+0x38]'),
    0x203f412: ('418b4540', 'created nanos = [task+0x40]'),
    0x203f41a: ('80bb3002000000', 'first-poll flag state+0x230'),
    0x203f424: ('0f859a000000', 'not first poll skips'),
    0x203f42a: ('c6833002000001', 'flag set'),
    0x203f470: ('e8bb42ea02', 'now - created'),
    0x203f4a8: ('480f45d1', 'None -> 0'),
    0x203f4ac: ('498b4530', 'monitor = [task+0x30]'),
    0x203f4b0: ('f048015058', 'monitor+0x58 += first-poll delay ns'),
    0x203f4bc: ('f048ff4018', 'monitor+0x18 += 1'),
    0x203f4c6: ('48874810', 'woke = swap([task+0x10], 0)'),
    0x203f4ca: ('48398b28020000', 'compare last poll end state+0x228 with woke'),
    0x203f4d1: ('7324', 'last end >= woke: no idle'),
    0x203f4d3: ('498b4530', 'monitor'),
    0x203f4d7: ('f048ff4020', 'monitor+0x20 += 1'),
    0x203f4df: ('482b8328020000', 'idle = woke - last end'),
    0x203f4e6: ('0f825f050000', 'borrow panics'),
    0x203f4ec: ('498b5530', 'monitor'),
    0x203f4f0: ('f048014260', 'monitor+0x60 += idle ns'),
    0x203f500: ('498b4530', 'monitor'),
    0x203f5d4: ('498b4530', 'monitor'),
    0x203f618: ('498b4530', 'monitor'),
    0x203f4f7: ('4885c9', 'woke == 0 test'),
    0x203f4fa: ('0f8421010000', 'woke == 0 skips scheduling'),
    0x203f504: ('f048ff4028', 'monitor+0x28 += 1'),
    0x203f529: ('0f80d2040000', 'created + woke overflow'),
    0x203f548: ('0f80b3040000', 'created + woke overflow'),
    0x203f58a: ('e8a141ea02', 'now - (created + woke)'),
    0x203f5c2: ('480f45ce', 'None -> 0'),
    0x203f5d8: ('483b90a0000000', 'delay secs vs monitor+0xa0'),
    0x203f5ee: ('39b0a8000000', 'delay nanos vs monitor+0xa8'),
    0x203f5df: ('7521', 'secs differ'),
    0x203f5f4: ('760e', 'threshold nanos <= delay nanos'),
    0x203f602: ('72f2', 'secs below'),
    0x203f5f6: ('ba80000000', 'short delay ns at +0x80'),
    0x203f5fb: ('be48000000', 'short delay count at +0x48'),
    0x203f604: ('ba88000000', 'long delay ns at +0x88'),
    0x203f609: ('be40000000', 'long delay count at +0x40'),
    0x203f60e: ('f048ff0430', 'count += 1'),
    0x203f613: ('f048010c10', 'ns += delay'),
    0x203f61c: ('f048014868', 'monitor+0x68 += delay ns'),
    0x203f621: ('4c896c2448', 'task kept at rsp+0x48'),
    0x203f6e2: ('488d0d9f1f6503', 'instrumented waker vtable'),
    0x203f70e: ('bf01000000', 'clock id 1'),
    0x203f713: ('e8e840ea02', 'poll start now'),
    0x203f718: ('4889c5', 'poll start secs'),
    0x203f724: ('8954243c', 'poll start nanos'),
    0x203f71b: ('0fb68322020000', 'async state byte state+0x222'),
    0x203f728: ('7416', 'state 0 starts'),
    0x203f72a: ('83f803', 'state 3 resumes'),
    0x203f72d: ('0f845f040000', 'resume into the loop'),
    0x203f733: ('488d3d46356503', 'resumed-after-completion Location'),
    0x203f73a: ('ff15f8f87203', 'panic'),
    0x203fbac: ('e85f930000', 'poll accept future 0x2048f10'),
    0x203fbb1: ('4c8bbc2490000000', 'tag'),
    0x203fbb9: ('4983ff03', 'tag 3 is Pending'),
    0x203fbbd: ('0f84bf000000', 'Pending exits'),
    0x203fc82: ('c6832202000003', 'state 3'),
    0x203fc89: ('bf01000000', 'clock id 1'),
    0x203fc8e: ('e86d3bea02', 'poll end now'),
    0x203fcd8: ('e8533aea02', 'end - created'),
    0x203fd11: ('490f45cf', 'None -> 0'),
    0x203fd15: ('48898b28020000', 'state+0x228 = last poll end ns'),
    0x203fd1c: ('4c89b42470020000', 'end'),
    0x203fd2c: ('4889ac2430040000', 'poll start'),
    0x203fd57: ('e8d439ea02', 'end - start'),
    0x203fd7b: ('488b4c2448', 'task'),
    0x203fd80: ('488b4930', 'monitor'),
    0x203fd84: ('483b8190000000', 'poll secs vs monitor+0x90'),
    0x203fd8d: ('443bb998000000', 'poll nanos vs monitor+0x98'),
    0x203fd8b: ('7515', 'secs differ'),
    0x203fd94: ('730e', 'nanos >= threshold'),
    0x203fda2: ('72f2', 'secs below'),
    0x203fd96: ('be70000000', 'fast poll ns at +0x70'),
    0x203fd9b: ('bf30000000', 'fast poll count at +0x30'),
    0x203fda4: ('be78000000', 'slow poll ns at +0x78'),
    0x203fda9: ('bf38000000', 'slow poll count at +0x38'),
    0x203fdcb: ('f048ff0439', 'count += 1'),
    0x203fdd0: ('f048010431', 'ns += poll'),
    0x203fdd5: ('b001', 'return Pending (1)'),
    0x203fa4b: ('488d3db61c6503', 'tokio-metrics Location'),
    0x203fa52: ('ff15f8e67203', 'panic'),
    0x203fa01: ('488d3d52ea78fe', 'overflow message'),
    0x203fa08: ('488d1511377103', 'std time Location'),
    0x203fa0f: ('be28000000', 'length 0x28'),
    0x203fa14: ('ff154eea7203', 'panic'),
    0x203fe36: ('4183ff02', 'tag 2 is the accept error'),
    0x203fe3a: ('0f8545010000', 'other tags spawn'),
    0x203fe4a: ('ff1550ea7203', 'wall clock'),
    0x203fe85: ('488d05454438fe', 'timestamp format'),
    0x203fe94: ('48c78424b800000016000000', 'length 0x16'),
    0x203feb8: ('8b05aaac7303', 'lazy prefix Once state'),
    0x203fec6: ('0f10058bac7303', 'lazy prefix &str'),
    0x203fed2: ('488d8320020000', 'kind byte at state+0x220'),
    0x203fee1: ('488d0df8b19300', 'timestamp formatter'),
    0x203fefd: ('488d0d8c741700', '&str Display'),
    0x203ff14: ('488b05cd367303', 'kind Display'),
    0x203ff30: ('488b05b9e57203', 'error Display'),
    0x203ff3f: ('488d3d8eb11bfe', 'stdout template'),
    0x203ff4e: ('ff1514ea7203', 'print to stdout'),
    0x203ff76: ('488b7c2408', 'error object'),
    0x203ff7e: ('ff10', 'error dropped'),
    0x203ff80: ('e9fffbffff', 'loops back'),
    0x203ffbf: ('e84c832700', 'clone state+0xc8'),
    0x203ffe3: ('e878e82100', 'spawn'),
    0x203ffe8: ('e997fbffff', 'loops back'),
    0x2049374: ('837e18ff', 'listener fd -1 check'),
    0x2049378: ('0f8436040000', 'fd -1 panics'),
    0x204938a: ('e891cec801', 'accept4'),
    0x2049397: ('0f8439010000', 'Ok -> registration'),
    0x20493bd: ('488d1594a937fe', 'io::Error jump table'),
    0x20493d2: ('41803c060d', 'kind byte vs WouldBlock'),
    0x20493cd: ('b80f000000', 'Custom kind offset'),
    0x20493ee: ('48b9000000000b000000', 'Os EAGAIN'),
    0x2049412: ('48b9000000000d000000', 'Simple WouldBlock'),
    0x20493d9: ('e9c7010000', 'other error'),
    0x20493fd: ('e9a3010000', 'other error'),
    0x204941f: ('0f8580010000', 'other error'),
    0x204945e: ('f0480fb1be90000000', 'clear readiness'),
    0x20494f7: ('4c8b7c2438', 'peer SocketAddr tag'),
    0x2049550: ('ba03000000', 'interest 3'),
    0x2049558: ('e823daf202', 'Tokio registration'),
    0x204956d: ('4883f802', 'registration error tag 2'),
    0x204957b: ('ff1587517203', 'close'),
    0x2049583: ('488d35f77c78fe', 'Tokio shutdown message'),
    0x204958a: ('ba38000000', 'length 0x38'),
    0x204958f: ('bf28000000', 'kind 0x28'),
    0x20495b8: ('e8133b8400', 'wrap error'),
    0x20495c0: ('41bd02000000', 'tag 2'),
    0x20495ce: ('4c896d00', 'store tag'),
    0x20495d2: ('4c896508', 'store error'),
    0x2049678: ('41f6c701', 'SocketAddr tag bit 0 = V6'),
    0x204967c: ('0f8493000000', 'V4 continues'),
    0x2049682: ('488d3d5cb537fe', '"ip not v4"'),
    0x2049689: ('be09000000', 'length 9'),
    0x204968e: ('e81d348400', 'make error'),
    0x20496a4: ('83ffff', 'fd -1 check'),
    0x20496a9: ('ff1559507203', 'close'),
    0x20496b9: ('41bd02000000', 'tag 2'),
    0x20496bf: ('e902ffffff', 'store error result'),
    0x20496f4: ('48c70003000000', 'Pending tag 3'),
    0x20497b4: ('488d3d2d9b6403', 'panic Location'),
    0x20497bb: ('ff15af4c7203', 'panic'),
    0x4b6f893: ('803f01', 'kind == 1'),
    0x4b6f898: ('488d352f76b9fb', '"gossip"'),
    0x4b6f89f: ('ba06000000', 'length 6'),
    0x4b6f8ad: ('488d351176b9fb', '"validator"'),
    0x4b6f8b4: ('ba09000000', 'length 9'),
    0x4edba61: ('488d05a3178ffb', '"stdout"'),
    0x4edba6c: ('48c745b806000000', 'length 6'),
    0x225e460: ('488d35678a4afe', 'gossip label'),
    0x225e46f: ('ba06000000', 'length 6'),
    0x225e4a6: ('488d050b9417fe', 'task name'),
    0x225e4b5: ('48c784245831000018000000', 'length 0x18'),
    0x225e5ac: ('66c78424a80200000100', 'flag word 1'),
    0x225e910: ('488d35ae854afe', 'validator label'),
    0x225e91f: ('ba09000000', 'length 9'),
    0x225e956: ('488d055b8f17fe', 'task name'),
    0x225e965: ('48c784245831000018000000', 'length 0x18'),
    0x225ea5c: ('66c78424a80200000000', 'flag word 0'),
}

# va: (instruction length, target) for every rel8/rel32 branch, call and RIP-relative operand in the windows.
OPERANDS = {
    0x203f3fc: (5, 0x4ee3800),  # entry_a: call
    0x203f424: (6, 0x203f4c4),  # entry_a: jne
    0x203f470: (5, 0x4ee3730),  # entry_a: call
    0x203f4d1: (2, 0x203f4f7),  # timing_a: jae
    0x203f4e6: (6, 0x203fa4b),  # timing_a: jb
    0x203f4f5: (2, 0x203f500),  # timing_a: jmp
    0x203f4fa: (6, 0x203f621),  # timing_a: je
    0x203f529: (6, 0x203fa01),  # timing_a: jo
    0x203f543: (2, 0x203f554),  # timing_a: jb
    0x203f548: (6, 0x203fa01),  # timing_a: jo
    0x203f58a: (5, 0x4ee3730),  # timing_a: call
    0x203f5df: (2, 0x203f602),  # timing_a: jne
    0x203f5f4: (2, 0x203f604),  # timing_a: jbe
    0x203f600: (2, 0x203f60e),  # timing_a: jmp
    0x203f602: (2, 0x203f5f6),  # timing_a: jb
    0x203f6e2: (7, 0x5691688),  # resume_a: lea
    0x203f713: (5, 0x4ee3800),  # resume_a: call
    0x203f728: (2, 0x203f740),  # resume_a: je
    0x203f72d: (6, 0x203fb92),  # resume_a: je
    0x203f733: (7, 0x5692c80),  # resume_a: lea
    0x203f73a: (6, 0x576f038),  # resume_a: call
    0x203fa01: (7, 0x7ce45a),  # add_overflow_a: lea
    0x203fa08: (7, 0x5753120),  # add_overflow_a: lea
    0x203fa14: (6, 0x576e468),  # add_overflow_a: call
    0x203fa4b: (7, 0x5691708),  # overflow_a: lea
    0x203fa52: (6, 0x576e150),  # overflow_a: call
    0x203fbac: (5, 0x2048f10),  # loop_a: call
    0x203fbbd: (6, 0x203fc82),  # loop_a: je
    0x203fbe0: (6, 0x576dfe0),  # loop_a: call
    0x203fbed: (6, 0x203fe36),  # loop_a: jne
    0x203fbfa: (6, 0x203fe36),  # loop_a: jne
    0x203fc07: (6, 0x203fe36),  # loop_a: jne
    0x203fc14: (6, 0x203fe36),  # loop_a: jne
    0x203fc21: (6, 0x203fe36),  # loop_a: jne
    0x203fc40: (6, 0x204003f),  # loop_a: jne
    0x203fc57: (6, 0x203fde9),  # loop_a: je
    0x203fc6b: (6, 0x203fe03),  # loop_a: je
    0x203fc7d: (5, 0x203fe0d),  # loop_a: jmp
    0x203fc8e: (5, 0x4ee3800),  # pending_a: call
    0x203fcd8: (5, 0x4ee3730),  # pending_a: call
    0x203fd57: (5, 0x4ee3730),  # pending_a: call
    0x203fd69: (2, 0x203fd7b),  # pending_a: jne
    0x203fd8b: (2, 0x203fda2),  # pending_a: jne
    0x203fd94: (2, 0x203fda4),  # pending_a: jae
    0x203fda0: (2, 0x203fdae),  # pending_a: jmp
    0x203fda2: (2, 0x203fd96),  # pending_a: jb
    0x203fe3a: (6, 0x203ff85),  # dispatch_a: jne
    0x203fe4a: (6, 0x576e8a0),  # dispatch_a: call
    0x203fe85: (7, 0x3c42d1),  # dispatch_a: lea
    0x203feb8: (6, 0x577ab68),  # dispatch_a: mov
    0x203fec0: (6, 0x203fff9),  # dispatch_a: jne
    0x203fec6: (7, 0x577ab58),  # dispatch_a: movups
    0x203fee1: (7, 0x297b0e0),  # dispatch_a: lea
    0x203fefd: (7, 0x21b7390),  # dispatch_a: lea
    0x203ff14: (7, 0x57735e8),  # dispatch_a: mov
    0x203ff30: (7, 0x576e4f0),  # dispatch_a: mov
    0x203ff3f: (7, 0x1fb0d4),  # dispatch_a: lea
    0x203ff4e: (6, 0x576e968),  # dispatch_a: call
    0x203ff5f: (2, 0x203ff76),  # dispatch_a: je
    0x203ff64: (2, 0x203ff76),  # dispatch_a: je
    0x203ff70: (6, 0x576e010),  # dispatch_a: call
    0x203ff80: (5, 0x203fb84),  # dispatch_a: jmp
    0x203ff9a: (6, 0x576dfe0),  # dispatch_a: call
    0x203ffbf: (5, 0x22b8310),  # dispatch_a: call
    0x203ffe3: (5, 0x225e860),  # dispatch_a: call
    0x203ffe8: (5, 0x203fb84),  # dispatch_a: jmp
    0x2041c7c: (5, 0x4ee3800),  # entry_b: call
    0x2041ca4: (6, 0x2041d44),  # entry_b: jne
    0x2041cf0: (5, 0x4ee3730),  # entry_b: call
    0x2041d51: (2, 0x2041d77),  # timing_b: jae
    0x2041d66: (6, 0x20422cb),  # timing_b: jb
    0x2041d75: (2, 0x2041d80),  # timing_b: jmp
    0x2041d7a: (6, 0x2041ea1),  # timing_b: je
    0x2041da9: (6, 0x2042281),  # timing_b: jo
    0x2041dc3: (2, 0x2041dd4),  # timing_b: jb
    0x2041dc8: (6, 0x2042281),  # timing_b: jo
    0x2041e0a: (5, 0x4ee3730),  # timing_b: call
    0x2041e5f: (2, 0x2041e82),  # timing_b: jne
    0x2041e74: (2, 0x2041e84),  # timing_b: jbe
    0x2041e80: (2, 0x2041e8e),  # timing_b: jmp
    0x2041e82: (2, 0x2041e76),  # timing_b: jb
    0x2041f62: (7, 0x5691688),  # resume_b: lea
    0x2041f93: (5, 0x4ee3800),  # resume_b: call
    0x2041fa8: (2, 0x2041fc0),  # resume_b: je
    0x2041fad: (6, 0x2042412),  # resume_b: je
    0x2041fb3: (7, 0x5692c80),  # resume_b: lea
    0x2041fba: (6, 0x576f038),  # resume_b: call
    0x2042281: (7, 0x7ce45a),  # add_overflow_b: lea
    0x2042288: (7, 0x5753120),  # add_overflow_b: lea
    0x2042294: (6, 0x576e468),  # add_overflow_b: call
    0x20422cb: (7, 0x5691708),  # overflow_b: lea
    0x20422d2: (6, 0x576e150),  # overflow_b: call
    0x204242c: (5, 0x2048f10),  # loop_b: call
    0x204243d: (6, 0x2042502),  # loop_b: je
    0x2042460: (6, 0x576dfe0),  # loop_b: call
    0x204246d: (6, 0x20426b6),  # loop_b: jne
    0x204247a: (6, 0x20426b6),  # loop_b: jne
    0x2042487: (6, 0x20426b6),  # loop_b: jne
    0x2042494: (6, 0x20426b6),  # loop_b: jne
    0x20424a1: (6, 0x20426b6),  # loop_b: jne
    0x20424c0: (6, 0x20428bf),  # loop_b: jne
    0x20424d7: (6, 0x2042669),  # loop_b: je
    0x20424eb: (6, 0x2042683),  # loop_b: je
    0x20424fd: (5, 0x204268d),  # loop_b: jmp
    0x204250e: (5, 0x4ee3800),  # pending_b: call
    0x2042558: (5, 0x4ee3730),  # pending_b: call
    0x20425d7: (5, 0x4ee3730),  # pending_b: call
    0x20425e9: (2, 0x20425fb),  # pending_b: jne
    0x204260b: (2, 0x2042622),  # pending_b: jne
    0x2042614: (2, 0x2042624),  # pending_b: jae
    0x2042620: (2, 0x204262e),  # pending_b: jmp
    0x2042622: (2, 0x2042616),  # pending_b: jb
    0x20426ba: (6, 0x2042805),  # dispatch_b: jne
    0x20426ca: (6, 0x576e8a0),  # dispatch_b: call
    0x2042705: (7, 0x3c42d1),  # dispatch_b: lea
    0x2042738: (6, 0x577ab68),  # dispatch_b: mov
    0x2042740: (6, 0x2042879),  # dispatch_b: jne
    0x2042746: (7, 0x577ab58),  # dispatch_b: movups
    0x2042761: (7, 0x297b0e0),  # dispatch_b: lea
    0x204277d: (7, 0x21b7390),  # dispatch_b: lea
    0x2042794: (7, 0x57735e8),  # dispatch_b: mov
    0x20427b0: (7, 0x576e4f0),  # dispatch_b: mov
    0x20427bf: (7, 0x1fb0d4),  # dispatch_b: lea
    0x20427ce: (6, 0x576e968),  # dispatch_b: call
    0x20427df: (2, 0x20427f6),  # dispatch_b: je
    0x20427e4: (2, 0x20427f6),  # dispatch_b: je
    0x20427f0: (6, 0x576e010),  # dispatch_b: call
    0x2042800: (5, 0x2042404),  # dispatch_b: jmp
    0x204281a: (6, 0x576dfe0),  # dispatch_b: call
    0x204283f: (5, 0x22b8310),  # dispatch_b: call
    0x2042863: (5, 0x225e3b0),  # dispatch_b: call
    0x2042868: (5, 0x2042404),  # dispatch_b: jmp
    0x2049378: (6, 0x20497b4),  # accept: je
    0x204938a: (5, 0x3cd6220),  # accept: call
    0x2049397: (6, 0x20494d6),  # accept: je
    0x20493bd: (7, 0x3c3d58),  # accept: lea
    0x20493d7: (2, 0x2049425),  # accept: je
    0x20493d9: (5, 0x20495a5),  # accept: jmp
    0x20493fb: (2, 0x2049425),  # accept: je
    0x20493fd: (5, 0x20495a5),  # accept: jmp
    0x204941f: (6, 0x20495a5),  # accept: jne
    0x2049458: (2, 0x2049469),  # would_block: jne
    0x2049467: (2, 0x2049450),  # would_block: jne
    0x2049528: (7, 0x5755fa0),  # accepted: lea
    0x204952f: (6, 0x576f0a8),  # accepted: call
    0x204953c: (7, 0x5755fa0),  # accepted: lea
    0x2049558: (5, 0x4f76f80),  # accepted: call
    0x2049571: (6, 0x204962a),  # accepted: jne
    0x204957b: (6, 0x576e708),  # accepted: call
    0x2049581: (2, 0x20495ad),  # accepted: jmp
    0x2049583: (7, 0x7d1281),  # accepted: lea
    0x2049594: (6, 0x576ee60),  # accepted: call
    0x20495b8: (5, 0x288d0d0),  # accepted: call
    0x20495e7: (6, 0x576dfe0),  # accepted: call
    0x2049625: (5, 0x20496fd),  # accepted: jmp
    0x204967c: (6, 0x2049715),  # v4_check: je
    0x2049682: (7, 0x3c4be5),  # v4_check: lea
    0x204968e: (5, 0x288cab0),  # v4_check: call
    0x204969b: (5, 0x28963c0),  # v4_check: call
    0x20496a7: (2, 0x20496af),  # v4_check: je
    0x20496a9: (6, 0x576e708),  # v4_check: call
    0x20496b4: (5, 0x1fc1ad0),  # v4_check: call
    0x20496bf: (5, 0x20495c6),  # v4_check: jmp
    0x20497b4: (7, 0x56932e8),  # closed: lea
    0x20497bb: (6, 0x576e470),  # closed: call
    0x225e460: (7, 0x706ece),  # label_g: lea
    0x225e474: (6, 0x576e000),  # label_g: call
    0x225e4a6: (7, 0x3d78b8),  # task_g: lea
    0x225e910: (7, 0x706ec5),  # label_v: lea
    0x225e924: (6, 0x576e000),  # label_v: call
    0x225e956: (7, 0x3d78b8),  # task_v: lea
    0x4b6f896: (2, 0x4b6f8ad),  # kind_fmt: jne
    0x4b6f898: (7, 0x706ece),  # kind_fmt: lea
    0x4b6f8a7: (6, 0x576e000),  # kind_fmt: jmp
    0x4b6f8ad: (7, 0x706ec5),  # kind_fmt: lea
    0x4b6f8bc: (6, 0x576e000),  # kind_fmt: jmp
    0x4edba61: (7, 0x7cd20b),  # print_label: lea
}

# Slot: (RELATIVE file pointer, or GLOB_DAT symbol name).
SLOTS = {
    0x576e968: (PRINT, 'std print to stdout'),
    0x576e8a0: (0x151cba0, 'wall clock now'),
    0x57735e8: (KIND_FMT, 'kind Display'),
    0x576e4f0: (0x1367fb0, 'error Display'),
    0x576e000: (0x1573450, 'Formatter str write'),
    LAZY_PREFIX: (0x143ed40, 'lazy prefix initialiser'),
    0x576f038: (0x157b560, 'resumed-state panic'),
    0x576e150: (0x157b520, 'tokio-metrics panic'),
    0x576e468: (0x157a9b0, 'time overflow panic'),
    0x576e470: (0x157a9f0, 'poll_evented panic'),
    0x576e708: ('close', 'close(2)'),
    0x576dfe0: ('memcpy', 'memcpy'),
}
WAKER = (0x1f6ad20, 0x219a6d0, 0x219a6e0, 0x219a6b0)

TEXT = {
    TS_FORMAT: b'%Y-%m-%dT%H:%M:%S%.3fZ',
    0x3c4be5: b'ip not v4',
    0x7d1281: b'A Tokio 1.x context was found, but it is being shutdown.',
    0x7ce45a: b'overflow when adding duration to instant',
    0x7cd20b: b'stdout',
    0x706ece: b'gossip',
    0x706ec5: b'validator',
    0x3d78b8: b'handle_stream_connection',
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
    waker = tuple(img.relative.get(WAKER_VTABLE + 8 * i) for i in range(4))
    require(waker == WAKER, f'waker vtable {WAKER_VTABLE:#x} is {waker}')
    return dict(targets=out, locations=locs, waker_vtable=[hex(v) for v in waker])


def check_twins(img):
    """The two loops are byte-identical inside the windows except rel operands; only the spawn target differs."""
    a_start, a_end = img.fde(LOOP_A)
    b_start, b_end = img.fde(LOOP_B)
    require(b_start - a_start == TWIN and b_end - a_end == TWIN, 'loop FDEs are not a fixed shift apart')
    compared, spans, pairs = 0, 0, 0
    for a_name, (a_fde, a_va, a_hex) in WINDOWS.items():
        if not a_name.endswith('_a'):
            continue
        b_fde, b_va, b_hex = WINDOWS[a_name[:-1] + 'b']
        require(a_fde == LOOP_A and b_fde == LOOP_B and b_va == a_va + TWIN, f'{a_name} twin layout changed')
        a, b = bytes.fromhex(a_hex), bytes.fromhex(b_hex)
        require(len(a) == len(b), f'{a_name} twin lengths differ')
        free = set()
        for va, (n, want) in OPERANDS.items():
            if a_va <= va < a_va + len(a):
                require(va + TWIN in OPERANDS and OPERANDS[va + TWIN][0] == n, f'twin operand at {va + TWIN:#x} missing')
                other = OPERANDS[va + TWIN][1]
                if va == SPAWN_CALL:
                    require((want, other) == (SPAWN_V, SPAWN_G), 'spawn targets changed')
                elif a_start <= want < a_end:
                    require(other == want + TWIN, f'internal target at {va:#x} does not move with the twin')
                else:
                    require(other == want, f'external target at {va:#x} differs between twins')
                rel = 1 if n == 2 else 4
                free.update(range(va - a_va + n - rel, va - a_va + n))
                spans += 1
        diff = {i for i in range(len(a)) if a[i] != b[i]}
        require(diff <= free, f'{a_name} twins differ outside rel operands at {sorted(diff - free)[:4]}')
        compared += len(a)
        pairs += 1
    return dict(shift=hex(TWIN), window_pairs=pairs, compared_bytes=compared, rel_operands=spans,
                only_difference=f'{SPAWN_CALL:#x}: call {SPAWN_V:#x} (validator) vs '
                                f'{SPAWN_CALL + TWIN:#x}: call {SPAWN_G:#x} (gossip)')


def disp8(raw):
    return raw[-1]


def counter(f, va):
    """Monitor offset updated by a `lock inc/add QWORD PTR [reg+disp8]` fact."""
    raw = f[va]
    require(raw[:2] == b'\xf0\x48' and raw[2] in (0x01, 0xff), f'{va:#x} is not a locked 64-bit counter update')
    return disp8(raw)


def imm32(raw):
    return struct.unpack('<I', raw[-4:])[0]


def check_metrics(f):
    for va in (0x203f3fc, 0x203f713, 0x203fc8e):
        require(OPERANDS[va][1] == NOW and imm32(f[va - 5]) == 1, f'clock read at {va:#x} changed')
    for va in (0x203f470, 0x203f58a, 0x203fcd8, 0x203fd57):
        require(OPERANDS[va][1] == SINCE, f'duration call at {va:#x} changed')
    require(f[0x203f409] == bytes.fromhex('498b4538') and f[0x203f412] == bytes.fromhex('418b4540'), 'created Instant offsets')
    require(all(f[va][-1] == 0x30 for va in (0x203f4ac, 0x203f4d3, 0x203f4ec, 0x203f500, 0x203f5d4, 0x203f618, 0x203fd80)), 'monitor = [task+0x30]')
    require(f[0x203f41a][2:4] == struct.pack('<H', 0x230) and f[0x203f42a][-1] == 1, 'first-poll flag changed')
    require(f[0x203f4c6] == bytes.fromhex('48874810'), 'woke swap changed')
    require(f[0x203f4ca][-4:] == struct.pack('<I', 0x228) and f[0x203fd15][-4:] == struct.pack('<I', 0x228), 'last poll end slot')
    first = dict(count=counter(f, 0x203f4bc), ns=counter(f, 0x203f4b0))
    idle = dict(count=counter(f, 0x203f4d7), ns=counter(f, 0x203f4f0))
    sched = dict(count=counter(f, 0x203f504), ns=counter(f, 0x203f61c))
    require((first, idle, sched) == ({'count': 0x18, 'ns': 0x58}, {'count': 0x20, 'ns': 0x60}, {'count': 0x28, 'ns': 0x68}),
            'first-poll / idle / scheduled counters changed')
    require(OPERANDS[0x203f4d1][1] == 0x203f4f7 and OPERANDS[0x203f4fa][1] == 0x203f621, 'idle / scheduled gates changed')
    require(f[0x203f5d8][-4:] == struct.pack('<I', 0xa0) and f[0x203f5ee][2:6] == struct.pack('<I', 0xa8), 'delay threshold')
    short = dict(count=imm32(f[0x203f5fb]), ns=imm32(f[0x203f5f6]))
    long_ = dict(count=imm32(f[0x203f609]), ns=imm32(f[0x203f604]))
    require((short, long_) == ({'count': 0x48, 'ns': 0x80}, {'count': 0x40, 'ns': 0x88}), 'delay split counters changed')
    require(OPERANDS[0x203f602][1] == 0x203f5f6 and OPERANDS[0x203f5f4][1] == 0x203f604, 'delay split branches changed')
    require(f[0x203fd84][-4:] == struct.pack('<I', 0x90) and f[0x203fd8d][-4:] == struct.pack('<I', 0x98), 'poll threshold')
    fast = dict(count=imm32(f[0x203fd9b]), ns=imm32(f[0x203fd96]))
    slow = dict(count=imm32(f[0x203fda9]), ns=imm32(f[0x203fda4]))
    require((fast, slow) == ({'count': 0x30, 'ns': 0x70}, {'count': 0x38, 'ns': 0x78}), 'poll split counters changed')
    require(OPERANDS[0x203fda2][1] == 0x203fd96 and OPERANDS[0x203fd94][1] == 0x203fda4, 'poll split branches changed')
    require(f[0x203fd1c][-4:] == struct.pack('<I', 0x270) and f[0x203fd2c][-4:] == struct.pack('<I', 0x430)
            and f[0x203f718] == bytes.fromhex('4889c5') and f[0x203f724][-1] == 0x3c, 'poll duration = end - start')
    require(f[0x203fdd5] == bytes.fromhex('b001') and f[0x203fc82][-1] == 3, 'Pending exit changed')
    require(OPERANDS[0x203f6e2][1] == WAKER_VTABLE, 'instrumented waker vtable operand')
    require(OPERANDS[0x203f4e6][1] == 0x203fa4b and OPERANDS[0x203fa4b][1] == 0x5691708, 'idle borrow panic')
    require(OPERANDS[0x203f529][1] == OPERANDS[0x203f548][1] == 0x203fa01 and OPERANDS[0x203fa08][1] == 0x5753120,
            'instant overflow panic')
    return dict(monitor='[[state]+0x30]', clock='0x4ee3800(1) at poll entry, at resume and at Pending exit',
                first_poll=dict(gate='byte state+0x230 == 0, then set to 1', counters={k: hex(v) for k, v in first.items()},
                                value='now - created ([task+0x38], [task+0x40])'),
                idle=dict(gate='woke = swap([task+0x10], 0) > state+0x228', counters={k: hex(v) for k, v in idle.items()},
                          value='woke - state+0x228 (ns since created)'),
                scheduled=dict(gate='woke != 0', counters={k: hex(v) for k, v in sched.items()},
                               value='now - (created + woke)',
                               split=dict(threshold='Duration at monitor+0xa0/+0xa8',
                                          below={k: hex(v) for k, v in short.items()},
                                          at_or_above={k: hex(v) for k, v in long_.items()})),
                poll=dict(value='end - start (start at resume 0x203f713, end at Pending 0x203fc8e)',
                          split=dict(threshold='Duration at monitor+0x90/+0x98',
                                     below={k: hex(v) for k, v in fast.items()},
                                     at_or_above={k: hex(v) for k, v in slow.items()}),
                          last_end='state+0x228 = end - created (ns)'),
                waker=f'{WAKER_VTABLE:#x} (clone, wake, wake_by_ref, drop) wraps the task waker')


def template(img, va):
    """Decode a rustc packed format template: literal-length bytes and 0xc0 placeholders, ending at 0x00."""
    pieces, pos = [], va
    for _ in range(64):
        b = img.read(pos, 1)[0]
        if b == 0xc0:
            pieces.append(None)
            n = img.read(pos + 1, 1)[0]
            pos += 2
        elif b == 0:
            return pieces
        elif b < 0x80:
            n = b
            pos += 1
        else:
            raise EvidenceError(f'template {va:#x}: unexpected byte {b:#x} at {pos:#x}')
        if n:
            lit = img.read(pos, n)
            require(all(0x20 <= c < 0x7f or c == 0x0a for c in lit), f'template {va:#x}: literal at {pos:#x} not text')
            pieces.append(lit.decode())
            pos += n
        elif pieces and pieces[-1] is None and img.read(pos, 1)[0] != 0xc0:
            return pieces
    raise EvidenceError(f'template {va:#x}: no terminator')


def check_loop(img, f):
    require(OPERANDS[0x203fbac][1] == ACCEPT and f[0x203fbb9][-1] == 3 and OPERANDS[0x203fbbd][1] == 0x203fc82,
            'loop poll / Pending exit changed')
    require(f[0x203f71b][-4:] == struct.pack('<I', 0x222) and f[0x203f72a][-1] == 3
            and OPERANDS[0x203f72d][1] == 0x203fb92 and OPERANDS[0x203f733][1] == 0x5692c80
            and OPERANDS[0x203f73a][1] == 0x576f038, 'async state dispatch changed')
    pieces = template(img, TEMPLATE)
    require(pieces == [None, ' ERROR >>> ', None, ' @@ node failed to accept ', None, ' connection: ', None, '\n\n'],
            f'template {TEMPLATE:#x} is {pieces}')
    require(f[0x203fe36][-1] == 2 and OPERANDS[0x203fe3a][1] == 0x203ff85, 'error tag changed')
    require(OPERANDS[0x203fe85][1] == TS_FORMAT and imm32(f[0x203fe94]) == len(TEXT[TS_FORMAT]), 'timestamp format')
    require(f[0x203fed2][-4:] == struct.pack('<I', 0x220), 'kind byte offset changed')
    for va, want in ((0x203fee1, 0x297b0e0), (0x203fefd, 0x21b7390), (0x203ff14, 0x57735e8), (0x203ff30, 0x576e4f0),
                     (0x203feb8, LAZY_PREFIX + 0x18), (0x203fec6, LAZY_PREFIX + 8), (0x203ff3f, TEMPLATE),
                     (0x203ff4e, 0x576e968), (0x203ff80, 0x203fb84), (0x203ffbf, 0x22b8310), (0x203ffe8, 0x203fb84)):
        require(OPERANDS[va][1] == want, f'operand at {va:#x} changed')
    require(f[0x203ff7e] == bytes.fromhex('ff10'), 'error drop changed')
    arm = {va: t for va, (n, t) in OPERANDS.items() if 0x203fe40 <= va < 0x203ff85}
    calls = {va: t for va, t in arm.items() if WINDOWS['dispatch_a'][2][2 * (va - 0x203fe36):][:2] in ('ff', 'e8', 'e9')}
    require(calls == {0x203fe4a: 0x576e8a0, 0x203ff4e: 0x576e968, 0x203ff70: 0x576e010, 0x203ff80: 0x203fb84},
            'error arm calls or jumps changed')
    stdout = OPERANDS[0x4edba61][1]
    require(TEXT.get(stdout) == b'stdout' and imm32(f[0x4edba6c]) == 6, 'print sink label changed')
    labels = {}
    for fn, lea, ln, flag in ((SPAWN_G, 0x225e460, 0x225e46f, 0x225e5ac), (SPAWN_V, 0x225e910, 0x225e91f, 0x225ea5c)):
        text = TEXT[OPERANDS[lea][1]]
        require(imm32(f[ln]) == len(text), f'{fn:#x} label length')
        require(TEXT[OPERANDS[lea + 0x46][1]] == b'handle_stream_connection' and imm32(f[lea + 0x55]) == 0x18,
                f'{fn:#x} task name changed')
        labels[hex(fn)] = dict(label=text.decode(), task='handle_stream_connection',
                               flag=struct.unpack('<H', f[flag][-2:])[0])
    require(f[0x4b6f893] == bytes.fromhex('803f01') and TEXT[OPERANDS[0x4b6f898][1]] == b'gossip'
            and TEXT[OPERANDS[0x4b6f8ad][1]] == b'validator', 'kind formatter changed')
    return dict(poll=hex(ACCEPT), pending='tag 3 -> state+0x222 = 3, poll metrics, return 1',
                resume=f'state 0 starts, 3 resumes at 0x203fb92, else panic {location(img, 0x5692c80)}',
                error=dict(tag=2, format=''.join('{}' if p is None else p for p in pieces),
                           sink='stdout via 0x576e968 -> 0x4edba50', kind='byte state+0x220 (1 -> gossip, else validator)',
                           after='drop the error, jmp 0x203fb84 (accept poll); no return, no sleep'),
                spawn=dict(clone='0x22b8310(state+0xc8)', targets={hex(LOOP_A): hex(SPAWN_V), hex(LOOP_B): hex(SPAWN_G)},
                           labels=labels))


def check_accept(img, f):
    require(OPERANDS[0x204938a][1] == ACCEPT4 and OPERANDS[0x2049397][1] == 0x20494d6, 'accept4 call changed')
    require(f[0x2049374][-1] == 0xff and OPERANDS[0x2049378][1] == 0x20497b4 and OPERANDS[0x20497b4][1] == 0x56932e8
            and OPERANDS[0x20497bb][1] == 0x576e470, 'fd -1 panic changed')
    table = [JUMP_TABLE + struct.unpack('<i', img.read(JUMP_TABLE + 4 * i, 4))[0] for i in range(4)]
    require(OPERANDS[0x20493bd][1] == JUMP_TABLE and table == [0x20493d2, 0x20493cd, 0x20493de, 0x2049402],
            f'io::Error repr table is {[hex(t) for t in table]}')
    require(f[0x20493d2] == bytes.fromhex('41803c060d') and f[0x20493cd] == bytes.fromhex('b80f000000'), 'WouldBlock kind test')
    require(f[0x20493ee][2:] == struct.pack('<Q', 11 << 32) and f[0x2049412][2:] == struct.pack('<Q', 13 << 32), 'EAGAIN / Simple')
    for va in (0x20493d7, 0x20493fb):
        require(OPERANDS[va][1] == 0x2049425, f'WouldBlock branch at {va:#x}')
    for va in (0x20493d9, 0x20493fd, 0x204941f):
        require(OPERANDS[va][1] == 0x20495a5, f'error branch at {va:#x}')
    require(f[0x204945e] == bytes.fromhex('f0480fb1be90000000'), 'readiness clear changed')
    require(imm32(f[0x2049550]) == 3 and OPERANDS[0x2049558][1] == 0x4f76f80 and f[0x204956d][-1] == 2
            and OPERANDS[0x2049571][1] == 0x204962a, 'registration changed')
    require(OPERANDS[0x204957b][1] == 0x576e708 and OPERANDS[0x20496a9][1] == 0x576e708, 'close calls changed')
    require(OPERANDS[0x2049583][1] == 0x7d1281 and imm32(f[0x204958a]) == 0x38 and imm32(f[0x204958f]) == 0x28,
            'Tokio shutdown error changed')
    require(OPERANDS[0x20495b8][1] == 0x288d0d0 and imm32(f[0x20495c0]) == 2 and f[0x20495ce] == bytes.fromhex('4c896d00')
            and f[0x20495d2] == bytes.fromhex('4c896508'), 'error result layout changed')
    require(f[0x20494f7] == bytes.fromhex('4c8b7c2438') and f[0x2049678] == bytes.fromhex('41f6c701'), 'peer tag test changed')
    require(OPERANDS[0x204967c][1] == 0x2049715 and TEXT[OPERANDS[0x2049682][1]] == b'ip not v4'
            and imm32(f[0x2049689]) == 9 and OPERANDS[0x204968e][1] == 0x288cab0, 'v4 gate changed')
    require(f[0x20496a4][-1] == 0xff and imm32(f[0x20496b9]) == 2 and OPERANDS[0x20496bf][1] == 0x20495c6, 'v6 result')
    require(f[0x20496f4] == bytes.fromhex('48c70003000000'), 'Pending tag changed')
    return dict(fde=hex(ACCEPT), accept4=hex(ACCEPT4), listener_fd_minus_one=f'panic at {location(img, 0x56932e8)}',
                would_block='kind 13 (SimpleMessage/Custom/Simple) or Os 11 -> 0x2049425, clear readiness; no result',
                other_error='0x20495a5 -> 0x288d0d0 -> tag 2',
                registration='0x4f76f80(interest 3); failure closes the fd -> tag 2; Tokio shutdown -> tag 2',
                ipv6_peer='SocketAddr tag bit 0 set -> "ip not v4" (0x288cab0), close fd, tag 2', pending='tag 3')


def check_callers(img):
    text = next((x for x in img.secs if x['name'] == '.text'), None)
    require(text is not None, 'no .text section')
    code = img.data[text['offset']:text['offset'] + text['size']]
    calls, pos = [], code.find(b'\xe8')
    while 0 <= pos < len(code) - 4:
        if text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0] == ACCEPT:
            calls.append(text['address'] + pos)
        pos = code.find(b'\xe8', pos + 1)
    owners = {}
    for va in calls:
        owners.setdefault(hex(img.containing(va)[0]), []).append(hex(va))
    require(set(owners) == {hex(LOOP_A), hex(LOOP_B), hex(SELECT)}, f'accept poll callers live in {sorted(owners)}')
    require(owners[hex(LOOP_A)] == ['0x203fbac'] and owners[hex(LOOP_B)] == [hex(0x203fbac + TWIN)],
            'twin poll sites changed')
    require(not [s for s, p in img.relative.items() if p == ACCEPT], 'RELATIVE slot holds the accept poll')
    return dict(accept_poll=owners, scanned='.text, every e8 rel32; no RELATIVE slots',
                select=f'{SELECT:#x} polls the same accept future from {len(owners[hex(SELECT)])} sites (not decoded)')


def poll_metrics(first, now, woke, last_end, start, end, long_delay, slow_poll):
    """Monitor offsets incremented by one instrumented poll that ends Pending, and the new state+0x228.

    All times are nanoseconds since the task was created: `now` is read at entry, `start` after the
    bookkeeping (0x203f713) and `end` at the Pending exit.  `woke` is 0 when the waker did not fire.
    """
    inc = {}

    def add(off, v):
        inc[off] = inc.get(off, 0) + v
    if first:
        add(0x18, 1)
        add(0x58, now)
    if woke > last_end:
        add(0x20, 1)
        add(0x60, woke - last_end)
    if woke:
        delay = max(0, now - woke)
        add(0x28, 1)
        add(0x68, delay)
        add(0x48 if delay < long_delay else 0x40, 1)
        add(0x80 if delay < long_delay else 0x88, delay)
    poll = max(0, end - start)
    add(0x30 if poll < slow_poll else 0x38, 1)
    add(0x70 if poll < slow_poll else 0x78, poll)
    return inc, end


def analyse(data):
    img = Image(data)
    win = windows(img)
    f = facts(img)
    return dict(target=TARGET, fdes=[hex(LOOP_A), hex(LOOP_B), hex(ACCEPT)],
                windows={k: hex(v) for k, v in win.items()}, operands=check_operands(img),
                twins=check_twins(img), metrics=check_metrics(f), loop=check_loop(img, f),
                accept=check_accept(img, f), callers=check_callers(img))


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
    m = result['metrics']
    print(f"poll split: {m['poll']['split']['threshold']}; delay split: {m['scheduled']['split']['threshold']}")
    print(f"accept error: {result['loop']['error']['after']}")
    print(f"twins: {result['twins']['only_difference']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
