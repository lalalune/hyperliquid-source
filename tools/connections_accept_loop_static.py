#!/usr/bin/env python3
"""Static node #94 node-connection accept loops `0x22c0d30` / `0x22c15e0`, checked from authenticated bytes.

Question: what does the node do when accepting a peer connection fails?  The
can1357 lead (`node/connections.rs` `accept_*_stream_connections`,
`net_utils/tcp/tcp_listener.rs` `run_accept_loop`) uses `accept().await?` and
returns the error, ending the loop.  Where does the binary differ?

Two twin async loops (`0x22c0d30` spawns `0x225e860`, label "validator";
`0x22c15e0` spawns `0x225e3b0`, label "gossip") poll the accept future
`0x22c47a0`.  On its error tag the loop prints
`<ts> ERROR >>> <prefix> @@ node failed to accept <kind> connection: <err>`
to stdout and jumps straight back to the accept poll; it neither returns nor
sleeps.  `0x22c47a0` also rejects every IPv6 peer with `ip not v4`.

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; call, branch and RIP-relative
targets, the packed format template, string literals, the io::Error jump table,
a panic Location, RELATIVE and GLOB_DAT slots are decoded here.  Nothing from
the binary is executed.
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
LOOP_A = 0x22c0d30
LOOP_B = 0x22c15e0
TWIN = LOOP_B - LOOP_A
ACCEPT = 0x22c47a0
KIND_FMT = 0x4b6f890
PRINT = 0x4edba50
SPAWN_V = 0x225e860
SPAWN_G = 0x225e3b0
ACCEPT4 = 0x3cd6220
TEMPLATE = 0x1fb0d4
TS_FORMAT = 0x3d7402
JUMP_TABLE = 0x3d67ac
PANIC_LOCATION = 0x56a0368
LAZY_PREFIX = 0x577ab50

WINDOWS = {
    'loop_a': (LOOP_A, 0x22c11c3,
        '4c89b370010000c68338020000004c8dab700100004c8d6424504c89e74c89ee4c89fae8b53500004c8b6c24504983fd'
        '030f84aa000000488b6c2458488d742460488dbc24f0030000baa8000000ff15c9cd4a0380bb38020000030f85130100'
        '0080bb30020000030f850601000080bbb8010000030f85f900000080bb28020000030f85ec00000080bb20020000030f'
        '85df0000004c8bb3e0010000498d7e18b10131c0f0410fb04e180f85af020000488d83e8010000488b93e80100004885'
        'd27468488b8bf001000048894a084885c9746e488b104889110f57c00f1100eb6a'),
    'pending_a': (LOOP_A, 0x22c12a4,
        'c6834202000003488b0b4883f9027426488d7318488b7b08488b4310f6c1017412488b481048ffc94883e1f04801cf48'
        '83c710ff5068b0014881c4b80500005b415c415d415e415f5dc3'),
    'dispatch_a': (LOOP_A, 0x22c1337,
        '4183fd020f853201000048892c24488d7c2420ff1550d54a038b4424208984249c000000c78424900000000100000048'
        '8b442424488984249400000049bd00000000000000804c896c2450488d05796011fe488944247048c744247816000000'
        '48c78424800000000800000048c7842488000000000000008b05b3974b0385c00f851f0100000f100594974b030f1144'
        '2440488d83400200004c89a42430020000488d0d019d6b0048898c2438020000488d4c244048898c2440020000488d0d'
        '955fefff48898c24480200004889842450020000488b05d6214b0348898424580200004889e04889842460020000488b'
        '05c4d04a034889842468020000488d3d999cf3fd488db42430020000ff151fd54a03488b7424504c39ee74124885f674'
        '0d488b7c245831d2ff15abcb4a03488b3c24488b07ff10e950fdffff488d7c2460488db424f0030000ba88000000ff15'
        '55cb4a034c8da424780400004c896c245048896c2458488db3e80000004c8dac24300200004c89efe85c6effff488dbb'
        'a0000000488d7424504c89e24c89e9e895d3f9ffe9f3fcffff'),
    'loop_b': (LOOP_B, 0x22c1a73,
        '4c89b370010000c68338020000004c8dab700100004c8d6424504c89e74c89ee4c89fae8052d00004c8b6c24504983fd'
        '030f84aa000000488b6c2458488d742460488dbc24f0030000baa8000000ff1519c54a0380bb38020000030f85130100'
        '0080bb30020000030f850601000080bbb8010000030f85f900000080bb28020000030f85ec00000080bb20020000030f'
        '85df0000004c8bb3e0010000498d7e18b10131c0f0410fb04e180f85af020000488d83e8010000488b93e80100004885'
        'd27468488b8bf001000048894a084885c9746e488b104889110f57c00f1100eb6a'),
    'pending_b': (LOOP_B, 0x22c1b54,
        'c6834202000003488b0b4883f9027426488d7318488b7b08488b4310f6c1017412488b481048ffc94883e1f04801cf48'
        '83c710ff5068b0014881c4b80500005b415c415d415e415f5dc3'),
    'dispatch_b': (LOOP_B, 0x22c1be7,
        '4183fd020f853201000048892c24488d7c2420ff15a0cc4a038b4424208984249c000000c78424900000000100000048'
        '8b442424488984249400000049bd00000000000000804c896c2450488d05c95711fe488944247048c744247816000000'
        '48c78424800000000800000048c7842488000000000000008b05038f4b0385c00f851f0100000f1005e48e4b030f1144'
        '2440488d83400200004c89a42430020000488d0d51946b0048898c2438020000488d4c244048898c2440020000488d0d'
        'e556efff48898c24480200004889842450020000488b0526194b0348898424580200004889e04889842460020000488b'
        '0514c84a034889842468020000488d3de993f3fd488db42430020000ff156fcc4a03488b7424504c39ee74124885f674'
        '0d488b7c245831d2ff15fbc24a03488b3c24488b07ff10e950fdffff488d7c2460488db424f0030000ba88000000ff15'
        'a5c24a034c8da424780400004c896c245048896c2458488db3e80000004c8dac24300200004c89efe8ac65ffff488dbb'
        'a0000000488d7424504c89e24c89e9e835c6f9ffe9f3fcffff'),
    'accept': (ACCEPT, 0x22c4c01,
        '488b7340837e18ff0f84310400004883c618488dbc24f8000000e80016a10180bc24f8000000000f841a0100004c8ba4'
        '24000100004c89642428c7442420010000004589e64183e603b810000000488d0d561b11fe4a6314b14801caffe2b80f'
        '00000041803c040d744ce9a30100004c89e048b900000000ffffffff4821c848b9000000000b0000004839c87428e97f'
        '0100004c89e048b900000000ffffffff4821c848b9000000000d0000004839c80f855c010000'),
    'would_block': (ACCEPT, 0x22c4cb7,
        '488b4330488b4b500fb65358488b7010488b869000000083e1334881f13f00ff000f1f84000000000089c7c1ef104038'
        'fa750f89c721cff0480fb1be9000000075e7'),
    'accepted': (ACCEPT, 0x22c4d48,
        '8bac24fc0000000f108424000100000f114424280f108424100100000f114424384c8b6c24280f104424300f29442450'
        '488b44244048894424600f298424c000000048898424d0000000488b442408c60001488d3dff114903ff1501a34a0349'
        '89d0896c24204c8d0deb114903488dbc24f8000000488d742420ba030000004889c1e8b121cb02488b8424f80000004c'
        '8ba424000100004883f8020f85af0000008b7c2420ff1515994a03eb26488d3585c450feba38000000bf28000000ff15'
        '54a04a034989c441c60701488b442408c60001488b442410c600014c89e7e8a5825c004989c741bc02000000488bac24'
        '880000004c8965004c897d08488d7d10488db42490010000ba88000000ff1585914a0366c7859800000000004489b59a'
        '000000664489ad9e0000000f288424a00000000f1185a0000000488b8424b0000000488985b0000000b001e990010000'),
    'v4_check': (ACCEPT, 0x22c4e98,
        '488b8c24080100008b5424200f288424c00000000f298424e0000000488bb424d00000004889b424f0000000488b7424'
        '10c6060148894c24608954246848894424504c896424584d89ee49c1ee1041f6c5017471488d3d4f3411febe09000000'
        'e8b37b5c004989c7488d7c2450e8b6145d008b7c246883ffff7406ff15ef974a03488d7c2450e81dfcf8ff41bc020000'
        '00e906ffffff'),
    'pending': (ACCEPT, 0x22c5017, '488b84248800000048c70003000000b0038883c80000004881c4180200005b415c415d415e415f5dc3'),
    'closed': (ACCEPT, 0x22c5040, '488d3d21b33d03ff1523944a030f0b'),
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
    0x22c11e6: ('e8b5350000', 'loop polls accept future 0x22c47a0(out=rsp+0x50, listener=rbx+0x170)'),
    0x22c11eb: ('4c8b6c2450', 'tag = [rsp+0x50]'),
    0x22c11f0: ('4983fd03', 'tag 3 is Pending'),
    0x22c11f4: ('0f84aa000000', 'Pending leaves the loop'),
    0x22c12a4: ('c6834202000003', 'Pending stores state 3'),
    0x22c12da: ('b001', 'Pending returns 1'),
    0x22c1337: ('4183fd02', 'tag 2 is the accept error'),
    0x22c133b: ('0f8532010000', 'other tags spawn'),
    0x22c134a: ('ff1550d54a03', 'error arm reads wall clock'),
    0x22c1373: ('49bd0000000000000080', 'timestamp is a borrowed format (0x8000000000000000 niche)'),
    0x22c1382: ('488d05796011fe', 'timestamp format string'),
    0x22c138e: ('48c744247816000000', 'format string length 0x16'),
    0x22c13af: ('8b05b3974b03', 'lazy prefix Once state'),
    0x22c13bd: ('0f100594974b03', 'lazy prefix &str'),
    0x22c13c9: ('488d8340020000', 'kind byte at state +0x240'),
    0x22c13d8: ('488d0d019d6b00', 'timestamp formatter'),
    0x22c13f4: ('488d0d955fefff', '&str Display for the lazy prefix'),
    0x22c140b: ('488b05d6214b03', 'kind Display'),
    0x22c1425: ('488b05c4d04a03', 'error Display'),
    0x22c1434: ('488d3d999cf3fd', 'stdout template'),
    0x22c1443: ('ff151fd54a03', 'print to stdout'),
    0x22c1465: ('488b3c24', 'error object'),
    0x22c146c: ('ff10', 'error dropped'),
    0x22c146e: ('e950fdffff', 'error arm loops back'),
    0x22c14af: ('e85c6effff', 'clone shared handle state+0xe8'),
    0x22c14c6: ('e895d3f9ff', 'spawn handler future'),
    0x22c14cb: ('e9f3fcffff', 'spawn arm loops back'),
    0x22c4c05: ('837e18ff', 'listener fd -1 check'),
    0x22c4c09: ('0f8431040000', 'fd -1 panics'),
    0x22c4c1b: ('e80016a101', 'accept4 wrapper'),
    0x22c4c20: ('80bc24f800000000', 'accept4 result tag'),
    0x22c4c28: ('0f841a010000', 'Ok goes to registration'),
    0x22c4c4f: ('488d0d561b11fe', 'io::Error repr jump table'),
    0x22c4c64: ('41803c040d', 'kind byte compared with WouldBlock'),
    0x22c4c5f: ('b80f000000', 'Custom kind offset 0xf'),
    0x22c4c80: ('48b9000000000b000000', 'Os code EAGAIN (11)'),
    0x22c4ca4: ('48b9000000000d000000', 'Simple kind WouldBlock (13)'),
    0x22c4c6b: ('e9a3010000', 'non-WouldBlock error'),
    0x22c4c8f: ('e97f010000', 'non-EAGAIN error'),
    0x22c4cb1: ('0f855c010000', 'non-WouldBlock simple error'),
    0x22c4cee: ('f0480fb1be90000000', 'clear readiness'),
    0x22c4d48: ('8bac24fc000000', 'accepted fd'),
    0x22c4d69: ('4c8b6c2428', 'peer SocketAddr tag'),
    0x22c4dc2: ('ba03000000', 'register interest 3 (readable|writable)'),
    0x22c4dca: ('e8b121cb02', 'Tokio registration'),
    0x22c4ddf: ('4883f802', 'registration error is tag 2'),
    0x22c4ded: ('ff1515994a03', 'close fd on registration error'),
    0x22c4df5: ('488d3585c450fe', 'Tokio shutdown message'),
    0x22c4dfc: ('ba38000000', 'message length 0x38'),
    0x22c4e01: ('bf28000000', 'error kind 0x28'),
    0x22c4e26: ('e8a5825c00', 'wrap as listener error'),
    0x22c4e2e: ('41bc02000000', 'tag 2'),
    0x22c4e3c: ('4c896500', 'store tag'),
    0x22c4e40: ('4c897d08', 'store error'),
    0x22c4ee6: ('41f6c501', 'SocketAddr tag bit 0 = V6'),
    0x22c4eea: ('7471', 'V4 continues'),
    0x22c4eec: ('488d3d4f3411fe', '"ip not v4"'),
    0x22c4ef3: ('be09000000', 'length 9'),
    0x22c4ef8: ('e8b37b5c00', 'make error'),
    0x22c4f0e: ('83ffff', 'fd -1 check'),
    0x22c4f13: ('ff15ef974a03', 'close fd'),
    0x22c4f1e: ('e81dfcf8ff', 'drop stream'),
    0x22c4f23: ('41bc02000000', 'tag 2'),
    0x22c4f29: ('e906ffffff', 'store error result'),
    0x22c501f: ('48c70003000000', 'Pending tag 3'),
    0x22c5040: ('488d3d21b33d03', 'panic location'),
    0x22c5047: ('ff1523944a03', 'panic'),
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
    0x225e460: (7, 0x706ece),  # label_g: lea
    0x225e474: (6, 0x576e000),  # label_g: call
    0x225e4a6: (7, 0x3d78b8),  # task_g: lea
    0x225e910: (7, 0x706ec5),  # label_v: lea
    0x225e924: (6, 0x576e000),  # label_v: call
    0x225e956: (7, 0x3d78b8),  # task_v: lea
    0x22c11e6: (5, 0x22c47a0),  # loop_a: call
    0x22c11f4: (6, 0x22c12a4),  # loop_a: je
    0x22c1211: (6, 0x576dfe0),  # loop_a: call
    0x22c121e: (6, 0x22c1337),  # loop_a: jne
    0x22c122b: (6, 0x22c1337),  # loop_a: jne
    0x22c1238: (6, 0x22c1337),  # loop_a: jne
    0x22c1245: (6, 0x22c1337),  # loop_a: jne
    0x22c1252: (6, 0x22c1337),  # loop_a: jne
    0x22c126d: (6, 0x22c1522),  # loop_a: jne
    0x22c1284: (2, 0x22c12ee),  # loop_a: je
    0x22c1294: (2, 0x22c1304),  # loop_a: je
    0x22c12a2: (2, 0x22c130e),  # loop_a: jmp
    0x22c12b2: (2, 0x22c12da),  # pending_a: je
    0x22c12c3: (2, 0x22c12d7),  # pending_a: je
    0x22c133b: (6, 0x22c1473),  # dispatch_a: jne
    0x22c134a: (6, 0x576e8a0),  # dispatch_a: call
    0x22c1382: (7, 0x3d7402),  # dispatch_a: lea
    0x22c13af: (6, 0x577ab68),  # dispatch_a: mov
    0x22c13b7: (6, 0x22c14dc),  # dispatch_a: jne
    0x22c13bd: (7, 0x577ab58),  # dispatch_a: movups
    0x22c13d8: (7, 0x297b0e0),  # dispatch_a: lea
    0x22c13f4: (7, 0x21b7390),  # dispatch_a: lea
    0x22c140b: (7, 0x57735e8),  # dispatch_a: mov
    0x22c1425: (7, 0x576e4f0),  # dispatch_a: mov
    0x22c1434: (7, 0x1fb0d4),  # dispatch_a: lea
    0x22c1443: (6, 0x576e968),  # dispatch_a: call
    0x22c1451: (2, 0x22c1465),  # dispatch_a: je
    0x22c1456: (2, 0x22c1465),  # dispatch_a: je
    0x22c145f: (6, 0x576e010),  # dispatch_a: call
    0x22c146e: (5, 0x22c11c3),  # dispatch_a: jmp
    0x22c1485: (6, 0x576dfe0),  # dispatch_a: call
    0x22c14af: (5, 0x22b8310),  # dispatch_a: call
    0x22c14c6: (5, 0x225e860),  # dispatch_a: call
    0x22c14cb: (5, 0x22c11c3),  # dispatch_a: jmp
    0x22c1a96: (5, 0x22c47a0),  # loop_b: call
    0x22c1aa4: (6, 0x22c1b54),  # loop_b: je
    0x22c1ac1: (6, 0x576dfe0),  # loop_b: call
    0x22c1ace: (6, 0x22c1be7),  # loop_b: jne
    0x22c1adb: (6, 0x22c1be7),  # loop_b: jne
    0x22c1ae8: (6, 0x22c1be7),  # loop_b: jne
    0x22c1af5: (6, 0x22c1be7),  # loop_b: jne
    0x22c1b02: (6, 0x22c1be7),  # loop_b: jne
    0x22c1b1d: (6, 0x22c1dd2),  # loop_b: jne
    0x22c1b34: (2, 0x22c1b9e),  # loop_b: je
    0x22c1b44: (2, 0x22c1bb4),  # loop_b: je
    0x22c1b52: (2, 0x22c1bbe),  # loop_b: jmp
    0x22c1b62: (2, 0x22c1b8a),  # pending_b: je
    0x22c1b73: (2, 0x22c1b87),  # pending_b: je
    0x22c1beb: (6, 0x22c1d23),  # dispatch_b: jne
    0x22c1bfa: (6, 0x576e8a0),  # dispatch_b: call
    0x22c1c32: (7, 0x3d7402),  # dispatch_b: lea
    0x22c1c5f: (6, 0x577ab68),  # dispatch_b: mov
    0x22c1c67: (6, 0x22c1d8c),  # dispatch_b: jne
    0x22c1c6d: (7, 0x577ab58),  # dispatch_b: movups
    0x22c1c88: (7, 0x297b0e0),  # dispatch_b: lea
    0x22c1ca4: (7, 0x21b7390),  # dispatch_b: lea
    0x22c1cbb: (7, 0x57735e8),  # dispatch_b: mov
    0x22c1cd5: (7, 0x576e4f0),  # dispatch_b: mov
    0x22c1ce4: (7, 0x1fb0d4),  # dispatch_b: lea
    0x22c1cf3: (6, 0x576e968),  # dispatch_b: call
    0x22c1d01: (2, 0x22c1d15),  # dispatch_b: je
    0x22c1d06: (2, 0x22c1d15),  # dispatch_b: je
    0x22c1d0f: (6, 0x576e010),  # dispatch_b: call
    0x22c1d1e: (5, 0x22c1a73),  # dispatch_b: jmp
    0x22c1d35: (6, 0x576dfe0),  # dispatch_b: call
    0x22c1d5f: (5, 0x22b8310),  # dispatch_b: call
    0x22c1d76: (5, 0x225e3b0),  # dispatch_b: call
    0x22c1d7b: (5, 0x22c1a73),  # dispatch_b: jmp
    0x22c4c09: (6, 0x22c5040),  # accept: je
    0x22c4c1b: (5, 0x3cd6220),  # accept: call
    0x22c4c28: (6, 0x22c4d48),  # accept: je
    0x22c4c4f: (7, 0x3d67ac),  # accept: lea
    0x22c4c69: (2, 0x22c4cb7),  # accept: je
    0x22c4c6b: (5, 0x22c4e13),  # accept: jmp
    0x22c4c8d: (2, 0x22c4cb7),  # accept: je
    0x22c4c8f: (5, 0x22c4e13),  # accept: jmp
    0x22c4cb1: (6, 0x22c4e13),  # accept: jne
    0x22c4ce8: (2, 0x22c4cf9),  # would_block: jne
    0x22c4cf7: (2, 0x22c4ce0),  # would_block: jne
    0x22c4d9a: (7, 0x5755fa0),  # accepted: lea
    0x22c4da1: (6, 0x576f0a8),  # accepted: call
    0x22c4dae: (7, 0x5755fa0),  # accepted: lea
    0x22c4dca: (5, 0x4f76f80),  # accepted: call
    0x22c4de3: (6, 0x22c4e98),  # accepted: jne
    0x22c4ded: (6, 0x576e708),  # accepted: call
    0x22c4df3: (2, 0x22c4e1b),  # accepted: jmp
    0x22c4df5: (7, 0x7d1281),  # accepted: lea
    0x22c4e06: (6, 0x576ee60),  # accepted: call
    0x22c4e26: (5, 0x288d0d0),  # accepted: call
    0x22c4e55: (6, 0x576dfe0),  # accepted: call
    0x22c4e93: (5, 0x22c5028),  # accepted: jmp
    0x22c4eea: (2, 0x22c4f5d),  # v4_check: je
    0x22c4eec: (7, 0x3d8342),  # v4_check: lea
    0x22c4ef8: (5, 0x288cab0),  # v4_check: call
    0x22c4f05: (5, 0x28963c0),  # v4_check: call
    0x22c4f11: (2, 0x22c4f19),  # v4_check: je
    0x22c4f13: (6, 0x576e708),  # v4_check: call
    0x22c4f1e: (5, 0x2254b40),  # v4_check: call
    0x22c4f29: (5, 0x22c4e34),  # v4_check: jmp
    0x22c5040: (7, 0x56a0368),  # closed: lea
    0x22c5047: (6, 0x576e470),  # closed: call
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
    0x576e708: ('close', 'close(2)'),
    0x576dfe0: ('memcpy', 'memcpy'),
}

TEXT = {
    TS_FORMAT: b'%Y-%m-%dT%H:%M:%S%.3fZ',
    0x3d8342: b'ip not v4',
    0x7d1281: b'A Tokio 1.x context was found, but it is being shutdown.',
    0x7cd20b: b'stdout',
    0x706ece: b'gossip',
    0x706ec5: b'validator',
    0x3d78b8: b'handle_stream_connection',
}

# The only offsets at which the two loop windows may differ: rel operands whose targets move with the twin.
SPAWN_CALL = 0x22c14c6


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
    return out


def check_twins(img):
    """The two loops are byte-identical except inside rel operands; only the spawn call target differs."""
    a_start, a_end = img.fde(LOOP_A)
    b_start, b_end = img.fde(LOOP_B)
    require(b_start - a_start == TWIN and b_end - a_end == TWIN, 'loop FDEs are not a fixed shift apart')
    compared, spans = 0, 0
    for a_name in ('loop_a', 'pending_a', 'dispatch_a'):
        a_fde, a_va, a_hex = WINDOWS[a_name]
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
    return dict(shift=hex(TWIN), compared_bytes=compared, rel_operands=spans,
                only_difference=f'{SPAWN_CALL:#x}: call {SPAWN_V:#x} (validator) vs '
                                f'{SPAWN_CALL + TWIN:#x}: call {SPAWN_G:#x} (gossip)')


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


def location(img, va):
    ptr = img.relative.get(va)
    require(ptr is not None, f'Location {va:#x} has no RELATIVE file pointer')
    n, line, col = struct.unpack('<QII', img.read(va + 8, 16))
    require(0 < n < 256, f'Location {va:#x} has length {n}')
    path = img.read(ptr, n)
    require(all(0x20 <= c < 0x7f for c in path), f'Location {va:#x} path is not text')
    return f'{path.decode()}:{line}:{col}'


def check_error_arm(img, f):
    pieces = template(img, TEMPLATE)
    require(pieces == [None, ' ERROR >>> ', None, ' @@ node failed to accept ', None, ' connection: ', None, '\n\n'],
            f'template {TEMPLATE:#x} is {pieces}')
    require(f[0x22c11f0][-1] == 3 and f[0x22c1337][-1] == 2, 'loop tag constants changed')
    require(f[0x22c12a4][-1] == 3 and f[0x22c12da] == bytes.fromhex('b001'), 'Pending arm changed')
    require(struct.unpack('<I', f[0x22c138e][-4:])[0] == len(TEXT[TS_FORMAT]), 'timestamp format length')
    require(f[0x22c13c9][-4:] == struct.pack('<I', 0x240), 'kind byte offset changed')
    require(f[0x22c1465] == bytes.fromhex('488b3c24') and f[0x22c146c] == bytes.fromhex('ff10'), 'error drop changed')
    args = [(0x22c13d8, 0x297b0e0), (0x22c13f4, 0x21b7390), (0x22c140b, 0x57735e8), (0x22c1425, 0x576e4f0)]
    for va, want in args:
        require(OPERANDS[va][1] == want, f'argument formatter at {va:#x} changed')
    require(OPERANDS[0x22c13af][1] == LAZY_PREFIX + 0x18 and OPERANDS[0x22c13bd][1] == LAZY_PREFIX + 8,
            'lazy prefix layout changed')
    require(OPERANDS[0x22c1443][1] == 0x576e968 and OPERANDS[0x22c146e][1] == 0x22c11c3,
            'error arm no longer prints to stdout and loops back')
    require(OPERANDS[0x22c1434][1] == TEMPLATE, 'template operand changed')
    arm = {va: t for va, (n, t) in OPERANDS.items() if 0x22c1341 <= va < 0x22c1473}
    require({va: t for va, t in arm.items() if WINDOWS['dispatch_a'][2][2 * (va - 0x22c1337):][:2] in ('ff', 'e8', 'e9')}
            == {0x22c134a: 0x576e8a0, 0x22c1443: 0x576e968, 0x22c145f: 0x576e010, 0x22c146e: 0x22c11c3},
            'error arm calls or jumps changed')
    require(set(arm.values()) - {0x576e8a0, 0x576e968, 0x576e010, 0x22c11c3, 0x22c1465, 0x22c14dc, 0x577ab68,
                                 0x577ab58, 0x3d7402, 0x297b0e0, 0x21b7390, 0x57735e8, 0x576e4f0, TEMPLATE} == set(),
            'error arm references changed')
    stdout = OPERANDS[0x4edba61][1]
    require(TEXT.get(stdout) == b'stdout' and f[0x4edba6c][-4:] == struct.pack('<I', 6), 'print sink label changed')
    return dict(tag=2, sink='stdout via 0x576e968 -> 0x4edba50 (label "stdout")',
                format=''.join('{}' if p is None else p for p in pieces),
                args=['wall clock now formatted with %Y-%m-%dT%H:%M:%S%.3fZ (0x297b0e0)',
                      f'lazy &str static {LAZY_PREFIX:#x} (init 0x143ed40, Display 0x21b7390)',
                      'kind byte state+0x240 (Display 0x4b6f890: 1 -> "gossip", else "validator")',
                      'error (Display 0x1367fb0)'],
                after='drop the error, jmp 0x22c11c3 (accept poll); no return, no sleep')


def check_spawn_arm(f):
    require(OPERANDS[0x22c133b][1] == 0x22c1473 and OPERANDS[0x22c14af][1] == 0x22b8310, 'spawn arm entry changed')
    require(OPERANDS[SPAWN_CALL][1] == SPAWN_V and OPERANDS[SPAWN_CALL + TWIN][1] == SPAWN_G, 'spawn targets changed')
    require(OPERANDS[0x22c14cb][1] == 0x22c11c3, 'spawn arm no longer loops back')
    labels = {}
    for fn, lea, ln, flag in ((SPAWN_G, 0x225e460, 0x225e46f, 0x225e5ac), (SPAWN_V, 0x225e910, 0x225e91f, 0x225ea5c)):
        text = TEXT[OPERANDS[lea][1]]
        require(struct.unpack('<I', f[ln][-4:])[0] == len(text), f'{fn:#x} label length')
        task = lea + 0x46
        require(TEXT[OPERANDS[task][1]] == b'handle_stream_connection' and f[task + 0xf][-4:] == struct.pack('<I', 0x18),
                f'{fn:#x} task name changed')
        labels[hex(fn)] = dict(label=text.decode(), task='handle_stream_connection',
                               flag=struct.unpack('<H', f[flag][-2:])[0])
    require(labels[hex(SPAWN_G)]['flag'] == 1 and labels[hex(SPAWN_V)]['flag'] == 0, 'spawn flags changed')
    return dict(tags='0 and 1', clone='0x22b8310(state+0xe8)', spawn={hex(LOOP_A): hex(SPAWN_V), hex(LOOP_B): hex(SPAWN_G)},
                labels=labels, after='jmp 0x22c11c3 without awaiting the handler')


def check_kind(f):
    require(f[0x4b6f893] == bytes.fromhex('803f01'), 'kind compare changed')
    require(TEXT[OPERANDS[0x4b6f898][1]] == b'gossip' and f[0x4b6f89f][-4:] == struct.pack('<I', 6), 'kind 1 text')
    require(TEXT[OPERANDS[0x4b6f8ad][1]] == b'validator' and f[0x4b6f8b4][-4:] == struct.pack('<I', 9), 'kind other text')
    require(OPERANDS[0x4b6f8a7][1] == OPERANDS[0x4b6f8bc][1] == 0x576e000, 'kind formatter sink')
    return {'1': 'gossip', 'other': 'validator'}


def check_accept(img, f):
    require(OPERANDS[0x22c4c1b][1] == ACCEPT4 and OPERANDS[0x22c4c28][1] == 0x22c4d48, 'accept4 call changed')
    require(f[0x22c4c05][-1] == 0xff and OPERANDS[0x22c4c09][1] == 0x22c5040 and OPERANDS[0x22c5047][1] == 0x576e470,
            'fd -1 panic changed')
    panic = location(img, PANIC_LOCATION)
    require(OPERANDS[0x22c5040][1] == PANIC_LOCATION and panic.endswith('/tokio-1.44.2/src/io/poll_evented.rs:288:26'),
            f'fd -1 panic Location is {panic}')
    table = [JUMP_TABLE + struct.unpack('<i', img.read(JUMP_TABLE + 4 * i, 4))[0] for i in range(4)]
    require(OPERANDS[0x22c4c4f][1] == JUMP_TABLE and table == [0x22c4c64, 0x22c4c5f, 0x22c4c70, 0x22c4c94],
            f'io::Error repr table is {[hex(t) for t in table]}')
    require(f[0x22c4c64] == bytes.fromhex('41803c040d'), 'WouldBlock kind compare changed')
    require(f[0x22c4c5f] == bytes.fromhex('b80f000000'), 'Custom kind offset changed')
    require(f[0x22c4c80][2:] == struct.pack('<Q', 11 << 32), 'EAGAIN compare changed')
    require(f[0x22c4ca4][2:] == struct.pack('<Q', 13 << 32), 'Simple WouldBlock compare changed')
    for va in (0x22c4c69, 0x22c4c8d):
        require(OPERANDS[va][1] == 0x22c4cb7, f'WouldBlock branch at {va:#x}')
    for va in (0x22c4c6b, 0x22c4c8f, 0x22c4cb1):
        require(OPERANDS[va][1] == 0x22c4e13, f'error branch at {va:#x}')
    require(f[0x22c4cee] == bytes.fromhex('f0480fb1be90000000'), 'readiness clear changed')
    require(f[0x22c4dc2] == bytes.fromhex('ba03000000') and OPERANDS[0x22c4dca][1] == 0x4f76f80, 'registration changed')
    require(f[0x22c4ddf][-1] == 2 and OPERANDS[0x22c4de3][1] == 0x22c4e98, 'registration result tag')
    require(OPERANDS[0x22c4ded][1] == 0x576e708 and OPERANDS[0x22c4f13][1] == 0x576e708, 'close calls changed')
    require(OPERANDS[0x22c4df5][1] == 0x7d1281 and f[0x22c4dfc][-4:] == struct.pack('<I', 0x38)
            and f[0x22c4e01][-4:] == struct.pack('<I', 0x28), 'Tokio shutdown error changed')
    require(OPERANDS[0x22c4e26][1] == 0x288d0d0 and f[0x22c4e2e] == bytes.fromhex('41bc02000000')
            and f[0x22c4e3c] == bytes.fromhex('4c896500') and f[0x22c4e40] == bytes.fromhex('4c897d08'),
            'error result layout changed')
    require(f[0x22c4d69] == bytes.fromhex('4c8b6c2428') and f[0x22c4ee6] == bytes.fromhex('41f6c501'),
            'peer address tag test changed')
    require(OPERANDS[0x22c4eea][1] == 0x22c4f5d and TEXT[OPERANDS[0x22c4eec][1]] == b'ip not v4'
            and f[0x22c4ef3][-4:] == struct.pack('<I', 9) and OPERANDS[0x22c4ef8][1] == 0x288cab0, 'v4 gate changed')
    require(f[0x22c4f0e][-1] == 0xff and f[0x22c4f23] == bytes.fromhex('41bc02000000')
            and OPERANDS[0x22c4f29][1] == 0x22c4e34, 'v6 rejection result changed')
    require(f[0x22c501f] == bytes.fromhex('48c70003000000'), 'Pending tag changed')
    return dict(fde=hex(ACCEPT), accept4=hex(ACCEPT4), listener_fd_minus_one=f'panic at {panic}',
                would_block='kind 13 (SimpleMessage/Custom/Simple) or Os 11 -> 0x22c4cb7, clear readiness; no result',
                other_error='0x22c4e13 -> 0x288d0d0 -> tag 2',
                registration='0x4f76f80(interest 3); failure closes the fd -> tag 2; Tokio shutdown -> tag 2',
                ipv6_peer='SocketAddr tag bit 0 set -> "ip not v4" (0x288cab0), close fd, tag 2',
                pending='tag 3')


def check_callers(img):
    text = next((x for x in img.secs if x['name'] == '.text'), None)
    require(text is not None, 'no .text section')
    code = img.data[text['offset']:text['offset'] + text['size']]
    want = {ACCEPT: [0x22c11e6, 0x22c11e6 + TWIN], SPAWN_V: [SPAWN_CALL], SPAWN_G: [SPAWN_CALL + TWIN]}
    calls, pos = {k: [] for k in want}, code.find(b'\xe8')
    while 0 <= pos < len(code) - 4:
        tgt = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
        if tgt in calls:
            calls[tgt].append(text['address'] + pos)
        pos = code.find(b'\xe8', pos + 1)
    # The accept poll 0x22c47a0 is reached only from these two twins.  The spawn helpers are shared with a
    # sibling accept-loop family (0x203f3e0 / 0x2041c60, which poll the other accept monomorph 0x2048f10), so
    # they have one extra caller each; the twin spawn sites are still verified here and in check_twins.
    require(calls[ACCEPT] == want[ACCEPT], f'callers of accept poll are {[hex(x) for x in calls[ACCEPT]]}')
    require(not [s for s, p in img.relative.items() if p == ACCEPT], 'RELATIVE slot holds the accept poll')
    for k in (SPAWN_V, SPAWN_G):
        require(set(want[k]) <= set(calls[k]), f'twin spawn site missing from callers of {k:#x}')
    return dict(accept_poll=[hex(x) for x in calls[ACCEPT]],
                spawn_validator=[hex(x) for x in calls[SPAWN_V]], spawn_gossip=[hex(x) for x in calls[SPAWN_G]],
                sibling_family='0x203f3e0 / 0x2041c60 poll 0x2048f10 and reuse the same spawn helpers',
                scanned='.text, every e8 rel32')


def accept_result(error=None, peer='v4', registered=True):
    """Tag 0x22c47a0 stores for one ready poll.  `error` is an io::ErrorKind name or None."""
    if error == 'WouldBlock':
        return 3
    if error is not None or not registered or peer == 'v6':
        return 2
    return 0


def loop_step(tag):
    """What the binary loop does with one accept result."""
    if tag == 3:
        return 'pending'
    if tag == 2:
        return 'print-stdout-continue'
    return 'spawn-continue'


def lead_step(tag):
    """What the lead `accept().await?` loop does with the same result."""
    if tag == 3:
        return 'pending'
    if tag == 2:
        return 'return-err'
    return 'spawn-continue'


def analyse(data):
    img = Image(data)
    win = windows(img)
    f = facts(img)
    return dict(target=TARGET, fdes=[hex(LOOP_A), hex(LOOP_B), hex(ACCEPT)],
                windows={k: hex(v) for k, v in win.items()}, operands=check_operands(img),
                twins=check_twins(img), error_arm=check_error_arm(img, f), spawn_arm=check_spawn_arm(f),
                kind=check_kind(f), accept=check_accept(img, f), callers=check_callers(img))


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
    print(f"accept error: {result['error_arm']['after']}")
    print(f"ipv6 peer: {result['accept']['ipv6_peer']}")
    print(f"twins: {result['twins']['only_difference']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
