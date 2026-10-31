#!/usr/bin/env python3
"""Static node #94 `node/consensus/config.rs` validator and public-IP checks, from authenticated bytes.

Question: what does the consensus config builder `0x284a5a0` check before it
returns?  The can1357 lead (`node/consensus/config.rs`) says it looks the
signer's address up in `StaticConfig.node_ips` and panics with "validator is
not in node_ips" when it is absent, then, when `static_config + 0x8f2` is set,
compares the configured node IP with the discovered public IPv4 address and
panics on a mismatch; it decodes the node-IP tag as Ip = 0, Error = 1,
LocalNode = 2.

In the binary the function makes three checks, each with its own panic
Location in `config.rs`:

* 30:17, "running with wallet that is not a validator": a full in-order walk
  of the tree at `static + 0xa48` compares the wallet's 20 bytes with a field
  of every 0x58-byte item, keeps the tag and u32 of the last match, and
  panics when nothing matched (or the tree is empty);
* 44:25 / 51:21: only when the byte at `static + 0x8f2` is set, a helper
  returns the public IP as a String, which is parsed with the inlined std
  `Ipv4Addr` parser (longer than 15 bytes or not fully consumed: an IPv4
  `AddrParseError`).  A parse error logs "could not get public ip, not
  validating against abci state" and goes on.  Otherwise, unless the wallet is
  in a second address set, a node IP whose tag is not 0 or whose u32 differs
  panics with "public_ip does not match abci state";
* 60:13, "validator is not in node_ips": unless the wallet is in that second
  set, a lookup in a third map, built after the IP step, panics when the
  wallet is missing or its value tag is 2.

The fifth config.rs Location, 71:32, is the last (stack) argument of
`0x258ad80`, called with that third map and the str "node_ips".

The node-IP Debug formatter `0x284b660` has two arms: tag 1 prints
"LocalNode" plus a u32, every other tag prints "Ip" plus a field.  Every
message is prefixed with the str "CONFIGURATION ERROR".

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; call, branch and RIP-relative
targets, the format templates, the Locations, the RELATIVE and GLOB_DAT slots
and a whole-`.text` census of references to the config.rs Locations are
decoded here.  Nothing from the binary is executed.
"""
import argparse
import ipaddress
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
BUILD = 0x284a5a0
NODE_IP_DEBUG = 0x284b660
PATH_VA = 0x1e03e0
PATH = b'/home/ubuntu/hl/code_Mainnet/node/src/consensus/config.rs'
WALLET_PANIC, MISMATCH_PANIC, PARSE_LOG, NODE_IPS_PANIC, HANDLE = 0x56c53d0, 0x56c5370, 0x56c5388, 0x56c53a0, 0x56c53b8
LOCATIONS = {WALLET_PANIC: (30, 17), MISMATCH_PANIC: (44, 25), PARSE_LOG: (51, 21), NODE_IPS_PANIC: (60, 13),
             HANDLE: (71, 32)}
# Location -> the `lea` that passes it
LOCATION_SITES = {WALLET_PANIC: 0x284b07d, MISMATCH_PANIC: 0x284abd8, PARSE_LOG: 0x284ac96, NODE_IPS_PANIC: 0x284b0da,
                  HANDLE: 0x284ae41}
PREFIX = (0x56c5360, 0x3f4813, b'CONFIGURATION ERROR')
TEMPLATES = {
    0x1dedcc: (2, [None, ': running with wallet that is not a validator, address=', None]),
    0x1ebedd: (3, [None, ': public_ip does not match abci state. public_ip=', None, ' abci_node_ip=', None]),
    0x1f41c9: (3, ['could not get public ip, not validating against abci state: ', None, ' @@ [public_ip: ', None,
                   '] @ [abci_node_ip: ', None, ']']),
    0x20210b: (2, [None, ': validator is not in node_ips: ', None]),
}
PANIC_FMT_SLOT = 0x576e098
LOG_SLOT = 0x576e978
MEMCMP_SLOT = 0x576e488
SLOTS = {
    0x57732e8: 0x33de620,   # called before the second set is built
    0x5773b48: 0x45c3d20,   # builds the third (node_ips) map
    0x576e948: 0x13ca370,   # returns the public IP String
    LOG_SLOT: 0x143d010,
    PANIC_FMT_SLOT: 0x157b810,
    0x5770708: 0x157d4b0,   # AddrParseError Display
    0x576f570: 0x1444400,   # wallet address formatter
    0x5775088: 0x4c7b1e0,   # node_ips address formatter
}
SECOND_SET = 0x3bb4f30
HANDLE_NEW = 0x258ad80
HANDLE_LABEL = (0x20a778, b'node_ips')
IPV4_PARSE = 0x1573af0
STR_DISPLAY = 0x21b7390
STRING_DISPLAY = 0x288bb90
VARIANTS = {1: (0x3f482d, b'LocalNode', 0x21b6940), 'other': (0x3f482b, b'Ip', 0x28e8b50)}
PARSE_ERROR = dict(fn=0x157d4b0, lens=0x25d7f8, ptrs=0x5674c48, kind=1, text=b'invalid IPv4 address syntax')
STATIC = dict(validate=0x8f2, options=0x8f8, root=0xa48, height=0xa50, length=0xa58)
WALLET = (0x80, 0x90)

WINDOWS = {
    'scan': (0x284a5a0, 0x284a5a0,
        '554157415641554154534881ec980d00004989d74889bc24f80000008b8290000000898424d0000000f30f6f82800000'
        '00660f7f8424c0000000488bbe480a00004885ff0f844f0a00004989f6488b86580a00004885c00f843c0a00004d8dae'
        'f80800004d8b86500a0000b10231f6eb1d6666666666662e0f1f840000000000bf0000000048ffc80f84140200004885'
        'f6741d440fb78eae0400004d39c80f83bc0000004989f14d89c2e9d5000000904d85c074384d89c14889fe4983e10774'
        '314531d26666662e0f1f840000000000488bb6b004000049ffc24d39d175f14c89c74c29d74983f8087315eb514889fe'
        'eb4c4c89c74983f80872430f1f440000488bb6b0040000488bb6b0040000488bb6b0040000488bb6b0040000488bb6b0'
        '040000488bb6b0040000488bb6b0040000488bb6b00400004883c7f875c231ff4531c0440fb78eae0400004d39c80f82'
        '50ffffff6666662e0f1f8400000000004c8b0e4d85c90f841b09000048ffc7440fb796ac0400004c89ce66453b91ae04'
        '000073dc4885ff0f84930000004f8d04d14981c0b80400004989fb4983e3070f84eb00000031db660f1f840000000000'
        '498b304c8d86b004000048ffc34939db75ee4989fb4929db4883ff0872436690498b30488bb6b0040000488bb6b00400'
        '00488bb6b0040000488bb6b0040000488bb6b0040000488bb6b0040000488bb6b00400004c8d86b00400004983c3f875'
        'bf4531c0eb11662e0f1f8400000000004d8d42014c89ce496bfa58f3410f6f443940660f6e8c24d000000066410f6e54'
        '3950660f748424c0000000660f74d1660fdbc266440fd7d04181faffff00000f851bfeffff4c01cf4883c7080fb64f4c'
        '8b574d448b4f4844894c2460f30f6f4738660f7f442450e9f4fdffff0f1f40004989fb4883ff080f8274ffffffe92eff'
        'ffff80f9020f84ee0700008b44246089442440660f6f442450660f7f442430884c240389542404'),
    'checks': (0x284a5a0, 0x284a867,
        '410fb6aef2080000400fb6fd897c2410ff156b8af202488b084885c9740cf30f6f4008b801000000eb06660fefc031c0'
        '488984240002000048c78424080200000000000048898c2410020000660fd6842418020000488984242002000048c784'
        '24280200000000000048898c2430020000f30f7f8424380200004c89ac2448020000488d7c2470488db42400020000e8'
        '35a636018b44246089842410020000660f6f442450660f7f842400020000488b4424704885c04c897c24204c89742418'
        '40886c24020f842f0100004c89ac24f00000004c8b7c24784c8dac2400020000488b1d3a3bf2024c89bc24e000000048'
        '898424e8000000488d700848894424280fb780e600000048894424088d0485000000004c8d348048c7c5ffffffff6666'
        '2e0f1f8400000000004d85f6743b4c8d6614ba140000004c89efffd348984885c00f98c10f9fc028c848ffc54983c6ec'
        '4c89e63c0174d20fb6c085c07510eb2a660f1f840000000000488b6c24084983ef010f82e0050000488b442428488b84'
        'e8e8000000e96dffffff31db4c8b742418488b84248000000048c784240802000000000000488b8c24e800000048898c'
        '2410020000488b9424e0000000488994241802000048c78424280200000000000048898c243002000048899424380200'
        '00b9010000004c8b7c24204c8bac24f00000000fb66c2402eb06b30131c931c048898c240002000048898c2420020000'
        '48898424400200004c8da42400020000660f1f840000000000488dbc24600100004c89e6e8c02702004883bc24600100'
        '000075e54084ed0f8416020000488dbc2400020000ff15863ef202488b8424280200004889842480000000f30f6f8424'
        '18020000660f7f442470488bb424000200004885f67410488bbc240802000031d2ff151235f202488b8c2480000000b0'
        '014883f90f0f87e0000000488b442478488984240002000048898c2408020000488dbc2400020000e8bc8fd2fe48b900'
        'ffffffff0000004821c14883bc2408020000000f94c248c1e90884c2b801000000480f45c10f849000000084db0f8449'
        '010000807c240300750a394424040f8438010000488d05dea7e7024889842400020000488d05ffc796ff488984240802'
        '0000488d4424704889842410020000488d05e30f04004889842418020000488d4424034889842420020000488d05970a'
        '00004889842428020000488d3d05139afd488d1591a7e702488db42400020000ff15ab34f202e9fd0400008884242001'
        '000048c784246001000000000000c784247001000000000000c684247401000000488d4424704889842440010000488d'
        '4424034889842400010000488d8424200100004889842400020000488b05bf5af2024889842408020000488d84244001'
        '00004889842410020000488d05c808e6ff4889842418020000488d8424000100004889842420020000488d05d9fae5ff'
        '4889842428020000488d3533959afd488d0deba6e702488dbc2460010000488d942400020000ff15c53cf202488b7424'
        '704885f6740d488b7c247831d2ff154633f202'),
    'node_ips': (0x284a5a0, 0x284acca,
        '8b44244089842411020000660f6f442430f30f7f842401020000c684240002000001488d7c2470488d8c24000200008b'
        '7424104c89eaff15428ef20284db0f84f70000008b44244089842410020000660f6f442430660f7f842400020000488b'
        '4424704885c00f845e030000488b4c247848894c24084c8da42400020000488b2d3937f202488d70080fb788e6000000'
        '48894424284c8da8e300000048894c24108d048d000000004c8d3c8049c7c6ffffffff0f1f004d85ff743b488d5e14ba'
        '140000004c89e7ffd548984885c00f98c10f9fc028c84983c50549ffc64983c7ec4889de3c0174ce0fb6c085c0750ceb'
        '300f1f4400004c8b742410488b4c24084883e901488b4424280f82bb02000048894c24084a8b84f020010000e964ffff'
        'ff41807d00024c8b7c24204c8b7424180fb66c24020f8494020000'),
    'handle': (0x284a5a0, 0x284ae13,
        '488dbc2460010000ba980000004c89feff15b731f20248c78424200100000000000048c784244001000000000000488d'
        '0570a5e7024c8d942440010000488d1521f99bfd488dbc24d0070000488d7424704c8d8c2420010000b9080000004531'
        'c0504152e804ffd3ff'),
    'panics': (0x284a5a0, 0x284afbf,
        'b301e92dfaffffbf08000000bed0050000ff154a30f202e914010000488d059efbf2024889842460010000488d842460'
        '0100004889842400020000488d3d97fbf202488d0d60efe1024c8d0541efe102488d942400020000be01000000ff1596'
        '38f202e9ecfdffff488d3d12a5e702ff153c34f202e9b6000000488d0520a3e7024889842400020000488d0541c396ff'
        '4889842408020000488d8424c00000004889842410020000488b050245f2024889842418020000488d3d4f3d99fd488d'
        '154ca3e702488db42400020000ff150630f202eb5b4c8b7c2420488d05c0a2e7024889842400020000488d05e1c296ff'
        '4889842408020000488d4424304889842410020000488b05bd9ff2024889842418020000488d3d31709bfd488d15bfa2'
        'e702488db42400020000ff15a92ff2020f0b'),
    'node_ip_debug': (0x284b660, 0x284b660,
        '55415741564154534883ec404889f3488d4701803f01756b48894424084c8b334c8b7b084d8b6718488d359e91bafdba'
        '090000004c89f741ffd440b50184c00f85ad010000f64312800f859f000000488d353e75a0fdba010000004c89f741ff'
        'd484c00f8589010000488d7c24084889dee86ab296ff84c00f845c010000e96f01000048894424084c8b334c8b7b084d'
        '8b6718488d353191bafdba020000004c89f741ffd440b50184c00f8542010000f64312800f859e000000488d35d374a0'
        'fdba010000004c89f741ffd484c00f851e010000488d7c24084889dee80fd4090084c00f84f1000000e904010000'),
    'str_display': (0x21b7390, 0x21b7390,
        '4889f0488b37488b57084889c7ff255d6c5b03'),
    'string_display': (0x288bb90, 0x288bb90,
        '4889f0488b7708488b57104889c7ff255c24ee02'),
    'addr_parse_error_display': (0x157d4b0, 0x157d4b0,
        '4889f00fb60fc1e103488d153803cefe488b1411488d357d770f04488b34314889c7ff25280b1f04'),
}

OPERANDS = {
    0x157d4b9: (7, 0x25d7f8),  # addr_parse_error_display: lea
    0x157d4c4: (7, 0x5674c48),  # addr_parse_error_display: lea
    0x157d4d2: (6, 0x576e000),  # addr_parse_error_display: jmp
    0x21b739d: (6, 0x576e000),  # str_display: jmp
    0x284a5e4: (6, 0x284b039),  # scan: je
    0x284a5f7: (6, 0x284b039),  # scan: je
    0x284a60f: (2, 0x284a62e),  # scan: jmp
    0x284a628: (6, 0x284a842),  # scan: je
    0x284a631: (2, 0x284a650),  # scan: je
    0x284a63e: (6, 0x284a700),  # scan: jae
    0x284a64a: (5, 0x284a724),  # scan: jmp
    0x284a653: (2, 0x284a68d),  # scan: je
    0x284a65f: (2, 0x284a692),  # scan: je
    0x284a67d: (2, 0x284a670),  # scan: jne
    0x284a689: (2, 0x284a6a0),  # scan: jae
    0x284a68b: (2, 0x284a6de),  # scan: jmp
    0x284a690: (2, 0x284a6de),  # scan: jmp
    0x284a699: (2, 0x284a6de),  # scan: jb
    0x284a6dc: (2, 0x284a6a0),  # scan: jne
    0x284a6ee: (6, 0x284a644),  # scan: jb
    0x284a706: (6, 0x284b027),  # scan: je
    0x284a722: (2, 0x284a700),  # scan: jae
    0x284a727: (6, 0x284a7c0),  # scan: je
    0x284a73f: (6, 0x284a830),  # scan: je
    0x284a760: (2, 0x284a750),  # scan: jne
    0x284a76c: (2, 0x284a7b1),  # scan: jb
    0x284a7af: (2, 0x284a770),  # scan: jne
    0x284a7b4: (2, 0x284a7c7),  # scan: jmp
    0x284a7ff: (6, 0x284a620),  # scan: jne
    0x284a827: (5, 0x284a620),  # scan: jmp
    0x284a837: (6, 0x284a7b1),  # scan: jb
    0x284a83d: (5, 0x284a770),  # scan: jmp
    0x284a845: (6, 0x284b039),  # scan: je
    0x284a877: (6, 0x57732e8),  # checks: call
    0x284a883: (2, 0x284a891),  # checks: je
    0x284a88f: (2, 0x284a897),  # checks: jmp
    0x284a8f6: (5, 0x3bb4f30),  # checks: call
    0x284a92c: (6, 0x284aa61),  # checks: je
    0x284a947: (7, 0x576e488),  # checks: mov
    0x284a993: (2, 0x284a9d0),  # checks: je
    0x284a9bc: (2, 0x284a990),  # checks: je
    0x284a9c3: (2, 0x284a9d5),  # checks: jne
    0x284a9c5: (2, 0x284a9f1),  # checks: jmp
    0x284a9d9: (6, 0x284afbf),  # checks: jb
    0x284a9ec: (5, 0x284a95e),  # checks: jmp
    0x284aa5f: (2, 0x284aa67),  # checks: jmp
    0x284aa9b: (5, 0x286d260),  # checks: call
    0x284aaa9: (2, 0x284aa90),  # checks: jne
    0x284aaae: (6, 0x284acca),  # checks: je
    0x284aabc: (6, 0x576e948),  # checks: call
    0x284aaec: (2, 0x284aafe),  # checks: je
    0x284aaf8: (6, 0x576e010),  # checks: call
    0x284ab0c: (6, 0x284abf2),  # checks: ja
    0x284ab2f: (5, 0x1573af0),  # checks: call
    0x284ab5c: (6, 0x284abf2),  # checks: je
    0x284ab64: (6, 0x284acb3),  # checks: je
    0x284ab6f: (2, 0x284ab7b),  # checks: jne
    0x284ab75: (6, 0x284acb3),  # checks: je
    0x284ab7b: (7, 0x56c5360),  # checks: lea
    0x284ab8a: (7, 0x21b7390),  # checks: lea
    0x284aba6: (7, 0x288bb90),  # checks: lea
    0x284abc2: (7, 0x284b660),  # checks: lea
    0x284abd1: (7, 0x1ebedd),  # checks: lea
    0x284abd8: (7, 0x56c5370),  # checks: lea
    0x284abe7: (6, 0x576e098),  # checks: call
    0x284abed: (5, 0x284b0ef),  # checks: jmp
    0x284ac42: (7, 0x5770708),  # checks: mov
    0x284ac61: (7, 0x26ab530),  # checks: lea
    0x284ac80: (7, 0x26aa760),  # checks: lea
    0x284ac8f: (7, 0x1f41c9),  # checks: lea
    0x284ac96: (7, 0x56c5388),  # checks: lea
    0x284acad: (6, 0x576e978),  # checks: call
    0x284acbb: (2, 0x284acca),  # checks: je
    0x284acc4: (6, 0x576e010),  # checks: call
    0x284ad00: (6, 0x5773b48),  # node_ips: call
    0x284ad08: (6, 0x284ae05),  # node_ips: je
    0x284ad30: (6, 0x284b094),  # node_ips: je
    0x284ad48: (7, 0x576e488),  # node_ips: mov
    0x284ad83: (2, 0x284adc0),  # node_ips: je
    0x284adb0: (2, 0x284ad80),  # node_ips: je
    0x284adb7: (2, 0x284adc5),  # node_ips: jne
    0x284adb9: (2, 0x284adeb),  # node_ips: jmp
    0x284add3: (6, 0x284b094),  # node_ips: jb
    0x284ade6: (5, 0x284ad4f),  # node_ips: jmp
    0x284adff: (6, 0x284b099),  # node_ips: je
    0x284ae23: (6, 0x576dfe0),  # handle: call
    0x284ae41: (7, 0x56c53b8),  # handle: lea
    0x284ae50: (7, 0x20a778),  # handle: lea
    0x284ae77: (5, 0x258ad80),  # handle: call
    0x284afc1: (5, 0x284a9f3),  # panics: jmp
    0x284afd0: (6, 0x576e020),  # panics: call
    0x284afd6: (5, 0x284b0ef),  # panics: jmp
    0x284afdb: (7, 0x577ab80),  # panics: lea
    0x284affa: (7, 0x577ab98),  # panics: lea
    0x284b001: (7, 0x5669f68),  # panics: lea
    0x284b008: (7, 0x5669f50),  # panics: lea
    0x284b01c: (6, 0x576e8b8),  # panics: call
    0x284b022: (5, 0x284ae13),  # panics: jmp
    0x284b027: (7, 0x56c5540),  # panics: lea
    0x284b02e: (6, 0x576e470),  # panics: call
    0x284b034: (5, 0x284b0ef),  # panics: jmp
    0x284b039: (7, 0x56c5360),  # panics: lea
    0x284b048: (7, 0x21b7390),  # panics: lea
    0x284b067: (7, 0x576f570),  # panics: mov
    0x284b076: (7, 0x1dedcc),  # panics: lea
    0x284b07d: (7, 0x56c53d0),  # panics: lea
    0x284b08c: (6, 0x576e098),  # panics: call
    0x284b092: (2, 0x284b0ef),  # panics: jmp
    0x284b099: (7, 0x56c5360),  # panics: lea
    0x284b0a8: (7, 0x21b7390),  # panics: lea
    0x284b0c4: (7, 0x5775088),  # panics: mov
    0x284b0d3: (7, 0x20210b),  # panics: lea
    0x284b0da: (7, 0x56c53a0),  # panics: lea
    0x284b0e9: (6, 0x576e098),  # panics: call
    0x284b676: (2, 0x284b6e3),  # node_ip_debug: jne
    0x284b688: (7, 0x3f482d),  # node_ip_debug: lea
    0x284b69f: (6, 0x284b852),  # node_ip_debug: jne
    0x284b6a9: (6, 0x284b74e),  # node_ip_debug: jne
    0x284b6af: (7, 0x252bf4),  # node_ip_debug: lea
    0x284b6c3: (6, 0x284b852),  # node_ip_debug: jne
    0x284b6d1: (5, 0x21b6940),  # node_ip_debug: call
    0x284b6d8: (6, 0x284b83a),  # node_ip_debug: je
    0x284b6de: (5, 0x284b852),  # node_ip_debug: jmp
    0x284b6f3: (7, 0x3f482b),  # node_ip_debug: lea
    0x284b70a: (6, 0x284b852),  # node_ip_debug: jne
    0x284b714: (6, 0x284b7b8),  # node_ip_debug: jne
    0x284b71a: (7, 0x252bf4),  # node_ip_debug: lea
    0x284b72e: (6, 0x284b852),  # node_ip_debug: jne
    0x284b73c: (5, 0x28e8b50),  # node_ip_debug: call
    0x284b743: (6, 0x284b83a),  # node_ip_debug: je
    0x284b749: (5, 0x284b852),  # node_ip_debug: jmp
    0x288bb9e: (6, 0x576e000),  # string_display: jmp
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
        dynsym = next((s for s in self.secs if s['name'] == '.dynsym'), None)
        dynstr = next((s for s in self.secs if s['name'] == '.dynstr'), None)
        require(dynsym is not None and dynstr is not None, 'no .dynsym/.dynstr')
        self.relative, self.glob_dat = {}, {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
            elif info & 0xffffffff == 6:
                name = dynstr['offset'] + struct.unpack_from('<I', data, dynsym['offset'] + 24 * (info >> 32))[0]
                self.glob_dat[where] = data[name:data.index(b'\0', name)].decode()
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
    """An instruction `prefix` + rel32/disp32 (or rel8 for a 1-byte prefix) at `va` whose target must be `target`."""
    raw = bytes.fromhex(prefix)
    n = 2 if len(raw) == 1 and raw[0] in range(0x70, 0x80) or raw == b'\xeb' else len(raw) + 4
    require(windowed(va, n), f'instruction at {va:#x} is outside every window')
    require(img.read(va, len(raw)) == raw, f'instruction at {va:#x} is not {prefix}')
    require(OPERANDS.get(va) == (n, target), f'operand table at {va:#x} does not pin {target:#x}')
    got = img.target(va, n)
    require(got == target, f'operand at {va:#x} goes to {got:#x}, not {target:#x}')


def exact(img, va, hexs):
    raw = bytes.fromhex(hexs)
    require(windowed(va, len(raw)), f'instruction at {va:#x} is outside every window')
    require(img.read(va, len(raw)) == raw, f'instruction at {va:#x} is not {hexs}')


def text_at(img, va, n):
    s = img.read(va, n)
    require(all(0x20 <= c < 0x7f for c in s), f'{va:#x} is not text')
    return s


def location(img, va):
    ptr = img.relative.get(va)
    require(ptr is not None, f'Location {va:#x} has no RELATIVE file pointer')
    n, line, col = struct.unpack('<QII', img.read(va + 8, 16))
    require(0 < n < 256, f'Location {va:#x} has length {n}')
    return text_at(img, ptr, n), line, col


def template(img, va, args):
    """Decode a rustc packed format template with `args` placeholders: literal-length bytes and 0xc0 placeholders.

    The templates run straight into the next one, so the end is the literal after the last placeholder.
    """
    pieces, pos = [], va
    for _ in range(64):
        b = img.read(pos, 1)[0]
        if b == 0xc0:
            pieces.append(None)
            n = img.read(pos + 1, 1)[0]
            pos += 2
        elif b == 0:
            break
        elif b < 0x80:
            n = b
            pos += 1
        else:
            raise EvidenceError(f'template {va:#x}: unexpected byte {b:#x} at {pos:#x}')
        if n:
            pieces.append(text_at(img, pos, n).decode())
            pos += n
        if pieces.count(None) == args:
            break
    require(pieces.count(None) == args, f'template {va:#x} has {pieces.count(None)} placeholders, not {args}')
    return pieces


def check_strings(img):
    require(img.data.count(PATH[PATH.index(b'/node/src/'):]) == 1, 'config.rs path is not unique in the file')
    require(img.read(PATH_VA, len(PATH)) == PATH, f'path string at {PATH_VA:#x} changed')
    found = {}
    for slot, addend in img.relative.items():
        if addend == PATH_VA:
            path, line, col = location(img, slot)
            require(path == PATH, f'Location {slot:#x} has a different length or path')
            found[slot] = (line, col)
    require(found == LOCATIONS, f'config.rs Locations are {sorted((hex(k), v) for k, v in found.items())}')
    slot, va, text = PREFIX
    require(img.relative.get(slot) == va, f'prefix str {slot:#x} no longer points at {va:#x}')
    require(struct.unpack('<Q', img.read(slot + 8, 8))[0] == len(text), 'prefix str length changed')
    require(img.read(va, len(text)) == text, 'prefix text changed')
    for va, (args, want) in TEMPLATES.items():
        got = template(img, va, args)
        require(got == want, f'template {va:#x} is {got}')
    for slot, want in SLOTS.items():
        require(img.relative.get(slot) == want, f'slot {slot:#x} no longer holds {want:#x}')
    require(img.glob_dat.get(MEMCMP_SLOT) == 'memcmp', f'{MEMCMP_SLOT:#x} is not the memcmp GLOB_DAT slot')
    for _, (va, name, _) in VARIANTS.items():
        require(img.read(va, len(name)) == name, f'variant name at {va:#x} changed')
    p = PARSE_ERROR
    n = struct.unpack('<Q', img.read(p['lens'] + 8 * p['kind'], 8))[0]
    ptr = img.relative.get(p['ptrs'] + 8 * p['kind'])
    require(ptr is not None and img.read(ptr, n) == p['text'], 'AddrParseError(Ipv4) text changed')
    return dict(path=PATH.decode(), prefix=text.decode(),
                locations={hex(k): f'{v[0]}:{v[1]}' for k, v in sorted(LOCATIONS.items())},
                templates={hex(k): ''.join('{}' if x is None else x for x in v[1]) for k, v in TEMPLATES.items()})


def census(img):
    """Every RIP-relative disp32 in .text that resolves to a config.rs Location, and every RELATIVE slot holding one."""
    t = img.text
    raw = img.read(t['address'], t['size'])
    base = t['address']
    refs = {}
    for m in re.finditer(rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', raw):
        p = m.start() + 1
        if p + 4 > len(raw) or p < 3:
            continue
        tgt = base + p + 4 + struct.unpack_from('<i', raw, p)[0]
        if tgt in LOCATIONS:
            start = p - 3
            require(raw[start] in (0x48, 0x4c) and raw[start + 1] == 0x8d,
                    f'reference to Location {tgt:#x} at {base + p:#x} is not a REX.W lea')
            refs[base + start] = tgt
    held = sorted(hex(s) for s, a in img.relative.items() if a in LOCATIONS)
    require(not held, f'RELATIVE slots {held} hold a config.rs Location')
    want = {site: loc for loc, site in LOCATION_SITES.items()}
    require(refs == want, f'config.rs Location references are {sorted((hex(k), hex(v)) for k, v in refs.items())}')
    return {hex(k): f'{LOCATIONS[v][0]}:{LOCATIONS[v][1]}' for k, v in sorted(refs.items())}


def disp(off):
    return struct.pack('<I', off).hex()


def check_scan(img):
    """30:17: walk every item of the tree at static+0xa48; last match wins; no match panics."""
    exact(img, 0x284a5b1, '4989d7')                                  # r15 = signer
    exact(img, 0x284a5bc, '8b82' + disp(WALLET[1]))                  # wallet bytes 16..20
    exact(img, 0x284a5c9, 'f30f6f82' + disp(WALLET[0]))              # wallet bytes 0..16
    exact(img, 0x284a5da, '488bbe' + disp(STATIC['root']))
    op(img, 0x284a5e4, '0f84', 0x284b039)                            # no root -> wallet panic
    exact(img, 0x284a5ea, '4989f6')                                  # r14 = static
    exact(img, 0x284a5ed, '488b86' + disp(STATIC['length']))
    op(img, 0x284a5f7, '0f84', 0x284b039)                            # no items -> wallet panic
    exact(img, 0x284a5fd, '4d8dae' + disp(STATIC['options']))        # r13 = static+0x8f8
    exact(img, 0x284a604, '4d8b86' + disp(STATIC['height']))
    exact(img, 0x284a60b, 'b102')                                    # tag = 2: nothing matched yet
    exact(img, 0x284a625, '48ffc8')                                  # one item consumed
    op(img, 0x284a628, '0f84', 0x284a842)                            # all `length` items seen
    exact(img, 0x284a7c7, '496bfa58')                                # item index * 0x58
    exact(img, 0x284a7cb, 'f3410f6f443940')                          # item bytes +0x38..+0x48 (node+8)
    exact(img, 0x284a7db, '66410f6e543950')                          # item bytes +0x48..+0x4c
    exact(img, 0x284a7f8, '4181faffff0000')                          # all 20 bytes equal
    op(img, 0x284a7ff, '0f85', 0x284a620)                            # differ -> next item
    exact(img, 0x284a80c, '0fb64f4c')                                # tag = item+0x4c
    exact(img, 0x284a810, '8b574d')                                  # u32 = item+0x4d
    op(img, 0x284a827, 'e9', 0x284a620)                              # match -> keep walking
    exact(img, 0x284a842, '80f902')
    op(img, 0x284a845, '0f84', 0x284b039)                            # still 2 -> wallet panic
    exact(img, 0x284a85f, '884c2403')                                # [rsp+3] = tag
    exact(img, 0x284a863, '89542404')                                # [rsp+4] = u32
    return dict(tree=f'static+{STATIC["root"]:#x} (height +{STATIC["height"]:#x}, length +{STATIC["length"]:#x})',
                wallet=f'signer+{WALLET[0]:#x}..+{WALLET[1] + 4:#x}', item_size=0x58,
                compared='item+0x38..+0x4c', kept='tag item+0x4c, u32 item+0x4d', walk='every item; last match wins',
                no_match='panic config.rs:30:17')


def check_second_set(img):
    """The validate byte, the second set (bl=0 when the wallet is in it, 1 otherwise)."""
    exact(img, 0x284a867, '410fb6ae' + disp(STATIC['validate']))     # ebp = validate byte
    exact(img, 0x284a873, '897c2410')                                # [rsp+0x10] = validate
    op(img, 0x284a877, 'ff15', 0x57732e8)
    exact(img, 0x284a8e1, '4c89ac2448020000')                        # static+0x8f8 into the argument
    op(img, 0x284a8f6, 'e8', SECOND_SET)
    op(img, 0x284a92c, '0f84', 0x284aa61)                            # empty set
    exact(img, 0x284aa61, 'b301')                                    # -> bl = 1
    op(img, 0x284a947, '488b1d', MEMCMP_SLOT)
    exact(img, 0x284a999, 'ba14000000')                              # memcmp 20 bytes
    op(img, 0x284a9c5, 'eb', 0x284a9f1)                              # equal
    exact(img, 0x284a9f1, '31db')                                    # -> bl = 0
    op(img, 0x284a9d9, '0f82', 0x284afbf)                            # below a leaf
    exact(img, 0x284afbf, 'b301')                                    # -> bl = 1
    op(img, 0x284afc1, 'e9', 0x284a9f3)
    return dict(validate=f'static+{STATIC["validate"]:#x}', builder=hex(SECOND_SET), key_bytes=20,
                in_set='bl = 0', not_in_set_or_empty='bl = 1')


def check_public_ip(img):
    """44:25 / 51:21: only when the validate byte is set."""
    exact(img, 0x284aaab, '4084ed')
    op(img, 0x284aaae, '0f84', 0x284acca)                            # validate == 0 -> skip the IP step
    op(img, 0x284aabc, 'ff15', 0x576e948)                            # String
    exact(img, 0x284ab06, 'b001')                                    # al = AddrKind::Ipv4
    exact(img, 0x284ab08, '4883f90f')
    op(img, 0x284ab0c, '0f87', 0x284abf2)                            # len > 15 -> log
    op(img, 0x284ab2f, 'e8', IPV4_PARSE)
    exact(img, 0x284ab41, '4883bc240802000000')                      # input fully consumed
    exact(img, 0x284ab51, '84c2')
    op(img, 0x284ab5c, '0f84', 0x284abf2)                            # parse failed -> log
    exact(img, 0x284ab62, '84db')
    op(img, 0x284ab64, '0f84', 0x284acb3)                            # in the second set -> no compare
    exact(img, 0x284ab6a, '807c240300')
    op(img, 0x284ab6f, '75', 0x284ab7b)                              # tag != 0 -> mismatch panic
    exact(img, 0x284ab71, '39442404')
    op(img, 0x284ab75, '0f84', 0x284acb3)                            # u32 equal -> ok
    # mismatch panic: prefix, public IP String, node IP Debug
    op(img, 0x284ab7b, '488d05', PREFIX[0])
    op(img, 0x284ab8a, '488d05', STR_DISPLAY)
    exact(img, 0x284ab99, '488d442470')
    op(img, 0x284aba6, '488d05', STRING_DISPLAY)
    exact(img, 0x284abb5, '488d442403')
    op(img, 0x284abc2, '488d05', NODE_IP_DEBUG)
    op(img, 0x284abd1, '488d3d', 0x1ebedd)
    op(img, 0x284abd8, '488d15', MISMATCH_PANIC)
    op(img, 0x284abe7, 'ff15', PANIC_FMT_SLOT)
    # parse-error log, then on to 0x284acb3
    exact(img, 0x284abf2, '88842420010000')
    op(img, 0x284ac42, '488b05', 0x5770708)
    op(img, 0x284ac8f, '488d35', 0x1f41c9)
    op(img, 0x284ac96, '488d0d', PARSE_LOG)
    op(img, 0x284acad, 'ff15', LOG_SLOT)
    require(0x284acad + 6 == 0x284acb3, 'log call does not fall through to 0x284acb3')
    exact(img, 0x284acb3, '488b742470')
    # str / String Display and AddrParseError Display
    exact(img, STR_DISPLAY, '4889f0488b37488b57084889c7')
    op(img, STR_DISPLAY + 13, 'ff25', 0x576e000)
    exact(img, STRING_DISPLAY, '4889f0488b7708488b57104889c7')
    op(img, STRING_DISPLAY + 14, 'ff25', 0x576e000)
    p = PARSE_ERROR
    exact(img, p['fn'] + 3, '0fb60fc1e103')
    op(img, p['fn'] + 9, '488d15', p['lens'])
    op(img, p['fn'] + 20, '488d35', p['ptrs'])
    return dict(fetch=hex(SLOTS[0x576e948]), parse=f'{IPV4_PARSE:#x} after len <= 15, whole input consumed',
                parse_error=p['text'].decode(), parse_error_path='log config.rs:51:21, continue',
                compare='skipped when in the second set; tag 0 and equal u32 required',
                mismatch='panic config.rs:44:25 (public_ip as the fetched String, abci_node_ip via 0x284b660)')


def check_node_ips(img):
    """60:13: unless in the second set, the wallet must be in the third map with a value tag other than 2."""
    exact(img, 0x284ace4, 'c684240002000001')
    exact(img, 0x284acf9, '8b742410')                                # esi = validate
    exact(img, 0x284acfd, '4c89ea')                                  # rdx = static+0x8f8
    op(img, 0x284ad00, 'ff15', 0x5773b48)
    exact(img, 0x284ad06, '84db')
    op(img, 0x284ad08, '0f84', 0x284ae05)                            # in the second set -> skip
    op(img, 0x284ad30, '0f84', 0x284b094)                            # empty map -> panic
    op(img, 0x284ad48, '488b2d', MEMCMP_SLOT)
    exact(img, 0x284ad5f, '4c8da8e3000000')                          # value cursor node+0xe3
    exact(img, 0x284ad89, 'ba14000000')
    exact(img, 0x284ada0, '4983c505')                                # +5 per key
    op(img, 0x284adb9, 'eb', 0x284adeb)                              # equal
    op(img, 0x284add3, '0f82', 0x284b094)                            # below a leaf -> panic
    exact(img, 0x284adeb, '41807d0002')
    op(img, 0x284adff, '0f84', 0x284b099)                            # value tag 2 -> panic
    return dict(builder=hex(SLOTS[0x5773b48]), args='(out, validate, static+0x8f8, &(1, wallet))',
                value='5 bytes (tag, u32) at node+0xe8+5i', missing_or_tag_2='panic config.rs:60:13')


def check_handle(img):
    """71:32: pushed as the last argument of 0x258ad80, next to the third map and the str "node_ips"."""
    op(img, 0x284ae41, '488d05', HANDLE)
    op(img, 0x284ae50, '488d15', HANDLE_LABEL[0])
    exact(img, 0x284ae5f, '488d742470')                              # rsi = the third map
    exact(img, 0x284ae6c, 'b9' + struct.pack('<I', len(HANDLE_LABEL[1])).hex())
    exact(img, 0x284ae74, '50')                                      # push rax = Location
    op(img, 0x284ae77, 'e8', HANDLE_NEW)
    require(img.read(HANDLE_LABEL[0], len(HANDLE_LABEL[1])) == HANDLE_LABEL[1], 'node_ips label changed')
    return dict(callee=hex(HANDLE_NEW), label=HANDLE_LABEL[1].decode(), location='71:32', map='rsp+0x70')


def check_panics(img):
    out = {}
    for name, lea, fmt, arg, slot, tmpl, loc, call in (
            ('wallet', 0x284b039, 0x284b067, '488d8424c0000000', 0x576f570, 0x1dedcc, WALLET_PANIC, 0x284b08c),
            ('node_ips', 0x284b099, 0x284b0c4, '488d442430', 0x5775088, 0x20210b, NODE_IPS_PANIC, 0x284b0e9)):
        op(img, lea, '488d05', PREFIX[0])
        op(img, lea + 15, '488d05', STR_DISPLAY)
        exact(img, lea + 30, arg)
        op(img, fmt, '488b05', slot)
        op(img, fmt + 15, '488d3d', tmpl)
        op(img, fmt + 22, '488d15', loc)
        op(img, call, 'ff15', PANIC_FMT_SLOT)
        out[name] = dict(template=hex(tmpl), location=f'{LOCATIONS[loc][0]}:{LOCATIONS[loc][1]}',
                         address_formatter=hex(SLOTS[slot]))
    exact(img, 0x284b0ef, '0f0b')
    return out


def check_node_ip_debug(img):
    exact(img, 0x284b66f, '488d4701')                                # field at +1
    exact(img, 0x284b673, '803f01')
    op(img, 0x284b676, '75', 0x284b6e3)                              # tag != 1 -> "Ip"
    out = {}
    for key, lea, ln, call in ((1, 0x284b688, 0x284b68f, 0x284b6d1), ('other', 0x284b6f3, 0x284b6fa, 0x284b73c)):
        va, name, field = VARIANTS[key]
        op(img, lea, '488d35', va)
        exact(img, ln, 'ba' + struct.pack('<I', len(name)).hex())
        op(img, call, 'e8', field)
        out[str(key)] = dict(name=name.decode(), field_formatter=hex(field))
    return out


# ---- models -------------------------------------------------------------------------------------------------


class Panic(Exception):
    pass


def node_ip_debug(tag, value):
    return f'LocalNode({value})' if tag == 1 else f'Ip({value})'


def parse_ipv4(text):
    """std `Ipv4Addr::parse_ascii`: over 15 bytes is an error before parsing."""
    if len(text) > 15:
        return None
    try:
        return ipaddress.IPv4Address(text) if text.count('.') == 3 and all(p.isdigit() for p in text.split('.')) else None
    except ValueError:
        return None


def build(items, wallet, second_set, validate, public_ip, node_ips):
    """The binary's 0x284a5a0 checks.  items: [(address, tag, u32)]; node_ips: {address: (tag, u32)}."""
    found = None
    for address, tag, value in items:
        if address == wallet:
            found = (tag, value)
    if found is None:
        raise Panic(f'CONFIGURATION ERROR: running with wallet that is not a validator, address={wallet} @ 30:17')
    exempt = wallet in second_set
    log = None
    if validate:
        ip = parse_ipv4(public_ip)
        if ip is None:
            log = (f'could not get public ip, not validating against abci state: invalid IPv4 address syntax '
                   f'@@ [public_ip: {public_ip}] @ [abci_node_ip: {node_ip_debug(*found)}]] @ 51:21')
        elif not exempt and not (found[0] == 0 and found[1] == ip):
            raise Panic(f'CONFIGURATION ERROR: public_ip does not match abci state. public_ip={public_ip} '
                        f'abci_node_ip={node_ip_debug(*found)} @ 44:25')
    if not exempt:
        value = node_ips.get(wallet)
        if value is None or value[0] == 2:
            raise Panic(f'CONFIGURATION ERROR: validator is not in node_ips: {wallet} @ 60:13')
    return dict(node_ip=found, log=log)


def lead_build(items, wallet, validate, public_ip):
    """The lead: `node_ips.get(wallet)` or "validator is not in node_ips"; Ip = 0, Error = 1, LocalNode = 2."""
    table = {a: (t, v) for a, t, v in items}
    if wallet not in table:
        raise Panic(f'validator is not in node_ips: {wallet}')
    tag, value = table[wallet]
    ip = parse_ipv4(public_ip)
    if ip is not None and validate and not (tag == 0 and value == ip):
        name = {0: 'Ip', 1: 'Error', 2: 'LocalNode'}.get(tag, 'Unknown')
        raise Panic(f'public_ip does not match abci state. public_ip={ip} abci_node_ip={name}({value})')
    return dict(node_ip=(tag, value))


def analyse(data):
    img = Image(data)
    wins = windows(img)
    ops = check_operands(img)
    strings = check_strings(img)
    refs = census(img)
    return dict(
        target=TARGET,
        fde=dict(build=[hex(x) for x in img.fde(BUILD)], node_ip_debug=[hex(x) for x in img.fde(NODE_IP_DEBUG)]),
        strings=strings,
        census=dict(scanned='.text, every disp32 after a RIP-relative ModRM byte; RELATIVE slots', references=refs),
        wallet_scan=check_scan(img),
        second_set=check_second_set(img),
        public_ip=check_public_ip(img),
        node_ips=check_node_ips(img),
        handle=check_handle(img),
        panics=check_panics(img),
        node_ip_debug=check_node_ip_debug(img),
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
    print(f'{BUILD:#x}: config.rs Locations {", ".join(rec["census"]["references"].values())}')
    print('30:17 wallet not in the static+0xa48 walk; 44:25 / 51:21 public IP (only when static+0x8f2 is set); '
          '60:13 wallet not in node_ips (both skipped when in the second set)')
    print('node IP Debug: tag 1 = LocalNode, other = Ip')
    return 0


if __name__ == '__main__':
    sys.exit(main())
