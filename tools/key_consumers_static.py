"""Static evidence for the RE-005 key-consumers packet.

Answers, for the authenticated hl-node 115 artifact only:

1.  The 0x98-byte rebuild record of RE-005-node115-config-fetch
    carries its "key" field as length / pointer / length at
    +0x78 / +0x80 / +0x88 and the "chain" tag byte inside the
    qword at +0x90 (Local 0, Sandbox 1, Testnet 2, Mainnet 3).
    The shaper bodies lvl4_a (0x2ae41e0) and lvl3_c (0x2cde430)
    place the record at phase +0x10, spread record +0x78..+0x90
    over phase +0xa8..+0xc0, copy the tag byte to phase +0x1e8,
    and pass an embedded record at phase +0x220 to a gate body.
    Which phase offsets does each shaper actually read again,
    and which does it never touch?
2.  The gate bodies gate_c (0x2cb6500) and gate_a (0x2aeaef0)
    are the record's main downstream consumer.  What do they
    read at the embedded record's key slots +0x78 / +0x80 /
    +0x88 / +0x90, where did the values they consume come
    from, and what decides their arms after the key check?
3.  The key-lookup callee behind GOT slot 0x64e0b38
    (0x150ad00) receives (tag, key pointer, key length) from
    four call sites.  What does it do with the triple: copy,
    comparison, pass-on?  What does its helper 0x14c2b50
    return, and who consumes that result?
4.  Is the chain tag ever compared anywhere downstream, and
    are the key bytes ever compared in any traced body?

Method: every load, store, lea and other-destination bracket
access through the record register (rbx in the gates and in
lvl4_a, r13 in lvl3_c) at the offsets of interest is censused
from instruction-aligned objdump text; the gate key path and
the embedded-record byte stores are byte-pinned; the lookup
callee's tag jump table is read through the section table;
every string is re-read through the section table on each
run; the per-chain reference slots of the lookup callee's
global (0x64f0210, reached through GOT slot 0x64e0b40) are
read from the artifact's .data section.  Bodies over ~4 KB
are hash- and pin-pinned only; the lookup callee (1,541 B)
and its helper (247 B) are exported in full.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7a8278'
                 'fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-key-consumers'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

OWNERS = {
    'builder_c': ('0x2b7b640', '0x2b7b79c',
                  '1ce5b5a8e849cc065b72f30af834a79f75454bd412d8'
                  'c67df9137859bbcc8003'),
    'lookup_d': ('0x564cce0', '0x564cf36',
                 'e69561afd60a4ae323867f1eb25f2a6997c85c488524e'
                 '15bf0ca9f9fed100e92'),
    'lvl4_a': ('0x2ae41e0', '0x2ae6d66',
               '90ae09003ca680bd4b5f32fec22ee1f7146cc1f67b758'
               'f8e2f2ac880545b730b'),
    'lvl3_c': ('0x2cde430', '0x2ce0dd1',
               '99c49a3e20f63cf199f2a160ba9560e439acb2b49a669'
               '68623aa9607acfa417b'),
    'gate_c': ('0x2cb6500', '0x2cbbbdf',
               '62835f8a447ea034c30a4fa0663abad74226444817882'
               'c469f883d7d92e4a8d0'),
    'gate_a': ('0x2aeaef0', '0x2af0654',
               'd1b4e3ecb40fb4027b69240f48eacf2de2cf5f7e8c3ae'
               '5c0e6910a784fdcce29'),
    'key_lookup': ('0x150ad00', '0x150b305',
                   'c01b4b7405fad32a62db8e4df88040ad03075d91fee1'
                   'edcb44f8c4b61a581cc7'),
    'cmp_helper': ('0x14c2b50', '0x14c2c47',
                   '074affff6e4b9cdde4a45cde23119c255abf8f58d91f'
                   'ed46e8362100e5af0efc'),
}
EXPORTED = ('builder_c', 'lookup_d', 'key_lookup', 'cmp_helper')

FRAMES = {'builder_c': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                       'va': '0x103d604'},
               'fde': {'bytes_hex': '3c000000d08a140068559f015c0100000437410eff420e10420e18410e20470e900a83048e038f020321010e20410e18420e10420e08410e900a000000000000',
                       'va': '0x11860d0'}},
 'cmp_helper': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                        'va': '0x103d604'},
                'fde': {'bytes_hex': '38000000e096000068be4700f7000000045fbe12ff420e10420e18410e20440e800183048e038f0202c80e20410e18420e10420e08410e8001000000',
                        'va': '0x1046ce0'}},
 'gate_a': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                    'va': '0x103d604'},
            'fde': {'bytes_hex': '6400000098ef130050e996016457000004d72b0eff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0ee08d0183078c068d058e048f0386020307530e38410e30420e28420e20420e18420e10410e08410ee08d01000000',
                    'va': '0x117c598'}},
 'gate_c': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                    'va': '0x103d604'},
            'fde': {'bytes_hex': '64000000dc9215001cfcb101df56000004a3ed0dff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0ee08d0183078c068d058e048f0386020391520e38410e30420e28420e20420e18420e10410e08410ee08d01000000',
                    'va': '0x11968dc'}},
 'key_lookup': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                        'va': '0x103d604'},
                'fde': {'bytes_hex': '480000002ce30000ccf34b0005060000042fa812ff420e10420e18420e20420e28410e30470e900283068c058d048e038f020300050e30410e28420e20420e18420e10420e08410e90020000',
                        'va': '0x104b92c'}},
 'lookup_d': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                      'va': '0x103d604'},
              'fde': {'bytes_hex': '50000000e0a03200f8552e045602000004533605ff410e10420e18420e20420e28420e30410e38470ed00183078c068d058e048f03860203e7010e38410e30420e28420e20420e18420e10410e08410ed0010000',
                      'va': '0x13676e0'}},
 'lvl3_c': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                    'va': '0x103d604'},
            'fde': {'bytes_hex': '50000000acb015007c5db401a12900000493f70dff410e10420e18420e20420e28420e30410e38470ee00983078c068d058e048f03860203f11a0e38410e30420e28420e20420e18420e10410e08410ee0090000',
                    'va': '0x11986ac'}},
 'lvl4_a': {'cie': {'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
                    'va': '0x103d604'},
            'fde': {'bytes_hex': '500000009cee13003c7d9601862b00000417260eff410e10420e18420e20420e28420e30410e38470ee01f83078c068d058e048f03860203791c0e38410e30420e28420e20420e18420e10410e08410ee01f0000',
                    'va': '0x117c49c'}}}

# GOT slot 0x64e0b38 is the key-lookup slot: exactly four
# rip-relative call sites exist binary-wide, one per traced
# caller body.
KEY_SLOT = 0x64E0B38
KEY_CALLEE = 0x150AD00
KEY_SLOT_SITES = ['0x2ae4580', '0x2aeb2f7', '0x2cb6907',
                  '0x2cde645']

# The two gate bodies have exactly two direct callers each,
# all inside their own shaper; no .rela.dyn addend names
# either gate.
GATE_CALLERS = {
    'gate_c': ['0x2cde6f4', '0x2cdf58b'],
    'gate_a': ['0x2ae4627', '0x2ae548c'],
}

SLOT_TABLE = {
    'key_slot': (0x64E0B38, 8, 0x150AD00),
    'key_global_slot': (0x64E0B40, 8, 0x64F0210),
    'key_state_slot': (0x64E0B48, 8, 0x1562670),
    'config_slot': (0x64E0A80, 8, 0x1506840),
    'crit_call_slot': (0x64E0EB0, 8, 0x1534810),
    'helper_state_slot': (0x64DFFE0, 8, 0x154CD10),
}
DYN_SLOTS = {
    'alloc_slot': (0x64DF480, 8, 104159280),
    'log_slot': (0x64DF4B8, 8, 97106176),
    'dealloc_slot': (0x64DF4A0, 8, 104193584),
}
COPY_SLOT = 0x64DF508

# Byte pins on the gate key path.  The two gates carry the
# same instruction bytes at every pinned site (clone check).
GATE_KEY_PINS = {
    'gate_c': [
        (0x2CB6780, '440fb67b72',
         'path 1: movzx r15d, byte [rbx+0x72] (tag byte)'),
        (0x2CB6798, '48899388000000',
         'path 1: mov [rbx+0x88], rdx (the "hl-node" pointer)'),
        (0x2CB679F, '48c7839000000007000000',
         'path 1: mov qword [rbx+0x90], 7'),
        (0x2CB6849, '48895378',
         'merge: mov [rbx+0x78], rdx'),
        (0x2CB684D, '4889bb80000000',
         'merge: mov [rbx+0x80], rdi'),
        (0x2CB68F0, 'ff158aa18203',
         'call through config slot 0x64e0a80'),
        (0x2CB68F6, '488b7378',
         'post-check: mov rsi, [rbx+0x78] (key pointer)'),
        (0x2CB68FA, '488b9380000000',
         'post-check: mov rdx, [rbx+0x80] (key length)'),
        (0x2CB6907, 'ff152ba28203',
         'call through key slot 0x64e0b38'),
        (0x2CB6912, '80bb1c01000002',
         'cmp byte [rbx+0x11c], 2 (not the lookup result)'),
    ],
    'gate_a': [
        (0x2AEB170, '440fb67b72',
         'path 1: movzx r15d, byte [rbx+0x72] (tag byte)'),
        (0x2AEB188, '48899388000000',
         'path 1: mov [rbx+0x88], rdx (the "hl-node" pointer)'),
        (0x2AEB18F, '48c7839000000007000000',
         'path 1: mov qword [rbx+0x90], 7'),
        (0x2AEB239, '48895378',
         'merge: mov [rbx+0x78], rdx'),
        (0x2AEB23D, '4889bb80000000',
         'merge: mov [rbx+0x80], rdi'),
        (0x2AEB2E0, 'ff159a579f03',
         'call through config slot 0x64e0a80'),
        (0x2AEB2E6, '488b7378',
         'post-check: mov rsi, [rbx+0x78] (key pointer)'),
        (0x2AEB2EA, '488b9380000000',
         'post-check: mov rdx, [rbx+0x80] (key length)'),
        (0x2AEB2F7, 'ff153b589f03',
         'call through key slot 0x64e0b38'),
    ],
}

# Byte pins on the shapers' embedded-record header stores:
# at both gate call sites each shaper writes the chain tag
# byte at embedded +0x70 (phase +0x290) and the gate dispatch
# byte 0 at embedded +0x71 (phase +0x291), and nothing at
# embedded +0x78..+0x98 (phase +0x298..+0x2b8).
EMB_PINS = {
    'lvl3_c': [
        (0x2CDE6D8, '41888590020000',
         'site 1: mov byte [r13+0x290], al (embedded tag)'),
        (0x2CDE6DF, '41c6859102000000',
         'site 1: mov byte [r13+0x291], 0 (dispatch byte)'),
        (0x2CDF56F, '41888590020000',
         'site 2: mov byte [r13+0x290], al (embedded tag)'),
        (0x2CDF576, '41c6859102000000',
         'site 2: mov byte [r13+0x291], 0 (dispatch byte)'),
    ],
    'lvl4_a': [
        (0x2AE460B, '888390020000',
         'site 1: mov byte [rbx+0x290], al (embedded tag)'),
        (0x2AE4611, 'c6839102000000',
         'site 1: mov byte [rbx+0x291], 0 (dispatch byte)'),
        (0x2AE5470, '888390020000',
         'site 2: mov byte [rbx+0x290], al (embedded tag)'),
        (0x2AE5476, 'c6839102000000',
         'site 2: mov byte [rbx+0x291], 0 (dispatch byte)'),
    ],
}

LOOKUP_PINS = [
    (0x150AD3D, '400fb6c7',
     'movzx edi, dil: the tag byte is the dispatch key'),
    (0x150AD67, '49399fd0000000',
     'tag 1 arm: cmp qword [r15+0xd0], rbx (sentinel)'),
    (0x150AD92, '49399fb8000000',
     'tag 2 arm: cmp qword [r15+0xb8], rbx (sentinel)'),
    (0x150ADCD, '49399fa0000000',
     'tag 3 arm: cmp qword [r15+0xa0], rbx (sentinel)'),
    (0x150B110, 'e83b7afbff',
     'call cmp_helper 0x14c2b50'),
    (0x150B209, '4881c4e0000000',
     'tag 0 target: add rsp, 0xe0 (plain epilogue)'),
]
HELPER_PINS = [
    (0x14C2B79, 'ff1561d40105',
     'call through state slot 0x64dffe0'),
    (0x14C2BBF, 'b001',
     'applied arm: mov al, 1 before freeing the descriptor'),
    (0x14C2C18, 'e8c3980800',
     'delegated arm: call equality callee 0x154c4e0'),
]

# The lookup callee dispatches on the tag byte through the
# relative jump table at 0x465704 (.rodata, identity-mapped).
JUMP_TABLE = {
    'base': '0x465704',
    'entries': {'0x0': '0x150b209', '0x1': '0x150ad51',
                '0x2': '0x150ad7c', '0x3': '0x150adb7',
                '0x4': '0x150c679', '0x5': '0x150c679',
                '0x6': '0x150c697', '0x7': '0x150c697'},
}
# Per-tag reference-string field base inside the global at
# 0x64f0210: {+0x0 sentinel/capacity, +0x8 pointer,
# +0x10 length}.  Tag 0 returns before any field is read.
TAG_FIELDS = {'0x1': '0xd0', '0x2': '0xb8', '0x3': '0xa0'}

GATE_C_CENSUS = {'leas': {'rbx': {'0x120': ['0x2cb67b1', '0x2cb67dd'],
                  '0x78': ['0x2cb6785', '0x2cb67f0', '0x2cb6bcd'],
                  '0x90': ['0x2cb6b4e', '0x2cb715f']}},
 'loads': {'rbx': {'0x108': ['0x2cb6835'],
                   '0x11d': ['0x2cb68d0'],
                   '0x120': ['0x2cb67e9', '0x2cbb053'],
                   '0x121': ['0x2cb6809'],
                   '0x122': ['0x2cb6810'],
                   '0x123': ['0x2cb6818'],
                   '0x124': ['0x2cb681f'],
                   '0x70': ['0x2cb656e'],
                   '0x72': ['0x2cb6780', '0x2cb712e'],
                   '0x78': ['0x2cb68f6', '0x2cbb0ba'],
                   '0x80': ['0x2cb68fa', '0x2cbb0c3'],
                   '0x88': ['0x2cb6827'],
                   '0x90': ['0x2cb682e']}},
 'other_dst': {'rbx': {'0x11c': ['0x2cb6912', '0x2cb6927'],
                       '0x11e': ['0x2cbb772'],
                       '0x72': ['0x2cb6f2a'],
                       '0x73': ['0x2cbbba8']}},
 'stores': {'rbx': {'0x108': ['0x2cb67aa', '0x2cb71e5'],
                    '0x11c': ['0x2cb685b'],
                    '0x11d': ['0x2cb6862'],
                    '0x11e': ['0x2cb6840',
                              '0x2cbb6a6',
                              '0x2cbb6c4',
                              '0x2cbb796'],
                    '0x120': ['0x2cb67bd'],
                    '0x121': ['0x2cb67c4'],
                    '0x71': ['0x2cbb7d4', '0x2cbbbc7'],
                    '0x72': ['0x2cb6572'],
                    '0x73': ['0x2cb657d',
                             '0x2cb6bc7',
                             '0x2cb999d',
                             '0x2cbbbc3'],
                    '0x78': ['0x2cb6849', '0x2cb6bd6'],
                    '0x80': ['0x2cb684d'],
                    '0x88': ['0x2cb6798', '0x2cb6bdf'],
                    '0x90': ['0x2cb679f', '0x2cb7175'],
                    '0x98': ['0x2cb6854']}}}

GATE_A_CENSUS = {'leas': {'rbx': {'0x120': ['0x2aeb1a1', '0x2aeb1cd'],
                  '0x78': ['0x2aeb175', '0x2aeb1e0', '0x2aeb5ad'],
                  '0x90': ['0x2aeb52e', '0x2aebb3f']}},
 'loads': {'rbx': {'0x108': ['0x2aeb225'],
                   '0x11d': ['0x2aeb2c0'],
                   '0x120': ['0x2aeb1d9', '0x2aefaaa'],
                   '0x121': ['0x2aeb1f9'],
                   '0x122': ['0x2aeb200'],
                   '0x123': ['0x2aeb208'],
                   '0x124': ['0x2aeb20f'],
                   '0x70': ['0x2aeaf5e'],
                   '0x72': ['0x2aeb170', '0x2aebb0e'],
                   '0x78': ['0x2aeb2e6', '0x2aefb11'],
                   '0x80': ['0x2aeb2ea', '0x2aefb29'],
                   '0x88': ['0x2aeb217'],
                   '0x90': ['0x2aeb21e']}},
 'other_dst': {'rbx': {'0x11c': ['0x2aeb302', '0x2aeb317'],
                       '0x11e': ['0x2af01d8'],
                       '0x72': ['0x2aeb90a'],
                       '0x73': ['0x2af060e']}},
 'stores': {'rbx': {'0x108': ['0x2aeb19a', '0x2aebbc5'],
                    '0x11c': ['0x2aeb24b'],
                    '0x11d': ['0x2aeb252'],
                    '0x11e': ['0x2aeb230',
                              '0x2af010c',
                              '0x2af012a',
                              '0x2af01fc'],
                    '0x120': ['0x2aeb1ad'],
                    '0x121': ['0x2aeb1b4'],
                    '0x71': ['0x2af023a', '0x2af063c'],
                    '0x72': ['0x2aeaf62'],
                    '0x73': ['0x2aeaf6d',
                             '0x2aeb5a7',
                             '0x2aee46d',
                             '0x2af0638'],
                    '0x78': ['0x2aeb239', '0x2aeb5b6'],
                    '0x80': ['0x2aeb23d'],
                    '0x88': ['0x2aeb188', '0x2aeb5bf'],
                    '0x90': ['0x2aeb18f', '0x2aebb55'],
                    '0x98': ['0x2aeb244']}}}

LVL4A_PHASE_CENSUS = {'leas': {'rbx': {'0x205': ['0x2ae52fe'], '0xa8': ['0x2ae45a0']}},
 'loads': {'rbx': {'0x1e8': ['0x2ae45cc',
                             '0x2ae4792',
                             '0x2ae47b8',
                             '0x2ae4b72',
                             '0x2ae4cce',
                             '0x2ae4d6a',
                             '0x2ae4e61',
                             '0x2ae515e',
                             '0x2ae51d6',
                             '0x2ae542f',
                             '0x2ae54f0',
                             '0x2ae550a',
                             '0x2ae56b5',
                             '0x2ae5739',
                             '0x2ae57a5',
                             '0x2ae5b51',
                             '0x2ae5b6b'],
                   '0x88': ['0x2ae6c96'],
                   '0x90': ['0x2ae6ca7'],
                   '0xa0': ['0x2ae44c8'],
                   '0xa8': ['0x2ae5e29', '0x2ae6c66'],
                   '0xb0': ['0x2ae5e3a', '0x2ae6c77']}},
 'other_dst': {'rbx': {'0x205': ['0x2ae5e20', '0x2ae6c5d']}},
 'stores': {'rbx': {'0x1e8': ['0x2ae44ce'],
                    '0x205': ['0x2ae4213',
                              '0x2ae44dc',
                              '0x2ae475b',
                              '0x2ae48e5',
                              '0x2ae50f7',
                              '0x2ae54b9',
                              '0x2ae556d',
                              '0x2ae5b1a',
                              '0x2ae5e49',
                              '0x2ae6c86'],
                    '0x290': ['0x2ae460b', '0x2ae5470'],
                    '0x291': ['0x2ae4611', '0x2ae5476'],
                    '0x90': ['0x2ae448e'],
                    '0xa0': ['0x2ae447f'],
                    '0xa8': ['0x2ae44fa'],
                    '0xb8': ['0x2ae44eb']}}}

LVL3C_PHASE_CENSUS = {'leas': {'r13': {'0x205': ['0x2cdf3d7'], '0xa8': ['0x2cde665']}},
 'loads': {'r13': {'0x1e8': ['0x2cde692',
                             '0x2cde868',
                             '0x2cde88f',
                             '0x2cdec50',
                             '0x2cdedc7',
                             '0x2cdee55',
                             '0x2cdef47',
                             '0x2cdf24b',
                             '0x2cdf2bb',
                             '0x2cdf527',
                             '0x2cdf5f3',
                             '0x2cdf60e',
                             '0x2cdf7b0',
                             '0x2cdf83e',
                             '0x2cdf89f',
                             '0x2cdfc1f',
                             '0x2cdfc3a'],
                   '0x88': ['0x2ce0d0f'],
                   '0x90': ['0x2ce0d1b'],
                   '0xa0': ['0x2cde564'],
                   '0xa8': ['0x2cdfeee', '0x2ce0ce2'],
                   '0xb0': ['0x2cdfeff', '0x2ce0cee']}},
 'other_dst': {'r13': {'0x205': ['0x2cdfee4', '0x2ce0cd8']}},
 'stores': {'r13': {'0x1e8': ['0x2cde56b'],
                    '0x205': ['0x2cde4b3',
                              '0x2cde57a',
                              '0x2cde82e',
                              '0x2cde9cf',
                              '0x2cdf1e1',
                              '0x2cdf5b9',
                              '0x2cdf670',
                              '0x2cdfbe5',
                              '0x2cdff0e',
                              '0x2ce0cfd'],
                    '0x290': ['0x2cde6d8', '0x2cdf56f'],
                    '0x291': ['0x2cde6df', '0x2cdf576'],
                    '0xa8': ['0x2cde58a'],
                    '0xb8': ['0x2cde59a']}}}

GATE_KEEP = ('+0x70', '+0x71', '+0x72', '+0x73', '+0x78',
             '+0x80', '+0x88', '+0x90', '+0x98', '+0x108',
             '+0x11c', '+0x11d', '+0x11e', '+0x120', '+0x121',
             '+0x122', '+0x123', '+0x124')
PHASE_KEEP = ('+0x88', '+0x90', '+0x98', '+0xa0', '+0xa8',
              '+0xb0', '+0xb8', '+0x1e8', '+0x205', '+0x290',
              '+0x291')
# Embedded-record key slots in phase coordinates: the
# shapers must not touch them at all.
EMB_KEY_OFFSETS = ('+0x298', '+0x2a0', '+0x2a8', '+0x2b0')

STRINGS = {
    'hl_node_gate_c': (0x60F0B2, 7, 'hl-node'),
    'hl_node_gate_a': (0x605CCD, 7, 'hl-node'),
    'crit_file': (0x43FEA4, 20, 'base/src/crit_msg.rs'),
    'infra_key': (0x60EB60, 5, 'infra'),
}
CRIT_MESSAGE = {'va': '0x465b90', 'descriptor_length': '0x47',
                'prefix': 'crit msg initialization not applied',
                'prefix_bytes': 35}

KEY_GLOBAL = '0x64f0210'
KEY_GLOBAL_FIELDS = ('0xa0', '0xa8', '0xb0', '0xb8', '0xc0',
                     '0xc8', '0xd0', '0xd8', '0xe0')
CRIT_GLOBAL = '0x64efeb8'

PHASE_MAP = {
    'record_base': '0x10',
    'spread': {'+0x78': '0xa8', '+0x80': '0xb0',
               '+0x88': '0xb8'},
    'tag_byte': '0x1e8',
    'embedded_base': '0x220',
    'embedded_tag': '0x290',
    'embedded_dispatch': '0x291',
}

FINDINGS = [
    'the gates never receive the key triple: the embedded '
    'record the shapers hand over carries record +0x8..+0x30 '
    'at its +0x0..+0x28, the chain tag byte at +0x70 and '
    'dispatch byte 0 at +0x71; its +0x78..+0x98 slots are '
    'written by neither shaper (no access at phase '
    '+0x298..+0x2b0 in either body)',
    'on the dispatch-0 arm the shaper-driven gate invocation '
    'takes, the gate manufactures the key pair itself: it '
    'stores the .rodata pointer "hl-node" (0x60f0b2 in '
    'gate_c, 0x605ccd in gate_a) at embedded +0x88 and 7 at '
    '+0x90, moves the pair to +0x78/+0x80, and calls the '
    'key-lookup callee with (tag, "hl-node", 7) after its '
    'config-slot check; the second gate arm instead moves '
    'a pre-existing +0x88/+0x90 pair down to +0x78/+0x80',
    'the lookup callee consumes (tag, pointer, length) '
    'without ever using the pointer or length as a memory '
    'base: tag 0 returns at once, tags 1/2/3 select the '
    'reference string field at global +0xd0/+0xb8/+0xa0, '
    'the field is copied out (alloc + memcpy) and handed '
    'with the caller key to helper 0x14c2b50; the helper '
    'either reports the crit-msg state applied (al = 1, '
    'descriptor strings freed) or delegates to equality '
    'callee 0x154c4e0; a nonzero verdict only makes the '
    'lookup callee emit the "crit msg initialization not '
    'applied" log record (base/src/crit_msg.rs line 471); '
    'no caller tests the result, which does not exist',
    'the chain tag is tested downstream only as the '
    'lookup callee\'s jump-table index and as the gate\'s '
    'post-call zero test (gate_c: test r15b,r15b at '
    '0x2cb690d, immediately before the +0x11c outcome-byte '
    'compares at 0x2cb6912; gate_a mirrors both); the key '
    'bytes are compared nowhere in any traced body - the '
    'only byte equality is delegated one level below the '
    'lookup callee, to 0x154c4e0',
    'after placement, the shapers read the triple again '
    'only to free it: guarded exit arms dealloc the '
    'lookup_d allocation through the spread pair '
    '(len at phase +0xa8, pointer at +0xb0) and through '
    'the record pair (len at +0x88, pointer at +0x90); '
    'the tag qword at phase +0xa0 is loaded once per '
    'shaper to form the lookup call\'s tag argument',
]


def read(va, data, size=None):
    for section in sections(data):
        if section['type'] == 8:
            continue
        if (section['address'] <= va and
                va < section['address'] + section['size']):
            offset = section['offset'] + va - section['address']
            end = (section['offset'] + section['size'] if size is None
                   else offset + size)
            return offset, bytes(data[offset:end])
    raise ValueError(hex(va))


def read_string(va, data, size):
    """Exactly size bytes at a VA, resolved through the
    section table like every other read in this tool."""
    _, raw = read(va, data, size)
    try:
        return raw.decode('ascii')
    except UnicodeDecodeError:
        raise ValueError('string is not valid ASCII')


def section_name(va, data):
    for section in sections(data):
        if (section['address'] <= va and
                va < section['address'] + section['size']):
            return section['name']
    raise ValueError(hex(va))


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def owners(data):
    check(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
          'unexpected node artifact')
    _, fdes, _ = fde_extents(data)
    extents = {(f['start'], f['end']): f for f in fdes}
    records = {}
    for role, (start, end, digest) in OWNERS.items():
        start, end = int(start, 16), int(end, 16)
        check((start, end) in extents, f'missing FDE {role}')
        offset, body = read(start, data, end - start)
        check(sha(body) == digest, f'body hash mismatch {role}')
        for kind in ('fde', 'cie'):
            fva = extents[(start, end)][kind]
            size = struct.unpack('<I', read(fva, data, 4)[1])[0] + 4
            want = FRAMES[role][kind]
            check(int(want['va'], 16) == fva and
                  read(fva, data, size)[1].hex() == want['bytes_hex'],
                  f'frame mismatch {role} {kind}')
        records[role] = {
            'start': hex(start), 'end': hex(end),
            'file_offset': hex(offset), 'bytes': end - start,
            'sha256': digest}
    return records


def frame_lines(data):
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.bin',
                                     delete=False) as tmp:
        tmp.write(data)
        name = tmp.name
    try:
        text = subprocess.run(['readelf', '-wf', name],
                              check=True, capture_output=True,
                              text=True).stdout
    finally:
        Path(name).unlink()
    wanted = []
    for start, end, _ in OWNERS.values():
        needle = (f'pc={int(start, 16):016x}..{int(end, 16):016x}')
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(OWNERS), 'owner frame lines missing')
    return [line + '\n' for line in wanted]


def objdump_text(data, role):
    start, end = int(OWNERS[role][0], 16), int(OWNERS[role][1], 16)
    offset, body = read(start, data, end - start)
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
        tmp.write(body)
        name = tmp.name
    try:
        return subprocess.run(
            ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
             '-M', 'intel', '--adjust-vma', str(start), name],
            check=True, capture_output=True, text=True).stdout
    finally:
        Path(name).unlink()


def exports(data, role):
    start, end = OWNERS[role][0], OWNERS[role][1]
    text = subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
         '--start-address', start, '--stop-address', end, str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def aligned_text(data, role):
    """Instruction-aligned objdump of one owner body from the
    ELF itself (carries the rip-target comments)."""
    start, end = OWNERS[role][0], OWNERS[role][1]
    return subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
         '--start-address', start, '--stop-address', end, str(TARGET)],
        check=True, capture_output=True, text=True).stdout


_LINE = re.compile(r'^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$')
_ALIGNED = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
_MEM = re.compile(r'\[(\w+)([+-]0x[0-9a-f]+)?\]')
_MEM_INDEX = re.compile(r'\[(\w+)\+(\w+)\*1\]')
_RIP = re.compile(r'\[rip\+0x[0-9a-f]+\].*#\s*([0-9a-f]+)')
_DIRECT = re.compile(r'^call\s+([0-9a-f]+)\s')


def classify_accesses(text, regs):
    """Classify bracket accesses by operand position.

    A mov-family bracket destination is a store, a bracket source
    is a load, a lea bracket is an address-taken; any other
    bracket destination (cmp, lock ops) is an other-destination
    record.  Returns VA lists per register and offset.
    """
    stores, loads, leas, other_dst = {}, {}, {}, {}

    def put(table, reg, off, va):
        table.setdefault(reg, {}).setdefault(off, []).append(va)

    for ln in text.splitlines():
        m = _LINE.match(ln)
        if not m:
            continue
        va, ins = int(m.group(1), 16), m.group(2).strip()
        if ' ' not in ins:
            continue
        mnem, ops = ins.split(None, 1)
        depth, cut = 0, None
        for i, ch in enumerate(ops):
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
            elif ch == ',' and depth == 0:
                cut = i
                break
        dst = ops if cut is None else ops[:cut]
        src = '' if cut is None else ops[cut + 1:]

        def scan(fragment):
            found = []
            for mm in _MEM.finditer(fragment):
                found.append((mm.group(1), mm.group(2) or '+0x0'))
            for mm in _MEM_INDEX.finditer(fragment):
                found.append((mm.group(1), 'index'))
            return found

        if mnem == 'lea':
            for reg, off in scan(ops):
                if reg in regs:
                    put(leas, reg, off, va)
            continue
        is_store = mnem.startswith('mov')
        for reg, off in scan(dst):
            if reg in regs:
                put(stores if is_store else other_dst, reg, off, va)
        for reg, off in scan(src):
            if reg in regs:
                put(loads, reg, off, va)
    return stores, loads, leas, other_dst


def _hexsites(table):
    return {reg: {off.lstrip('+'): [hex(va) for va in vas]
                  for off, vas in sorted(offs.items())}
            for reg, offs in sorted(table.items())}


def filtered_census(text, regs, keep):
    """The classify tables restricted to the offsets of
    interest, in records shape."""
    stores, loads, leas, other_dst = classify_accesses(text, regs)
    out = {}
    for name, table in (('stores', stores), ('loads', loads),
                        ('leas', leas), ('other_dst', other_dst)):
        shaped = _hexsites(table)
        pruned = {}
        for reg, offs in shaped.items():
            kept = {off: vas for off, vas in offs.items()
                    if '+' + off in keep}
            if kept:
                pruned[reg] = kept
        if pruned:
            out[name] = pruned
    return out


def rip_map(data, role):
    """The body's rip-relative target map and direct-call
    map, read from instruction-aligned objdump text."""
    rip, direct = {}, {}
    for ln in aligned_text(data, role).splitlines():
        m = _ALIGNED.match(ln)
        if not m:
            continue
        va, ins = int(m.group(1), 16), m.group(2).strip()
        rm = _RIP.search(ins)
        if rm:
            if ins.startswith('call'):
                kind = 'call'
            elif ins.startswith('lea'):
                kind = 'lea'
            else:
                kind = 'use'
            rip[hex(va)] = (kind, hex(int(rm.group(1), 16)))
            continue
        dm = _DIRECT.match(ins)
        if dm:
            direct[hex(va)] = hex(int(dm.group(1), 16))
    return rip, direct


def rela_entries(data):
    entries = {}
    for section in sections(data):
        if section['name'] != '.rela.dyn':
            continue
        check(section['size'] % 24 == 0, 'truncated.rela.dyn section')
        for i in range(section['offset'],
                       section['offset'] + section['size'], 24):
            off, info, addend = struct.unpack_from('<QQq', data, i)
            entries[off] = (info & 0xFFFFFFFF, info >> 32, addend)
    return entries


def rip_references(data, target):
    """Every rip-relative reference to target in .text (the
    series census: REX-prefixed modrm-checked scan plus the
    FF 15/FF 25 forms)."""
    text_sec = next((s for s in sections(data) if s['name'] == '.text'), None)
    check(text_sec is not None, 'missing.text section')
    base, off, size = (text_sec['address'], text_sec['offset'],
                       text_sec['size'])
    body = bytes(data[off:off + size])
    refs = set()
    for idx in range(size - 6):
        word = body[idx]
        if word in (0x48, 0x4C, 0x49, 0x4D) \
                and body[idx + 1] in (0x8D, 0x8B, 0x89, 0x88, 0x39,
                                      0x3B, 0x03, 0x2B, 0x85, 0x63) \
                and (body[idx + 2] & 0xC7) == 0x05:
            if base + idx + 7 + \
                    struct.unpack_from('<i', body, idx + 3)[0] == target:
                refs.add(base + idx)
        elif word == 0xFF and body[idx + 1] in (0x15, 0x25):
            if base + idx + 6 + \
                    struct.unpack_from('<i', body, idx + 2)[0] == target:
                refs.add(base + idx)
    return sorted(refs)


def dynsym_name(data, index):
    dynsym = next((s for s in sections(data) if s['name'] == '.dynsym'), None)
    check(dynsym is not None, 'missing.dynsym section')
    dynstr = next((s for s in sections(data) if s['name'] == '.dynstr'), None)
    check(dynstr is not None, 'missing.dynstr section')
    name_off = struct.unpack_from(
        '<I', data, dynsym['offset'] + index * 24)[0]
    start = dynstr['offset'] + name_off
    end = data.index(b'\0', start)
    try:
        return data[start:end].decode('ascii')
    except UnicodeDecodeError:
        raise ValueError('dynamic symbol name is not valid ASCII')


def slot_census(data):
    entries = rela_entries(data)
    records = {}
    for name, (slot, rtype, addend) in SLOT_TABLE.items():
        got = entries.get(slot)
        check(got is not None and got[0] == rtype and
              got[1] == 0 and got[2] == addend,
              f'slot {slot:#x} relocation mismatch')
        records[name] = {'slot': hex(slot),
                         'relocation': 'R_X86_64_JUMP_SLOT',
                         'callee': hex(addend)}
    for name, (slot, rtype, addend) in DYN_SLOTS.items():
        got = entries.get(slot)
        check(got is not None and got[0] == rtype and
              got[2] == addend,
              f'dyn slot {slot:#x} relocation mismatch')
        records[name] = {'slot': hex(slot),
                         'relocation': 'R_X86_64_JUMP_SLOT',
                         'addend': hex(addend)}
    got = entries.get(COPY_SLOT)
    check(got is not None and got[0] == 6 and got[2] == 0,
          'copy slot relocation mismatch')
    symbol = dynsym_name(data, got[1])
    check(symbol == 'memcpy', f'copy slot symbol mismatch: {symbol}')
    records['copy_slot'] = {'slot': hex(COPY_SLOT),
                            'relocation': 'R_X86_64_GLOB_DAT',
                            'symbol': symbol}
    return records


def gate_call_census(data):
    """Direct E8/E9 callers of both gates across .text, plus
    the (empty) set of relocation addends naming a gate."""
    text_sec = next((s for s in sections(data) if s['name'] == '.text'), None)
    check(text_sec is not None, 'missing.text section')
    base, off, size = (text_sec['address'], text_sec['offset'],
                       text_sec['size'])
    body = bytes(data[off:off + size])
    records = {}
    for role, target in (('gate_c', int(OWNERS['gate_c'][0], 16)),
                         ('gate_a', int(OWNERS['gate_a'][0], 16))):
        sites = []
        for opcode in (b'\xe8', b'\xe9'):
            i = body.find(opcode)
            while i != -1:
                if base + i + 5 + struct.unpack_from(
                        '<i', body, i + 1)[0] == target:
                    sites.append(base + i)
                i = body.find(opcode, i + 1)
        sites = [hex(s) for s in sorted(sites)]
        check(sites == GATE_CALLERS[role],
              f'{role} caller census mismatch: {sites}')
        records[role] = sites
    entries = rela_entries(data)
    gates = {int(OWNERS['gate_c'][0], 16), int(OWNERS['gate_a'][0], 16)}
    naming = [hex(off) for off, (_, _, add) in entries.items()
              if add in gates]
    check(naming == [], f'relocation names a gate: {naming}')
    records['rela_addends_naming_gates'] = naming
    return records


def key_slot_census(data):
    refs = [hex(va) for va in rip_references(data, KEY_SLOT)]
    check(refs == KEY_SLOT_SITES,
          f'key slot reference census mismatch: {refs}')
    return {'slot': hex(KEY_SLOT), 'callee': hex(KEY_CALLEE),
            'rip_relative_call_sites': refs}


def check_pins(data):
    records = {}
    for role, rows in GATE_KEY_PINS.items():
        _, body = read(int(OWNERS[role][0], 16), data,
                       int(OWNERS[role][1], 16) -
                       int(OWNERS[role][0], 16))
        for va, expected, _ in rows:
            rel = va - int(OWNERS[role][0], 16)
            got = body[rel:rel + len(bytes.fromhex(expected))]
            check(got.hex() == expected,
                  f'gate pin mismatch {role} at {va:#x}')
        records[role] = {hex(va): expected
                         for va, expected, _ in rows}
    for role, rows in EMB_PINS.items():
        _, body = read(int(OWNERS[role][0], 16), data,
                       int(OWNERS[role][1], 16) -
                       int(OWNERS[role][0], 16))
        for va, expected, _ in rows:
            rel = va - int(OWNERS[role][0], 16)
            got = body[rel:rel + len(bytes.fromhex(expected))]
            check(got.hex() == expected,
                  f'emb pin mismatch {role} at {va:#x}')
    for va, expected, _ in LOOKUP_PINS + HELPER_PINS:
        got = read(va, data, len(bytes.fromhex(expected)))[1]
        check(got.hex() == expected, f'pin mismatch at {va:#x}')
    return records


def body_census(data, role, regs, keep, expected, label):
    got = filtered_census(objdump_text(data, role), regs, keep)
    check(got == expected, f'{label} census mismatch')
    return got


def shaper_emb_absence(data):
    """The full shaper censuses must contain no access at
    the embedded key slots (phase +0x298..+0x2b0)."""
    for role, regs in (('lvl4_a', {'rbx'}), ('lvl3_c', {'r13'})):
        tables = classify_accesses(objdump_text(data, role), regs)
        for table in tables:
            shaped = _hexsites(table)
            for reg, offs in shaped.items():
                for off in offs:
                    check('+' + off not in EMB_KEY_OFFSETS,
                          f'{role} touches embedded key slot {off}')
    return True


def lookup_analysis(data):
    rip, direct = rip_map(data, 'key_lookup')
    check(rip == KEY_LOOKUP_RIP, 'key_lookup rip map mismatch')
    check(direct == KEY_LOOKUP_DIRECT,
          'key_lookup direct call map mismatch')
    # The (pointer, length) arguments are never used as a
    # memory base anywhere in the callee.
    tables = classify_accesses(objdump_text(data, 'key_lookup'),
                               {'rsi', 'rdx'})
    shaped = {}
    for name, table in (('stores', tables[0]), ('loads', tables[1]),
                        ('leas', tables[2]),
                        ('other_dst', tables[3])):
        s = _hexsites(table)
        if s:
            shaped[name] = s
    check(shaped == {}, f'key_lookup argument census: {shaped}')
    # The tag jump table, read through the section table
    # (.rodata is identity-mapped; read() resolves it).
    base = int(JUMP_TABLE['base'], 16)
    raw = read(base, data, 32)[1]
    entries = {}
    for i in range(8):
        disp = struct.unpack_from('<i', raw, i * 4)[0]
        entries[hex(i)] = hex(base + disp)
    check(entries == JUMP_TABLE['entries'],
          f'jump table mismatch: {entries}')
    return {'rip_targets': {site: {'kind': kind, 'target': target}
                            for site, (kind, target)
                            in sorted(rip.items())},
            'direct_calls': direct,
            'argument_bracket_accesses': shaped,
            'jump_table': {'base': JUMP_TABLE['base'],
                           'entries': entries},
            'tag_reference_fields': TAG_FIELDS,
            'tag_0_target': JUMP_TABLE['entries']['0x0']}


def helper_analysis(data):
    rip, direct = rip_map(data, 'cmp_helper')
    check(rip == HELPER_RIP, 'cmp_helper rip map mismatch')
    check(direct == HELPER_DIRECT,
          'cmp_helper direct call map mismatch')
    return {'rip_targets': {site: {'kind': kind, 'target': target}
                            for site, (kind, target)
                            in sorted(rip.items())},
            'direct_calls': direct}


def globals_census(data):
    gva = int(KEY_GLOBAL, 16)
    check(section_name(gva, data) == '.data',
          'key global not in .data')
    fields = {}
    for off in KEY_GLOBAL_FIELDS:
        val = struct.unpack(
            '<Q', read(gva + int(off, 16), data, 8)[1])[0]
        check(val == 0, f'key global field {off} nonzero: {val:#x}')
        fields[off] = hex(val)
    lazy = struct.unpack('<I', read(gva + 0x1C0, data, 4)[1])[0]
    check(lazy == 3, f'key global lazy dword mismatch: {lazy:#x}')
    cva = int(CRIT_GLOBAL, 16)
    check(section_name(cva, data) == '.data',
          'crit global not in .data')
    qwords = {}
    for off in (0, 8, 0x10, 0x18):
        qwords[hex(off)] = hex(struct.unpack(
            '<Q', read(cva + off, data, 8)[1])[0])
    check(qwords == {'0x0': '0x0', '0x8': '0x0', '0x10': '0xe',
                     '0x18': '0x0'},
          f'crit global qwords mismatch: {qwords}')
    cdword = struct.unpack('<I', read(cva + 0x40, data, 4)[1])[0]
    check(cdword == 3, f'crit global dword mismatch: {cdword:#x}')
    return {'key_global': {'va': KEY_GLOBAL, 'section': '.data',
                           'reference_fields': fields,
                           'lazy_dword_0x1c0': hex(lazy)},
            'crit_global': {'va': CRIT_GLOBAL, 'section': '.data',
                            'qwords': qwords,
                            'dword_0x40': hex(cdword)}}


def strings_census(data):
    records = {}
    for name, (va, size, want) in STRINGS.items():
        got = read_string(va, data, size)
        check(got == want, f'string mismatch {name}: {got!r}')
        records[name] = {'va': hex(va),
                         'section': section_name(va, data),
                         'bytes': size, 'value': got}
    va = int(CRIT_MESSAGE['va'], 16)
    raw = read(va, data, int(CRIT_MESSAGE['descriptor_length'],
                             16))[1]
    try:
        prefix = raw[:CRIT_MESSAGE['prefix_bytes']].decode('ascii')
    except UnicodeDecodeError:
        raise ValueError('crit message prefix is not valid ASCII')
    check(prefix == CRIT_MESSAGE['prefix'],
          f'crit message prefix mismatch: {prefix!r}')
    records['crit_message'] = {
        'va': CRIT_MESSAGE['va'], 'section': section_name(va, data),
        'descriptor_length': CRIT_MESSAGE['descriptor_length'],
        'prefix': prefix}
    return records


def analyze(data):
    records = {
        'artifact': {'size': len(data), 'sha256': sha(data)},
        'work_item': WORK_ITEM,
        'owners': owners(data),
        'exported_bodies': list(EXPORTED),
        'slots': slot_census(data),
        'gate_call_census': gate_call_census(data),
        'key_slot_census': key_slot_census(data),
        'gate_census': {
            'gate_c': body_census(data, 'gate_c', {'rbx'},
                                  GATE_KEEP, GATE_C_CENSUS,
                                  'gate_c'),
            'gate_a': body_census(data, 'gate_a', {'rbx'},
                                  GATE_KEEP, GATE_A_CENSUS,
                                  'gate_a'),
        },
        'shaper_census': {
            'lvl4_a': body_census(data, 'lvl4_a', {'rbx'},
                                  PHASE_KEEP, LVL4A_PHASE_CENSUS,
                                  'lvl4_a'),
            'lvl3_c': body_census(data, 'lvl3_c', {'r13'},
                                  PHASE_KEEP, LVL3C_PHASE_CENSUS,
                                  'lvl3_c'),
        },
        'shaper_emb_key_offsets_untouched': shaper_emb_absence(data),
        'pins': check_pins(data),
        'key_lookup': lookup_analysis(data),
        'cmp_helper': helper_analysis(data),
        'globals': globals_census(data),
        'strings': strings_census(data),
        'phase_map': PHASE_MAP,
        'findings': FINDINGS,
    }
    return records


def generate(data):
    OUT.mkdir(parents=True, exist_ok=True)
    records = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines(data)))
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(exports(data, role))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--generate', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    if args.generate:
        generate(data)
        return
    records = analyze(data)
    expected = json.loads((OUT / 'records.json').read_text())
    check(records == expected, 'records.json is stale')
    for role in EXPORTED:
        check((OUT / f'{role}.objdump.txt').read_text() ==
              exports(data, role), f'{role}.objdump.txt is stale')
    check((OUT / 'frames.txt').read_text() ==
          ''.join(frame_lines(data)), 'frames.txt is stale')
    print(json.dumps({'packet': WORK_ITEM, 'matches': True},
                     sort_keys=True))


KEY_LOOKUP_RIP = {'0x150ad25': ('use', '0x64f0100'),
 '0x150ad41': ('lea', '0x465704'),
 '0x150ad51': ('use', '0x64e0b40'),
 '0x150ad7c': ('use', '0x64e0b40'),
 '0x150adb7': ('use', '0x64e0b40'),
 '0x150addd': ('use', '0x64e0b40'),
 '0x150adf9': ('lea', '0x64f00f0'),
 '0x150ae0f': ('lea', '0x64f0100'),
 '0x150ae16': ('lea', '0x63fdb10'),
 '0x150ae1d': ('lea', '0x63fdad0'),
 '0x150ae33': ('call', '0x64df9f0'),
 '0x150ae56': ('lea', '0x63fc048'),
 '0x150ae5d': ('lea', '0x63fc008'),
 '0x150ae6e': ('call', '0x64df9f0'),
 '0x150ae9c': ('lea', '0x63fc048'),
 '0x150aea3': ('lea', '0x63fc008'),
 '0x150aeb4': ('call', '0x64df9f0'),
 '0x150aedd': ('call', '0x64df480'),
 '0x150aef8': ('call', '0x64df508'),
 '0x150aefe': ('use', '0x64e0b40'),
 '0x150af1c': ('use', '0x64e0b40'),
 '0x150af56': ('call', '0x64df480'),
 '0x150af71': ('call', '0x64df508'),
 '0x150afa0': ('lea', '0x63fc048'),
 '0x150afa7': ('lea', '0x63fc008'),
 '0x150afb8': ('call', '0x64df9f0'),
 '0x150afd9': ('lea', '0x63fc048'),
 '0x150afe0': ('lea', '0x63fc008'),
 '0x150aff1': ('call', '0x64df9f0'),
 '0x150b01a': ('call', '0x64df480'),
 '0x150b035': ('call', '0x64df508'),
 '0x150b05b': ('call', '0x64df480'),
 '0x150b076': ('call', '0x64df508'),
 '0x150b084': ('call', '0x64e0b48'),
 '0x150b104': ('lea', '0x64efeb8'),
 '0x150b11d': ('lea', '0x43fea4'),
 '0x150b158': ('call', '0x64e0a90'),
 '0x150b16c': ('lea', '0x465b90'),
 '0x150b194': ('lea', '0x14ce760'),
 '0x150b1ad': ('use', '0x64e0a98'),
 '0x150b1b9': ('lea', '0x448b05'),
 '0x150b1c5': ('call', '0x64df4b8'),
 '0x150b1cb': ('use', '0x64efe40'),
 '0x150b1e6': ('call', '0x64df4a0'),
 '0x150b203': ('call', '0x64df4a0'),
 '0x150b21a': ('lea', '0x64efe38'),
 '0x150b236': ('lea', '0x64efe40'),
 '0x150b23d': ('lea', '0x63fbfe0'),
 '0x150b244': ('lea', '0x63fc008'),
 '0x150b255': ('call', '0x64df9f0'),
 '0x150b268': ('call', '0x64df498'),
 '0x150b276': ('call', '0x64df498'),
 '0x150b286': ('call', '0x64df498'),
 '0x150b2ab': ('call', '0x64df4a0'),
 '0x150b2da': ('call', '0x64df4a0'),
 '0x150b2f7': ('call', '0x64df4a0')}

KEY_LOOKUP_DIRECT = {'0x150b110': '0x14c2b50', '0x150b148': '0x5c842e0', '0x150b300': '0x63f0a50'}

HELPER_RIP = {'0x14c2b79': ('call', '0x64dffe0'),
 '0x14c2b8b': ('lea', '0x15ebba0'),
 '0x14c2b97': ('lea', '0x448a8e'),
 '0x14c2ba1': ('call', '0x64df4b8'),
 '0x14c2bb5': ('call', '0x64df4a0'),
 '0x14c2bcc': ('call', '0x64df4a0'),
 '0x14c2c06': ('lea', '0x63f8db0')}

HELPER_DIRECT = {'0x14c2c18': '0x154c4e0',
 '0x14c2c2a': '0x15d32ae',
 '0x14c2c3a': '0x14c56b0',
 '0x14c2c42': '0x63f0a50'}

if __name__ == '__main__':
    main()
