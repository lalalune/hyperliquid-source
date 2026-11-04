#!/usr/bin/env python3
"""Trace who writes the RE-005 spawn payload fields and the phase fill.

The record-producer packet (research/work-items/RE-005-node115-
record-producer, PR #2555) identified the producers of the pipeline
records at body granularity and left three questions open, which
this packet takes.  It pins six bodies: the two spawner bodies
spawn_d (0x2ad5980) and spawn_e (0x2ad6560) again, the two helper
bodies they call into -- the GOT-slot 0x64e7360 callee 0x4784130
and the direct callee 0x2d4d540 -- the GOT-slot 0x64e1760 callee
0x5cf9600, and lvl4_c (0x2ae1690), the caller that hands the last
of those its two structs.

Question 1: which helper inside spawn_d/spawn_e writes which
payload field of the 0x3008-byte record (head block at the stack
struct base [rsp+0x3380], record proper at [rsp+0x3390], the
0x2ff8-byte payload copied out of the record)?  Answer, by final
writer of each record region:

- The GOT-slot 0x64e7360 callee is the body 0x4784130 (the slot's
  R_X86_64_RELATIVE addend).  Spawn calls it with rdi = the struct
  base, esi = 0x258 and rdx = a {pointer, length, capacity}
  descriptor of the string "abci_stream" built on the spawn stack.
  The callee writes the struct through rdi at [0x10..0x200) --
  twenty-five pinned stores plus a 0xb0-byte copy into
  [0x78..0x128) -- and at [0x0] (zero); it never writes [0x8..0x10)
  or anything at or above 0x200.  Its second argument is a scalar,
  not a length of the struct: the body clamps it against 0x2a300
  and multiplies it by 0x3e8 in a rate computation.  Its third
  argument is only read ([r15], [r15+0x8], [r15+0x10]).
- The direct callee 0x2d4d540 writes no byte of the record.  In
  the spawns it is called with rdi = the record copy at
  [rsp+0x6388], rsi = a context pointer ([entry+0xa8] + 0x18) and
  rdx = a 0x18-byte descriptor; its 521-byte body only reads the
  copy (the [rdi] qword and [rdi+0x8] dword, four times each, as
  a lookup key) and writes into the rsi context instead: a
  0x50-byte map entry at [rsi+0x48..0x98) (through r15 = rsi +
  0x48, two store blocks) and field stores at [rsi+0x98..0xaa].
  It has four direct callers binary-wide: the two spawns and the
  lvl2_d/lvl2_e bodies 0x2accee0/0x2ad0db0.
- The record head [0x0..0x148) is written last by the spawn
  bodies' own 0x148-byte copy (copy slot 0x64df508) out of a stack
  block assembled from two copies: [0x190..0x228) from the
  0x98-byte lookup-result block at frame [0xf8..0x190) and
  [0x228..0x2d8) from the context snapshot at frame [0x48..0xf8).
  The copy overwrites everything the slot callee left in that
  range.  The spawns then store r12 at record +0x148 and r14 at
  +0x150 (overwriting the callee's [0x158]/[0x160] struct stores)
  and finish record +0x158 by storing the function pointer
  0x2a92c20 and then overwriting its low dword with ebp and the
  next word with 0x0001.
- What survives of the callee's work is record [0x160..0x1f0)
  (struct [0x170..0x200)).  Record [0x1f0..0x2ff8) -- struct
  [0x200..0x3008) -- has no writer in any pinned body before the
  payload copy reads it: a precise negative, stated with the
  censuses that prove it (the spawns' descriptor-offset pattern
  tables are empty exactly as in the record-producer packet, and
  the callee store census is complete for its FDE).

Question 2: who walks the handler table at 0x64478a0..0x6447910
whose RELATIVE slots hold spawn_e (0x64478d0) and spawn_d
(0x64478f0)?  There is no table and no walker.  The range is a
run of adjacent .data.rel.ro statics: a relocated pointer to
the .rodata string "node/src/connections.rs" at the base
(addend 0x445db6), two {function, 0x340, 0x8} descriptors
(0x2a9fca0 at 0x64478b8, 0x2a9e0f0 at 0x64478d8), the bare
relocated pointers to spawn_e and spawn_d, a second pointer
to the same string at 0x64478f8 and a pointer to the
"node/src/gossip_config.rs" string at 0x6447910.  The complete reference census -- modrm-checked
rip-relative scan with every candidate verified against the
FDE-synced disassembly of its containing function, dword-
occurrence scan, qword scan for the base outside the relocation
table's own offset fields, relocation addends -- finds twelve
verified references, all passing an address as a call argument:
the base as rdx on non-returning arms in lvl2_d/lvl2_e, the two
descriptor addresses as registrar arguments in the small
bodies that build the objects they describe, the string static
after spawn_d as rdi in the spawns themselves, and the last
static as rdi in the body after spawn_e.  No instruction loads
through, indexes, or calls through any address in the range,
and the spawn slots themselves are named by no instruction at
all: how the spawns come to be invoked is outside every
statically decodable reference in the binary, the same boundary
class as the b-side caller of the earlier packets.  The
record-producer packet's "handler table" reading, drawn from
the relocation slots alone, is corrected by this census.

Question 3: what does the GOT-slot 0x64e1760 callee fill into
lvl4_c's phase struct?  The callee is the body 0x5cf9600 (the
slot's RELATIVE addend).  lvl4_c calls it with rdi = its stack
phase buffer at [rsp+0x5aa8] and rsi = the query struct at
[rsp+0x130] that the helper 0x5cf93f0 filled (lvl4_c first
patches the query word at +0xe5 to 0x0101).  The fill is only a
0x50-byte head.  On the tag-3 arm (the descriptor built from the
query fields +0x60/+0xe5/+0xe7 through the helper 0x5ce01f0
yields tag 3) it stores exactly {+0x0 = 2, +0x8 = the result
pair's second word}.  On the long arm it stores +0x0 = 0, zeroes
+0x8..+0x28, stores a fresh 0x98-byte heap block (copied from its
staging buffer) at +0x28, zero at +0x30, the query pointer itself
at +0x38, and the (word, word) result of its direct call
0x5cf3d00(query, [query+0x68]) at +0x40/+0x48 (the +0x48 store
rides the common-exit indexed store [rbx+rcx*1], rcx = 0x48 on
this arm and 0x8 on the tag arm).  A third arm writes nothing
into the phase struct at all: it builds a heap wrapper
{+0x40 = the phase pointer} and returns that instead.  The
callee reads the query struct (entry segment, before its first
r14 reload at 0x5cf9bc6: offsets 0x0, 0x8, 0x20, 0x28, 0x30,
0x38, 0x60, 0x68, 0x90, 0xa0, 0xb0, 0xc0, 0xd0 by lea, 0xe0,
0xe4, 0xe5, 0xe7, 0xe8, 0xe9) and stores into it nowhere -- the
body's only r14-destination instructions are one cmp and five
lock inc/dec refcount operations through reloaded values.  Every
phase field at or above +0x50 -- including all the shaping
sources lvl4_a and lvl3_c read (+0xc8..+0xf0, +0x1e8, the
dispatch byte +0x21a, the embedded record at +0x220) -- is left
exactly as the caller's stack held it.

Every fact is mechanical.  Six functions are pinned by exact FDE
extent, body SHA-256 and per-instruction byte pins; the four
bodies of at most about 4 KB retain full objdump exports, the
rest are retained as hash plus pins.  The censuses are re-derived
from fresh objdump text and binary scans on every run.  Captured
code is never executed; byte values are recorded exactly as
decoded.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = (
    'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-spawn-payload-fields'
OUT = ROOT / 'research/work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'
COPY_SLOT = 0x64DF508

EXPORTED = {'spawn_d', 'spawn_e', 'slot7360_callee', 'direct540'}

OWNERS = {
    'spawn_d': ('0x2ad5980', '0x2ad655e',
        '42d1acf80b7d6f20612d69b1df61149a8e669996649b6044f97a4859fac764a4'),
    'spawn_e': ('0x2ad6560', '0x2ad713e',
        'c8863fdfc321585b0cd46a5bdb0bcd1bd4c1a820ba53f9e56b6082037df03a79'),
    'slot7360_callee': ('0x4784130', '0x4784747',
        'dcdea2d4c674929e33ee250871c0a2e88299d599cd7435c8ab2cc9fb79ce0a8c'),
    'direct540': ('0x2d4d540', '0x2d4d749',
        '63f8b162ab28d87a0386a5afd901c1c15de19b023c0a6fd4d11ccd816e524dfb'),
    'slot1760_callee': ('0x5cf9600', '0x5cfa8b1',
        '12813161d76cb5aa11039d12cbbf45d6f170b2aa53da586df8e03b579e02d13b'),
    'lvl4_c': ('0x2ae1690', '0x2ae27b2',
        '6ca0595c13836bca0cb0173bd591a09d6da6791532e23a5a71c63715380727d9'),
}

FRAMES = {'spawn_d': {'fde': {'va': '0x117c13c', 'bytes_hex': '5c0000003ceb13003c989501de0b000004831a0eff410e10420e18420e20420e28420e30410e384a0d0b0eb880035b0d070ec0870383078c068d058e048f0386020393080e38410e30420e28420e20420e18420e10410e08410ec08703000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'spawn_e': {'fde': {'va': '0x117c19c', 'bytes_hex': '5c0000009ceb1300bca39501de0b0000040b1b0eff410e10420e18420e20420e28420e30410e384a0d0b0eb880035b0d070ec0870383078c068d058e048f0386020393080e38410e30420e28420e20420e18420e10410e08410ec08703000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'slot7360_callee': {'fde': {'va': '0x12c8c04', 'bytes_hex': '5000000004b6280024b54b031706000004936108ff410e10420e18420e20420e28420e30410e38470e900683078c068d058e048f038602034f040e38410e30420e28420e20420e18420e10410e08410e90060000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'direct540': {'fde': {'va': '0x119d220', 'bytes_hex': '5000000020fc15001803bb0109020000046be90dff410e10420e18420e20420e28420e30410e38470ef00183078c068d058e048f03860203b5010e38410e30420e28420e20420e18420e10410e08410ef0010000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'slot1760_callee': {'fde': {'va': '0x13d5768', 'bytes_hex': '6401000068813900903e9204b11200000453f602ff410e108602430d065483078c068d058e048f0302442e007b2e0002442e0002472e00024f2e00642e006e2e00502e0002502e00034a012e0002542e006f2e00722e004f2e0002632e000336012e00522e00672e00552e0002712e00542e00682e0002c52e00034d012e00029b2e0002962e005c2e005b2e0002762e0002b32e00572e00025e0c0708410c0610532e00502e0002962e1002af2e00612e00502e00552e00612e0002ab2e007d2e0002452e005d2e004b2e004f2e005b2e004f2e00522e00522e00502e00532e00582e004b2e004d2e00552e00532e004e2e004d2e00582e00522e00492e006b2e004d2e005d2e006a2e004e2e00582e004b2e00552e004f2e005b2e00502e00582e004b2e00682e005c2e005e2e00522e00492e00532e00552e00492e00502e004d2e004f2e004d2e004f2e00462e00462e004c2e00552e004d2e004f2e004d2e004d2e00482e00'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'lvl4_c': {'fde': {'va': '0x117c394', 'bytes_hex': '5c00000094ed1300f45296012211000004ab230eff410e10420e18420e20420e28420e30410e384a0d0b0eb8e0025b0d070ee0e60283078c068d058e048f038602034e0d0e38410e30420e28420e20420e18420e10410e08410ee0e602000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}}

CALL_TARGETS = {
    'spawn_d': {0x2AD60E9: 0x2D4D540},
    'spawn_e': {0x2AD6CC9: 0x2D4D540},
    'lvl4_c': {0x2AE16D1: 0x5CF93F0},
}

# Caller-set census subjects: the three callee bodies.
CENSUS_SUBJECTS = {
    0x4784130: 'slot7360_callee',
    0x2D4D540: 'direct540',
    0x5CF9600: 'slot1760_callee',
}
EXPECTED_CALLERS = {
    'slot7360_callee': [],
    'direct540': [
        {'containing_fde': '0x2accee0..0x2ad0db0', 'site': '0x2acdedc'},
        {'containing_fde': '0x2ad0db0..0x2ad4db7', 'site': '0x2ad1ef6'},
        {'containing_fde': '0x2ad5980..0x2ad655e', 'site': '0x2ad60e9'},
        {'containing_fde': '0x2ad6560..0x2ad713e', 'site': '0x2ad6cc9'}],
    'slot1760_callee': [],
}
EXPECTED_LEA_REFS = {}

# The two GOT slots: slot -> (callee the RELATIVE relocation names,
# the verified rip-relative reference sites, each with its form).
GOT_SLOTS = {
    0x64E7360: {
        'callee': 0x4784130,
        'ff15_sites': ['0x2ad5ad2', '0x2ad66b2', '0x5a5e358',
                       '0x5a62480'],
    },
    0x64E1760: {
        'callee': 0x5CF9600,
        'ff15_sites': ['0x15d7026', '0x15d70c2', '0x2ae16f2'],
    },
}

# The handler table at 0x64478a0..0x6447910: slot -> (file qword,
# RELATIVE addend or None), as read from the artifact.
TABLE_BASE = 0x64478A0
TABLE_END = 0x6447918
TABLE_SLOTS = {
    0x64478A0: ('0x0', 0x445DB6),
    0x64478A8: ('0x17', None),
    0x64478B0: ('0x1900000124', None),
    0x64478B8: ('0x0', 0x2A9FCA0),
    0x64478C0: ('0x340', None),
    0x64478C8: ('0x8', None),
    0x64478D0: ('0x0', 0x2AD6560),
    0x64478D8: ('0x0', 0x2A9E0F0),
    0x64478E0: ('0x340', None),
    0x64478E8: ('0x8', None),
    0x64478F0: ('0x0', 0x2AD5980),
    0x64478F8: ('0x0', 0x445DB6),
    0x6447900: ('0x17', None),
    0x6447908: ('0x54000000c0', None),
    0x6447910: ('0x0', 0x449029),
}
TABLE_VERIFIED_REFS = [
    {'site': '0x2ad09fe', 'target': '0x64478a0',
     'form': 'lea rdx on a non-returning arm in lvl2_e: rdi = '
             'the static 0x6057ad, esi = 0x7d, call through GOT '
             'slot 0x64df6b8, then ud2'},
    {'site': '0x2ad0a19', 'target': '0x64478a0',
     'form': 'lea rdx on a non-returning arm in lvl2_e: rdi = '
             'the static 0x6057eb, esi = 0x6b, call through GOT '
             'slot 0x64df6b8, then ud2'},
    {'site': '0x2ad4a0b', 'target': '0x64478a0',
     'form': 'lea rdx on a non-returning arm in lvl2_d: rdi = '
             'the static 0x6057ad, esi = 0x7d, call through GOT '
             'slot 0x64df6b8, then ud2'},
    {'site': '0x2ad4a26', 'target': '0x64478a0',
     'form': 'lea rdx on a non-returning arm in lvl2_d: rdi = '
             'the static 0x6057eb, esi = 0x6b, call through GOT '
             'slot 0x64df6b8, then ud2'},
    {'site': '0x2ad54ad', 'target': '0x64478b8',
     'form': 'lea r8 as the last argument of the direct '
             'registrar call 0x15d6730, with a fresh 0x340-byte '
             'copy of the body\'s stack template in rcx'},
    {'site': '0x2ad5539', 'target': '0x64478b8',
     'form': 'lea rsi as the second argument of the direct '
             'call 0x15dacd0 (rdi = the body\'s object) on the '
             'error arm'},
    {'site': '0x2ad5828', 'target': '0x64478d8',
     'form': 'lea r8 as the last argument of the direct '
             'registrar call 0x15d6730, with a fresh 0x340-byte '
             'copy of the body\'s stack template in rcx'},
    {'site': '0x2ad58b4', 'target': '0x64478d8',
     'form': 'lea rsi as the second argument of the direct '
             'call 0x15dacd0 (rdi = the body\'s object) on the '
             'error arm'},
    {'site': '0x2ad59cb', 'target': '0x64478f8',
     'form': 'lea rdi as the argument of the indirect call '
             'through GOT slot 0x64e1360 on spawn_d\'s '
             'entry-byte arm'},
    {'site': '0x2ad65ab', 'target': '0x64478f8',
     'form': 'lea rdi as the argument of the indirect call '
             'through GOT slot 0x64e1360 on spawn_e\'s '
             'entry-byte arm'},
    {'site': '0x2ad751c', 'target': '0x6447910',
     'form': 'lea rdi as the argument of the indirect call '
             'through GOT slot 0x64e1360 in the body after '
             'spawn_e'},
    {'site': '0x2ad752e', 'target': '0x6447910',
     'form': 'lea rdi as the argument of the indirect call '
             'through GOT slot 0x64e1368 in the body after '
             'spawn_e'},
]

# The .rodata strings the statics in the range point at, keyed
# by the RELATIVE addend that names them.  The contents are
# re-read through the section table on every run (read_string
# below): .rodata is identity-mapped in this ELF (address ==
# file offset) while .text sits at VA - 0x1000, so a blanket
# VA - 0x1000 read names a different string -- the string at
# 0x445db6 is "node/src/connections.rs" (and the following
# static word 0x17 is its length, 23); "src/method_router.rs"
# sits at 0x444db6, 0x1000 below the addend.
STATIC_STRINGS = {
    0x445DB6: 'node/src/connections.rs',
    0x449029: 'node/src/gossip_config.rs',
}

# Direct-access census over the spawn bodies' objdump text.  The
# zero patterns are the descriptor-field offsets mapped through
# the record embedding (the record-producer packet's tables); an
# exact entry pins the hit count.
_T_DE = (0x12E8, 0x13D8, 0x13E0, 0x13E8, 0x13F0,
         0x2278, 0x2368, 0x2370, 0x2378, 0x2380)


def _pats(reg, base, offs):
    return [f'[{reg}+{base + off:#x}]' for off in offs]


SPAWN_ZERO_PATTERNS = {
    'spawn_d': _pats('rsp', 0x3390, _T_DE) + _pats('r13', 0, _T_DE),
    'spawn_e': _pats('rsp', 0x3390, _T_DE) + _pats('r13', 0, _T_DE),
}
SPAWN_EXACT_COUNTS = {
    'spawn_d': {'[rsp+0x3380]': 5, '[rsp+0x3388]': 1,
                '[rsp+0x3390]': 2, '[rsp+0x34e8]': 2,
                '[rsp+0x6388]': 4, '[rsp+0x9390]': 5},
    'spawn_e': {'[rsp+0x3380]': 5, '[rsp+0x3388]': 1,
                '[rsp+0x3390]': 2, '[rsp+0x34e8]': 2,
                '[rsp+0x6388]': 4, '[rsp+0x9390]': 5},
}

# Classified access census for the three callee bodies.  Offsets
# are relative to the named entry register; counts are instruction
# counts in the body's own objdump text, classified by operand
# position (see classify_accesses).  'index' is the [rbx+rcx*1]
# store form.
CLASSIFIED = {
    'slot7360_callee': {
        'tracked': ('r14', 'r15'),
        'stores': {
            'r14': {'0x0': 1, '0x10': 1, '0x18': 1, '0x20': 1,
                    '0x28': 1, '0x38': 1, '0x48': 1, '0x58': 1,
                    '0x68': 1, '0x128': 1, '0x138': 1, '0x148': 1,
                    '0x158': 1, '0x160': 1, '0x168': 1, '0x170': 1,
                    '0x180': 1, '0x190': 1, '0x1a0': 1, '0x1b0': 1,
                    '0x1c0': 1, '0x1d0': 1, '0x1e0': 1, '0x1f0': 1,
                    '0x1f8': 1}},
        'loads': {'r15': {'0x0': 1, '0x8': 1, '0x10': 1}},
        'leas': {'r14': {'0x78': 1}, 'r15': {'0x1': 1}},
    },
    'direct540': {
        'tracked': ('rbx', 'r14', 'r15'),
        'stores': {
            'r14': {'0x98': 1, '0x9c': 1, '0xa4': 1, '0xa8': 1,
                    '0xa9': 1},
            'r15': {'0x0': 2, '0x10': 2, '0x20': 2, '0x30': 2,
                    '0x40': 2}},
        'loads': {
            'rbx': {'0x0': 4, '0x8': 4},
            'r14': {'0x48': 1},
            'r15': {'0x0': 1, '0x10': 1}},
        'leas': {'r14': {'0x48': 1}},
    },
    'slot1760_callee': {
        'tracked': ('rbx', 'r14'),
        'stores': {
            'rbx': {'0x0': 2, '0x8': 2, '0x18': 1, '0x28': 1,
                    '0x30': 1, '0x38': 1, '0x40': 1, '0x48': 1,
                    'index': 1}},
        'store_sites': {
            'rbx': ['0x5cf970a', '0x5cf970e', '0x5cfa198',
                    '0x5cfa19c', '0x5cfa1aa', '0x5cfa1ae',
                    '0x5cfa1b6', '0x5cfa1ba', '0x5cfa1c5',
                    '0x5cfa1c9', '0x5cfa491']},
        'r14_mov_stores': {},
        'r14_other_dst_sites': ['0x5cf9627', '0x5cf9c6e',
                                '0x5cf9c97', '0x5cfa3d3',
                                '0x5cfa6f6', '0x5cfa7d4'],
        # r14 loads in the entry segment, at or before the first
        # r14 reload at 0x5cf9bc6, while r14 still holds the
        # query struct pointer.
        'r14_segment_bound': '0x5cf9bc6',
        'r14_segment_loads': {
            '0x8': 1, '0x20': 2, '0x28': 1, '0x30': 1, '0x38': 2,
            '0x60': 2, '0x68': 2, '0x90': 4, '0xa0': 4, '0xb0': 4,
            '0xc0': 4, '0xe0': 2, '0xe4': 1, '0xe5': 2, '0xe7': 2,
            '0xe8': 2, '0xe9': 1},
        'r14_segment_read_dst': {'0x0': 1},
        'r14_segment_leas': {'0xd0': 2},
    },
}

PINS = {
    'spawn_d': [
        (0x4B, '488d3d261f9703',
         'the lea of the handler-table slot 0x64478f8 on the entry-byte arm'),
        (0x152, 'ff158818a103',
         'the indirect call through GOT slot 0x64e7360 that fills the record struct'),
        (0x15F, '48898424e8340000',
         'the store of the function pointer 0x2a92c20 at record +0x158'),
        (0x769, 'e852742700',
         'the direct call 0x2d4d540 against the record copy'),
        (0x7E9, '4889842480330000',
         'the self-referential store [rsp+0x3380] = &[rsp+0x40]'),
        (0x816, 'ff156c93a003',
         'the 0x148-byte head copy call into the record head'),
        (0x82C, '89ac24e8340000',
         'the dword store of ebp over record +0x158'),
        (0x987, 'ff15fb91a003',
         'the payload copy call (copy slot) at 0x2ad6307'),
    ],
    'spawn_e': [
        (0x4B, '488d3d46139703',
         'the lea of the handler-table slot 0x64478f8 on the entry-byte arm'),
        (0x152, 'ff15a80ca103',
         'the indirect call through GOT slot 0x64e7360 that fills the record struct'),
        (0x15F, '48898424e8340000',
         'the store of the function pointer 0x2a92c20 at record +0x158'),
        (0x167, '488dbc248f630000',
         'the lea forming the 0x200-byte copy destination [rsp+0x638f] in the record copy'),
        (0x769, 'e872682700',
         'the direct call 0x2d4d540 against the record copy'),
        (0x7E9, '4889842480330000',
         'the self-referential store [rsp+0x3380] = &[rsp+0x40]'),
        (0x7F6, '4889842488330000',
         'the self-referential store [rsp+0x3388] = &[rsp+0xf]'),
        (0x816, 'ff158c87a003',
         'the 0x148-byte head copy call into the record head'),
        (0x81C, '4c89a424d8340000',
         'the store of r12 at record +0x148'),
        (0x824, '4c89b424e0340000',
         'the store of r14 at record +0x150'),
        (0x82C, '89ac24e8340000',
         'the dword store of ebp over record +0x158'),
        (0x833, '66c78424ec3400000100',
         'the word store 0x0001 at record +0x15c'),
        (0x987, 'ff151b86a003',
         'the payload copy call (copy slot) at 0x2ad6ee7'),
    ],
    'slot7360_callee': [
        (0x155, '498b07',
         'the load of the descriptor pointer [r15] (r15 = entry rdx)'),
        (0x2E4, '4881fb00a30200',
         'the clamp cmp rbx,0x2a300 on the entry rsi scalar'),
        (0x335, '410f1186280100',
         'the movups store into the struct at [r14+0x128]'),
        (0x41D, 'ff15b5afd501',
         'the 0xb0-byte copy call into the struct at [r14+0x78]'),
        (0x423, '49c70600000000',
         'the zero store at the struct head [r14]'),
        (0x448, '4d89bef0010000',
         'the store of the sequence value at [r14+0x1f0]'),
    ],
    'direct540': [
        (0x34, '488b03',
         'the load of the record copy head qword [rbx]'),
        (0x70, 'ff15ca397903',
         'the lookup call through GOT slot 0x64e0f80'),
        (0xA7, '4d8d7e48',
         'the lea forming r15 = r14 + 0x48 (the context map)'),
        (0x11F, '410f1107',
         'the movups store of the map entry at [r15]'),
        (0x123, '4189ae98000000',
         'the field store at [r14+0x98]'),
    ],
    'slot1760_callee': [
        (0x45, '498b5660',
         'the load of the query qword [r14+0x60] for the descriptor'),
        (0x10A, '4c897b08',
         'the short-arm store [rbx+0x8] = r15'),
        (0x10E, '48c70302000000',
         'the short-arm store [rbx] = 2'),
        (0x198, 'e863a5ffff',
         'the call to the helper 0x5cf3d00 with the query struct'),
        (0x5C6, '4d8b7628',
         'the first reload of r14 from [r14+0x28] (end of the query segment)'),
        (0xB98, '0f114318',
         'the final zeroing movups at [rbx+0x18]'),
        (0xBAA, '4c896328',
         'the final store [rbx+0x28] = the fresh 0x98-byte block'),
        (0xBB6, '4c897338',
         'the final store [rbx+0x38] = r14'),
        (0xBC5, '4c893c0b',
         'the common-exit indexed store [rbx+rcx*1] = r15'),
        (0xE85, '48895840',
         'the wrapper-arm store embedding the phase pointer at [rax+0x40]'),
        (0xE89, '4889c3',
         'the wrapper-arm reload of rbx with the wrapper pointer'),
    ],
    'lvl4_c': [
        (0x41, 'e81a7d2103',
         'the helper call that fills the query struct at [rsp+0x130]'),
        (0x46, '66c78424150200000101',
         'the patch of the query word at +0xe5 ([rsp+0x215]) to 0x0101'),
        (0x52, '488dbc24a85a0000',
         'the lea forming rdi = the phase struct buffer [rsp+0x5aa8]'),
        (0x5A, '488db42430010000',
         'the lea forming rsi = the query struct [rsp+0x130]'),
        (0x62, 'ff156800a003',
         'the indirect call through GOT slot 0x64e1760 that fills the phase struct'),
    ],
}

SPAWN_PAYLOAD = {
    'slot7360_callee': {
        'identity': 'the GOT slot 0x64e7360 holds an R_X86_64_'
                    'RELATIVE relocation whose addend is '
                    '0x4784130; the slot has exactly four '
                    'rip-relative references binary-wide, all '
                    'FF 15 call sites: spawn_d 0x2ad5ad2, spawn_e '
                    '0x2ad66b2 and two b-side bodies (0x5a5e358, '
                    '0x5a62480)',
        'spawn_arguments': 'rdi = the record struct base '
                           '([rsp+0x3380] in the spawns), esi = '
                           '0x258, rdx = the address of a '
                           '{pointer, length, capacity} descriptor '
                           'of the 11-byte string "abci_stream" '
                           'the spawn built at [rsp+0x370]',
        'writes': 'through rdi (held in r14): twenty-five stores '
                  'covering [0x10..0x200) plus a 0xb0-byte copy '
                  '(copy slot, call at 0x478454d) into '
                  '[0x78..0x128), and a zero store at [0x0]; the '
                  'classified store census is complete for the '
                  'FDE -- no store names [0x8..0x10) and no store '
                  'or copy reaches [0x200] or above',
        'second_argument': 'a scalar, not a struct length: at '
                           '0x4784414 it is clamped against '
                           '0x2a300 (cmp/cmovb) and multiplied by '
                           '0x3e8 in a division-based rate '
                           'computation; it is never dereferenced',
        'third_argument': 'read only: [r15], [r15+0x8] and '
                          '[r15+0x10] once each (the descriptor '
                          'triple is copied into the constructed '
                          'struct at +0x10/+0x18/+0x20)',
    },
    'direct540': {
        'identity': 'the direct callee 0x2d4d540, a 521-byte '
                    'body; four direct call sites binary-wide '
                    '(lvl2_d 0x2acdedc, lvl2_e 0x2ad1ef6, spawn_d '
                    '0x2ad60e9, spawn_e 0x2ad6cc9), no tail calls, '
                    'no lea references',
        'spawn_arguments': 'rdi = the record copy at '
                           '[rsp+0x6388], rsi = the context '
                           'pointer [entry+0xa8] + 0x18, rdx = a '
                           '0x18-byte descriptor {0x605663, 0x18, '
                           'a dword out of the spawn frame}',
        'record_writes': 'none: the classified census finds zero '
                         'stores through rdi in the whole body; '
                         'the copy is only read -- its [rdi] '
                         'qword and [rdi+0x8] dword, four times '
                         'each, as the key of the lookup call '
                         'through GOT slot 0x64e0f80 at 0x2d4d5b0',
        'context_writes': 'through rsi (held in r14): a 0x50-byte '
                          'entry stored at [rsi+0x48..0x98) via '
                          'movups blocks through r15 = rsi + 0x48 '
                          '(the lea at 0x2d4d5e7; two store '
                          'blocks), and field stores at '
                          '[rsi+0x98] (dword), [rsi+0x9c] '
                          '(qword), [rsi+0xa4] (dword), '
                          '[rsi+0xa8]/[rsi+0xa9] (bytes)',
    },
    'head_copy': 'the record head [0x0..0x148) is the last write '
                 'to that range: the spawn bodies copy 0x148 '
                 'bytes (copy slot) from a stack block at '
                 '[rsp+0x190] assembled by two earlier copies -- '
                 '[rsp+0x190..0x228) from the 0x98-byte '
                 'lookup-result block at [rsp+0xf8], '
                 '[rsp+0x228..0x2d8) from the context snapshot '
                 'at [rsp+0x48] -- overwriting the slot '
                 'callee\'s stores to struct [0x10..0x158)',
    'spawn_stores': 'after the head copy each spawn stores r12 '
                    'at record +0x148 and r14 at record +0x150 '
                    '(overwriting the callee\'s struct stores at '
                    '+0x158/+0x160), stores the function pointer '
                    '0x2a92c20 at record +0x158 before the head '
                    'copy runs, and after it overwrites that '
                    'qword\'s low dword with ebp (0x2ad6d8c) and '
                    'the following word with 0x0001 (0x2ad6d93); '
                    'the struct head block [0x3380..0x3390) is '
                    'made self-referential ([rsp+0x3380] = '
                    '&[rsp+0x40], [rsp+0x3388] = &[rsp+0xf])',
    'attribution': 'final writer per record region: '
                   '[0x0..0x148) the 0x148-byte head copy; '
                   '[0x148..0x150) the spawn r12 store; '
                   '[0x150..0x158) the spawn r14 store; '
                   '[0x158..0x160) the spawn pointer/dword/word '
                   'store sequence; [0x160..0x1f0) the '
                   '0x64e7360 callee (its struct stores at '
                   '[0x170..0x200)); [0x1f0..0x2ff8) no writer '
                   'in any pinned body',
    'unattributed': 'record [0x1f0..0x2ff8) -- struct '
                    '[0x200..0x3008) -- is written by nothing in '
                    'the traced window before the payload copy '
                    '([rsp+0x3390] -> [rsp+0x9390], 0x2ff8 '
                    'bytes) reads it; the spawns\' descriptor-'
                    'offset pattern tables over the record are '
                    'empty exactly as in the record-producer '
                    'packet, and the slot callee\'s store census '
                    'stops at 0x200',
}

HANDLER_TABLE = {
    'structure': 'the range 0x64478a0..0x6447910 is not a '
                 'dispatch table but a run of adjacent '
                 '.data.rel.ro statics.  At 0x64478a0 a '
                 'relocated pointer to the .rodata string '
                 '"node/src/connections.rs" (RELATIVE addend '
                 '0x445db6), followed by the words 0x17 and '
                 '0x1900000124.  At 0x64478b8 the descriptor '
                 '{function 0x2a9fca0, 0x340, 0x8}; at '
                 '0x64478d0 the bare relocated pointer to '
                 'spawn_e; at 0x64478d8 the descriptor '
                 '{function 0x2a9e0f0, 0x340, 0x8}; at '
                 '0x64478f0 the bare relocated pointer to '
                 'spawn_d; at 0x64478f8 a second relocated '
                 'pointer to the same .rodata string, followed '
                 'by 0x17 and 0x54000000c0; at 0x6447910 a '
                 'relocated pointer to the .rodata string '
                 'at 0x449029 ("node/src/gossip_config.rs").  '
                 'The '
                 'seven RELATIVE slots sit at +0x0, +0x18, '
                 '+0x30, +0x38, +0x50, +0x58, +0x70 from the '
                 'base with eight plain data qwords between '
                 'them (0x17 twice, 0x340 twice, 0x8 twice, '
                 '0x1900000124, 0x54000000c0).  The '
                 'record-producer packet called the range a '
                 'handler table from its relocation slots '
                 'alone; the reference census here corrects '
                 'that reading',
    'walker_verdict': 'no walker and no dispatch: no '
                      'instruction loads through, indexes, or '
                      'calls through any address in the range, '
                      'and the two spawn pointers at '
                      '0x64478d0/0x64478f0 are named by no '
                      'instruction at all.  The twelve verified '
                      'references all pass an address in the '
                      'range as a call argument: the base '
                      '0x64478a0 as rdx on non-returning arms in '
                      'lvl2_d/lvl2_e (rdi = a neighbouring '
                      'static, esi = 0x7d or 0x6b, call through '
                      'GOT slot 0x64df6b8, then ud2); the '
                      'descriptor addresses 0x64478b8/0x64478d8 '
                      'as r8 to the registrar 0x15d6730 and as '
                      'rsi to the helper 0x15dacd0 in the two '
                      'small bodies that build the 0x340-byte '
                      'objects the descriptors describe (each '
                      'body also calls its descriptor\'s '
                      'function directly on its stack template '
                      'in cleanup: 0x2ad5280 calls 0x2a9fca0 at '
                      '0x2ad55ba, 0x2ad5600 calls 0x2a9e0f0 at '
                      '0x2ad593b); the string static 0x64478f8 '
                      'as rdi to the GOT-slot 0x64e1360 callee '
                      'in the two spawns; and 0x6447910 as rdi '
                      'to the GOT-slot 0x64e1360/0x64e1368 '
                      'callees in the body after spawn_e',
    'census': 'modrm-checked rip-relative scan of .text for '
              'targets in [0x64478a0, 0x6447918), every candidate '
              'verified or refuted against the FDE-synced '
              'disassembly of its containing function '
              '(recorded in the census records): twelve '
              'verified references, the rest phantoms; dword '
              'occurrences of in-range addresses in .text: '
              'zero; qword occurrences of the '
              'base 0x64478a0 anywhere in the file outside the '
              'relocation table\'s own offset fields: zero; '
              'relocation addends pointing into the range: '
              'zero; relocation slots in the range other than '
              'the seven named statics: zero',
    'boundary': 'how spawn_e/spawn_d themselves come to be '
                'invoked stays unobserved: their addresses sit '
                'as bare relocated fields among the statics, '
                'named by nothing, so the invoker obtains them '
                'from outside every statically decodable '
                'reference in the binary -- the same boundary '
                'class as the b-side caller of the block-fill '
                'packet, with the table reading itself now '
                'corrected',
}

PHASE_FILL = {
    'identity': 'the GOT slot 0x64e1760 holds an R_X86_64_'
                'RELATIVE relocation whose addend is 0x5cf9600; '
                'the slot has exactly three rip-relative '
                'references binary-wide, all FF 15 call sites: '
                'lvl4_c 0x2ae16f2 and two sites in the body '
                '0x15d6fd0..0x15d8447 (0x15d7026, 0x15d70c2)',
    'call_shape': 'lvl4_c calls with rdi = its stack phase '
                  'buffer at [rsp+0x5aa8], rsi = the query '
                  'struct at [rsp+0x130] filled by the direct '
                  'helper 0x5cf93f0 (call at 0x2ae16d1, esi = '
                  '1); between the two calls lvl4_c patches the '
                  'query word at +0xe5 to 0x0101 (store at '
                  '0x2ae16d6)',
    'written_fields': 'on the tag-3 arm: {+0x0 = 2, +0x8 = the '
                      'descriptor-result pair\'s second word} '
                      '(stores at 0x5cf970a/0x5cf970e, also '
                      'reached through the common exit with rcx '
                      '= 8); on the long arm: +0x0 = 0, '
                      '+0x8..+0x28 zeroed (movups at '
                      '0x5cfa198/0x5cfa19c), +0x28 = a fresh '
                      '0x98-byte heap block copied from the '
                      'callee\'s staging buffer (allocation '
                      'call at 0x5cfa16d, copy at 0x5cfa18f), '
                      '+0x30 = 0, +0x38 = the query pointer '
                      'itself (r14), +0x40 = the first word and '
                      '+0x48 = the second word of the result of '
                      'the direct call 0x5cf3d00(query, '
                      '[query+0x68]) at 0x5cf9798 (the +0x48 '
                      'store rides the common-exit indexed '
                      'store [rbx+rcx*1] at 0x5cfa1c5 with rcx '
                      '= 0x48)',
    'wrapper_arm': 'a third arm writes nothing into the phase '
                   'struct: it fills a heap wrapper ({+0x0 = 1, '
                   '+0x30 = 1, +0x38 = r14, +0x40 = the phase '
                   'pointer, +0x48 = a saved word} -- the '
                   '+0x40 store at 0x5cfa485), reloads rbx with '
                   'the wrapper (0x5cfa489) and only then stores '
                   '[rbx+0x48] (0x5cfa491), so that store is a '
                   'wrapper field, not a phase field; the arm '
                   'returns the wrapper',
    'read_only_fields': 'the query struct is read and never '
                        'stored into: in the entry segment (up '
                        'to the first r14 reload at 0x5cf9bc6) '
                        'the body loads +0x8, +0x20, +0x28, '
                        '+0x30, +0x38, +0x60, +0x68, +0x90, '
                        '+0xa0, +0xb0, +0xc0, +0xe0, +0xe4, '
                        '+0xe5, +0xe7, +0xe8, +0xe9, reads '
                        '+0x0 with a cmp and takes +0xd0 by lea '
                        '(twice); the body\'s only '
                        'r14-destination instructions are that '
                        'cmp and five lock inc/dec refcount '
                        'operations at 0x5cf9c6e ([r14-0x10]), '
                        '0x5cf9c97, 0x5cfa3d3, 0x5cfa6f6 and '
                        '0x5cfa7d4, all through reloaded values',
    'extent': 'the fill covers phase [0x0..0x50) at most; no '
              'store in the body names a phase offset at or '
              'above +0x50, so every field lvl4_a/lvl3_c later '
              'shape from (+0xc8..+0xf0, +0x1e8, the dispatch '
              'byte +0x21a, the embedded record at +0x220) is '
              'left exactly as the caller\'s stack held it',
}

BOUNDARIES = {
    'payload_first_writer':
        'for record [0x1f0..0x2ff8) there is no writer in the '
        'traced window at all: the region crosses the payload '
        'copy as stack residue; whether a sibling of the slot '
        'callee (the bodies 0x4784750 and 0x4784d00 operate on '
        'the same struct type and do store at +0x278/+0x2a0) is '
        'involved on some other path is a separate question -- '
        'neither sibling is called by the spawns or by the slot '
        'callee (their call-site census is the caller census of '
        'this packet)',
    'table_invocation':
        'the invoker of spawn_e/spawn_d is not in the binary\'s '
        'static references and the range the record-producer '
        'packet called a handler table is a run of statics; '
        'the two descriptors\' functions (0x2a9fca0, 0x2a9e0f0) '
        'and the string statics are pinned as contents and '
        'reference forms only',
    'phase_struct_above_0x50':
        'who produced the phase struct bytes at and above '
        '+0x50 that lvl4_a shapes from -- lvl4_c\'s own frame '
        'history and ctor_c\'s frame are the candidates -- is '
        'the next question on the c chain, together with what '
        'produces the phase structs that reach lvl4_a through '
        'call4a_b\'s [[rdx]]',
    'next_questions':
        'what writes the phase struct at and above +0x50 before '
        'lvl4_a shapes it; whether the slot callee\'s sibling '
        'bodies 0x4784750/0x4784d00 ever write the spawn '
        'struct\'s [0x200..0x3008) on another path; what the '
        'descriptor helper 0x5ce01f0 computes from the query '
        'fields, and what the 0x64e1360-slot callee does with '
        'the string-static address the spawns pass it',
}

LIMITS = (
    'Static trace only: no captured instruction was executed '
    'and no concrete input values were observed.  The '
    'classified access census classifies each instruction of '
    'the three callee bodies by operand position in fresh '
    'objdump text (a mov-family bracket destination is a store, '
    'a bracket source is a load, a lea bracket is an '
    'address-taken); register identity follows the entry '
    'assignments (r14 = rdi in 0x4784130, rbx/r14/r15 = '
    'rdi/rsi/rdx in 0x2d4d540 until the lea at 0x2d4d5e7 '
    'rebinds r15 to rsi + 0x48, rbx/r14 = rdi/rsi in 0x5cf9600) '
    'and, for 0x5cf9600, the r14 census is split at the first '
    'r14 reload (0x5cf9bc6) and the rbx store sites are '
    'enumerated by address because rbx is reloaded on later '
    'arms.  Whole-record copies move bytes without naming '
    'fields -- the copies observed are enumerated in the '
    'findings (the spawns\' struct copies, the head copy, the '
    'callee\'s [0x78..0x128) copy) -- so for copied fields the '
    'census is a statement about direct accesses and the '
    'copies actually observed.  The handler-table census '
    'verifies every candidate reference by re-disassembling '
    'its containing FDE from its start; raw byte-pattern hits '
    'that do not survive that check are recorded as phantoms, '
    'not references.  Jump-table arm reachability is recorded '
    'where the earlier packets recorded it and is not '
    're-decided here.  Raw values are recorded mechanically; '
    'no field types are guessed.')


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


def read_string(va, data):
    """The NUL-terminated ASCII string at a VA, resolved through
    the section table like every other read in this tool."""
    _, raw = read(va, data, 256)
    try:
        return raw.split(b'\0', 1)[0].decode('ascii')
    except UnicodeDecodeError:
        raise ValueError('string is not valid ASCII')


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


def check_pins(data):
    records = {}
    for role, rows in PINS.items():
        _, body = read(int(OWNERS[role][0], 16), data,
                       int(OWNERS[role][1], 16) - int(OWNERS[role][0], 16))
        for rel, expected, _ in rows:
            got = body[rel:rel + len(bytes.fromhex(expected))]
            check(got.hex() == expected,
                  f'byte pin mismatch {role} at +{rel:#x}')
        if role in EXPORTED:
            records[role] = {hex(int(OWNERS[role][0], 16) + rel): expected
                             for rel, expected, _ in rows}
    return records


def check_call(data, va, target):
    disp = struct.unpack('<i', read(va + 1, data, 4)[1])[0]
    check(read(va, data, 1)[1] == b'\xe8' and va + 5 + disp == target,
          f'call target mismatch at {va:#x}')


def check_call_targets(data):
    for role, mapping in CALL_TARGETS.items():
        for va, target in mapping.items():
            check_call(data, va, target)


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


def spawn_access_census(data):
    records = {}
    for role in ('spawn_d', 'spawn_e'):
        text = objdump_text(data, role)
        zero, exact = {}, {}
        for pattern in SPAWN_ZERO_PATTERNS[role]:
            count = text.count(pattern)
            check(count == 0,
                  f'census pattern {pattern} hit in {role}: {count}')
            zero[pattern] = 0
        for pattern, want in SPAWN_EXACT_COUNTS.get(role, {}).items():
            count = text.count(pattern)
            check(count == want,
                  f'census count {pattern} in {role}: {count} != {want}')
            exact[pattern] = count
        records[role] = {'zero_patterns': zero, 'exact_counts': exact}
    return records


_LINE = re.compile(r'^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$')
_MEM = re.compile(r'\[(\w+)([+-]0x[0-9a-f]+)?\]')
_MEM_INDEX = re.compile(r'\[(\w+)\+(\w+)\*1\]')


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


def _counts(table):
    return {reg: {off.lstrip('+'): len(vas)
                  for off, vas in sorted(offs.items())}
            for reg, offs in sorted(table.items())}


def _hexsites(table):
    return {reg: {off.lstrip('+'): [hex(va) for va in vas]
                  for off, vas in sorted(offs.items())}
            for reg, offs in sorted(table.items())}


def classified_census(data):
    records = {}
    for role, spec in CLASSIFIED.items():
        text = objdump_text(data, role)
        stores, loads, leas, other_dst = classify_accesses(
            text, spec['tracked'])
        rec = {'stores': _counts(stores), 'loads': _counts(loads),
               'leas': _counts(leas),
               'store_sites': _hexsites(stores)}
        if 'slot1760' not in role:
            check(rec['stores'] == spec['stores'],
                  f'{role} store census mismatch: {rec["stores"]}')
            check(rec['loads'] == spec['loads'],
                  f'{role} load census mismatch: {rec["loads"]}')
            check(rec['leas'] == spec['leas'],
                  f'{role} lea census mismatch: {rec["leas"]}')
        else:
            check(rec['stores'].get('rbx', {}) ==
                  spec['stores']['rbx'],
                  f'{role} rbx store census mismatch')
            sites = sorted(
                va for offs in stores.get('rbx', {}).values()
                for va in offs)
            check([hex(va) for va in sites] ==
                  spec['store_sites']['rbx'],
                  f'{role} rbx store sites mismatch')
            r14_stores = stores.get('r14', {})
            check(_counts({'r14': r14_stores}).get('r14', {}) ==
                  spec['r14_mov_stores'],
                  f'{role} r14 mov stores not empty: {r14_stores}')
            other = sorted(
                va for offs in other_dst.get('r14', {}).values()
                for va in offs)
            check([hex(va) for va in other] ==
                  spec['r14_other_dst_sites'],
                  f'{role} r14 other-dst sites mismatch: '
                  f'{[hex(va) for va in other]}')
            bound = int(spec['r14_segment_bound'], 16)
            seg_loads, seg_other, seg_leas = {}, {}, {}
            for table, out in ((loads, seg_loads),
                               (other_dst, seg_other),
                               (leas, seg_leas)):
                for off, vas in table.get('r14', {}).items():
                    kept = [va for va in vas if va <= bound]
                    if kept:
                        out[off.lstrip('+')] = len(kept)
            check(seg_loads == spec['r14_segment_loads'],
                  f'{role} r14 segment loads mismatch: {seg_loads}')
            check(seg_other == spec['r14_segment_read_dst'],
                  f'{role} r14 segment read-dst mismatch')
            check(seg_leas == spec['r14_segment_leas'],
                  f'{role} r14 segment leas mismatch')
            rec['r14_segment_loads'] = seg_loads
            rec['r14_segment_read_dst'] = seg_other
            rec['r14_segment_leas'] = seg_leas
            rec['r14_other_dst_sites'] = [hex(va) for va in other]
        records[role] = rec
    return records


def caller_census(data):
    _, fdes, _ = fde_extents(data)
    ordered = sorted((f['start'], f['end']) for f in fdes)
    starts = [s for s, _ in ordered]

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and ordered[i][0] <= va < ordered[i][1]:
            return f'{ordered[i][0]:#x}..{ordered[i][1]:#x}'
        return None

    text_sec = next((s for s in sections(data) if s['name'] == '.text'), None)
    check(text_sec is not None, 'missing.text section')
    base, off, size = (text_sec['address'], text_sec['offset'],
                       text_sec['size'])
    body = bytes(data[off:off + size])
    calls = {name: [] for name in CENSUS_SUBJECTS.values()}
    i = body.find(b'\xe8')
    while i != -1:
        va = base + i
        target = va + 5 + struct.unpack_from('<i', body, i + 1)[0]
        if target in CENSUS_SUBJECTS:
            calls[CENSUS_SUBJECTS[target]].append(
                {'site': hex(va), 'containing_fde': containing(va)})
        i = body.find(b'\xe8', i + 1)
    tails = {name: [] for name in CENSUS_SUBJECTS.values()}
    i = body.find(b'\xe9')
    while i != -1:
        va = base + i
        target = va + 5 + struct.unpack_from('<i', body, i + 1)[0]
        if target in CENSUS_SUBJECTS:
            tails[CENSUS_SUBJECTS[target]].append(hex(va))
        i = body.find(b'\xe9', i + 1)
    lea_refs = {name: [] for name in CENSUS_SUBJECTS.values()}
    for rex in (b'\x48', b'\x4c', b'\x49', b'\x4d'):
        j = body.find(rex)
        while j != -1:
            if j + 7 <= size and body[j + 1] == 0x8D \
                    and (body[j + 2] & 0xC7) == 0x05:
                target = (base + j + 7 +
                          struct.unpack_from('<i', body, j + 3)[0])
                if target in CENSUS_SUBJECTS:
                    lea_refs[CENSUS_SUBJECTS[target]].append(
                        hex(base + j))
            j = body.find(rex, j + 1)
    lea_refs = {k: sorted(set(v)) for k, v in lea_refs.items()}
    for name, sites in calls.items():
        check(sites == EXPECTED_CALLERS[name],
              f'caller census mismatch for {name}: {sites}')
        check(tails[name] == [], f'tail call to {name}')
        check(lea_refs[name] == EXPECTED_LEA_REFS.get(name, []),
              f'lea references to {name}: {lea_refs[name]}')
    return {'direct_call_sites': calls, 'tail_call_sites': tails,
            'lea_references': lea_refs}


def rela_entries(data):
    entries = {}
    for section in sections(data):
        if section['name'] != '.rela.dyn':
            continue
        check(section['size'] % 24 == 0, 'truncated.rela.dyn section')
        for i in range(section['offset'],
                       section['offset'] + section['size'], 24):
            off, info, addend = struct.unpack_from('<QQq', data, i)
            entries[off] = (info & 0xFFFFFFFF, addend)
    return entries


def rip_references(data, target):
    """Every rip-relative reference to target in .text (the
    record-producer census: REX-prefixed modrm-checked scan)."""
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


def got_census(data):
    entries = rela_entries(data)
    records = {}
    for slot, spec in GOT_SLOTS.items():
        check(entries.get(slot) == (8, spec['callee']),
              f'GOT slot {slot:#x} relocation mismatch')
        refs = rip_references(data, slot)
        sites = [hex(va) for va in refs]
        check(sites == spec['ff15_sites'],
              f'GOT slot {slot:#x} reference census mismatch: {sites}')
        records[hex(slot)] = {
            'relocation': 'R_X86_64_RELATIVE',
            'callee': hex(spec['callee']),
            'rip_relative_references': sites,
            'all_ff15_calls': True}
    return records


def _window_raw_scan(data):
    """Raw rip-relative candidate sites whose computed target
    lands in the handler-table window, without instruction-
    boundary verification."""
    text_sec = next((s for s in sections(data) if s['name'] == '.text'), None)
    check(text_sec is not None, 'missing.text section')
    base, off, size = (text_sec['address'], text_sec['offset'],
                       text_sec['size'])
    body = bytes(data[off:off + size])
    candidates = {}
    for idx in range(size - 6):
        va = base + idx
        word = body[idx]
        if word in (0x48, 0x4C, 0x49, 0x4D) \
                and body[idx + 1] in (0x8D, 0x8B, 0x89, 0x88, 0x39,
                                      0x3B, 0x03, 0x2B, 0x85, 0x63) \
                and (body[idx + 2] & 0xC7) == 0x05:
            target = va + 7 + struct.unpack_from('<i', body, idx + 3)[0]
            if TABLE_BASE <= target < TABLE_END:
                candidates[va] = ('rip-relative instruction', target)
        elif word == 0xC7 and body[idx + 1] == 0x05:
            target = va + 11 + struct.unpack_from('<i', body, idx + 2)[0]
            if TABLE_BASE <= target < TABLE_END:
                candidates[va] = ('rip-relative immediate store',
                                  target)
        elif word == 0xFF and body[idx + 1] in (0x15, 0x25):
            target = va + 6 + struct.unpack_from('<i', body, idx + 2)[0]
            if TABLE_BASE <= target < TABLE_END:
                candidates[va] = ('indirect call/jump', target)
        elif word in (0x8D, 0x8B) and (body[idx + 1] & 0xC7) == 0x05:
            target = va + 6 + struct.unpack_from('<i', body, idx + 2)[0]
            if TABLE_BASE <= target < TABLE_END:
                candidates[va] = ('rip-relative, no REX', target)
    for addr in range(TABLE_BASE, TABLE_END, 8):
        dword = struct.pack('<I', addr)
        i = body.find(dword)
        while i != -1:
            candidates.setdefault(
                base + i, ('embedded dword of table address', addr))
            i = body.find(dword, i + 1)
    return candidates


def _synced_instructions(data, fstart, fend):
    """(site VA -> (instruction text, rip target or None)) for the
    FDE disassembled from its own start."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.bin',
                                     delete=False) as tmp:
        tmp.write(data)
        name = tmp.name
    try:
        text = subprocess.run(
            ['objdump', '-d', '-M', 'intel',
             '--start-address', hex(fstart),
             '--stop-address', hex(fend), name],
            check=True, capture_output=True, text=True).stdout
    finally:
        Path(name).unlink()
    out = {}
    for ln in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\t(.*)$', ln)
        if not m:
            continue
        va = int(m.group(1), 16)
        rest = m.group(2)
        parts = rest.split('\t', 1)
        if len(parts) < 2:
            continue
        ins = parts[1].strip()
        target = None
        cm = re.search(r'#\s*([0-9a-f]+)', ins)
        if cm:
            target = int(cm.group(1), 16)
        out[va] = (ins, target)
    return out


def table_census(data):
    entries = rela_entries(data)
    slots = {}
    for va, (want_q, want_add) in TABLE_SLOTS.items():
        got = struct.unpack('<Q', read(va, data, 8)[1])[0]
        check(got == int(want_q, 16),
              f'table slot {va:#x} qword mismatch: {got:#x}')
        if want_add is None:
            check(va not in entries,
                  f'table slot {va:#x} unexpectedly relocated')
        else:
            check(entries.get(va) == (8, want_add),
                  f'table slot {va:#x} relocation mismatch')
        slots[hex(va)] = {'file_qword': want_q,
                          'relative_addend':
                              hex(want_add) if want_add is not None
                              else None}
    in_window_slots = sorted(
        off for off in entries if TABLE_BASE <= off < TABLE_END)
    check(in_window_slots ==
          [va for va, (_, a) in TABLE_SLOTS.items() if a is not None],
          'relocated table slots mismatch')
    addends_in = sorted(
        off for off, (typ, add) in entries.items()
        if typ == 8 and TABLE_BASE <= add < TABLE_END)
    check(addends_in == [], f'relocation addends into table: '
                            f'{addends_in}')
    string_addends = sorted({add for _, add in TABLE_SLOTS.values()
                             if add in STATIC_STRINGS})
    check(string_addends == sorted(STATIC_STRINGS),
          'static string addends mismatch')
    static_strings = {}
    for add in string_addends:
        got = read_string(add, data)
        check(got == STATIC_STRINGS[add],
              f'static string at {add:#x} mismatch: {got!r}')
        static_strings[hex(add)] = got
    masked = bytearray(data)
    for section in sections(data):
        if section['name'] == '.rela.dyn':
            masked[section['offset']:
                   section['offset'] + section['size']] = \
                b'\0' * section['size']
    check(bytes(masked).count(struct.pack('<Q', TABLE_BASE)) == 0,
          'table base occurs as a qword')
    _, fdes, _ = fde_extents(data)
    ordered = sorted((f['start'], f['end']) for f in fdes)
    starts = [s for s, _ in ordered]
    synced = {}
    candidates = _window_raw_scan(data)
    raw_records = []
    verified = []
    for va in sorted(candidates):
        kind, target = candidates[va]
        i = bisect.bisect_right(starts, va) - 1
        inside = (ordered[i] if i >= 0 and
                  ordered[i][0] <= va < ordered[i][1] else None)
        verdict = 'refuted'
        note = 'no containing FDE'
        if inside is not None:
            if inside not in synced:
                synced[inside] = _synced_instructions(
                    data, inside[0], inside[1])
            ins = synced[inside].get(va)
            note = (f'containing FDE {inside[0]:#x}..{inside[1]:#x}')
            if ins is not None:
                note += f'; instruction: {ins[0]}'
                if ins[1] is not None and \
                        TABLE_BASE <= ins[1] < TABLE_END:
                    verdict = 'verified'
                    verified.append(
                        {'site': hex(va), 'in': None,
                         'target': hex(ins[1]), 'form': kind})
            else:
                note += '; not an instruction start in the ' \
                        'FDE-synced disassembly'
        raw_records.append(
            {'site': hex(va), 'kind': kind,
             'computed_target': hex(target), 'verdict': verdict,
             'note': note})
    want = {(r['site'], r['target']) for r in TABLE_VERIFIED_REFS}
    got_v = {(r['site'], r['target']) for r in verified}
    check(got_v == want,
          f'verified table references mismatch: {got_v} != {want}')
    curated = {r['site']: r['form'] for r in TABLE_VERIFIED_REFS}
    for r in verified:
        va = int(r['site'], 16)
        i = bisect.bisect_right(starts, va) - 1
        r['in'] = (f'{ordered[i][0]:#x}..{ordered[i][1]:#x}'
                   if i >= 0 else None)
        r['form'] = curated[r['site']]
    return {'base': hex(TABLE_BASE), 'end': hex(TABLE_END),
            'slots': slots,
            'static_strings': static_strings,
            'verified_references': verified,
            'raw_candidates': raw_records,
            'base_qword_occurrences': 0,
            'relocation_addends_into_range': []}


def analyze(data):
    owner_records = owners(data)
    pin_records = check_pins(data)
    check_call_targets(data)
    return {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'bytes': TARGET_SIZE, 'sha256': TARGET_SHA256,
                     'snapshot': SNAPSHOT},
        'packet': WORK_ITEM,
        'captured_code_executed': False,
        'copy_slot': hex(COPY_SLOT),
        'owners': owner_records,
        'pins': pin_records,
        'got_census': got_census(data),
        'handler_table_census': table_census(data),
        'call_census': caller_census(data),
        'spawn_access_census': spawn_access_census(data),
        'classified_census': classified_census(data),
        'spawn_payload': SPAWN_PAYLOAD,
        'handler_table': HANDLER_TABLE,
        'phase_fill': PHASE_FILL,
        'boundaries': BOUNDARIES,
        'limits': LIMITS}


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


if __name__ == '__main__':
    main()
