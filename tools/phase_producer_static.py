#!/usr/bin/env python3
"""Node 115: who writes the phase struct at and above +0x50.

The spawn-payload packet (RE-005-node115-spawn-payload-fields)
showed that the GOT-slot 0x64e1760 callee 0x5cf9600 fills only
phase [0x0..0x50), so every field lvl4_a (0x2ae41e0) and lvl3_c
(0x2cde430) shape from at and above +0x50 -- the sources at
+0xc8..+0xf0, the byte at +0x1e8, the dispatch byte +0x21a, the
embedded record at +0x220 -- was left exactly as the caller's
stack held it, and recorded two questions: who produces those
bytes (lvl4_c's frame history and ctor_c's frame were the
candidates), and what produces the phase structs that reach
lvl4_a through call4a_b's [[rdx]] indirection.

Answers, all static and re-derived by analyze() below:

1. lvl4_c (0x2ae1690) copies its caller's phase struct into the
   buffer it shapes from.  The entry pointer is saved at
   [rsp+0x18] and, on both arms that reach a shaper, the whole
   0x2c40-byte struct is memcpy'd (GOT slot 0x64df508 =
   memcpy@GLIBC_2.14) from that pointer into lvl4_c's own buffer
   at [rsp+0x5aa8] -- at 0x2ae19cc on the arm that then calls
   lvl4_a directly, and at 0x2ae1b1f on the arm that calls
   lvl3_c and pre_4ab.  The slot-1760 fill at 0x2ae16f2 happens
   earlier and is overwritten in full before any shaping call;
   its only consumers are lvl4_c's own tag comparison and the
   head copy at [rsp+0xe0..0x128].  A complete census of
   lvl4_c's frame shows exactly four direct stores into the
   0x2c40-byte buffer region, all at +0x0/+0x8 (TLS save/error
   arms), all overwritten by the copies; the second full copy
   at [rsp+0x86e8] is never loaded from at all.
2. ctor_c (0x2cd8370), whose frame the entry pointer names,
   writes exactly three phase offsets: the stack probes at
   phase+0xc40 and phase+0x1c40 (zero qwords) and the dispatch
   byte phase+0x21a = 0, then calls lvl4_c with rdi = frame+8.
   Every other phase byte is inherited stack contents, and
   above ctor_c there is no static writer or caller at all:
   ctor_c's address is taken once, by the binary's main
   (registrar_stub_c 0x2cef8f0), which registers it with the
   registrar body 0x5c99970 (GOT slot 0x64e6c30) under the key
   cell 0x6440b48; the key cell, the slot and ctor_c each have
   exactly that one static reference, and ctor_c has no direct
   or tail call site.  The producer boundary is the registrar's
   runtime invocation, which static references do not expose.
3. Per shaped field: on the dispatch arm the zeroed byte
   selects (arm 0), each shaper first rebuilds the low fields
   from a record built on its own stack (lvl3_c via builder_c
   0x2b7b640's 0x98-byte record, keyed by the .rodata string
   "hl-node"; lvl4_a with the same build inlined), so the
   site-1 sources at +0xc8..+0xf0 and the +0x1e8 byte are
   shaper-produced there.  On every other arm neither shaper
   stores into +0xc0..+0x100 or +0x1e8 before shaping -- the
   rebuild stores are the only stores covering +0xc8..+0xf0 in
   either body, and each body holds exactly one +0x1e8 store --
   so those loads read the incoming bytes: the memcpy'd ctor_c
   contents, i.e. residue above the registrar boundary, except
   where an earlier pass through lvl4_c's call loop rewrote
   them.  The tag byte +0x248 is written only by the shapers
   themselves (constant 2 at site 1, 1 at site 2), and the
   embedded record head at +0x220 is written by the shaping
   stores before any consumer reads it.
4. The b-side phase structs are the same buffer again.
   lvl4_c builds a descriptor at [rsp+0x60]: [0] = the buffer
   pointer (through [rsp+0x30]), [1] = the heap pointer
   detached from its fill-head copy, [2] = &[rsp+0x228], and
   calls pre_4ab (0x24535c0) with rdx = &[rsp+0x60] at
   0x2ae2306.  pre_4ab stores descriptor[0] at its [rsp+0x48]
   and &[rsp+0x48] at [rsp+0x50], and calls call4a_b
   (0x2b404b0) with rdx = &[rsp+0x50]; call4a_b loads
   rbp = [rdx], then rdi = [rbp+0] = descriptor[0] = the
   buffer, and calls lvl4_a at 0x2b40577.  The [[rdx]] is two
   stack-cell dereferences through frames lvl4_c itself built;
   there is no table or indirect boundary on this path.

This is not a call graph, a type recovery or a field naming.
Captured code is never executed.
"""
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867'
                 'b5301')
WORK_ITEM = 'RE-005-node115-phase-producer'
OUT = ROOT / 'research/work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

REGISTRAR_SLOT = 0x64E6C30
COPY_SLOT = 0x64DF508
FILL_SLOT = 0x64E1760
CONFIG_SLOT = 0x64E0A80
KEY_CELL = 0x6440B48
KEY_STRING = 0x92A890
PHASE_LEN = 0x2C40
BUFFER_OFF = 0x5AA8
HICOPY_OFF = 0x86E8
FRAME_END = 0xB328

OWNERS = {
    'lvl4_c': ('0x2ae1690', '0x2ae27b2',
        '6ca0595c13836bca0cb0173bd591a09d6da6791532e23a5a71c63715380727d9'),
    'lvl4_a': ('0x2ae41e0', '0x2ae6d66',
        '90ae09003ca680bd4b5f32fec22ee1f7146cc1f67b758f8e2f2ac880545b730b'),
    'lvl3_c': ('0x2cde430', '0x2ce0dd1',
        '99c49a3e20f63cf199f2a160ba9560e439acb2b49a66968623aa9607acfa417b'),
    'ctor_c': ('0x2cd8370', '0x2cd83af',
        'ed23bc89640a43b1a5f373d5cb18929d79ce5b47923e58ba0565f592ba2b60d6'),
    'registrar_stub_c': ('0x2cef8f0', '0x2cef917',
        'c0621248d6ec3fd7ae1ee2df6b09bdd79541219362b313e5567717eb8f59a5c9'),
    'registrar_c': ('0x5c99970', '0x5c9a045',
        '85c321c5ef4dd64cd999ac133e97a170ffa7d088eab3fe7fcb64f31768181111'),
    'builder_c': ('0x2b7b640', '0x2b7b79c',
        '1ce5b5a8e849cc065b72f30af834a79f75454bd412d8c67df9137859bbcc8003'),
    'pre_4ab': ('0x24535c0', '0x245390d',
        'a088c449b6f4f8d7f75517ed445b3fb65b0eaeaccf04b2763a12cb5ca5778edb'),
    'call4a_b': ('0x2b404b0', '0x2b40666',
        '05ef87dc8cdf209d34d246b129dfe209764fe409efda8ee0ad73ceebb54fedac'),
    'slot1760_callee': ('0x5cf9600', '0x5cfa8b1',
        '12813161d76cb5aa11039d12cbbf45d6f170b2aa53da586df8e03b579e02d13b'),
}

FRAMES = {
    'lvl4_c': {
        'fde': {'va': '0x117c394', 'bytes_hex':
            '5c00000094ed1300f45296012211000004ab230eff410e10420e18420e20420e28420e30410e384a0d0b0eb8e0025b0d070ee0e60283078c068d058e048f038602034e0d0e38410e30420e28420e20420e18420e10410e08410ee0e602000000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
            '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'},
    },
    'lvl4_a': {
        'fde': {'va': '0x117c49c', 'bytes_hex':
            '500000009cee13003c7d9601862b00000417260eff410e10420e18420e20420e28420e30410e38470ee01f83078c068d058e048f03860203791c0e38410e30420e28420e20420e18420e10410e08410ee01f0000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
            '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'},
    },
    'lvl3_c': {
        'fde': {'va': '0x11986ac', 'bytes_hex':
            '50000000acb015007c5db401a12900000493f70dff410e10420e18420e20420e28420e30410e38470ee00983078c068d058e048f03860203f11a0e38410e30420e28420e20420e18420e10410e08410ee0090000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
            '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'},
    },
    'ctor_c': {
        'fde': {'va': '0xd8be0c', 'bytes_hex':
            '1c000000384f0e005cc5f4013f00000000470e88204f0e88404f0ed058590e08'},
        'cie': {'va': '0xca6ed8', 'bytes_hex':
            '1400000000000000017a5200017810011b0c070890010000'},
    },
    'registrar_stub_c': {
        'fde': {'va': '0xd8e218', 'bytes_hex':
            '1400000044730e00d016f6012700000000410e10650e0800'},
        'cie': {'va': '0xca6ed8', 'bytes_hex':
            '1400000000000000017a5200017810011b0c070890010000'},
    },
    'registrar_c': {
        'fde': {'va': '0x13ccf18', 'bytes_hex':
            '3000000018f9380050ca8c04d506000004ff2803ff410e108602430d065083078c068d058e048f0303d7040c0708410c06100000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
            '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'},
    },
    'builder_c': {
        'fde': {'va': '0x11860d0', 'bytes_hex':
            '3c000000d08a140068559f015c0100000437410eff420e10420e18410e20470e900a83048e038f020321010e20410e18420e10420e08410e900a000000000000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
            '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'},
    },
    'pre_4ab': {
        'fde': {'va': '0x110e384', 'bytes_hex':
            '50000000840d0d00345234014d0300000477db10ff410e10420e18420e20420e28420e30410e38470ec00183078c068d058e048f03860203ce020e38410e30420e28420e20420e18420e10410e08410ec0010000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
            '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'},
    },
    'call4a_b': {
        'fde': {'va': '0x118342c', 'bytes_hex':
            '4c0000002c5e14007cd09b01b60100000427330eff410e10420e18420e20420e28420e30410e38410e4083078c068d058e048f038602032b010e38410e30420e28420e20420e18420e10410e08410e40'},
        'cie': {'va': '0x103d604', 'bytes_hex':
            '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'},
    },
    'slot1760_callee': {
        'fde': {'va': '0x13d5768', 'bytes_hex':
            '6401000068813900903e9204b11200000453f602ff410e108602430d065483078c068d058e048f0302442e007b2e0002442e0002472e00024f2e00642e006e2e00502e0002502e00034a012e0002542e006f2e00722e004f2e0002632e000336012e00522e00672e00552e0002712e00542e00682e0002c52e00034d012e00029b2e0002962e005c2e005b2e0002762e0002b32e00572e00025e0c0708410c0610532e00502e0002962e1002af2e00612e00502e00552e00612e0002ab2e007d2e0002452e005d2e004b2e004f2e005b2e004f2e00522e00522e00502e00532e00582e004b2e004d2e00552e00532e004e2e004d2e00582e00522e00492e006b2e004d2e005d2e006a2e004e2e00582e004b2e00552e004f2e005b2e00502e00582e004b2e00682e005c2e005e2e00522e00492e00532e00552e00492e00502e004d2e004f2e004d2e004f2e00462e00462e004c2e00552e004d2e004f2e004d2e004d2e00482e00'},
        'cie': {'va': '0x103d604', 'bytes_hex':
            '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'},
    },
}

# Bodies small enough to export in full (<= ~4 KB).
EXPORTED = ('ctor_c', 'registrar_stub_c', 'registrar_c', 'builder_c',
            'pre_4ab', 'call4a_b')

PINS = {
    'lvl4_c': [
        (0x2f, '48897c2418',
         'prologue: the entry phase pointer (rdi) is saved at '
         '[rsp+0x18]'),
        (0x52, '488dbc24a85a0000',
         'the fill destination: lea rdi,[rsp+0x5aa8] (the buffer)'),
        (0x62, 'ff156800a003',
         'the phase fill call through GOT slot 0x64e1760 (body '
         '0x5cf9600; spawn-payload packet)'),
        (0xce, 'ba402c0000',
         'copy 1: mov edx,0x2c40 (the full phase length)'),
        (0xd3, '488b742418',
         'copy 1: mov rsi,QWORD PTR [rsp+0x18] (the entry pointer)'),
        (0xd8, 'ff159add9f03',
         'copy 1: memcpy call to [rsp+0x86e8] through GOT slot '
         '0x64df508'),
        (0x10b, '48898424a85a0000',
         'error arm: mov QWORD PTR [rsp+0x5aa8],rax (a vtable '
         'pointer over the buffer tag)'),
        (0x11a, '48898424b05a0000',
         'error arm: mov QWORD PTR [rsp+0x5ab0],rax'),
        (0x1fd, '48899424a85a0000',
         'TLS save: mov QWORD PTR [rsp+0x5aa8],rdx (the saved TLS '
         'phase word overwrites buffer+0x0)'),
        (0x205, '4889b424b05a0000',
         'TLS save: mov QWORD PTR [rsp+0x5ab0],rsi (buffer+0x8)'),
        (0x24f, '488dbc24682e0000',
         'copy 2 destination: lea rdi,[rsp+0x2e68]'),
        (0x257, 'ba402c0000', 'copy 2: mov edx,0x2c40'),
        (0x25c, '488b742418',
         'copy 2: mov rsi,QWORD PTR [rsp+0x18]'),
        (0x261, 'ff1511dc9f03',
         'copy 2: memcpy call through GOT slot 0x64df508'),
        (0x2aa, '488dbc2420020000',
         'copy 3 destination: lea rdi,[rsp+0x220]'),
        (0x2b2, 'ba402c0000', 'copy 3: mov edx,0x2c40'),
        (0x2b7, '488b742418',
         'copy 3: mov rsi,QWORD PTR [rsp+0x18]'),
        (0x2bc, 'ff15b6db9f03',
         'copy 3: memcpy call through GOT slot 0x64df508'),
        (0x327, '4c8da424a85a0000',
         'lvl4_a arm: lea r12,[rsp+0x5aa8] (the buffer)'),
        (0x32f, 'ba402c0000', 'copy 4: mov edx,0x2c40'),
        (0x337, '488b742418',
         'copy 4: mov rsi,QWORD PTR [rsp+0x18]'),
        (0x33c, 'ff1536db9f03',
         'copy 4: memcpy call into the buffer through GOT slot '
         '0x64df508, immediately before the lvl4_a call'),
        (0x3b7, 'e894270000', 'call lvl4_a (0x2ae41e0), rdi = r12'),
        (0x47a, '4c8da424a85a0000',
         'lvl3_c arm: lea r12,[rsp+0x5aa8] (the buffer)'),
        (0x482, 'ba402c0000', 'copy 5: mov edx,0x2c40'),
        (0x48a, '488b742418',
         'copy 5: mov rsi,QWORD PTR [rsp+0x18]'),
        (0x48f, 'ff15e3d99f03',
         'copy 5: memcpy call into the buffer through GOT slot '
         '0x64df508, before the lvl3_c and pre_4ab calls'),
        (0x4f6, '4c89642430',
         'mov QWORD PTR [rsp+0x30],r12: the buffer pointer is '
         'stored in the cell the lvl3_c guard and the b-side '
         'descriptor later read'),
        (0x7c7, '4889842480000000',
         'lvl3_c guard record: mov QWORD PTR [rsp+0x80],rax '
         '(rax = &[rsp+0xd0])'),
        (0x7cf, '488d442430', 'lea rax,[rsp+0x30]'),
        (0x7d4, '4889842488000000',
         'lvl3_c guard record: mov QWORD PTR [rsp+0x88],rax, so '
         '[[rdi+8]] for the lvl3_c call is [rsp+0x30] = the '
         'buffer pointer'),
        (0x85b, 'e840c51f00',
         'call lvl3_c (0x2cde430), rdi = &[rsp+0x80], rsi = '
         '&[rsp+0x2e68]'),
        (0xc4b, '4c89742460',
         'b-side descriptor[0]: mov QWORD PTR [rsp+0x60],r14 '
         '(r14 = [rsp+0x30] = the buffer pointer)'),
        (0xc50, '48897c2468',
         'b-side descriptor[1]: mov QWORD PTR [rsp+0x68],rdi '
         '(the heap pointer detached from the guard record)'),
        (0xc55, '488d842428020000', 'lea rax,[rsp+0x228]'),
        (0xc5d, '4889442470',
         'b-side descriptor[2]: mov QWORD PTR [rsp+0x70],rax'),
        (0xc76, 'e8b51297ff',
         'call pre_4ab (0x24535c0), rdx = &[rsp+0x60]'),
    ],
    'ctor_c': [
        (0x0, '4881ec00100000',
         'frame step 1: sub rsp,0x1000'),
        (0x7, '48c7042400000000',
         'probe store 1: mov QWORD PTR [rsp],0x0 -- at '
         'phase+0x1c40 in final-frame terms'),
        (0xf, '4881ec00100000',
         'frame step 2: sub rsp,0x1000'),
        (0x16, '48c7042400000000',
         'probe store 2: mov QWORD PTR [rsp],0x0 -- at '
         'phase+0xc40 in final-frame terms'),
        (0x1e, '4881ec480c0000',
         'frame step 3: sub rsp,0xc48 (frame total 0x2c48)'),
        (0x25, 'c684242202000000',
         'the dispatch byte: mov BYTE PTR [rsp+0x222],0x0 -- '
         'phase+0x21a with the phase base at [rsp+0x8]'),
        (0x2d, '488d7c2408',
         'lea rdi,[rsp+0x8]: the phase base passed down'),
        (0x32, 'e8e992e0ff',
         'call lvl4_c (0x2ae1690) -- ctor_c\'s only call'),
    ],
    'registrar_stub_c': [
        (0x7, '488d05728afeff',
         'lea rax,ctor_c (0x2cd8370) -- the only address-taken '
         'reference to ctor_c in the binary'),
        (0xe, '48890424',
         'mov QWORD PTR [rsp],rax: the pointer is stored in the '
         'stub\'s stack cell, passed as rdi = rsp'),
        (0x12, '488d353f127503',
         'lea rsi,key cell 0x6440b48 -- its only reference in '
         'the binary'),
        (0x1f, 'ff151b737f03',
         'call through GOT slot 0x64e6c30 (registrar body '
         '0x5c99970)'),
    ],
    'registrar_c': [
        (0x55, '48897da0',
         'the registrar saves its pointer argument (rdi) in its '
         'own frame at [rbp-0x60]'),
        (0x59, '48897598',
         'the registrar saves its key argument (rsi) in its own '
         'frame at [rbp-0x68]'),
    ],
    'builder_c': [
        (0xc, '4889fb',
         'rbx = rdi: the output record pointer'),
        (0x14, 'ff15263e9603',
         'call through GOT slot 0x64df480 with edi = 0x7 -- the '
         '7-byte key allocation ("hl-node" at 0x92a890)'),
    ],
    'pre_4ab': [
        (0x62, '4889442448',
         'mov QWORD PTR [rsp+0x48],rax -- descriptor[0], loaded '
         'from [rdx], becomes the cell call4a_b dereferences '
         'twice'),
        (0x6c, '4889442450',
         'mov QWORD PTR [rsp+0x50],rax -- rax = &[rsp+0x48] '
         'from the preceding lea, so [rsp+0x50] points at the '
         'descriptor[0] cell'),
        (0xb3, 'e838ce6e00',
         'call call4a_b (0x2b404b0), rdx = &[rsp+0x50]'),
    ],
    'call4a_b': [
        (0xc3, '488b7d00',
         'mov rdi,QWORD PTR [rbp+0x0] -- rbp = [entry rdx] = '
         '&[pre_4ab rsp+0x48], so rdi = descriptor[0]'),
        (0xc7, 'e8643cfaff', 'call lvl4_a (0x2ae41e0)'),
    ],
    'lvl4_a': [
        (0x11, '4889fb',
         'rbx = rdi: the phase pointer, held for the whole body'),
        (0x14, '0fb6871a020000',
         'the entry dispatch load: movzx eax,BYTE PTR '
         '[rdi+0x21a]'),
        (0x2ee, '4088bbe8010000',
         'the dispatch-0 rebuild\'s only +0x1e8 store: mov BYTE '
         'PTR [rbx+0x1e8],dil, dil from DWORD PTR [rbx+0xa0]'),
        (0x38d, '0f1183c0000000',
         'the rebuild store covering +0xc8: movups XMMWORD PTR '
         '[rbx+0xc0],xmm0, sourced from the phase\'s own '
         'just-rebuilt +0x10'),
        (0x424, 'c6834802000002',
         'shaping site 1: mov BYTE PTR [rbx+0x248],0x2 (the '
         'tag)'),
        (0x42b, '888390020000',
         'shaping site 1: mov BYTE PTR [rbx+0x290],al (al = '
         'the +0x1e8 byte)'),
    ],
    'lvl3_c': [
        (0x65, '4d8b2e',
         'r13 = [r14] with r14 = [rdi+8]: the phase pointer '
         'through the guard record'),
        (0x68, '410fb6851a020000',
         'the entry dispatch load: movzx eax,BYTE PTR '
         '[r13+0x21a]'),
        (0x12e, 'ff15a40f8003',
         'the dispatch-0 rebuild copy: memcpy through GOT slot '
         '0x64df508 (0x98 bytes, builder_c\'s record to '
         'phase+0x10)'),
        (0x13b, '4188bde8010000',
         'the rebuild\'s only +0x1e8 store: mov BYTE PTR '
         '[r13+0x1e8],dil, dil from DWORD PTR [r13+0xa0]'),
        (0x201, '410f1185c0000000',
         'the rebuild store covering +0xc8: movups XMMWORD PTR '
         '[r13+0xc0],xmm0, from builder_c\'s record on the '
         'stack'),
        (0x2a0, '41c6854802000002',
         'shaping site 1: mov BYTE PTR [r13+0x248],0x2 (the '
         'tag)'),
        (0x2a8, '41888590020000',
         'shaping site 1: mov BYTE PTR [r13+0x290],al (al = '
         'the +0x1e8 byte)'),
    ],
}

CALL_TARGETS = {
    'lvl4_c': {0x2ae1a47: 0x2ae41e0, 0x2ae1eeb: 0x2cde430,
               0x2ae2306: 0x24535c0},
    'ctor_c': {0x2cd83a2: 0x2ae1690},
    'pre_4ab': {0x2453673: 0x2b404b0},
    'call4a_b': {0x2b40577: 0x2ae41e0},
    'lvl3_c': {0x2cde6f4: 0x2cb6500},
}

CENSUS_SUBJECTS = {
    0x2cd8370: 'ctor_c',
    0x5c99970: 'registrar_c',
    0x2ae1690: 'lvl4_c',
    0x24535c0: 'pre_4ab',
    0x2b404b0: 'call4a_b',
    0x2ae41e0: 'lvl4_a',
    0x2cde430: 'lvl3_c',
}

EXPECTED_CALLERS = {
    'ctor_c': [],
    'registrar_c': [],
    'lvl4_c': [{'site': '0x2cd83a2',
                'containing_fde': '0x2cd8370..0x2cd83af'}],
    'pre_4ab': [{'site': '0x2ae2306',
                 'containing_fde': '0x2ae1690..0x2ae27b2'}],
    'call4a_b': [{'site': '0x2453673',
                  'containing_fde': '0x24535c0..0x245390d'}],
    'lvl4_a': [{'site': '0x2ae1a47',
                'containing_fde': '0x2ae1690..0x2ae27b2'},
               {'site': '0x2b40577',
                'containing_fde': '0x2b404b0..0x2b40666'}],
    'lvl3_c': [{'site': '0x2ae1eeb',
                'containing_fde': '0x2ae1690..0x2ae27b2'}],
}

EXPECTED_LEA_REFS = {'ctor_c': ['0x2cef8f7']}

# GOT slots whose relocation and rip-relative reference census
# this packet re-derives.  The copy slot is an imported symbol
# (GLOB_DAT), so it is checked by symbol name and by its call
# sites inside lvl4_c instead of a binary-wide reference list.
GOT_SPECS = {
    'registrar_slot': {'slot': REGISTRAR_SLOT, 'type': 8,
                       'callee': 0x5c99970,
                       'ff15_sites': ['0x2cef90f']},
    'fill_slot': {'slot': FILL_SLOT, 'type': 8,
                  'callee': 0x5cf9600,
                  'ff15_sites': ['0x15d7026', '0x15d70c2',
                                 '0x2ae16f2']},
}

COPY_CALL_SITES = ['0x2ae1768', '0x2ae18f1', '0x2ae194c',
                   '0x2ae19cc', '0x2ae1b1f']

# The lvl4_c frame census: every classified [rsp+X] access in
# the two phase-sized regions, plus the saved entry pointer.
LVL4C_FRAME = {
    'buffer_stores': {'0x5aa8': ['0x2ae179b', '0x2ae188d'],
                      '0x5ab0': ['0x2ae17aa', '0x2ae1895']},
    'buffer_loads': {'0x5aa8': ['0x2ae1716'],
                     '0x5ab0': ['0x2ae17d3'],
                     '0x5ab8': ['0x2ae171e'],
                     '0x5ac8': ['0x2ae1726'],
                     '0x5ad8': ['0x2ae172e'],
                     '0x5ae8': ['0x2ae1706']},
    'buffer_other_dst': {'0x5aa8': ['0x2ae16f8']},
    'buffer_leas': {'0x5aa8': ['0x2ae16e2', '0x2ae17c0',
                               '0x2ae19b7', '0x2ae1b0a',
                               '0x2ae1d46', '0x2ae238e',
                               '0x2ae25c8', '0x2ae267d',
                               '0x2ae2739']},
    'hicopy_stores': {},
    'hicopy_loads': {},
    'hicopy_other_dst': {},
    'hicopy_leas': {'0x86e8': ['0x2ae1756', '0x2ae2767']},
    'entry_slot_stores': ['0x2ae16bf'],
    'entry_slot_loads': ['0x2ae1763', '0x2ae18ec', '0x2ae1947',
                         '0x2ae19c7', '0x2ae1b1a', '0x2ae2794'],
}

# The two small bodies above lvl4_c: complete [rsp] censuses.
SMALL_CENSUS = {
    'ctor_c': {'stores': {'rsp': {'0x0': 2, '0x222': 1}},
               'loads': {}, 'leas': {'rsp': {'0x8': 1}}},
    'registrar_stub_c': {'stores': {'rsp': {'0x0': 1}},
                         'loads': {}, 'leas': {}},
}

# Complete classified bracket-access censuses for the two shapers,
# through the register that holds the phase pointer for the whole
# body (rbx in lvl4_a, set once at 0x2ae41f1; r13 in lvl3_c, set
# once at 0x2cde495).  The two bodies are structural twins: the
# tables agree at almost every offset.
SHAPER_SPECS = {
    'lvl4_a': {
        'stores': {'rbx': {'0x0': 1, '0x10': 1, '0x100': 1, '0x110': 1, '0x120': 1, '0x130': 1, '0x138': 1, '0x148': 1, '0x150': 4, '0x160': 4, '0x18': 1, '0x1e8': 1, '0x1e9': 1, '0x1ed': 1, '0x1ee': 1, '0x1ef': 1, '0x1f0': 1, '0x1fd': 1, '0x205': 10, '0x206': 4, '0x207': 2, '0x208': 4, '0x209': 4, '0x20a': 2, '0x20b': 1, '0x20c': 1, '0x20d': 1, '0x20e': 1, '0x20f': 1, '0x210': 3, '0x211': 1, '0x212': 1, '0x213': 1, '0x215': 1, '0x217': 1, '0x218': 5, '0x219': 1, '0x21a': 5, '0x220': 9, '0x228': 1, '0x230': 8, '0x238': 9, '0x240': 3, '0x248': 8, '0x250': 1, '0x258': 1, '0x260': 1, '0x270': 1, '0x28': 1, '0x290': 2, '0x291': 2, '0x2c8': 1, '0x2d0': 4, '0x2e0': 4, '0x348': 4, '0x358': 4, '0x38': 1, '0x3e0': 1, '0x3e8': 1, '0x3f0': 1, '0x3f8': 1, '0x48': 1, '0x50': 1, '0x60': 1, '0x70': 1, '0x8': 1, '0x80': 1, '0x90': 1, '0x918': 1, '0x919': 1, '0x9b0': 3, '0x9b1': 3, '0x9c8': 1, '0x9c9': 1, '0xa0': 1, '0xa8': 1, '0xae8': 1, '0xaf8': 1, '0xaf9': 1, '0xafd': 1, '0xafe': 1, '0xb20': 1, '0xb35': 1, '0xb36': 1, '0xb8': 1, '0xc0': 1, '0xd0': 1, '0xe0': 1, '0xf0': 1, 'index': 2}},
        'loads': {'rbx': {'0x0': 1, '0x10': 1, '0x100': 2, '0x108': 1, '0x110': 1, '0x118': 1, '0x11c': 1, '0x11d': 1, '0x11e': 1, '0x12b': 1, '0x133': 1, '0x138': 1, '0x140': 2, '0x148': 1, '0x1d0': 1, '0x1e0': 1, '0x1e8': 17, '0x1ea': 1, '0x1ee': 1, '0x1ef': 1, '0x1f1': 1, '0x20': 1, '0x201': 1, '0x220': 1, '0x228': 5, '0x230': 3, '0x238': 2, '0x240': 2, '0x248': 2, '0x258': 2, '0x260': 2, '0x268': 3, '0x270': 1, '0x2d0': 1, '0x2d8': 1, '0x2e0': 1, '0x2e8': 1, '0x30': 1, '0x3c8': 1, '0x3d8': 1, '0x3e0': 1, '0x3e8': 1, '0x3f0': 1, '0x3f8': 1, '0x40': 1, '0x50': 1, '0x60': 1, '0x70': 1, '0x8': 1, '0x80': 1, '0x88': 1, '0x90': 1, '0xa0': 1, '0xa8': 2, '0xb0': 2, '0xc0': 1, '0xc8': 18, '0xd0': 11, '0xd8': 9, '0xe0': 5, '0xe4': 1, '0xe8': 6, '0xf0': 4, '0xf8': 2, '0xf9': 1, 'index': 2}},
        'leas': {'rbx': {'0x10': 1, '0x150': 2, '0x1e9': 2, '0x205': 1, '0x20a': 1, '0x220': 11, '0x238': 4, '0x240': 1, '0x258': 2, '0x260': 2, '0x278': 1, '0x2b8': 6, '0x2d0': 3, '0x348': 1, '0x3e0': 1, '0x400': 2, '0xa8': 1, '0xc0': 1}},
        'store_sites': {'rbx': {'0x0': ['0x2ae48c2'], '0x10': ['0x2ae4443'], '0x100': ['0x2ae4541'], '0x110': ['0x2ae4536'], '0x120': ['0x2ae452b'], '0x130': ['0x2ae4520'], '0x138': ['0x2ae4829'], '0x148': ['0x2ae4837'], '0x150': ['0x2ae4dec', '0x2ae4e08', '0x2ae69ec', '0x2ae6a08'], '0x160': ['0x2ae4ddd', '0x2ae4dfa', '0x2ae69dd', '0x2ae69fa'], '0x18': ['0x2ae4473'], '0x1e8': ['0x2ae44ce'], '0x1e9': ['0x2ae4844'], '0x1ed': ['0x2ae4851'], '0x1ee': ['0x2ae48a8'], '0x1ef': ['0x2ae48b5'], '0x1f0': ['0x2ae48d0'], '0x1fd': ['0x2ae48de'], '0x205': ['0x2ae4213', '0x2ae44dc', '0x2ae475b', '0x2ae48e5', '0x2ae50f7', '0x2ae54b9', '0x2ae556d', '0x2ae5b1a', '0x2ae5e49', '0x2ae6c86'], '0x206': ['0x2ae487c', '0x2ae4c14', '0x2ae4e0f', '0x2ae6a38'], '0x207': ['0x2ae4bf2', '0x2ae6a68'], '0x208': ['0x2ae45d3', '0x2ae4641', '0x2ae693a', '0x2ae6954'], '0x209': ['0x2ae5436', '0x2ae54a6', '0x2ae68f2', '0x2ae690c'], '0x20a': ['0x2ae5e15', '0x2ae6c52'], '0x20b': ['0x2ae45b7'], '0x20c': ['0x2ae4edb'], '0x20d': ['0x2ae4ebc'], '0x20e': ['0x2ae50d4'], '0x20f': ['0x2ae5cb5'], '0x210': ['0x2ae4e23', '0x2ae5e0a', '0x2ae6c47'], '0x211': ['0x2ae5c2f'], '0x212': ['0x2ae421a'], '0x213': ['0x2ae466a'], '0x215': ['0x2ae4873'], '0x217': ['0x2ae481b'], '0x218': ['0x2ae4501', '0x2ae5e50', '0x2ae65dc', '0x2ae6978', '0x2ae6cc8'], '0x219': ['0x2ae44d5'], '0x21a': ['0x2ae5e5d', '0x2ae65e5', '0x2ae669d', '0x2ae6981', '0x2ae6cd1'], '0x220': ['0x2ae45e1', '0x2ae492f', '0x2ae4e31', '0x2ae50e2', '0x2ae5446', '0x2ae569e', '0x2ae5cca', '0x2ae6866', '0x2ae6882'], '0x228': ['0x2ae485e'], '0x230': ['0x2ae45ef', '0x2ae4e3f', '0x2ae50f0', '0x2ae5454', '0x2ae5691', '0x2ae5cd8', '0x2ae6857', '0x2ae6874'], '0x238': ['0x2ae486c', '0x2ae4e5a', '0x2ae5258', '0x2ae5274', '0x2ae5d71', '0x2ae678e', '0x2ae67aa', '0x2ae67ec', '0x2ae6808'], '0x240': ['0x2ae45fd', '0x2ae489a', '0x2ae5462'], '0x248': ['0x2ae4604', '0x2ae5249', '0x2ae5266', '0x2ae5469', '0x2ae677f', '0x2ae679c', '0x2ae67dd', '0x2ae67fa'], '0x250': ['0x2ae488c'], '0x258': ['0x2ae4949'], '0x260': ['0x2ae49cb'], '0x270': ['0x2ae49bc'], '0x28': ['0x2ae446f'], '0x290': ['0x2ae460b', '0x2ae5470'], '0x291': ['0x2ae4611', '0x2ae5476'], '0x2c8': ['0x2ae5d78'], '0x2d0': ['0x2ae5af3', '0x2ae5b01', '0x2ae6741', '0x2ae675d'], '0x2e0': ['0x2ae5ae4', '0x2ae5afa', '0x2ae6732', '0x2ae674f'], '0x348': ['0x2ae5aa9', '0x2ae5ac5', '0x2ae66f4', '0x2ae6710'], '0x358': ['0x2ae5a9a', '0x2ae5ab7', '0x2ae66e5', '0x2ae6702'], '0x38': ['0x2ae446b'], '0x3e0': ['0x2ae5609'], '0x3e8': ['0x2ae5610'], '0x3f0': ['0x2ae5617'], '0x3f8': ['0x2ae561e'], '0x48': ['0x2ae444f'], '0x50': ['0x2ae44c4'], '0x60': ['0x2ae44c0'], '0x70': ['0x2ae44bc'], '0x8': ['0x2ae48c5'], '0x80': ['0x2ae44b5'], '0x90': ['0x2ae448e'], '0x918': ['0x2ae4d8b'], '0x919': ['0x2ae4d92'], '0x9b0': ['0x2ae47d9', '0x2ae552b', '0x2ae5b8c'], '0x9b1': ['0x2ae47e0', '0x2ae5532', '0x2ae5b93'], '0x9c8': ['0x2ae51f7'], '0x9c9': ['0x2ae51fe'], '0xa0': ['0x2ae447f'], '0xa8': ['0x2ae44fa'], '0xae8': ['0x2ae4e68'], '0xaf8': ['0x2ae57c6'], '0xaf9': ['0x2ae57cd'], '0xafd': ['0x2ae4e6f'], '0xafe': ['0x2ae4e75'], '0xb20': ['0x2ae4b79'], '0xb35': ['0x2ae4b80'], '0xb36': ['0x2ae4b86'], '0xb8': ['0x2ae44eb'], '0xc0': ['0x2ae456d'], '0xd0': ['0x2ae4566'], '0xe0': ['0x2ae455f'], '0xf0': ['0x2ae4558'], 'index': ['0x2ae5bf2', '0x2ae5c0b']}},
    },
    'lvl3_c': {
        'stores': {'r13': {'0x0': 1, '0x100': 1, '0x110': 1, '0x120': 1, '0x130': 1, '0x138': 1, '0x148': 1, '0x150': 4, '0x160': 4, '0x1e8': 1, '0x1e9': 1, '0x1ed': 1, '0x1ee': 1, '0x1ef': 1, '0x1f0': 1, '0x1fd': 1, '0x205': 10, '0x206': 4, '0x207': 2, '0x208': 4, '0x209': 4, '0x20a': 2, '0x20b': 1, '0x20c': 1, '0x20d': 1, '0x20e': 1, '0x20f': 1, '0x210': 3, '0x211': 1, '0x212': 1, '0x213': 1, '0x215': 1, '0x217': 1, '0x218': 5, '0x219': 1, '0x21a': 5, '0x220': 9, '0x228': 1, '0x230': 8, '0x238': 9, '0x240': 3, '0x248': 8, '0x250': 1, '0x258': 1, '0x260': 1, '0x270': 1, '0x290': 2, '0x291': 2, '0x2c8': 1, '0x2d0': 4, '0x2e0': 4, '0x348': 4, '0x358': 4, '0x3e0': 1, '0x3e8': 1, '0x3f0': 1, '0x3f8': 1, '0x8': 1, '0x918': 1, '0x919': 1, '0x9b0': 3, '0x9b1': 3, '0x9c8': 1, '0x9c9': 1, '0xa8': 1, '0xae8': 1, '0xaf8': 1, '0xaf9': 1, '0xafd': 1, '0xafe': 1, '0xb20': 1, '0xb35': 1, '0xb36': 1, '0xb8': 1, '0xc0': 1, '0xd0': 1, '0xe0': 1, '0xf0': 1}},
        'loads': {'r13': {'0x0': 1, '0x100': 2, '0x108': 1, '0x110': 1, '0x118': 1, '0x11c': 1, '0x11d': 1, '0x11e': 1, '0x12b': 1, '0x133': 1, '0x138': 1, '0x140': 2, '0x148': 1, '0x1d0': 1, '0x1e0': 1, '0x1e8': 17, '0x1ea': 1, '0x1ee': 1, '0x1ef': 1, '0x1f1': 1, '0x201': 1, '0x21a': 1, '0x220': 1, '0x228': 5, '0x230': 3, '0x238': 2, '0x240': 2, '0x248': 2, '0x258': 2, '0x260': 2, '0x268': 3, '0x270': 1, '0x2d0': 1, '0x2d8': 1, '0x2e0': 1, '0x2e8': 1, '0x3c8': 1, '0x3d8': 1, '0x3e0': 1, '0x3e8': 1, '0x3f0': 1, '0x3f8': 1, '0x8': 1, '0x88': 1, '0x90': 1, '0xa0': 1, '0xa8': 2, '0xb0': 2, '0xc0': 1, '0xc8': 18, '0xd0': 11, '0xd8': 9, '0xe0': 5, '0xe4': 1, '0xe8': 6, '0xf0': 4, '0xf8': 2, '0xf9': 1}},
        'leas': {'r13': {'0x10': 2, '0x150': 2, '0x1e9': 2, '0x205': 1, '0x20a': 1, '0x220': 11, '0x238': 4, '0x240': 1, '0x258': 2, '0x260': 2, '0x278': 1, '0x2b8': 6, '0x2d0': 3, '0x348': 1, '0x3e0': 1, '0x400': 2, '0xa8': 1, '0xc0': 1}},
        'store_sites': {'r13': {'0x0': ['0x2cde9a9'], '0x100': ['0x2cde5f1'], '0x110': ['0x2cde5e1'], '0x120': ['0x2cde5d1'], '0x130': ['0x2cde5c2'], '0x138': ['0x2cde901'], '0x148': ['0x2cde910'], '0x150': ['0x2cdeecc', '0x2cdeeea', '0x2ce0a6b', '0x2ce0a89'], '0x160': ['0x2cdeebf', '0x2cdeedb', '0x2ce0a5b', '0x2ce0a7a'], '0x1e8': ['0x2cde56b'], '0x1e9': ['0x2cde91e'], '0x1ed': ['0x2cde92d'], '0x1ee': ['0x2cde98c'], '0x1ef': ['0x2cde99b'], '0x1f0': ['0x2cde9b9'], '0x1fd': ['0x2cde9c8'], '0x205': ['0x2cde4b3', '0x2cde57a', '0x2cde82e', '0x2cde9cf', '0x2cdf1e1', '0x2cdf5b9', '0x2cdf670', '0x2cdfbe5', '0x2cdff0e', '0x2ce0cfd'], '0x206': ['0x2cde95c', '0x2cded02', '0x2cdeef2', '0x2ce0ab6'], '0x207': ['0x2cdecdf', '0x2ce0ae3'], '0x208': ['0x2cde69a', '0x2cde715', '0x2ce09dc', '0x2ce09f7'], '0x209': ['0x2cdf52f', '0x2cdf5a5', '0x2ce0992', '0x2ce09ad'], '0x20a': ['0x2cdfed9', '0x2ce0ccd'], '0x20b': ['0x2cde67c'], '0x20c': ['0x2cdefd6'], '0x20d': ['0x2cdefb5'], '0x20e': ['0x2cdf1bb'], '0x20f': ['0x2cdfd77'], '0x210': ['0x2cdef06', '0x2cdfece', '0x2ce0cc2'], '0x211': ['0x2cdfcf3'], '0x212': ['0x2cde4bb'], '0x213': ['0x2cde73c'], '0x215': ['0x2cde952'], '0x217': ['0x2cde8f1'], '0x218': ['0x2cde5a1', '0x2cdff16', '0x2ce065f', '0x2ce072e', '0x2ce0d3d'], '0x219': ['0x2cde572'], '0x21a': ['0x2cdff24', '0x2ce0669', '0x2ce0738', '0x2ce074b', '0x2ce0d47'], '0x220': ['0x2cde6aa', '0x2cdea1d', '0x2cdef16', '0x2cdf1cb', '0x2cdf541', '0x2cdf798', '0x2cdfd8e', '0x2ce0905', '0x2ce0923'], '0x228': ['0x2cde93c'], '0x230': ['0x2cde6ba', '0x2cdef25', '0x2cdf1da', '0x2cdf551', '0x2cdf789', '0x2cdfd9d', '0x2ce08f8', '0x2ce0914'], '0x238': ['0x2cde94b', '0x2cdef40', '0x2cdf332', '0x2cdf350', '0x2cdfe33', '0x2ce0843', '0x2ce0861', '0x2ce0896', '0x2ce08b4'], '0x240': ['0x2cde6c9', '0x2cde97c', '0x2cdf560'], '0x248': ['0x2cde6d0', '0x2cdf325', '0x2cdf341', '0x2cdf567', '0x2ce0833', '0x2ce0852', '0x2ce088a', '0x2ce08a5'], '0x250': ['0x2cde96d'], '0x258': ['0x2cdea38'], '0x260': ['0x2cdeaba'], '0x270': ['0x2cdeaab'], '0x290': ['0x2cde6d8', '0x2cdf56f'], '0x291': ['0x2cde6df', '0x2cdf576'], '0x2c8': ['0x2cdfe3a'], '0x2d0': ['0x2cdfbbc', '0x2cdfbcc', '0x2ce07f2', '0x2ce0810'], '0x2e0': ['0x2cdfbaf', '0x2cdfbc4', '0x2ce07e2', '0x2ce0801'], '0x348': ['0x2cdfb7a', '0x2cdfb98', '0x2ce07a1', '0x2ce07bf'], '0x358': ['0x2cdfb6d', '0x2cdfb89', '0x2ce0791', '0x2ce07b0'], '0x3e0': ['0x2cdf70f'], '0x3e8': ['0x2cdf716'], '0x3f0': ['0x2cdf71d'], '0x3f8': ['0x2cdf724'], '0x8': ['0x2cde9ad'], '0x918': ['0x2cdee77'], '0x919': ['0x2cdee7e'], '0x9b0': ['0x2cde8b1', '0x2cdf630', '0x2cdfc5c'], '0x9b1': ['0x2cde8b8', '0x2cdf637', '0x2cdfc63'], '0x9c8': ['0x2cdf2dd'], '0x9c9': ['0x2cdf2e4'], '0xa8': ['0x2cde58a'], '0xae8': ['0x2cdef4f'], '0xaf8': ['0x2cdf8c1'], '0xaf9': ['0x2cdf8c8'], '0xafd': ['0x2cdef56'], '0xafe': ['0x2cdef5d'], '0xb20': ['0x2cdec58'], '0xb35': ['0x2cdec5f'], '0xb36': ['0x2cdec66'], '0xb8': ['0x2cde59a'], '0xc0': ['0x2cde631'], '0xd0': ['0x2cde629'], '0xe0': ['0x2cde621'], '0xf0': ['0x2cde619']}},
    },
}

PHASE_PRODUCER = {
    'question': 'who writes the phase struct\'s fields at and '
                'above +0x50 before lvl4_a/lvl3_c shape from '
                'them (spawn-payload packet, next question 1)',
    'answer': 'lvl4_c itself transports the struct.  Its frame '
              '(0xb328 bytes after the prologue) packs four '
              'phase-sized regions back to back -- [rsp+0x220], '
              '[rsp+0x2e68], the buffer at [rsp+0x5aa8] and '
              '[rsp+0x86e8], each 0x2c40 bytes -- and lvl4_c '
              'fills all four by memcpy (GOT slot 0x64df508 = '
              'memcpy@GLIBC_2.14) from the saved entry pointer '
              'at [rsp+0x18], always with rsi = [rsp+0x18] and '
              'edx = 0x2c40: to [rsp+0x86e8] at 0x2ae1768, to '
              '[rsp+0x2e68] at 0x2ae18f1, to [rsp+0x220] at '
              '0x2ae194c, and into the buffer at 0x2ae19cc (the '
              'arm that calls lvl4_a) and 0x2ae1b1f (the arm '
              'that calls lvl3_c and pre_4ab).  The shapers '
              'therefore work on a byte-for-byte copy of '
              'ctor_c\'s phase struct, not on the slot-1760 '
              'fill: the fill call at 0x2ae16f2 precedes the '
              'copies and its [0x0..0x50) result is overwritten '
              'in the buffer in full; only lvl4_c\'s own tag '
              'comparison (0x2ae16f8) and the head copy to '
              '[rsp+0xe0..0x128] (loads at 0x2ae1706..0x2ae172e) '
              'consume the fill.',
    'buffer_census': 'across lvl4_c\'s whole body, the buffer '
                     'region [rsp+0x5aa8, rsp+0x86e8) receives '
                     'exactly four direct stores, all at '
                     '+0x0/+0x8: the TLS phase-word saves at '
                     '0x2ae188d/0x2ae1895 and the TLS-state-2 '
                     'error arm\'s vtable stores at '
                     '0x2ae179b/0x2ae17aa.  Both pairs are '
                     'overwritten by the arm memcpy before the '
                     'shaping call on their path.  No other '
                     'instruction stores into the region; its '
                     'remaining accesses are the fill/head-copy '
                     'loads, the tag cmp and address-takens '
                     '(the fill destination, the memcpy r12 '
                     'setups and drop calls).  The [rsp+0x86e8] '
                     'copy is never loaded from at all: its '
                     'only accesses are the memcpy destination '
                     'lea at 0x2ae1756 and one unwind-path drop '
                     'lea at 0x2ae2767.',
    'entry_pointer': 'the saved entry pointer at [rsp+0x18] '
                     '(stored once, 0x2ae16bf) is loaded at '
                     'exactly six sites: the five memcpy '
                     'sources (0x2ae1763, 0x2ae18ec, 0x2ae1947, '
                     '0x2ae19c7, 0x2ae1b1a) and one unwind-path '
                     'drop (0x2ae2794).  lvl4_c never dereferences '
                     'the entry struct in place.',
    'ctor_c': 'ctor_c builds a 0x2c48-byte frame in three '
              'steps (sub rsp,0x1000 twice, then 0xc48) and '
              'writes exactly three phase offsets: the stack '
              'probe zero qwords at phase+0x1c40 (store at '
              '0x2cd8377) and phase+0xc40 (0x2cd8386), and the '
              'dispatch byte phase+0x21a = 0 (0x2cd8395, '
              '[rsp+0x222] with the phase base at [rsp+0x8]).  '
              'It then calls lvl4_c at 0x2cd83a2 with rdi = '
              'frame+8 and rsi inherited from its own caller.  '
              'Its complete store census is two [rsp] probes '
              'and the one byte store; every other byte of the '
              'phase region is inherited stack contents.',
    'boundary': 'above ctor_c there is no static writer and '
                'no static caller.  ctor_c\'s address is taken '
                'exactly once in the binary -- registrar_stub_c '
                '(the ELF entry point\'s main) at 0x2cef8f7 -- '
                'stored into the stub\'s stack cell, and passed '
                'to the registrar body 0x5c99970 through GOT '
                'slot 0x64e6c30 (R_X86_64_RELATIVE) with '
                'rsi = the key cell 0x6440b48.  The registrar '
                'slot and the key cell each have exactly that '
                'one rip-relative reference binary-wide; the '
                'cell is zero-filled and carries no relocation; '
                'ctor_c has no direct or tail call site; the '
                'registrar body itself has no direct caller '
                'either.  The registrar saves its pointer and '
                'key arguments in its own frame (0x5c999c5, '
                '0x5c999c9).  Whoever later invokes ctor_c does '
                'so through the registrar\'s runtime state, '
                'which no static reference exposes -- that '
                'invocation is the exact boundary, and the '
                'phase bytes ctor_c does not zero are stack '
                'residue at it.',
}

FIELD_ATTRIBUTION = {
    'question': 'for each shaped field (+0xc8..+0xf0 sources, '
                '+0x1e8, the dispatch byte +0x21a, the '
                'embedded record head at +0x220, the tag '
                '+0x248): a writer, or residue above the '
                'boundary',
    'sources_0xc8_0xf0': 'two regimes, split by the dispatch '
                         'byte.  On arm 0 -- the arm the '
                         'ctor_c-zeroed byte selects -- each '
                         'shaper first rebuilds the low fields '
                         'from a record built on its own '
                         'stack: lvl3_c calls builder_c '
                         '(0x2b7b640), whose 0x98-byte record '
                         'is keyed by the 7-byte .rodata '
                         'string "hl-node" (0x92a890; .rodata '
                         'is identity-mapped, and the 0x98 '
                         'length is the record length, not '
                         'the string\'s), memcpy\'s it to '
                         'phase+0x10 at 0x2cde55e and spreads '
                         'it over +0xa8..+0x138 with the '
                         'stores at 0x2cde58a..0x2cde631; '
                         'lvl4_a runs the same build inlined '
                         '(stores at 0x2ae4443..0x2ae456d, '
                         'the +0xc0..+0xf0 movups stores '
                         'sourced from the phase\'s own '
                         'just-rebuilt +0x10..+0x50).  The '
                         'site-1 shaping loads then read the '
                         'rebuilt values.  On every other arm '
                         'the loads read incoming bytes: the '
                         'complete store censuses show the '
                         'rebuild movups stores are the ONLY '
                         'stores covering +0xc8..+0xf0 in '
                         'either body (one store each at '
                         '+0xc0/+0xd0/+0xe0/+0xf0, none at '
                         '+0xc8/+0xd8/+0xe8/+0xf8), so no '
                         'other arm rewrites the sources '
                         'before shaping.  Incoming here means '
                         'the memcpy\'d ctor_c contents -- '
                         'residue above the registrar '
                         'boundary -- except where an earlier '
                         'pass through lvl4_c\'s lvl4_a call '
                         'loop (the loop re-enters lvl4_a at '
                         '0x2ae19e0 without re-copying) or an '
                         'earlier shaping pass rewrote them.',
    'byte_0x1e8': 'the same split.  Each body holds exactly '
                  'one +0x1e8 store (lvl4_a 0x2ae44ce, lvl3_c '
                  '0x2cde56b), in the dispatch-0 rebuild, '
                  'sourcing the low byte of the phase\'s own '
                  'DWORD at +0xa0 -- itself a rebuild field -- '
                  'before the site-1 shaping load (0x2ae45cc / '
                  '0x2cde692) copies it to the record byte '
                  '+0x290.  The other sixteen +0x1e8 loads in '
                  'each body sit on other arms and read the '
                  'incoming byte.',
    'dispatch_byte_0x21a': 'written by ctor_c (the byte zero '
                           'at 0x2cd8395) before any shaping; '
                           'carried into lvl4_c\'s buffer by '
                           'the arm memcpys; read once at each '
                           'shaper\'s entry (lvl4_a through '
                           'rdi at 0x2ae41f4, lvl3_c through '
                           'r13 at 0x2cde498).  Each shaper '
                           'also stores +0x21a at five later '
                           'sites -- state transitions after '
                           'the first dispatch, not producers '
                           'of the incoming value.',
    'record_head_0x220': 'written by the shapers\' shaping '
                         'stores themselves (nine +0x220 '
                         'store sites in each body; site 1: '
                         'lvl4_a 0x2ae45e1, lvl3_c 0x2cde6aa) '
                         'from the +0xc8 sources.  Its '
                         'incoming content is never read '
                         'before being overwritten on a '
                         'shaping path: the only +0x220 load '
                         'in each body (lvl4_a 0x2ae68b4, '
                         'lvl3_c 0x2ce0954) sits in a later '
                         'shaping block, after that block\'s '
                         'own +0x220 stores.',
    'tag_0x248': 'written only by the shapers: eight store '
                 'sites in each body, the constant 2 at '
                 'shaping site 1 (lvl4_a 0x2ae4604, lvl3_c '
                 '0x2cde6d0) and 1 at site 2.  The two +0x248 '
                 'loads in each body are 16-byte copies of '
                 'the shaped record\'s tail taken after the '
                 'stores; no incoming byte is ever consumed '
                 'as the tag.',
}

B_SIDE = {
    'question': 'what produces the phase structs that reach '
                'lvl4_a through call4a_b\'s [[rdx]] indirection '
                '(record-producer packet, b-side path)',
    'answer': 'the same lvl4_c buffer, delivered by a fully '
              'static chain with no table or indirect '
              'boundary.  On the lvl3_c arm\'s guard path, '
              'lvl4_c first stores the buffer pointer in '
              '[rsp+0x30] (0x2ae1b86, from the lea at '
              '0x2ae1b0a); the lvl3_c call itself reads it '
              'back through the guard record ([rsp+0x88] = '
              '&[rsp+0x30] at 0x2ae1e64, so lvl3_c\'s phase '
              'is [[rdi+8]] = the buffer).  After the guard '
              'sequence, lvl4_c builds a 0x18-byte descriptor '
              'at [rsp+0x60]: [0] = r14 = [rsp+0x30] = the '
              'buffer pointer (store at 0x2ae22db), [1] = the '
              'heap pointer detached from the guard record\'s '
              '+0x18 field -- the slot-1760 fill\'s fresh '
              '0x98-byte block, detached from lvl4_c\'s '
              'fill-head copy at [rsp+0x108] -- (store at '
              '0x2ae22e0), [2] = &[rsp+0x228] (store at '
              '0x2ae22ed), and calls pre_4ab at 0x2ae2306 with '
              'rdx = &[rsp+0x60].  pre_4ab stores '
              'descriptor[0] at its [rsp+0x48] (0x2453622) '
              'and &[rsp+0x48] at [rsp+0x50] (0x245362c), and '
              'calls call4a_b at 0x2453673 with rdx = '
              '&[rsp+0x50]; call4a_b loads rbp = [rdx] and '
              'then rdi = [rbp+0] (0x2b40573) = descriptor[0] '
              '= &[lvl4_c rsp+0x5aa8], and calls lvl4_a at '
              '0x2b40577 with rsi = its entry rcx (pre_4ab\'s '
              'pair cell).  The buffer at that moment holds '
              'the copy-5 memcpy result (0x2ae1b1f): nothing '
              'on the guard path stores into the buffer '
              'region between the copy and the pre_4ab call '
              '(the buffer census covers the whole body).',
    'producer': 'the b-side producer is therefore identical '
                'to the a-side producer of question 1: '
                'lvl4_c\'s memcpy from ctor_c\'s frame, over '
                'bytes that are stack residue above the '
                'registrar boundary except for ctor_c\'s '
                'three zeroed offsets.  Unlike the spawn '
                'chain of the earlier packets, this '
                'indirection resolves completely inside '
                'statically pinned frames.',
}

BOUNDARIES = {
    'registrar_invocation': 'who invokes ctor_c at runtime, '
                            'on what schedule and with what '
                            'stack history, is not statically '
                            'reachable: the registration is '
                            'the binary\'s main storing '
                            '&ctor_c in a stack cell and '
                            'calling the registrar body '
                            '0x5c99970 with the key cell '
                            '0x6440b48 as key; no other '
                            'instruction in the binary '
                            'references ctor_c, the key cell '
                            'or the registrar slot, and the '
                            'registrar\'s own caller is '
                            'likewise only the stub\'s GOT '
                            'call.  This packet states the '
                            'boundary; it does not trace the '
                            'registrar\'s runtime table.',
    'arm0_record_inputs': 'what builder_c and lvl4_a\'s '
                          'inlined build read beyond the '
                          '"hl-node" key -- in particular what '
                          'the config fetch through GOT slot '
                          '0x64e0a80 (R_X86_64_RELATIVE, body '
                          '0x1506840) returns to both shapers\' '
                          'entry sequences, and what the '
                          '0x64df480-slot call allocates -- is '
                          'recorded as an open edge, not '
                          'traced here.',
    'other_copies': 'of lvl4_c\'s three non-buffer memcpy '
                    'destinations, [rsp+0x86e8] has no reader '
                    'in the body at all and [rsp+0x220] / '
                    '[rsp+0x2e68] are read as records (not as '
                    'phase structs) on the arms that build '
                    'them; whether any consumer treats those '
                    'copies as phase structs on paths outside '
                    'the traced arms is not decided here.',
    'next_questions': 'what the 0x64e0a80 config fetch '
                      'returns and what builder_c reads from '
                      'it; who invokes ctor_c through the '
                      'registrar\'s runtime table (the '
                      'boundary above this chain); whether '
                      'the record the gate body 0x2cb6500 '
                      'accepts feeds any further phase '
                      'construction downstream',
}

LIMITS = (
    'Static trace only: no captured instruction was executed '
    'and no concrete input values were observed.  The '
    'classified censuses classify each instruction of the '
    'censused bodies by operand position in fresh objdump '
    'text (a mov-family bracket destination is a store, a '
    'bracket source is a load, a lea bracket is an '
    'address-taken); register identity follows the entry '
    'assignments (rbx = rdi in lvl4_a, set once at 0x2ae41f1; '
    'r13 = [[rdi+8]] in lvl3_c, set once at 0x2cde495; rsp in '
    'lvl4_c does not move between the prologue at 0x2ae16b8 '
    'and the epilogue, so its frame offsets are absolute for '
    'the whole body; rsp in ctor_c moves in three known steps '
    'and its phase offsets are derived arithmetically in the '
    'findings, with the phase base at final [rsp+0x8]).  A '
    'whole-struct copy moves bytes without naming fields: '
    'the five lvl4_c memcpys and lvl3_c\'s 0x98-byte rebuild '
    'copy are enumerated as call sites with pinned argument '
    'setups, so for copied fields the census is a statement '
    'about direct accesses and the copies actually observed.  '
    'Arm attribution (which stores dominate which loads) '
    'follows the entry dispatch structure read from the '
    'disassembly: the jmp-table dispatch on the +0x21a byte '
    'at each shaper\'s entry, the rebuild blocks that '
    'immediately precede shaping site 1 on the entry arm, and '
    'lvl4_c\'s two arm memcpys; jump-table arm reachability '
    'beyond that structure is not re-decided here.  The '
    'registrar body is pinned and its argument saves are '
    'cited; its internal runtime behaviour is not reversed '
    'in this packet.  Raw values are recorded mechanically; '
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
    return raw.split(b'\0', 1)[0].decode('ascii')


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


def caller_census(data):
    _, fdes, _ = fde_extents(data)
    ordered = sorted((f['start'], f['end']) for f in fdes)
    starts = [s for s, _ in ordered]

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and ordered[i][0] <= va < ordered[i][1]:
            return f'{ordered[i][0]:#x}..{ordered[i][1]:#x}'
        return None

    text_sec = next(s for s in sections(data) if s['name'] == '.text')
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
        for i in range(section['offset'],
                       section['offset'] + section['size'], 24):
            off, info, addend = struct.unpack_from('<QQq', data, i)
            entries[off] = (info & 0xFFFFFFFF, info >> 32, addend)
    return entries


def rip_references(data, target):
    """Every rip-relative reference to target in .text (the
    record-producer census: REX-prefixed modrm-checked scan)."""
    text_sec = next(s for s in sections(data) if s['name'] == '.text')
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
    dynsym = next(s for s in sections(data) if s['name'] == '.dynsym')
    dynstr = next(s for s in sections(data) if s['name'] == '.dynstr')
    name_off = struct.unpack_from(
        '<I', data, dynsym['offset'] + index * 24)[0]
    start = dynstr['offset'] + name_off
    end = data.index(b'\0', start)
    return data[start:end].decode('ascii')


def ff15_sites_in_body(data, role, slot):
    """FF 15 call sites to a GOT slot inside one owner body."""
    start, end = int(OWNERS[role][0], 16), int(OWNERS[role][1], 16)
    _, body = read(start, data, end - start)
    sites = []
    i = body.find(b'\xff\x15')
    while i != -1:
        va = start + i
        if va + 6 + struct.unpack_from('<i', body, i + 2)[0] == slot:
            sites.append(hex(va))
        i = body.find(b'\xff\x15', i + 1)
    return sites


def got_census(data):
    entries = rela_entries(data)
    records = {}
    for name, spec in GOT_SPECS.items():
        slot = spec['slot']
        got = entries.get(slot)
        check(got is not None and got[0] == spec['type'] and
              got[2] == spec['callee'],
              f'GOT slot {slot:#x} relocation mismatch')
        refs = rip_references(data, slot)
        sites = [hex(va) for va in refs]
        check(sites == spec['ff15_sites'],
              f'GOT slot {slot:#x} reference census mismatch: {sites}')
        records[name] = {
            'slot': hex(slot), 'relocation': 'R_X86_64_RELATIVE',
            'callee': hex(spec['callee']),
            'rip_relative_references': sites}
    got = entries.get(COPY_SLOT)
    check(got is not None and got[0] == 6 and got[2] == 0,
          'copy slot relocation mismatch')
    symbol = dynsym_name(data, got[1])
    check(symbol == 'memcpy', f'copy slot symbol mismatch: {symbol}')
    sites = ff15_sites_in_body(data, 'lvl4_c', COPY_SLOT)
    check(sites == COPY_CALL_SITES,
          f'copy call sites in lvl4_c mismatch: {sites}')
    records['copy_slot'] = {
        'slot': hex(COPY_SLOT), 'relocation': 'R_X86_64_GLOB_DAT',
        'symbol': symbol, 'lvl4_c_ff15_sites': sites}
    got = entries.get(CONFIG_SLOT)
    check(got is not None and got[0] == 8 and got[2] == 0x1506840,
          'config slot relocation mismatch')
    records['config_slot'] = {
        'slot': hex(CONFIG_SLOT), 'relocation': 'R_X86_64_RELATIVE',
        'callee': hex(0x1506840)}
    return records


def key_cell_census(data):
    entries = rela_entries(data)
    check(KEY_CELL not in entries,
          'key cell unexpectedly carries a relocation')
    _, raw = read(KEY_CELL, data, 8)
    check(struct.unpack('<Q', raw)[0] == 0,
          'key cell file contents are not zero')
    refs = [hex(va) for va in rip_references(data, KEY_CELL)]
    check(refs == ['0x2cef902'],
          f'key cell reference census mismatch: {refs}')
    return {'cell': hex(KEY_CELL), 'file_qword': '0x0',
            'relocation': None, 'rip_relative_references': refs}


def lvl4c_frame_census(data):
    text = objdump_text(data, 'lvl4_c')
    stores, loads, leas, other_dst = classify_accesses(text, {'rsp'})

    def region(off):
        value = int(off, 16)
        if BUFFER_OFF <= value < HICOPY_OFF:
            return 'buffer'
        if HICOPY_OFF <= value < FRAME_END:
            return 'hicopy'
        return None

    records = {f'{r}_{label}': {}
               for r in ('buffer', 'hicopy')
               for label in ('stores', 'loads', 'leas', 'other_dst')}
    for label, table in (('stores', stores), ('loads', loads),
                         ('leas', leas), ('other_dst', other_dst)):
        for reg in table:
            for off, vas in table[reg].items():
                r = region(off)
                if r is None:
                    continue
                key = f'{r}_{label}'
                records.setdefault(key, {})[off.lstrip('+')] = \
                    [hex(va) for va in vas]
    for key, want in LVL4C_FRAME.items():
        if key.startswith('entry_slot'):
            continue
        check(records.get(key, {}) == want,
              f'lvl4_c frame census mismatch {key}: '
              f'{records.get(key, {})}')
    entry_stores = [hex(va) for va in
                    stores.get('rsp', {}).get('+0x18', [])]
    entry_loads = [hex(va) for va in
                   loads.get('rsp', {}).get('+0x18', [])]
    check(entry_stores == LVL4C_FRAME['entry_slot_stores'],
          f'entry slot stores mismatch: {entry_stores}')
    check(entry_loads == LVL4C_FRAME['entry_slot_loads'],
          f'entry slot loads mismatch: {entry_loads}')
    records['entry_slot_stores'] = entry_stores
    records['entry_slot_loads'] = entry_loads
    return records


def small_census(data):
    records = {}
    for role, spec in SMALL_CENSUS.items():
        text = objdump_text(data, role)
        stores, loads, leas, _ = classify_accesses(text, {'rsp'})
        rec = {'stores': _counts(stores), 'loads': _counts(loads),
               'leas': _counts(leas)}
        check(rec == spec, f'{role} small census mismatch: {rec}')
        records[role] = rec
    return records


def shaper_census(data):
    records = {}
    for role, reg in (('lvl4_a', 'rbx'), ('lvl3_c', 'r13')):
        text = objdump_text(data, role)
        stores, loads, leas, _ = classify_accesses(text, {reg})
        rec = {'stores': _counts(stores), 'loads': _counts(loads),
               'leas': _counts(leas),
               'store_sites': _hexsites(stores)}
        spec = SHAPER_SPECS[role]
        check(rec['stores'] == spec['stores'],
              f'{role} store census mismatch')
        check(rec['loads'] == spec['loads'],
              f'{role} load census mismatch')
        check(rec['leas'] == spec['leas'],
              f'{role} lea census mismatch')
        check(rec['store_sites'] == spec['store_sites'],
              f'{role} store sites mismatch')
        records[role] = rec
    return records


def analyze(data):
    owner_records = owners(data)
    pin_records = check_pins(data)
    check_call_targets(data)
    _, key_raw = read(KEY_STRING, data, 7)
    key_string = key_raw.decode('ascii')
    check(key_string == 'hl-node',
          f'builder key string mismatch: {key_string!r}')
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
        'key_cell': key_cell_census(data),
        'builder_key_string': {'va': hex(KEY_STRING), 'length': 7,
                               'value': key_string,
                               'note': 'length-prefixed in the '
                                       'code (edi = 0x7 at the '
                                       'allocation); the .rodata '
                                       'bytes are not NUL-terminated '
                                       'here ("hl-node" is followed '
                                       'immediately by "no wallet")'},
        'call_census': caller_census(data),
        'lvl4c_frame_census': lvl4c_frame_census(data),
        'small_census': small_census(data),
        'shaper_census': shaper_census(data),
        'phase_producer': PHASE_PRODUCER,
        'field_attribution': FIELD_ATTRIBUTION,
        'b_side': B_SIDE,
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
