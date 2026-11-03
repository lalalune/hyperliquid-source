#!/usr/bin/env python3
"""Node 115: what the GOT-slot 0x64e0a80 "config fetch" returns.

The phase-producer packet (RE-005-node115-phase-producer)
recorded an open edge: on the dispatch arm ctor_c's zeroed byte
selects, lvl4_a (0x2ae41e0) calls through GOT slot 0x64e0a80
(R_X86_64_RELATIVE, body 0x1506840) before building the
0x98-byte record, and lvl3_c (0x2cde430) calls builder_c
(0x2b7b640), whose record is keyed by the .rodata string
"hl-node".  The edge asked what the 0x64e0a80 call returns and
what the builders read from it beyond the key.

Answers, all static and re-derived by analyze() below:

1. The slot resolves to body 0x1506840..0x15069f2 (434 bytes).
   It has exactly four rip-relative references in the binary,
   all FF 15 calls: lvl4_a at 0x2ae4281, the body 0x2aeaef0 at
   0x2aeb2e0, the gate body 0x2cb6500 at 0x2cb68f0 and lvl3_c
   at 0x2cde525.  It has no direct (E8) or tail (E9) caller.
   builder_c never references it.
2. The callee is not a fetch and produces nothing its callers
   consume.  Its only argument is rdi, a pointer to a 0x50-byte
   struct the caller has just seeded on its own stack
   (sentinel qwords 0x8000000000000000 at +0x0/+0x18/+0x30,
   the dword 0x64 at +0x48, the byte ([0x64f01b0] == 2) at
   +0x4c, a word at +0x4d).  A complete bracket census of the
   body shows eight loads through rdi (+0x0, +0x8, +0x18,
   +0x20, +0x30, +0x38, +0x48, +0x4c) and NO store through
   rdi; every store lands in the callee's own frame.  No
   caller tests rax after the call (the next instructions are
   pinned at all four sites).
3. What the body does with the struct: if its head qword is
   0x8000000000000001 it stages a default from globals -- the
   lazy-state dword at 0x64f01b8 (with a once-init arm through
   the 0x64df9f0 slot), the state byte at 0x64f01b0 compared
   to 2, the 16-byte .rodata constant at 0x454950, the
   sentinel for +0x0/+0x18/+0x30 and 0xa for +0x48 -- and on
   every other head value it stages a byte copy of the
   caller's [rdi..rdi+0x50].  Either way the staged copy at
   [rsp+0x18] is passed, with the global pointer loaded from
   slot 0x64e0a88 (R_X86_64_RELATIVE to the .data struct at
   0x64efd00), to the predicate body 0x14c2a40.  The
   predicate likewise never stores through its staged-copy
   argument (rbx = rsi; its bracket census through rbx is
   loads only): it asks the 0x64dffe0-slot callee about the
   global's +0x18 field, emits through the 0x64df4b8 log slot
   and, on the disabled arm, compares the staged copy against
   the global with the direct callee 0x154c2c0, whose result
   is the predicate's return.  Only when the predicate
   returns nonzero does the fetch body emit log records of
   its own -- a descriptor naming the .rodata string
   "base/src/log/state.rs" (0x44b81d, 21 bytes) through the
   0x64e0a90 slot and a message descriptor (string at
   0x465a54, first 22 bytes "enable_log not applied") through
   the 0x64df4b8 log slot.  The call is a log-state check on
   a caller-seeded default struct; it contributes no bytes
   to anything.
4. The 0x98-byte record's actual producers are the lookup
   callees the shapers and builder_c run after (or, for
   builder_c, instead of) the check.  lookup_a (slot
   0x64e1d08, body 0x163a4b0) writes a 0x250-byte default
   entry into its rdi: the "hl-node" key descriptor is copied
   to entry +0x20..+0x38, sentinels land at +0x38/+0x50/
   +0x68, the constants 0x3e7 at +0x110, 0x1020700 at +0x1e8
   and 0x11000000110000 at +0x248, and a complete store
   census shows the window [entry+0x40, entry+0x50) is never
   stored -- the caller's seeded +0x48 dword and +0x4c/+0x4d
   bytes survive there (in builder_c the entry is a fresh
   stack slot, so the window is that frame's residue).
   lookup_b (slot 0x64e73c0, body 0x564d700) transforms the
   entry in the slot that held the key descriptor; lookup_c
   (slot 0x64e1da8, body 0x165de90) memcpy's 0x250 bytes from
   that slot into its own frame and delegates the output
   write to its worker 0x165dfb0.  builder_c then tests the
   converted value's head qword against 0x8000000000000001:
   on that arm it writes the record itself -- record +0x0 =
   0x10 and record +0x8..+0x40 copied from the value's
   +0x8..+0x40, nothing at +0x40..+0x98 -- and on the other
   arm lookup_d (slot 0x64e73c8, body 0x564cce0) rewrites
   the entry in place and builder_c memcpy's its first 0x98
   bytes out.  lookup_d's complete store census through its
   entry pointer (rbx = rdi) is twelve sites: +0x0..+0x78
   copied from the value the 0x64ebcb0-slot callee builds out
   of the converted value's +0x48 sub-object (or the defaults
   {0, 1, 0} when that pointer is null), +0x78 and +0x88 set
   to the length of the converted value's "key" field (the
   3-byte key at 0x92ab2c, looked up through the direct
   callee 0x4e4ca30), +0x80 set to a fresh copy of that
   string's bytes, and the byte at +0x90 set from the "chain"
   field (the 5-byte key at 0x92a7be): "Local" -> 0,
   "Sandbox" -> 1, "Testnet" -> 2, "Mainnet" -> 3, decided
   by pinned byte compares; a missing "chain" field takes a
   panic arm.  Record bytes +0x91..+0x98 are lookup_a's
   (its +0x90 qword store is 0; lookup_d overwrites only the
   +0x90 byte).

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
WORK_ITEM = 'RE-005-node115-config-fetch'
OUT = ROOT / 'research/work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

CONFIG_SLOT = 0x64E0A80
CONFIG_CALLEE = 0x1506840
GLOBAL_BYTE = 0x64F01B0
GLOBAL_DWORD = 0x64F01B8
GLOBAL_STRUCT = 0x64EFD00
KEY_STRING = 0x92A890
FILE_STRING = 0x44B81D
MSG_STRING = 0x465A54
CHAIN_KEY = 0x92A7BE
KEY_KEY = 0x92AB2C
UNWRAP_STRING = 0x92A732
ARM_A_CONST = 0x454950
SENTINEL = 0x8000000000000000

OWNERS = {
    'config_fetch': ('0x1506840', '0x15069f2',
        '34189b04fb9454d33dbe002156516ed83a2d63ae8e98c63b88a6d87119287c71'),
    'predicate': ('0x14c2a40', '0x14c2b4c',
        '3859bdfff5581cd4525e6c586973fbf0e01d847b4f676b5afcefd76137bb1d84'),
    'builder_c': ('0x2b7b640', '0x2b7b79c',
        '1ce5b5a8e849cc065b72f30af834a79f75454bd412d8c67df9137859bbcc8003'),
    'lookup_a': ('0x163a4b0', '0x163a66c',
        '579d70a866d9befafc51745673ad60ec4bd4d0c261e33deea54d8fea06690b88'),
    'lookup_b': ('0x564d700', '0x564df8c',
        'd80ed0188335a8ce1b4587d9248f8010c61b066fb162a5129e90f968905fe7bf'),
    'lookup_c': ('0x165de90', '0x165dfaa',
        '74c6473d58677655e2e99becf0abe03d3a1f31bcf251ad92e390520ad846aeae'),
    'c_worker': ('0x165dfb0', '0x165e513',
        'a074b2b22ad5683f183a1e2ea1516c71da55af8b3d9683b5d489aa7f79cf74a2'),
    'lookup_d': ('0x564cce0', '0x564cf36',
        'e69561afd60a4ae323867f1eb25f2a6997c85c488524e15bf0ca9f9fed100e92'),
    'lvl4_a': ('0x2ae41e0', '0x2ae6d66',
        '90ae09003ca680bd4b5f32fec22ee1f7146cc1f67b758f8e2f2ac880545b730b'),
    'lvl3_c': ('0x2cde430', '0x2ce0dd1',
        '99c49a3e20f63cf199f2a160ba9560e439acb2b49a66968623aa9607acfa417b'),
}

FRAMES = {
    'config_fetch': {
        'fde': {'va': '0xcb155c', 'bytes_hex':
                '2400000088a60000dc528500b201000000410e10470ec0018302036b010e10410e08410ec0010000'},
        'cie': {'va': '0xca6ed8', 'bytes_hex':
                '1400000000000000017a5200017810011b0c070890010000'}},
    'predicate': {
        'fde': {'va': '0x1046ca4', 'bytes_hex':
                '38000000a496000094bd47000c010000047fbe12ff420e10420e18410e20440e800183048e038f0202dd0e20410e18420e10420e08410e8001000000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
                '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'builder_c': {
        'fde': {'va': '0x11860d0', 'bytes_hex':
                '3c000000d08a140068559f015c0100000437410eff420e10420e18410e20470e900a83048e038f020321010e20410e18420e10420e08410e900a000000000000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
                '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'lookup_a': {
        'fde': {'va': '0xcbf7d0', 'bytes_hex':
                '10000000fc880100d8ac9700bc01000000000000'},
        'cie': {'va': '0xca6ed8', 'bytes_hex':
                '1400000000000000017a5200017810011b0c070890010000'}},
    'lookup_b': {
        'fde': {'va': '0x13677d8', 'bytes_hex':
                '50000000d8a13200205f2e048c08000004c33505ff410e10420e18420e20420e28420e30410e38470ee01983078c068d058e048f038602038a070e38410e30420e28420e20420e18420e10410e08410ee0190000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
                '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'lookup_c': {
        'fde': {'va': '0x1067a88', 'bytes_hex':
                '4000000088a4020000645f001a01000004733f12ff420e10420e18420e20410e28470ea00583058c048e038f0202c70e28410e20420e18420e10420e08410ea005000000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
                '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'c_worker': {
        'fde': {'va': '0x1067acc', 'bytes_hex':
                '50000000cca40200dc645f006305000004633f12ff410e10420e18420e20420e28420e30410e38470eb00283078c068d058e048f038602036f040e38410e30420e28420e20420e18420e10410e08410eb0020000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
                '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'lookup_d': {
        'fde': {'va': '0x13676e0', 'bytes_hex':
                '50000000e0a03200f8552e045602000004533605ff410e10420e18420e20420e28420e30410e38470ed00183078c068d058e048f03860203e7010e38410e30420e28420e20420e18420e10410e08410ed0010000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
                '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'lvl4_a': {
        'fde': {'va': '0x117c49c', 'bytes_hex':
                '500000009cee13003c7d9601862b00000417260eff410e10420e18420e20420e28420e30410e38470ee01f83078c068d058e048f03860203791c0e38410e30420e28420e20420e18420e10410e08410ee01f0000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
                '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'lvl3_c': {
        'fde': {'va': '0x11986ac', 'bytes_hex':
                '50000000acb015007c5db401a12900000493f70dff410e10420e18420e20420e28420e30410e38470ee00983078c068d058e048f03860203f11a0e38410e30420e28420e20420e18420e10410e08410ee0090000'},
        'cie': {'va': '0x103d604', 'bytes_hex':
                '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
}

# Bodies small enough to export in full (<= ~4 KB).
EXPORTED = ('config_fetch', 'predicate', 'builder_c', 'lookup_a',
            'lookup_b', 'lookup_c', 'c_worker', 'lookup_d')

PINS = {
    'config_fetch': [
        (0x12, '488b07',
         'mov rax,QWORD PTR [rdi]: the head qword load -- the '
         'only [rdi] load outside the copy arm'),
        (0x15, '488d4b01', 'lea rcx,[rbx+0x1] with rbx = the '
         'sentinel: the tag value 0x8000000000000001'),
        (0x19, '4839c8', 'cmp rax,rcx: the arm split'),
        (0x1e, '8b055499fe04',
         'mov eax,DWORD PTR [0x64f01b8]: the lazy-state dword'),
        (0x2e, '803d3b99fe0402',
         'cmp BYTE PTR [0x64f01b0],0x2: the state byte'),
        (0x35, '0f94c0', 'sete al: the flag byte'),
        (0x3c, '660feb05cce0f4fe',
         'por xmm0,XMMWORD PTR [0x454950]: the .rodata constant '
         'ORed with the flag'),
        (0x44, 'b90a000000',
         'mov ecx,0xa: the default arm\'s +0x48 dword'),
        (0x51, '0f104708',
         'movups xmm0,XMMWORD PTR [rdi+0x8]: the copy arm\'s '
         'first load'),
        (0x85, '4889442418',
         'mov QWORD PTR [rsp+0x18],rax: the staged copy begins '
         'in the callee\'s own frame'),
        (0xc5, '488b3d7ca1fd04',
         'mov rdi,QWORD PTR [0x64e0a88]: the global pointer '
         'loaded from the neighbouring slot'),
        (0xcc, '488d742418',
         'lea rsi,[rsp+0x18]: the staged copy is the '
         'predicate\'s second argument'),
        (0xd1, 'e82ac1fbff', 'call 0x14c2a40: the predicate'),
        (0xd6, '84c0', 'test al,al: the log arm split'),
        (0xde, '488d05f84ef4fe',
         'lea rax,[0x44b81d]: the "base/src/log/state.rs" '
         'descriptor pointer'),
        (0x100, 'e89bd97704',
         'call 0x5c842e0: the log arm\'s first direct callee'),
        (0x10d, 'ff153da1fd04',
         'call QWORD PTR [0x64e0a90]: the log gate slot'),
        (0x11c, '488d05f1f0f5fe',
         'lea rax,[0x465a54]: the message descriptor pointer'),
        (0x127, '48c74424082d000000',
         'mov QWORD PTR [rsp+0x8],0x2d: the message '
         'descriptor\'s second qword'),
        (0x166, 'ff150c8bfd04',
         'call QWORD PTR [0x64df4b8]: the log emission slot'),
        (0x188, '488d3de997fe04',
         'lea rdi,[0x64f01b8]: the once-init arm takes the '
         'state dword\'s address'),
        (0x1a7, 'ff150390fd04',
         'call QWORD PTR [0x64df9f0]: the once-init slot'),
    ],
    'predicate': [
        (0x9, '4889f3',
         'mov rbx,rsi: the staged copy pointer, held for the '
         'whole body'),
        (0xc, '4989fe',
         'mov r14,rdi: the global struct pointer'),
        (0xf, '4c8d7f18', 'lea r15,[rdi+0x18]'),
        (0x1b, '8b4740',
         'mov eax,DWORD PTR [rdi+0x40]: the global arm split'),
        (0x29, 'ff1571d50105',
         'call QWORD PTR [0x64dffe0]: the enabled check, with '
         'rdi = global+0x18 and rsi/rdx = the global\'s +0x8 '
         'and +0x10 fields'),
        (0x51, 'ff1521ca0105',
         'call QWORD PTR [0x64df4b8]: the predicate\'s own log '
         'emission'),
        (0xdd, 'e89e970800',
         'call 0x154c2c0: the staged-vs-global comparison on '
         'the disabled arm'),
        (0xef, 'e8e0061100',
         'call 0x15d3214: the nonzero-+0x40 arm\'s helper'),
    ],
    'builder_c': [
        (0xc, '4889fb',
         'mov rbx,rdi: the output record pointer (carried from '
         'the phase-producer packet)'),
        (0x14, 'ff15263e9603',
         'call QWORD PTR [0x64df480] with edi = 0x7: the key '
         'allocation (carried pin)'),
        (0x34, '48c744245007000000',
         'mov QWORD PTR [rsp+0x50],0x7: the key descriptor\'s '
         'first qword'),
        (0x5b, 'ff1567669603',
         'call QWORD PTR [0x64e1d08]: lookup_a, rdi = '
         '&[rsp+0x2a0] (the fresh entry slot), rsi = the key '
         'descriptor'),
        (0x6c, 'ff150ebd9603',
         'call QWORD PTR [0x64e73c0]: lookup_b, rdi = the key '
         'descriptor slot, rsi = the entry'),
        (0x78, 'ff15ea669603',
         'call QWORD PTR [0x64e1da8]: lookup_c, rdi = rsp '
         '(the converted value out), rsi = the lookup_b slot'),
        (0x7e, '48b80100000000000080',
         'movabs rax,0x8000000000000001: the value tag test '
         'constant'),
        (0x88, '48390424',
         'cmp QWORD PTR [rsp],rax: the converted value\'s head '
         'against the tag'),
        (0x8e, '488b442438',
         'mov rax,QWORD PTR [rsp+0x38]: the tagged arm copies '
         'the value\'s +0x38'),
        (0x93, '48894338',
         'mov QWORD PTR [rbx+0x38],rax: ... into record +0x38'),
        (0xb2, '48c70310000000',
         'mov QWORD PTR [rbx],0x10: the tagged arm\'s record '
         'head'),
        (0xff, 'ff1583bc9603',
         'call QWORD PTR [0x64e73c8]: lookup_d, rdi = the '
         'entry, rsi = &[rsp+0x50] (the copied value)'),
        (0x115, 'ba98000000',
         'mov edx,0x98: the record length'),
        (0x11d, 'ff15a53d9603',
         'call QWORD PTR [0x64df508]: memcpy of the entry\'s '
         'first 0x98 bytes into the record'),
    ],
    'lookup_a': [
        (0x0, '4889f8', 'mov rax,rdi: the entry pointer is the '
         'return value'),
        (0x3, '488b4e10',
         'mov rcx,QWORD PTR [rsi+0x10]: the key descriptor\'s '
         'third qword'),
        (0x7, '48894f30',
         'mov QWORD PTR [rdi+0x30],rcx: ... lands at entry '
         '+0x30'),
        (0xb, '0f1006',
         'movups xmm0,XMMWORD PTR [rsi]: the key descriptor\'s '
         'first 16 bytes'),
        (0xe, '0f114720',
         'movups XMMWORD PTR [rdi+0x20],xmm0: ... land at '
         'entry +0x20'),
        (0x1c, '48894f38',
         'mov QWORD PTR [rdi+0x38],rcx with rcx = the '
         'sentinel: entry +0x38'),
        (0x6d, '48894f50',
         'mov QWORD PTR [rdi+0x50],rcx: entry +0x50 sentinel'),
        (0x7c, '48894f68',
         'mov QWORD PTR [rdi+0x68],rcx: entry +0x68 sentinel'),
        (0x8b, '48c78710010000e7030000',
         'mov QWORD PTR [rdi+0x110],0x3e7'),
        (0x96, '48c70700000000',
         'mov QWORD PTR [rdi],0x0: the entry head is zeroed, '
         'not tagged'),
        (0xb0, '48c787e801000000070201',
         'mov QWORD PTR [rdi+0x1e8],0x1020700'),
        (0x17e, '48b90000110000001100',
         'movabs rcx,0x11000000110000'),
        (0x188, '48898f48020000',
         'mov QWORD PTR [rdi+0x248],rcx: the constant lands '
         'at entry +0x248'),
    ],
    'lookup_c': [
        (0x14, '488d7c2428',
         'lea rdi,[rsp+0x28]: the local entry copy destination'),
        (0x19, 'ba50020000', 'mov edx,0x250: the entry length'),
        (0x1e, 'ff155416e804',
         'call QWORD PTR [0x64df508]: memcpy of the entry from '
         'rsi (the lookup_b slot)'),
        (0x29, 'ff15d133e804',
         'call QWORD PTR [0x64e1290]: the context init, rdi = '
         '&[rsp+0x8]'),
        (0x3c, 'e8df000000',
         'call 0x165dfb0: the worker that writes the output '
         '(rdi = out, rsi = the entry copy, rdx = the '
         'context)'),
        (0x46, 'e895060000',
         'call 0x165e570: the entry copy\'s drop'),
    ],
    'c_worker': [
        (0x11, '4989d7', 'mov r15,rdx: the context pointer'),
        (0x17, '4889fb', 'mov rbx,rdi: the output pointer'),
        (0x1a, '4c8da6e8010000',
         'lea r12,[rsi+0x1e8]: the worker reads the entry '
         'starting at +0x1e8'),
    ],
    'lookup_d': [
        (0x17, '488d35c0da2dfb',
         'lea rsi,[0x92a7be]: the "chain" key'),
        (0x1e, 'ba05000000', 'mov edx,0x5: the key length'),
        (0x26, 'e825fd7fff',
         'call 0x4e4ca30: the field lookup, rdi = the '
         'converted value'),
        (0x40, 'b94c6f6361',
         'mov ecx,0x61636f4c: "Loca" -- the "Local" compare'),
        (0x56, 'b953616e64',
         'mov ecx,0x646e6153: "Sand" -- the "Sandbox" compare'),
        (0x69, 'b954657374',
         'mov ecx,0x74736554: "Test" -- the "Testnet" compare'),
        (0x7c, 'b94d61696e',
         'mov ecx,0x6e69614d: "Main" -- the "Mainnet" compare'),
        (0xbf, '488d3586dd2dfb',
         'lea rsi,[0x92ab2c]: the "key" key'),
        (0xc6, 'ba03000000', 'mov edx,0x3: the key length'),
        (0x177, 'ff1553eee900',
         'call QWORD PTR [0x64ebcb0]: the value builder, rdi '
         '= &[rsp+0x20] out, rsi = &[rsp+0x8] descriptor'),
        (0x17d, '837c242010',
         'cmp DWORD PTR [rsp+0x20],0x10: the built value\'s '
         'tag takes a panic arm'),
        (0x1d5, '4088ab90000000',
         'mov BYTE PTR [rbx+0x90],bpl: the chain tag byte '
         'lands at record +0x90'),
    ],
    'lvl4_a': [
        (0x45, '8b058dbfa003',
         'mov eax,DWORD PTR [0x64f01b8]: the lazy-state dword '
         'guard before the seed'),
        (0x5d, '803d6cbfa00302',
         'cmp BYTE PTR [0x64f01b0],0x2: the state byte the '
         'seed\'s flag derives from'),
        (0x64, '4889ac24d0000000',
         'seed: mov QWORD PTR [rsp+0xd0],rbp (rbp = the '
         'sentinel) at struct +0x0'),
        (0x6c, '4889ac24e8000000',
         'seed: mov QWORD PTR [rsp+0xe8],rbp at struct +0x18'),
        (0x74, '0f9484241c010000',
         'seed: sete BYTE PTR [rsp+0x11c] at struct +0x4c'),
        (0x7c, '66c784241d0100000001',
         'seed: mov WORD PTR [rsp+0x11d],0x100 at struct +0x4d'),
        (0x86, '4889ac2400010000',
         'seed: mov QWORD PTR [rsp+0x100],rbp at struct +0x30'),
        (0x8e, 'c784241801000064000000',
         'seed: mov DWORD PTR [rsp+0x118],0x64 at struct +0x48'),
        (0x99, '488dbc24d0000000',
         'lea rdi,[rsp+0xd0]: the seeded struct is the '
         'callee\'s only argument'),
        (0xa1, 'ff15f9c79f03',
         'call QWORD PTR [0x64e0a80]: the config check'),
        (0xa7, 'bf07000000',
         'mov edi,0x7: the instruction after the call -- rax '
         'is not tested'),
        (0xfc, 'ff1526da9f03',
         'call QWORD PTR [0x64e1d08]: lookup_a on the same '
         'struct slot, rsi = the key descriptor at '
         '[rsp+0x380]'),
    ],
    'lvl3_c': [
        (0x96, '8b05ec1c8103',
         'mov eax,DWORD PTR [0x64f01b8]: the lazy-state dword '
         'guard'),
        (0xae, '803dcb1c810302',
         'cmp BYTE PTR [0x64f01b0],0x2: the state byte'),
        (0xb5, '4c89bc2490010000',
         'seed: mov QWORD PTR [rsp+0x190],r15 (the sentinel) '
         'at struct +0x0'),
        (0xbd, '4c89bc24a8010000',
         'seed: mov QWORD PTR [rsp+0x1a8],r15 at struct +0x18'),
        (0xc5, '0f948424dc010000',
         'seed: sete BYTE PTR [rsp+0x1dc] at struct +0x4c'),
        (0xcd, '66c78424dd0100000001',
         'seed: mov WORD PTR [rsp+0x1dd],0x100 at struct +0x4d'),
        (0xd7, '4c89bc24c0010000',
         'seed: mov QWORD PTR [rsp+0x1c0],r15 at struct +0x30'),
        (0xdf, 'c78424d801000064000000',
         'seed: mov DWORD PTR [rsp+0x1d8],0x64 at struct +0x48'),
        (0xea, '4c8db42490010000',
         'lea r14,[rsp+0x190]: the seeded struct'),
        (0xf5, 'ff1555258003',
         'call QWORD PTR [0x64e0a80]: the config check'),
        (0xfb, '488dbc2410040000',
         'lea rdi,[rsp+0x410]: the instruction after the call '
         'sets up builder_c\'s record buffer -- rax is not '
         'tested'),
    ],
}

# Byte pins at absolute VAs, for the two config-check call
# sites that are not packet owners (the body 0x2aeaef0 and the
# gate body 0x2cb6500).  Both seed the same struct shape and
# pass its address in rdi.
SITE_PINS = [
    (0x2aeb276, '8b053c4fa003',
     'body 0x2aeaef0: mov eax,DWORD PTR [0x64f01b8] -- the '
     'lazy-state guard'),
    (0x2aeb284, '803d254fa00302',
     'body 0x2aeaef0: cmp BYTE PTR [0x64f01b0],0x2'),
    (0x2aeb295, '48898424e0030000',
     'body 0x2aeaef0: seed sentinel at struct +0x0 '
     '([rsp+0x3e0])'),
    (0x2aeb2ad, 'c784242804000064000000',
     'body 0x2aeaef0: seed mov DWORD PTR [rsp+0x428],0x64 at '
     'struct +0x48'),
    (0x2aeb2d8, '488dbc24e0030000',
     'body 0x2aeaef0: lea rdi,[rsp+0x3e0]'),
    (0x2aeb2e0, 'ff159a579f03',
     'body 0x2aeaef0: call QWORD PTR [0x64e0a80]'),
    (0x2cb6886, '8b052c998303',
     'gate body 0x2cb6500: mov eax,DWORD PTR [0x64f01b8]'),
    (0x2cb6894, '803d1599830302',
     'gate body 0x2cb6500: cmp BYTE PTR [0x64f01b0],0x2'),
    (0x2cb68a5, '4889842430070000',
     'gate body 0x2cb6500: seed sentinel at struct +0x0 '
     '([rsp+0x730])'),
    (0x2cb68bd, 'c784247807000064000000',
     'gate body 0x2cb6500: seed mov DWORD PTR [rsp+0x778],'
     '0x64 at struct +0x48'),
    (0x2cb68e8, '488dbc2430070000',
     'gate body 0x2cb6500: lea rdi,[rsp+0x730]'),
    (0x2cb68f0, 'ff158aa18203',
     'gate body 0x2cb6500: call QWORD PTR [0x64e0a80]'),
]

# GOT slots this packet re-derives: name -> (slot, rela type,
# addend).  Type 8 is R_X86_64_RELATIVE.  The memcpy slot is
# type 6 (GLOB_DAT) and is checked by symbol instead.
SLOT_TABLE = {
    'config_slot': (CONFIG_SLOT, 8, CONFIG_CALLEE),
    'config_global_ptr_slot': (0x64E0A88, 8, GLOBAL_STRUCT),
    'config_log_gate_slot': (0x64E0A90, 8, 0x1563D10),
    'config_log_fn_slot': (0x64E0A98, 8, 0x1689420),
    'lookup_a_slot': (0x64E1D08, 8, 0x163A4B0),
    'lookup_b_slot': (0x64E73C0, 8, 0x564D700),
    'lookup_c_slot': (0x64E1DA8, 8, 0x165DE90),
    'lookup_d_slot': (0x64E73C8, 8, 0x564CCE0),
    'alloc_slot': (0x64DF480, 8, 0x6355830),
    'once_init_slot': (0x64DF9F0, 8, 0x5C87D50),
    'log_emit_slot': (0x64DF4B8, 8, 0x5C9B900),
    'pred_check_slot': (0x64DFFE0, 8, 0x154CD10),
    'dealloc_slot': (0x64DF4A0, 8, 0x635DE30),
    'ctx_init_slot': (0x64E1290, 8, 0x5C9A530),
    'value_build_slot': (0x64EBCB0, 8, 0x5654BF0),
    'panic_unwrap_slot': (0x64DF6A0, 8, 0x1680C30),
    'panic_body_slot': (0x64DF830, 8, 0x1680C10),
    'alloc_error_slot': (0x64DF498, 8, 0x141E264),
}
COPY_SLOT = 0x64DF508

# The config slot's complete rip-relative reference list
# (series census method: REX-prefixed modrm-checked forms and
# FF 15/FF 25), with the containing FDE of each site.
CONFIG_SLOT_REFS = {
    '0x2ae4281': '0x2ae41e0..0x2ae6d66',
    '0x2aeb2e0': '0x2aeaef0..0x2af0654',
    '0x2cb68f0': '0x2cb6500..0x2cbbbdf',
    '0x2cde525': '0x2cde430..0x2ce0dd1',
}

# In-body rip-relative target maps, read off instruction-
# aligned objdump text: site -> (kind, target).  kind is
# 'call' for an FF 15 call, 'lea' for an address-taken, and
# 'use' for any other rip operand (loads, compares).
RIP_MAPS = {
    'config_fetch': {
        '0x150685e': ('use', '0x64f01b8'),
        '0x150686e': ('use', '0x64f01b0'),
        '0x150687c': ('use', '0x454950'),
        '0x1506905': ('use', '0x64e0a88'),
        '0x150691e': ('lea', '0x44b81d'),
        '0x150694d': ('call', '0x64e0a90'),
        '0x150695c': ('lea', '0x465a54'),
        '0x1506978': ('lea', '0x14ce760'),
        '0x150698e': ('use', '0x64e0a98'),
        '0x150699a': ('lea', '0x448b05'),
        '0x15069a6': ('call', '0x64df4b8'),
        '0x15069b5': ('lea', '0x64f01b0'),
        '0x15069c8': ('lea', '0x64f01b8'),
        '0x15069cf': ('lea', '0x63fe2b8'),
        '0x15069d6': ('lea', '0x63fe278'),
        '0x15069e7': ('call', '0x64df9f0'),
    },
    'predicate': {
        '0x14c2a69': ('call', '0x64dffe0'),
        '0x14c2a7b': ('lea', '0x15ebba0'),
        '0x14c2a87': ('lea', '0x448a8e'),
        '0x14c2a91': ('call', '0x64df4b8'),
        '0x14c2aa5': ('call', '0x64df4a0'),
        '0x14c2aba': ('call', '0x64df4a0'),
        '0x14c2ad1': ('call', '0x64df4a0'),
        '0x14c2b0b': ('lea', '0x63f8db0'),
    },
    'builder_c': {
        '0x2b7b654': ('call', '0x64df480'),
        '0x2b7b663': ('use', '0x92a893'),
        '0x2b7b66c': ('use', '0x92a890'),
        '0x2b7b69b': ('call', '0x64e1d08'),
        '0x2b7b6ac': ('call', '0x64e73c0'),
        '0x2b7b6b8': ('call', '0x64e1da8'),
        '0x2b7b73f': ('call', '0x64e73c8'),
        '0x2b7b75d': ('call', '0x64df508'),
        '0x2b7b77d': ('call', '0x64df498'),
        '0x2b7b796': ('call', '0x64df4c0'),
    },
    'lookup_c': {
        '0x165deae': ('call', '0x64df508'),
        '0x165deb9': ('call', '0x64e1290'),
        '0x165df08': ('use', '0x64df4a0'),
        '0x165df55': ('call', '0x64df4a0'),
        '0x165df8b': ('call', '0x64df4c0'),
        '0x165dfa4': ('call', '0x64df4c0'),
    },
    'lookup_d': {
        '0x564ccf7': ('lea', '0x92a7be'),
        '0x564cd72': ('lea', '0x92a732'),
        '0x564cd79': ('lea', '0x64aae00'),
        '0x564cd80': ('lea', '0x64ab288'),
        '0x564cd91': ('call', '0x64df6a0'),
        '0x564cd9f': ('lea', '0x92ab2c'),
        '0x564cdc5': ('call', '0x64df498'),
        '0x564cdeb': ('call', '0x64df480'),
        '0x564ce06': ('call', '0x64df508'),
        '0x564ce57': ('call', '0x64ebcb0'),
        '0x564cee3': ('lea', '0x64ab258'),
        '0x564ceea': ('call', '0x64df830'),
        '0x564cef0': ('lea', '0x64ab270'),
        '0x564cef7': ('call', '0x64df830'),
        '0x564cf07': ('call', '0x64df498'),
        '0x564cf25': ('call', '0x64df4a0'),
    },
}

# Direct (E8) call maps, read off the same aligned text.
E8_MAPS = {
    'config_fetch': {'0x1506911': '0x14c2a40',
                     '0x1506940': '0x5c842e0'},
    'predicate': {'0x14c2b1d': '0x154c2c0',
                  '0x14c2b2f': '0x15d3214',
                  '0x14c2b3f': '0x14c5640',
                  '0x14c2b47': '0x63f0a50'},
    'builder_c': {'0x2b7b748': '0x2ab8cc0',
                  '0x2b7b789': '0x2ab8cc0',
                  '0x2b7b791': '0x63f0a50'},
    'lookup_c': {'0x165decc': '0x165dfb0',
                 '0x165ded6': '0x165e570',
                 '0x165df7a': '0x165e570',
                 '0x165df84': '0x1675a40',
                 '0x165df97': '0x165e570',
                 '0x165df9f': '0x63f0a50'},
    'lookup_d': {'0x564cd06': '0x4e4ca30',
                 '0x564cdae': '0x4e4ca30',
                 '0x564cf31': '0x63f0a50'},
}

# Bracket-access censuses (site lists by offset).
CONFIG_FETCH_RDI_LOADS = {
    '0x0': ['0x1506852'], '0x8': ['0x1506891'],
    '0x18': ['0x150689d'], '0x20': ['0x15068a1'],
    '0x30': ['0x15068ad'], '0x38': ['0x15068b1'],
    '0x48': ['0x15068bd'], '0x4c': ['0x15068c0']}
PREDICATE_RBX_LOADS = {
    '0x0': ['0x14c2a97', '0x14c2ae4'], '0x8': ['0x14c2a9f'],
    '0x10': ['0x14c2ae7'], '0x18': ['0x14c2aab'],
    '0x20': ['0x14c2ab4', '0x14c2aeb'],
    '0x30': ['0x14c2ac0', '0x14c2aef'], '0x38': ['0x14c2acb'],
    '0x40': ['0x14c2adb']}
LOOKUP_A_RDI_STORES = {
    '0x0': ['0x163a546'], '0x10': ['0x163a54d'],
    '0x20': ['0x163a4be'], '0x30': ['0x163a4b7'],
    '0x38': ['0x163a4cc'], '0x50': ['0x163a51d'],
    '0x68': ['0x163a52c'], '0x80': ['0x163a4d0'],
    '0x90': ['0x163a4db'], '0xa0': ['0x163a4e6'],
    '0xb0': ['0x163a4f1'], '0xc0': ['0x163a4fc'],
    '0xd0': ['0x163a507'], '0xe0': ['0x163a512'],
    '0xf0': ['0x163a521'], '0x100': ['0x163a530'],
    '0x110': ['0x163a53b'], '0x118': ['0x163a555'],
    '0x128': ['0x163a576'], '0x130': ['0x163a581'],
    '0x138': ['0x163a58f'], '0x148': ['0x163a596'],
    '0x150': ['0x163a5b7'], '0x160': ['0x163a5be'],
    '0x168': ['0x163a5c9'], '0x178': ['0x163a5d0'],
    '0x180': ['0x163a5db'], '0x190': ['0x163a5e2'],
    '0x198': ['0x163a5ed'], '0x1a8': ['0x163a5f4'],
    '0x1b0': ['0x163a5ff'], '0x1c0': ['0x163a606'],
    '0x1c8': ['0x163a611'], '0x1d8': ['0x163a618'],
    '0x1e0': ['0x163a623'], '0x1e8': ['0x163a560'],
    '0x1f0': ['0x163a56b'], '0x1f8': ['0x163a5a1'],
    '0x208': ['0x163a5ac'], '0x210': ['0x163a63f'],
    '0x220': ['0x163a64a'], '0x230': ['0x163a655'],
    '0x240': ['0x163a660'], '0x248': ['0x163a638']}
LOOKUP_D_RBX_STORES = {
    '0x0': ['0x564ceb2'], '0x10': ['0x564ceae'],
    '0x20': ['0x564ceaa'], '0x30': ['0x564cea6'],
    '0x40': ['0x564ce8e'], '0x50': ['0x564ce85'],
    '0x60': ['0x564ce7c'], '0x70': ['0x564ce70'],
    '0x78': ['0x564cebc'], '0x80': ['0x564cec0'],
    '0x88': ['0x564cec7'], '0x90': ['0x564ceb5']}

CONFIG_FETCH = {
    'question': 'what does the config fetch through GOT slot '
                '0x64e0a80 return, and what do builder_c and '
                'lvl4_a\'s inlined build read from it beyond '
                'the "hl-node" key (phase-producer packet, '
                'open edge 1)',
    'slot': 'GOT slot 0x64e0a80 carries exactly one '
            'R_X86_64_RELATIVE relocation, addend 0x1506840; '
            'the callee body is 0x1506840..0x15069f2 (434 '
            'bytes).  Its complete rip-relative reference '
            'list (series census method) is four FF 15 call '
            'sites: 0x2ae4281 in lvl4_a, 0x2aeb2e0 in the body '
            '0x2aeaef0..0x2af0654, 0x2cb68f0 in the gate body '
            '0x2cb6500..0x2cbbbdf, and 0x2cde525 in lvl3_c.  '
            'No instruction anywhere calls or tail-calls '
            '0x1506840 directly (the E8/E9 census for the '
            'callee is empty), and builder_c (0x2b7b640) '
            'contains no reference to the slot at all: its '
            'rip-target map is pinned and the slot is not in '
            'it.',
    'argument': 'the callee\'s only argument is rdi, a '
                'pointer to a 0x50-byte struct the caller '
                'seeded on its own stack immediately before '
                'the call.  Both shaper seeds are pinned '
                'byte-for-byte: sentinel qwords '
                '0x8000000000000000 at +0x0/+0x18/+0x30 '
                '(lvl4_a stores at 0x2ae4244/0x2ae424c/'
                '0x2ae4266 over base [rsp+0xd0]; lvl3_c at '
                '0x2cde4e5/0x2cde4ed/0x2cde507 over base '
                '[rsp+0x190]), the dword 0x64 at +0x48, the '
                'sete byte ([0x64f01b0] == 2) at +0x4c and '
                'the word 0x100 at +0x4d, each preceded by '
                'the lazy-state guard (the dword load at '
                '0x2ae4225 / 0x2cde4c6 and its init arm).  '
                'The other two callers seed the same shape '
                '(sentinels at +0x0, the 0x64 dword at +0x48, '
                'the sete byte at +0x4c; their pinned stores '
                'are in the packet as absolute site pins, '
                'with the +0x4d byte copied from their '
                'caller\'s [rbx+0x11d] and a 0x1 word at '
                '+0x4e).',
    'return': 'nothing.  A complete bracket census of the '
              'callee classifies eight loads through rdi '
              '(+0x0 at 0x1506852, then the copy arm\'s '
              '+0x8/+0x18/+0x20/+0x30/+0x38/+0x48/+0x4c at '
              '0x1506891..0x15068c0) and no store through '
              'rdi, no lea of rdi, and no other-destination '
              'access: every store in the body lands in the '
              'callee\'s own frame ([rsp+0x18] staging and '
              'the log-arm descriptors).  The struct the '
              'caller seeded is byte-identical after the '
              'call.  No caller consumes a return value: '
              'after lvl4_a\'s call the next instruction '
              '(0x2ae4287) loads edi = 0x7 for the key '
              'allocation, after lvl3_c\'s call the next '
              'instruction (0x2cde52b) loads rdi with '
              'builder_c\'s record buffer, and the other '
              'two sites continue with loads from their own '
              'frames (0x2aeb2e6, 0x2cb68f6); no test of rax '
              'follows any of the four calls.',
    'body': 'the callee compares the struct\'s head qword '
            '([rdi], 0x1506852) against 0x8000000000000001 '
            '(0x1506859).  On the equal arm it stages a '
            'default built from globals: the lazy-state '
            'dword at 0x64f01b8 (0x150685e; a nonzero value '
            'first takes the once-init arm at 0x15069b5, '
            'which calls the 0x64df9f0-slot body 0x5c87d50 '
            'with rdi = &0x64f01b8), the state byte at '
            '0x64f01b0 compared to 2 (0x150686e, sete at '
            '0x1506875), that flag ORed into the 16-byte '
            '.rodata constant at 0x454950 (por at '
            '0x150687c; the constant is 00 00 01 00 followed '
            'by zeros, so the staged +0x4c byte is the flag '
            'and the +0x4d word is 0x100), the sentinel for '
            'the staged +0x0/+0x18/+0x30 and 0xa (0x1506884) '
            'for the staged +0x48 dword.  On the other arm '
            'it stages a byte copy of the caller\'s '
            '[rdi..rdi+0x50] (loads at 0x1506891..'
            '0x15068c0).  The three 16-byte fields of the '
            'default arm\'s staging (+0x8..+0x18, '
            '+0x20..+0x30, +0x38..+0x48) are read from the '
            'callee\'s own frame slots at [rsp+0xa0], '
            '[rsp+0x90] and [rsp+0x80], which that arm never '
            'writes; only the copy arm writes them (from '
            'the caller\'s struct).  Both arms converge on '
            'the store sequence at 0x15068c5, which lays '
            'the staged 0x50 bytes at [rsp+0x18].',
    'predicate_call': 'the callee then loads rdi from slot '
                      '0x64e0a88 (0x1506905; the slot\'s '
                      'R_X86_64_RELATIVE addend is the .data '
                      'struct at 0x64efd00, whose first four '
                      'file qwords are 0, 0, 9, 0) and calls '
                      'the predicate body 0x14c2a40 directly '
                      '(0x1506911) with rsi = &[rsp+0x18].  '
                      'If the predicate returns zero the '
                      'callee returns at once (test at '
                      '0x1506916); the caller\'s struct was '
                      'never touched either way.',
    'log_arm': 'when the predicate returns nonzero, the '
               'callee builds a location descriptor at '
               '[rsp+0x68] -- pointer 0x44b81d (the .rodata '
               'string "base/src/log/state.rs", 21 bytes, at '
               '0x150691e), the qword 0x15 at +0x8 and the '
               'dword 0x31 at +0x10 -- calls 0x5c842e0 with '
               'edi = 1 (0x1506940), passes the descriptor '
               'and that result through slot 0x64e0a90 (body '
               '0x1563d10, call at 0x150694d), and only if '
               'the low bit of the result is set builds a '
               'message descriptor at [rsp] -- pointer '
               '0x465a54 (0x150695c; the .rodata bytes there '
               'begin "enable_log not applied", 22 bytes, '
               'immediately followed by "log_state") and the '
               'qword 0x2d -- and emits through slot '
               '0x64df4b8 (body 0x5c9b900, call at '
               '0x15069a6) with rdi = 0x448b05 and an '
               'argument array at [rsp+0x18] holding the '
               'message descriptor\'s address, the function '
               'pointer 0x14ce760, the address of the saved '
               'staged +0x18 qword and the value loaded '
               'from slot 0x64e0a98 (addend 0x1689420).',
}

PREDICATE = {
    'body': 'the predicate 0x14c2a40..0x14c2b4c (268 bytes) '
            'takes rdi = the global struct at 0x64efd00 and '
            'rsi = the staged copy.  It holds rsi in rbx '
            '(0x14c2a49) and rdi in r14 (0x14c2a4c).  A '
            'complete bracket census through rbx shows '
            'loads only -- the staged fields at +0x0/+0x8 '
            '(0x14c2a97, 0x14c2a9f), +0x18/+0x20 (0x14c2aab, '
            '0x14c2ab4), +0x30/+0x38 (0x14c2ac0, 0x14c2acb) '
            'and the wholesale copy loads at +0x0..+0x40 '
            '(0x14c2ae4..0x14c2aef) and +0x40 (0x14c2adb) '
            '-- and no store through rbx: the staged copy '
            'is read, never written.',
    'arms': 'if the global\'s dword at +0x40 is nonzero '
            '(0x14c2a5b) the predicate first calls '
            '0x15d3214 with rdi = global+0x18 (0x14c2b2f).  '
            'It then calls the 0x64dffe0-slot body '
            '0x154cd10 (0x14c2a69) with rdi = global+0x18, '
            'rsi = the global\'s +0x8 qword and rdx = its '
            '+0x10 qword.  If that returns nonzero, the '
            'predicate emits its own log record through '
            'slot 0x64df4b8 (0x14c2a91, rdi = 0x448a8e) and '
            'validates each of the staged copy\'s three '
            '{length, pointer} fields (+0x0/+0x8, '
            '+0x18/+0x20, +0x30/+0x38): for each nonzero '
            'length it calls the 0x64df4a0-slot body '
            '0x635de30 with (pointer, length, 0) (calls at '
            '0x14c2aa5, 0x14c2aba, 0x14c2ad1), then returns '
            '1.  If the check returns zero, the predicate '
            'copies the staged 0x50 bytes into its own '
            'frame, appends the global pointer, and calls '
            '0x154c2c0 (0x14c2b1d) with rdi = global+0x18, '
            'edx = 1 and rcx = 0x63f8db0; that call\'s '
            'result is the predicate\'s return value.',
}

RECORD_ATTRIBUTION = {
    'question': 'per-field attribution for the 0x98-byte '
                'record builder_c assembles (and lvl4_a '
                'builds inlined), now that the config check '
                'is shown to contribute nothing',
    'builder_c_sequence': 'builder_c never calls the config '
                          'check (its rip-target map has no '
                          '0x64e0a80 entry).  It allocates '
                          'the 7-byte key through slot '
                          '0x64df480 (body 0x6355830), writes '
                          'the "hl-node" bytes into it from '
                          '0x92a890, and forms the key '
                          'descriptor {7, pointer, 7} at '
                          '[rsp+0x50].  Then, in order: '
                          'lookup_a (call at 0x2b7b69b) with '
                          'rdi = &[rsp+0x2a0] and rsi = the '
                          'key descriptor; lookup_b (call '
                          'at 0x2b7b6ac) with rdi = '
                          '&[rsp+0x50] and rsi = '
                          '&[rsp+0x2a0]; lookup_c (call at '
                          '0x2b7b6b8) with rdi = rsp and '
                          'rsi = &[rsp+0x50].  lvl4_a runs '
                          'the same three calls inlined on '
                          'its dispatch arm, after the '
                          'config check, with the entry at '
                          '[rsp+0xd0] and the key descriptor '
                          'at [rsp+0x380].',
    'lookup_a': 'lookup_a (0x163a4b0..0x163a66c) returns '
                'rdi and writes the 0x250-byte default '
                'entry there.  Its complete store census '
                'through rdi (44 store sites) shows: the '
                'key descriptor is copied verbatim to '
                'entry +0x20 (movups at 0x163a4be) and '
                '+0x30 (the descriptor\'s third qword, at '
                '0x163a4b7); the sentinel lands at +0x38 '
                '(0x163a4cc), +0x50 (0x163a51d) and +0x68 '
                '(0x163a52c); the head +0x0 and +0x10 are '
                'zeroed (0x163a546, 0x163a54d); +0x110 '
                'takes 0x3e7 (0x163a53b), +0x1e8 takes '
                '0x1020700 (0x163a560), +0x248 takes '
                '0x11000000110000 (0x163a638); nine '
                '{0, 0, 8} triples and the remaining '
                'single qwords are zeroed as the census '
                'table lists.  No store in the census '
                'covers the window [entry+0x40, '
                'entry+0x50): in lvl4_a the caller\'s '
                'seeded +0x48 dword (0x64), +0x4c flag '
                'byte and +0x4d word survive into the '
                'entry there, the +0x40 qword is written '
                'by neither the seed nor lookup_a, and in '
                'builder_c the whole window is the fresh '
                'frame\'s residue.',
    'lookup_b': 'lookup_b (0x564d700..0x564df8c, 2188 '
                'bytes) is called with rdi = the slot that '
                'held the key descriptor and rsi = the '
                'entry; lookup_c then memcpy\'s 0x250 '
                'bytes from that slot, so the slot holds '
                'the entry lookup_c converts.  lookup_b\'s '
                'internal reads and writes are not '
                'reversed in this packet (see boundaries).',
    'lookup_c': 'lookup_c (0x165de90..0x165dfaa) memcpy\'s '
                'the 0x250-byte entry from its rsi into '
                'its own frame (call at 0x165deae, length '
                'pinned at 0x165dea9), initialises a '
                'context at [rsp+0x8] through slot '
                '0x64e1290 (call at 0x165deb9), and calls '
                'its worker 0x165dfb0 (0x165decc) with '
                'rdi = the output pointer, rsi = the entry '
                'copy and rdx = the context; the worker '
                'holds rdi in rbx and first reads the '
                'entry at +0x1e8 (lea at 0x165dfca).  '
                'lookup_c then drops the entry copy '
                'through 0x165e570 (0x165ded6) and '
                'releases the context\'s string vector '
                'through the 0x64df4a0 dealloc slot.  '
                'The converted value lookup_c leaves at '
                'its rdi is what builder_c tests and '
                'lookup_d queries.',
    'tagged_arm': 'builder_c compares the converted '
                  'value\'s head qword at [rsp] against '
                  '0x8000000000000001 (movabs at '
                  '0x2b7b6be, cmp at 0x2b7b6c8).  On the '
                  'equal arm it writes the record itself: '
                  'record +0x0 = 0x10 (store at '
                  '0x2b7b6f2) and record +0x8..+0x40 '
                  'copied from the value\'s +0x8..+0x40 '
                  '(the movups copies at 0x2b7b6d7..'
                  '0x2b7b6ee and the +0x38 qword at '
                  '0x2b7b6d3).  It stores nothing at '
                  'record +0x40..+0x98 on this arm; those '
                  'bytes are the record buffer\'s prior '
                  'contents (in lvl3_c, its stack).',
    'lookup_d_arm': 'on the other arm builder_c copies '
                    'the converted value over the key '
                    'descriptor slot, calls lookup_d '
                    '(0x2b7b73f) with rdi = the entry and '
                    'rsi = the copy, drops the value '
                    'through 0x2ab8cc0, and memcpy\'s the '
                    'entry\'s first 0x98 bytes into the '
                    'record (length at 0x2b7b755, call at '
                    '0x2b7b75d).  lookup_d\'s complete '
                    'store census through its entry '
                    'pointer is twelve sites: +0x0, '
                    '+0x10, +0x20, +0x30, +0x40, +0x50, '
                    '+0x60 and +0x70 (the copies at '
                    '0x564ceb2..0x564ce70) take the '
                    '0x78-byte value the 0x64ebcb0-slot '
                    'callee 0x5654bf0 builds at '
                    'lookup_d\'s [rsp+0x20] (call at '
                    '0x564ce57) from a descriptor '
                    '{[rsp+0x8], [rsp+0x10], [rsp+0x18]} '
                    'formed out of the converted value\'s '
                    '+0x48 sub-object -- its +0x8, +0x10 '
                    'and base+0x18 -- or the defaults '
                    '{rdx = 1, rax = 0, rcx = 0} when that '
                    'pointer is null; +0x78 (0x564cebc) '
                    'and +0x88 (0x564cec7) take the "key" '
                    'field\'s length; +0x80 (0x564cec0) '
                    'takes a fresh allocation (slot '
                    '0x64df480) holding a copy of that '
                    'string\'s bytes (memcpy at '
                    '0x564ce06); and the byte at +0x90 '
                    '(0x564ceb5) takes the chain tag.  '
                    'When the "key" field is absent '
                    '(the lookup at 0x564cdae returns '
                    'null), +0x78 and +0x88 take the '
                    'sentinel 0x8000000000000000 and no '
                    'instruction on that arm writes r12, '
                    'so +0x80 takes the caller\'s r12 '
                    '(in lvl4_a, the entry pointer set '
                    'at 0x2ae42ea).  When the built '
                    'value\'s head dword is 0x10 the arm '
                    'takes a panic call instead (cmp at '
                    '0x564ce5d).',
    'chain_tag': 'the tag byte comes from the converted '
                 'value\'s "chain" field: lookup_d looks '
                 'the 5-byte key at 0x92a7be ("chain") up '
                 'through the direct callee 0x4e4ca30 '
                 '(call at 0x564cd06, length at '
                 '0x564ccfe).  A 5-byte value equal to '
                 '"Local" (the xor compares at '
                 '0x564cd20/0x564cd27) gives 0; a 7-byte '
                 'value equal to "Sandbox" (0x564cd36) '
                 'gives 1, to "Testnet" (0x564cd49) gives '
                 '2, to "Mainnet" (0x564cd5c) gives 3.  '
                 'Any other value, or a missing field, '
                 'takes the panic arms: the unwrap call '
                 'through slot 0x64df6a0 with the 43-byte '
                 'message at 0x92a732 ("called '
                 '`Result::unwrap()` on an `Err` value", '
                 'call at 0x564cd91) or the panic bodies '
                 'through slot 0x64df830 (calls at '
                 '0x564ceea, 0x564cef7).',
    'tail': 'record bytes +0x91..+0x98 are lookup_a\'s: '
            'its +0x90 qword store (0x163a4db) writes 0 '
            'across +0x90..+0x98, and lookup_d overwrites '
            'only the single byte at +0x90.  On the '
            'tagged arm those bytes are not the '
            'builder\'s at all (see tagged_arm).',
    'fetch_role': 'the config check\'s only connection to '
                  'the record is ordering: in the two '
                  'shapers it runs on the seeded struct '
                  'before lookup_a overwrites that struct '
                  'as the entry, and its default arm reads '
                  'the same two globals (0x64f01b0, '
                  '0x64f01b8) the shapers\' seeds derive '
                  'their +0x4c flag from.  It reads the '
                  'seed and the globals; it writes '
                  'nothing any later instruction can '
                  'observe.',
}

BOUNDARIES = {
    'lookup_b_internals': 'what lookup_b (0x564d700) '
                          'reads and writes inside the '
                          'slot it transforms -- in '
                          'particular whether it consults '
                          'any global or the key string '
                          'beyond the entry it is handed '
                          '-- is not reversed in this '
                          'packet; only its call contract '
                          'and the 0x250-byte extent '
                          'lookup_c copies are pinned.',
    'c_worker_internals': 'how lookup_c\'s worker '
                          '0x165dfb0 converts the entry '
                          'into the value lookup_d '
                          'queries -- which entry fields '
                          'become the "chain" and "key" '
                          'fields and the +0x48 sub-object '
                          '-- is not reversed in this '
                          'packet; the worker is pinned as '
                          'an owner and its argument '
                          'contract is recorded.',
    'value_builder': 'what the 0x64ebcb0-slot callee '
                     '0x5654bf0 builds from lookup_d\'s '
                     'descriptor, and what the predicate\'s '
                     'comparison callee 0x154c2c0 and '
                     'check callee 0x154cd10 compute, are '
                     'one level below this packet\'s '
                     'bodies and are not reversed here.',
    'global_struct_writers': 'who writes the .data '
                             'struct at 0x64efd00 and the '
                             'lazy-state byte/dword at '
                             '0x64f01b0/0x64f01b8 at '
                             'runtime is not traced; the '
                             'packet pins their file '
                             'contents and every static '
                             'reader on the traced paths.',
    'next_questions': 'what lookup_b reads beyond the '
                      'entry; how the worker 0x165dfb0 '
                      'maps entry fields to the converted '
                      'value\'s "chain"/"key" fields; who '
                      'consumes the record\'s +0x78/+0x80/'
                      '+0x88 "key" triple and +0x90 chain '
                      'tag downstream (the gate body '
                      '0x2cb6500 loads [rbx+0x78] and '
                      '[rbx+0x80] immediately after its '
                      'own config check at 0x2cb68f6); '
                      'who writes the log-state struct at '
                      '0x64efd00',
}

LIMITS = (
    'Static trace only: no captured instruction was '
    'executed and no concrete input values were observed.  '
    'The bracket censuses classify each instruction of the '
    'censused bodies by operand position in fresh objdump '
    'text (a mov-family bracket destination is a store, a '
    'bracket source is a load, a lea bracket is an '
    'address-taken); register identity follows the entry '
    'assignments (rbx = rsi in the predicate, set once at '
    '0x14c2a49; rbx = rdi in lookup_d, set once at '
    '0x564ccf4; rdi in config_fetch and lookup_a is the '
    'entry argument throughout).  The config slot\'s '
    'binary-wide reference list uses the series census '
    'method (REX-prefixed modrm-checked forms and FF '
    '15/FF 25 over .text); the four references it finds '
    'are each pinned byte-for-byte at instruction '
    'boundaries, and the in-body rip-target maps are read '
    'from instruction-aligned objdump text, not from the '
    'byte scan.  A whole-struct copy moves bytes without '
    'naming fields: the copies (the callee\'s staging, '
    'lookup_c\'s 0x250-byte memcpy, builder_c\'s 0x98-byte '
    'memcpy, lookup_d\'s [rsp+0x20] value copy) are '
    'enumerated as call sites with pinned argument '
    'setups, so for copied fields the census is a '
    'statement about direct accesses and the copies '
    'actually observed.  Arm attribution follows the '
    'branch structure read from the disassembly (the head-'
    'qword compares, the predicate\'s test, the chain '
    'field\'s length and byte compares); reachability '
    'beyond that structure is not re-decided here.  '
    'Strings are read through the section table (.rodata '
    'is identity-mapped in this ELF, .text resolves at '
    'VA - 0x1000 and .data.rel.ro at VA - 0x2000, all '
    'through the section headers, never by a fixed '
    'delta), and every named string is re-read on every '
    'run and fails closed on drift.  Raw values are '
    'recorded mechanically; no field types are guessed.')


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
    return raw.decode('ascii')


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
    for va, expected, _ in SITE_PINS:
        got = read(va, data, len(bytes.fromhex(expected)))[1]
        check(got.hex() == expected,
              f'site pin mismatch at {va:#x}')
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
        for i in range(section['offset'],
                       section['offset'] + section['size'], 24):
            off, info, addend = struct.unpack_from('<QQq', data, i)
            entries[off] = (info & 0xFFFFFFFF, info >> 32, addend)
    return entries


def rip_references(data, target):
    """Every rip-relative reference to target in .text (the
    series census: REX-prefixed modrm-checked scan plus the
    FF 15/FF 25 forms)."""
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


def slot_census(data):
    entries = rela_entries(data)
    records = {}
    for name, (slot, rtype, addend) in SLOT_TABLE.items():
        got = entries.get(slot)
        check(got is not None and got[0] == rtype and
              got[2] == addend,
              f'slot {slot:#x} relocation mismatch')
        records[name] = {'slot': hex(slot),
                         'relocation': 'R_X86_64_RELATIVE',
                         'callee': hex(addend)}
    got = entries.get(COPY_SLOT)
    check(got is not None and got[0] == 6 and got[2] == 0,
          'copy slot relocation mismatch')
    symbol = dynsym_name(data, got[1])
    check(symbol == 'memcpy', f'copy slot symbol mismatch: {symbol}')
    records['copy_slot'] = {'slot': hex(COPY_SLOT),
                            'relocation': 'R_X86_64_GLOB_DAT',
                            'symbol': symbol}
    return records


def config_slot_census(data):
    _, fdes, _ = fde_extents(data)
    ordered = sorted((f['start'], f['end']) for f in fdes)
    starts = [s for s, _ in ordered]

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and ordered[i][0] <= va < ordered[i][1]:
            return f'{ordered[i][0]:#x}..{ordered[i][1]:#x}'
        return None

    refs = [hex(va) for va in rip_references(data, CONFIG_SLOT)]
    records = {site: containing(int(site, 16)) for site in refs}
    check(records == CONFIG_SLOT_REFS,
          f'config slot reference census mismatch: {records}')
    # No direct or tail call anywhere targets the callee.
    text_sec = next(s for s in sections(data) if s['name'] == '.text')
    base, off, size = (text_sec['address'], text_sec['offset'],
                       text_sec['size'])
    body = bytes(data[off:off + size])
    for opcode in (b'\xe8', b'\xe9'):
        i = body.find(opcode)
        while i != -1:
            target = (base + i + 5 +
                      struct.unpack_from('<i', body, i + 1)[0])
            check(target != CONFIG_CALLEE,
                  f'direct call to the config callee at '
                  f'{base + i:#x}')
            i = body.find(opcode, i + 1)
    return {'slot': hex(CONFIG_SLOT), 'callee': hex(CONFIG_CALLEE),
            'rip_relative_references': records,
            'direct_or_tail_callers': []}


def body_censuses(data):
    records = {}
    text = objdump_text(data, 'config_fetch')
    stores, loads, leas, other = classify_accesses(text, {'rdi'})
    check(stores == {} and leas == {} and other == {},
          f'config_fetch rdi census: unexpected non-load access '
          f'{stores} {leas} {other}')
    got = _hexsites(loads).get('rdi', {})
    check(got == CONFIG_FETCH_RDI_LOADS,
          f'config_fetch rdi load census mismatch: {got}')
    records['config_fetch_rdi'] = {'stores': {}, 'leas': {},
                                  'other_dst': {}, 'loads': got}
    text = objdump_text(data, 'predicate')
    stores, loads, leas, other = classify_accesses(text, {'rbx'})
    check(stores == {} and leas == {} and other == {},
          f'predicate rbx census: unexpected non-load access '
          f'{stores} {leas} {other}')
    got = _hexsites(loads).get('rbx', {})
    check(got == PREDICATE_RBX_LOADS,
          f'predicate rbx load census mismatch: {got}')
    records['predicate_rbx'] = {'stores': {}, 'leas': {},
                                'other_dst': {}, 'loads': got}
    text = objdump_text(data, 'lookup_a')
    stores, loads, leas, other = classify_accesses(text, {'rdi'})
    check(loads == {} and leas == {} and other == {},
          f'lookup_a rdi census: unexpected non-store access '
          f'{loads} {leas} {other}')
    got = _hexsites(stores).get('rdi', {})
    check(got == LOOKUP_A_RDI_STORES,
          f'lookup_a rdi store census mismatch')
    records['lookup_a_rdi'] = {'stores': got, 'loads': {},
                               'leas': {}, 'other_dst': {}}
    text = objdump_text(data, 'lookup_d')
    stores, loads, leas, other = classify_accesses(text, {'rbx'})
    check(loads == {} and leas == {} and other == {},
          f'lookup_d rbx census: unexpected non-store access '
          f'{loads} {leas} {other}')
    got = _hexsites(stores).get('rbx', {})
    check(got == LOOKUP_D_RBX_STORES,
          f'lookup_d rbx store census mismatch: {got}')
    records['lookup_d_rbx'] = {'stores': got, 'loads': {},
                               'leas': {}, 'other_dst': {}}
    return records


def call_maps(data):
    records = {}
    for role, want_rip in RIP_MAPS.items():
        rip, direct = rip_map(data, role)
        got = {site: (kind, target) for site, (kind, target)
               in rip.items()}
        check(got == want_rip,
              f'{role} rip map mismatch: {got}')
        check(direct == E8_MAPS[role],
              f'{role} direct call map mismatch: {direct}')
        records[role] = {
            'rip_targets': {site: {'kind': kind, 'target': target}
                            for site, (kind, target)
                            in sorted(rip.items())},
            'direct_calls': direct}
    # The two shapers: exactly one config-slot call each.
    for role, site in (('lvl4_a', '0x2ae4281'),
                       ('lvl3_c', '0x2cde525')):
        rip, _ = rip_map(data, role)
        hits = [s for s, (_, t) in rip.items()
                if t == hex(CONFIG_SLOT)]
        check(hits == [site],
              f'{role} config slot sites mismatch: {hits}')
        records[role] = {'config_slot_sites': hits}
    return records


def strings_and_globals(data):
    key = read_string(KEY_STRING, data, 7)
    check(key == 'hl-node', f'key string mismatch: {key!r}')
    file_str = read_string(FILE_STRING, data, 21)
    check(file_str == 'base/src/log/state.rs',
          f'file string mismatch: {file_str!r}')
    check(read(FILE_STRING + 21, data, 1)[1] == b'\0',
          'file string is not NUL-terminated at 21')
    chain = read_string(CHAIN_KEY, data, 5)
    check(chain == 'chain', f'chain key mismatch: {chain!r}')
    key_key = read_string(KEY_KEY, data, 3)
    check(key_key == 'key', f'key key mismatch: {key_key!r}')
    msg = read_string(MSG_STRING, data, 45)
    check(msg[:22] == 'enable_log not applied',
          f'message prefix mismatch: {msg[:22]!r}')
    check(msg[22:31] == 'log_state',
          f'message continuation mismatch: {msg[22:31]!r}')
    unwrap = read_string(UNWRAP_STRING, data, 43)
    check(unwrap == 'called `Result::unwrap()` on an `Err` value',
          f'unwrap string mismatch: {unwrap!r}')
    const = read(ARM_A_CONST, data, 16)[1]
    check(const.hex() == '00000100000000000000000000000000',
          f'arm-A constant mismatch: {const.hex()}')
    check(section_name(GLOBAL_BYTE, data) == '.data' and
          section_name(GLOBAL_DWORD, data) == '.data' and
          section_name(GLOBAL_STRUCT, data) == '.data',
          'global section mismatch')
    byte_val = read(GLOBAL_BYTE, data, 1)[1][0]
    dword_val = struct.unpack('<I', read(GLOBAL_DWORD, data, 4)[1])[0]
    qwords = [hex(q) for q in
              struct.unpack('<4Q', read(GLOBAL_STRUCT, data, 32)[1])]
    check(byte_val == 0 and dword_val == 3 and
          qwords == ['0x0', '0x0', '0x9', '0x0'],
          f'global file contents mismatch: {byte_val} '
          f'{dword_val} {qwords}')
    return {
        'key_string': {'va': hex(KEY_STRING), 'length': 7,
                       'value': key},
        'file_string': {'va': hex(FILE_STRING), 'length': 21,
                        'value': file_str,
                        'note': 'NUL-terminated at 21 bytes; '
                                'the descriptor the callee '
                                'builds carries length 0x15 '
                                'and the dword 0x31'},
        'chain_key': {'va': hex(CHAIN_KEY), 'length': 5,
                      'value': chain},
        'key_key': {'va': hex(KEY_KEY), 'length': 3,
                    'value': key_key},
        'message_string': {'va': hex(MSG_STRING),
                           'descriptor_qword': '0x2d',
                           'prefix': msg[:22],
                           'note': 'the .rodata bytes run on '
                                   'into "log_state" with no '
                                   'NUL; the descriptor the '
                                   'callee builds pairs the '
                                   'pointer with the qword '
                                   '0x2d'},
        'unwrap_string': {'va': hex(UNWRAP_STRING), 'length': 43,
                          'value': unwrap},
        'arm_a_const': {'va': hex(ARM_A_CONST),
                        'bytes_hex': const.hex()},
        'globals': {
            'state_byte': {'va': hex(GLOBAL_BYTE),
                           'section': '.data',
                           'file_value': '0x0'},
            'state_dword': {'va': hex(GLOBAL_DWORD),
                            'section': '.data',
                            'file_value': '0x3'},
            'predicate_struct': {'va': hex(GLOBAL_STRUCT),
                                 'section': '.data',
                                 'first_qwords': qwords},
        },
    }


def analyze(data):
    owner_records = owners(data)
    pin_records = check_pins(data)
    return {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'bytes': TARGET_SIZE, 'sha256': TARGET_SHA256,
                     'snapshot': SNAPSHOT},
        'packet': WORK_ITEM,
        'captured_code_executed': False,
        'config_slot': hex(CONFIG_SLOT),
        'owners': owner_records,
        'pins': pin_records,
        'slot_census': slot_census(data),
        'config_slot_census': config_slot_census(data),
        'body_censuses': body_censuses(data),
        'call_maps': call_maps(data),
        'strings_and_globals': strings_and_globals(data),
        'config_fetch': CONFIG_FETCH,
        'predicate': PREDICATE,
        'record_attribution': RECORD_ATTRIBUTION,
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
