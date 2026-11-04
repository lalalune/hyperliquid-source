#!/usr/bin/env python3
"""RE-006 node #115 u32 twin cursor search (0x35bf500): retained static packet tool.

The body at 0x35bf500 is the u32 twin of the runner-up layout (#2546):
the sixth cursor-search shape of the RE-006 family to be pinned, after
the clones (RE-006 main packet), variants A and B (#2530), the sibling
(#2542) and the runner-up (#2546) -- the family census in the variant
packet counted it with 6 direct call sites.  It walks the same key
array as the runner-up (keys at node + 0x2c8) but with u32 keys, so the
node header is narrower: the count word sits at node + 0x2f6 and the
child edges start at node + 0x2f8 (the runner-up's u64 header has them
at + 0x322 / + 0x328).  It returns the same 32-byte caller record as
the rest of the family (flag +0x0, node +0x8, height +0x10, position
+0x18).  Its 6 direct call sites sit in 6 caller FDEs (two clone
triples), and every one of them is flag-only: the flag test immediately
follows the call, and no consumer reads the record's node, height or
position in its site window -- the search is a pure membership oracle
for its callers.  The whole-FDE slot census per (caller, base) unit
settles the height question the same way as the earlier packets: none
of the 219 height-slot reads in the 6 census units consumes the
record's height -- each is a wholesale vector copy of the frame struct
or belongs to another phase of the same frame slot.

analyze() decodes and checks everything without authenticating the artifact,
so counterfactual byte flips surface as the specific failed check.
generate() authenticates the artifact first, then regenerates records.json,
frames.txt and the twin's full-body disassembly export byte-for-byte.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export as _foundation_decode

PACKET_ID = 'RE-006-node115-u32-twin-search'
PACKET_DIR = ROOT / 'research' / 'work-items' / PACKET_ID

U32TWIN_START = 0x35bf500
U32TWIN_END = 0x35bf592
U32TWIN_NAME = 'u32_twin_search'
ARTIFACT_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARTIFACT_SIZE = 105896032

# Body landmarks (all pinned again in U32TWIN_PINS).
KEY_DEREF = 0x35bf503        # mov (%rcx),%ecx -- the u32 key is dereferenced once
COUNT_LOAD = 0x35bf505       # movzwl 0x2f6(%rsi),%r8d -- count word at node + 0x2f6
KEY_COMPARE = 0x35bf525      # cmp 0x2cc(%rsi,%rdi,4),%ecx -- scan index from -1: keys at +0x2c8
DESCENT_LOAD = 0x35bf56c     # mov 0x2f8(%rsi,%rdi,8),%rsi -- child edges from +0x2f8
FLAG_ZERO = 0x35bf579        # xor %ecx,%ecx -- hit epilogue: flag 0
NODE_STORE = 0x35bf57b       # mov %rsi,0x8(%rax)
HEIGHT_STORE = 0x35bf57f     # mov %rdx,0x10(%rax)
POSITION_STORE = 0x35bf583   # mov %rdi,0x18(%rax)
FLAG_STORE = 0x35bf587       # mov %rcx,(%rax)
FLAG_ONE = 0x35bf58b         # mov $0x1,%ecx -- miss epilogue: flag 1

NODE_LAYOUT = {
    'keys_per_node': 11,
    'key_offset': 0x2c8,
    'key_size': 4,
    'count_offset': 0x2f6,
    'edge_base': 0x2f8,
    'child_index_offset': 0x2f4,
}
RECORD_LAYOUT = {'size': 32, 'flag': 0x0, 'node': 0x8, 'height': 0x10, 'position': 0x18}
VECTOR_MNEMONICS = ('movups', 'movupd', 'movapd', 'movaps', 'movdqu', 'movdqa')
FDE_COUNT = 135313

EXPECTED = {
    'call_sites': 6,
    'caller_fdes': 6,
    'census_units': 6,
    'node_position_sites': 0,
    'flag_only_sites': 6,
    'flag_node_addr_sites': 0,
    'flag_dword_sites': 0,
    'flag_byte_sites': 6,
    'presentations': {'embedded_frame': 3, 'embedded_register': 3},
    'record_forms': {'lea': 3, 'register': 3},
    'height_read_units': 6,
    'height_never_read_units': 0,
    'height_reads': 219,
    'height_vector_copy_reads': 96,
    'height_other_phase_reads': 123,
    'height_consumed_reads': 0,
    'windows': 129,
    'site_windows': 6,
    'attribution_windows': 123,
    'tail_call_sites': 0,
    'rela_relative_hits': 0,
}

U32TWIN_BODY_SHA256 = '90fda960e4f1a5fbffb665662ff5ae5384a64c5c54ac1443f37536c1d5400142'
U32TWIN_PINS = {
    0x35bf500: ('4889f8', 'mov    %rdi,%rax'),
    0x35bf503: ('8b09', 'mov    (%rcx),%ecx'),
    0x35bf505: ('440fb786f60200', 'movzwl 0x2f6(%rsi),%r8d'),
    0x35bf50d: ('4589c1', 'mov    %r8d,%r9d'),
    0x35bf510: ('41c1e102', 'shl    $0x2,%r9d'),
    0x35bf514: ('48c7c7ffffffff', 'mov    $0xffffffffffffffff,%rdi'),
    0x35bf51b: ('0f1f440000', 'nopl   0x0(%rax,%rax,1)'),
    0x35bf520: ('4d85c9', 'test   %r9,%r9'),
    0x35bf523: ('743b', 'je     0x35bf560'),
    0x35bf525: ('3b8cbecc020000', 'cmp    0x2cc(%rsi,%rdi,4),%ecx'),
    0x35bf52c: ('410f97c2', 'seta   %r10b'),
    0x35bf530: ('4180da00', 'sbb    $0x0,%r10b'),
    0x35bf534: ('48ffc7', 'inc    %rdi'),
    0x35bf537: ('4983c1fc', 'add    $0xfffffffffffffffc,%r9'),
    0x35bf53b: ('4180fa01', 'cmp    $0x1,%r10b'),
    0x35bf53f: ('74df', 'je     0x35bf520'),
    0x35bf541: ('450fb6c2', 'movzbl %r10b,%r8d'),
    0x35bf545: ('4585c0', 'test   %r8d,%r8d'),
    0x35bf548: ('742f', 'je     0x35bf579'),
    0x35bf54a: ('4989d0', 'mov    %rdx,%r8'),
    0x35bf54d: ('4983e801', 'sub    $0x1,%r8'),
    0x35bf551: ('7319', 'jae    0x35bf56c'),
    0x35bf553: ('eb36', 'jmp    0x35bf58b'),
    0x35bf555: ('66662e0f1f8400', 'data16 cs nopw 0x0(%rax,%rax,1)'),
    0x35bf560: ('4c89c7', 'mov    %r8,%rdi'),
    0x35bf563: ('4989d0', 'mov    %rdx,%r8'),
    0x35bf566: ('4983e801', 'sub    $0x1,%r8'),
    0x35bf56a: ('721f', 'jb     0x35bf58b'),
    0x35bf56c: ('488bb4fef80200', 'mov    0x2f8(%rsi,%rdi,8),%rsi'),
    0x35bf574: ('4c89c2', 'mov    %r8,%rdx'),
    0x35bf577: ('eb8c', 'jmp    0x35bf505'),
    0x35bf579: ('31c9', 'xor    %ecx,%ecx'),
    0x35bf57b: ('48897008', 'mov    %rsi,0x8(%rax)'),
    0x35bf57f: ('48895010', 'mov    %rdx,0x10(%rax)'),
    0x35bf583: ('48897818', 'mov    %rdi,0x18(%rax)'),
    0x35bf587: ('488908', 'mov    %rcx,(%rax)'),
    0x35bf58a: ('c3', 'ret'),
    0x35bf58b: ('b901000000', 'mov    $0x1,%ecx'),
    0x35bf590: ('ebe9', 'jmp    0x35bf57b'),
}
BOUNDARIES = {
    0x28cd7a0: ((0x28cd7a0, 0x28d8ac4), '40df69913a9976f4cf044e6f9b686fac43d0f63ba54b984ff79524a3a1794a76'),
    0x2c440c0: ((0x2c440c0, 0x2c448ff), '7ef99a2ff64c60500054cf389f38cb330356f705c54cd5ddbabd8abd8ec60ede'),
    0x538cd30: ((0x538cd30, 0x5397b4d), 'fe615521c3cebf329ae984293dd270e6aefd1a74dec4f2b7989b12a555ef833d'),
    0x5397b50: ((0x5397b50, 0x53a296d), 'a69d025534ce5dca6536f52e51c69a0402842bfce4a0e0b148eb3d429d0282d0'),
    0x55a5f10: ((0x55a5f10, 0x55a674f), '75f94a553579a4bb71f2db50e648f8f240f43ac7ccc472df4c2152fa647cb4c9'),
    0x55a6750: ((0x55a6750, 0x55a6f8f), '84541919c27ff59f42c81d3bba612804cc1695853c53a79c79b8c452341796b0'),
}
SITES = {
    0x28d3e11: {"caller": 0x28cd7a0, "base": 0x20, "class": 'flag_only', "flag": 0x28d3e16, "presentation": 'embedded_frame', "record_form": 'lea', "triple": None},
    0x2c4437a: {"caller": 0x2c440c0, "base": 0xa0, "class": 'flag_only', "flag": 0x2c4437f, "presentation": 'embedded_register', "record_form": 'register', "triple": None},
    0x5392ed7: {"caller": 0x538cd30, "base": 0x20, "class": 'flag_only', "flag": 0x5392edc, "presentation": 'embedded_frame', "record_form": 'lea', "triple": None},
    0x539dcf7: {"caller": 0x5397b50, "base": 0x20, "class": 'flag_only', "flag": 0x539dcfc, "presentation": 'embedded_frame', "record_form": 'lea', "triple": None},
    0x55a61ca: {"caller": 0x55a5f10, "base": 0xa0, "class": 'flag_only', "flag": 0x55a61cf, "presentation": 'embedded_register', "record_form": 'register', "triple": None},
    0x55a6a0a: {"caller": 0x55a6750, "base": 0xa0, "class": 'flag_only', "flag": 0x55a6a0f, "presentation": 'embedded_register', "record_form": 'register', "triple": None},
}
WINDOWS = {
    'caller_0x28cd7a0_height_0x28cdfac': {"range": (0x28cdf9d, 0x28cdfb1), "calls": {}, "pins": {0x28cdfac: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28ce765': {"range": (0x28ce755, 0x28ce76a), "calls": {}, "pins": {0x28ce765: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28ce808': {"range": (0x28ce7ff, 0x28ce80d), "calls": {}, "pins": {0x28ce808: ('488b742430', 'mov    0x30(%rsp),%rsi')}},
    'caller_0x28cd7a0_height_0x28ce905': {"range": (0x28ce8f7, 0x28ce90a), "calls": {}, "pins": {0x28ce905: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28ce9d0': {"range": (0x28ce9c0, 0x28ce9d5), "calls": {}, "pins": {0x28ce9d0: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28cea38': {"range": (0x28cea28, 0x28cea3d), "calls": {}, "pins": {0x28cea38: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x28cd7a0_height_0x28ced54': {"range": (0x28ced44, 0x28ced59), "calls": {}, "pins": {0x28ced54: ('488b442430', 'mov    0x30(%rsp),%rax')}},
    'caller_0x28cd7a0_height_0x28cee82': {"range": (0x28cee72, 0x28cee87), "calls": {}, "pins": {0x28cee82: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28cf112': {"range": (0x28cf102, 0x28cf117), "calls": {}, "pins": {0x28cf112: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28cf19e': {"range": (0x28cf18e, 0x28cf1a3), "calls": {}, "pins": {0x28cf19e: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28cf2c5': {"range": (0x28cf2b9, 0x28cf2ca), "calls": {}, "pins": {0x28cf2c5: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28cf86d': {"range": (0x28cf85d, 0x28cf872), "calls": {}, "pins": {0x28cf86d: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28cf91d': {"range": (0x28cf90f, 0x28cf922), "calls": {}, "pins": {0x28cf91d: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28cf957': {"range": (0x28cf946, 0x28cf95c), "calls": {}, "pins": {0x28cf957: ('4c8b7c2430', 'mov    0x30(%rsp),%r15')}},
    'caller_0x28cd7a0_height_0x28cfac0': {"range": (0x28cfab0, 0x28cfac5), "calls": {}, "pins": {0x28cfac0: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28cfcae': {"range": (0x28cfc9e, 0x28cfcb3), "calls": {}, "pins": {0x28cfcae: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28d0270': {"range": (0x28d025e, 0x28d0275), "calls": {}, "pins": {0x28d0270: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28d0c14': {"range": (0x28d0c04, 0x28d0c19), "calls": {}, "pins": {0x28d0c14: ('488b442430', 'mov    0x30(%rsp),%rax')}},
    'caller_0x28cd7a0_height_0x28d20f9': {"range": (0x28d20eb, 0x28d20fe), "calls": {}, "pins": {0x28d20f9: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x28cd7a0_height_0x28d246d': {"range": (0x28d245f, 0x28d2474), "calls": {}, "pins": {0x28d246d: ('48817c24301127', 'cmpq   $0x2711,0x30(%rsp)')}},
    'caller_0x28cd7a0_height_0x28d25f5': {"range": (0x28d25e7, 0x28d25fa), "calls": {}, "pins": {0x28d25f5: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x28cd7a0_height_0x28d29f3': {"range": (0x28d29e4, 0x28d29f8), "calls": {}, "pins": {0x28d29f3: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28d2da2': {"range": (0x28d2d94, 0x28d2da7), "calls": {}, "pins": {0x28d2da2: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x28cd7a0_height_0x28d3092': {"range": (0x28d3084, 0x28d3097), "calls": {}, "pins": {0x28d3092: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x28cd7a0_height_0x28d36ef': {"range": (0x28d36e0, 0x28d36f4), "calls": {}, "pins": {0x28d36ef: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28d380e': {"range": (0x28d3805, 0x28d3813), "calls": {}, "pins": {0x28d380e: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x28cd7a0_height_0x28d3888': {"range": (0x28d387e, 0x28d388d), "calls": {}, "pins": {0x28d3888: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28d396e': {"range": (0x28d395a, 0x28d3973), "calls": {}, "pins": {0x28d396e: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x28cd7a0_height_0x28d3d49': {"range": (0x28d3d3a, 0x28d3d4e), "calls": {}, "pins": {0x28d3d49: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28d3f5b': {"range": (0x28d3f4c, 0x28d3f60), "calls": {}, "pins": {0x28d3f5b: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x28cd7a0_height_0x28d47a7': {"range": (0x28d4795, 0x28d47ad), "calls": {}, "pins": {0x28d47a7: ('f20f10642430', 'movsd  0x30(%rsp),%xmm4')}},
    'caller_0x28cd7a0_height_0x28d4ed1': {"range": (0x28d4ebe, 0x28d4ed6), "calls": {}, "pins": {0x28d4ed1: ('4c8b6c2430', 'mov    0x30(%rsp),%r13')}},
    'caller_0x28cd7a0_height_0x28d5131': {"range": (0x28d511f, 0x28d5137), "calls": {}, "pins": {0x28d5131: ('f20f10642430', 'movsd  0x30(%rsp),%xmm4')}},
    'caller_0x28cd7a0_height_0x28d5b06': {"range": (0x28d5af6, 0x28d5b0b), "calls": {}, "pins": {0x28d5b06: ('488b442430', 'mov    0x30(%rsp),%rax')}},
    'caller_0x28cd7a0_height_0x28d5c52': {"range": (0x28d5c44, 0x28d5c57), "calls": {}, "pins": {0x28d5c52: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x28cd7a0_height_0x28d6f76': {"range": (0x28d6f66, 0x28d6f7b), "calls": {}, "pins": {0x28d6f76: ('4c8b7c2430', 'mov    0x30(%rsp),%r15')}},
    'caller_0x28cd7a0_height_0x28d6fd5': {"range": (0x28d6fc9, 0x28d6fda), "calls": {}, "pins": {0x28d6fd5: ('4c8b4c2430', 'mov    0x30(%rsp),%r9')}},
    'caller_0x2c440c0_height_0x2c44220': {"range": (0x2c44218, 0x2c44227), "calls": {}, "pins": {0x2c44220: ('488b9424b00000', 'mov    0xb0(%rsp),%rdx')}},
    'caller_0x2c440c0_height_0x2c44421': {"range": (0x2c4440e, 0x2c44428), "calls": {}, "pins": {0x2c44421: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx')}},
    'caller_0x2c440c0_height_0x2c44690': {"range": (0x2c4467f, 0x2c44697), "calls": {}, "pins": {0x2c44690: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx')}},
    'caller_0x2c440c0_height_0x2c447e0': {"range": (0x2c447cb, 0x2c447e7), "calls": {}, "pins": {0x2c447e0: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538d534': {"range": (0x538d525, 0x538d539), "calls": {}, "pins": {0x538d534: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538dced': {"range": (0x538dcdd, 0x538dcf2), "calls": {}, "pins": {0x538dced: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538dd8a': {"range": (0x538dd81, 0x538dd8f), "calls": {}, "pins": {0x538dd8a: ('488b742430', 'mov    0x30(%rsp),%rsi')}},
    'caller_0x538cd30_height_0x538de93': {"range": (0x538de85, 0x538de98), "calls": {}, "pins": {0x538de93: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538df78': {"range": (0x538df68, 0x538df7d), "calls": {}, "pins": {0x538df78: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538dfde': {"range": (0x538dfce, 0x538dfe3), "calls": {}, "pins": {0x538dfde: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x538cd30_height_0x538e2f1': {"range": (0x538e2e1, 0x538e2f6), "calls": {}, "pins": {0x538e2f1: ('488b442430', 'mov    0x30(%rsp),%rax')}},
    'caller_0x538cd30_height_0x538e41e': {"range": (0x538e40e, 0x538e423), "calls": {}, "pins": {0x538e41e: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538e6ab': {"range": (0x538e69b, 0x538e6b0), "calls": {}, "pins": {0x538e6ab: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538e736': {"range": (0x538e726, 0x538e73b), "calls": {}, "pins": {0x538e736: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538e85c': {"range": (0x538e850, 0x538e861), "calls": {}, "pins": {0x538e85c: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538ee91': {"range": (0x538ee81, 0x538ee96), "calls": {}, "pins": {0x538ee91: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538ef3f': {"range": (0x538ef31, 0x538ef44), "calls": {}, "pins": {0x538ef3f: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538ef79': {"range": (0x538ef68, 0x538ef7e), "calls": {}, "pins": {0x538ef79: ('4c8b7c2430', 'mov    0x30(%rsp),%r15')}},
    'caller_0x538cd30_height_0x538f061': {"range": (0x538f051, 0x538f066), "calls": {}, "pins": {0x538f061: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538f24c': {"range": (0x538f23c, 0x538f251), "calls": {}, "pins": {0x538f24c: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x538f800': {"range": (0x538f7ee, 0x538f805), "calls": {}, "pins": {0x538f800: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x5390191': {"range": (0x5390181, 0x5390196), "calls": {}, "pins": {0x5390191: ('488b442430', 'mov    0x30(%rsp),%rax')}},
    'caller_0x538cd30_height_0x5391668': {"range": (0x539165a, 0x539166d), "calls": {}, "pins": {0x5391668: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x538cd30_height_0x53918d8': {"range": (0x53918ca, 0x53918df), "calls": {}, "pins": {0x53918d8: ('48817c24301127', 'cmpq   $0x2711,0x30(%rsp)')}},
    'caller_0x538cd30_height_0x5391998': {"range": (0x539198a, 0x539199d), "calls": {}, "pins": {0x5391998: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x538cd30_height_0x5391d35': {"range": (0x5391d26, 0x5391d3a), "calls": {}, "pins": {0x5391d35: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x5391f0f': {"range": (0x5391f01, 0x5391f14), "calls": {}, "pins": {0x5391f0f: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x538cd30_height_0x53920c7': {"range": (0x53920b9, 0x53920cc), "calls": {}, "pins": {0x53920c7: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x538cd30_height_0x53927b6': {"range": (0x53927a7, 0x53927bb), "calls": {}, "pins": {0x53927b6: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x53928d5': {"range": (0x53928cc, 0x53928da), "calls": {}, "pins": {0x53928d5: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x538cd30_height_0x539294f': {"range": (0x5392945, 0x5392954), "calls": {}, "pins": {0x539294f: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x5392a35': {"range": (0x5392a21, 0x5392a3a), "calls": {}, "pins": {0x5392a35: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x538cd30_height_0x5392e0f': {"range": (0x5392e00, 0x5392e14), "calls": {}, "pins": {0x5392e0f: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x5393021': {"range": (0x5393012, 0x5393026), "calls": {}, "pins": {0x5393021: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x538cd30_height_0x539385a': {"range": (0x5393848, 0x5393860), "calls": {}, "pins": {0x539385a: ('f20f10642430', 'movsd  0x30(%rsp),%xmm4')}},
    'caller_0x538cd30_height_0x5393f77': {"range": (0x5393f64, 0x5393f7c), "calls": {}, "pins": {0x5393f77: ('4c8b6c2430', 'mov    0x30(%rsp),%r13')}},
    'caller_0x538cd30_height_0x53941e3': {"range": (0x53941d1, 0x53941e9), "calls": {}, "pins": {0x53941e3: ('f20f10642430', 'movsd  0x30(%rsp),%xmm4')}},
    'caller_0x538cd30_height_0x5394b9c': {"range": (0x5394b8c, 0x5394ba1), "calls": {}, "pins": {0x5394b9c: ('488b442430', 'mov    0x30(%rsp),%rax')}},
    'caller_0x538cd30_height_0x5394ce7': {"range": (0x5394cd9, 0x5394cec), "calls": {}, "pins": {0x5394ce7: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x538cd30_height_0x539601a': {"range": (0x539600a, 0x539601f), "calls": {}, "pins": {0x539601a: ('4c8b6c2430', 'mov    0x30(%rsp),%r13')}},
    'caller_0x538cd30_height_0x5396079': {"range": (0x539606d, 0x539607e), "calls": {}, "pins": {0x5396079: ('4c8b4c2430', 'mov    0x30(%rsp),%r9')}},
    'caller_0x5397b50_height_0x5398354': {"range": (0x5398345, 0x5398359), "calls": {}, "pins": {0x5398354: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x5398b0d': {"range": (0x5398afd, 0x5398b12), "calls": {}, "pins": {0x5398b0d: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x5398baa': {"range": (0x5398ba1, 0x5398baf), "calls": {}, "pins": {0x5398baa: ('488b742430', 'mov    0x30(%rsp),%rsi')}},
    'caller_0x5397b50_height_0x5398cb3': {"range": (0x5398ca5, 0x5398cb8), "calls": {}, "pins": {0x5398cb3: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x5398d98': {"range": (0x5398d88, 0x5398d9d), "calls": {}, "pins": {0x5398d98: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x5398dfe': {"range": (0x5398dee, 0x5398e03), "calls": {}, "pins": {0x5398dfe: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x5397b50_height_0x5399111': {"range": (0x5399101, 0x5399116), "calls": {}, "pins": {0x5399111: ('488b442430', 'mov    0x30(%rsp),%rax')}},
    'caller_0x5397b50_height_0x539923e': {"range": (0x539922e, 0x5399243), "calls": {}, "pins": {0x539923e: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x53994cb': {"range": (0x53994bb, 0x53994d0), "calls": {}, "pins": {0x53994cb: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x5399556': {"range": (0x5399546, 0x539955b), "calls": {}, "pins": {0x5399556: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x539967c': {"range": (0x5399670, 0x5399681), "calls": {}, "pins": {0x539967c: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x5399cb1': {"range": (0x5399ca1, 0x5399cb6), "calls": {}, "pins": {0x5399cb1: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x5399d5f': {"range": (0x5399d51, 0x5399d64), "calls": {}, "pins": {0x5399d5f: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x5399d99': {"range": (0x5399d88, 0x5399d9e), "calls": {}, "pins": {0x5399d99: ('4c8b7c2430', 'mov    0x30(%rsp),%r15')}},
    'caller_0x5397b50_height_0x5399e81': {"range": (0x5399e71, 0x5399e86), "calls": {}, "pins": {0x5399e81: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x539a06c': {"range": (0x539a05c, 0x539a071), "calls": {}, "pins": {0x539a06c: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x539a620': {"range": (0x539a60e, 0x539a625), "calls": {}, "pins": {0x539a620: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x539afb1': {"range": (0x539afa1, 0x539afb6), "calls": {}, "pins": {0x539afb1: ('488b442430', 'mov    0x30(%rsp),%rax')}},
    'caller_0x5397b50_height_0x539c488': {"range": (0x539c47a, 0x539c48d), "calls": {}, "pins": {0x539c488: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x5397b50_height_0x539c6f8': {"range": (0x539c6ea, 0x539c6ff), "calls": {}, "pins": {0x539c6f8: ('48817c24301127', 'cmpq   $0x2711,0x30(%rsp)')}},
    'caller_0x5397b50_height_0x539c7b8': {"range": (0x539c7aa, 0x539c7bd), "calls": {}, "pins": {0x539c7b8: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x5397b50_height_0x539cb55': {"range": (0x539cb46, 0x539cb5a), "calls": {}, "pins": {0x539cb55: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x539cd2f': {"range": (0x539cd21, 0x539cd34), "calls": {}, "pins": {0x539cd2f: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x5397b50_height_0x539cee7': {"range": (0x539ced9, 0x539ceec), "calls": {}, "pins": {0x539cee7: ('488b7c2430', 'mov    0x30(%rsp),%rdi')}},
    'caller_0x5397b50_height_0x539d5d6': {"range": (0x539d5c7, 0x539d5db), "calls": {}, "pins": {0x539d5d6: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x539d6f5': {"range": (0x539d6ec, 0x539d6fa), "calls": {}, "pins": {0x539d6f5: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x5397b50_height_0x539d76f': {"range": (0x539d765, 0x539d774), "calls": {}, "pins": {0x539d76f: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x539d855': {"range": (0x539d841, 0x539d85a), "calls": {}, "pins": {0x539d855: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x5397b50_height_0x539dc2f': {"range": (0x539dc20, 0x539dc34), "calls": {}, "pins": {0x539dc2f: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x539de41': {"range": (0x539de32, 0x539de46), "calls": {}, "pins": {0x539de41: ('488b4c2430', 'mov    0x30(%rsp),%rcx')}},
    'caller_0x5397b50_height_0x539e67a': {"range": (0x539e668, 0x539e680), "calls": {}, "pins": {0x539e67a: ('f20f10642430', 'movsd  0x30(%rsp),%xmm4')}},
    'caller_0x5397b50_height_0x539ed97': {"range": (0x539ed84, 0x539ed9c), "calls": {}, "pins": {0x539ed97: ('4c8b6c2430', 'mov    0x30(%rsp),%r13')}},
    'caller_0x5397b50_height_0x539f003': {"range": (0x539eff1, 0x539f009), "calls": {}, "pins": {0x539f003: ('f20f10642430', 'movsd  0x30(%rsp),%xmm4')}},
    'caller_0x5397b50_height_0x539f9bc': {"range": (0x539f9ac, 0x539f9c1), "calls": {}, "pins": {0x539f9bc: ('488b442430', 'mov    0x30(%rsp),%rax')}},
    'caller_0x5397b50_height_0x539fb07': {"range": (0x539faf9, 0x539fb0c), "calls": {}, "pins": {0x539fb07: ('488b542430', 'mov    0x30(%rsp),%rdx')}},
    'caller_0x5397b50_height_0x53a0e3a': {"range": (0x53a0e2a, 0x53a0e3f), "calls": {}, "pins": {0x53a0e3a: ('4c8b6c2430', 'mov    0x30(%rsp),%r13')}},
    'caller_0x5397b50_height_0x53a0e99': {"range": (0x53a0e8d, 0x53a0e9e), "calls": {}, "pins": {0x53a0e99: ('4c8b4c2430', 'mov    0x30(%rsp),%r9')}},
    'caller_0x55a5f10_height_0x55a6070': {"range": (0x55a6068, 0x55a6077), "calls": {}, "pins": {0x55a6070: ('488b9424b00000', 'mov    0xb0(%rsp),%rdx')}},
    'caller_0x55a5f10_height_0x55a6271': {"range": (0x55a625e, 0x55a6278), "calls": {}, "pins": {0x55a6271: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx')}},
    'caller_0x55a5f10_height_0x55a64e0': {"range": (0x55a64cf, 0x55a64e7), "calls": {}, "pins": {0x55a64e0: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx')}},
    'caller_0x55a5f10_height_0x55a6630': {"range": (0x55a661b, 0x55a6637), "calls": {}, "pins": {0x55a6630: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx')}},
    'caller_0x55a6750_height_0x55a68b0': {"range": (0x55a68a8, 0x55a68b7), "calls": {}, "pins": {0x55a68b0: ('488b9424b00000', 'mov    0xb0(%rsp),%rdx')}},
    'caller_0x55a6750_height_0x55a6ab1': {"range": (0x55a6a9e, 0x55a6ab8), "calls": {}, "pins": {0x55a6ab1: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx')}},
    'caller_0x55a6750_height_0x55a6d20': {"range": (0x55a6d0f, 0x55a6d27), "calls": {}, "pins": {0x55a6d20: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx')}},
    'caller_0x55a6750_height_0x55a6e70': {"range": (0x55a6e5b, 0x55a6e77), "calls": {}, "pins": {0x55a6e70: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx')}},
    'site_0x28d3e11': {"range": (0x28d3dc4, 0x28d3e1b), "calls": {}, "pins": {0x28d3dc4: ('4489b424e00200', 'mov    %r14d,0x2e0(%rsp)'), 0x28d3dcc: ('4183fe32', 'cmp    $0x32,%r14d'), 0x28d3dd2: ('48b80000000000', 'movabs $0x8000000000000000,%rax'), 0x28d3ddc: ('488bbc24300200', 'mov    0x230(%rsp),%rdi'), 0x28d3de4: ('483907', 'cmp    %rax,(%rdi)'), 0x28d3de9: ('488b442418', 'mov    0x18(%rsp),%rax'), 0x28d3dee: ('488b7038', 'mov    0x38(%rax),%rsi'), 0x28d3dfb: ('488b442418', 'mov    0x18(%rsp),%rax'), 0x28d3e00: ('488b5040', 'mov    0x40(%rax),%rdx'), 0x28d3e04: ('488d7c2420', 'lea    0x20(%rsp),%rdi'), 0x28d3e09: ('488d8c24e00200', 'lea    0x2e0(%rsp),%rcx'), 0x28d3e11: ('e8eab6ce00', 'call   0x35bf500'), 0x28d3e16: ('807c242000', 'cmpb   $0x0,0x20(%rsp)')}},
    'site_0x2c4437a': {"range": (0x2c4417b, 0x2c44386), "calls": {}, "pins": {0x2c4417b: ('488dac24a00000', 'lea    0xa0(%rsp),%rbp'), 0x2c44311: ('4c8bb424a80000', 'mov    0xa8(%rsp),%r14'), 0x2c44342: ('4c8bbc24a80000', 'mov    0xa8(%rsp),%r15'), 0x2c4434a: ('4489a424100100', 'mov    %r12d,0x110(%rsp)'), 0x2c44352: ('4183fc32', 'cmp    $0x32,%r12d'), 0x2c44358: ('49395e30', 'cmp    %rbx,0x30(%r14)'), 0x2c4435e: ('498b7638', 'mov    0x38(%r14),%rsi'), 0x2c44362: ('4885f6', 'test   %rsi,%rsi'), 0x2c4436b: ('498b5640', 'mov    0x40(%r14),%rdx'), 0x2c4436f: ('4889ef', 'mov    %rbp,%rdi'), 0x2c44372: ('488d8c24100100', 'lea    0x110(%rsp),%rcx'), 0x2c4437a: ('e881b19700', 'call   0x35bf500'), 0x2c4437f: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)')}},
    'site_0x5392ed7': {"range": (0x5392e8a, 0x5392ee1), "calls": {}, "pins": {0x5392e8a: ('4489b424700300', 'mov    %r14d,0x370(%rsp)'), 0x5392e92: ('4183fe32', 'cmp    $0x32,%r14d'), 0x5392e98: ('48b80000000000', 'movabs $0x8000000000000000,%rax'), 0x5392ea2: ('488bbc24180200', 'mov    0x218(%rsp),%rdi'), 0x5392eaa: ('483907', 'cmp    %rax,(%rdi)'), 0x5392eaf: ('488b442418', 'mov    0x18(%rsp),%rax'), 0x5392eb4: ('488b7038', 'mov    0x38(%rax),%rsi'), 0x5392ec1: ('488b442418', 'mov    0x18(%rsp),%rax'), 0x5392ec6: ('488b5040', 'mov    0x40(%rax),%rdx'), 0x5392eca: ('488d7c2420', 'lea    0x20(%rsp),%rdi'), 0x5392ecf: ('488d8c24700300', 'lea    0x370(%rsp),%rcx'), 0x5392ed7: ('e824c622fe', 'call   0x35bf500'), 0x5392edc: ('807c242000', 'cmpb   $0x0,0x20(%rsp)')}},
    'site_0x539dcf7': {"range": (0x539dcaa, 0x539dd01), "calls": {}, "pins": {0x539dcaa: ('4489b424700300', 'mov    %r14d,0x370(%rsp)'), 0x539dcb2: ('4183fe32', 'cmp    $0x32,%r14d'), 0x539dcb8: ('48b80000000000', 'movabs $0x8000000000000000,%rax'), 0x539dcc2: ('488bbc24180200', 'mov    0x218(%rsp),%rdi'), 0x539dcca: ('483907', 'cmp    %rax,(%rdi)'), 0x539dccf: ('488b442418', 'mov    0x18(%rsp),%rax'), 0x539dcd4: ('488b7038', 'mov    0x38(%rax),%rsi'), 0x539dce1: ('488b442418', 'mov    0x18(%rsp),%rax'), 0x539dce6: ('488b5040', 'mov    0x40(%rax),%rdx'), 0x539dcea: ('488d7c2420', 'lea    0x20(%rsp),%rdi'), 0x539dcef: ('488d8c24700300', 'lea    0x370(%rsp),%rcx'), 0x539dcf7: ('e8041822fe', 'call   0x35bf500'), 0x539dcfc: ('807c242000', 'cmpb   $0x0,0x20(%rsp)')}},
    'site_0x55a61ca': {"range": (0x55a5fcb, 0x55a61d6), "calls": {}, "pins": {0x55a5fcb: ('488dac24a00000', 'lea    0xa0(%rsp),%rbp'), 0x55a6161: ('4c8bb424a80000', 'mov    0xa8(%rsp),%r14'), 0x55a6192: ('4c8bbc24a80000', 'mov    0xa8(%rsp),%r15'), 0x55a619a: ('4489a424100100', 'mov    %r12d,0x110(%rsp)'), 0x55a61a2: ('4183fc32', 'cmp    $0x32,%r12d'), 0x55a61a8: ('49395e30', 'cmp    %rbx,0x30(%r14)'), 0x55a61ae: ('498b7638', 'mov    0x38(%r14),%rsi'), 0x55a61b2: ('4885f6', 'test   %rsi,%rsi'), 0x55a61bb: ('498b5640', 'mov    0x40(%r14),%rdx'), 0x55a61bf: ('4889ef', 'mov    %rbp,%rdi'), 0x55a61c2: ('488d8c24100100', 'lea    0x110(%rsp),%rcx'), 0x55a61ca: ('e8319301fe', 'call   0x35bf500'), 0x55a61cf: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)')}},
    'site_0x55a6a0a': {"range": (0x55a680b, 0x55a6a16), "calls": {}, "pins": {0x55a680b: ('488dac24a00000', 'lea    0xa0(%rsp),%rbp'), 0x55a69a1: ('4c8bb424a80000', 'mov    0xa8(%rsp),%r14'), 0x55a69d2: ('4c8bbc24a80000', 'mov    0xa8(%rsp),%r15'), 0x55a69da: ('4489a424100100', 'mov    %r12d,0x110(%rsp)'), 0x55a69e2: ('4183fc32', 'cmp    $0x32,%r12d'), 0x55a69e8: ('49395e30', 'cmp    %rbx,0x30(%r14)'), 0x55a69ee: ('498b7638', 'mov    0x38(%r14),%rsi'), 0x55a69f2: ('4885f6', 'test   %rsi,%rsi'), 0x55a69fb: ('498b5640', 'mov    0x40(%r14),%rdx'), 0x55a69ff: ('4889ef', 'mov    %rbp,%rdi'), 0x55a6a02: ('488d8c24100100', 'lea    0x110(%rsp),%rcx'), 0x55a6a0a: ('e8f18a01fe', 'call   0x35bf500'), 0x55a6a0f: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)')}},
}
SLOT_CENSUS = {
    '0x28cd7a0|0x20': {'flag': [0x28cd9b7, 0x28cdb1d, 0x28cdbbb, 0x28cdbe1, 0x28cdc24, 0x28cdcf7, 0x28cdd5e, 0x28cdf01, 0x28cdfa2, 0x28ce21d, 0x28ce278, 0x28ce371, 0x28ce571, 0x28ce674, 0x28ce72d, 0x28ce750, 0x28ce7f0, 0x28ce8f7, 0x28ce9bb, 0x28cea28, 0x28ceb8e, 0x28ced3f, 0x28cee1b, 0x28cee6d, 0x28ceffb, 0x28cf0fd, 0x28cf189, 0x28cf1ff, 0x28cf2b4, 0x28cf42c, 0x28cf513, 0x28cf55c, 0x28cf5cc, 0x28cf621, 0x28cf6ca, 0x28cf833, 0x28cf858, 0x28cf90f, 0x28cf93c, 0x28cfaab, 0x28cfbd4, 0x28cfc99, 0x28cfe44, 0x28cff06, 0x28d024e, 0x28d037a, 0x28d04d6, 0x28d0860, 0x28d08d2, 0x28d091f, 0x28d09cc, 0x28d0b8f, 0x28d0bff, 0x28d0c76, 0x28d0e67, 0x28d0f08, 0x28d0fce, 0x28d1080, 0x28d1193, 0x28d12e6, 0x28d148e, 0x28d16b1, 0x28d17a4, 0x28d189b, 0x28d1faf, 0x28d200d, 0x28d20d2, 0x28d23e5, 0x28d2447, 0x28d248f, 0x28d25ca, 0x28d2734, 0x28d2775, 0x28d2890, 0x28d28c0, 0x28d29dc, 0x28d2ac7, 0x28d2ca2, 0x28d2d7b, 0x28d2f92, 0x28d306b, 0x28d3105, 0x28d31d2, 0x28d32d3, 0x28d3437, 0x28d36db, 0x28d376f, 0x28d37cf, 0x28d37fb, 0x28d387e, 0x28d38c8, 0x28d38e6, 0x28d3a4f, 0x28d3d27, 0x28d3d9c, 0x28d3e16, 0x28d3f47, 0x28d3fda, 0x28d41e6, 0x28d42f6, 0x28d4342, 0x28d4611, 0x28d46cd, 0x28d4710, 0x28d4785, 0x28d492f, 0x28d4a11, 0x28d4a63, 0x28d4c80, 0x28d4e2f, 0x28d4eac, 0x28d507c, 0x28d510f, 0x28d5af1, 0x28d5c44, 0x28d5ff4, 0x28d606c, 0x28d624d, 0x28d62f3, 0x28d635b, 0x28d653f, 0x28d68c2, 0x28d6a06, 0x28d6b81, 0x28d6d26, 0x28d6e6a, 0x28d6f61, 0x28d6fc4, 0x28d7112, 0x28d785e, 0x28d7b50, 0x28d7bba, 0x28d8126], 'node': [0x28cd9c7, 0x28cdb3a, 0x28cdbf1, 0x28cdd07, 0x28cdd77, 0x28cdf11, 0x28cdfa7, 0x28ce22d, 0x28ce295, 0x28ce381, 0x28ce760, 0x28ce7f5, 0x28ce9cb, 0x28cea3d, 0x28ceb9e, 0x28ced4f, 0x28cee2b, 0x28cee7d, 0x28cf00b, 0x28cf10d, 0x28cf199, 0x28cf21c, 0x28cf2c0, 0x28cf30e, 0x28cf43c, 0x28cf56c, 0x28cf631, 0x28cf6da, 0x28cf868, 0x28cf94c, 0x28cfabb, 0x28cfca9, 0x28cff12, 0x28d026b, 0x28d038a, 0x28d04e6, 0x28d0870, 0x28d0ba4, 0x28d0c0f, 0x28d0c8f, 0x28d0dca, 0x28d0e77, 0x28d0f18, 0x28d109d, 0x28d119d, 0x28d12f5, 0x28d149a, 0x28d1501, 0x28d1564, 0x28d1624, 0x28d16ce, 0x28d17c1, 0x28d18b8, 0x28d198a, 0x28d1b67, 0x28d1d0a, 0x28d1e06, 0x28d1fbf, 0x28d20f4, 0x28d25f0, 0x28d2af7, 0x28d2d9d, 0x28d308d, 0x28d31e2, 0x28d32f0, 0x28d3454, 0x28d356c, 0x28d377f, 0x28d3816, 0x28d3951, 0x28d3dac, 0x28d3ff4, 0x28d406d, 0x28d40df, 0x28d4185, 0x28d4203, 0x28d435f, 0x28d47a2, 0x28d49d1, 0x28d4a1b, 0x28d4e47, 0x28d4ecc, 0x28d512c, 0x28d5371, 0x28d5416, 0x28d5656, 0x28d5a5a, 0x28d5b01, 0x28d5d76, 0x28d5e36, 0x28d5f2c, 0x28d601e, 0x28d6071, 0x28d625d, 0x28d6662, 0x28d682b, 0x28d6924, 0x28d6a2f, 0x28d6d43, 0x28d6edb, 0x28d6f21, 0x28d6f71, 0x28d6fd0, 0x28d7061, 0x28d744d, 0x28d7549, 0x28d76b0, 0x28d786e, 0x28d7b60, 0x28d7bca, 0x28d7d92, 0x28d7e39, 0x28d8130], 'height': [0x28cdfac, 0x28ce232, 0x28ce765, 0x28ce808, 0x28ce905, 0x28ce9d0, 0x28cea38, 0x28ced54, 0x28cee82, 0x28cf112, 0x28cf19e, 0x28cf2c5, 0x28cf86d, 0x28cf91d, 0x28cf957, 0x28cfac0, 0x28cfcae, 0x28cfe84, 0x28d0270, 0x28d038f, 0x28d0875, 0x28d0c14, 0x28d0cf2, 0x28d1537, 0x28d1629, 0x28d198f, 0x28d1b6c, 0x28d1d40, 0x28d1e3b, 0x28d1fc4, 0x28d20f9, 0x28d246d, 0x28d25f5, 0x28d28c6, 0x28d29f3, 0x28d2da2, 0x28d3092, 0x28d31fe, 0x28d34e9, 0x28d35a2, 0x28d36ef, 0x28d380e, 0x28d3888, 0x28d396e, 0x28d3d49, 0x28d3f5b, 0x28d40a2, 0x28d42fc, 0x28d46d3, 0x28d47a7, 0x28d4c86, 0x28d4ed1, 0x28d5131, 0x28d53a6, 0x28d544b, 0x28d568b, 0x28d5a8f, 0x28d5b06, 0x28d5c52, 0x28d5dac, 0x28d5e6b, 0x28d6262, 0x28d6698, 0x28d6929, 0x28d6f76, 0x28d6fd5, 0x28d7118, 0x28d7452, 0x28d76b5], 'position': [0x28cd9cd, 0x28cdb2d, 0x28cdbf7, 0x28cdf17, 0x28ce29b, 0x28ce387, 0x28ce76a, 0x28ce9d5, 0x28ced59, 0x28cee87, 0x28cf117, 0x28cf1a3, 0x28cf20f, 0x28cf2ca, 0x28cf348, 0x28cf442, 0x28cf637, 0x28cf6e0, 0x28cf87a, 0x28cfac5, 0x28cfcb3, 0x28cff18, 0x28d0275, 0x28d0baa, 0x28d0c19, 0x28d0c82, 0x28d0e04, 0x28d1090, 0x28d156a, 0x28d16d4, 0x28d17c7, 0x28d18be, 0x28d20eb, 0x28d25e7, 0x28d2d94, 0x28d3084, 0x28d32f6, 0x28d345a, 0x28d3973, 0x28d4119, 0x28d4209, 0x28d4365, 0x28d47ad, 0x28d4998, 0x28d4ed6, 0x28d5137, 0x28d5b0b, 0x28d5ed0, 0x28d6865, 0x28d6d49, 0x28d7022, 0x28d750a, 0x28d7874, 0x28d7d53, 0x28d7dfa]},
    '0x2c440c0|0xa0': {'flag': [0x2c4420d, 0x2c442fe, 0x2c4432f, 0x2c4437f, 0x2c44672, 0x2c446c2, 0x2c447be, 0x2c44811], 'node': [0x2c44311, 0x2c44342, 0x2c44419], 'height': [0x2c44220, 0x2c44421, 0x2c44690, 0x2c447e0], 'position': [0x2c44429]},
    '0x538cd30|0x20': {'flag': [0x538cf47, 0x538d0aa, 0x538d147, 0x538d16d, 0x538d1b0, 0x538d283, 0x538d2ea, 0x538d489, 0x538d52a, 0x538d7a5, 0x538d800, 0x538d901, 0x538dafa, 0x538dbfc, 0x538dcb5, 0x538dcd8, 0x538dd72, 0x538de85, 0x538df63, 0x538dfce, 0x538e132, 0x538e2dc, 0x538e3b8, 0x538e409, 0x538e595, 0x538e696, 0x538e721, 0x538e797, 0x538e84b, 0x538ea56, 0x538eb3b, 0x538eb84, 0x538ebf3, 0x538ec46, 0x538ecee, 0x538ee57, 0x538ee7c, 0x538ef31, 0x538ef5e, 0x538f04c, 0x538f176, 0x538f237, 0x538f3e1, 0x538f4a3, 0x538f7de, 0x538f90a, 0x538fa62, 0x538fde0, 0x538fe50, 0x538fe9d, 0x538ff49, 0x539010c, 0x539017c, 0x53901f3, 0x53903e3, 0x5390484, 0x539054a, 0x53905fc, 0x539070f, 0x5390862, 0x5390a0a, 0x5390c2c, 0x5390d1f, 0x5390e16, 0x5391525, 0x5391582, 0x5391641, 0x5391850, 0x53918b2, 0x53918fa, 0x5391971, 0x5391ab8, 0x5391bd2, 0x5391c02, 0x5391d1e, 0x5391e07, 0x5391ee8, 0x53920a0, 0x53921d3, 0x53922a0, 0x53923a1, 0x53924fe, 0x53927a2, 0x5392836, 0x5392896, 0x53928c2, 0x5392945, 0x539298f, 0x53929ad, 0x5392b15, 0x5392ded, 0x5392e62, 0x5392edc, 0x539300d, 0x53930a0, 0x53932ac, 0x53933bb, 0x5393407, 0x53936d3, 0x539378b, 0x53937ce, 0x5393838, 0x53939cc, 0x5393aae, 0x5393b00, 0x5393d26, 0x5393ed5, 0x5393f52, 0x5394126, 0x53941c1, 0x5394b87, 0x5394cd9, 0x5395088, 0x53950fe, 0x53952dc, 0x5395382, 0x53953ea, 0x53955db, 0x5395981, 0x5395aa1, 0x5395c1c, 0x5395dc0, 0x5395f05, 0x5396005, 0x5396068, 0x53961b6, 0x5396900, 0x5396bf0, 0x5396c5a, 0x53971b4], 'node': [0x538cf57, 0x538d0c7, 0x538d17d, 0x538d293, 0x538d303, 0x538d499, 0x538d52f, 0x538d7b5, 0x538d81d, 0x538d911, 0x538dce8, 0x538dd77, 0x538df73, 0x538dfe3, 0x538e142, 0x538e2ec, 0x538e3c8, 0x538e419, 0x538e5a5, 0x538e6a6, 0x538e731, 0x538e7b4, 0x538e857, 0x538e8a5, 0x538ea66, 0x538eb94, 0x538ec56, 0x538ecfe, 0x538ee8c, 0x538ef6e, 0x538f05c, 0x538f247, 0x538f4af, 0x538f7fb, 0x538f91a, 0x538fa72, 0x538fdf0, 0x5390121, 0x539018c, 0x539020c, 0x5390346, 0x53903f3, 0x5390494, 0x5390619, 0x5390719, 0x5390871, 0x5390a16, 0x5390a7c, 0x5390adf, 0x5390b9f, 0x5390c49, 0x5390d3c, 0x5390e33, 0x5390f0d, 0x53910e7, 0x539128a, 0x5391386, 0x5391535, 0x5391663, 0x5391993, 0x5391e37, 0x5391f0a, 0x53920c2, 0x53922b0, 0x53923be, 0x539251b, 0x5392633, 0x5392846, 0x53928dd, 0x5392a18, 0x5392e72, 0x53930ba, 0x5393133, 0x53931a5, 0x539324b, 0x53932c9, 0x5393424, 0x5393855, 0x5393a6e, 0x5393ab8, 0x5393eed, 0x5393f72, 0x53941de, 0x539441c, 0x53944c1, 0x5394701, 0x5394af0, 0x5394b97, 0x5394e0a, 0x5394eca, 0x5394fc0, 0x53950b0, 0x5395103, 0x53952ec, 0x53956fe, 0x53958c6, 0x53959bf, 0x5395aca, 0x5395ddd, 0x5395f7e, 0x5395fc4, 0x5396015, 0x5396074, 0x5396105, 0x53964ea, 0x53965e6, 0x539674d, 0x5396910, 0x5396c00, 0x5396c6a, 0x5396e3a, 0x5396ed4, 0x53971be], 'height': [0x538d534, 0x538d7ba, 0x538dced, 0x538dd8a, 0x538de93, 0x538df78, 0x538dfde, 0x538e2f1, 0x538e41e, 0x538e6ab, 0x538e736, 0x538e85c, 0x538ee91, 0x538ef3f, 0x538ef79, 0x538f061, 0x538f24c, 0x538f421, 0x538f800, 0x538f91f, 0x538fdf5, 0x5390191, 0x539026e, 0x5390ab2, 0x5390ba4, 0x5390f12, 0x53910ec, 0x53912c0, 0x53913bb, 0x539153a, 0x5391668, 0x53918d8, 0x5391998, 0x5391c08, 0x5391d35, 0x5391f0f, 0x53920c7, 0x53922cc, 0x53925b0, 0x5392669, 0x53927b6, 0x53928d5, 0x539294f, 0x5392a35, 0x5392e0f, 0x5393021, 0x5393168, 0x53933c1, 0x5393791, 0x539385a, 0x5393d2c, 0x5393f77, 0x53941e3, 0x5394451, 0x53944f6, 0x5394736, 0x5394b25, 0x5394b9c, 0x5394ce7, 0x5394e40, 0x5394eff, 0x53952f1, 0x5395734, 0x53959c4, 0x539601a, 0x5396079, 0x53961bc, 0x53964ef, 0x5396752], 'position': [0x538cf5d, 0x538d0ba, 0x538d183, 0x538d49f, 0x538d823, 0x538d917, 0x538dcf2, 0x538df7d, 0x538e2f6, 0x538e423, 0x538e6b0, 0x538e73b, 0x538e7a7, 0x538e861, 0x538e8df, 0x538ea6c, 0x538ec5c, 0x538ed04, 0x538ee9e, 0x538f066, 0x538f251, 0x538f4b5, 0x538f805, 0x5390127, 0x5390196, 0x53901ff, 0x5390380, 0x539060c, 0x5390ae5, 0x5390c4f, 0x5390d42, 0x5390e39, 0x539165a, 0x539198a, 0x5391f01, 0x53920b9, 0x53923c4, 0x5392521, 0x5392a3a, 0x53931df, 0x53932cf, 0x539342a, 0x5393860, 0x5393a35, 0x5393f7c, 0x53941e9, 0x5394ba1, 0x5394f64, 0x5395900, 0x5395de3, 0x53960c6, 0x53965a7, 0x5396916, 0x5396dfb, 0x5396e95]},
    '0x5397b50|0x20': {'flag': [0x5397d67, 0x5397eca, 0x5397f67, 0x5397f8d, 0x5397fd0, 0x53980a3, 0x539810a, 0x53982a9, 0x539834a, 0x53985c5, 0x5398620, 0x5398721, 0x539891a, 0x5398a1c, 0x5398ad5, 0x5398af8, 0x5398b92, 0x5398ca5, 0x5398d83, 0x5398dee, 0x5398f52, 0x53990fc, 0x53991d8, 0x5399229, 0x53993b5, 0x53994b6, 0x5399541, 0x53995b7, 0x539966b, 0x5399876, 0x539995b, 0x53999a4, 0x5399a13, 0x5399a66, 0x5399b0e, 0x5399c77, 0x5399c9c, 0x5399d51, 0x5399d7e, 0x5399e6c, 0x5399f96, 0x539a057, 0x539a201, 0x539a2c3, 0x539a5fe, 0x539a72a, 0x539a882, 0x539ac00, 0x539ac70, 0x539acbd, 0x539ad69, 0x539af2c, 0x539af9c, 0x539b013, 0x539b203, 0x539b2a4, 0x539b36a, 0x539b41c, 0x539b52f, 0x539b682, 0x539b82a, 0x539ba4c, 0x539bb3f, 0x539bc36, 0x539c345, 0x539c3a2, 0x539c461, 0x539c670, 0x539c6d2, 0x539c71a, 0x539c791, 0x539c8d8, 0x539c9f2, 0x539ca22, 0x539cb3e, 0x539cc27, 0x539cd08, 0x539cec0, 0x539cff3, 0x539d0c0, 0x539d1c1, 0x539d31e, 0x539d5c2, 0x539d656, 0x539d6b6, 0x539d6e2, 0x539d765, 0x539d7af, 0x539d7cd, 0x539d935, 0x539dc0d, 0x539dc82, 0x539dcfc, 0x539de2d, 0x539dec0, 0x539e0cc, 0x539e1db, 0x539e227, 0x539e4f3, 0x539e5ab, 0x539e5ee, 0x539e658, 0x539e7ec, 0x539e8ce, 0x539e920, 0x539eb46, 0x539ecf5, 0x539ed72, 0x539ef46, 0x539efe1, 0x539f9a7, 0x539faf9, 0x539fea8, 0x539ff1e, 0x53a00fc, 0x53a01a2, 0x53a020a, 0x53a03fb, 0x53a07a1, 0x53a08c1, 0x53a0a3c, 0x53a0be0, 0x53a0d25, 0x53a0e25, 0x53a0e88, 0x53a0fd6, 0x53a1720, 0x53a1a10, 0x53a1a7a, 0x53a1fd4], 'node': [0x5397d77, 0x5397ee7, 0x5397f9d, 0x53980b3, 0x5398123, 0x53982b9, 0x539834f, 0x53985d5, 0x539863d, 0x5398731, 0x5398b08, 0x5398b97, 0x5398d93, 0x5398e03, 0x5398f62, 0x539910c, 0x53991e8, 0x5399239, 0x53993c5, 0x53994c6, 0x5399551, 0x53995d4, 0x5399677, 0x53996c5, 0x5399886, 0x53999b4, 0x5399a76, 0x5399b1e, 0x5399cac, 0x5399d8e, 0x5399e7c, 0x539a067, 0x539a2cf, 0x539a61b, 0x539a73a, 0x539a892, 0x539ac10, 0x539af41, 0x539afac, 0x539b02c, 0x539b166, 0x539b213, 0x539b2b4, 0x539b439, 0x539b539, 0x539b691, 0x539b836, 0x539b89c, 0x539b8ff, 0x539b9bf, 0x539ba69, 0x539bb5c, 0x539bc53, 0x539bd2d, 0x539bf07, 0x539c0aa, 0x539c1a6, 0x539c355, 0x539c483, 0x539c7b3, 0x539cc57, 0x539cd2a, 0x539cee2, 0x539d0d0, 0x539d1de, 0x539d33b, 0x539d453, 0x539d666, 0x539d6fd, 0x539d838, 0x539dc92, 0x539deda, 0x539df53, 0x539dfc5, 0x539e06b, 0x539e0e9, 0x539e244, 0x539e675, 0x539e88e, 0x539e8d8, 0x539ed0d, 0x539ed92, 0x539effe, 0x539f23c, 0x539f2e1, 0x539f521, 0x539f910, 0x539f9b7, 0x539fc2a, 0x539fcea, 0x539fde0, 0x539fed0, 0x539ff23, 0x53a010c, 0x53a051e, 0x53a06e6, 0x53a07df, 0x53a08ea, 0x53a0bfd, 0x53a0d9e, 0x53a0de4, 0x53a0e35, 0x53a0e94, 0x53a0f25, 0x53a130a, 0x53a1406, 0x53a156d, 0x53a1730, 0x53a1a20, 0x53a1a8a, 0x53a1c5a, 0x53a1cf4, 0x53a1fde], 'height': [0x5398354, 0x53985da, 0x5398b0d, 0x5398baa, 0x5398cb3, 0x5398d98, 0x5398dfe, 0x5399111, 0x539923e, 0x53994cb, 0x5399556, 0x539967c, 0x5399cb1, 0x5399d5f, 0x5399d99, 0x5399e81, 0x539a06c, 0x539a241, 0x539a620, 0x539a73f, 0x539ac15, 0x539afb1, 0x539b08e, 0x539b8d2, 0x539b9c4, 0x539bd32, 0x539bf0c, 0x539c0e0, 0x539c1db, 0x539c35a, 0x539c488, 0x539c6f8, 0x539c7b8, 0x539ca28, 0x539cb55, 0x539cd2f, 0x539cee7, 0x539d0ec, 0x539d3d0, 0x539d489, 0x539d5d6, 0x539d6f5, 0x539d76f, 0x539d855, 0x539dc2f, 0x539de41, 0x539df88, 0x539e1e1, 0x539e5b1, 0x539e67a, 0x539eb4c, 0x539ed97, 0x539f003, 0x539f271, 0x539f316, 0x539f556, 0x539f945, 0x539f9bc, 0x539fb07, 0x539fc60, 0x539fd1f, 0x53a0111, 0x53a0554, 0x53a07e4, 0x53a0e3a, 0x53a0e99, 0x53a0fdc, 0x53a130f, 0x53a1572], 'position': [0x5397d7d, 0x5397eda, 0x5397fa3, 0x53982bf, 0x5398643, 0x5398737, 0x5398b12, 0x5398d9d, 0x5399116, 0x5399243, 0x53994d0, 0x539955b, 0x53995c7, 0x5399681, 0x53996ff, 0x539988c, 0x5399a7c, 0x5399b24, 0x5399cbe, 0x5399e86, 0x539a071, 0x539a2d5, 0x539a625, 0x539af47, 0x539afb6, 0x539b01f, 0x539b1a0, 0x539b42c, 0x539b905, 0x539ba6f, 0x539bb62, 0x539bc59, 0x539c47a, 0x539c7aa, 0x539cd21, 0x539ced9, 0x539d1e4, 0x539d341, 0x539d85a, 0x539dfff, 0x539e0ef, 0x539e24a, 0x539e680, 0x539e855, 0x539ed9c, 0x539f009, 0x539f9c1, 0x539fd84, 0x53a0720, 0x53a0c03, 0x53a0ee6, 0x53a13c7, 0x53a1736, 0x53a1c1b, 0x53a1cb5]},
    '0x55a5f10|0xa0': {'flag': [0x55a605d, 0x55a614e, 0x55a617f, 0x55a61cf, 0x55a64c2, 0x55a6512, 0x55a660e, 0x55a6661], 'node': [0x55a6161, 0x55a6192, 0x55a6269], 'height': [0x55a6070, 0x55a6271, 0x55a64e0, 0x55a6630], 'position': [0x55a6279]},
    '0x55a6750|0xa0': {'flag': [0x55a689d, 0x55a698e, 0x55a69bf, 0x55a6a0f, 0x55a6d02, 0x55a6d52, 0x55a6e4e, 0x55a6ea1], 'node': [0x55a69a1, 0x55a69d2, 0x55a6aa9], 'height': [0x55a68b0, 0x55a6ab1, 0x55a6d20, 0x55a6e70], 'position': [0x55a6ab9]},
}
HEIGHT_READS = {
    '0x28cd7a0|0x20': {0x28cdfac: 'other_phase', 0x28ce232: 'vector_copy', 0x28ce765: 'other_phase', 0x28ce808: 'other_phase', 0x28ce905: 'other_phase', 0x28ce9d0: 'other_phase', 0x28cea38: 'other_phase', 0x28ced54: 'other_phase', 0x28cee82: 'other_phase', 0x28cf112: 'other_phase', 0x28cf19e: 'other_phase', 0x28cf2c5: 'other_phase', 0x28cf86d: 'other_phase', 0x28cf91d: 'other_phase', 0x28cf957: 'other_phase', 0x28cfac0: 'other_phase', 0x28cfcae: 'other_phase', 0x28cfe84: 'vector_copy', 0x28d0270: 'other_phase', 0x28d038f: 'vector_copy', 0x28d0875: 'vector_copy', 0x28d0c14: 'other_phase', 0x28d0cf2: 'vector_copy', 0x28d1537: 'vector_copy', 0x28d1629: 'vector_copy', 0x28d198f: 'vector_copy', 0x28d1b6c: 'vector_copy', 0x28d1d40: 'vector_copy', 0x28d1e3b: 'vector_copy', 0x28d1fc4: 'vector_copy', 0x28d20f9: 'other_phase', 0x28d246d: 'other_phase', 0x28d25f5: 'other_phase', 0x28d28c6: 'vector_copy', 0x28d29f3: 'other_phase', 0x28d2da2: 'other_phase', 0x28d3092: 'other_phase', 0x28d31fe: 'vector_copy', 0x28d34e9: 'vector_copy', 0x28d35a2: 'vector_copy', 0x28d36ef: 'other_phase', 0x28d380e: 'other_phase', 0x28d3888: 'other_phase', 0x28d396e: 'other_phase', 0x28d3d49: 'other_phase', 0x28d3f5b: 'other_phase', 0x28d40a2: 'vector_copy', 0x28d42fc: 'vector_copy', 0x28d46d3: 'vector_copy', 0x28d47a7: 'other_phase', 0x28d4c86: 'vector_copy', 0x28d4ed1: 'other_phase', 0x28d5131: 'other_phase', 0x28d53a6: 'vector_copy', 0x28d544b: 'vector_copy', 0x28d568b: 'vector_copy', 0x28d5a8f: 'vector_copy', 0x28d5b06: 'other_phase', 0x28d5c52: 'other_phase', 0x28d5dac: 'vector_copy', 0x28d5e6b: 'vector_copy', 0x28d6262: 'vector_copy', 0x28d6698: 'vector_copy', 0x28d6929: 'vector_copy', 0x28d6f76: 'other_phase', 0x28d6fd5: 'other_phase', 0x28d7118: 'vector_copy', 0x28d7452: 'vector_copy', 0x28d76b5: 'vector_copy'},
    '0x2c440c0|0xa0': {0x2c44220: 'other_phase', 0x2c44421: 'other_phase', 0x2c44690: 'other_phase', 0x2c447e0: 'other_phase'},
    '0x538cd30|0x20': {0x538d534: 'other_phase', 0x538d7ba: 'vector_copy', 0x538dced: 'other_phase', 0x538dd8a: 'other_phase', 0x538de93: 'other_phase', 0x538df78: 'other_phase', 0x538dfde: 'other_phase', 0x538e2f1: 'other_phase', 0x538e41e: 'other_phase', 0x538e6ab: 'other_phase', 0x538e736: 'other_phase', 0x538e85c: 'other_phase', 0x538ee91: 'other_phase', 0x538ef3f: 'other_phase', 0x538ef79: 'other_phase', 0x538f061: 'other_phase', 0x538f24c: 'other_phase', 0x538f421: 'vector_copy', 0x538f800: 'other_phase', 0x538f91f: 'vector_copy', 0x538fdf5: 'vector_copy', 0x5390191: 'other_phase', 0x539026e: 'vector_copy', 0x5390ab2: 'vector_copy', 0x5390ba4: 'vector_copy', 0x5390f12: 'vector_copy', 0x53910ec: 'vector_copy', 0x53912c0: 'vector_copy', 0x53913bb: 'vector_copy', 0x539153a: 'vector_copy', 0x5391668: 'other_phase', 0x53918d8: 'other_phase', 0x5391998: 'other_phase', 0x5391c08: 'vector_copy', 0x5391d35: 'other_phase', 0x5391f0f: 'other_phase', 0x53920c7: 'other_phase', 0x53922cc: 'vector_copy', 0x53925b0: 'vector_copy', 0x5392669: 'vector_copy', 0x53927b6: 'other_phase', 0x53928d5: 'other_phase', 0x539294f: 'other_phase', 0x5392a35: 'other_phase', 0x5392e0f: 'other_phase', 0x5393021: 'other_phase', 0x5393168: 'vector_copy', 0x53933c1: 'vector_copy', 0x5393791: 'vector_copy', 0x539385a: 'other_phase', 0x5393d2c: 'vector_copy', 0x5393f77: 'other_phase', 0x53941e3: 'other_phase', 0x5394451: 'vector_copy', 0x53944f6: 'vector_copy', 0x5394736: 'vector_copy', 0x5394b25: 'vector_copy', 0x5394b9c: 'other_phase', 0x5394ce7: 'other_phase', 0x5394e40: 'vector_copy', 0x5394eff: 'vector_copy', 0x53952f1: 'vector_copy', 0x5395734: 'vector_copy', 0x53959c4: 'vector_copy', 0x539601a: 'other_phase', 0x5396079: 'other_phase', 0x53961bc: 'vector_copy', 0x53964ef: 'vector_copy', 0x5396752: 'vector_copy'},
    '0x5397b50|0x20': {0x5398354: 'other_phase', 0x53985da: 'vector_copy', 0x5398b0d: 'other_phase', 0x5398baa: 'other_phase', 0x5398cb3: 'other_phase', 0x5398d98: 'other_phase', 0x5398dfe: 'other_phase', 0x5399111: 'other_phase', 0x539923e: 'other_phase', 0x53994cb: 'other_phase', 0x5399556: 'other_phase', 0x539967c: 'other_phase', 0x5399cb1: 'other_phase', 0x5399d5f: 'other_phase', 0x5399d99: 'other_phase', 0x5399e81: 'other_phase', 0x539a06c: 'other_phase', 0x539a241: 'vector_copy', 0x539a620: 'other_phase', 0x539a73f: 'vector_copy', 0x539ac15: 'vector_copy', 0x539afb1: 'other_phase', 0x539b08e: 'vector_copy', 0x539b8d2: 'vector_copy', 0x539b9c4: 'vector_copy', 0x539bd32: 'vector_copy', 0x539bf0c: 'vector_copy', 0x539c0e0: 'vector_copy', 0x539c1db: 'vector_copy', 0x539c35a: 'vector_copy', 0x539c488: 'other_phase', 0x539c6f8: 'other_phase', 0x539c7b8: 'other_phase', 0x539ca28: 'vector_copy', 0x539cb55: 'other_phase', 0x539cd2f: 'other_phase', 0x539cee7: 'other_phase', 0x539d0ec: 'vector_copy', 0x539d3d0: 'vector_copy', 0x539d489: 'vector_copy', 0x539d5d6: 'other_phase', 0x539d6f5: 'other_phase', 0x539d76f: 'other_phase', 0x539d855: 'other_phase', 0x539dc2f: 'other_phase', 0x539de41: 'other_phase', 0x539df88: 'vector_copy', 0x539e1e1: 'vector_copy', 0x539e5b1: 'vector_copy', 0x539e67a: 'other_phase', 0x539eb4c: 'vector_copy', 0x539ed97: 'other_phase', 0x539f003: 'other_phase', 0x539f271: 'vector_copy', 0x539f316: 'vector_copy', 0x539f556: 'vector_copy', 0x539f945: 'vector_copy', 0x539f9bc: 'other_phase', 0x539fb07: 'other_phase', 0x539fc60: 'vector_copy', 0x539fd1f: 'vector_copy', 0x53a0111: 'vector_copy', 0x53a0554: 'vector_copy', 0x53a07e4: 'vector_copy', 0x53a0e3a: 'other_phase', 0x53a0e99: 'other_phase', 0x53a0fdc: 'vector_copy', 0x53a130f: 'vector_copy', 0x53a1572: 'vector_copy'},
    '0x55a5f10|0xa0': {0x55a6070: 'other_phase', 0x55a6271: 'other_phase', 0x55a64e0: 'other_phase', 0x55a6630: 'other_phase'},
    '0x55a6750|0xa0': {0x55a68b0: 'other_phase', 0x55a6ab1: 'other_phase', 0x55a6d20: 'other_phase', 0x55a6e70: 'other_phase'},
}


class PacketError(RuntimeError):
    pass


def _sha256(body):
    return hashlib.sha256(body).hexdigest()


def _section_bytes(sections_, data, start, end):
    for sec in sections_:
        if sec['type'] != 8 and sec['address'] <= start and end <= sec['address'] + sec['size']:
            off = sec['offset'] + (start - sec['address'])
            return data[off:off + end - start]
    raise PacketError(f'no file-backed section covers {start:#x}..{end:#x}')


_LINE = re.compile(r'^\s+([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$')


def _decode(sections_, data, start, end):
    body = _section_bytes(sections_, data, start, end)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as handle:
        handle.write(body)
        path = handle.name
    try:
        out = subprocess.check_output(
            ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
             f'--adjust-vma={start:#x}', path], text=True)
    finally:
        Path(path).unlink()
    _foundation_decode(out, start, end, body)
    rows = {}
    for line in out.splitlines():
        m = _LINE.match(line)
        if m:
            rows[int(m.group(1), 16)] = (m.group(2).replace(' ', ''), m.group(3).strip())
    return rows


def _check_pins(rows, pins, what):
    for addr, (raw, text) in sorted(pins.items()):
        row = rows.get(addr)
        if row is None:
            raise PacketError(f'{what}: no decoded instruction at pinned address {addr:#x}')
        if row != (raw, text):
            raise PacketError(f'{what}: pinned instruction mismatch at {addr:#x}')


def _check_calls(rows, calls, what):
    for addr, target in sorted(calls.items()):
        row = rows.get(addr)
        if row is None or not row[1].startswith('call'):
            raise PacketError(f'{what}: retained call missing at {addr:#x}')
        if int(row[1].split()[-1], 16) != target:
            raise PacketError(f'{what}: retained call target mismatch at {addr:#x}')


def _branch_sites(data, secs, target):
    direct, tail = set(), set()
    for sec in secs:
        if not (sec['flags'] & 4 and sec['size']):
            continue
        body = data[sec['offset']:sec['offset'] + sec['size']]
        base = sec['address']
        for op, acc in ((0xE8, direct), (0xE9, tail)):
            needle = bytes((op,))
            i = body.find(needle)
            while i != -1:
                if i + 5 <= len(body):
                    disp = struct.unpack_from('<i', body, i + 1)[0]
                    if base + i + 5 + disp == target:
                        acc.add(base + i)
                i = body.find(needle, i + 1)
    return direct, tail


_STORE_RE = re.compile(r'^mov\w*\s+[^,]+,\s*0x[0-9a-f]+\(%rsp\)$')


def _slot_reads(rows, slot):
    """Instructions that READ the given rsp slot (the chain's textual census):
    the slot appears in the operand text, the instruction is not an lea, and
    it is not a mov-family store whose destination is an rsp slot."""
    needle = f'{slot:#x}(%rsp)'
    hits = []
    for addr, (_raw, text) in sorted(rows.items()):
        if needle not in text or text.startswith('lea'):
            continue
        if _STORE_RE.match(text):
            continue
        hits.append(addr)
    return hits


def analyze(data):
    secs = sections(data)
    _summary, fdes, _gaps = fde_extents(data)
    if len(fdes) != FDE_COUNT:
        raise PacketError(f'FDE census mismatch: {len(fdes)} != {FDE_COUNT}')
    starts = [f['start'] for f in fdes]
    if len(set(starts)) != len(starts):
        raise PacketError('FDE starts are not unique')
    extents = {f['start']: (f['start'], f['end']) for f in fdes}

    # --- the u32 twin body
    body = _section_bytes(secs, data, U32TWIN_START, U32TWIN_END)
    if _sha256(body) != U32TWIN_BODY_SHA256:
        raise PacketError('u32 twin body differs from its pinned digest')
    rows = _decode(secs, data, U32TWIN_START, U32TWIN_END)
    _check_pins(rows, U32TWIN_PINS, 'u32 twin body')
    for addr, (_raw, text) in rows.items():
        if text.startswith('call'):
            raise PacketError(f'u32 twin body is not call-free: call at {addr:#x}')
        m = re.match(r'^(?:jmp|j\w+)\s+(0x[0-9a-f]+)$', text)
        if m and not (U32TWIN_START <= int(m.group(1), 16) < U32TWIN_END):
            raise PacketError(f'u32 twin body branches outside itself at {addr:#x}')

    # --- caller boundaries
    caller_rows = {}
    for start, ((bs, be), digest) in sorted(BOUNDARIES.items()):
        if extents.get(start) != (bs, be):
            raise PacketError(f'caller {start:#x} extent differs from the unwind table')
        raw = _section_bytes(secs, data, bs, be)
        if _sha256(raw) != digest:
            raise PacketError(f'caller {start:#x} differs from its pinned digest')
        caller_rows[start] = _decode(secs, data, bs, be)

    # --- branch census over the executable sections
    direct, tail = _branch_sites(data, secs, U32TWIN_START)
    if tail:
        raise PacketError('u32 twin search has tail-call sites')
    if direct != set(SITES):
        raise PacketError('call-site census mismatch: byte scan disagrees with the retained sites')
    rela_hits = 0
    for sec in secs:
        if sec['name'] != '.rela.dyn':
            continue
        raw = data[sec['offset']:sec['offset'] + sec['size']]
        for off in range(0, len(raw) - 23, 24):
            _r_off, r_type, r_add = struct.unpack_from('<QQq', raw, off)
            if r_type == 8 and r_add == U32TWIN_START:  # R_X86_64_RELATIVE
                rela_hits += 1
    if rela_hits != EXPECTED['rela_relative_hits']:
        raise PacketError('R_X86_64_RELATIVE census mismatch for the u32 twin body')

    # --- per-site records, windows, flag tests, flag-only verification
    classes = Counter()
    presentations = Counter()
    record_forms = Counter()
    flag_forms = Counter()
    for site, info in sorted(SITES.items()):
        caller = info['caller']
        rows = caller_rows[caller]
        win = WINDOWS[f'site_{site:#x}']
        ws, we = win['range']
        if not (BOUNDARIES[caller][0][0] <= ws and we <= BOUNDARIES[caller][0][1]):
            raise PacketError(f'site {site:#x} window escapes its caller FDE')
        _check_pins(rows, win['pins'], f'site {site:#x}')
        _check_calls(rows, win['calls'], f'site {site:#x}')
        call_row = rows.get(site)
        if call_row is None or call_row[1] != 'call   0x35bf500':
            raise PacketError(f'site {site:#x} is not a u32 twin call in its caller decode')
        flag_row = rows[info['flag']]
        if flag_row[1].startswith('cmpl'):
            form = 'dword'
        elif flag_row[1].startswith('cmpb'):
            form = 'byte'
        else:
            raise PacketError(f'site {site:#x}: unrecognised flag test {flag_row[1]!r}')
        if info['class'] == 'flag_only':
            if info['triple'] is not None:
                raise PacketError(f'site {site:#x}: consumption triple retained for a flag-only site')
            if info['flag'] != site + 5:
                raise PacketError(f'site {site:#x}: flag test does not immediately follow the call')
            # Inside the retained window, after the call, the flag test is
            # the only instruction allowed to touch a record slot: no
            # instruction in (site, window end] other than the flag test
            # itself may read the node, height or position slot.
            for a in sorted(rows):
                if site < a <= we and a != info['flag']:
                    for slot in (info['base'] + 8, info['base'] + 0x10, info['base'] + 0x18):
                        if f'{slot:#x}(%rsp)' in rows[a][1]:
                            raise PacketError(
                                f'site {site:#x}: instruction {a:#x} reads a record field '
                                f'other than the flag inside the site window')
        else:
            raise PacketError(f'site {site:#x}: unrecognised consumption class {info["class"]!r}')
        flag_forms[form] += 1
        classes[info['class']] += 1
        presentations[info['presentation']] += 1
        record_forms[info['record_form']] += 1

    # --- attribution windows
    for name, win in sorted(WINDOWS.items()):
        if name.startswith('site_'):
            continue
        caller = int(name.split('_')[1], 16)
        rows = caller_rows[caller]
        ws, we = win['range']
        if not (BOUNDARIES[caller][0][0] <= ws and we <= BOUNDARIES[caller][0][1]):
            raise PacketError(f'window {name} escapes its caller FDE')
        _check_pins(rows, win['pins'], f'window {name}')
        _check_calls(rows, win['calls'], f'window {name}')

    # --- whole-FDE slot census per (caller, base) unit
    units = {}
    for site, info in SITES.items():
        units.setdefault((info['caller'], info['base']), []).append(site)
    if len(units) != EXPECTED['census_units']:
        raise PacketError('census unit count mismatch')
    census = {}
    for (caller, base), _sites in sorted(units.items()):
        rows = caller_rows[caller]
        got = {
            'flag': _slot_reads(rows, base),
            'node': _slot_reads(rows, base + 8),
            'height': _slot_reads(rows, base + 0x10),
            'position': _slot_reads(rows, base + 0x18),
        }
        key = f'{caller:#x}|{base:#x}'
        want = SLOT_CENSUS[key]
        for field in ('flag', 'node', 'height', 'position'):
            if got[field] != want[field]:
                raise PacketError(f'slot census mismatch in {key} field {field}')
        census[key] = got

    # --- height verdict
    h_reads = 0
    h_classes = Counter()
    h_units = 0
    for key, per_read in sorted(HEIGHT_READS.items()):
        caller = int(key.split('|')[0], 16)
        rows = caller_rows[caller]
        if per_read:
            h_units += 1
        for read, cls in sorted(per_read.items()):
            h_reads += 1
            h_classes[cls] += 1
            text = rows[read][1]
            if cls == 'vector_copy':
                if not text.startswith(VECTOR_MNEMONICS):
                    raise PacketError(f'height read {read:#x} classed vector_copy but reads {text!r}')
            elif cls == 'other_phase':
                if f'caller_{caller:#x}_height_{read:#x}' not in WINDOWS:
                    raise PacketError(f'height read {read:#x} classed other_phase without a window')
            else:
                raise PacketError(f'height read {read:#x} has unrecognised class {cls!r}')
    census_height = {key: census[key]['height'] for key in census}
    retained_height = {key: sorted(per) for key, per in HEIGHT_READS.items()}
    if census_height != retained_height:
        raise PacketError('height read census disagrees with the retained attribution')

    counters = {
        'call_sites': len(SITES),
        'caller_fdes': len(BOUNDARIES),
        'census_units': len(units),
        'node_position_sites': classes['node_position'],
        'flag_only_sites': classes['flag_only'],
        'flag_node_addr_sites': classes['flag_node_addr'],
        'flag_dword_sites': flag_forms['dword'],
        'flag_byte_sites': flag_forms['byte'],
        'presentations': dict(presentations),
        'record_forms': dict(record_forms),
        'height_read_units': h_units,
        'height_never_read_units': len(units) - h_units,
        'height_reads': h_reads,
        'height_vector_copy_reads': h_classes['vector_copy'],
        'height_other_phase_reads': h_classes['other_phase'],
        'height_consumed_reads': 0,
        'windows': len(WINDOWS),
        'site_windows': sum(1 for n in WINDOWS if n.startswith('site_')),
        'attribution_windows': sum(1 for n in WINDOWS if '_height_' in n),
        'tail_call_sites': len(tail),
        'rela_relative_hits': rela_hits,
    }
    if counters != EXPECTED:
        raise PacketError(f'counter mismatch: {counters} != {EXPECTED}')

    return {
        'packet': {
            'id': PACKET_ID,
            'artifact': 'artifacts/node/115/hl-node',
            'scope': 'node #115 only',
            'status': 'complete-for-this-question',
        },
        'extractor': {
            'tool': 'tools/u32_twin_search_static.py',
            'test': 'tests/test_u32_twin_search_static.py',
            'authentication_inside_analyze': False,
        },
        'node': {
            'artifact_sha256': ARTIFACT_SHA256,
            'artifact_size': ARTIFACT_SIZE,
            'fde_records': FDE_COUNT,
        },
        'u32_twin': {
            'range': [hex(U32TWIN_START), hex(U32TWIN_END)],
            'length_bytes': U32TWIN_END - U32TWIN_START,
            'sha256': U32TWIN_BODY_SHA256,
            'call_free': True,
            'key_dereference': hex(KEY_DEREF),
            'count_load': hex(COUNT_LOAD),
            'key_compare': hex(KEY_COMPARE),
            'descent_load': hex(DESCENT_LOAD),
            'hit_flag_value': 0,
            'miss_flag_value': 1,
        },
        'node_layout': {k: (hex(v) if isinstance(v, int) and v > 11 else v) for k, v in NODE_LAYOUT.items()},
        'record_layout': {'size': 32, 'flag': '0x0', 'node': '0x8', 'height': '0x10', 'position': '0x18'},
        'boundaries': {
            f'caller_{start:#x}': {'range': [hex(bs), hex(be)], 'sha256': digest}
            for start, ((bs, be), digest) in sorted(BOUNDARIES.items())
        },
        'call_sites': {
            hex(site): {
                'caller': hex(info['caller']),
                'record_base': hex(info['base']),
                'class': info['class'],
                'flag_test': hex(info['flag']),
                'presentation': info['presentation'],
                'record_form': info['record_form'],
            }
            for site, info in sorted(SITES.items())
        },
        'slot_census': {
            key: {field: [hex(a) for a in addrs] for field, addrs in fields.items()}
            for key, fields in sorted(census.items())
        },
        'height_reads': {
            key: {hex(a): cls for a, cls in sorted(per.items())}
            for key, per in sorted(HEIGHT_READS.items())
        },
        'height_verdict': {
            'consumed_reads': 0,
            'statement': 'no consumer reads the u32 twin record height field as a number: '
                         'at every call site the flag is the only record field read, and in '
                         'every census unit the height slot reads are wholesale vector '
                         'copies of the frame struct or belong to other phases of the same '
                         'frame slot',
        },
        'windows': {
            name: {
                'range': [hex(win['range'][0]), hex(win['range'][1])],
                'calls': {hex(a): hex(t) for a, t in sorted(win['calls'].items())},
                'pins': {hex(a): [raw, text] for a, (raw, text) in sorted(win['pins'].items())},
            }
            for name, win in sorted(WINDOWS.items())
        },
        'counters': counters,
    }


def _frames(data):
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as handle:
        handle.write(data)
        path = handle.name
    try:
        out = subprocess.check_output(['readelf', '-wf', path], text=True)
    finally:
        Path(path).unlink()
    ranges = [(U32TWIN_START, U32TWIN_END)] + [v[0] for v in BOUNDARIES.values()]
    kept = []
    for line in out.splitlines():
        m = re.match(r'^([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+FDE\s+cie=[0-9a-f]+\s+pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
        if m:
            pc = (int(m.group(4), 16), int(m.group(5), 16))
            if pc in ranges:
                kept.append(line.replace(path, '<authenticated-node115>'))
    return ('\n'.join(kept) + '\n').encode()


def _u32_twin_export(data):
    """Full-body export in the chain's format: intel-syntax objdump of the
    authenticated ELF itself, with the source path normalised."""
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as handle:
        handle.write(data)
        path = handle.name
    try:
        out = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={U32TWIN_START:#x}',
             f'--stop-address={U32TWIN_END:#x}', path], text=True)
    finally:
        Path(path).unlink()
    if f'{U32TWIN_START:x}:' not in out:
        raise PacketError('u32 twin export does not cover the body')
    return out.replace(path, '<authenticated-node115>').encode()


def generate(data, out_dir):
    if _sha256(data) != ARTIFACT_SHA256 or len(data) != ARTIFACT_SIZE:
        raise PacketError('artifact SHA-256 mismatch')
    records = analyze(data)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json.dumps(records, indent=1, sort_keys=True) + '\n')
    (out / 'frames.txt').write_bytes(_frames(data))
    (out / 'u32_twin_search_full_body_35bf500_35bf592_objdump.txt').write_bytes(_u32_twin_export(data))
    return records


def main(argv):
    if len(argv) != 3 or argv[1] != 'generate':
        print('usage: u32_twin_search_static.py generate <output-dir>', file=sys.stderr)
        return 2
    artifact = ROOT / 'artifacts/node/115/hl-node'
    generate(artifact.read_bytes(), argv[2])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
