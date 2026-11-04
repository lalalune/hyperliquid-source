#!/usr/bin/env python3
"""Pin the node 115 element-builder window for RE-006 (static only).

This extractor authenticates the builder machinery that PR #2561's
writer census pointed to: the insertion paths of the sibling-search
node layout (keys at node +0x798, count at +0x7f2, edges at +0x7f8,
elements of 0xb0 bytes at node + position * 0xb0).  The window pinned
here is the complete allocation and insertion machinery for that
layout, in its three clone families:

* three insert wrappers (305 bytes each) that allocate a fresh leaf
  node of 0x7f8 bytes through GOT slot 0x64df480 and copy the new
  element in with one whole-element memcpy of 0xb0 bytes;
* three insert-and-split giants (3,418 bytes each) behind them, the
  only E8 callers of which are the wrappers;
* six flat-to-tree build initialisers and three bulk-build giants
  (2,328 bytes each) that populate fresh trees from a flat array;
* four insert-or-assign drivers, the only E8 callers of the
  wrappers, whose element arrives as a caller-supplied argument.

The census below shows that no body in this window stores to any of
the eight element fields the join callee reads (+0x40, +0x58, +0x60,
+0x78, +0x80, +0x88, +0x90, +0x98), through any non-stack address,
and that every element-derived store in the window is the
displacement-0 head-qword store.  Element bytes enter a node only as
wholesale copies: a 0xb0 whole-element memcpy, a head-qword store
plus a 0xa8 tail memcpy, or a whole-element memmove shift.  The
drivers in turn never write a field either: they forward their
element argument, or stage and return it through 0xb0 memcpys.  The
original per-field writer therefore sits above the drivers' element
argument; the drivers' own E8 callers are censused as the boundary
and are not traced, per the one-level rule of the lane brief.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export as _foundation_decode

PACKET_ID = 'RE-006-node115-element-builder'
ARTIFACT_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARTIFACT_SIZE = 105896032

ALLOC_SLOT = 0x64DF480
MEMCPY_SLOT = 0x64DF508
MEMMOVE_SLOT = 0x64DF568
DEALLOC_SLOT = 0x64DF4A0
ALLOC_BODY = 0x6355830
DEALLOC_BODY = 0x635DE30
SIBLING = (0x35BF460, 0x35BF4F2)
CALLEE = (0x36A0D80, 0x36A0FD6)

LEAF_NODE_SIZE = 0x7F8
INTERNAL_NODE_SIZE = 0x858
ELEMENT_SIZE = 0xB0
TAIL_SIZE = 0xA8

BODIES = {
    'wrap_a': {'range': (0x26daaf0, 0x26dac21), 'sha256': '1050c903c10baac22b9bf6bd5192298aaec5c8fb1479e2ed4e641f0f12016b81',
        'role': 'insert wrapper, clone family 1: root-leaf fast path (0x7f8 allocation + one 0xb0 element memcpy), else dispatches to giant_a1'},
    'wrap_b': {'range': (0x370e210, 0x370e341), 'sha256': '11b70d7da6e9e6ac66bd340b615a5af7801374e34e109afa73d39252468fa08b',
        'role': 'insert wrapper, clone family 2: same shape as wrap_a, dispatches to giant_a2'},
    'wrap_c': {'range': (0x51f0d50, 0x51f0e81), 'sha256': '8ca3d5692ae4ca79eafe7b0e332cc7f904180363b70d6bb00ba615b85af0ae1f',
        'role': 'insert wrapper, clone family 3: same shape as wrap_a, dispatches to giant_a3'},
    'giant_a1': {'range': (0x1ca5420, 0x1ca617a), 'sha256': '5b4d5332e56906f1c135cb8a27d5612474c259e207b18c6cfd39e88066433298',
        'role': 'insert + split-propagation giant, clone family 1; only E8 caller is wrap_a'},
    'giant_a2': {'range': (0x34e4910, 0x34e566a), 'sha256': '7f23dfcd3bd7ef137458d40e91786a33ac32f9072681c660b918a35f2cd87eda',
        'role': 'insert + split-propagation giant, clone family 2; only E8 caller is wrap_b'},
    'giant_a3': {'range': (0x4c693b0, 0x4c6a10a), 'sha256': '53660947d40b14a05ffc591e2f94655f9db72df901873716aac52ccdd57475a5',
        'role': 'insert + split-propagation giant, clone family 3; only E8 caller is wrap_c'},
    'init_b1a': {'range': (0x23a4e90, 0x23a5039), 'sha256': '67d9a0f647964fcd8a8d6a2169e5a74867b9aa02b159ebf8b69e8dd644d1b062',
        'role': 'flat-to-tree build initialiser, clone family 1 (single-element and partitioned paths), calls giant_b1'},
    'init_b1b': {'range': (0x23b3680, 0x23b3813), 'sha256': '89250936d707451adb64fcaf0b7315c02b01128a4dfb17831ab59f1f2398b669',
        'role': 'flat-to-tree build initialiser, clone family 1 (second entry), calls giant_b1'},
    'init_b2a': {'range': (0x3885190, 0x3885323), 'sha256': '84162b0f613d621f005b7975b69d32ac6bdd4d1069e89e37e8f09719b3b36e38',
        'role': 'flat-to-tree build initialiser, clone family 2, calls giant_b2'},
    'init_b2b': {'range': (0x3896840, 0x38969e9), 'sha256': 'b1f5383147501e9d257fb7e135d92f95f38e5ff88a0a47b4ec1767062fee234b',
        'role': 'flat-to-tree build initialiser, clone family 2 (second entry), calls giant_b2'},
    'init_b3a': {'range': (0x5169d90, 0x5169f39), 'sha256': 'f7ae9b60d45e698a6031413be11cbb705380e0859d56ce3f0fad8a9230152584',
        'role': 'flat-to-tree build initialiser, clone family 3, calls giant_b3'},
    'init_b3b': {'range': (0x516a760, 0x516a8f3), 'sha256': '3bad2f3ca2c952f96f5e0eddb29d761d76b2de0ce1af1613e2cecc6aec742d39',
        'role': 'flat-to-tree build initialiser, clone family 3 (second entry), calls giant_b3'},
    'giant_b1': {'range': (0x1cff190, 0x1cffaa8), 'sha256': '76c31607cfade1b5abf715ae6f77e5ec0d76c51fb0c4a9839454b17c2f7faccf',
        'role': 'bulk-build insert giant, clone family 1; only E8 callers are init_b1a and init_b1b'},
    'giant_b2': {'range': (0x3578e50, 0x3579768), 'sha256': '316536b3a781637d45c2b3cd41bb7e8154b8592782e4e0b0efbc0f57d3f11207',
        'role': 'bulk-build insert giant, clone family 2; only E8 callers are init_b2a and init_b2b'},
    'giant_b3': {'range': (0x4cba750, 0x4cbb068), 'sha256': 'd7747ca9b61f5009cfb4edb68d60341c3036c4f77f93c17a54ac90bca1cd6b9a',
        'role': 'bulk-build insert giant, clone family 3; only E8 callers are init_b3a and init_b3b'},
    'caller_a': {'range': (0x2dc3900, 0x2dc3dda), 'sha256': 'ef31f8404f187a290a687c149ba3d3a05c3427274bc9ccabc2735008eb693720',
        'role': 'insert-or-assign driver, clone family 1: the element arrives as the 4th argument; forwards it to wrap_a or copies it wholesale (0xb0 memcpys)'},
    'caller_b1': {'range': (0x3ce15b0, 0x3ce1711), 'sha256': '2462c10c151e3eb8e3a5af9d077104b722cb234e2b4f1444dc9ec1c410073e58',
        'role': 'insert-or-assign driver, clone family 2 (full form): element argument forwarded to wrap_b or copied wholesale'},
    'caller_b2': {'range': (0x3f1a150, 0x3f1a1f4), 'sha256': 'd049f95c5ad500b3cb695059448545bd118c7fc08803745172b0d5079a468755',
        'role': 'insert-or-assign driver, clone family 2 (thin adapter form): forwards the element argument to wrap_b'},
    'caller_c': {'range': (0x4dd2ca0, 0x4dd317a), 'sha256': '03ee628fc1427fcc089c3a745d9b92a128afe42e8151d998177e629a30aef7cb',
        'role': 'insert-or-assign driver, clone family 3: element argument forwarded to wrap_c or copied wholesale'},
    'alloc_body': {'range': (0x6355830, 0x63558f2), 'sha256': '72c29274a75359df7c598d254d102cbab84f51d359256facb415bb90bffec5af',
        'role': 'shared allocator body bound to GOT slot 0x64df480'},
    'dealloc_body': {'range': (0x635de30, 0x635ded5), 'sha256': '714fc5cdd28a2587427c9dac8a25685ec09695a3a21bc9af0eb09b29ae503f61',
        'role': 'shared sized-deallocation body bound to GOT slot 0x64df4a0'},
}

PINNED_ROWS = {
    'wrap_a': {
        40741616: ('55', 'push   %rbp'),
        40741617: ('4157', 'push   %r15'),
        40741619: ('4156', 'push   %r14'),
        40741621: ('4155', 'push   %r13'),
        40741623: ('4154', 'push   %r12'),
        40741625: ('53', 'push   %rbx'),
        40741626: ('4883ec38', 'sub    $0x38,%rsp'),
        40741630: ('4989d7', 'mov    %rdx,%r15'),
        40741633: ('4989f6', 'mov    %rsi,%r14'),
        40741636: ('4889fb', 'mov    %rdi,%rbx'),
        40741639: ('48837e1000', 'cmpq   $0x0,0x10(%rsi)'),
        40741644: ('7446', 'je     0x26dab54'),
        40741646: ('498d4610', 'lea    0x10(%r14),%rax'),
        40741650: ('488b4810', 'mov    0x10(%rax),%rcx'),
        40741654: ('48894c2430', 'mov    %rcx,0x30(%rsp)'),
        40741659: ('0f1000', 'movups (%rax),%xmm0'),
        40741662: ('0f29442420', 'movaps %xmm0,0x20(%rsp)'),
        40741667: ('498b5608', 'mov    0x8(%r14),%rdx'),
        40741671: ('4d8d4e28', 'lea    0x28(%r14),%r9'),
        40741675: ('488d7c2408', 'lea    0x8(%rsp),%rdi'),
        40741680: ('488d742420', 'lea    0x20(%rsp),%rsi'),
        40741685: ('4c89f9', 'mov    %r15,%rcx'),
        40741688: ('4d89f0', 'mov    %r14,%r8'),
        40741691: ('e8e0a85cff', 'call   0x1ca5420'),
        40741696: ('4d8b2e', 'mov    (%r14),%r13'),
        40741699: ('4c8b642408', 'mov    0x8(%rsp),%r12'),
        40741704: ('488b442410', 'mov    0x10(%rsp),%rax'),
        40741709: ('488b6c2418', 'mov    0x18(%rsp),%rbp'),
        40741714: ('eb7c', 'jmp    0x26dabd0'),
        40741716: ('4d8b2e', 'mov    (%r14),%r13'),
        40741719: ('bff8070000', 'mov    $0x7f8,%edi'),
        40741724: ('ff151e49e003', 'call   *0x3e0491e(%rip)'),
        40741730: ('4885c0', 'test   %rax,%rax'),
        40741733: ('0f848d000000', 'je     0x26dabf8'),
        40741739: ('4989c4', 'mov    %rax,%r12'),
        40741742: ('48c78090070000', 'movq   $0x0,0x790(%rax)'),
        40741749: ('00000000', ''),
        40741753: ('66c780f2070000', 'movw   $0x0,0x7f2(%rax)'),
        40741760: ('0000', ''),
        40741762: ('49894500', 'mov    %rax,0x0(%r13)'),
        40741766: ('49c74508000000', 'movq   $0x0,0x8(%r13)'),
        40741773: ('00', ''),
        40741774: ('0fb7a8f2070000', 'movzwl 0x7f2(%rax),%ebp'),
        40741781: ('4883fd0b', 'cmp    $0xb,%rbp'),
        40741785: ('736d', 'jae    0x26dac08'),
        40741787: ('498b4608', 'mov    0x8(%r14),%rax'),
        40741791: ('8d4d01', 'lea    0x1(%rbp),%ecx'),
        40741794: ('6641898c24f207', 'mov    %cx,0x7f2(%r12)'),
        40741801: ('0000', ''),
        40741803: ('498984ec980700', 'mov    %rax,0x798(%r12,%rbp,8)'),
        40741810: ('00', ''),
        40741811: ('4869c5b0000000', 'imul   $0xb0,%rbp,%rax'),
        40741818: ('4c89e7', 'mov    %r12,%rdi'),
        40741821: ('4801c7', 'add    %rax,%rdi'),
        40741824: ('bab0000000', 'mov    $0xb0,%edx'),
        40741829: ('4c89fe', 'mov    %r15,%rsi'),
        40741832: ('ff153a49e003', 'call   *0x3e0493a(%rip)'),
        40741838: ('31c0', 'xor    %eax,%eax'),
        40741840: ('49ff4510', 'incq   0x10(%r13)'),
        40741844: ('498b0e', 'mov    (%r14),%rcx'),
        40741847: ('4c8923', 'mov    %r12,(%rbx)'),
        40741850: ('48894308', 'mov    %rax,0x8(%rbx)'),
        40741854: ('48896b10', 'mov    %rbp,0x10(%rbx)'),
        40741858: ('48894b18', 'mov    %rcx,0x18(%rbx)'),
        40741862: ('4889d8', 'mov    %rbx,%rax'),
        40741865: ('4883c438', 'add    $0x38,%rsp'),
        40741869: ('5b', 'pop    %rbx'),
        40741870: ('415c', 'pop    %r12'),
        40741872: ('415d', 'pop    %r13'),
        40741874: ('415e', 'pop    %r14'),
        40741876: ('415f', 'pop    %r15'),
        40741878: ('5d', 'pop    %rbp'),
        40741879: ('c3', 'ret'),
        40741880: ('bf08000000', 'mov    $0x8,%edi'),
        40741885: ('bef8070000', 'mov    $0x7f8,%esi'),
        40741890: ('ff158848e003', 'call   *0x3e04888(%rip)'),
        40741896: ('488d3db1d9d7fd', 'lea    -0x228264f(%rip),%rdi'),
        40741903: ('488d15a24ed403', 'lea    0x3d44ea2(%rip),%rdx'),
        40741910: ('be20000000', 'mov    $0x20,%esi'),
        40741915: ('ff150f4be003', 'call   *0x3e04b0f(%rip)'),
    },
    'wrap_b': {
        57729552: ('55', 'push   %rbp'),
        57729553: ('4157', 'push   %r15'),
        57729555: ('4156', 'push   %r14'),
        57729557: ('4155', 'push   %r13'),
        57729559: ('4154', 'push   %r12'),
        57729561: ('53', 'push   %rbx'),
        57729562: ('4883ec38', 'sub    $0x38,%rsp'),
        57729566: ('4989d7', 'mov    %rdx,%r15'),
        57729569: ('4989f6', 'mov    %rsi,%r14'),
        57729572: ('4889fb', 'mov    %rdi,%rbx'),
        57729575: ('48837e1000', 'cmpq   $0x0,0x10(%rsi)'),
        57729580: ('7446', 'je     0x370e274'),
        57729582: ('498d4610', 'lea    0x10(%r14),%rax'),
        57729586: ('488b4810', 'mov    0x10(%rax),%rcx'),
        57729590: ('48894c2430', 'mov    %rcx,0x30(%rsp)'),
        57729595: ('0f1000', 'movups (%rax),%xmm0'),
        57729598: ('0f29442420', 'movaps %xmm0,0x20(%rsp)'),
        57729603: ('498b5608', 'mov    0x8(%r14),%rdx'),
        57729607: ('4d8d4e28', 'lea    0x28(%r14),%r9'),
        57729611: ('488d7c2408', 'lea    0x8(%rsp),%rdi'),
        57729616: ('488d742420', 'lea    0x20(%rsp),%rsi'),
        57729621: ('4c89f9', 'mov    %r15,%rcx'),
        57729624: ('4d89f0', 'mov    %r14,%r8'),
        57729627: ('e8b066ddff', 'call   0x34e4910'),
        57729632: ('4d8b2e', 'mov    (%r14),%r13'),
        57729635: ('4c8b642408', 'mov    0x8(%rsp),%r12'),
        57729640: ('488b442410', 'mov    0x10(%rsp),%rax'),
        57729645: ('488b6c2418', 'mov    0x18(%rsp),%rbp'),
        57729650: ('eb7c', 'jmp    0x370e2f0'),
        57729652: ('4d8b2e', 'mov    (%r14),%r13'),
        57729655: ('bff8070000', 'mov    $0x7f8,%edi'),
        57729660: ('ff15fe11dd02', 'call   *0x2dd11fe(%rip)'),
        57729666: ('4885c0', 'test   %rax,%rax'),
        57729669: ('0f848d000000', 'je     0x370e318'),
        57729675: ('4989c4', 'mov    %rax,%r12'),
        57729678: ('48c78090070000', 'movq   $0x0,0x790(%rax)'),
        57729685: ('00000000', ''),
        57729689: ('66c780f2070000', 'movw   $0x0,0x7f2(%rax)'),
        57729696: ('0000', ''),
        57729698: ('49894500', 'mov    %rax,0x0(%r13)'),
        57729702: ('49c74508000000', 'movq   $0x0,0x8(%r13)'),
        57729709: ('00', ''),
        57729710: ('0fb7a8f2070000', 'movzwl 0x7f2(%rax),%ebp'),
        57729717: ('4883fd0b', 'cmp    $0xb,%rbp'),
        57729721: ('736d', 'jae    0x370e328'),
        57729723: ('498b4608', 'mov    0x8(%r14),%rax'),
        57729727: ('8d4d01', 'lea    0x1(%rbp),%ecx'),
        57729730: ('6641898c24f207', 'mov    %cx,0x7f2(%r12)'),
        57729737: ('0000', ''),
        57729739: ('498984ec980700', 'mov    %rax,0x798(%r12,%rbp,8)'),
        57729746: ('00', ''),
        57729747: ('4869c5b0000000', 'imul   $0xb0,%rbp,%rax'),
        57729754: ('4c89e7', 'mov    %r12,%rdi'),
        57729757: ('4801c7', 'add    %rax,%rdi'),
        57729760: ('bab0000000', 'mov    $0xb0,%edx'),
        57729765: ('4c89fe', 'mov    %r15,%rsi'),
        57729768: ('ff151a12dd02', 'call   *0x2dd121a(%rip)'),
        57729774: ('31c0', 'xor    %eax,%eax'),
        57729776: ('49ff4510', 'incq   0x10(%r13)'),
        57729780: ('498b0e', 'mov    (%r14),%rcx'),
        57729783: ('4c8923', 'mov    %r12,(%rbx)'),
        57729786: ('48894308', 'mov    %rax,0x8(%rbx)'),
        57729790: ('48896b10', 'mov    %rbp,0x10(%rbx)'),
        57729794: ('48894b18', 'mov    %rcx,0x18(%rbx)'),
        57729798: ('4889d8', 'mov    %rbx,%rax'),
        57729801: ('4883c438', 'add    $0x38,%rsp'),
        57729805: ('5b', 'pop    %rbx'),
        57729806: ('415c', 'pop    %r12'),
        57729808: ('415d', 'pop    %r13'),
        57729810: ('415e', 'pop    %r14'),
        57729812: ('415f', 'pop    %r15'),
        57729814: ('5d', 'pop    %rbp'),
        57729815: ('c3', 'ret'),
        57729816: ('bf08000000', 'mov    $0x8,%edi'),
        57729821: ('bef8070000', 'mov    $0x7f8,%esi'),
        57729826: ('ff156811dd02', 'call   *0x2dd1168(%rip)'),
        57729832: ('488d3d91a2d4fc', 'lea    -0x32b5d6f(%rip),%rdi'),
        57729839: ('488d154a6dd502', 'lea    0x2d56d4a(%rip),%rdx'),
        57729846: ('be20000000', 'mov    $0x20,%esi'),
        57729851: ('ff15ef13dd02', 'call   *0x2dd13ef(%rip)'),
    },
    'wrap_c': {
        85921104: ('55', 'push   %rbp'),
        85921105: ('4157', 'push   %r15'),
        85921107: ('4156', 'push   %r14'),
        85921109: ('4155', 'push   %r13'),
        85921111: ('4154', 'push   %r12'),
        85921113: ('53', 'push   %rbx'),
        85921114: ('4883ec38', 'sub    $0x38,%rsp'),
        85921118: ('4989d7', 'mov    %rdx,%r15'),
        85921121: ('4989f6', 'mov    %rsi,%r14'),
        85921124: ('4889fb', 'mov    %rdi,%rbx'),
        85921127: ('48837e1000', 'cmpq   $0x0,0x10(%rsi)'),
        85921132: ('7446', 'je     0x51f0db4'),
        85921134: ('498d4610', 'lea    0x10(%r14),%rax'),
        85921138: ('488b4810', 'mov    0x10(%rax),%rcx'),
        85921142: ('48894c2430', 'mov    %rcx,0x30(%rsp)'),
        85921147: ('0f1000', 'movups (%rax),%xmm0'),
        85921150: ('0f29442420', 'movaps %xmm0,0x20(%rsp)'),
        85921155: ('498b5608', 'mov    0x8(%r14),%rdx'),
        85921159: ('4d8d4e28', 'lea    0x28(%r14),%r9'),
        85921163: ('488d7c2408', 'lea    0x8(%rsp),%rdi'),
        85921168: ('488d742420', 'lea    0x20(%rsp),%rsi'),
        85921173: ('4c89f9', 'mov    %r15,%rcx'),
        85921176: ('4d89f0', 'mov    %r14,%r8'),
        85921179: ('e81086a7ff', 'call   0x4c693b0'),
        85921184: ('4d8b2e', 'mov    (%r14),%r13'),
        85921187: ('4c8b642408', 'mov    0x8(%rsp),%r12'),
        85921192: ('488b442410', 'mov    0x10(%rsp),%rax'),
        85921197: ('488b6c2418', 'mov    0x18(%rsp),%rbp'),
        85921202: ('eb7c', 'jmp    0x51f0e30'),
        85921204: ('4d8b2e', 'mov    (%r14),%r13'),
        85921207: ('bff8070000', 'mov    $0x7f8,%edi'),
        85921212: ('ff15bee62e01', 'call   *0x12ee6be(%rip)'),
        85921218: ('4885c0', 'test   %rax,%rax'),
        85921221: ('0f848d000000', 'je     0x51f0e58'),
        85921227: ('4989c4', 'mov    %rax,%r12'),
        85921230: ('48c78090070000', 'movq   $0x0,0x790(%rax)'),
        85921237: ('00000000', ''),
        85921241: ('66c780f2070000', 'movw   $0x0,0x7f2(%rax)'),
        85921248: ('0000', ''),
        85921250: ('49894500', 'mov    %rax,0x0(%r13)'),
        85921254: ('49c74508000000', 'movq   $0x0,0x8(%r13)'),
        85921261: ('00', ''),
        85921262: ('0fb7a8f2070000', 'movzwl 0x7f2(%rax),%ebp'),
        85921269: ('4883fd0b', 'cmp    $0xb,%rbp'),
        85921273: ('736d', 'jae    0x51f0e68'),
        85921275: ('498b4608', 'mov    0x8(%r14),%rax'),
        85921279: ('8d4d01', 'lea    0x1(%rbp),%ecx'),
        85921282: ('6641898c24f207', 'mov    %cx,0x7f2(%r12)'),
        85921289: ('0000', ''),
        85921291: ('498984ec980700', 'mov    %rax,0x798(%r12,%rbp,8)'),
        85921298: ('00', ''),
        85921299: ('4869c5b0000000', 'imul   $0xb0,%rbp,%rax'),
        85921306: ('4c89e7', 'mov    %r12,%rdi'),
        85921309: ('4801c7', 'add    %rax,%rdi'),
        85921312: ('bab0000000', 'mov    $0xb0,%edx'),
        85921317: ('4c89fe', 'mov    %r15,%rsi'),
        85921320: ('ff15dae62e01', 'call   *0x12ee6da(%rip)'),
        85921326: ('31c0', 'xor    %eax,%eax'),
        85921328: ('49ff4510', 'incq   0x10(%r13)'),
        85921332: ('498b0e', 'mov    (%r14),%rcx'),
        85921335: ('4c8923', 'mov    %r12,(%rbx)'),
        85921338: ('48894308', 'mov    %rax,0x8(%rbx)'),
        85921342: ('48896b10', 'mov    %rbp,0x10(%rbx)'),
        85921346: ('48894b18', 'mov    %rcx,0x18(%rbx)'),
        85921350: ('4889d8', 'mov    %rbx,%rax'),
        85921353: ('4883c438', 'add    $0x38,%rsp'),
        85921357: ('5b', 'pop    %rbx'),
        85921358: ('415c', 'pop    %r12'),
        85921360: ('415d', 'pop    %r13'),
        85921362: ('415e', 'pop    %r14'),
        85921364: ('415f', 'pop    %r15'),
        85921366: ('5d', 'pop    %rbp'),
        85921367: ('c3', 'ret'),
        85921368: ('bf08000000', 'mov    $0x8,%edi'),
        85921373: ('bef8070000', 'mov    $0x7f8,%esi'),
        85921378: ('ff1528e62e01', 'call   *0x12ee628(%rip)'),
        85921384: ('488d3d517726fb', 'lea    -0x4d988af(%rip),%rdi'),
        85921391: ('488d153a962a01', 'lea    0x12a963a(%rip),%rdx'),
        85921398: ('be20000000', 'mov    $0x20,%esi'),
        85921403: ('ff15afe82e01', 'call   *0x12ee8af(%rip)'),
    },
    'init_b1a': {
        37375632: ('4157', 'push   %r15'),
        37375634: ('4156', 'push   %r14'),
        37375636: ('4154', 'push   %r12'),
        37375638: ('53', 'push   %rbx'),
        37375639: ('4881ec18010000', 'sub    $0x118,%rsp'),
        37375646: ('4889fb', 'mov    %rdi,%rbx'),
        37375649: ('0f1006', 'movups (%rsi),%xmm0'),
        37375652: ('0f104e10', 'movups 0x10(%rsi),%xmm1'),
        37375656: ('0f294c2450', 'movaps %xmm1,0x50(%rsp)'),
        37375661: ('0f29442440', 'movaps %xmm0,0x40(%rsp)'),
        37375666: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        37375671: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        37375676: ('e8cf19faff', 'call   0x2346890'),
        37375681: ('4c8b7c2428', 'mov    0x28(%rsp),%r15'),
        37375686: ('4d85ff', 'test   %r15,%r15'),
        37375689: ('0f84b7000000', 'je     0x23a4f86'),
        37375695: ('4c8b742420', 'mov    0x20(%rsp),%r14'),
        37375700: ('488d44240f', 'lea    0xf(%rsp),%rax'),
        37375705: ('4889442440', 'mov    %rax,0x40(%rsp)'),
        37375710: ('4983ff01', 'cmp    $0x1,%r15'),
        37375714: ('0f85dd000000', 'jne    0x23a4fc5'),
        37375720: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        37375725: ('bff8070000', 'mov    $0x7f8,%edi'),
        37375730: ('ff1588a51304', 'call   *0x413a588(%rip)'),
        37375736: ('4885c0', 'test   %rax,%rax'),
        37375739: ('0f84e4000000', 'je     0x23a4fe5'),
        37375745: ('48c78090070000', 'movq   $0x0,0x790(%rax)'),
        37375752: ('00000000', ''),
        37375756: ('66c780f2070000', 'movw   $0x0,0x7f2(%rax)'),
        37375763: ('0000', ''),
        37375765: ('48c74424380000', 'movq   $0x0,0x38(%rsp)'),
        37375772: ('0000', ''),
        37375774: ('4889442430', 'mov    %rax,0x30(%rsp)'),
        37375779: ('48c74424100000', 'movq   $0x0,0x10(%rsp)'),
        37375786: ('0000', ''),
        37375788: ('4969c7b8000000', 'imul   $0xb8,%r15,%rax'),
        37375795: ('4c01f0', 'add    %r14,%rax'),
        37375798: ('48c74424480300', 'movq   $0x3,0x48(%rsp)'),
        37375805: ('0000', ''),
        37375807: ('4c89b424f80000', 'mov    %r14,0xf8(%rsp)'),
        37375814: ('00', ''),
        37375815: ('4c89b424000100', 'mov    %r14,0x100(%rsp)'),
        37375822: ('00', ''),
        37375823: ('4c89a424080100', 'mov    %r12,0x108(%rsp)'),
        37375830: ('00', ''),
        37375831: ('48898424100100', 'mov    %rax,0x110(%rsp)'),
        37375838: ('00', ''),
        37375839: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        37375844: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        37375849: ('488d542410', 'lea    0x10(%rsp),%rdx'),
        37375854: ('e81da295ff', 'call   0x1cff190'),
        37375859: ('0f10442430', 'movups 0x30(%rsp),%xmm0'),
        37375864: ('488b442410', 'mov    0x10(%rsp),%rax'),
        37375869: ('0f1103', 'movups %xmm0,(%rbx)'),
        37375872: ('48894310', 'mov    %rax,0x10(%rbx)'),
        37375876: ('eb2d', 'jmp    0x23a4fb3'),
        37375878: ('48c70300000000', 'movq   $0x0,(%rbx)'),
        37375885: ('48c74310000000', 'movq   $0x0,0x10(%rbx)'),
        37375892: ('00', ''),
        37375893: ('488b442418', 'mov    0x18(%rsp),%rax'),
        37375898: ('4885c0', 'test   %rax,%rax'),
        37375901: ('7414', 'je     0x23a4fb3'),
        37375903: ('488b7c2420', 'mov    0x20(%rsp),%rdi'),
        37375908: ('4869f0b8000000', 'imul   $0xb8,%rax,%rsi'),
        37375915: ('31d2', 'xor    %edx,%edx'),
        37375917: ('ff15eda41304', 'call   *0x413a4ed(%rip)'),
        37375923: ('4889d8', 'mov    %rbx,%rax'),
        37375926: ('4881c418010000', 'add    $0x118,%rsp'),
        37375933: ('5b', 'pop    %rbx'),
        37375934: ('415c', 'pop    %r12'),
        37375936: ('415e', 'pop    %r14'),
        37375938: ('415f', 'pop    %r15'),
        37375940: ('c3', 'ret'),
        37375941: ('4983ff15', 'cmp    $0x15,%r15'),
        37375945: ('732c', 'jae    0x23a4ff7'),
        37375947: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        37375952: ('ba01000000', 'mov    $0x1,%edx'),
        37375957: ('4c89f7', 'mov    %r14,%rdi'),
        37375960: ('4c89fe', 'mov    %r15,%rsi'),
        37375963: ('e890283200', 'call   0x26c7870'),
        37375968: ('e903ffffff', 'jmp    0x23a4ee8'),
        37375973: ('bf08000000', 'mov    $0x8,%edi'),
        37375978: ('bef8070000', 'mov    $0x7f8,%esi'),
        37375983: ('ff159ba41304', 'call   *0x413a49b(%rip)'),
        37375989: ('0f0b', 'ud2'),
        37375991: ('488d542440', 'lea    0x40(%rsp),%rdx'),
        37375996: ('4c89f7', 'mov    %r14,%rdi'),
        37375999: ('4c89fe', 'mov    %r15,%rsi'),
        37376002: ('ff1540031404', 'call   *0x4140340(%rip)'),
        37376008: ('e9dbfeffff', 'jmp    0x23a4ee8'),
        37376013: ('4889c3', 'mov    %rax,%rbx'),
        37376016: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        37376021: ('eb03', 'jmp    0x23a501a'),
        37376023: ('4889c3', 'mov    %rax,%rbx'),
        37376026: ('4d85e4', 'test   %r12,%r12'),
        37376029: ('7412', 'je     0x23a5031'),
        37376031: ('4969f4b8000000', 'imul   $0xb8,%r12,%rsi'),
        37376038: ('4c89f7', 'mov    %r14,%rdi'),
        37376041: ('31d2', 'xor    %edx,%edx'),
        37376043: ('ff156fa41304', 'call   *0x413a46f(%rip)'),
        37376049: ('4889df', 'mov    %rbx,%rdi'),
        37376052: ('e817ba0404', 'call   0x63f0a50'),
    },
    'init_b1b': {
        37435008: ('4157', 'push   %r15'),
        37435010: ('4156', 'push   %r14'),
        37435012: ('4154', 'push   %r12'),
        37435014: ('53', 'push   %rbx'),
        37435015: ('4881ec18010000', 'sub    $0x118,%rsp'),
        37435022: ('4889fb', 'mov    %rdi,%rbx'),
        37435025: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        37435030: ('e83593f1ff', 'call   0x22cc9d0'),
        37435035: ('4c8b7c2428', 'mov    0x28(%rsp),%r15'),
        37435040: ('4d85ff', 'test   %r15,%r15'),
        37435043: ('0f84b7000000', 'je     0x23b3760'),
        37435049: ('4c8b742420', 'mov    0x20(%rsp),%r14'),
        37435054: ('488d44240f', 'lea    0xf(%rsp),%rax'),
        37435059: ('4889442440', 'mov    %rax,0x40(%rsp)'),
        37435064: ('4983ff01', 'cmp    $0x1,%r15'),
        37435068: ('0f85dd000000', 'jne    0x23b379f'),
        37435074: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        37435079: ('bff8070000', 'mov    $0x7f8,%edi'),
        37435084: ('ff15aebd1204', 'call   *0x412bdae(%rip)'),
        37435090: ('4885c0', 'test   %rax,%rax'),
        37435093: ('0f84e4000000', 'je     0x23b37bf'),
        37435099: ('48c78090070000', 'movq   $0x0,0x790(%rax)'),
        37435106: ('00000000', ''),
        37435110: ('66c780f2070000', 'movw   $0x0,0x7f2(%rax)'),
        37435117: ('0000', ''),
        37435119: ('48c74424380000', 'movq   $0x0,0x38(%rsp)'),
        37435126: ('0000', ''),
        37435128: ('4889442430', 'mov    %rax,0x30(%rsp)'),
        37435133: ('48c74424100000', 'movq   $0x0,0x10(%rsp)'),
        37435140: ('0000', ''),
        37435142: ('4969c7b8000000', 'imul   $0xb8,%r15,%rax'),
        37435149: ('4c01f0', 'add    %r14,%rax'),
        37435152: ('48c74424480300', 'movq   $0x3,0x48(%rsp)'),
        37435159: ('0000', ''),
        37435161: ('4c89b424f80000', 'mov    %r14,0xf8(%rsp)'),
        37435168: ('00', ''),
        37435169: ('4c89b424000100', 'mov    %r14,0x100(%rsp)'),
        37435176: ('00', ''),
        37435177: ('4c89a424080100', 'mov    %r12,0x108(%rsp)'),
        37435184: ('00', ''),
        37435185: ('48898424100100', 'mov    %rax,0x110(%rsp)'),
        37435192: ('00', ''),
        37435193: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        37435198: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        37435203: ('488d542410', 'lea    0x10(%rsp),%rdx'),
        37435208: ('e843ba94ff', 'call   0x1cff190'),
        37435213: ('0f10442430', 'movups 0x30(%rsp),%xmm0'),
        37435218: ('488b442410', 'mov    0x10(%rsp),%rax'),
        37435223: ('0f1103', 'movups %xmm0,(%rbx)'),
        37435226: ('48894310', 'mov    %rax,0x10(%rbx)'),
        37435230: ('eb2d', 'jmp    0x23b378d'),
        37435232: ('48c70300000000', 'movq   $0x0,(%rbx)'),
        37435239: ('48c74310000000', 'movq   $0x0,0x10(%rbx)'),
        37435246: ('00', ''),
        37435247: ('488b442418', 'mov    0x18(%rsp),%rax'),
        37435252: ('4885c0', 'test   %rax,%rax'),
        37435255: ('7414', 'je     0x23b378d'),
        37435257: ('488b7c2420', 'mov    0x20(%rsp),%rdi'),
        37435262: ('4869f0b8000000', 'imul   $0xb8,%rax,%rsi'),
        37435269: ('31d2', 'xor    %edx,%edx'),
        37435271: ('ff1513bd1204', 'call   *0x412bd13(%rip)'),
        37435277: ('4889d8', 'mov    %rbx,%rax'),
        37435280: ('4881c418010000', 'add    $0x118,%rsp'),
        37435287: ('5b', 'pop    %rbx'),
        37435288: ('415c', 'pop    %r12'),
        37435290: ('415e', 'pop    %r14'),
        37435292: ('415f', 'pop    %r15'),
        37435294: ('c3', 'ret'),
        37435295: ('4983ff15', 'cmp    $0x15,%r15'),
        37435299: ('732c', 'jae    0x23b37d1'),
        37435301: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        37435306: ('ba01000000', 'mov    $0x1,%edx'),
        37435311: ('4c89f7', 'mov    %r14,%rdi'),
        37435314: ('4c89fe', 'mov    %r15,%rsi'),
        37435317: ('e8b6403100', 'call   0x26c7870'),
        37435322: ('e903ffffff', 'jmp    0x23b36c2'),
        37435327: ('bf08000000', 'mov    $0x8,%edi'),
        37435332: ('bef8070000', 'mov    $0x7f8,%esi'),
        37435337: ('ff15c1bc1204', 'call   *0x412bcc1(%rip)'),
        37435343: ('0f0b', 'ud2'),
        37435345: ('488d542440', 'lea    0x40(%rsp),%rdx'),
        37435350: ('4c89f7', 'mov    %r14,%rdi'),
        37435353: ('4c89fe', 'mov    %r15,%rsi'),
        37435356: ('ff15e61f1304', 'call   *0x4131fe6(%rip)'),
        37435362: ('e9dbfeffff', 'jmp    0x23b36c2'),
        37435367: ('4889c3', 'mov    %rax,%rbx'),
        37435370: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        37435375: ('eb03', 'jmp    0x23b37f4'),
        37435377: ('4889c3', 'mov    %rax,%rbx'),
        37435380: ('4d85e4', 'test   %r12,%r12'),
        37435383: ('7412', 'je     0x23b380b'),
        37435385: ('4969f4b8000000', 'imul   $0xb8,%r12,%rsi'),
        37435392: ('4c89f7', 'mov    %r14,%rdi'),
        37435395: ('31d2', 'xor    %edx,%edx'),
        37435397: ('ff1595bc1204', 'call   *0x412bc95(%rip)'),
        37435403: ('4889df', 'mov    %rbx,%rdi'),
        37435406: ('e83dd20304', 'call   0x63f0a50'),
    },
    'init_b2a': {
        59265424: ('4157', 'push   %r15'),
        59265426: ('4156', 'push   %r14'),
        59265428: ('4154', 'push   %r12'),
        59265430: ('53', 'push   %rbx'),
        59265431: ('4881ec18010000', 'sub    $0x118,%rsp'),
        59265438: ('4889fb', 'mov    %rdi,%rbx'),
        59265441: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        59265446: ('e8f5f94e00', 'call   0x3d74ba0'),
        59265451: ('4c8b7c2428', 'mov    0x28(%rsp),%r15'),
        59265456: ('4d85ff', 'test   %r15,%r15'),
        59265459: ('0f84b7000000', 'je     0x3885270'),
        59265465: ('4c8b742420', 'mov    0x20(%rsp),%r14'),
        59265470: ('488d44240f', 'lea    0xf(%rsp),%rax'),
        59265475: ('4889442440', 'mov    %rax,0x40(%rsp)'),
        59265480: ('4983ff01', 'cmp    $0x1,%r15'),
        59265484: ('0f85dd000000', 'jne    0x38852af'),
        59265490: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        59265495: ('bff8070000', 'mov    $0x7f8,%edi'),
        59265500: ('ff159ea2c502', 'call   *0x2c5a29e(%rip)'),
        59265506: ('4885c0', 'test   %rax,%rax'),
        59265509: ('0f84e4000000', 'je     0x38852cf'),
        59265515: ('48c78090070000', 'movq   $0x0,0x790(%rax)'),
        59265522: ('00000000', ''),
        59265526: ('66c780f2070000', 'movw   $0x0,0x7f2(%rax)'),
        59265533: ('0000', ''),
        59265535: ('48c74424380000', 'movq   $0x0,0x38(%rsp)'),
        59265542: ('0000', ''),
        59265544: ('4889442430', 'mov    %rax,0x30(%rsp)'),
        59265549: ('48c74424100000', 'movq   $0x0,0x10(%rsp)'),
        59265556: ('0000', ''),
        59265558: ('4969c7b8000000', 'imul   $0xb8,%r15,%rax'),
        59265565: ('4c01f0', 'add    %r14,%rax'),
        59265568: ('48c74424480300', 'movq   $0x3,0x48(%rsp)'),
        59265575: ('0000', ''),
        59265577: ('4c89b424f80000', 'mov    %r14,0xf8(%rsp)'),
        59265584: ('00', ''),
        59265585: ('4c89b424000100', 'mov    %r14,0x100(%rsp)'),
        59265592: ('00', ''),
        59265593: ('4c89a424080100', 'mov    %r12,0x108(%rsp)'),
        59265600: ('00', ''),
        59265601: ('48898424100100', 'mov    %rax,0x110(%rsp)'),
        59265608: ('00', ''),
        59265609: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        59265614: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        59265619: ('488d542410', 'lea    0x10(%rsp),%rdx'),
        59265624: ('e8f33bcfff', 'call   0x3578e50'),
        59265629: ('0f10442430', 'movups 0x30(%rsp),%xmm0'),
        59265634: ('488b442410', 'mov    0x10(%rsp),%rax'),
        59265639: ('0f1103', 'movups %xmm0,(%rbx)'),
        59265642: ('48894310', 'mov    %rax,0x10(%rbx)'),
        59265646: ('eb2d', 'jmp    0x388529d'),
        59265648: ('48c70300000000', 'movq   $0x0,(%rbx)'),
        59265655: ('48c74310000000', 'movq   $0x0,0x10(%rbx)'),
        59265662: ('00', ''),
        59265663: ('488b442418', 'mov    0x18(%rsp),%rax'),
        59265668: ('4885c0', 'test   %rax,%rax'),
        59265671: ('7414', 'je     0x388529d'),
        59265673: ('488b7c2420', 'mov    0x20(%rsp),%rdi'),
        59265678: ('4869f0b8000000', 'imul   $0xb8,%rax,%rsi'),
        59265685: ('31d2', 'xor    %edx,%edx'),
        59265687: ('ff1503a2c502', 'call   *0x2c5a203(%rip)'),
        59265693: ('4889d8', 'mov    %rbx,%rax'),
        59265696: ('4881c418010000', 'add    $0x118,%rsp'),
        59265703: ('5b', 'pop    %rbx'),
        59265704: ('415c', 'pop    %r12'),
        59265706: ('415e', 'pop    %r14'),
        59265708: ('415f', 'pop    %r15'),
        59265710: ('c3', 'ret'),
        59265711: ('4983ff15', 'cmp    $0x15,%r15'),
        59265715: ('732c', 'jae    0x38852e1'),
        59265717: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        59265722: ('ba01000000', 'mov    $0x1,%edx'),
        59265727: ('4c89f7', 'mov    %r14,%rdi'),
        59265730: ('4c89fe', 'mov    %r15,%rsi'),
        59265733: ('e8966eae00', 'call   0x436c160'),
        59265738: ('e903ffffff', 'jmp    0x38851d2'),
        59265743: ('bf08000000', 'mov    $0x8,%edi'),
        59265748: ('bef8070000', 'mov    $0x7f8,%esi'),
        59265753: ('ff15b1a1c502', 'call   *0x2c5a1b1(%rip)'),
        59265759: ('0f0b', 'ud2'),
        59265761: ('488d542440', 'lea    0x40(%rsp),%rdx'),
        59265766: ('4c89f7', 'mov    %r14,%rdi'),
        59265769: ('4c89fe', 'mov    %r15,%rsi'),
        59265772: ('ff15d604c602', 'call   *0x2c604d6(%rip)'),
        59265778: ('e9dbfeffff', 'jmp    0x38851d2'),
        59265783: ('4889c3', 'mov    %rax,%rbx'),
        59265786: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        59265791: ('eb03', 'jmp    0x3885304'),
        59265793: ('4889c3', 'mov    %rax,%rbx'),
        59265796: ('4d85e4', 'test   %r12,%r12'),
        59265799: ('7412', 'je     0x388531b'),
        59265801: ('4969f4b8000000', 'imul   $0xb8,%r12,%rsi'),
        59265808: ('4c89f7', 'mov    %r14,%rdi'),
        59265811: ('31d2', 'xor    %edx,%edx'),
        59265813: ('ff1585a1c502', 'call   *0x2c5a185(%rip)'),
        59265819: ('4889df', 'mov    %rbx,%rdi'),
        59265822: ('e82db7b602', 'call   0x63f0a50'),
    },
    'init_b2b': {
        59336768: ('4157', 'push   %r15'),
        59336770: ('4156', 'push   %r14'),
        59336772: ('4154', 'push   %r12'),
        59336774: ('53', 'push   %rbx'),
        59336775: ('4881ec18010000', 'sub    $0x118,%rsp'),
        59336782: ('4889fb', 'mov    %rdi,%rbx'),
        59336785: ('0f1006', 'movups (%rsi),%xmm0'),
        59336788: ('0f104e10', 'movups 0x10(%rsi),%xmm1'),
        59336792: ('0f294c2450', 'movaps %xmm1,0x50(%rsp)'),
        59336797: ('0f29442440', 'movaps %xmm0,0x40(%rsp)'),
        59336802: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        59336807: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        59336812: ('e85f065300', 'call   0x3dc6ed0'),
        59336817: ('4c8b7c2428', 'mov    0x28(%rsp),%r15'),
        59336822: ('4d85ff', 'test   %r15,%r15'),
        59336825: ('0f84b7000000', 'je     0x3896936'),
        59336831: ('4c8b742420', 'mov    0x20(%rsp),%r14'),
        59336836: ('488d44240f', 'lea    0xf(%rsp),%rax'),
        59336841: ('4889442440', 'mov    %rax,0x40(%rsp)'),
        59336846: ('4983ff01', 'cmp    $0x1,%r15'),
        59336850: ('0f85dd000000', 'jne    0x3896975'),
        59336856: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        59336861: ('bff8070000', 'mov    $0x7f8,%edi'),
        59336866: ('ff15d88bc402', 'call   *0x2c48bd8(%rip)'),
        59336872: ('4885c0', 'test   %rax,%rax'),
        59336875: ('0f84e4000000', 'je     0x3896995'),
        59336881: ('48c78090070000', 'movq   $0x0,0x790(%rax)'),
        59336888: ('00000000', ''),
        59336892: ('66c780f2070000', 'movw   $0x0,0x7f2(%rax)'),
        59336899: ('0000', ''),
        59336901: ('48c74424380000', 'movq   $0x0,0x38(%rsp)'),
        59336908: ('0000', ''),
        59336910: ('4889442430', 'mov    %rax,0x30(%rsp)'),
        59336915: ('48c74424100000', 'movq   $0x0,0x10(%rsp)'),
        59336922: ('0000', ''),
        59336924: ('4969c7b8000000', 'imul   $0xb8,%r15,%rax'),
        59336931: ('4c01f0', 'add    %r14,%rax'),
        59336934: ('48c74424480300', 'movq   $0x3,0x48(%rsp)'),
        59336941: ('0000', ''),
        59336943: ('4c89b424f80000', 'mov    %r14,0xf8(%rsp)'),
        59336950: ('00', ''),
        59336951: ('4c89b424000100', 'mov    %r14,0x100(%rsp)'),
        59336958: ('00', ''),
        59336959: ('4c89a424080100', 'mov    %r12,0x108(%rsp)'),
        59336966: ('00', ''),
        59336967: ('48898424100100', 'mov    %rax,0x110(%rsp)'),
        59336974: ('00', ''),
        59336975: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        59336980: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        59336985: ('488d542410', 'lea    0x10(%rsp),%rdx'),
        59336990: ('e82d25ceff', 'call   0x3578e50'),
        59336995: ('0f10442430', 'movups 0x30(%rsp),%xmm0'),
        59337000: ('488b442410', 'mov    0x10(%rsp),%rax'),
        59337005: ('0f1103', 'movups %xmm0,(%rbx)'),
        59337008: ('48894310', 'mov    %rax,0x10(%rbx)'),
        59337012: ('eb2d', 'jmp    0x3896963'),
        59337014: ('48c70300000000', 'movq   $0x0,(%rbx)'),
        59337021: ('48c74310000000', 'movq   $0x0,0x10(%rbx)'),
        59337028: ('00', ''),
        59337029: ('488b442418', 'mov    0x18(%rsp),%rax'),
        59337034: ('4885c0', 'test   %rax,%rax'),
        59337037: ('7414', 'je     0x3896963'),
        59337039: ('488b7c2420', 'mov    0x20(%rsp),%rdi'),
        59337044: ('4869f0b8000000', 'imul   $0xb8,%rax,%rsi'),
        59337051: ('31d2', 'xor    %edx,%edx'),
        59337053: ('ff153d8bc402', 'call   *0x2c48b3d(%rip)'),
        59337059: ('4889d8', 'mov    %rbx,%rax'),
        59337062: ('4881c418010000', 'add    $0x118,%rsp'),
        59337069: ('5b', 'pop    %rbx'),
        59337070: ('415c', 'pop    %r12'),
        59337072: ('415e', 'pop    %r14'),
        59337074: ('415f', 'pop    %r15'),
        59337076: ('c3', 'ret'),
        59337077: ('4983ff15', 'cmp    $0x15,%r15'),
        59337081: ('732c', 'jae    0x38969a7'),
        59337083: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        59337088: ('ba01000000', 'mov    $0x1,%edx'),
        59337093: ('4c89f7', 'mov    %r14,%rdi'),
        59337096: ('4c89fe', 'mov    %r15,%rsi'),
        59337099: ('e8d057ad00', 'call   0x436c160'),
        59337104: ('e903ffffff', 'jmp    0x3896898'),
        59337109: ('bf08000000', 'mov    $0x8,%edi'),
        59337114: ('bef8070000', 'mov    $0x7f8,%esi'),
        59337119: ('ff15eb8ac402', 'call   *0x2c48aeb(%rip)'),
        59337125: ('0f0b', 'ud2'),
        59337127: ('488d542440', 'lea    0x40(%rsp),%rdx'),
        59337132: ('4c89f7', 'mov    %r14,%rdi'),
        59337135: ('4c89fe', 'mov    %r15,%rsi'),
        59337138: ('ff1590e9c402', 'call   *0x2c4e990(%rip)'),
        59337144: ('e9dbfeffff', 'jmp    0x3896898'),
        59337149: ('4889c3', 'mov    %rax,%rbx'),
        59337152: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        59337157: ('eb03', 'jmp    0x38969ca'),
        59337159: ('4889c3', 'mov    %rax,%rbx'),
        59337162: ('4d85e4', 'test   %r12,%r12'),
        59337165: ('7412', 'je     0x38969e1'),
        59337167: ('4969f4b8000000', 'imul   $0xb8,%r12,%rsi'),
        59337174: ('4c89f7', 'mov    %r14,%rdi'),
        59337177: ('31d2', 'xor    %edx,%edx'),
        59337179: ('ff15bf8ac402', 'call   *0x2c48abf(%rip)'),
        59337185: ('4889df', 'mov    %rbx,%rdi'),
        59337188: ('e867a0b502', 'call   0x63f0a50'),
    },
    'init_b3a': {
        85368208: ('4157', 'push   %r15'),
        85368210: ('4156', 'push   %r14'),
        85368212: ('4154', 'push   %r12'),
        85368214: ('53', 'push   %rbx'),
        85368215: ('4881ec18010000', 'sub    $0x118,%rsp'),
        85368222: ('4889fb', 'mov    %rdi,%rbx'),
        85368225: ('0f1006', 'movups (%rsi),%xmm0'),
        85368228: ('0f104e10', 'movups 0x10(%rsi),%xmm1'),
        85368232: ('0f294c2450', 'movaps %xmm1,0x50(%rsp)'),
        85368237: ('0f29442440', 'movaps %xmm0,0x40(%rsp)'),
        85368242: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        85368247: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        85368252: ('e86f9fa200', 'call   0x5b93d30'),
        85368257: ('4c8b7c2428', 'mov    0x28(%rsp),%r15'),
        85368262: ('4d85ff', 'test   %r15,%r15'),
        85368265: ('0f84b7000000', 'je     0x5169e86'),
        85368271: ('4c8b742420', 'mov    0x20(%rsp),%r14'),
        85368276: ('488d44240f', 'lea    0xf(%rsp),%rax'),
        85368281: ('4889442440', 'mov    %rax,0x40(%rsp)'),
        85368286: ('4983ff01', 'cmp    $0x1,%r15'),
        85368290: ('0f85dd000000', 'jne    0x5169ec5'),
        85368296: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        85368301: ('bff8070000', 'mov    $0x7f8,%edi'),
        85368306: ('ff1588563701', 'call   *0x1375688(%rip)'),
        85368312: ('4885c0', 'test   %rax,%rax'),
        85368315: ('0f84e4000000', 'je     0x5169ee5'),
        85368321: ('48c78090070000', 'movq   $0x0,0x790(%rax)'),
        85368328: ('00000000', ''),
        85368332: ('66c780f2070000', 'movw   $0x0,0x7f2(%rax)'),
        85368339: ('0000', ''),
        85368341: ('48c74424380000', 'movq   $0x0,0x38(%rsp)'),
        85368348: ('0000', ''),
        85368350: ('4889442430', 'mov    %rax,0x30(%rsp)'),
        85368355: ('48c74424100000', 'movq   $0x0,0x10(%rsp)'),
        85368362: ('0000', ''),
        85368364: ('4969c7b8000000', 'imul   $0xb8,%r15,%rax'),
        85368371: ('4c01f0', 'add    %r14,%rax'),
        85368374: ('48c74424480300', 'movq   $0x3,0x48(%rsp)'),
        85368381: ('0000', ''),
        85368383: ('4c89b424f80000', 'mov    %r14,0xf8(%rsp)'),
        85368390: ('00', ''),
        85368391: ('4c89b424000100', 'mov    %r14,0x100(%rsp)'),
        85368398: ('00', ''),
        85368399: ('4c89a424080100', 'mov    %r12,0x108(%rsp)'),
        85368406: ('00', ''),
        85368407: ('48898424100100', 'mov    %rax,0x110(%rsp)'),
        85368414: ('00', ''),
        85368415: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        85368420: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        85368425: ('488d542410', 'lea    0x10(%rsp),%rdx'),
        85368430: ('e8dd08b5ff', 'call   0x4cba750'),
        85368435: ('0f10442430', 'movups 0x30(%rsp),%xmm0'),
        85368440: ('488b442410', 'mov    0x10(%rsp),%rax'),
        85368445: ('0f1103', 'movups %xmm0,(%rbx)'),
        85368448: ('48894310', 'mov    %rax,0x10(%rbx)'),
        85368452: ('eb2d', 'jmp    0x5169eb3'),
        85368454: ('48c70300000000', 'movq   $0x0,(%rbx)'),
        85368461: ('48c74310000000', 'movq   $0x0,0x10(%rbx)'),
        85368468: ('00', ''),
        85368469: ('488b442418', 'mov    0x18(%rsp),%rax'),
        85368474: ('4885c0', 'test   %rax,%rax'),
        85368477: ('7414', 'je     0x5169eb3'),
        85368479: ('488b7c2420', 'mov    0x20(%rsp),%rdi'),
        85368484: ('4869f0b8000000', 'imul   $0xb8,%rax,%rsi'),
        85368491: ('31d2', 'xor    %edx,%edx'),
        85368493: ('ff15ed553701', 'call   *0x13755ed(%rip)'),
        85368499: ('4889d8', 'mov    %rbx,%rax'),
        85368502: ('4881c418010000', 'add    $0x118,%rsp'),
        85368509: ('5b', 'pop    %rbx'),
        85368510: ('415c', 'pop    %r12'),
        85368512: ('415e', 'pop    %r14'),
        85368514: ('415f', 'pop    %r15'),
        85368516: ('c3', 'ret'),
        85368517: ('4983ff15', 'cmp    $0x15,%r15'),
        85368521: ('732c', 'jae    0x5169ef7'),
        85368523: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        85368528: ('ba01000000', 'mov    $0x1,%edx'),
        85368533: ('4c89f7', 'mov    %r14,%rdi'),
        85368536: ('4c89fe', 'mov    %r15,%rsi'),
        85368539: ('e8d0072800', 'call   0x53ea6b0'),
        85368544: ('e903ffffff', 'jmp    0x5169de8'),
        85368549: ('bf08000000', 'mov    $0x8,%edi'),
        85368554: ('bef8070000', 'mov    $0x7f8,%esi'),
        85368559: ('ff159b553701', 'call   *0x137559b(%rip)'),
        85368565: ('0f0b', 'ud2'),
        85368567: ('488d542440', 'lea    0x40(%rsp),%rdx'),
        85368572: ('4c89f7', 'mov    %r14,%rdi'),
        85368575: ('4c89fe', 'mov    %r15,%rsi'),
        85368578: ('ff1540b43701', 'call   *0x137b440(%rip)'),
        85368584: ('e9dbfeffff', 'jmp    0x5169de8'),
        85368589: ('4889c3', 'mov    %rax,%rbx'),
        85368592: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        85368597: ('eb03', 'jmp    0x5169f1a'),
        85368599: ('4889c3', 'mov    %rax,%rbx'),
        85368602: ('4d85e4', 'test   %r12,%r12'),
        85368605: ('7412', 'je     0x5169f31'),
        85368607: ('4969f4b8000000', 'imul   $0xb8,%r12,%rsi'),
        85368614: ('4c89f7', 'mov    %r14,%rdi'),
        85368617: ('31d2', 'xor    %edx,%edx'),
        85368619: ('ff156f553701', 'call   *0x137556f(%rip)'),
        85368625: ('4889df', 'mov    %rbx,%rdi'),
        85368628: ('e8176b2801', 'call   0x63f0a50'),
    },
    'init_b3b': {
        85370720: ('4157', 'push   %r15'),
        85370722: ('4156', 'push   %r14'),
        85370724: ('4154', 'push   %r12'),
        85370726: ('53', 'push   %rbx'),
        85370727: ('4881ec18010000', 'sub    $0x118,%rsp'),
        85370734: ('4889fb', 'mov    %rdi,%rbx'),
        85370737: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        85370742: ('e8e5f89600', 'call   0x5ada060'),
        85370747: ('4c8b7c2428', 'mov    0x28(%rsp),%r15'),
        85370752: ('4d85ff', 'test   %r15,%r15'),
        85370755: ('0f84b7000000', 'je     0x516a840'),
        85370761: ('4c8b742420', 'mov    0x20(%rsp),%r14'),
        85370766: ('488d44240f', 'lea    0xf(%rsp),%rax'),
        85370771: ('4889442440', 'mov    %rax,0x40(%rsp)'),
        85370776: ('4983ff01', 'cmp    $0x1,%r15'),
        85370780: ('0f85dd000000', 'jne    0x516a87f'),
        85370786: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        85370791: ('bff8070000', 'mov    $0x7f8,%edi'),
        85370796: ('ff15ce4c3701', 'call   *0x1374cce(%rip)'),
        85370802: ('4885c0', 'test   %rax,%rax'),
        85370805: ('0f84e4000000', 'je     0x516a89f'),
        85370811: ('48c78090070000', 'movq   $0x0,0x790(%rax)'),
        85370818: ('00000000', ''),
        85370822: ('66c780f2070000', 'movw   $0x0,0x7f2(%rax)'),
        85370829: ('0000', ''),
        85370831: ('48c74424380000', 'movq   $0x0,0x38(%rsp)'),
        85370838: ('0000', ''),
        85370840: ('4889442430', 'mov    %rax,0x30(%rsp)'),
        85370845: ('48c74424100000', 'movq   $0x0,0x10(%rsp)'),
        85370852: ('0000', ''),
        85370854: ('4969c7b8000000', 'imul   $0xb8,%r15,%rax'),
        85370861: ('4c01f0', 'add    %r14,%rax'),
        85370864: ('48c74424480300', 'movq   $0x3,0x48(%rsp)'),
        85370871: ('0000', ''),
        85370873: ('4c89b424f80000', 'mov    %r14,0xf8(%rsp)'),
        85370880: ('00', ''),
        85370881: ('4c89b424000100', 'mov    %r14,0x100(%rsp)'),
        85370888: ('00', ''),
        85370889: ('4c89a424080100', 'mov    %r12,0x108(%rsp)'),
        85370896: ('00', ''),
        85370897: ('48898424100100', 'mov    %rax,0x110(%rsp)'),
        85370904: ('00', ''),
        85370905: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        85370910: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        85370915: ('488d542410', 'lea    0x10(%rsp),%rdx'),
        85370920: ('e823ffb4ff', 'call   0x4cba750'),
        85370925: ('0f10442430', 'movups 0x30(%rsp),%xmm0'),
        85370930: ('488b442410', 'mov    0x10(%rsp),%rax'),
        85370935: ('0f1103', 'movups %xmm0,(%rbx)'),
        85370938: ('48894310', 'mov    %rax,0x10(%rbx)'),
        85370942: ('eb2d', 'jmp    0x516a86d'),
        85370944: ('48c70300000000', 'movq   $0x0,(%rbx)'),
        85370951: ('48c74310000000', 'movq   $0x0,0x10(%rbx)'),
        85370958: ('00', ''),
        85370959: ('488b442418', 'mov    0x18(%rsp),%rax'),
        85370964: ('4885c0', 'test   %rax,%rax'),
        85370967: ('7414', 'je     0x516a86d'),
        85370969: ('488b7c2420', 'mov    0x20(%rsp),%rdi'),
        85370974: ('4869f0b8000000', 'imul   $0xb8,%rax,%rsi'),
        85370981: ('31d2', 'xor    %edx,%edx'),
        85370983: ('ff15334c3701', 'call   *0x1374c33(%rip)'),
        85370989: ('4889d8', 'mov    %rbx,%rax'),
        85370992: ('4881c418010000', 'add    $0x118,%rsp'),
        85370999: ('5b', 'pop    %rbx'),
        85371000: ('415c', 'pop    %r12'),
        85371002: ('415e', 'pop    %r14'),
        85371004: ('415f', 'pop    %r15'),
        85371006: ('c3', 'ret'),
        85371007: ('4983ff15', 'cmp    $0x15,%r15'),
        85371011: ('732c', 'jae    0x516a8b1'),
        85371013: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        85371018: ('ba01000000', 'mov    $0x1,%edx'),
        85371023: ('4c89f7', 'mov    %r14,%rdi'),
        85371026: ('4c89fe', 'mov    %r15,%rsi'),
        85371029: ('e816fe2700', 'call   0x53ea6b0'),
        85371034: ('e903ffffff', 'jmp    0x516a7a2'),
        85371039: ('bf08000000', 'mov    $0x8,%edi'),
        85371044: ('bef8070000', 'mov    $0x7f8,%esi'),
        85371049: ('ff15e14b3701', 'call   *0x1374be1(%rip)'),
        85371055: ('0f0b', 'ud2'),
        85371057: ('488d542440', 'lea    0x40(%rsp),%rdx'),
        85371062: ('4c89f7', 'mov    %r14,%rdi'),
        85371065: ('4c89fe', 'mov    %r15,%rsi'),
        85371068: ('ff1506af3701', 'call   *0x137af06(%rip)'),
        85371074: ('e9dbfeffff', 'jmp    0x516a7a2'),
        85371079: ('4889c3', 'mov    %rax,%rbx'),
        85371082: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        85371087: ('eb03', 'jmp    0x516a8d4'),
        85371089: ('4889c3', 'mov    %rax,%rbx'),
        85371092: ('4d85e4', 'test   %r12,%r12'),
        85371095: ('7412', 'je     0x516a8eb'),
        85371097: ('4969f4b8000000', 'imul   $0xb8,%r12,%rsi'),
        85371104: ('4c89f7', 'mov    %r14,%rdi'),
        85371107: ('31d2', 'xor    %edx,%edx'),
        85371109: ('ff15b54b3701', 'call   *0x1374bb5(%rip)'),
        85371115: ('4889df', 'mov    %rbx,%rdi'),
        85371118: ('e85d612801', 'call   0x63f0a50'),
    },
    'caller_b1': {
        63837616: ('4157', 'push   %r15'),
        63837618: ('4156', 'push   %r14'),
        63837620: ('4154', 'push   %r12'),
        63837622: ('53', 'push   %rbx'),
        63837623: ('4881ec18010000', 'sub    $0x118,%rsp'),
        63837630: ('4989ce', 'mov    %rcx,%r14'),
        63837633: ('4889fb', 'mov    %rdi,%rbx'),
        63837636: ('4889e7', 'mov    %rsp,%rdi'),
        63837639: ('e8f454feff', 'call   0x3cc6ac0'),
        63837644: ('833c2401', 'cmpl   $0x1,(%rsp)'),
        63837648: ('751e', 'jne    0x3ce15f0'),
        63837650: ('4c8b7c2408', 'mov    0x8(%rsp),%r15'),
        63837655: ('488b442418', 'mov    0x18(%rsp),%rax'),
        63837660: ('4d85ff', 'test   %r15,%r15'),
        63837663: ('7467', 'je     0x3ce1648'),
        63837665: ('4869c0b0000000', 'imul   $0xb0,%rax,%rax'),
        63837672: ('4901c7', 'add    %rax,%r15'),
        63837675: ('e98d000000', 'jmp    0x3ce167d'),
        63837680: ('48837c240800', 'cmpq   $0x0,0x8(%rsp)'),
        63837686: ('0f84a6000000', 'je     0x3ce16a2'),
        63837692: ('488d442408', 'lea    0x8(%rsp),%rax'),
        63837697: ('488b4820', 'mov    0x20(%rax),%rcx'),
        63837701: ('48894c2450', 'mov    %rcx,0x50(%rsp)'),
        63837706: ('0f1000', 'movups (%rax),%xmm0'),
        63837709: ('0f104810', 'movups 0x10(%rax),%xmm1'),
        63837713: ('0f294c2440', 'movaps %xmm1,0x40(%rsp)'),
        63837718: ('0f29442430', 'movaps %xmm0,0x30(%rsp)'),
        63837723: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        63837728: ('488d742430', 'lea    0x30(%rsp),%rsi'),
        63837733: ('4c89f2', 'mov    %r14,%rdx'),
        63837736: ('e8e3cba2ff', 'call   0x370e210'),
        63837741: ('48837c246000', 'cmpq   $0x0,0x60(%rsp)'),
        63837747: ('0f85a6000000', 'jne    0x3ce16df'),
        63837753: ('4c8b7c2468', 'mov    0x68(%rsp),%r15'),
        63837758: ('4c8b642470', 'mov    0x70(%rsp),%r12'),
        63837763: ('e991000000', 'jmp    0x3ce16d9'),
        63837768: ('488b4c2410', 'mov    0x10(%rsp),%rcx'),
        63837773: ('483b4118', 'cmp    0x18(%rcx),%rax'),
        63837777: ('0f83a1000000', 'jae    0x3ce16f8'),
        63837783: ('48034110', 'add    0x10(%rcx),%rax'),
        63837787: ('488b11', 'mov    (%rcx),%rdx'),
        63837790: ('31f6', 'xor    %esi,%esi'),
        63837792: ('4839d0', 'cmp    %rdx,%rax'),
        63837795: ('480f43f2', 'cmovae %rdx,%rsi'),
        63837799: ('488b4908', 'mov    0x8(%rcx),%rcx'),
        63837803: ('4829f0', 'sub    %rsi,%rax'),
        63837806: ('4869c0b8000000', 'imul   $0xb8,%rax,%rax'),
        63837813: ('4c8d3c01', 'lea    (%rcx,%rax,1),%r15'),
        63837817: ('4983c708', 'add    $0x8,%r15'),
        63837821: ('4c8b2584de7f02', 'mov    0x27fde84(%rip),%r12'),
        63837828: ('bab0000000', 'mov    $0xb0,%edx'),
        63837833: ('4889df', 'mov    %rbx,%rdi'),
        63837836: ('4c89fe', 'mov    %r15,%rsi'),
        63837839: ('41ffd4', 'call   *%r12'),
        63837842: ('bab0000000', 'mov    $0xb0,%edx'),
        63837847: ('4c89ff', 'mov    %r15,%rdi'),
        63837850: ('4c89f6', 'mov    %r14,%rsi'),
        63837853: ('41ffd4', 'call   *%r12'),
        63837856: ('eb44', 'jmp    0x3ce16e6'),
        63837858: ('4c8b7c2410', 'mov    0x10(%rsp),%r15'),
        63837863: ('4c8b642418', 'mov    0x18(%rsp),%r12'),
        63837868: ('488b442420', 'mov    0x20(%rsp),%rax'),
        63837873: ('4889442460', 'mov    %rax,0x60(%rsp)'),
        63837878: ('488d7c2468', 'lea    0x68(%rsp),%rdi'),
        63837883: ('bab0000000', 'mov    $0xb0,%edx'),
        63837888: ('4c89f6', 'mov    %r14,%rsi'),
        63837891: ('ff153fde7f02', 'call   *0x27fde3f(%rip)'),
        63837897: ('488d542460', 'lea    0x60(%rsp),%rdx'),
        63837902: ('4c89ff', 'mov    %r15,%rdi'),
        63837905: ('4c89e6', 'mov    %r12,%rsi'),
        63837908: ('e867838600', 'call   0x4549a40'),
        63837913: ('4d3b6718', 'cmp    0x18(%r15),%r12'),
        63837917: ('7319', 'jae    0x3ce16f8'),
        63837919: ('48c70302000000', 'movq   $0x2,(%rbx)'),
        63837926: ('4889d8', 'mov    %rbx,%rax'),
        63837929: ('4881c418010000', 'add    $0x118,%rsp'),
        63837936: ('5b', 'pop    %rbx'),
        63837937: ('415c', 'pop    %r12'),
        63837939: ('415e', 'pop    %r14'),
        63837941: ('415f', 'pop    %r15'),
        63837943: ('c3', 'ret'),
        63837944: ('488d3d4e4baefc', 'lea    -0x351b4b2(%rip),%rdi'),
        63837951: ('488d1582c57902', 'lea    0x279c582(%rip),%rdx'),
        63837958: ('be14000000', 'mov    $0x14,%esi'),
        63837963: ('ff155fe07f02', 'call   *0x27fe05f(%rip)'),
    },
    'caller_b2': {
        66167120: ('4157', 'push   %r15'),
        66167122: ('4156', 'push   %r14'),
        66167124: ('53', 'push   %rbx'),
        66167125: ('4881ece0000000', 'sub    $0xe0,%rsp'),
        66167132: ('4889fb', 'mov    %rdi,%rbx'),
        66167135: ('48833e00', 'cmpq   $0x0,(%rsi)'),
        66167139: ('7438', 'je     0x3f1a19d'),
        66167141: ('488b4620', 'mov    0x20(%rsi),%rax'),
        66167145: ('4889442420', 'mov    %rax,0x20(%rsp)'),
        66167150: ('0f1006', 'movups (%rsi),%xmm0'),
        66167153: ('0f104e10', 'movups 0x10(%rsi),%xmm1'),
        66167157: ('0f294c2410', 'movaps %xmm1,0x10(%rsp)'),
        66167162: ('0f290424', 'movaps %xmm0,(%rsp)'),
        66167166: ('488d7c2428', 'lea    0x28(%rsp),%rdi'),
        66167171: ('4889e6', 'mov    %rsp,%rsi'),
        66167174: ('e885407fff', 'call   0x370e210'),
        66167179: ('488b442428', 'mov    0x28(%rsp),%rax'),
        66167184: ('4c8b742430', 'mov    0x30(%rsp),%r14'),
        66167189: ('f30f6f442438', 'movdqu 0x38(%rsp),%xmm0'),
        66167195: ('eb3b', 'jmp    0x3f1a1d8'),
        66167197: ('4c8b7608', 'mov    0x8(%rsi),%r14'),
        66167201: ('4c8b7e10', 'mov    0x10(%rsi),%r15'),
        66167205: ('488b4618', 'mov    0x18(%rsi),%rax'),
        66167209: ('4889442428', 'mov    %rax,0x28(%rsp)'),
        66167214: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        66167219: ('4889d6', 'mov    %rdx,%rsi'),
        66167222: ('bab0000000', 'mov    $0xb0,%edx'),
        66167227: ('ff1547535c02', 'call   *0x25c5347(%rip)'),
        66167233: ('488d542428', 'lea    0x28(%rsp),%rdx'),
        66167238: ('4c89f7', 'mov    %r14,%rdi'),
        66167241: ('4c89fe', 'mov    %r15,%rsi'),
        66167244: ('e86ff86200', 'call   0x4549a40'),
        66167249: ('66490f6ec7', 'movq   %r15,%xmm0'),
        66167254: ('31c0', 'xor    %eax,%eax'),
        66167256: ('488903', 'mov    %rax,(%rbx)'),
        66167259: ('4c897308', 'mov    %r14,0x8(%rbx)'),
        66167263: ('f30f7f4310', 'movdqu %xmm0,0x10(%rbx)'),
        66167268: ('4889d8', 'mov    %rbx,%rax'),
        66167271: ('4881c4e0000000', 'add    $0xe0,%rsp'),
        66167278: ('5b', 'pop    %rbx'),
        66167279: ('415e', 'pop    %r14'),
        66167281: ('415f', 'pop    %r15'),
        66167283: ('c3', 'ret'),
    },
    'alloc_body': {
        104159280: ('f30f1efa', 'endbr64'),
        104159284: ('4881ff00100000', 'cmp    $0x1000,%rdi'),
        104159291: ('0f877f000000', 'ja     0x63558c0'),
        104159297: ('488d15781f3d00', 'lea    0x3d1f78(%rip),%rdx'),
        104159304: ('488d4707', 'lea    0x7(%rdi),%rax'),
        104159308: ('48c7c158efffff', 'mov    $0xffffffffffffef58,%rcx'),
        104159315: ('48c1e803', 'shr    $0x3,%rax'),
        104159319: ('488d35a2213d00', 'lea    0x3d21a2(%rip),%rsi'),
        104159326: ('440fb60402', 'movzbl (%rdx,%rax,1),%r8d'),
        104159331: ('644c8b91380300', 'mov    %fs:0x338(%rcx),%r10'),
        104159338: ('00', ''),
        104159339: ('4e0314c6', 'add    (%rsi,%r8,8),%r10'),
        104159343: ('644c3b91400300', 'cmp    %fs:0x340(%rcx),%r10'),
        104159350: ('00', ''),
        104159351: ('7347', 'jae    0x63558c0'),
        104159353: ('644c8b1c250000', 'mov    %fs:0x0,%r11'),
        104159360: ('0000', ''),
        104159362: ('4f8d0c40', 'lea    (%r8,%r8,2),%r9'),
        104159366: ('4b8d04cb', 'lea    (%r11,%r9,8),%rax'),
        104159370: ('4801c8', 'add    %rcx,%rax'),
        104159373: ('488b9060030000', 'mov    0x360(%rax),%rdx'),
        104159380: ('488b32', 'mov    (%rdx),%rsi'),
        104159383: ('4c8d4208', 'lea    0x8(%rdx),%r8'),
        104159387: ('663b9070030000', 'cmp    0x370(%rax),%dx'),
        104159394: ('7424', 'je     0x63558c8'),
        104159396: ('4c898060030000', 'mov    %r8,0x360(%rax)'),
        104159403: ('644c8991380300', 'mov    %r10,%fs:0x338(%rcx)'),
        104159410: ('00', ''),
        104159411: ('48838068030000', 'addq   $0x1,0x368(%rax)'),
        104159418: ('01', ''),
        104159419: ('4889f0', 'mov    %rsi,%rax'),
        104159422: ('c3', 'ret'),
        104159423: ('90', 'nop'),
        104159424: ('e9abe1ffff', 'jmp    0x6353a70'),
        104159429: ('0f1f00', 'nopl   (%rax)'),
        104159432: ('663b9074030000', 'cmp    0x374(%rax),%dx'),
        104159439: ('74ef', 'je     0x63558c0'),
        104159441: ('4c898060030000', 'mov    %r8,0x360(%rax)'),
        104159448: ('66448980700300', 'mov    %r8w,0x370(%rax)'),
        104159455: ('00', ''),
        104159456: ('644c8991380300', 'mov    %r10,%fs:0x338(%rcx)'),
        104159463: ('00', ''),
        104159464: ('48838068030000', 'addq   $0x1,0x368(%rax)'),
        104159471: ('01', ''),
        104159472: ('ebc9', 'jmp    0x63558bb'),
    },
    'dealloc_body': {
        104193584: ('f30f1efa', 'endbr64'),
        104193588: ('4881fe00100000', 'cmp    $0x1000,%rsi'),
        104193595: ('0f878f000000', 'ja     0x635ded0'),
        104193601: ('85d2', 'test   %edx,%edx'),
        104193603: ('0f8587000000', 'jne    0x635ded0'),
        104193609: ('f7c7ff0f0000', 'test   $0xfff,%edi'),
        104193615: ('747f', 'je     0x635ded0'),
        104193617: ('488d0d68993c00', 'lea    0x3c9968(%rip),%rcx'),
        104193624: ('488d4607', 'lea    0x7(%rsi),%rax'),
        104193628: ('49c7c058efffff', 'mov    $0xffffffffffffef58,%r8'),
        104193635: ('48c1e803', 'shr    $0x3,%rax'),
        104193639: ('4c8d15929b3c00', 'lea    0x3c9b92(%rip),%r10'),
        104193646: ('440fb60c01', 'movzbl (%rcx,%rax,1),%r9d'),
        104193651: ('4f8b1cca', 'mov    (%r10,%r9,8),%r11'),
        104193655: ('644d0398480300', 'add    %fs:0x348(%r8),%r11'),
        104193662: ('00', ''),
        104193663: ('644d3b98500300', 'cmp    %fs:0x350(%r8),%r11'),
        104193670: ('00', ''),
        104193671: ('7347', 'jae    0x635ded0'),
        104193673: ('64488b04250000', 'mov    %fs:0x0,%rax'),
        104193680: ('0000', ''),
        104193682: ('4b8d0c49', 'lea    (%r9,%r9,2),%rcx'),
        104193686: ('4c8d14c8', 'lea    (%rax,%rcx,8),%r10'),
        104193690: ('4d01c2', 'add    %r8,%r10'),
        104193693: ('4d8b8a60030000', 'mov    0x360(%r10),%r9'),
        104193700: ('6645398a720300', 'cmp    %r9w,0x372(%r10)'),
        104193707: ('00', ''),
        104193708: ('7422', 'je     0x635ded0'),
        104193710: ('498d51f8', 'lea    -0x8(%r9),%rdx'),
        104193714: ('49899260030000', 'mov    %rdx,0x360(%r10)'),
        104193721: ('498979f8', 'mov    %rdi,-0x8(%r9)'),
        104193725: ('644d8998480300', 'mov    %r11,%fs:0x348(%r8)'),
        104193732: ('00', ''),
        104193733: ('c3', 'ret'),
        104193734: ('662e0f1f840000', 'cs nopw 0x0(%rax,%rax,1)'),
        104193741: ('000000', ''),
        104193744: ('e9fbe7ffff', 'jmp    0x635c6d0'),
    },
}

EXPECTED_CALLERS = {'wrap_a': [(47988030, 47986944)], 'wrap_b': [(63837736, 63837616), (66167174, 66167120)], 'wrap_c': [(81604830, 81603744)], 'giant_a1': [(40741691, 40741616)], 'giant_a2': [(57729627, 57729552)], 'giant_a3': [(85921179, 85921104)], 'giant_b1': [(37375854, 37375632), (37435208, 37435008)], 'giant_b2': [(59265624, 59265424), (59336990, 59336768)], 'giant_b3': [(85368430, 85368208), (85370920, 85370720)], 'caller_a': [(46540744, 46540176)], 'caller_b1': [(44603285, 44602624), (46552044, 46549104), (46552492, 46549104), (57254929, 57254864), (57259667, 57259600), (66128841, 66128576), (89786997, 89786336), (89789813, 89789152), (90064108, 90060656), (90064556, 90060656)], 'caller_b2': [(57285479, 57283376)], 'caller_c': [(90052011, 90042320)]}

EXPECTED = {'bodies': 21, 'rows': 5506, 'alloc_sites': 27, 'alloc_leaf_0x7f8': 15, 'alloc_internal_0x858': 12, 'memcpy_whole_element_0xb0': 22, 'memcpy_tail_0xa8': 51, 'memmove_element_shifts': 15, 'other_copy_sites': 54, 'head_stores': 21, 'field_stores': 0, 'element_other_stores': 0, 'stores_at_eight_displacements_nonstack': 0, 'node_field_stores': 285, 'node_init_zero_stores': 54, 'sibling_e8_sites': 99, 'sibling_sites_in_pinned_bodies': 0, 'driver_caller_sites': 13}

_LINE_RE = re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)(.*)$')


def _hx(value):
    return f'0x{value:x}'


def _section_bytes(data, secs, start, end):
    for sec in secs:
        if sec['type'] != 8 and sec['address'] <= start and end <= sec['address'] + sec['size']:
            off = sec['offset'] + (start - sec['address'])
            return data[off:off + end - start]
    raise AssertionError(f'no file-backed section covers {start:#x}..{end:#x}')


def _digest(data, secs, start, end):
    return hashlib.sha256(_section_bytes(data, secs, start, end)).hexdigest()


def _decode(data, secs, start, end):
    body = _section_bytes(data, secs, start, end)
    handle = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
    try:
        handle.write(body)
        handle.close()
        out = subprocess.check_output(
            ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
             f'--adjust-vma={start:#x}', handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    _foundation_decode(out, start, end, body)
    rows = {}
    for line in out.splitlines():
        match = _LINE_RE.match(line)
        if match:
            rows[int(match.group(1), 16)] = (
                re.sub(r'\s', '', match.group(2)),
                match.group(3).strip().split('#')[0].rstrip())
    return rows


def _check_pins(rows, pins, what):
    if rows != pins:
        for address in sorted(set(rows) | set(pins)):
            if rows.get(address) != pins.get(address):
                raise AssertionError(
                    f'{what} instruction at {address:#x} differs: '
                    f'{rows.get(address)!r} != {pins.get(address)!r}')
        raise AssertionError(f'{what} instructions differ')
    return rows


def _rela_entries(data, secs):
    """All (offset, type, sym, addend) tuples from SHT_RELA sections."""
    entries = []
    for sec in secs:
        if sec['type'] != 4:
            continue
        blob = _section_bytes(data, secs, sec['address'],
                              sec['address'] + sec['size'])
        for off in range(0, len(blob) - 23, 24):
            r_offset, r_info, r_addend = struct.unpack_from('<QQq', blob, off)
            entries.append((r_offset, r_info & 0xFFFFFFFF, r_info >> 32,
                            r_addend))
    return entries


def _dynsym_name(data, secs, index):
    """Resolve a .dynsym index to its symbol name via sh_link."""
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize = struct.unpack_from('<H', data, 58)[0]
    dynsym_idx = next(i for i, s in enumerate(secs) if s['type'] == 11)
    link = struct.unpack_from('<I', data, shoff + dynsym_idx * entsize + 40)[0]
    dynsym = secs[dynsym_idx]
    dynstr = secs[link]
    st_name = struct.unpack_from(
        '<I', data, dynsym['offset'] + index * 24)[0]
    table = _section_bytes(data, secs, dynstr['address'],
                           dynstr['address'] + dynstr['size'])
    end = table.find(b'\0', st_name)
    return table[st_name:end].decode('utf-8')


def _slot_fact(data, secs, relas, slot, want_type, want_addend=None,
               want_sym=None):
    hits = [e for e in relas if e[0] == slot]
    if len(hits) != 1:
        raise AssertionError(f'slot {_hx(slot)} has {len(hits)} relocations')
    _off, rtype, sym, addend = hits[0]
    if rtype != want_type:
        raise AssertionError(f'slot {_hx(slot)} relocation type is {rtype}')
    fact = {'slot': _hx(slot), 'rela_type': rtype}
    if want_addend is not None:
        if addend != want_addend:
            raise AssertionError(
                f'slot {_hx(slot)} relocation addend is {_hx(addend)}')
        fact['rela_addend'] = _hx(addend)
    if want_sym is not None:
        name = _dynsym_name(data, secs, sym)
        if name != want_sym:
            raise AssertionError(
                f'slot {_hx(slot)} binds {name!r}, not {want_sym!r}')
        fact['symbol'] = name
    content = struct.unpack_from(
        '<Q', _section_bytes(data, secs, slot, slot + 8), 0)[0]
    if content != 0:
        raise AssertionError(f'slot {_hx(slot)} initialised content is not zero')
    fact['initialised_content'] = '0x0'
    return fact


_REG64 = {}
for _full, _base in [('rax', 'rax'), ('eax', 'rax'), ('ax', 'rax'),
                     ('al', 'rax'), ('ah', 'rax'), ('rbx', 'rbx'),
                     ('ebx', 'rbx'), ('bx', 'rbx'), ('bl', 'rbx'),
                     ('bh', 'rbx'), ('rcx', 'rcx'), ('ecx', 'rcx'),
                     ('cx', 'rcx'), ('cl', 'rcx'), ('ch', 'rcx'),
                     ('rdx', 'rdx'), ('edx', 'rdx'), ('dx', 'rdx'),
                     ('dl', 'rdx'), ('dh', 'rdx'), ('rsi', 'rsi'),
                     ('esi', 'rsi'), ('si', 'rsi'), ('sil', 'rsi'),
                     ('rdi', 'rdi'), ('edi', 'rdi'), ('di', 'rdi'),
                     ('dil', 'rdi'), ('rbp', 'rbp'), ('ebp', 'rbp'),
                     ('bp', 'rbp'), ('bpl', 'rbp'), ('rsp', 'rsp'),
                     ('esp', 'rsp'), ('sp', 'rsp'), ('spl', 'rsp')]:
    _REG64[_full] = _base
for _i in range(8, 16):
    for _suf in ('', 'd', 'w', 'b'):
        _REG64[f'r{_i}{_suf}'] = f'r{_i}'

_MEMFULL_RE = re.compile(
    r'^(-?0x[0-9a-f]+)?\(%([a-z0-9]+)(?:,%([a-z0-9]+)(?:,([0-9]+))?)?\)$')
_EIGHT = {0x40, 0x58, 0x60, 0x78, 0x80, 0x88, 0x90, 0x98}
_NODEFIELD = {0x790, 0x798, 0x7A0, 0x7F0, 0x7F2, 0x7F8, 0x800, 0x808, 0x810}
_SLOTS = {ALLOC_SLOT: 'alloc', MEMCPY_SLOT: 'memcpy',
          MEMMOVE_SLOT: 'memmove', DEALLOC_SLOT: 'dealloc',
          0x64DF490: 'alloc_fail', 0x64DF730: 'assert'}
_KNOWN = {'mov', 'movabs', 'lea', 'add', 'sub', 'imul', 'call', 'cmp',
          'test', 'jmp', 'push', 'pop', 'ret', 'leave', 'nop', 'xor',
          'or', 'and', 'shl', 'shr', 'sar', 'neg', 'not', 'inc', 'dec',
          'movups', 'movaps', 'movdqa', 'movdqu', 'pxor', 'xchg', 'ud2',
          'int3', 'je', 'jne', 'ja', 'jae', 'jb', 'jbe', 'jg', 'jge',
          'jl', 'jle', 'jo', 'jno', 'js', 'jns', 'jnp', 'jp', 'rep',
          'movzwl', 'movzbl', 'movswl', 'movsbl', 'cdqe', 'cqto',
          'cltq', 'hlt', 'pause'}


def _base_mnem(mnem):
    if mnem in _KNOWN:
        return mnem
    if mnem and mnem[-1] in 'bwlq' and mnem[:-1] in _KNOWN:
        return mnem[:-1]
    return mnem


def _reg_of(tok):
    tok = tok.strip()
    if tok.startswith('%'):
        return _REG64.get(tok[1:])
    return None


def _parse_mem(tok):
    match = _MEMFULL_RE.match(tok.strip())
    if not match:
        return None
    disp = int(match.group(1), 16) if match.group(1) else 0
    if disp < 0:
        disp = None
    return disp, _REG64.get(match.group(2)), \
        (_REG64.get(match.group(3)) if match.group(3) else None)


def _split_ops(text):
    parts = text.split(None, 1)
    if len(parts) < 2:
        return (parts[0] if parts else ''), []
    ops, depth, cur = [], 0, ''
    for ch in parts[1]:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            ops.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        ops.append(cur.strip())
    return parts[0], ops


def _census_body(data, secs, start, end):
    """Store/copy census over one pinned body.

    Provenance tracker: a register is tainted when its value is
    data-dependent on an `imul $0xb0` or `imul $0xb8` result in this
    body (the element/record address arithmetic).  Propagation
    mirrors the series convention: mov/movabs copy, lea unions,
    add/sub union into the destination, any other register write
    clears, and a call clears the caller-saved registers.  A store is
    element-derived when its base or index register is tainted.
    """
    rows = _decode(data, secs, start, end)
    taint = {r: set() for r in set(_REG64.values())}
    caller_saved = {'rax', 'rcx', 'rdx', 'rsi', 'rdi',
                    'r8', 'r9', 'r10', 'r11'}
    slot_loaded = {}
    out = {'rows': len(rows), 'e8_sites': [], 'alloc_sites': [],
           'init_zero_790': [], 'init_zero_7f2': [], 'memcpy_b0': [],
           'memcpy_a8': [], 'memmove_tainted': [], 'copy_other': [],
           'head_stores': [], 'field_stores': [], 'elem_other_stores': [],
           'stores_eight_nonstack': 0, 'node_field_stores': 0,
           'slot_calls': []}
    addr_list = sorted(rows)
    for idx, a in enumerate(addr_list):
        text = rows[a][1]
        mnem, ops = _split_ops(text)
        bm = _base_mnem(mnem)
        raw = bytes.fromhex(rows[a][0])
        if raw[0] == 0xE8 and len(raw) == 5:
            rel = struct.unpack_from('<i', raw, 1)[0]
            out['e8_sites'].append((a, a + 5 + rel))
        if ops and bm not in ('cmp', 'test', 'lea'):
            dest = ops[-1]
            pm = _parse_mem(dest)
            if pm and len(ops) >= 2:
                disp, basereg, idxreg = pm
                if basereg not in (None, 'rsp'):
                    t = set()
                    if basereg:
                        t |= taint.get(basereg, set())
                    if idxreg:
                        t |= taint.get(idxreg, set())
                    if disp in _EIGHT:
                        out['stores_eight_nonstack'] += 1
                    if disp in _NODEFIELD:
                        out['node_field_stores'] += 1
                    if t:
                        if disp == 0:
                            out['head_stores'].append(a)
                        elif disp in _EIGHT:
                            out['field_stores'].append((a, disp))
                        else:
                            out['elem_other_stores'].append((a, disp))
                    if disp == 0x790 and ops[0] == '$0x0':
                        out['init_zero_790'].append(a)
                    if disp == 0x7F2 and ops[0] == '$0x0':
                        out['init_zero_7f2'].append(a)
        if bm == 'call':
            target_slot = None
            if ops:
                op = ops[0]
                if op.startswith('*') and '(%rip)' in op:
                    dispv = int(re.search(
                        r'(-?0x[0-9a-f]+)\(%rip\)', op).group(1), 16)
                    target_slot = _SLOTS.get(a + len(raw) + dispv)
                elif op.startswith('*%'):
                    target_slot = slot_loaded.get(_reg_of(op[1:]))
            if target_slot is not None:
                size = None
                if target_slot in ('alloc', 'memcpy', 'memmove', 'dealloc'):
                    sreg = 'di' if target_slot == 'alloc' else 'dx'
                    for j in range(idx - 1, max(idx - 12, -1), -1):
                        t2 = rows[addr_list[j]][1]
                        if re.search(r',%(?:e|r)?' + sreg + r'$', t2) \
                                and t2.split()[0].rstrip('bwlq') in ('mov', 'lea'):
                            mi = re.match(r'mov\s+\$(0x[0-9a-f]+),%(?:e|r)?'
                                          + sreg, t2)
                            size = int(mi.group(1), 16) if mi else 'computed'
                            break
                        if t2.startswith('call'):
                            break
                dest_tainted = bool(taint.get('rdi'))
                out['slot_calls'].append((a, target_slot, size, dest_tainted))
                if target_slot == 'alloc':
                    out['alloc_sites'].append((a, size))
                elif target_slot == 'memcpy' and size == ELEMENT_SIZE:
                    out['memcpy_b0'].append(a)
                elif target_slot == 'memcpy' and size == TAIL_SIZE:
                    out['memcpy_a8'].append(a)
                elif target_slot == 'memmove' and dest_tainted:
                    out['memmove_tainted'].append(a)
                elif target_slot in ('memcpy', 'memmove'):
                    out['copy_other'].append(
                        (a, target_slot, size, dest_tainted))
            for r in caller_saved:
                taint[r] = set()
            slot_loaded = {k: v for k, v in slot_loaded.items()
                           if k not in caller_saved}
            continue
        if bm == 'mov' and len(ops) == 2 and '(%rip)' in ops[0]:
            dispv = int(re.search(r'(-?0x[0-9a-f]+)\(%rip\)',
                                  ops[0]).group(1), 16)
            slot = a + len(raw) + dispv
            if slot in _SLOTS:
                dst = _reg_of(ops[1])
                if dst:
                    slot_loaded[dst] = _SLOTS[slot]
                    continue
        if bm == 'imul' and len(ops) >= 2 and ops[0] in ('$0xb0', '$0xb8'):
            dst = _reg_of(ops[-1])
            if dst:
                taint[dst] = {'B0' if ops[0] == '$0xb0' else 'B8'}
            continue
        if bm in ('mov', 'movabs', 'lea', 'add', 'sub', 'xor', 'or',
                  'and', 'shl', 'shr', 'sar', 'neg', 'not', 'inc', 'dec'):
            if bm == 'xor' and len(ops) == 2 and ops[0] == ops[1]:
                dst = _reg_of(ops[1])
                if dst:
                    taint[dst] = set()
                continue
            if ops:
                dst = _reg_of(ops[-1])
                if dst and dst != 'rsp':
                    newt = set()
                    if bm in ('mov', 'movabs') and len(ops) == 2:
                        src = _reg_of(ops[0])
                        newt = set(taint.get(src, set())) if src else set()
                    elif bm == 'lea' and len(ops) == 2:
                        pm = _parse_mem(ops[0])
                        if pm:
                            _d, b1, b2 = pm
                            for b in (b1, b2):
                                if b:
                                    newt |= taint.get(b, set())
                    elif bm in ('add', 'sub') and len(ops) == 2:
                        src = _reg_of(ops[0])
                        newt = set(taint.get(dst, set()))
                        if src:
                            newt |= taint.get(src, set())
                    taint[dst] = newt
            continue
        if ops and bm not in ('cmp', 'test', 'jmp', 'je', 'jne', 'ja',
                              'jae', 'jb', 'jbe', 'jg', 'jge', 'jl',
                              'jle', 'jo', 'jno', 'js', 'jns', 'jnp',
                              'jp', 'ret', 'nop', 'push', 'leave'):
            dst = _reg_of(ops[-1])
            if dst and dst != 'rsp' and '(%' not in ops[-1]:
                taint[dst] = set()
    return out


def _e8_callers(data, secs, ordered, targets):
    """Binary-wide E8 census: target -> [(site, (fde_start, fde_end))]."""
    text_sec = next(s for s in secs if s['name'] == '.text')
    tbody = _section_bytes(data, secs, text_sec['address'],
                           text_sec['address'] + text_sec['size'])
    tva = text_sec['address']
    starts = [o['start'] for o in ordered]
    import bisect

    def fde_of(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and ordered[i]['start'] <= va < ordered[i]['end']:
            return (ordered[i]['start'], ordered[i]['end'])
        return None

    want = {v: k for k, v in targets.items()}
    hits = {k: [] for k in targets}
    pos = 0
    while True:
        j = tbody.find(b'\xe8', pos)
        if j < 0:
            break
        rel = struct.unpack_from('<i', tbody, j + 1)[0]
        tgt = tva + j + 5 + rel
        if tgt in want:
            hits[want[tgt]].append((tva + j, fde_of(tva + j)))
        pos = j + 1
    return hits


def analyze(data):
    secs = sections(data)
    summary, ordered, _gaps = fde_extents(data)
    by_start = {o['start']: o for o in ordered}
    for name, body in BODIES.items():
        start, end = body['range']
        if start not in by_start or by_start[start]['end'] != end:
            raise AssertionError(f'{name} range is not an FDE extent')
        if _digest(data, secs, start, end) != body['sha256']:
            raise AssertionError(f'{name} differs from its pinned digest')
    for name, pins in PINNED_ROWS.items():
        start, end = BODIES[name]['range']
        _check_pins(_decode(data, secs, start, end), pins, name)
    relas = _rela_entries(data, secs)
    slots = {
        'alloc': _slot_fact(data, secs, relas, ALLOC_SLOT, 8,
                            want_addend=ALLOC_BODY),
        'memcpy': _slot_fact(data, secs, relas, MEMCPY_SLOT, 6,
                             want_sym='memcpy'),
        'memmove': _slot_fact(data, secs, relas, MEMMOVE_SLOT, 6,
                              want_sym='memmove'),
        'dealloc': _slot_fact(data, secs, relas, DEALLOC_SLOT, 8,
                              want_addend=DEALLOC_BODY),
    }
    censuses = {}
    for name, body in BODIES.items():
        if name in ('alloc_body', 'dealloc_body'):
            continue
        start, end = body['range']
        census = _census_body(data, secs, start, end)
        if census['field_stores']:
            raise AssertionError(
                f'{name} stores to an element field: '
                f'{census["field_stores"]!r}')
        if census['elem_other_stores']:
            raise AssertionError(
                f'{name} has an element-derived store outside the head '
                f'qword: {census["elem_other_stores"]!r}')
        if census['stores_eight_nonstack']:
            raise AssertionError(
                f'{name} stores at an element-field displacement through '
                f'a non-stack address')
        censuses[name] = census
    targets = {name: body['range'][0] for name, body in BODIES.items()
               if name not in ('alloc_body', 'dealloc_body')}
    targets['sibling'] = SIBLING[0]
    callers = _e8_callers(data, secs, ordered, targets)
    call_graph = {}
    for name in ('wrap_a', 'wrap_b', 'wrap_c', 'giant_a1', 'giant_a2',
                 'giant_a3', 'giant_b1', 'giant_b2', 'giant_b3',
                 'caller_a', 'caller_b1', 'caller_b2', 'caller_c'):
        got = sorted((site, fde[0]) for site, fde in callers[name])
        want = sorted(EXPECTED_CALLERS[name])
        if got != want:
            raise AssertionError(
                f'E8 callers of {name} differ: {got!r} != {want!r}')
        call_graph[name] = [
            {'site': _hx(site),
             'caller_fde': [_hx(fde[0]), _hx(fde[1])]
             } for site, fde in sorted(callers[name])]
    sibling_sites = callers['sibling']
    pinned_ranges = [tuple(b['range']) for b in BODIES.values()]
    sibling_in_pinned = [site for site, _f in sibling_sites
                         if any(s <= site < e for s, e in pinned_ranges)]
    if sibling_in_pinned:
        raise AssertionError(
            f'pinned bodies call the sibling search: {sibling_in_pinned!r}')

    def site_list(addrs):
        return [_hx(a) for a in addrs]

    census_records = {}
    counters = {'bodies': len(BODIES), 'rows': 0, 'alloc_sites': 0,
                'alloc_leaf_0x7f8': 0, 'alloc_internal_0x858': 0,
                'memcpy_whole_element_0xb0': 0, 'memcpy_tail_0xa8': 0,
                'memmove_element_shifts': 0, 'other_copy_sites': 0,
                'head_stores': 0, 'field_stores': 0,
                'element_other_stores': 0,
                'stores_at_eight_displacements_nonstack': 0,
                'node_field_stores': 0, 'node_init_zero_stores': 0,
                'sibling_e8_sites': len(sibling_sites),
                'sibling_sites_in_pinned_bodies': len(sibling_in_pinned),
                'driver_caller_sites': sum(len(callers[n]) for n in
                                           ('caller_a', 'caller_b1',
                                            'caller_b2', 'caller_c'))}
    for name, census in censuses.items():
        counters['rows'] += census['rows']
        counters['alloc_sites'] += len(census['alloc_sites'])
        counters['alloc_leaf_0x7f8'] += sum(
            1 for _a, s in census['alloc_sites'] if s == LEAF_NODE_SIZE)
        counters['alloc_internal_0x858'] += sum(
            1 for _a, s in census['alloc_sites'] if s == INTERNAL_NODE_SIZE)
        counters['memcpy_whole_element_0xb0'] += len(census['memcpy_b0'])
        counters['memcpy_tail_0xa8'] += len(census['memcpy_a8'])
        counters['memmove_element_shifts'] += len(census['memmove_tainted'])
        counters['other_copy_sites'] += len(census['copy_other'])
        counters['head_stores'] += len(census['head_stores'])
        counters['field_stores'] += len(census['field_stores'])
        counters['element_other_stores'] += len(
            census['elem_other_stores'])
        counters['stores_at_eight_displacements_nonstack'] += \
            census['stores_eight_nonstack']
        counters['node_field_stores'] += census['node_field_stores']
        counters['node_init_zero_stores'] += len(census['init_zero_790']) \
            + len(census['init_zero_7f2'])
        census_records[name] = {
            'rows': census['rows'],
            'e8_sites': [{'site': _hx(a), 'target': _hx(t)}
                         for a, t in census['e8_sites']],
            'alloc_sites': [{'site': _hx(a), 'size': _hx(s)}
                            for a, s in census['alloc_sites']],
            'node_init_zero_stores': {
                'parent_+0x790': site_list(census['init_zero_790']),
                'count_+0x7f2': site_list(census['init_zero_7f2'])},
            'memcpy_whole_element_0xb0': site_list(census['memcpy_b0']),
            'memcpy_tail_0xa8': site_list(census['memcpy_a8']),
            'memmove_element_shifts': site_list(census['memmove_tainted']),
            'other_copy_sites': [
                {'site': _hx(a), 'slot': k,
                 'size': _hx(s) if isinstance(s, int) else s,
                 'dest_element_derived': t}
                for a, k, s, t in census['copy_other']],
            'head_stores': site_list(census['head_stores']),
            'field_stores': [], 'element_other_stores': [],
            'stores_at_eight_displacements_nonstack':
                census['stores_eight_nonstack'],
            'node_field_stores': census['node_field_stores'],
            'slot_calls': [
                {'site': _hx(a), 'slot': k,
                 'size': _hx(s) if isinstance(s, int) else s,
                 'dest_element_derived': t}
                for a, k, s, t in census['slot_calls']],
        }
    if counters != EXPECTED:
        raise AssertionError(f'counters differ: {counters!r} != {EXPECTED!r}')
    bodies_record = {}
    for name, body in BODIES.items():
        start, end = body['range']
        bodies_record[name] = {
            'role': body['role'], 'range': [_hx(start), _hx(end)],
            'size': end - start, 'sha256': body['sha256']}
    field_verdict = (
        'no writer in the traced window: no store at this displacement '
        'through a non-stack address in any of the 19 pinned builder '
        'bodies, and no element-derived store at this displacement; '
        'the field moves only inside wholesale element copies '
        '(0xb0 whole-element memcpy, head-qword store plus 0xa8 tail '
        'memcpy, whole-element memmove shifts)')
    records = {
        'packet': PACKET_ID,
        'node': {
            'artifact_sha256': ARTIFACT_SHA256,
            'artifact_size': ARTIFACT_SIZE,
            'authenticated_fdes': len(ordered),
        },
        'question': (
            'PR #2561 proved the eight element fields the join callee '
            'reads are written by no body in the consumption window. '
            'Who writes them?  This packet traces the allocation and '
            'insertion paths of the sibling-search node layout outward '
            'from its handle constructors and censuses every store '
            'into a new element.'),
        'duplicate_gate': (
            'open-PR sweep of lalalune/hyperliquid-source for element '
            'builder / insertion / 0x7f8 / 0x7f2 / 0x798 / 35bf460: the '
            'only RE-006 hits are the predecessor packets #2542 '
            '(sibling search), #2558 (join callee) and #2561 (join '
            'helper + consumption-window writer census); no open PR '
            'identifies the builder for this node layout.'),
        'slots': slots,
        'bodies': bodies_record,
        'call_graph': call_graph,
        'allocation': {
            'allocator_slot': _hx(ALLOC_SLOT),
            'allocator_body': _hx(ALLOC_BODY),
            'leaf_node_size': _hx(LEAF_NODE_SIZE),
            'internal_node_size': _hx(INTERNAL_NODE_SIZE),
            'note': (
                'every fresh node in the window is allocated by a call '
                'through the allocator slot with a constant size: '
                '0x7f8 for a leaf node (11 elements of 0xb0 bytes, 11 '
                'keys, parent pointer, child index, count, 12 edge '
                'slots) and 0x858 for an internal node (the same '
                'layout plus 0x60 bytes); every fresh node is '
                'initialised with a zero parent pointer at +0x790 '
                'and a zero count at +0x7f2 (27 sites each)'),
        },
        'insertion_census': census_records,
        'layouts': {
            'node': {
                'elements': 'node + position * 0xb0, 11 slots',
                'element_size': '0xb0',
                'parent_pointer': 'node + 0x790',
                'keys': 'node + 0x798, 11 u64',
                'child_index': 'node + 0x7f0 (u16)',
                'count': 'node + 0x7f2 (u16)',
                'edges': 'node + 0x7f8 + position * 8',
            },
            'flat': {
                'stride': '0xb8', 'key': 'record + 0x0',
                'element': 'record + 0x8',
            },
        },
        'field_verdicts': {
            _hx(d): field_verdict
            for d in (0x40, 0x58, 0x60, 0x78, 0x80, 0x88, 0x90, 0x98)},
        'boundary': {
            'statement': (
                'the four insert-or-assign drivers receive the element '
                'as a caller-supplied argument and only forward it or '
                'copy it wholesale (0xb0 memcpys); the original '
                'per-field writer is whoever fills that 0xb0-byte '
                'element buffer above the drivers.  The drivers\' '
                'direct E8 callers are censused below and deliberately '
                'not traced (one more level up, per the lane brief).'),
            'driver_callers': {
                name: call_graph[name]
                for name in ('caller_a', 'caller_b1', 'caller_b2',
                             'caller_c')},
        },
        'counters': counters,
        'verdict': (
            'the element builder for the sibling-search node layout '
            'never writes the eight join-callee fields individually: '
            'across the 19 pinned builder bodies (3 insert wrappers, '
            '3 insert/split giants, 6 build initialisers, 3 '
            'bulk-build giants, 4 insert-or-assign drivers; 5,506 '
            'decoded instructions) there is no store at any of the '
            'eight displacements through a non-stack address, and '
            'every element-derived store is the displacement-0 head '
            'qword (21 sites).  Elements enter nodes only as '
            'wholesale copies of an already-built element image: 22 '
            'whole-element 0xb0 memcpys, 51 tail 0xa8 memcpys paired '
            'with head-qword stores, and 15 whole-element memmove '
            'shifts.  The image itself arrives as the drivers\' '
            'caller-supplied element argument; its per-field writer '
            'is above that boundary.'),
        'extractor': 'tools/element_builder_static.py',
    }
    return records


def _frames(data):
    retained = {tuple(b['range']) for b in BODIES.values()}
    retained.add(SIBLING)
    retained.add(CALLEE)
    handle = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
    try:
        handle.write(data)
        handle.close()
        out = subprocess.check_output(
            ['readelf', '--debug-dump=frames', handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    lines = []
    for line in out.splitlines():
        if ' FDE ' not in line:
            continue
        match = re.search(r'pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
        if match and (int(match.group(1), 16),
                      int(match.group(2), 16)) in retained:
            lines.append(line)
    if len(lines) != len(retained):
        raise AssertionError(
            f'frames cover {len(lines)} of {len(retained)} FDEs')
    return '\n'.join(lines) + '\n'


def _body_export(data, start, end):
    handle = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
    try:
        handle.write(data)
        handle.close()
        out = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={start:#x}', f'--stop-address={end:#x}',
             handle.name], text=True)
    finally:
        Path(handle.name).unlink()
    return out.replace(handle.name, '<authenticated-node115>')


def _export_name(name, start, end):
    return f'{name}_full_body_{start:x}_{end:x}_objdump.txt'


class PacketError(AssertionError):
    """The artifact does not authenticate against node 115."""


def generate(data, out_dir):
    if hashlib.sha256(data).hexdigest() != ARTIFACT_SHA256 \
            or len(data) != ARTIFACT_SIZE:
        raise PacketError('artifact SHA-256 mismatch')
    records = analyze(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (out_dir / 'frames.txt').write_text(_frames(data))
    for name, body in BODIES.items():
        start, end = body['range']
        (out_dir / _export_name(name, start, end)).write_text(
            _body_export(data, start, end))
    return records


def main(argv):
    if len(argv) != 3 or argv[1] != 'generate':
        raise SystemExit(
            'usage: element_builder_static.py generate <out-dir>')
    artifact = ROOT / 'artifacts/node/115/hl-node'
    generate(artifact.read_bytes(), argv[2])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
