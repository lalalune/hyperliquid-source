#!/usr/bin/env python3
"""Static evidence for the RE-006 node 115 join callee.

Resolves GOT slot 0x64e7198 — the indirect callee shared by the three
2816-byte cursor-search join sites pinned in
RE-006-node115-sibling-search (#2542) — from the artifact itself, and
pins the callee it delivers control to.

The node 115 ELF is a static PIE (ET_DYN, no dynamic linker in the
loop): slot 0x64e7198 lies in .got, its file-initialised content is
zero, and it carries exactly one relocation, an R_X86_64_RELATIVE
whose addend 0x36a0d80 is an exact FDE start. The addend is therefore
the callee. A binary-wide census of rip-relative references (every
mod=00/rm=101 modrm position whose disp32 names the slot, for every
trailing-immediate length) finds exactly four call sites: the three
joins and one further consumer phase in FDE 0x2f0f3b0. At all four,
rdi is the join-produced element pointer (node + position x 0xb0 on
the joins' search arm, the handle root + clamped index x 0xb8 + 8 on
their fallback arm, the same two arms inside 0x2f0f3b0 itself).

The callee (0x36a0d80..0x36a0fd6, 598 bytes) is a pure function of
the element pointer: it saves rdi in rbx, reads eight element fields
(+0x40, +0x58, +0x78, +0x60 on every execution; +0x90, +0x98 in its
clamp phase; +0x80 or +0x88 per arm), writes nothing through the
pointer, makes no direct call, and calls one helper seven times —
always through GOT slot 0x64dfaf8, itself a single
R_X86_64_RELATIVE to 0x63efec0 — under a four-argument contract
(u128 numerator in rdi/rsi, u128 denominator in rdx/rcx, quotient in
rax/rdx) consistent with unsigned __divti3-style division. It
returns in xmm0 a double: an integer built from the two u128
products of the field pairs, scaled and clamped against 10^14,
divided by the double 10^14 at 0x459378.

analyze() validates the artifact without authenticating it (any byte
flip fails the specific check); generate() authenticates first and
regenerates records.json, frames.txt and the callee full-body export
byte-for-byte.
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

PACKET_ID = 'RE-006-node115-join-callee'
ARTIFACT_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARTIFACT_SIZE = 105896032
FDE_COUNT = 135313

SLOT = 0x64E7198
GOT_RANGE = (105772120, 105832792)
HELPER_SLOT = 0x64DFAF8
HELPER_TARGET = 0x63EFEC0
CALLEE = {'range': (0x36A0D80, 0x36A0FD6),
          'sha256': '7bef359785703ce3ca6bbe09784c734204e78fc47f25759f4d14c08823b6dfc2'}
CALLEE_PINS = {57281920: ('55', 'push   %rbp'), 57281921: ('4157', 'push   %r15'), 57281923: ('4156', 'push   %r14'), 57281925: ('4155', 'push   %r13'), 57281927: ('4154', 'push   %r12'), 57281929: ('53', 'push   %rbx'), 57281930: ('50', 'push   %rax'), 57281931: ('4889fb', 'mov    %rdi,%rbx'), 57281934: ('4c8b7740', 'mov    0x40(%rdi),%r14'), 57281938: ('4c89f0', 'mov    %r14,%rax'), 57281941: ('48f76758', 'mulq   0x58(%rdi)'), 57281945: ('4989d4', 'mov    %rdx,%r12'), 57281948: ('4989c5', 'mov    %rax,%r13'), 57281951: ('49bf00407a10f3', 'movabs $0x5af3107a4000,%r15'), 57281961: ('4889c7', 'mov    %rax,%rdi'), 57281964: ('4889d6', 'mov    %rdx,%rsi'), 57281967: ('4c89fa', 'mov    %r15,%rdx'), 57281970: ('31c9', 'xor    %ecx,%ecx'), 57281972: ('ff153eede302', 'call   *0x2e3ed3e(%rip)        # 0x64dfaf8'), 57281978: ('4889c6', 'mov    %rax,%rsi'), 57281981: ('4889d1', 'mov    %rdx,%rcx'), 57281984: ('4889d7', 'mov    %rdx,%rdi'), 57281987: ('490fafff', 'imul   %r15,%rdi'), 57281991: ('49f7e7', 'mul    %r15'), 57281994: ('4801fa', 'add    %rdi,%rdx'), 57281997: ('4929c5', 'sub    %rax,%r13'), 57282000: ('4919d4', 'sbb    %rdx,%r12'), 57282003: ('4531ff', 'xor    %r15d,%r15d'), 57282006: ('4d09ec', 'or     %r13,%r12'), 57282009: ('410f95c7', 'setne  %r15b'), 57282013: ('4901f7', 'add    %rsi,%r15'), 57282016: ('4883d100', 'adc    $0x0,%rcx'), 57282020: ('7405', 'je     0x36a0deb'), 57282022: ('41b601', 'mov    $0x1,%r14b'), 57282025: ('eb10', 'jmp    0x36a0dfb'), 57282027: ('4d85f6', 'test   %r14,%r14'), 57282030: ('0f94c0', 'sete   %al'), 57282033: ('4c09f9', 'or     %r15,%rcx'), 57282036: ('410f95c6', 'setne  %r14b'), 57282040: ('4120c6', 'and    %al,%r14b'), 57282043: ('488b4378', 'mov    0x78(%rbx),%rax'), 57282047: ('48f76360', 'mulq   0x60(%rbx)'), 57282051: ('4889c5', 'mov    %rax,%rbp'), 57282054: ('4989d5', 'mov    %rdx,%r13'), 57282057: ('4531e4', 'xor    %r12d,%r12d'), 57282060: ('48ba00407a10f3', 'movabs $0x5af3107a4000,%rdx'), 57282070: ('4889c7', 'mov    %rax,%rdi'), 57282073: ('4c89ee', 'mov    %r13,%rsi'), 57282076: ('31c9', 'xor    %ecx,%ecx'), 57282078: ('ff15d4ece302', 'call   *0x2e3ecd4(%rip)        # 0x64dfaf8'), 57282084: ('4584f6', 'test   %r14b,%r14b'), 57282087: ('7566', 'jne    0x36a0e8f'), 57282089: ('4889c1', 'mov    %rax,%rcx'), 57282092: ('48c7c0ffffffff', 'mov    $0xffffffffffffffff,%rax'), 57282099: ('4839e8', 'cmp    %rbp,%rax'), 57282102: ('49beff3f7a10f3', 'movabs $0x5af3107a3fff,%r14'), 57282112: ('4c89f0', 'mov    %r14,%rax'), 57282115: ('4c19e8', 'sbb    %r13,%rax'), 57282118: ('49c7c5ffffffff', 'mov    $0xffffffffffffffff,%r13'), 57282125: ('7251', 'jb     0x36a0ea0'), 57282127: ('4885c9', 'test   %rcx,%rcx'), 57282130: ('48bd00407a10f3', 'movabs $0x5af3107a4000,%rbp'), 57282140: ('744c', 'je     0x36a0eaa'), 57282142: ('4989d0', 'mov    %rdx,%r8'), 57282145: ('4c89f8', 'mov    %r15,%rax'), 57282148: ('48f7e5', 'mul    %rbp'), 57282151: ('4889c7', 'mov    %rax,%rdi'), 57282154: ('4889d6', 'mov    %rdx,%rsi'), 57282157: ('4889ca', 'mov    %rcx,%rdx'), 57282160: ('4c89c1', 'mov    %r8,%rcx'), 57282163: ('ff157fece302', 'call   *0x2e3ec7f(%rip)        # 0x64dfaf8'), 57282169: ('4885d2', 'test   %rdx,%rdx'), 57282172: ('7405', 'je     0x36a0e83'), 57282174: ('4531e4', 'xor    %r12d,%r12d'), 57282177: ('eb27', 'jmp    0x36a0eaa'), 57282179: ('4989c4', 'mov    %rax,%r12'), 57282182: ('4839e8', 'cmp    %rbp,%rax'), 57282185: ('4c0f43e5', 'cmovae %rbp,%r12'), 57282189: ('eb1b', 'jmp    0x36a0eaa'), 57282191: ('49beff3f7a10f3', 'movabs $0x5af3107a3fff,%r14'), 57282201: ('49c7c5ffffffff', 'mov    $0xffffffffffffffff,%r13'), 57282208: ('48bd00407a10f3', 'movabs $0x5af3107a4000,%rbp'), 57282218: ('4c8bbb90000000', 'mov    0x90(%rbx),%r15'), 57282225: ('488b8b98000000', 'mov    0x98(%rbx),%rcx'), 57282232: ('4c89e0', 'mov    %r12,%rax'), 57282235: ('4829c8', 'sub    %rcx,%rax'), 57282238: ('7473', 'je     0x36a0f33'), 57282240: ('7362', 'jae    0x36a0f24'), 57282242: ('488b9b80000000', 'mov    0x80(%rbx),%rbx'), 57282249: ('4c89e0', 'mov    %r12,%rax'), 57282252: ('48f7e5', 'mul    %rbp'), 57282255: ('4889c7', 'mov    %rax,%rdi'), 57282258: ('4889d6', 'mov    %rdx,%rsi'), 57282261: ('4889ca', 'mov    %rcx,%rdx'), 57282264: ('31c9', 'xor    %ecx,%ecx'), 57282266: ('ff1518ece302', 'call   *0x2e3ec18(%rip)        # 0x64dfaf8'), 57282272: ('4c89f9', 'mov    %r15,%rcx'), 57282275: ('4829d9', 'sub    %rbx,%rcx'), 57282278: ('724b', 'jb     0x36a0f33'), 57282280: ('4885d2', 'test   %rdx,%rdx'), 57282283: ('7546', 'jne    0x36a0f33'), 57282285: ('480fafd1', 'imul   %rcx,%rdx'), 57282289: ('4889d6', 'mov    %rdx,%rsi'), 57282292: ('48f7e1', 'mul    %rcx'), 57282295: ('4801f2', 'add    %rsi,%rdx'), 57282298: ('4939c5', 'cmp    %rax,%r13'), 57282301: ('4919d6', 'sbb    %rdx,%r14'), 57282304: ('7231', 'jb     0x36a0f33'), 57282306: ('48b900407a10f3', 'movabs $0x5af3107a4000,%rcx'), 57282316: ('4889c7', 'mov    %rax,%rdi'), 57282319: ('4889d6', 'mov    %rdx,%rsi'), 57282322: ('4889ca', 'mov    %rcx,%rdx'), 57282325: ('31c9', 'xor    %ecx,%ecx'), 57282327: ('ff15dbebe302', 'call   *0x2e3ebdb(%rip)        # 0x64dfaf8'), 57282333: ('4801c3', 'add    %rax,%rbx'), 57282336: ('730e', 'jae    0x36a0f30'), 57282338: ('eb0f', 'jmp    0x36a0f33'), 57282340: ('488b9b88000000', 'mov    0x88(%rbx),%rbx'), 57282347: ('4c39f1', 'cmp    %r14,%rcx'), 57282350: ('763b', 'jbe    0x36a0f6b'), 57282352: ('4989df', 'mov    %rbx,%r15'), 57282355: ('66490f6ecf', 'movq   %r15,%xmm1'), 57282360: ('660f620dd002db', 'punpckldq -0x324fd30(%rip),%xmm1        # 0x451210'), 57282368: ('660f5c0d28f2da', 'subpd  -0x3250dd8(%rip),%xmm1        # 0x450170'), 57282376: ('660f28c1', 'movapd %xmm1,%xmm0'), 57282380: ('660f15c1', 'unpckhpd %xmm1,%xmm0'), 57282384: ('f20f58c1', 'addsd  %xmm1,%xmm0'), 57282388: ('f20f5e051c84db', 'divsd  -0x3247be4(%rip),%xmm0        # 0x459378'), 57282396: ('4883c408', 'add    $0x8,%rsp'), 57282400: ('5b', 'pop    %rbx'), 57282401: ('415c', 'pop    %r12'), 57282403: ('415d', 'pop    %r13'), 57282405: ('415e', 'pop    %r14'), 57282407: ('415f', 'pop    %r15'), 57282409: ('5d', 'pop    %rbp'), 57282410: ('c3', 'ret'), 57282411: ('4d89f0', 'mov    %r14,%r8'), 57282414: ('4929c8', 'sub    %rcx,%r8'), 57282417: ('49ffc0', 'inc    %r8'), 57282420: ('48f7e5', 'mul    %rbp'), 57282423: ('4889c7', 'mov    %rax,%rdi'), 57282426: ('4889d6', 'mov    %rdx,%rsi'), 57282429: ('4c89c2', 'mov    %r8,%rdx'), 57282432: ('31c9', 'xor    %ecx,%ecx'), 57282434: ('ff1570ebe302', 'call   *0x2e3eb70(%rip)        # 0x64dfaf8'), 57282440: ('4889d9', 'mov    %rbx,%rcx'), 57282443: ('4c29f9', 'sub    %r15,%rcx'), 57282446: ('72a0', 'jb     0x36a0f30'), 57282448: ('4885d2', 'test   %rdx,%rdx'), 57282451: ('759b', 'jne    0x36a0f30'), 57282453: ('480fafd1', 'imul   %rcx,%rdx'), 57282457: ('4889d6', 'mov    %rdx,%rsi'), 57282460: ('48f7e1', 'mul    %rcx'), 57282463: ('4801f2', 'add    %rsi,%rdx'), 57282466: ('4939c5', 'cmp    %rax,%r13'), 57282469: ('4919d6', 'sbb    %rdx,%r14'), 57282472: ('7286', 'jb     0x36a0f30'), 57282474: ('48b900407a10f3', 'movabs $0x5af3107a4000,%rcx'), 57282484: ('4889c7', 'mov    %rax,%rdi'), 57282487: ('4889d6', 'mov    %rdx,%rsi'), 57282490: ('4889ca', 'mov    %rcx,%rdx'), 57282493: ('31c9', 'xor    %ecx,%ecx'), 57282495: ('ff1533ebe302', 'call   *0x2e3eb33(%rip)        # 0x64dfaf8'), 57282501: ('4901c7', 'add    %rax,%r15'), 57282504: ('0f8262ffffff', 'jb     0x36a0f30'), 57282510: ('4c89fb', 'mov    %r15,%rbx'), 57282513: ('e95affffff', 'jmp    0x36a0f30')}
CALLERS = {44602624: ((44602624, 44605440), 'd33c9906f43bb0c54ab7cf6a21f3b8cd465f135cb9716ea7e4991eefafbb2aa0'), 89786336: ((89786336, 89789152), '41e588d7db79f90108f6981acc95af94e2534e68a0aa570c5f0270ece139ec5d'), 89789152: ((89789152, 89791968), '1c2af67af44f5fe0dcb0eb706c5b9c2db8d4793c5ac01475387cfe160a6cf0ba'), 49345456: ((49345456, 49346874), '2f5fe82fbc64267cdc17936d2556d8453b92cc54a3353e95535ef93ab11453ed')}
CALL_SITES = {
    0x2A89978: {'caller': 0x2A89500, 'kind': 'join'},
    0x55A0C58: {'caller': 0x55A07E0, 'kind': 'join'},
    0x55A1758: {'caller': 0x55A12E0, 'kind': 'join'},
    0x2F0F6CC: {'caller': 0x2F0F3B0, 'kind': 'consumer_phase'},
}
WINDOWS = {'join_0x2a89978': {'range': (44603664, 44603774), 'pins': {44603664: ('e84b5bb300', 'call   0x35bf460'), 44603669: ('83bc2480000000', 'cmpl   $0x1,0x80(%rsp)'), 44603677: ('745f', 'je     0x2a8997e'), 44603679: ('4869bc24980000', 'imul   $0xb0,0x98(%rsp),%rdi'), 44603691: ('4803bc24880000', 'add    0x88(%rsp),%rdi'), 44603699: ('eb43', 'jmp    0x2a89978'), 44603701: ('488d742420', 'lea    0x20(%rsp),%rsi'), 44603706: ('4c89ff', 'mov    %r15,%rdi'), 44603709: ('e8cecaac01', 'call   0x4556410'), 44603714: ('a801', 'test   $0x1,%al'), 44603716: ('7538', 'jne    0x2a8997e'), 44603718: ('483b93e0060000', 'cmp    0x6e0(%rbx),%rdx'), 44603725: ('732f', 'jae    0x2a8997e'), 44603727: ('480393d8060000', 'add    0x6d8(%rbx),%rdx'), 44603734: ('31c0', 'xor    %eax,%eax'), 44603736: ('4c39ea', 'cmp    %r13,%rdx'), 44603739: ('490f43c5', 'cmovae %r13,%rax'), 44603743: ('4829c2', 'sub    %rax,%rdx'), 44603746: ('488b83d0060000', 'mov    0x6d0(%rbx),%rax'), 44603753: ('4869cab8000000', 'imul   $0xb8,%rdx,%rcx'), 44603760: ('488d3c08', 'lea    (%rax,%rcx,1),%rdi'), 44603764: ('4883c708', 'add    $0x8,%rdi'), 44603768: ('ff151ad8a503', 'call   *0x3a5d81a(%rip)        # 0x64e7198')}, 'calls': {44603664: '0x35bf460', 44603709: '0x4556410'}}, 'join_0x55a0c58': {'range': (89787376, 89787486), 'pins': {89787376: ('e86be801fe', 'call   0x35bf460'), 89787381: ('83bc2480000000', 'cmpl   $0x1,0x80(%rsp)'), 89787389: ('745f', 'je     0x55a0c5e'), 89787391: ('4869bc24980000', 'imul   $0xb0,0x98(%rsp),%rdi'), 89787403: ('4803bc24880000', 'add    0x88(%rsp),%rdi'), 89787411: ('eb43', 'jmp    0x55a0c58'), 89787413: ('488d742420', 'lea    0x20(%rsp),%rsi'), 89787418: ('4c89ff', 'mov    %r15,%rdi'), 89787421: ('e8ee57fbfe', 'call   0x4556410'), 89787426: ('a801', 'test   $0x1,%al'), 89787428: ('7538', 'jne    0x55a0c5e'), 89787430: ('483b93e0060000', 'cmp    0x6e0(%rbx),%rdx'), 89787437: ('732f', 'jae    0x55a0c5e'), 89787439: ('480393d8060000', 'add    0x6d8(%rbx),%rdx'), 89787446: ('31c0', 'xor    %eax,%eax'), 89787448: ('4c39ea', 'cmp    %r13,%rdx'), 89787451: ('490f43c5', 'cmovae %r13,%rax'), 89787455: ('4829c2', 'sub    %rax,%rdx'), 89787458: ('488b83d0060000', 'mov    0x6d0(%rbx),%rax'), 89787465: ('4869cab8000000', 'imul   $0xb8,%rdx,%rcx'), 89787472: ('488d3c08', 'lea    (%rax,%rcx,1),%rdi'), 89787476: ('4883c708', 'add    $0x8,%rdi'), 89787480: ('ff153a65f400', 'call   *0xf4653a(%rip)        # 0x64e7198')}, 'calls': {89787376: '0x35bf460', 89787421: '0x4556410'}}, 'join_0x55a1758': {'range': (89790192, 89790302), 'pins': {89790192: ('e86bdd01fe', 'call   0x35bf460'), 89790197: ('83bc2480000000', 'cmpl   $0x1,0x80(%rsp)'), 89790205: ('745f', 'je     0x55a175e'), 89790207: ('4869bc24980000', 'imul   $0xb0,0x98(%rsp),%rdi'), 89790219: ('4803bc24880000', 'add    0x88(%rsp),%rdi'), 89790227: ('eb43', 'jmp    0x55a1758'), 89790229: ('488d742420', 'lea    0x20(%rsp),%rsi'), 89790234: ('4c89ff', 'mov    %r15,%rdi'), 89790237: ('e8ee4cfbfe', 'call   0x4556410'), 89790242: ('a801', 'test   $0x1,%al'), 89790244: ('7538', 'jne    0x55a175e'), 89790246: ('483b93e0060000', 'cmp    0x6e0(%rbx),%rdx'), 89790253: ('732f', 'jae    0x55a175e'), 89790255: ('480393d8060000', 'add    0x6d8(%rbx),%rdx'), 89790262: ('31c0', 'xor    %eax,%eax'), 89790264: ('4c39ea', 'cmp    %r13,%rdx'), 89790267: ('490f43c5', 'cmovae %r13,%rax'), 89790271: ('4829c2', 'sub    %rax,%rdx'), 89790274: ('488b83d0060000', 'mov    0x6d0(%rbx),%rax'), 89790281: ('4869cab8000000', 'imul   $0xb8,%rdx,%rcx'), 89790288: ('488d3c08', 'lea    (%rax,%rcx,1),%rdi'), 89790292: ('4883c708', 'add    $0x8,%rdi'), 89790296: ('ff153a5af400', 'call   *0xf45a3a(%rip)        # 0x64e7198')}, 'calls': {89790192: '0x35bf460', 89790237: '0x4556410'}}, 'caller_0x2f0f3b0_entry_search': {'range': (49345476, 49345582), 'pins': {49345476: ('4989d5', 'mov    %rdx,%r13'), 49345479: ('4989f6', 'mov    %rsi,%r14'), 49345482: ('4989ff', 'mov    %rdi,%r15'), 49345485: ('4889742430', 'mov    %rsi,0x30(%rsp)'), 49345490: ('488b5a58', 'mov    0x58(%rdx),%rbx'), 49345494: ('4889d8', 'mov    %rbx,%rax'), 49345497: ('48f7d8', 'neg    %rax'), 49345500: ('7150', 'jno    0x2f0f42e'), 49345502: ('498b7560', 'mov    0x60(%r13),%rsi'), 49345506: ('4885f6', 'test   %rsi,%rsi'), 49345509: ('0f84b9030000', 'je     0x2f0f7a4'), 49345515: ('498b5568', 'mov    0x68(%r13),%rdx'), 49345519: ('488dbc24880000', 'lea    0x88(%rsp),%rdi'), 49345527: ('488d4c2430', 'lea    0x30(%rsp),%rcx'), 49345532: ('e85f006b00', 'call   0x35bf460'), 49345537: ('83bc2488000000', 'cmpl   $0x1,0x88(%rsp)'), 49345545: ('0f8495030000', 'je     0x2f0f7a4'), 49345551: ('4c896c2418', 'mov    %r13,0x18(%rsp)'), 49345556: ('4c893424', 'mov    %r14,(%rsp)'), 49345560: ('4c69ac24a00000', 'imul   $0xb0,0xa0(%rsp),%r13'), 49345572: ('4c03ac24900000', 'add    0x90(%rsp),%r13'), 49345580: ('eb4c', 'jmp    0x2f0f47a')}, 'calls': {49345532: '0x35bf460'}}, 'caller_0x2f0f3b0_fallback': {'range': (49345582, 49345658), 'pins': {49345582: ('498d7d58', 'lea    0x58(%r13),%rdi'), 49345586: ('488d742430', 'lea    0x30(%rsp),%rsi'), 49345591: ('e8d46f6401', 'call   0x4556410'), 49345596: ('a801', 'test   $0x1,%al'), 49345598: ('0f8560030000', 'jne    0x2f0f7a4'), 49345604: ('493b5570', 'cmp    0x70(%r13),%rdx'), 49345608: ('0f8356030000', 'jae    0x2f0f7a4'), 49345614: ('4c893424', 'mov    %r14,(%rsp)'), 49345618: ('49035568', 'add    0x68(%r13),%rdx'), 49345622: ('31c0', 'xor    %eax,%eax'), 49345624: ('4839da', 'cmp    %rbx,%rdx'), 49345627: ('480f43c3', 'cmovae %rbx,%rax'), 49345631: ('4829c2', 'sub    %rax,%rdx'), 49345634: ('4c896c2418', 'mov    %r13,0x18(%rsp)'), 49345639: ('498b4560', 'mov    0x60(%r13),%rax'), 49345643: ('4869cab8000000', 'imul   $0xb8,%rdx,%rcx'), 49345650: ('4c8d2c08', 'lea    (%rax,%rcx,1),%r13'), 49345654: ('4983c508', 'add    $0x8,%r13')}, 'calls': {49345591: '0x4556410'}}, 'caller_0x2f0f3b0_inline_reads': {'range': (49345658, 49345692), 'pins': {49345658: ('49beff3f7a10f3', 'movabs $0x5af3107a3fff,%r14'), 49345668: ('498b4540', 'mov    0x40(%r13),%rax'), 49345672: ('49f76558', 'mulq   0x58(%r13)'), 49345676: ('4889d3', 'mov    %rdx,%rbx'), 49345679: ('498b4d78', 'mov    0x78(%r13),%rcx'), 49345683: ('48894c2410', 'mov    %rcx,0x10(%rsp)'), 49345688: ('498b6d60', 'mov    0x60(%r13),%rbp')}, 'calls': {}}, 'caller_0x2f0f3b0_got_call': {'range': (49346239, 49346269), 'pins': {49346239: ('4c89642440', 'mov    %r12,0x40(%rsp)'), 49346244: ('4c897c2410', 'mov    %r15,0x10(%rsp)'), 49346249: ('4c89ef', 'mov    %r13,%rdi'), 49346252: ('ff15c67a5d03', 'call   *0x35d7ac6(%rip)        # 0x64e7198'), 49346258: ('4d8b7540', 'mov    0x40(%r13),%r14'), 49346262: ('4c89f0', 'mov    %r14,%rax'), 49346265: ('49f76558', 'mulq   0x58(%r13)')}, 'calls': {}}}
ELEMENT_LOADS = {64: [57281934], 88: [57281941], 120: [57282043], 96: [57282047], 144: [57282218], 152: [57282225], 128: [57282242], 136: [57282340]}
HELPER_CALLS = [57281972, 57282078, 57282163, 57282266, 57282327, 57282434, 57282495]
RET_SITES = [57282410]
MOVABS = {100000000000000: [57281951, 57282060, 57282130, 57282208, 57282306, 57282474], 99999999999999: [57282102, 57282191]}
SCALE_IMMEDIATE = 0x5AF3107A4000          # 10^14
CLAMP_IMMEDIATE = 0x5AF3107A3FFF          # 10^14 - 1
FP_CONSTANTS = {'scale_double_bits': 4816244402031689728, 'conv_pair_bits': [4841369599423283200, 4985484787499139072], 'punpck_dwords': [1127219200, 1160773632, 0, 0]}
EXPECTED = {'call_sites': 4, 'callers': 4, 'callee_bytes': 598, 'callee_instructions': 167, 'direct_calls': 0, 'element_loads': 8, 'element_offsets': 8, 'element_stores': 0, 'fde_count': 135313, 'helper_calls': 7, 'helper_slot_rela_entries': 1, 'join_call_sites': 3, 'other_call_sites': 1, 'ret_sites': 1, 'rip_relative_references': 4, 'scale_movabs_sites': 6, 'clamp_movabs_sites': 2, 'slot_initialised_qword': 0, 'slot_rela_entries': 1, 'trailing_immediate_references': 0, 'windows': 7}

_LINE_RE = re.compile(r'^\s+([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$')
_MODRM_RE = re.compile(rb'(?=[\x05\x0d\x15\x1d\x25\x2d\x35\x3d])')
_MEM_RE = re.compile(r'(0x[0-9a-f]+)\(%r(di|bx)\)')


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
            rows[int(match.group(1), 16)] = (match.group(2).replace(' ', ''),
                                             match.group(3).strip())
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


def _check_calls(rows, calls):
    for address, target in calls.items():
        row = rows.get(address)
        if row is None or row[1].split() != ['call', target]:
            raise AssertionError(f'call at {address:#x} is not a call to {target}')


def _check_windows(data, secs):
    decoded = {}
    for name, window in WINDOWS.items():
        start, end = window['range']
        rows = _decode(data, secs, start, end)
        _check_pins(rows, window['pins'], f'window {name}')
        _check_calls(rows, window['calls'])
        decoded[name] = rows
    return decoded


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


def analyze(data):
    secs = sections(data)
    if struct.unpack_from('<H', data, 16)[0] != 3:
        raise AssertionError('artifact is not ET_DYN (static PIE)')
    _summary, fdes, _gaps = fde_extents(data)
    if len(fdes) != FDE_COUNT:
        raise AssertionError(f'FDE census is {len(fdes)}, expected {FDE_COUNT}')
    if len({f['start'] for f in fdes}) != FDE_COUNT:
        raise AssertionError('FDE starts are not unique')
    extents = {f['start']: (f['start'], f['end']) for f in fdes}

    # --- the slot: section, relocation, initialised content ---
    got = next(s for s in secs if s['name'] == '.got')
    if (got['address'], got['address'] + got['size']) != GOT_RANGE:
        raise AssertionError('.got extent differs from its pin')
    if not (GOT_RANGE[0] <= SLOT < GOT_RANGE[1]):
        raise AssertionError('slot lies outside .got')
    entries = _rela_entries(data, secs)
    slot_hits = [e for e in entries if e[0] == SLOT]
    if slot_hits != [(SLOT, 8, 0, CALLEE['range'][0])]:
        raise AssertionError(
            f'slot {SLOT:#x} relocation differs: {slot_hits!r}')
    helper_hits = [e for e in entries if e[0] == HELPER_SLOT]
    if helper_hits != [(HELPER_SLOT, 8, 0, HELPER_TARGET)]:
        raise AssertionError(
            f'helper slot {HELPER_SLOT:#x} relocation differs: {helper_hits!r}')
    slot_qword = struct.unpack_from(
        '<Q', _section_bytes(data, secs, SLOT, SLOT + 8), 0)[0]
    if slot_qword != 0:
        raise AssertionError('slot initialised content is not zero')

    # --- the callee body ---
    start, end = CALLEE['range']
    if extents.get(start) != (start, end):
        raise AssertionError('callee range is not an exact FDE extent')
    if _digest(data, secs, start, end) != CALLEE['sha256']:
        raise AssertionError('callee differs from its pinned digest')
    rows = _decode(data, secs, start, end)
    _check_pins(rows, CALLEE_PINS, 'callee')
    for address in sorted(rows):
        parts = rows[address][1].split()
        if parts and parts[0].startswith('j') and len(parts) == 2 \
                and parts[1].startswith('0x'):
            if not (start <= int(parts[1], 16) < end):
                raise AssertionError(
                    f'callee branch at {address:#x} leaves the body')
    if rows[0x36A0D8B][1] != 'mov    %rdi,%rbx':
        raise AssertionError('callee does not save rdi in rbx at entry')

    loads, stores = {}, []
    for address in sorted(rows):
        text = rows[address][1]
        for match in _MEM_RE.finditer(text):
            offset = int(match.group(1), 16)
            if ',' in text and match.start() > text.rfind(','):
                stores.append((address, offset))
            else:
                loads.setdefault(offset, []).append(address)
    if loads != ELEMENT_LOADS:
        raise AssertionError(f'callee element loads differ: {loads!r}')
    if stores:
        raise AssertionError(f'callee writes through the element: {stores!r}')

    helper_calls, direct_calls, rets = [], 0, []
    for address in sorted(rows):
        text = rows[address][1]
        if text.startswith('call'):
            if '(%rip)' in text:
                if f'# {HELPER_SLOT:#x}' not in text:
                    raise AssertionError(
                        f'callee indirect call at {address:#x} names another slot')
                helper_calls.append(address)
            else:
                direct_calls += 1
        if text == 'ret':
            rets.append(address)
    if helper_calls != HELPER_CALLS:
        raise AssertionError(f'callee helper call census differs: {helper_calls!r}')
    if direct_calls:
        raise AssertionError('callee makes a direct call')
    if rets != RET_SITES:
        raise AssertionError(f'callee ret census differs: {rets!r}')

    movabs = {}
    for address in sorted(rows):
        match = re.match(r'movabs\s+\$0x([0-9a-f]+),', rows[address][1])
        if match:
            movabs.setdefault(int(match.group(1), 16), []).append(address)
    if movabs != MOVABS:
        raise AssertionError(f'callee movabs census differs: {movabs!r}')

    scale_bits = struct.unpack_from(
        '<Q', _section_bytes(data, secs, 0x459378, 0x459380), 0)[0]
    if scale_bits != FP_CONSTANTS['scale_double_bits']:
        raise AssertionError('divisor double at 0x459378 differs')
    conv_pair = struct.unpack_from(
        '<2Q', _section_bytes(data, secs, 0x450170, 0x450180), 0)
    if list(conv_pair) != FP_CONSTANTS['conv_pair_bits']:
        raise AssertionError('conversion constant pair at 0x450170 differs')
    punpck = struct.unpack_from(
        '<4I', _section_bytes(data, secs, 0x451210, 0x451220), 0)
    if list(punpck) != FP_CONSTANTS['punpck_dwords']:
        raise AssertionError('punpckldq constants at 0x451210 differ')

    # --- callers ---
    caller_rows = {}
    for caller, ((cs, ce), caller_sha) in CALLERS.items():
        if extents.get(cs) != (cs, ce):
            raise AssertionError(f'caller {caller:#x} range is not an exact FDE extent')
        if _digest(data, secs, cs, ce) != caller_sha:
            raise AssertionError(f'caller {caller:#x} differs from its pinned digest')
        caller_rows[caller] = _decode(data, secs, cs, ce)

    # --- binary-wide rip-relative census naming the slot ---
    hits = {}
    for sec in secs:
        if sec['type'] == 8 or not (sec['flags'] & 4 and sec['size']):
            continue
        blob = _section_bytes(data, secs, sec['address'],
                              sec['address'] + sec['size'])
        for match in _MODRM_RE.finditer(blob):
            pos = match.start()
            if pos + 5 > len(blob):
                continue
            disp = struct.unpack_from('<i', blob, pos + 1)[0]
            # A reference's modrm sits at p; its target is p + 5 + k +
            # disp32, where k is a trailing-immediate length (0 for
            # call/mov/lea forms). The modrm position alone therefore
            # identifies every rip-relative reference to the slot.
            for k in (0, 1, 2, 4):
                if sec['address'] + pos + 5 + k + disp == SLOT:
                    hits.setdefault(sec['address'] + pos, set()).add(k)
    expected_hits = {site + 1: {0} for site in CALL_SITES}
    if hits != expected_hits:
        raise AssertionError(f'rip-relative census differs: {hits!r}')
    for site, info in CALL_SITES.items():
        if not (CALLERS[info['caller']][0][0] <= site
                < CALLERS[info['caller']][0][1]):
            raise AssertionError(f'site {site:#x} lies outside its caller')
        row = caller_rows[info['caller']].get(site)
        if row is None or not row[1].startswith('call') \
                or f'# {SLOT:#x}' not in row[1]:
            raise AssertionError(
                f'site {site:#x} is not a call through slot {SLOT:#x}')

    # --- windows + argument provenance spot checks ---
    decoded = _check_windows(data, secs)
    for site, info in CALL_SITES.items():
        if info['kind'] != 'join':
            continue
        wrows = decoded[f'join_{site:#x}']
        texts = [wrows[a][1] for a in sorted(wrows)]
        if sum('$0xb0' in text for text in texts) != 1:
            raise AssertionError(f'join {site:#x} search-arm scale differs')
        if sum('$0xb8' in text for text in texts) != 1:
            raise AssertionError(f'join {site:#x} fallback-arm scale differs')
        if sum(text.startswith('add') and '$0x8' in text for text in texts) != 1:
            raise AssertionError(f'join {site:#x} fallback bias differs')
    entry_rows = decoded['caller_0x2f0f3b0_entry_search']
    if '%rdx,%r13' not in entry_rows[0x2F0F3C4][1]:
        raise AssertionError('consumer phase does not take its handle from rdx')
    got_rows = decoded['caller_0x2f0f3b0_got_call']
    if got_rows[0x2F0F6C9][1].split() != ['mov', '%r13,%rdi']:
        raise AssertionError('consumer phase does not pass its element in rdi')

    counters = {
        'call_sites': len(CALL_SITES),
        'callers': len(CALLERS),
        'callee_bytes': end - start,
        'callee_instructions': len(CALLEE_PINS),
        'direct_calls': direct_calls,
        'element_loads': sum(len(v) for v in loads.values()),
        'element_offsets': len(loads),
        'element_stores': len(stores),
        'fde_count': len(fdes),
        'helper_calls': len(helper_calls),
        'helper_slot_rela_entries': len(helper_hits),
        'join_call_sites': sum(1 for i in CALL_SITES.values()
                               if i['kind'] == 'join'),
        'other_call_sites': sum(1 for i in CALL_SITES.values()
                                if i['kind'] != 'join'),
        'ret_sites': len(rets),
        'rip_relative_references': len(hits),
        'scale_movabs_sites': len(movabs.get(SCALE_IMMEDIATE, [])),
        'clamp_movabs_sites': len(movabs.get(CLAMP_IMMEDIATE, [])),
        'slot_initialised_qword': slot_qword,
        'slot_rela_entries': len(slot_hits),
        'trailing_immediate_references': sum(
            1 for ks in hits.values() for k in ks if k),
        'windows': len(WINDOWS),
    }
    if counters != EXPECTED:
        raise AssertionError(f'counters differ: {counters} != {EXPECTED}')

    return {
        'boundaries': {
            f'caller_{caller:#x}': {'range': [_hx(rng[0]), _hx(rng[1])],
                                    'sha256': sha}
            for caller, (rng, sha) in CALLERS.items()},
        'call_sites': {
            _hx(site): {'caller': _hx(info['caller']), 'kind': info['kind']}
            for site, info in CALL_SITES.items()},
        'callee': {
            'direct_calls': direct_calls,
            'element_loads': {_hx(off): [_hx(a) for a in addrs]
                              for off, addrs in ELEMENT_LOADS.items()},
            'element_stores': len(stores),
            'helper_calls': [_hx(a) for a in HELPER_CALLS],
            'helper_rela_addend': _hx(HELPER_TARGET),
            'helper_slot': _hx(HELPER_SLOT),
            'range': [_hx(start), _hx(end)],
            'ret_sites': [_hx(a) for a in RET_SITES],
            'sha256': CALLEE['sha256'],
            'size': end - start,
        },
        'counters': counters,
        'extractor': 'tools/join_callee_static.py',
        'node': {'artifact_sha256': ARTIFACT_SHA256,
                 'artifact_size': ARTIFACT_SIZE,
                 'fde_count': len(fdes)},
        'packet': PACKET_ID,
        'slot': {
            'address': _hx(SLOT),
            'initialised_qword': slot_qword,
            'mechanism': 'R_X86_64_RELATIVE addend in a static PIE; the '
                         'slot content is initialised to zero, so the '
                         'addend alone carries the target',
            'rela_addend': _hx(start),
            'rela_entries': len(slot_hits),
            'section': '.got',
            'section_range': [_hx(GOT_RANGE[0]), _hx(GOT_RANGE[1])],
        },
        'verdict': 'slot 0x64e7198 resolves to the 598-byte body at '
                   '0x36a0d80; at all four call sites rdi is the '
                   'join-produced element pointer; the callee reads '
                   'eight element fields, writes none, and returns a '
                   '1e14-scaled ratio in xmm0',
        'windows': sorted(WINDOWS),
    }


def _frames(data):
    retained = {CALLEE['range']} | {rng for rng, _sha in CALLERS.values()}
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
        if match and (int(match.group(1), 16), int(match.group(2), 16)) in retained:
            lines.append(line)
    if len(lines) != len(retained):
        raise AssertionError(f'frames cover {len(lines)} of {len(retained)} FDEs')
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


class PacketError(AssertionError):
    """The artifact does not authenticate against node 115."""


def generate(data, out_dir):
    if hashlib.sha256(data).hexdigest() != ARTIFACT_SHA256 or len(data) != ARTIFACT_SIZE:
        raise PacketError('artifact SHA-256 mismatch')
    records = analyze(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (out_dir / 'frames.txt').write_text(_frames(data))
    start, end = CALLEE['range']
    name = f'join_callee_full_body_{start:x}_{end:x}_objdump.txt'
    (out_dir / name).write_text(_body_export(data, start, end))
    return records


def main(argv):
    if len(argv) != 3 or argv[1] != 'generate':
        raise SystemExit('usage: join_callee_static.py generate <out-dir>')
    artifact = ROOT / 'artifacts/node/115/hl-node'
    generate(artifact.read_bytes(), argv[2])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
