"""Static evidence for the producers of the innermost RE-006 records.

Companion extractor for
``research/work-items/RE-006-node115-innermost-records``. PR #2590
traced the producers of the drivers' element-argument inputs one
level up and left four boundaries: the s1 giants' tail-source
regions, the sub-lookups' inner decode records, the 0xf8 helpers'
internal production, and the inputs of the wrappers'/giants' own
callers. This extractor pins, from the authenticated node-115
artifact only:

* the body behind the "decode" calls, ``0x24cb0a0`` — a pure
  0xb8-stride lower_bound with zero stores, returning a flag in
  ``rax`` and an index in ``rdx``; it produces no record at all;
* the binary-wide caller censuses of that body (18 E8 sites), of the
  three join-consumer B wrappers (4/5/5 sites) and of the three s1
  giants (4 sites each including one recursive self-call), with a
  matching zero census for E9 jumps, rip-relative leas inside the
  packet bodies and R_X86_64_RELATIVE addends naming any target;
* the giants' tail regions: zero direct stores into
  ``[rsp+0xd49, rsp+0xe48)`` / ``[rsp+0xd29, rsp+0xe28)`` — the 0xff
  tail source is a parking buffer written only by a park ``memcpy``
  of the element's own tail and read back by the restore ``memcpy``;
* the sub-lookups' record chains: staging records receiving exactly
  nine direct stores each, middle tail buffers at the frame top
  receiving none, and the full ``memcpy`` tables (8 sites in
  ``0x2bb7270``, 4 in ``0x2bb52a0``);
* the 0xf8 helpers' internal production: a ten-``memcpy`` chain plus
  direct tag/byte stores per helper, the two helpers mirroring each
  other with a +0x10 stack-displacement shift, and zero decode calls
  in the ``0x55e16d0`` clone;
* every B-wrapper call site (14) and giant call site (9 external):
  at all 14 wrapper sites ``r8`` is a ``lea`` of a caller-frame
  record, assembled in one of two shapes.

Every address is a virtual address in the artifact; every file
offset is resolved through the section table (``.rodata`` identity,
``.text`` delta ``0x1000``, ``.data.rel.ro`` delta ``0x2000``).
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

from artifacts import ROOT  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from foundation_millis import decode_export as _foundation_decode  # noqa: E402

ARTIFACT_SHA256 = \
    'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARTIFACT_SIZE = 105_896_032
MEMCPY_SLOT = 0x64DF508
DECODE_BODY = 0x24CB0A0
SIBLING_SEARCH = 0x35BF460
NONSENTINEL_FALLBACK = 0x4556410

BODIES = {'bwc_a1': {'exported': False,
            'range': (44584544, 44597918),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': '7bca2f033becd6f8a8f0d184a434cdd74677915f45e0c9ab31aa61970bbaaace'},
 'bwc_a2': {'exported': True,
            'range': (44612672, 44613105),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': 'b45e239ca04d7a57848bc12ba89762bcd836ffc909e7c5996d066673e9ffebe8'},
 'bwc_a3': {'exported': True,
            'range': (46393520, 46394792),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': 'c1c4b3774cd1c2de34c46374fa9f9a4b8344bfc732f96dacaad5f542815008f6'},
 'bwc_b1': {'exported': False,
            'range': (88954800, 88978548),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': '155583f5bcc0b7aff8164fb7aacf8e4792ba836bb17ae19c2d03e9e437d18ba4'},
 'bwc_b2': {'exported': False,
            'range': (89661824, 89674371),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': '0dce413fbb40e408ffca0831ec0ee804509e99cbde0b23f565bbb9b71dd2f19f'},
 'bwc_b3': {'exported': True,
            'range': (89752560, 89753832),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': '6f533c250a2367373730365e336d44997afa8200de1858a7431c9eabf0950d81'},
 'bwc_b4': {'exported': True,
            'range': (90218416, 90218849),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': '5b23a89bba537eed46d967ad3afde6bcbaaa108fe158a0b9f617eae09a7ff77d'},
 'bwc_c1': {'exported': False,
            'range': (88930960, 88954788),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': '824e0d4571ca1e4393eb87acd38dd36b9e9d87e1762905e464cc6942e698b1cf'},
 'bwc_c2': {'exported': False,
            'range': (89674384, 89686931),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': '0c80314b405562e1053ce3a5195ee216628d43b51d5e84e4833c900b19fe051a'},
 'bwc_c3': {'exported': True,
            'range': (89768544, 89769816),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': 'c085bb074f81eea81d0e5e69ae498b13f7c3c4b761936d122b86d4f16471d35c'},
 'bwc_c4': {'exported': True,
            'range': (90217968, 90218401),
            'role': 'caller FDE of a B wrapper (question iv)',
            'sha256': '925c2098402d2dac58c01f90b8adcad3c31c11f9e109226604dca31e63ccc78e'},
 'dc_ca': {'exported': True,
           'range': (47986944, 47988186),
           'role': 'insert-or-assign driver caller_a; decode caller (boundary)',
           'sha256': 'ef31f8404f187a290a687c149ba3d3a05c3427274bc9ccabc2735008eb693720'},
 'dc_o1': {'exported': True,
           'range': (45689424, 45689830),
           'role': 'decode caller in FDE 0x2b92a50 (boundary)',
           'sha256': 'aedebadcafec4da400cf5d4d264dae1b3987f75683f5bb6316f58f4ec3109ad5'},
 'dc_o2': {'exported': True,
           'range': (46537520, 46539495),
           'role': 'decode caller in FDE 0x2c61b30 (boundary)',
           'sha256': 'fb6986607aeb4f699ed29f505bba328b2ea171995bccc10fd3e418dbed54a2b1'},
 'decode': {'exported': True,
            'range': (38580384, 38580692),
            'role': 'the body behind the decode calls: a pure 0xb8-stride lower_bound (question '
                    'ii)',
            'sha256': '3d150ceb58b41495a86136ef7c0f8b007889d82daeae6284c6916d39c8408fce'},
 'gc_a1': {'exported': True,
           'range': (43071312, 43073897),
           'role': 'caller FDE of an s1 giant (question iv)',
           'sha256': '827bd25e4149df28194078ff2dcae48637aaac538ec080d16a6acf36d70d7669'},
 'gc_a2': {'exported': False,
           'range': (46072048, 46079623),
           'role': 'caller FDE of an s1 giant (question iv)',
           'sha256': 'bb26b1f5745c4d2173d8b09dc8f9a4097263111ffbfdb4828420590f5dc1fcde'},
 'gc_b1': {'exported': True,
           'range': (84754240, 84756809),
           'role': 'caller FDE of an s1 giant (question iv)',
           'sha256': '59efc5dcd324ddcca0ecc0135f56cd4acf845285c4522e77fd7398c318a45736'},
 'gc_b2': {'exported': True,
           'range': (88921152, 88922511),
           'role': 'caller FDE of an s1 giant (question iv)',
           'sha256': '076663f0d7d441fd5874a3bd057790bcb94b5ea1d1f2276445be76fedec7d904'},
 'gc_c1': {'exported': True,
           'range': (84751664, 84754233),
           'role': 'caller FDE of an s1 giant (question iv)',
           'sha256': 'adc1c7694c6f463274c4088725b10227daae2be8d896b6df81834e1a36df7ae3'},
 'gc_c2': {'exported': True,
           'range': (88919792, 88921151),
           'role': 'caller FDE of an s1 giant (question iv)',
           'sha256': 'ffdfccdcb301f16db38a1b7ddea7512ce8f2f3e099ac145874c0168eb5000a74'},
 'giant_s1a': {'exported': False,
               'range': (42784672, 42830532),
               'role': 's1 giant caller A (question i)',
               'sha256': '40df69913a9976f4cf044e6f9b686fac43d0f63ba54b984ff79524a3a1794a76'},
 'giant_s1b': {'exported': False,
               'range': (87608624, 87653197),
               'role': 's1 giant caller B (question i)',
               'sha256': 'fe615521c3cebf329ae984293dd270e6aefd1a74dec4f2b7989b12a555ef833d'},
 'giant_s1c': {'exported': False,
               'range': (87653200, 87697773),
               'role': 's1 giant caller C (question i)',
               'sha256': 'a69d025534ce5dca6536f52e51c69a0402842bfce4a0e0b148eb3d429d0282d0'},
 'helper_s3a': {'exported': False,
                'range': (46540832, 46549090),
                'role': '0xf8-record helper 0x2c62820 (question iii)',
                'sha256': '9176b5c3361b91321a3b0cd99c2e90bf4538c1d7b21a68d63f68d5082e33fe96'},
 'helper_s3b': {'exported': False,
                'range': (90052304, 90060642),
                'role': '0xf8-record helper clone 0x55e16d0 (question iii)',
                'sha256': '22651e5a99e6a1279013c659838c4b561df8dd2d2e6ad97b0f8ce31b6b783b30'},
 'inner_ca': {'exported': True,
              'range': (45857696, 45860685),
              'role': 'inner body called by sublookup_ca; decode caller (boundary)',
              'sha256': 'f3e69ec027f6e24352c49415a533d2cc5e75443ce6681b3c6b51331a3446fa35'},
 'inner_s3': {'exported': True,
              'range': (45863088, 45865882),
              'role': 'inner body called by helper_s3a; decode caller (boundary)',
              'sha256': '889874f504716879ed3af8bfab1a9f7909972bfee409b4125910ce5a114c1a6e'},
 'jc1wb': {'exported': True,
           'range': (44602096, 44602611),
           'role': 'join-consumer B wrapper, clone 1 (question iv target)',
           'sha256': '4baf4e6d6cced4771553c5b0d1076588e41b3a4615c18ec2ca1b15e89942878b'},
 'jc2wb': {'exported': True,
           'range': (89785280, 89785795),
           'role': 'join-consumer B wrapper, clone 2 (question iv target)',
           'sha256': 'ed441b6a9a65d6c87b64a934b2cb20cda64baa62a1ecf2460d2cca2d438057d2'},
 'jc3wb': {'exported': True,
           'range': (89785808, 89786323),
           'role': 'join-consumer B wrapper, clone 3 (question iv target)',
           'sha256': 'cd81189e54a7827889842baf9abc422764e4b3d154a99ed85399ac637f47baad'},
 'sublookup_ca': {'exported': False,
                  'range': (45838960, 45848723),
                  'role': 'sub-lookup 0x2bb7270 for helper 0x2762570 (question ii)',
                  'sha256': '6dbf7f8390953d24bdd5b7a225e83f3e1614fb79ee6b3f40d423f8728d44234b'},
 'sublookup_jc1': {'exported': False,
                   'range': (45830816, 45836502),
                   'role': 'sub-lookup clone 0x2bb52a0 for helper 0x27622f0 (question ii)',
                   'sha256': '879e56724ec4d83c7b7ef7699fa08a1f6b3a12ecd72f50972d828c02a5b2fe13'}}

EXPORTED = [name for name, body in BODIES.items() if body['exported']]

PINNED_ROWS_FULL = {'decode': {38580384: ('488b4718', 'mov    0x18(%rdi),%rax'),
            38580388: ('4885c0', 'test   %rax,%rax'),
            38580391: ('0f8497000000', 'je     0x24cb144'),
            38580397: ('488b17', 'mov    (%rdi),%rdx'),
            38580400: ('4c8b4f10', 'mov    0x10(%rdi),%r9'),
            38580404: ('31c9', 'xor    %ecx,%ecx'),
            38580406: ('4939d1', 'cmp    %rdx,%r9'),
            38580409: ('480f43ca', 'cmovae %rdx,%rcx'),
            38580413: ('4929c9', 'sub    %rcx,%r9'),
            38580416: ('4c29ca', 'sub    %r9,%rdx'),
            38580419: ('4989c0', 'mov    %rax,%r8'),
            38580422: ('4929d0', 'sub    %rdx,%r8'),
            38580425: ('0f867c000000', 'jbe    0x24cb14b'),
            38580431: ('488b4f08', 'mov    0x8(%rdi),%rcx'),
            38580435: ('4c8b11', 'mov    (%rcx),%r10'),
            38580438: ('488b3e', 'mov    (%rsi),%rdi'),
            38580441: ('4939fa', 'cmp    %rdi,%r10'),
            38580444: ('0f97c0', 'seta   %al'),
            38580447: ('1c00', 'sbb    $0x0,%al'),
            38580449: ('0fb6c0', 'movzbl %al,%eax'),
            38580452: ('84c0', 'test   %al,%al'),
            38580454: ('0f84d0000000', 'je     0x24cb1bc'),
            38580460: ('3dff000000', 'cmp    $0xff,%eax'),
            38580465: ('0f85c6000000', 'jne    0x24cb1bd'),
            38580471: ('31f6', 'xor    %esi,%esi'),
            38580473: ('4983f801', 'cmp    $0x1,%r8'),
            38580477: ('7430', 'je     0x24cb12f'),
            38580479: ('90', 'nop'),
            38580480: ('4889f0', 'mov    %rsi,%rax'),
            38580483: ('4d89c1', 'mov    %r8,%r9'),
            38580486: ('49d1e9', 'shr    $1,%r9'),
            38580489: ('4c01ce', 'add    %r9,%rsi'),
            38580492: ('4c69d6b8000000', 'imul   $0xb8,%rsi,%r10'),
            38580499: ('4a393c11', 'cmp    %rdi,(%rcx,%r10,1)'),
            38580503: ('480f47f0', 'cmova  %rax,%rsi'),
            38580507: ('4d29c8', 'sub    %r9,%r8'),
            38580510: ('4983f801', 'cmp    $0x1,%r8'),
            38580514: ('77dc', 'ja     0x24cb100'),
            38580516: ('4869c6b8000000', 'imul   $0xb8,%rsi,%rax'),
            38580523: ('4c8b1401', 'mov    (%rcx,%rax,1),%r10'),
            38580527: ('4939fa', 'cmp    %rdi,%r10'),
            38580530: ('7404', 'je     0x24cb138'),
            38580532: ('4883d600', 'adc    $0x0,%rsi'),
            38580536: ('31c0', 'xor    %eax,%eax'),
            38580538: ('4939fa', 'cmp    %rdi,%r10'),
            38580541: ('0f95c0', 'setne  %al'),
            38580544: ('4801f2', 'add    %rsi,%rdx'),
            38580547: ('c3', 'ret'),
            38580548: ('31d2', 'xor    %edx,%edx'),
            38580550: ('4531c9', 'xor    %r9d,%r9d'),
            38580553: ('eb06', 'jmp    0x24cb151'),
            38580555: ('4c01c8', 'add    %r9,%rax'),
            38580558: ('4889c2', 'mov    %rax,%rdx'),
            38580561: ('4969c9b8000000', 'imul   $0xb8,%r9,%rcx'),
            38580568: ('48034f08', 'add    0x8(%rdi),%rcx'),
            38580572: ('4c29ca', 'sub    %r9,%rdx'),
            38580575: ('b801000000', 'mov    $0x1,%eax'),
            38580580: ('4885d2', 'test   %rdx,%rdx'),
            38580583: ('7468', 'je     0x24cb1d1'),
            38580585: ('488b36', 'mov    (%rsi),%rsi'),
            38580588: ('31ff', 'xor    %edi,%edi'),
            38580590: ('4883fa01', 'cmp    $0x1,%rdx'),
            38580594: ('7430', 'je     0x24cb1a4'),
            38580596: ('6666662e0f1f840000000000', 'data16 data16 cs nopw 0x0(%rax,%rax,1)'),
            38580608: ('4989f8', 'mov    %rdi,%r8'),
            38580611: ('4989d1', 'mov    %rdx,%r9'),
            38580614: ('49d1e9', 'shr    $1,%r9'),
            38580617: ('4c01cf', 'add    %r9,%rdi'),
            38580620: ('4c69d7b8000000', 'imul   $0xb8,%rdi,%r10'),
            38580627: ('4a393411', 'cmp    %rsi,(%rcx,%r10,1)'),
            38580631: ('490f47f8', 'cmova  %r8,%rdi'),
            38580635: ('4c29ca', 'sub    %r9,%rdx'),
            38580638: ('4883fa01', 'cmp    $0x1,%rdx'),
            38580642: ('77dc', 'ja     0x24cb180'),
            38580644: ('4869d7b8000000', 'imul   $0xb8,%rdi,%rdx'),
            38580651: ('48393411', 'cmp    %rsi,(%rcx,%rdx,1)'),
            38580655: ('7504', 'jne    0x24cb1b5'),
            38580657: ('31c0', 'xor    %eax,%eax'),
            38580659: ('eb04', 'jmp    0x24cb1b9'),
            38580661: ('4883d700', 'adc    $0x0,%rdi'),
            38580665: ('4889fa', 'mov    %rdi,%rdx'),
            38580668: ('c3', 'ret'),
            38580669: ('4969c1b8000000', 'imul   $0xb8,%r9,%rax'),
            38580676: ('4801c1', 'add    %rax,%rcx'),
            38580679: ('b801000000', 'mov    $0x1,%eax'),
            38580684: ('4885d2', 'test   %rdx,%rdx'),
            38580687: ('7598', 'jne    0x24cb169'),
            38580689: ('31d2', 'xor    %edx,%edx'),
            38580691: ('c3', 'ret')},
 'jc1wb': {44602096: ('55', 'push   %rbp'),
           44602097: ('4157', 'push   %r15'),
           44602099: ('4156', 'push   %r14'),
           44602101: ('53', 'push   %rbx'),
           44602102: ('4881ece8010000', 'sub    $0x1e8,%rsp'),
           44602109: ('4889f3', 'mov    %rsi,%rbx'),
           44602112: ('4989fe', 'mov    %rdi,%r14'),
           44602115: ('4889542410', 'mov    %rdx,0x10(%rsp)'),
           44602120: ('884c240e', 'mov    %cl,0xe(%rsp)'),
           44602124: ('44884c240f', 'mov    %r9b,0xf(%rsp)'),
           44602129: ('4889b424c8010000', 'mov    %rsi,0x1c8(%rsp)'),
           44602137: ('488d442410', 'lea    0x10(%rsp),%rax'),
           44602142: ('48898424d0010000', 'mov    %rax,0x1d0(%rsp)'),
           44602150: ('488d44240e', 'lea    0xe(%rsp),%rax'),
           44602155: ('48898424d8010000', 'mov    %rax,0x1d8(%rsp)'),
           44602163: ('488dbc24b0000000', 'lea    0xb0(%rsp),%rdi'),
           44602171: ('ba18010000', 'mov    $0x118,%edx'),
           44602176: ('4c89c6', 'mov    %r8,%rsi'),
           44602179: ('ff15bf61a503', 'call   *0x3a561bf(%rip)'),
           44602185: ('488d44240f', 'lea    0xf(%rsp),%rax'),
           44602190: ('48898424e0010000', 'mov    %rax,0x1e0(%rsp)'),
           44602198: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
           44602203: ('4c89f6', 'mov    %r14,%rsi'),
           44602206: ('4889da', 'mov    %rbx,%rdx'),
           44602209: ('e8fa0f0000', 'call   0x2a8a360'),
           44602214: ('48ba0000000000000080', 'movabs $0x8000000000000000,%rdx'),
           44602224: ('488b4c2418', 'mov    0x18(%rsp),%rcx'),
           44602229: ('488d7201', 'lea    0x1(%rdx),%rsi'),
           44602233: ('0fb6442420', 'movzbl 0x20(%rsp),%eax'),
           44602238: ('4839f1', 'cmp    %rsi,%rcx'),
           44602241: ('7564', 'jne    0x2a893e7'),
           44602243: ('488b8c2460010000', 'mov    0x160(%rsp),%rcx'),
           44602251: ('4839d1', 'cmp    %rdx,%rcx'),
           44602254: ('0f85ba000000', 'jne    0x2a8944e'),
           44602260: ('488b8c2468010000', 'mov    0x168(%rsp),%rcx'),
           44602268: ('89c5', 'mov    %eax,%ebp'),
           44602270: ('4885c9', 'test   %rcx,%rcx'),
           44602273: ('0f84ca000000', 'je     0x2a89471'),
           44602279: ('488b942470010000', 'mov    0x170(%rsp),%rdx'),
           44602287: ('488b842478010000', 'mov    0x178(%rsp),%rax'),
           44602295: ('48c744242000000000', 'movq   $0x0,0x20(%rsp)'),
           44602304: ('48894c2428', 'mov    %rcx,0x28(%rsp)'),
           44602309: ('4889542430', 'mov    %rdx,0x30(%rsp)'),
           44602314: ('48c744244000000000', 'movq   $0x0,0x40(%rsp)'),
           44602323: ('48894c2448', 'mov    %rcx,0x48(%rsp)'),
           44602328: ('4889542450', 'mov    %rdx,0x50(%rsp)'),
           44602333: ('b901000000', 'mov    $0x1,%ecx'),
           44602338: ('e98e000000', 'jmp    0x2a89475'),
           44602343: ('0f10442421', 'movups 0x21(%rsp),%xmm0'),
           44602348: ('0f104c2431', 'movups 0x31(%rsp),%xmm1'),
           44602353: ('0f10542440', 'movups 0x40(%rsp),%xmm2'),
           44602358: ('0f11942488000000', 'movups %xmm2,0x88(%rsp)'),
           44602366: ('0f114c2479', 'movups %xmm1,0x79(%rsp)'),
           44602371: ('0f11442469', 'movups %xmm0,0x69(%rsp)'),
           44602376: ('4c8b7c2450', 'mov    0x50(%rsp),%r15'),
           44602381: ('48894c2460', 'mov    %rcx,0x60(%rsp)'),
           44602386: ('88442468', 'mov    %al,0x68(%rsp)'),
           44602390: ('488b542410', 'mov    0x10(%rsp),%rdx'),
           44602395: ('440fb64c240f', 'movzbl 0xf(%rsp),%r9d'),
           44602401: ('0fb64c240e', 'movzbl 0xe(%rsp),%ecx'),
           44602406: ('4c8d8424b0000000', 'lea    0xb0(%rsp),%r8'),
           44602414: ('4c89f7', 'mov    %r14,%rdi'),
           44602417: ('4889de', 'mov    %rbx,%rsi'),
           44602420: ('e8c7000000', 'call   0x2a89500'),
           44602425: ('488d542460', 'lea    0x60(%rsp),%rdx'),
           44602430: ('4c89f7', 'mov    %r14,%rdi'),
           44602433: ('4889de', 'mov    %rbx,%rsi'),
           44602436: ('4c89f9', 'mov    %r15,%rcx'),
           44602439: ('e8b40b0000', 'call   0x2a8a000'),
           44602444: ('eb6a', 'jmp    0x2a894b8'),
           44602446: ('4885c9', 'test   %rcx,%rcx'),
           44602449: ('7465', 'je     0x2a894b8'),
           44602451: ('488bbc2468010000', 'mov    0x168(%rsp),%rdi'),
           44602459: ('48c1e103', 'shl    $0x3,%rcx'),
           44602463: ('488d3489', 'lea    (%rcx,%rcx,4),%rsi'),
           44602467: ('31d2', 'xor    %edx,%edx'),
           44602469: ('89c3', 'mov    %eax,%ebx'),
           44602471: ('ff153360a503', 'call   *0x3a56033(%rip)'),
           44602477: ('89d8', 'mov    %ebx,%eax'),
           44602479: ('eb47', 'jmp    0x2a894b8'),
           44602481: ('31c9', 'xor    %ecx,%ecx'),
           44602483: ('31c0', 'xor    %eax,%eax'),
           44602485: ('48894c2418', 'mov    %rcx,0x18(%rsp)'),
           44602490: ('48894c2438', 'mov    %rcx,0x38(%rsp)'),
           44602495: ('4889442458', 'mov    %rax,0x58(%rsp)'),
           44602500: ('488d9c2498000000', 'lea    0x98(%rsp),%rbx'),
           44602508: ('4c8d742418', 'lea    0x18(%rsp),%r14'),
           44602513: ('6666666666662e0f1f840000000000',
                      'data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'),
           44602528: ('4889df', 'mov    %rbx,%rdi'),
           44602531: ('4c89f6', 'mov    %r14,%rsi'),
           44602534: ('e8f5ba9bff', 'call   0x2444fa0'),
           44602539: ('4883bc249800000000', 'cmpq   $0x0,0x98(%rsp)'),
           44602548: ('75ea', 'jne    0x2a894a0'),
           44602550: ('89e8', 'mov    %ebp,%eax'),
           44602552: ('4881c4e8010000', 'add    $0x1e8,%rsp'),
           44602559: ('5b', 'pop    %rbx'),
           44602560: ('415e', 'pop    %r14'),
           44602562: ('415f', 'pop    %r15'),
           44602564: ('5d', 'pop    %rbp'),
           44602565: ('c3', 'ret'),
           44602566: ('4889c3', 'mov    %rax,%rbx'),
           44602569: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
           44602574: ('e80dca0200', 'call   0x2ab5ee0'),
           44602579: ('eb10', 'jmp    0x2a894e5'),
           44602581: ('4889c3', 'mov    %rax,%rbx'),
           44602584: ('488dbc24b0000000', 'lea    0xb0(%rsp),%rdi'),
           44602592: ('e80bc20100', 'call   0x2aa56f0'),
           44602597: ('4889df', 'mov    %rbx,%rdi'),
           44602600: ('e863759603', 'call   0x63f0a50'),
           44602605: ('ff15cd5fa503', 'call   *0x3a55fcd(%rip)')},
 'jc2wb': {89785280: ('55', 'push   %rbp'),
           89785281: ('4157', 'push   %r15'),
           89785283: ('4156', 'push   %r14'),
           89785285: ('53', 'push   %rbx'),
           89785286: ('4881ece8010000', 'sub    $0x1e8,%rsp'),
           89785293: ('4889f3', 'mov    %rsi,%rbx'),
           89785296: ('4989fe', 'mov    %rdi,%r14'),
           89785299: ('4889542410', 'mov    %rdx,0x10(%rsp)'),
           89785304: ('884c240e', 'mov    %cl,0xe(%rsp)'),
           89785308: ('44884c240f', 'mov    %r9b,0xf(%rsp)'),
           89785313: ('4889b424c8010000', 'mov    %rsi,0x1c8(%rsp)'),
           89785321: ('488d442410', 'lea    0x10(%rsp),%rax'),
           89785326: ('48898424d0010000', 'mov    %rax,0x1d0(%rsp)'),
           89785334: ('488d44240e', 'lea    0xe(%rsp),%rax'),
           89785339: ('48898424d8010000', 'mov    %rax,0x1d8(%rsp)'),
           89785347: ('488dbc24b0000000', 'lea    0xb0(%rsp),%rdi'),
           89785355: ('ba18010000', 'mov    $0x118,%edx'),
           89785360: ('4c89c6', 'mov    %r8,%rsi'),
           89785363: ('ff15eff0f300', 'call   *0xf3f0ef(%rip)'),
           89785369: ('488d44240f', 'lea    0xf(%rsp),%rax'),
           89785374: ('48898424e0010000', 'mov    %rax,0x1e0(%rsp)'),
           89785382: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
           89785387: ('4c89f6', 'mov    %r14,%rsi'),
           89785390: ('4889da', 'mov    %rbx,%rdx'),
           89785393: ('e81a210000', 'call   0x55a2550'),
           89785398: ('48ba0000000000000080', 'movabs $0x8000000000000000,%rdx'),
           89785408: ('488b4c2418', 'mov    0x18(%rsp),%rcx'),
           89785413: ('488d7201', 'lea    0x1(%rdx),%rsi'),
           89785417: ('0fb6442420', 'movzbl 0x20(%rsp),%eax'),
           89785422: ('4839f1', 'cmp    %rsi,%rcx'),
           89785425: ('7564', 'jne    0x55a04b7'),
           89785427: ('488b8c2460010000', 'mov    0x160(%rsp),%rcx'),
           89785435: ('4839d1', 'cmp    %rdx,%rcx'),
           89785438: ('0f85ba000000', 'jne    0x55a051e'),
           89785444: ('488b8c2468010000', 'mov    0x168(%rsp),%rcx'),
           89785452: ('89c5', 'mov    %eax,%ebp'),
           89785454: ('4885c9', 'test   %rcx,%rcx'),
           89785457: ('0f84ca000000', 'je     0x55a0541'),
           89785463: ('488b942470010000', 'mov    0x170(%rsp),%rdx'),
           89785471: ('488b842478010000', 'mov    0x178(%rsp),%rax'),
           89785479: ('48c744242000000000', 'movq   $0x0,0x20(%rsp)'),
           89785488: ('48894c2428', 'mov    %rcx,0x28(%rsp)'),
           89785493: ('4889542430', 'mov    %rdx,0x30(%rsp)'),
           89785498: ('48c744244000000000', 'movq   $0x0,0x40(%rsp)'),
           89785507: ('48894c2448', 'mov    %rcx,0x48(%rsp)'),
           89785512: ('4889542450', 'mov    %rdx,0x50(%rsp)'),
           89785517: ('b901000000', 'mov    $0x1,%ecx'),
           89785522: ('e98e000000', 'jmp    0x55a0545'),
           89785527: ('0f10442421', 'movups 0x21(%rsp),%xmm0'),
           89785532: ('0f104c2431', 'movups 0x31(%rsp),%xmm1'),
           89785537: ('0f10542440', 'movups 0x40(%rsp),%xmm2'),
           89785542: ('0f11942488000000', 'movups %xmm2,0x88(%rsp)'),
           89785550: ('0f114c2479', 'movups %xmm1,0x79(%rsp)'),
           89785555: ('0f11442469', 'movups %xmm0,0x69(%rsp)'),
           89785560: ('4c8b7c2450', 'mov    0x50(%rsp),%r15'),
           89785565: ('48894c2460', 'mov    %rcx,0x60(%rsp)'),
           89785570: ('88442468', 'mov    %al,0x68(%rsp)'),
           89785574: ('488b542410', 'mov    0x10(%rsp),%rdx'),
           89785579: ('440fb64c240f', 'movzbl 0xf(%rsp),%r9d'),
           89785585: ('0fb64c240e', 'movzbl 0xe(%rsp),%ecx'),
           89785590: ('4c8d8424b0000000', 'lea    0xb0(%rsp),%r8'),
           89785598: ('4c89f7', 'mov    %r14,%rdi'),
           89785601: ('4889de', 'mov    %rbx,%rsi'),
           89785604: ('e8d7020000', 'call   0x55a07e0'),
           89785609: ('488d542460', 'lea    0x60(%rsp),%rdx'),
           89785614: ('4c89f7', 'mov    %r14,%rdi'),
           89785617: ('4889de', 'mov    %rbx,%rsi'),
           89785620: ('4c89f9', 'mov    %r15,%rcx'),
           89785623: ('e8341b0000', 'call   0x55a2050'),
           89785628: ('eb6a', 'jmp    0x55a0588'),
           89785630: ('4885c9', 'test   %rcx,%rcx'),
           89785633: ('7465', 'je     0x55a0588'),
           89785635: ('488bbc2468010000', 'mov    0x168(%rsp),%rdi'),
           89785643: ('48c1e103', 'shl    $0x3,%rcx'),
           89785647: ('488d3489', 'lea    (%rcx,%rcx,4),%rsi'),
           89785651: ('31d2', 'xor    %edx,%edx'),
           89785653: ('89c3', 'mov    %eax,%ebx'),
           89785655: ('ff1563eff300', 'call   *0xf3ef63(%rip)'),
           89785661: ('89d8', 'mov    %ebx,%eax'),
           89785663: ('eb47', 'jmp    0x55a0588'),
           89785665: ('31c9', 'xor    %ecx,%ecx'),
           89785667: ('31c0', 'xor    %eax,%eax'),
           89785669: ('48894c2418', 'mov    %rcx,0x18(%rsp)'),
           89785674: ('48894c2438', 'mov    %rcx,0x38(%rsp)'),
           89785679: ('4889442458', 'mov    %rax,0x58(%rsp)'),
           89785684: ('488d9c2498000000', 'lea    0x98(%rsp),%rbx'),
           89785692: ('4c8d742418', 'lea    0x18(%rsp),%r14'),
           89785697: ('6666666666662e0f1f840000000000',
                      'data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'),
           89785712: ('4889df', 'mov    %rbx,%rdi'),
           89785715: ('4c89f6', 'mov    %r14,%rsi'),
           89785718: ('e85501c4ff', 'call   0x51e06d0'),
           89785723: ('4883bc249800000000', 'cmpq   $0x0,0x98(%rsp)'),
           89785732: ('75ea', 'jne    0x55a0570'),
           89785734: ('89e8', 'mov    %ebp,%eax'),
           89785736: ('4881c4e8010000', 'add    $0x1e8,%rsp'),
           89785743: ('5b', 'pop    %rbx'),
           89785744: ('415e', 'pop    %r14'),
           89785746: ('415f', 'pop    %r15'),
           89785748: ('5d', 'pop    %rbp'),
           89785749: ('c3', 'ret'),
           89785750: ('4889c3', 'mov    %rax,%rbx'),
           89785753: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
           89785758: ('e80d680900', 'call   0x5636db0'),
           89785763: ('eb10', 'jmp    0x55a05b5'),
           89785765: ('4889c3', 'mov    %rax,%rbx'),
           89785768: ('488dbc24b0000000', 'lea    0xb0(%rsp),%rdi'),
           89785776: ('e80ba10800', 'call   0x562a6c0'),
           89785781: ('4889df', 'mov    %rbx,%rdi'),
           89785784: ('e89304e500', 'call   0x63f0a50'),
           89785789: ('ff15fdeef300', 'call   *0xf3eefd(%rip)')},
 'jc3wb': {89785808: ('55', 'push   %rbp'),
           89785809: ('4157', 'push   %r15'),
           89785811: ('4156', 'push   %r14'),
           89785813: ('53', 'push   %rbx'),
           89785814: ('4881ece8010000', 'sub    $0x1e8,%rsp'),
           89785821: ('4889f3', 'mov    %rsi,%rbx'),
           89785824: ('4989fe', 'mov    %rdi,%r14'),
           89785827: ('4889542410', 'mov    %rdx,0x10(%rsp)'),
           89785832: ('884c240e', 'mov    %cl,0xe(%rsp)'),
           89785836: ('44884c240f', 'mov    %r9b,0xf(%rsp)'),
           89785841: ('4889b424c8010000', 'mov    %rsi,0x1c8(%rsp)'),
           89785849: ('488d442410', 'lea    0x10(%rsp),%rax'),
           89785854: ('48898424d0010000', 'mov    %rax,0x1d0(%rsp)'),
           89785862: ('488d44240e', 'lea    0xe(%rsp),%rax'),
           89785867: ('48898424d8010000', 'mov    %rax,0x1d8(%rsp)'),
           89785875: ('488dbc24b0000000', 'lea    0xb0(%rsp),%rdi'),
           89785883: ('ba18010000', 'mov    $0x118,%edx'),
           89785888: ('4c89c6', 'mov    %r8,%rsi'),
           89785891: ('ff15dfeef300', 'call   *0xf3eedf(%rip)'),
           89785897: ('488d44240f', 'lea    0xf(%rsp),%rax'),
           89785902: ('48898424e0010000', 'mov    %rax,0x1e0(%rsp)'),
           89785910: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
           89785915: ('4c89f6', 'mov    %r14,%rsi'),
           89785918: ('4889da', 'mov    %rbx,%rdx'),
           89785921: ('e87a1c0000', 'call   0x55a22c0'),
           89785926: ('48ba0000000000000080', 'movabs $0x8000000000000000,%rdx'),
           89785936: ('488b4c2418', 'mov    0x18(%rsp),%rcx'),
           89785941: ('488d7201', 'lea    0x1(%rdx),%rsi'),
           89785945: ('0fb6442420', 'movzbl 0x20(%rsp),%eax'),
           89785950: ('4839f1', 'cmp    %rsi,%rcx'),
           89785953: ('7564', 'jne    0x55a06c7'),
           89785955: ('488b8c2460010000', 'mov    0x160(%rsp),%rcx'),
           89785963: ('4839d1', 'cmp    %rdx,%rcx'),
           89785966: ('0f85ba000000', 'jne    0x55a072e'),
           89785972: ('488b8c2468010000', 'mov    0x168(%rsp),%rcx'),
           89785980: ('89c5', 'mov    %eax,%ebp'),
           89785982: ('4885c9', 'test   %rcx,%rcx'),
           89785985: ('0f84ca000000', 'je     0x55a0751'),
           89785991: ('488b942470010000', 'mov    0x170(%rsp),%rdx'),
           89785999: ('488b842478010000', 'mov    0x178(%rsp),%rax'),
           89786007: ('48c744242000000000', 'movq   $0x0,0x20(%rsp)'),
           89786016: ('48894c2428', 'mov    %rcx,0x28(%rsp)'),
           89786021: ('4889542430', 'mov    %rdx,0x30(%rsp)'),
           89786026: ('48c744244000000000', 'movq   $0x0,0x40(%rsp)'),
           89786035: ('48894c2448', 'mov    %rcx,0x48(%rsp)'),
           89786040: ('4889542450', 'mov    %rdx,0x50(%rsp)'),
           89786045: ('b901000000', 'mov    $0x1,%ecx'),
           89786050: ('e98e000000', 'jmp    0x55a0755'),
           89786055: ('0f10442421', 'movups 0x21(%rsp),%xmm0'),
           89786060: ('0f104c2431', 'movups 0x31(%rsp),%xmm1'),
           89786065: ('0f10542440', 'movups 0x40(%rsp),%xmm2'),
           89786070: ('0f11942488000000', 'movups %xmm2,0x88(%rsp)'),
           89786078: ('0f114c2479', 'movups %xmm1,0x79(%rsp)'),
           89786083: ('0f11442469', 'movups %xmm0,0x69(%rsp)'),
           89786088: ('4c8b7c2450', 'mov    0x50(%rsp),%r15'),
           89786093: ('48894c2460', 'mov    %rcx,0x60(%rsp)'),
           89786098: ('88442468', 'mov    %al,0x68(%rsp)'),
           89786102: ('488b542410', 'mov    0x10(%rsp),%rdx'),
           89786107: ('440fb64c240f', 'movzbl 0xf(%rsp),%r9d'),
           89786113: ('0fb64c240e', 'movzbl 0xe(%rsp),%ecx'),
           89786118: ('4c8d8424b0000000', 'lea    0xb0(%rsp),%r8'),
           89786126: ('4c89f7', 'mov    %r14,%rdi'),
           89786129: ('4889de', 'mov    %rbx,%rsi'),
           89786132: ('e8c70b0000', 'call   0x55a12e0'),
           89786137: ('488d542460', 'lea    0x60(%rsp),%rdx'),
           89786142: ('4c89f7', 'mov    %r14,%rdi'),
           89786145: ('4889de', 'mov    %rbx,%rsi'),
           89786148: ('4c89f9', 'mov    %r15,%rcx'),
           89786151: ('e8b4160000', 'call   0x55a1de0'),
           89786156: ('eb6a', 'jmp    0x55a0798'),
           89786158: ('4885c9', 'test   %rcx,%rcx'),
           89786161: ('7465', 'je     0x55a0798'),
           89786163: ('488bbc2468010000', 'mov    0x168(%rsp),%rdi'),
           89786171: ('48c1e103', 'shl    $0x3,%rcx'),
           89786175: ('488d3489', 'lea    (%rcx,%rcx,4),%rsi'),
           89786179: ('31d2', 'xor    %edx,%edx'),
           89786181: ('89c3', 'mov    %eax,%ebx'),
           89786183: ('ff1553edf300', 'call   *0xf3ed53(%rip)'),
           89786189: ('89d8', 'mov    %ebx,%eax'),
           89786191: ('eb47', 'jmp    0x55a0798'),
           89786193: ('31c9', 'xor    %ecx,%ecx'),
           89786195: ('31c0', 'xor    %eax,%eax'),
           89786197: ('48894c2418', 'mov    %rcx,0x18(%rsp)'),
           89786202: ('48894c2438', 'mov    %rcx,0x38(%rsp)'),
           89786207: ('4889442458', 'mov    %rax,0x58(%rsp)'),
           89786212: ('488d9c2498000000', 'lea    0x98(%rsp),%rbx'),
           89786220: ('4c8d742418', 'lea    0x18(%rsp),%r14'),
           89786225: ('6666666666662e0f1f840000000000',
                      'data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'),
           89786240: ('4889df', 'mov    %rbx,%rdi'),
           89786243: ('4c89f6', 'mov    %r14,%rsi'),
           89786246: ('e845ffc3ff', 'call   0x51e06d0'),
           89786251: ('4883bc249800000000', 'cmpq   $0x0,0x98(%rsp)'),
           89786260: ('75ea', 'jne    0x55a0780'),
           89786262: ('89e8', 'mov    %ebp,%eax'),
           89786264: ('4881c4e8010000', 'add    $0x1e8,%rsp'),
           89786271: ('5b', 'pop    %rbx'),
           89786272: ('415e', 'pop    %r14'),
           89786274: ('415f', 'pop    %r15'),
           89786276: ('5d', 'pop    %rbp'),
           89786277: ('c3', 'ret'),
           89786278: ('4889c3', 'mov    %rax,%rbx'),
           89786281: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
           89786286: ('e8fd650900', 'call   0x5636db0'),
           89786291: ('eb10', 'jmp    0x55a07c5'),
           89786293: ('4889c3', 'mov    %rax,%rbx'),
           89786296: ('488dbc24b0000000', 'lea    0xb0(%rsp),%rdi'),
           89786304: ('e8fb9e0800', 'call   0x562a6c0'),
           89786309: ('4889df', 'mov    %rbx,%rdi'),
           89786312: ('e88302e500', 'call   0x63f0a50'),
           89786317: ('ff15edecf300', 'call   *0xf3eced(%rip)')}}

PINNED_ROWS_PARTIAL = {'bwc_a1': {44590615: ('488bb424b8020000', 'mov    0x2b8(%rsp),%rsi'),
            44590623: ('488d9424f8020000', 'lea    0x2f8(%rsp),%rdx'),
            44590691: ('488dbc24d0000000', 'lea    0xd0(%rsp),%rdi'),
            44590699: ('e8e0810200', 'call   0x2aae850'),
            44590714: ('488dbc24e0050000', 'lea    0x5e0(%rsp),%rdi'),
            44590722: ('488db42469030000', 'lea    0x369(%rsp),%rsi'),
            44590737: ('41ffd7', 'call   *%r15'),
            44590751: ('4c89b424d0000000', 'mov    %r14,0xd0(%rsp)'),
            44590759: ('889c24d8000000', 'mov    %bl,0xd8(%rsp)'),
            44590771: ('488dbc24d9000000', 'lea    0xd9(%rsp),%rdi'),
            44590779: ('488db424e0050000', 'lea    0x5e0(%rsp),%rsi'),
            44590787: ('41ffd7', 'call   *%r15'),
            44590846: ('4c8d8424d0000000', 'lea    0xd0(%rsp),%r8'),
            44590857: ('e8e22b0000', 'call   0x2a892f0'),
            44592015: ('488dbc2460030000', 'lea    0x360(%rsp),%rdi'),
            44592023: ('488bb424b8020000', 'mov    0x2b8(%rsp),%rsi'),
            44592031: ('488d9424f8020000', 'lea    0x2f8(%rsp),%rdx'),
            44592039: ('e834b4cdff', 'call   0x2761fe0'),
            44592075: ('488dbc24e0050000', 'lea    0x5e0(%rsp),%rdi'),
            44592083: ('488db42469030000', 'lea    0x369(%rsp),%rsi'),
            44592098: ('41ffd7', 'call   *%r15'),
            44592112: ('4c89b424d0000000', 'mov    %r14,0xd0(%rsp)'),
            44592120: ('889c24d8000000', 'mov    %bl,0xd8(%rsp)'),
            44592132: ('488dbc24d9000000', 'lea    0xd9(%rsp),%rdi'),
            44592140: ('488db424e0050000', 'lea    0x5e0(%rsp),%rsi'),
            44592148: ('41ffd7', 'call   *%r15'),
            44592207: ('4c8d8424d0000000', 'lea    0xd0(%rsp),%r8'),
            44592218: ('e891260000', 'call   0x2a892f0')},
 'bwc_a2': {44612867: ('488d7c2470', 'lea    0x70(%rsp),%rdi'),
            44612872: ('488d542408', 'lea    0x8(%rsp),%rdx'),
            44612877: ('498db670060000', 'lea    0x670(%r14),%rsi'),
            44612884: ('e8c762cdff', 'call   0x2761fe0'),
            44612920: ('488d742479', 'lea    0x79(%rsp),%rsi'),
            44612925: ('488dbc24a9020000', 'lea    0x2a9(%rsp),%rdi'),
            44612938: ('ff15b837a503', 'call   *0x3a537b8(%rip)'),
            44612960: ('4c89ac2490010000', 'mov    %r13,0x190(%rsp)'),
            44612968: ('4488a42498010000', 'mov    %r12b,0x198(%rsp)'),
            44612976: ('488dbc2499010000', 'lea    0x199(%rsp),%rdi'),
            44612984: ('488db424a9020000', 'lea    0x2a9(%rsp),%rsi'),
            44612997: ('ff157d37a503', 'call   *0x3a5377d(%rip)'),
            44613044: ('4c8d842490010000', 'lea    0x190(%rsp),%r8'),
            44613058: ('e829d5ffff', 'call   0x2a892f0')},
 'bwc_a3': {46394235: ('488dbc24d0010000', 'lea    0x1d0(%rsp),%rdi'),
            46394243: ('488d9424d0000000', 'lea    0xd0(%rsp),%rdx'),
            46394251: ('4c89fe', 'mov    %r15,%rsi'),
            46394254: ('e83d31b2ff', 'call   0x2761cd0'),
            46394301: ('488db424d9010000', 'lea    0x1d9(%rsp),%rsi'),
            46394309: ('488dbc24d0000000', 'lea    0xd0(%rsp),%rdi'),
            46394322: ('ff1530098a03', 'call   *0x38a0930(%rip)'),
            46394370: ('488dbc24d9010000', 'lea    0x1d9(%rsp),%rdi'),
            46394378: ('488db424d0000000', 'lea    0xd0(%rsp),%rsi'),
            46394391: ('ff15eb088a03', 'call   *0x38a08eb(%rip)'),
            46394397: ('4c89bc24d0010000', 'mov    %r15,0x1d0(%rsp)'),
            46394405: ('4488b424d8010000', 'mov    %r14b,0x1d8(%rsp)'),
            46394462: ('4c8d8424d0010000', 'lea    0x1d0(%rsp),%r8'),
            46394481: ('e87aa6e4ff', 'call   0x2a892f0')},
 'bwc_b1': {88963141: ('488dbc24a0000000', 'lea    0xa0(%rsp),%rdi'),
            88963164: ('488dbc2470050000', 'lea    0x570(%rsp),%rdi'),
            88963172: ('488db42439070000', 'lea    0x739(%rsp),%rsi'),
            88963180: ('41ffd4', 'call   *%r12'),
            88963757: ('488dbc24a0000000', 'lea    0xa0(%rsp),%rdi'),
            88963765: ('e846851500', 'call   0x5630000'),
            88963877: ('4c89bc24a0000000', 'mov    %r15,0xa0(%rsp)'),
            88963885: ('4088ac24a8000000', 'mov    %bpl,0xa8(%rsp)'),
            88963898: ('488dbc24a9000000', 'lea    0xa9(%rsp),%rdi'),
            88963906: ('488db42470050000', 'lea    0x570(%rsp),%rsi'),
            88963914: ('41ffd4', 'call   *%r12'),
            88963983: ('4c8d8424a0000000', 'lea    0xa0(%rsp),%r8'),
            88963994: ('e821880c00', 'call   0x55a03c0')},
 'bwc_b2': {89667319: ('488bb424b0020000', 'mov    0x2b0(%rsp),%rsi'),
            89667327: ('488d9424f8030000', 'lea    0x3f8(%rsp),%rdx'),
            89667395: ('488dbc24b0000000', 'lea    0xb0(%rsp),%rdi'),
            89667403: ('e8b0c80a00', 'call   0x5630000'),
            89667426: ('4c89ff', 'mov    %r15,%rdi'),
            89667429: ('488db424e9020000', 'lea    0x2e9(%rsp),%rsi'),
            89667444: ('ffd5', 'call   *%rbp'),
            89667457: ('4c89b424b0000000', 'mov    %r14,0xb0(%rsp)'),
            89667465: ('889c24b8000000', 'mov    %bl,0xb8(%rsp)'),
            89667477: ('488dbc24b9000000', 'lea    0xb9(%rsp),%rdi'),
            89667485: ('4c89fe', 'mov    %r15,%rsi'),
            89667488: ('ffd5', 'call   *%rbp'),
            89667546: ('4c8d8424b0000000', 'lea    0xb0(%rsp),%r8'),
            89667557: ('e8d6cb0100', 'call   0x55a03c0'),
            89668719: ('488dbc24e0020000', 'lea    0x2e0(%rsp),%rdi'),
            89668727: ('488bb424b0020000', 'mov    0x2b0(%rsp),%rsi'),
            89668735: ('488d9424f8030000', 'lea    0x3f8(%rsp),%rdx'),
            89668743: ('e8b4e7f0ff', 'call   0x5492440'),
            89668787: ('4c89ff', 'mov    %r15,%rdi'),
            89668790: ('488db424e9020000', 'lea    0x2e9(%rsp),%rsi'),
            89668805: ('ffd5', 'call   *%rbp'),
            89668818: ('4c89b424b0000000', 'mov    %r14,0xb0(%rsp)'),
            89668826: ('889c24b8000000', 'mov    %bl,0xb8(%rsp)'),
            89668838: ('488dbc24b9000000', 'lea    0xb9(%rsp),%rdi'),
            89668846: ('4c89fe', 'mov    %r15,%rsi'),
            89668849: ('ffd5', 'call   *%rbp'),
            89668907: ('4c8d8424b0000000', 'lea    0xb0(%rsp),%r8'),
            89668918: ('e885c60100', 'call   0x55a03c0')},
 'bwc_b3': {89753275: ('488dbc24d0010000', 'lea    0x1d0(%rsp),%rdi'),
            89753283: ('488d9424d0000000', 'lea    0xd0(%rsp),%rdx'),
            89753291: ('4c89fe', 'mov    %r15,%rsi'),
            89753294: ('e88d7fefff', 'call   0x5490660'),
            89753341: ('488db424d9010000', 'lea    0x1d9(%rsp),%rsi'),
            89753349: ('488dbc24d0000000', 'lea    0xd0(%rsp),%rdi'),
            89753362: ('ff15f06df400', 'call   *0xf46df0(%rip)'),
            89753410: ('488dbc24d9010000', 'lea    0x1d9(%rsp),%rdi'),
            89753418: ('488db424d0000000', 'lea    0xd0(%rsp),%rsi'),
            89753431: ('ff15ab6df400', 'call   *0xf46dab(%rip)'),
            89753437: ('4c89bc24d0010000', 'mov    %r15,0x1d0(%rsp)'),
            89753445: ('4488b424d8010000', 'mov    %r14b,0x1d8(%rsp)'),
            89753502: ('4c8d8424d0010000', 'lea    0x1d0(%rsp),%r8'),
            89753521: ('e80a7c0000', 'call   0x55a03c0')},
 'bwc_b4': {90218611: ('488d7c2470', 'lea    0x70(%rsp),%rdi'),
            90218616: ('488d542408', 'lea    0x8(%rsp),%rdx'),
            90218621: ('498db670060000', 'lea    0x670(%r14),%rsi'),
            90218628: ('e8b783e8ff', 'call   0x5492440'),
            90218664: ('488d742479', 'lea    0x79(%rsp),%rsi'),
            90218669: ('488dbc24a9020000', 'lea    0x2a9(%rsp),%rdi'),
            90218682: ('ff154854ed00', 'call   *0xed5448(%rip)'),
            90218704: ('4c89ac2490010000', 'mov    %r13,0x190(%rsp)'),
            90218712: ('4488a42498010000', 'mov    %r12b,0x198(%rsp)'),
            90218720: ('488dbc2499010000', 'lea    0x199(%rsp),%rdi'),
            90218728: ('488db424a9020000', 'lea    0x2a9(%rsp),%rsi'),
            90218741: ('ff150d54ed00', 'call   *0xed540d(%rip)'),
            90218788: ('4c8d842490010000', 'lea    0x190(%rsp),%r8'),
            90218802: ('e88962f9ff', 'call   0x55a03c0')},
 'bwc_c1': {88939368: ('488dbc24b0000000', 'lea    0xb0(%rsp),%rdi'),
            88939391: ('488dbc2470050000', 'lea    0x570(%rsp),%rdi'),
            88939399: ('488db42439070000', 'lea    0x739(%rsp),%rsi'),
            88939407: ('41ffd4', 'call   *%r12'),
            88939984: ('488dbc24b0000000', 'lea    0xb0(%rsp),%rdi'),
            88939992: ('e823e21500', 'call   0x5630000'),
            88940104: ('4c89bc24b0000000', 'mov    %r15,0xb0(%rsp)'),
            88940112: ('4088ac24b8000000', 'mov    %bpl,0xb8(%rsp)'),
            88940125: ('488dbc24b9000000', 'lea    0xb9(%rsp),%rdi'),
            88940133: ('488db42470050000', 'lea    0x570(%rsp),%rsi'),
            88940141: ('41ffd4', 'call   *%r12'),
            88940210: ('4c8d8424b0000000', 'lea    0xb0(%rsp),%r8'),
            88940221: ('e80ee70c00', 'call   0x55a05d0')},
 'bwc_c2': {89679879: ('488bb424b0020000', 'mov    0x2b0(%rsp),%rsi'),
            89679887: ('488d9424f8030000', 'lea    0x3f8(%rsp),%rdx'),
            89679955: ('488dbc24b0000000', 'lea    0xb0(%rsp),%rdi'),
            89679963: ('e8a0970a00', 'call   0x5630000'),
            89679986: ('4c89ff', 'mov    %r15,%rdi'),
            89679989: ('488db424e9020000', 'lea    0x2e9(%rsp),%rsi'),
            89680004: ('ffd5', 'call   *%rbp'),
            89680017: ('4c89b424b0000000', 'mov    %r14,0xb0(%rsp)'),
            89680025: ('889c24b8000000', 'mov    %bl,0xb8(%rsp)'),
            89680037: ('488dbc24b9000000', 'lea    0xb9(%rsp),%rdi'),
            89680045: ('4c89fe', 'mov    %r15,%rsi'),
            89680048: ('ffd5', 'call   *%rbp'),
            89680106: ('4c8d8424b0000000', 'lea    0xb0(%rsp),%r8'),
            89680117: ('e8d69c0100', 'call   0x55a05d0'),
            89681279: ('488dbc24e0020000', 'lea    0x2e0(%rsp),%rdi'),
            89681287: ('488bb424b0020000', 'mov    0x2b0(%rsp),%rsi'),
            89681295: ('488d9424f8030000', 'lea    0x3f8(%rsp),%rdx'),
            89681303: ('e8a4b6f0ff', 'call   0x5492440'),
            89681347: ('4c89ff', 'mov    %r15,%rdi'),
            89681350: ('488db424e9020000', 'lea    0x2e9(%rsp),%rsi'),
            89681365: ('ffd5', 'call   *%rbp'),
            89681378: ('4c89b424b0000000', 'mov    %r14,0xb0(%rsp)'),
            89681386: ('889c24b8000000', 'mov    %bl,0xb8(%rsp)'),
            89681398: ('488dbc24b9000000', 'lea    0xb9(%rsp),%rdi'),
            89681406: ('4c89fe', 'mov    %r15,%rsi'),
            89681409: ('ffd5', 'call   *%rbp'),
            89681467: ('4c8d8424b0000000', 'lea    0xb0(%rsp),%r8'),
            89681478: ('e885970100', 'call   0x55a05d0')},
 'bwc_c3': {89769259: ('488dbc24d0010000', 'lea    0x1d0(%rsp),%rdi'),
            89769267: ('488d9424d0000000', 'lea    0xd0(%rsp),%rdx'),
            89769275: ('4c89fe', 'mov    %r15,%rsi'),
            89769278: ('e81d41efff', 'call   0x5490660'),
            89769325: ('488db424d9010000', 'lea    0x1d9(%rsp),%rsi'),
            89769333: ('488dbc24d0000000', 'lea    0xd0(%rsp),%rdi'),
            89769346: ('ff15802ff400', 'call   *0xf42f80(%rip)'),
            89769394: ('488dbc24d9010000', 'lea    0x1d9(%rsp),%rdi'),
            89769402: ('488db424d0000000', 'lea    0xd0(%rsp),%rsi'),
            89769415: ('ff153b2ff400', 'call   *0xf42f3b(%rip)'),
            89769421: ('4c89bc24d0010000', 'mov    %r15,0x1d0(%rsp)'),
            89769429: ('4488b424d8010000', 'mov    %r14b,0x1d8(%rsp)'),
            89769486: ('4c8d8424d0010000', 'lea    0x1d0(%rsp),%r8'),
            89769505: ('e8aa3f0000', 'call   0x55a05d0')},
 'bwc_c4': {90218163: ('488d7c2470', 'lea    0x70(%rsp),%rdi'),
            90218168: ('488d542408', 'lea    0x8(%rsp),%rdx'),
            90218173: ('498db670060000', 'lea    0x670(%r14),%rsi'),
            90218180: ('e87785e8ff', 'call   0x5492440'),
            90218216: ('488d742479', 'lea    0x79(%rsp),%rsi'),
            90218221: ('488dbc24a9020000', 'lea    0x2a9(%rsp),%rdi'),
            90218234: ('ff150856ed00', 'call   *0xed5608(%rip)'),
            90218256: ('4c89ac2490010000', 'mov    %r13,0x190(%rsp)'),
            90218264: ('4488a42498010000', 'mov    %r12b,0x198(%rsp)'),
            90218272: ('488dbc2499010000', 'lea    0x199(%rsp),%rdi'),
            90218280: ('488db424a9020000', 'lea    0x2a9(%rsp),%rsi'),
            90218293: ('ff15cd55ed00', 'call   *0xed55cd(%rip)'),
            90218340: ('4c8d842490010000', 'lea    0x190(%rsp),%r8'),
            90218354: ('e85966f9ff', 'call   0x55a05d0')},
 'dc_ca': {47986944: ('55', 'push   %rbp'),
           47986945: ('4157', 'push   %r15'),
           47986947: ('4156', 'push   %r14'),
           47986949: ('4155', 'push   %r13'),
           47986951: ('4154', 'push   %r12'),
           47986953: ('53', 'push   %rbx'),
           47987350: ('e8057670ff', 'call   0x24cb0a0')},
 'dc_o1': {45689424: ('4157', 'push   %r15'),
           45689426: ('4156', 'push   %r14'),
           45689428: ('4154', 'push   %r12'),
           45689430: ('53', 'push   %rbx'),
           45689431: ('4883ec38', 'sub    $0x38,%rsp'),
           45689435: ('4989d7', 'mov    %rdx,%r15'),
           45689595: ('e8a08593ff', 'call   0x24cb0a0')},
 'dc_o2': {46537520: ('55', 'push   %rbp'),
           46537521: ('4157', 'push   %r15'),
           46537523: ('4156', 'push   %r14'),
           46537525: ('4155', 'push   %r13'),
           46537527: ('4154', 'push   %r12'),
           46537529: ('53', 'push   %rbx'),
           46538048: ('e85b9386ff', 'call   0x24cb0a0')},
 'gc_a1': {43071916: ('89842499000000', 'mov    %eax,0x99(%rsp)'),
           43071927: ('0f11842489000000', 'movups %xmm0,0x89(%rsp)'),
           43071939: ('88842488000000', 'mov    %al,0x88(%rsp)'),
           43071946: ('48c78424800000002d000000', 'movq   $0x2d,0x80(%rsp)'),
           43071958: ('488db42480000000', 'lea    0x80(%rsp),%rsi'),
           43071966: ('4889df', 'mov    %rbx,%rdi'),
           43071969: ('4c89f2', 'mov    %r14,%rdx'),
           43071972: ('e8b79dfbff', 'call   0x28cd7a0'),
           43073465: ('898c2488000000', 'mov    %ecx,0x88(%rsp)'),
           43073472: ('c684248c00000001', 'movb   $0x1,0x8c(%rsp)'),
           43073480: ('48c784248000000035000000', 'movq   $0x35,0x80(%rsp)'),
           43073492: ('488db42480000000', 'lea    0x80(%rsp),%rsi'),
           43073500: ('4889df', 'mov    %rbx,%rdi'),
           43073503: ('4c89f2', 'mov    %r14,%rdx'),
           43073506: ('e8b997fbff', 'call   0x28cd7a0')},
 'gc_a2': {46073087: ('4889e7', 'mov    %rsp,%rdi'),
           46073090: ('488db424f8000000', 'lea    0xf8(%rsp),%rsi'),
           46073109: ('488dbc2430040000', 'lea    0x430(%rsp),%rdi'),
           46073117: ('4889e6', 'mov    %rsp,%rsi'),
           46073120: ('488b942430030000', 'mov    0x330(%rsp),%rdx'),
           46073128: ('e873d2cdff', 'call   0x28cd7a0')},
 'gc_b1': {84754820: ('488b7e10', 'mov    0x10(%rsi),%rdi'),
           84754824: ('4889c6', 'mov    %rax,%rsi'),
           84754835: ('89842499000000', 'mov    %eax,0x99(%rsp)'),
           84754846: ('0f11842489000000', 'movups %xmm0,0x89(%rsp)'),
           84754858: ('88842488000000', 'mov    %al,0x88(%rsp)'),
           84754865: ('48c78424800000002d000000', 'movq   $0x2d,0x80(%rsp)'),
           84754877: ('488db42480000000', 'lea    0x80(%rsp),%rsi'),
           84754885: ('4889df', 'mov    %rbx,%rdi'),
           84754888: ('4c89f2', 'mov    %r14,%rdx'),
           84754891: ('e8608b2b00', 'call   0x538cd30'),
           84756377: ('898c2488000000', 'mov    %ecx,0x88(%rsp)'),
           84756384: ('c684248c00000001', 'movb   $0x1,0x8c(%rsp)'),
           84756392: ('48c784248000000035000000', 'movq   $0x35,0x80(%rsp)'),
           84756404: ('488db42480000000', 'lea    0x80(%rsp),%rsi'),
           84756412: ('4889df', 'mov    %rbx,%rdi'),
           84756415: ('4c89f2', 'mov    %r14,%rdx'),
           84756418: ('e869852b00', 'call   0x538cd30')},
 'gc_b2': {88922019: ('488d7c2440', 'lea    0x40(%rsp),%rdi'),
           88922024: ('4889ee', 'mov    %rbp,%rsi'),
           88922027: ('4c89fa', 'mov    %r15,%rdx'),
           88922043: ('488d7c2448', 'lea    0x48(%rsp),%rdi'),
           88922053: ('488d7c2440', 'lea    0x40(%rsp),%rdi'),
           88922058: ('488db424f0010000', 'lea    0x1f0(%rsp),%rsi'),
           88922071: ('488dbc2480010000', 'lea    0x180(%rsp),%rdi'),
           88922079: ('488d742440', 'lea    0x40(%rsp),%rsi'),
           88922084: ('488b542410', 'mov    0x10(%rsp),%rdx'),
           88922089: ('e842f5ebff', 'call   0x538cd30')},
 'gc_c1': {84752244: ('488b7e10', 'mov    0x10(%rsi),%rdi'),
           84752248: ('4889c6', 'mov    %rax,%rsi'),
           84752259: ('89842499000000', 'mov    %eax,0x99(%rsp)'),
           84752270: ('0f11842489000000', 'movups %xmm0,0x89(%rsp)'),
           84752282: ('88842488000000', 'mov    %al,0x88(%rsp)'),
           84752289: ('48c78424800000002d000000', 'movq   $0x2d,0x80(%rsp)'),
           84752301: ('488db42480000000', 'lea    0x80(%rsp),%rsi'),
           84752309: ('4889df', 'mov    %rbx,%rdi'),
           84752312: ('4c89f2', 'mov    %r14,%rdx'),
           84752315: ('e890432c00', 'call   0x5397b50'),
           84753801: ('898c2488000000', 'mov    %ecx,0x88(%rsp)'),
           84753808: ('c684248c00000001', 'movb   $0x1,0x8c(%rsp)'),
           84753816: ('48c784248000000035000000', 'movq   $0x35,0x80(%rsp)'),
           84753828: ('488db42480000000', 'lea    0x80(%rsp),%rsi'),
           84753836: ('4889df', 'mov    %rbx,%rdi'),
           84753839: ('4c89f2', 'mov    %r14,%rdx'),
           84753842: ('e8993d2c00', 'call   0x5397b50')},
 'gc_c2': {88920659: ('488d7c2440', 'lea    0x40(%rsp),%rdi'),
           88920664: ('4889ee', 'mov    %rbp,%rsi'),
           88920667: ('4c89fa', 'mov    %r15,%rdx'),
           88920683: ('488d7c2448', 'lea    0x48(%rsp),%rdi'),
           88920693: ('488d7c2440', 'lea    0x40(%rsp),%rdi'),
           88920698: ('488db424f0010000', 'lea    0x1f0(%rsp),%rsi'),
           88920711: ('488dbc2480010000', 'lea    0x180(%rsp),%rdi'),
           88920719: ('488d742440', 'lea    0x40(%rsp),%rsi'),
           88920724: ('488b542410', 'mov    0x10(%rsp),%rdx'),
           88920729: ('e8b2a8ecff', 'call   0x5397b50')},
 'giant_s1a': {42784672: ('55', 'push   %rbp'),
               42784673: ('4157', 'push   %r15'),
               42784675: ('4156', 'push   %r14'),
               42784677: ('4155', 'push   %r13'),
               42784679: ('4154', 'push   %r12'),
               42784681: ('53', 'push   %rbx'),
               42787044: ('e8b7f6ffff', 'call   0x28cd7a0'),
               42793825: ('48898424400d0000', 'mov    %rax,0xd40(%rsp)'),
               42793838: ('0f298424300d0000', 'movaps %xmm0,0xd30(%rsp)'),
               42793851: ('0f298424200d0000', 'movaps %xmm0,0xd20(%rsp)'),
               42793883: ('660f299c24100d0000', 'movapd %xmm3,0xd10(%rsp)'),
               42793892: ('660f299424000d0000', 'movapd %xmm2,0xd00(%rsp)'),
               42793901: ('660f298c24f00c0000', 'movapd %xmm1,0xcf0(%rsp)'),
               42793910: ('660f7f8424e00c0000', 'movdqa %xmm0,0xce0(%rsp)'),
               42793919: ('488d7c2420', 'lea    0x20(%rsp),%rdi'),
               42793924: ('488d9424e00c0000', 'lea    0xce0(%rsp),%rdx'),
               42793932: ('4c89e6', 'mov    %r12,%rsi'),
               42793935: ('e8ccf83100', 'call   0x2bef4a0'),
               42825117: ('4889df', 'mov    %rbx,%rdi'),
               42825120: ('4c89e6', 'mov    %r12,%rsi'),
               42825136: ('488d742429', 'lea    0x29(%rsp),%rsi'),
               42825141: ('488dbc24490d0000', 'lea    0xd49(%rsp),%rdi'),
               42825154: ('ff15407fc003', 'call   *0x3c07f40(%rip)'),
               42825160: ('4183fc02', 'cmp    $0x2,%r12d'),
               42825164: ('0f852e010000', 'jne    0x28d7700'),
               42825472: ('488b6c2410', 'mov    0x10(%rsp),%rbp'),
               42825484: ('488d7c2429', 'lea    0x29(%rsp),%rdi'),
               42825489: ('488db424490d0000', 'lea    0xd49(%rsp),%rsi'),
               42825502: ('ff15e47dc003', 'call   *0x3c07de4(%rip)'),
               42825508: ('4c89642420', 'mov    %r12,0x20(%rsp)'),
               42825513: ('44886c2428', 'mov    %r13b,0x28(%rsp)'),
               42825526: ('488d542420', 'lea    0x20(%rsp),%rdx'),
               42825531: ('4c89e7', 'mov    %r12,%rdi'),
               42825534: ('4889de', 'mov    %rbx,%rsi'),
               42825537: ('ff1599f4c003', 'call   *0x3c0f499(%rip)')},
 'giant_s1b': {87608624: ('55', 'push   %rbp'),
               87608625: ('4157', 'push   %r15'),
               87608627: ('4156', 'push   %r14'),
               87608629: ('4155', 'push   %r13'),
               87608631: ('4154', 'push   %r12'),
               87608633: ('53', 'push   %rbx'),
               87610988: ('e8bff6ffff', 'call   0x538cd30'),
               87617795: ('48898424200d0000', 'mov    %rax,0xd20(%rsp)'),
               87617808: ('0f298424100d0000', 'movaps %xmm0,0xd10(%rsp)'),
               87617821: ('0f298424000d0000', 'movaps %xmm0,0xd00(%rsp)'),
               87617853: ('660f299c24f00c0000', 'movapd %xmm3,0xcf0(%rsp)'),
               87617862: ('660f299424e00c0000', 'movapd %xmm2,0xce0(%rsp)'),
               87617871: ('660f298c24d00c0000', 'movapd %xmm1,0xcd0(%rsp)'),
               87617880: ('660f7f8424c00c0000', 'movdqa %xmm0,0xcc0(%rsp)'),
               87617889: ('488d7c2420', 'lea    0x20(%rsp),%rdi'),
               87617894: ('488d9424c00c0000', 'lea    0xcc0(%rsp),%rdx'),
               87617902: ('4c89ee', 'mov    %r13,%rsi'),
               87617905: ('e8dac41300', 'call   0x54cb650'),
               87647802: ('4889df', 'mov    %rbx,%rdi'),
               87647805: ('4c89e6', 'mov    %r12,%rsi'),
               87647821: ('488d742429', 'lea    0x29(%rsp),%rsi'),
               87647826: ('488dbc24290d0000', 'lea    0xd29(%rsp),%rdi'),
               87647839: ('ff15a38e1401', 'call   *0x1148ea3(%rip)'),
               87647845: ('4183fc02', 'cmp    $0x2,%r12d'),
               87647849: ('0f852e010000', 'jne    0x539679d'),
               87648157: ('488b6c2410', 'mov    0x10(%rsp),%rbp'),
               87648169: ('488d7c2429', 'lea    0x29(%rsp),%rdi'),
               87648174: ('488db424290d0000', 'lea    0xd29(%rsp),%rsi'),
               87648187: ('ff15478d1401', 'call   *0x1148d47(%rip)'),
               87648193: ('4c89642420', 'mov    %r12,0x20(%rsp)'),
               87648198: ('44886c2428', 'mov    %r13b,0x28(%rsp)'),
               87648211: ('488d542420', 'lea    0x20(%rsp),%rdx'),
               87648216: ('4c89ef', 'mov    %r13,%rdi'),
               87648219: ('4889de', 'mov    %rbx,%rsi'),
               87648222: ('ff15fc031501', 'call   *0x11503fc(%rip)')},
 'giant_s1c': {87653200: ('55', 'push   %rbp'),
               87653201: ('4157', 'push   %r15'),
               87653203: ('4156', 'push   %r14'),
               87653205: ('4155', 'push   %r13'),
               87653207: ('4154', 'push   %r12'),
               87653209: ('53', 'push   %rbx'),
               87655564: ('e8bff6ffff', 'call   0x5397b50'),
               87662371: ('48898424200d0000', 'mov    %rax,0xd20(%rsp)'),
               87662384: ('0f298424100d0000', 'movaps %xmm0,0xd10(%rsp)'),
               87662397: ('0f298424000d0000', 'movaps %xmm0,0xd00(%rsp)'),
               87662429: ('660f299c24f00c0000', 'movapd %xmm3,0xcf0(%rsp)'),
               87662438: ('660f299424e00c0000', 'movapd %xmm2,0xce0(%rsp)'),
               87662447: ('660f298c24d00c0000', 'movapd %xmm1,0xcd0(%rsp)'),
               87662456: ('660f7f8424c00c0000', 'movdqa %xmm0,0xcc0(%rsp)'),
               87662465: ('488d7c2420', 'lea    0x20(%rsp),%rdi'),
               87662470: ('488d9424c00c0000', 'lea    0xcc0(%rsp),%rdx'),
               87662478: ('4c89ee', 'mov    %r13,%rsi'),
               87662481: ('e8ca191300', 'call   0x54cb960'),
               87692378: ('4889df', 'mov    %rbx,%rdi'),
               87692381: ('4c89e6', 'mov    %r12,%rsi'),
               87692397: ('488d742429', 'lea    0x29(%rsp),%rsi'),
               87692402: ('488dbc24290d0000', 'lea    0xd29(%rsp),%rdi'),
               87692415: ('ff1583e01301', 'call   *0x113e083(%rip)'),
               87692421: ('4183fc02', 'cmp    $0x2,%r12d'),
               87692425: ('0f852e010000', 'jne    0x53a15bd'),
               87692733: ('488b6c2410', 'mov    0x10(%rsp),%rbp'),
               87692745: ('488d7c2429', 'lea    0x29(%rsp),%rdi'),
               87692750: ('488db424290d0000', 'lea    0xd29(%rsp),%rsi'),
               87692763: ('ff1527df1301', 'call   *0x113df27(%rip)'),
               87692769: ('4c89642420', 'mov    %r12,0x20(%rsp)'),
               87692774: ('44886c2428', 'mov    %r13b,0x28(%rsp)'),
               87692787: ('488d542420', 'lea    0x20(%rsp),%rdx'),
               87692792: ('4c89ef', 'mov    %r13,%rdi'),
               87692795: ('4889de', 'mov    %rbx,%rsi'),
               87692798: ('ff15dc551401', 'call   *0x11455dc(%rip)')},
 'helper_s3a': {46540832: ('55', 'push   %rbp'),
                46540833: ('4157', 'push   %r15'),
                46540835: ('4156', 'push   %r14'),
                46540837: ('4155', 'push   %r13'),
                46540839: ('4154', 'push   %r12'),
                46540841: ('53', 'push   %rbx'),
                46541595: ('e8808586ff', 'call   0x24cb0a0'),
                46542840: ('e8b3a0f5ff', 'call   0x2bbd0b0'),
                46543777: ('e8fa7c86ff', 'call   0x24cb0a0'),
                46544262: ('e8259bf5ff', 'call   0x2bbd0b0'),
                46545024: ('488dbc2408070000', 'lea    0x708(%rsp),%rdi'),
                46545032: ('4c89e6', 'mov    %r12,%rsi'),
                46545075: ('488dbc2471040000', 'lea    0x471(%rsp),%rdi'),
                46545083: ('488db424ea070000', 'lea    0x7ea(%rsp),%rsi'),
                46545091: ('ff153fbc8703', 'call   *0x387bc3f(%rip)'),
                46545510: ('e8357686ff', 'call   0x24cb0a0'),
                46546062: ('e80d7486ff', 'call   0x24cb0a0'),
                46547043: ('488dbc2480050000', 'lea    0x580(%rsp),%rdi'),
                46547051: ('488db42489020000', 'lea    0x289(%rsp),%rsi'),
                46547062: ('ff158cb48703', 'call   *0x387b48c(%rip)'),
                46547068: ('4c89642428', 'mov    %r12,0x28(%rsp)'),
                46547073: ('4c89a424b8030000', 'mov    %r12,0x3b8(%rsp)'),
                46547081: ('44886c2430', 'mov    %r13b,0x30(%rsp)'),
                46547086: ('4488ac24c0030000', 'mov    %r13b,0x3c0(%rsp)'),
                46547099: ('488dbc24c1030000', 'lea    0x3c1(%rsp),%rdi'),
                46547107: ('488db42480050000', 'lea    0x580(%rsp),%rsi'),
                46547115: ('ff1557b48703', 'call   *0x387b457(%rip)'),
                46547456: ('498906', 'mov    %rax,(%r14)'),
                46547660: ('4889df', 'mov    %rbx,%rdi'),
                46547663: ('488db42480050000', 'lea    0x580(%rsp),%rsi'),
                46547678: ('41ffd6', 'call   *%r14'),
                46547749: ('488dbc24a9000000', 'lea    0xa9(%rsp),%rdi'),
                46547757: ('4889de', 'mov    %rbx,%rsi'),
                46547760: ('41ffd6', 'call   *%r14'),
                46547947: ('488dbc24ea070000', 'lea    0x7ea(%rsp),%rdi'),
                46547955: ('488db424a9000000', 'lea    0xa9(%rsp),%rsi'),
                46547963: ('ff1507b18703', 'call   *0x387b107(%rip)'),
                46548013: ('498906', 'mov    %rax,(%r14)'),
                46548178: ('e8d98bf5ff', 'call   0x2bbd0b0'),
                46548472: ('498906', 'mov    %rax,(%r14)'),
                46548624: ('488db424a0000000', 'lea    0xa0(%rsp),%rsi'),
                46548632: ('e8731d8f01', 'call   0x4556410'),
                46548646: ('49c70602000000', 'movq   $0x2,(%r14)'),
                46548661: ('488dbc24e9080000', 'lea    0x8e9(%rsp),%rdi'),
                46548669: ('488db424ea070000', 'lea    0x7ea(%rsp),%rsi'),
                46548682: ('ff1538ae8703', 'call   *0x387ae38(%rip)'),
                46548699: ('48c70003000000', 'movq   $0x3,(%rax)'),
                46548732: ('488dbc2429060000', 'lea    0x629(%rsp),%rdi'),
                46548740: ('488db424e9080000', 'lea    0x8e9(%rsp),%rsi'),
                46548753: ('ff15f1ad8703', 'call   *0x387adf1(%rip)'),
                46548770: ('48c70002000000', 'movq   $0x2,(%rax)'),
                46548784: ('4d8937', 'mov    %r14,(%r15)'),
                46548787: ('8b442414', 'mov    0x14(%rsp),%eax'),
                46548791: ('41884708', 'mov    %al,0x8(%r15)'),
                46548795: ('498d7f09', 'lea    0x9(%r15),%rdi'),
                46548799: ('488db42429060000', 'lea    0x629(%rsp),%rsi'),
                46548812: ('ff15b6ad8703', 'call   *0x387adb6(%rip)'),
                46548845: ('66410f1187b0000000', 'movupd %xmm0,0xb0(%r15)'),
                46548854: ('66410f118fc0000000', 'movupd %xmm1,0xc0(%r15)'),
                46548863: ('66410f1197d0000000', 'movupd %xmm2,0xd0(%r15)'),
                46548880: ('498987e0000000', 'mov    %rax,0xe0(%r15)'),
                46548887: ('49899fe8000000', 'mov    %rbx,0xe8(%r15)'),
                46548902: ('498987f0000000', 'mov    %rax,0xf0(%r15)'),
                46549008: ('488db424ea070000', 'lea    0x7ea(%rsp),%rsi'),
                46549021: ('488dbc2471040000', 'lea    0x471(%rsp),%rdi'),
                46549029: ('ff15ddac8703', 'call   *0x387acdd(%rip)')},
 'helper_s3b': {90052304: ('55', 'push   %rbp'),
                90052305: ('4157', 'push   %r15'),
                90052307: ('4156', 'push   %r14'),
                90052309: ('4155', 'push   %r13'),
                90052311: ('4154', 'push   %r12'),
                90052313: ('53', 'push   %rbx'),
                90052431: ('e80cddfdfd', 'call   0x35bf460'),
                90053214: ('e8fdd9fdfd', 'call   0x35bf460'),
                90053291: ('e86049f7fe', 'call   0x4556410'),
                90055380: ('e887d1fdfd', 'call   0x35bf460'),
                90055444: ('e8f740f7fe', 'call   0x4556410'),
                90056512: ('488dbc2418070000', 'lea    0x718(%rsp),%rdi'),
                90056520: ('4c89e6', 'mov    %r12,%rsi'),
                90056563: ('488dbc2481040000', 'lea    0x481(%rsp),%rdi'),
                90056571: ('488db424fa070000', 'lea    0x7fa(%rsp),%rsi'),
                90056579: ('ff157fcdef00', 'call   *0xefcd7f(%rip)'),
                90057132: ('e8afcafdfd', 'call   0x35bf460'),
                90057187: ('e8283af7fe', 'call   0x4556410'),
                90057709: ('e86ec8fdfd', 'call   0x35bf460'),
                90057761: ('e8ea37f7fe', 'call   0x4556410'),
                90058584: ('488dbc2490050000', 'lea    0x590(%rsp),%rdi'),
                90058592: ('488db42499020000', 'lea    0x299(%rsp),%rsi'),
                90058603: ('ff1597c5ef00', 'call   *0xefc597(%rip)'),
                90058640: ('488dbc24d1030000', 'lea    0x3d1(%rsp),%rdi'),
                90058648: ('488db42490050000', 'lea    0x590(%rsp),%rsi'),
                90058656: ('ff1562c5ef00', 'call   *0xefc562(%rip)'),
                90059008: ('498906', 'mov    %rax,(%r14)'),
                90059212: ('4889df', 'mov    %rbx,%rdi'),
                90059215: ('488db42490050000', 'lea    0x590(%rsp),%rsi'),
                90059230: ('41ffd6', 'call   *%r14'),
                90059301: ('488dbc24a9000000', 'lea    0xa9(%rsp),%rdi'),
                90059309: ('4889de', 'mov    %rbx,%rsi'),
                90059312: ('41ffd6', 'call   *%r14'),
                90059499: ('488dbc24fa070000', 'lea    0x7fa(%rsp),%rdi'),
                90059507: ('488db424a9000000', 'lea    0xa9(%rsp),%rsi'),
                90059515: ('ff1507c2ef00', 'call   *0xefc207(%rip)'),
                90059565: ('498906', 'mov    %rax,(%r14)'),
                90060024: ('498906', 'mov    %rax,(%r14)'),
                90060176: ('488db424a0000000', 'lea    0xa0(%rsp),%rsi'),
                90060184: ('e8732ef7fe', 'call   0x4556410'),
                90060198: ('49c70602000000', 'movq   $0x2,(%r14)'),
                90060213: ('488dbc24f9080000', 'lea    0x8f9(%rsp),%rdi'),
                90060221: ('488db424fa070000', 'lea    0x7fa(%rsp),%rsi'),
                90060234: ('ff1538bfef00', 'call   *0xefbf38(%rip)'),
                90060284: ('488dbc2439060000', 'lea    0x639(%rsp),%rdi'),
                90060292: ('488db424f9080000', 'lea    0x8f9(%rsp),%rsi'),
                90060305: ('ff15f1beef00', 'call   *0xefbef1(%rip)'),
                90060347: ('498d7f09', 'lea    0x9(%r15),%rdi'),
                90060351: ('488db42439060000', 'lea    0x639(%rsp),%rsi'),
                90060364: ('ff15b6beef00', 'call   *0xefbeb6(%rip)'),
                90060560: ('488db424fa070000', 'lea    0x7fa(%rsp),%rsi'),
                90060573: ('488dbc2481040000', 'lea    0x481(%rsp),%rdi'),
                90060581: ('ff15ddbdef00', 'call   *0xefbddd(%rip)')},
 'inner_ca': {45857696: ('55', 'push   %rbp'),
              45857697: ('4157', 'push   %r15'),
              45857699: ('4156', 'push   %r14'),
              45857701: ('4155', 'push   %r13'),
              45857703: ('4154', 'push   %r12'),
              45857705: ('53', 'push   %rbx'),
              45858429: ('e81ef290ff', 'call   0x24cb0a0'),
              45858715: ('e800f190ff', 'call   0x24cb0a0'),
              45858826: ('e85134a000', 'call   0x35bf460'),
              45858875: ('e8d0a39901', 'call   0x4556410')},
 'inner_s3': {45863088: ('55', 'push   %rbp'),
              45863089: ('4157', 'push   %r15'),
              45863091: ('4156', 'push   %r14'),
              45863093: ('4155', 'push   %r13'),
              45863095: ('4154', 'push   %r12'),
              45863097: ('53', 'push   %rbx'),
              45863853: ('e8eedc90ff', 'call   0x24cb0a0'),
              45863994: ('e82120a000', 'call   0x35bf460'),
              45864085: ('e8768f9901', 'call   0x4556410')},
 'sublookup_ca': {45839095: ('48c78424c804000004000000', 'movq   $0x4,0x4c8(%rsp)'),
                  45839755: ('4c89bc24e0050000', 'mov    %r15,0x5e0(%rsp)'),
                  45839947: ('e8503a91ff', 'call   0x24cb0a0'),
                  45840199: ('e8543991ff', 'call   0x24cb0a0'),
                  45841576: ('4c89bc24e0050000', 'mov    %r15,0x5e0(%rsp)'),
                  45841792: ('488dbc2488060000', 'lea    0x688(%rsp),%rdi'),
                  45841800: ('4889ee', 'mov    %rbp,%rsi'),
                  45841819: ('4c89a424c8040000', 'mov    %r12,0x4c8(%rsp)'),
                  45841832: ('4488b424d0040000', 'mov    %r14b,0x4d0(%rsp)'),
                  45841845: ('488dbc24d1040000', 'lea    0x4d1(%rsp),%rdi'),
                  45841853: ('488db42469070000', 'lea    0x769(%rsp),%rsi'),
                  45841861: ('ff153d779203', 'call   *0x392773d(%rip)'),
                  45841875: ('48898424d0050000', 'mov    %rax,0x5d0(%rsp)'),
                  45841888: ('888424d8050000', 'mov    %al,0x5d8(%rsp)'),
                  45842514: ('e8493091ff', 'call   0x24cb0a0'),
                  45842570: ('4869cab8000000', 'imul   $0xb8,%rdx,%rcx'),
                  45842577: ('4c8d2408', 'lea    (%rax,%rcx,1),%r12'),
                  45842581: ('4983c408', 'add    $0x8,%r12'),
                  45843008: ('4c89bc24e0050000', 'mov    %r15,0x5e0(%rsp)'),
                  45843179: ('e8b02d91ff', 'call   0x24cb0a0'),
                  45843414: ('e8c52c91ff', 'call   0x24cb0a0'),
                  45843883: ('e8f02a91ff', 'call   0x24cb0a0'),
                  45844118: ('e8052a91ff', 'call   0x24cb0a0'),
                  45844277: ('e8662991ff', 'call   0x24cb0a0'),
                  45845236: ('488dbc24e0050000', 'lea    0x5e0(%rsp),%rdi'),
                  45845244: ('488db42489020000', 'lea    0x289(%rsp),%rsi'),
                  45845261: ('41ffd6', 'call   *%r14'),
                  45845264: ('48895c2428', 'mov    %rbx,0x28(%rsp)'),
                  45845269: ('48899c2418040000', 'mov    %rbx,0x418(%rsp)'),
                  45845277: ('40886c2430', 'mov    %bpl,0x30(%rsp)'),
                  45845282: ('4088ac2420040000', 'mov    %bpl,0x420(%rsp)'),
                  45845295: ('488dbc2421040000', 'lea    0x421(%rsp),%rdi'),
                  45845303: ('488db424e0050000', 'lea    0x5e0(%rsp),%rsi'),
                  45845311: ('41ffd6', 'call   *%r14'),
                  45845704: ('48894130', 'mov    %rax,0x30(%rcx)'),
                  45845734: ('660f115120', 'movupd %xmm2,0x20(%rcx)'),
                  45845739: ('660f114910', 'movupd %xmm1,0x10(%rcx)'),
                  45845744: ('0f1101', 'movups %xmm0,(%rcx)'),
                  45845760: ('4c89e7', 'mov    %r12,%rdi'),
                  45845763: ('488db424e0050000', 'lea    0x5e0(%rsp),%rsi'),
                  45845778: ('41ffd6', 'call   *%r14'),
                  45845824: ('4889842440010000', 'mov    %rax,0x140(%rsp)'),
                  45845837: ('88842448010000', 'mov    %al,0x148(%rsp)'),
                  45845849: ('488dbc2449010000', 'lea    0x149(%rsp),%rdi'),
                  45845857: ('4c89e6', 'mov    %r12,%rsi'),
                  45845860: ('41ffd6', 'call   *%r14'),
                  45845863: ('4c89bc2428020000', 'mov    %r15,0x228(%rsp)'),
                  45846031: ('488dbc2469070000', 'lea    0x769(%rsp),%rdi'),
                  45846039: ('488db42449010000', 'lea    0x149(%rsp),%rsi'),
                  45846047: ('ff15e3669203', 'call   *0x39266e3(%rip)'),
                  45848474: ('488b9c2450020000', 'mov    0x250(%rsp),%rbx'),
                  45848482: ('488d7b08', 'lea    0x8(%rbx),%rdi'),
                  45848492: ('c6070c', 'movb   $0xc,(%rdi)'),
                  45848508: ('488db424d0040000', 'lea    0x4d0(%rsp),%rsi'),
                  45848516: ('ff153e5d9203', 'call   *0x3925d3e(%rip)'),
                  45848522: ('4c8923', 'mov    %r12,(%rbx)'),
                  45848592: ('488dbc24f8000000', 'lea    0xf8(%rsp),%rdi'),
                  45848620: ('4c89a424c8040000', 'mov    %r12,0x4c8(%rsp)'),
                  45848628: ('4488b424d0040000', 'mov    %r14b,0x4d0(%rsp)'),
                  45848636: ('488db42469070000', 'lea    0x769(%rsp),%rsi'),
                  45848649: ('488dbc24d1040000', 'lea    0x4d1(%rsp),%rdi'),
                  45848657: ('ff15b15c9203', 'call   *0x3925cb1(%rip)'),
                  45848671: ('48898424d0050000', 'mov    %rax,0x5d0(%rsp)'),
                  45848684: ('888424d8050000', 'mov    %al,0x5d8(%rsp)')},
 'sublookup_jc1': {45830956: ('48c784247005000004000000', 'movq   $0x4,0x570(%rsp)'),
                   45831704: ('e8439ea000', 'call   0x35bf460'),
                   45831765: ('e8b60d9a01', 'call   0x4556410'),
                   45831969: ('e83a9da000', 'call   0x35bf460'),
                   45832045: ('e89e0c9a01', 'call   0x4556410'),
                   45832565: ('4c89fe', 'mov    %r15,%rsi'),
                   45832586: ('4c89bc2470050000', 'mov    %r15,0x570(%rsp)'),
                   45832596: ('888c2478050000', 'mov    %cl,0x578(%rsp)'),
                   45832608: ('488dbc2479050000', 'lea    0x579(%rsp),%rdi'),
                   45832616: ('488db42489060000', 'lea    0x689(%rsp),%rsi'),
                   45832624: ('ff15529b9203', 'call   *0x3929b52(%rip)'),
                   45832638: ('4889842478060000', 'mov    %rax,0x678(%rsp)'),
                   45832651: ('88842480060000', 'mov    %al,0x680(%rsp)'),
                   45836037: ('488dbc2489060000', 'lea    0x689(%rsp),%rdi'),
                   45836045: ('488db42491010000', 'lea    0x191(%rsp),%rsi'),
                   45836053: ('ff15ed8d9203', 'call   *0x3928ded(%rip)'),
                   45836266: ('488d7b08', 'lea    0x8(%rbx),%rdi'),
                   45836276: ('c60705', 'movb   $0x5,(%rdi)'),
                   45836292: ('488db42478050000', 'lea    0x578(%rsp),%rsi'),
                   45836300: ('ff15f68c9203', 'call   *0x3928cf6(%rip)'),
                   45836306: ('4c893b', 'mov    %r15,(%rbx)'),
                   45836372: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
                   45836397: ('48899c2470050000', 'mov    %rbx,0x570(%rsp)'),
                   45836405: ('4088ac2478050000', 'mov    %bpl,0x578(%rsp)'),
                   45836413: ('488db42489060000', 'lea    0x689(%rsp),%rsi'),
                   45836426: ('488dbc2479050000', 'lea    0x579(%rsp),%rdi'),
                   45836434: ('ff15708c9203', 'call   *0x3928c70(%rip)'),
                   45836448: ('4889842478060000', 'mov    %rax,0x678(%rsp)'),
                   45836461: ('88842480060000', 'mov    %al,0x680(%rsp)')}}

EXPECTED = {'b_wrapper_sites': [{'byte_store': '0x2a866a7',
                      'caller': 'bwc_a1',
                      'key_rows': ['0x2a86617',
                                   '0x2a8661f',
                                   '0x2a86663',
                                   '0x2a8666b',
                                   '0x2a8667a',
                                   '0x2a86682',
                                   '0x2a86691',
                                   '0x2a8669f',
                                   '0x2a866a7',
                                   '0x2a866b3',
                                   '0x2a866bb',
                                   '0x2a866c3',
                                   '0x2a866fe',
                                   '0x2a86709'],
                      'lea_r8_row': '0x2a866fe',
                      'producer_call': '0x2a8666b',
                      'producer_target': '0x2aae850',
                      'record_disp': '0xd0',
                      'scratch_memcpy': [1504, 873, 271],
                      'scratch_memcpy_call': '0x2a86691',
                      'shape': 'X',
                      'site': '0x2a86709',
                      'tag_store': '0x2a8669f',
                      'tail_memcpy': [217, 1504, 271],
                      'tail_memcpy_call': '0x2a866c3',
                      'wrapper': 'jc1wb'},
                     {'byte_store': '0x2a86bf8',
                      'caller': 'bwc_a1',
                      'key_rows': ['0x2a86b8f',
                                   '0x2a86b97',
                                   '0x2a86b9f',
                                   '0x2a86ba7',
                                   '0x2a86bcb',
                                   '0x2a86bd3',
                                   '0x2a86be2',
                                   '0x2a86bf0',
                                   '0x2a86bf8',
                                   '0x2a86c04',
                                   '0x2a86c0c',
                                   '0x2a86c14',
                                   '0x2a86c4f',
                                   '0x2a86c5a'],
                      'lea_r8_row': '0x2a86c4f',
                      'producer_call': '0x2a86ba7',
                      'producer_target': '0x2761fe0',
                      'record_disp': '0xd0',
                      'scratch_memcpy': [1504, 873, 271],
                      'scratch_memcpy_call': '0x2a86be2',
                      'shape': 'X',
                      'site': '0x2a86c5a',
                      'tag_store': '0x2a86bf0',
                      'tail_memcpy': [217, 1504, 271],
                      'tail_memcpy_call': '0x2a86c14',
                      'wrapper': 'jc1wb'},
                     {'byte_store': '0x2a8bd68',
                      'caller': 'bwc_a2',
                      'key_rows': ['0x2a8bd03',
                                   '0x2a8bd08',
                                   '0x2a8bd0d',
                                   '0x2a8bd14',
                                   '0x2a8bd38',
                                   '0x2a8bd3d',
                                   '0x2a8bd4a',
                                   '0x2a8bd60',
                                   '0x2a8bd68',
                                   '0x2a8bd70',
                                   '0x2a8bd78',
                                   '0x2a8bd85',
                                   '0x2a8bdb4',
                                   '0x2a8bdc2'],
                      'lea_r8_row': '0x2a8bdb4',
                      'producer_call': '0x2a8bd14',
                      'producer_target': '0x2761fe0',
                      'record_disp': '0x190',
                      'scratch_memcpy': [681, 121, 271],
                      'scratch_memcpy_call': '0x2a8bd4a',
                      'shape': 'X',
                      'site': '0x2a8bdc2',
                      'tag_store': '0x2a8bd60',
                      'tail_memcpy': [409, 681, 271],
                      'tail_memcpy_call': '0x2a8bd85',
                      'wrapper': 'jc1wb'},
                     {'byte_store': '0x2c3ec25',
                      'caller': 'bwc_a3',
                      'key_rows': ['0x2c3eb7b',
                                   '0x2c3eb83',
                                   '0x2c3eb8b',
                                   '0x2c3eb8e',
                                   '0x2c3ebbd',
                                   '0x2c3ebc5',
                                   '0x2c3ebd2',
                                   '0x2c3ec02',
                                   '0x2c3ec0a',
                                   '0x2c3ec17',
                                   '0x2c3ec1d',
                                   '0x2c3ec25',
                                   '0x2c3ec5e',
                                   '0x2c3ec71'],
                      'lea_r8_row': '0x2c3ec5e',
                      'park_memcpy': [208, 473, 255],
                      'park_memcpy_call': '0x2c3ebd2',
                      'producer_call': '0x2c3eb8e',
                      'producer_target': '0x2761cd0',
                      'record_disp': '0x1d0',
                      'shape': 'Y',
                      'site': '0x2c3ec71',
                      'tag_store': '0x2c3ec1d',
                      'tail_memcpy': [473, 208, 255],
                      'tail_memcpy_call': '0x2c3ec17',
                      'wrapper': 'jc1wb'},
                     {'byte_store': '0x54d7b2d',
                      'caller': 'bwc_b1',
                      'key_rows': ['0x54d7845',
                                   '0x54d785c',
                                   '0x54d7864',
                                   '0x54d786c',
                                   '0x54d7aad',
                                   '0x54d7ab5',
                                   '0x54d7b25',
                                   '0x54d7b2d',
                                   '0x54d7b3a',
                                   '0x54d7b42',
                                   '0x54d7b4a',
                                   '0x54d7b8f',
                                   '0x54d7b9a'],
                      'lea_r8_row': '0x54d7b8f',
                      'producer_call': '0x54d7ab5',
                      'producer_target': '0x5630000',
                      'record_disp': '0xa0',
                      'scratch_memcpy': [1392, 1849, 271],
                      'scratch_memcpy_call': '0x54d786c',
                      'shape': 'X',
                      'site': '0x54d7b9a',
                      'tag_store': '0x54d7b25',
                      'tail_memcpy': [169, 1392, 271],
                      'tail_memcpy_call': '0x54d7b4a',
                      'wrapper': 'jc2wb'},
                     {'byte_store': '0x5583789',
                      'caller': 'bwc_b2',
                      'key_rows': ['0x55836f7',
                                   '0x55836ff',
                                   '0x5583743',
                                   '0x558374b',
                                   '0x5583762',
                                   '0x5583765',
                                   '0x5583774',
                                   '0x5583781',
                                   '0x5583789',
                                   '0x5583795',
                                   '0x558379d',
                                   '0x55837a0',
                                   '0x55837da',
                                   '0x55837e5'],
                      'lea_r8_row': '0x55837da',
                      'producer_call': '0x558374b',
                      'producer_target': '0x5630000',
                      'record_disp': '0xb0',
                      'scratch_memcpy': [1312, 745, 271],
                      'scratch_memcpy_call': '0x5583774',
                      'shape': 'X',
                      'site': '0x55837e5',
                      'tag_store': '0x5583781',
                      'tail_memcpy': [185, 'reg:r15', 271],
                      'tail_memcpy_call': '0x55837a0',
                      'wrapper': 'jc2wb'},
                     {'byte_store': '0x5583cda',
                      'caller': 'bwc_b2',
                      'key_rows': ['0x5583c6f',
                                   '0x5583c77',
                                   '0x5583c7f',
                                   '0x5583c87',
                                   '0x5583cb3',
                                   '0x5583cb6',
                                   '0x5583cc5',
                                   '0x5583cd2',
                                   '0x5583cda',
                                   '0x5583ce6',
                                   '0x5583cee',
                                   '0x5583cf1',
                                   '0x5583d2b',
                                   '0x5583d36'],
                      'lea_r8_row': '0x5583d2b',
                      'producer_call': '0x5583c87',
                      'producer_target': '0x5492440',
                      'record_disp': '0xb0',
                      'scratch_memcpy': [1312, 745, 271],
                      'scratch_memcpy_call': '0x5583cc5',
                      'shape': 'X',
                      'site': '0x5583d36',
                      'tag_store': '0x5583cd2',
                      'tail_memcpy': [185, 'reg:r15', 271],
                      'tail_memcpy_call': '0x5583cf1',
                      'wrapper': 'jc2wb'},
                     {'byte_store': '0x5598765',
                      'caller': 'bwc_b3',
                      'key_rows': ['0x55986bb',
                                   '0x55986c3',
                                   '0x55986cb',
                                   '0x55986ce',
                                   '0x55986fd',
                                   '0x5598705',
                                   '0x5598712',
                                   '0x5598742',
                                   '0x559874a',
                                   '0x5598757',
                                   '0x559875d',
                                   '0x5598765',
                                   '0x559879e',
                                   '0x55987b1'],
                      'lea_r8_row': '0x559879e',
                      'park_memcpy': [208, 473, 255],
                      'park_memcpy_call': '0x5598712',
                      'producer_call': '0x55986ce',
                      'producer_target': '0x5490660',
                      'record_disp': '0x1d0',
                      'shape': 'Y',
                      'site': '0x55987b1',
                      'tag_store': '0x559875d',
                      'tail_memcpy': [473, 208, 255],
                      'tail_memcpy_call': '0x5598757',
                      'wrapper': 'jc2wb'},
                     {'byte_store': '0x560a0d8',
                      'caller': 'bwc_b4',
                      'key_rows': ['0x560a073',
                                   '0x560a078',
                                   '0x560a07d',
                                   '0x560a084',
                                   '0x560a0a8',
                                   '0x560a0ad',
                                   '0x560a0ba',
                                   '0x560a0d0',
                                   '0x560a0d8',
                                   '0x560a0e0',
                                   '0x560a0e8',
                                   '0x560a0f5',
                                   '0x560a124',
                                   '0x560a132'],
                      'lea_r8_row': '0x560a124',
                      'producer_call': '0x560a084',
                      'producer_target': '0x5492440',
                      'record_disp': '0x190',
                      'scratch_memcpy': [681, 121, 271],
                      'scratch_memcpy_call': '0x560a0ba',
                      'shape': 'X',
                      'site': '0x560a132',
                      'tag_store': '0x560a0d0',
                      'tail_memcpy': [409, 681, 271],
                      'tail_memcpy_call': '0x560a0f5',
                      'wrapper': 'jc2wb'},
                     {'byte_store': '0x54d1e50',
                      'caller': 'bwc_c1',
                      'key_rows': ['0x54d1b68',
                                   '0x54d1b7f',
                                   '0x54d1b87',
                                   '0x54d1b8f',
                                   '0x54d1dd0',
                                   '0x54d1dd8',
                                   '0x54d1e48',
                                   '0x54d1e50',
                                   '0x54d1e5d',
                                   '0x54d1e65',
                                   '0x54d1e6d',
                                   '0x54d1eb2',
                                   '0x54d1ebd'],
                      'lea_r8_row': '0x54d1eb2',
                      'producer_call': '0x54d1dd8',
                      'producer_target': '0x5630000',
                      'record_disp': '0xb0',
                      'scratch_memcpy': [1392, 1849, 271],
                      'scratch_memcpy_call': '0x54d1b8f',
                      'shape': 'X',
                      'site': '0x54d1ebd',
                      'tag_store': '0x54d1e48',
                      'tail_memcpy': [185, 1392, 271],
                      'tail_memcpy_call': '0x54d1e6d',
                      'wrapper': 'jc3wb'},
                     {'byte_store': '0x5586899',
                      'caller': 'bwc_c2',
                      'key_rows': ['0x5586807',
                                   '0x558680f',
                                   '0x5586853',
                                   '0x558685b',
                                   '0x5586872',
                                   '0x5586875',
                                   '0x5586884',
                                   '0x5586891',
                                   '0x5586899',
                                   '0x55868a5',
                                   '0x55868ad',
                                   '0x55868b0',
                                   '0x55868ea',
                                   '0x55868f5'],
                      'lea_r8_row': '0x55868ea',
                      'producer_call': '0x558685b',
                      'producer_target': '0x5630000',
                      'record_disp': '0xb0',
                      'scratch_memcpy': [1312, 745, 271],
                      'scratch_memcpy_call': '0x5586884',
                      'shape': 'X',
                      'site': '0x55868f5',
                      'tag_store': '0x5586891',
                      'tail_memcpy': [185, 'reg:r15', 271],
                      'tail_memcpy_call': '0x55868b0',
                      'wrapper': 'jc3wb'},
                     {'byte_store': '0x5586dea',
                      'caller': 'bwc_c2',
                      'key_rows': ['0x5586d7f',
                                   '0x5586d87',
                                   '0x5586d8f',
                                   '0x5586d97',
                                   '0x5586dc3',
                                   '0x5586dc6',
                                   '0x5586dd5',
                                   '0x5586de2',
                                   '0x5586dea',
                                   '0x5586df6',
                                   '0x5586dfe',
                                   '0x5586e01',
                                   '0x5586e3b',
                                   '0x5586e46'],
                      'lea_r8_row': '0x5586e3b',
                      'producer_call': '0x5586d97',
                      'producer_target': '0x5492440',
                      'record_disp': '0xb0',
                      'scratch_memcpy': [1312, 745, 271],
                      'scratch_memcpy_call': '0x5586dd5',
                      'shape': 'X',
                      'site': '0x5586e46',
                      'tag_store': '0x5586de2',
                      'tail_memcpy': [185, 'reg:r15', 271],
                      'tail_memcpy_call': '0x5586e01',
                      'wrapper': 'jc3wb'},
                     {'byte_store': '0x559c5d5',
                      'caller': 'bwc_c3',
                      'key_rows': ['0x559c52b',
                                   '0x559c533',
                                   '0x559c53b',
                                   '0x559c53e',
                                   '0x559c56d',
                                   '0x559c575',
                                   '0x559c582',
                                   '0x559c5b2',
                                   '0x559c5ba',
                                   '0x559c5c7',
                                   '0x559c5cd',
                                   '0x559c5d5',
                                   '0x559c60e',
                                   '0x559c621'],
                      'lea_r8_row': '0x559c60e',
                      'park_memcpy': [208, 473, 255],
                      'park_memcpy_call': '0x559c582',
                      'producer_call': '0x559c53e',
                      'producer_target': '0x5490660',
                      'record_disp': '0x1d0',
                      'shape': 'Y',
                      'site': '0x559c621',
                      'tag_store': '0x559c5cd',
                      'tail_memcpy': [473, 208, 255],
                      'tail_memcpy_call': '0x559c5c7',
                      'wrapper': 'jc3wb'},
                     {'byte_store': '0x5609f18',
                      'caller': 'bwc_c4',
                      'key_rows': ['0x5609eb3',
                                   '0x5609eb8',
                                   '0x5609ebd',
                                   '0x5609ec4',
                                   '0x5609ee8',
                                   '0x5609eed',
                                   '0x5609efa',
                                   '0x5609f10',
                                   '0x5609f18',
                                   '0x5609f20',
                                   '0x5609f28',
                                   '0x5609f35',
                                   '0x5609f64',
                                   '0x5609f72'],
                      'lea_r8_row': '0x5609f64',
                      'producer_call': '0x5609ec4',
                      'producer_target': '0x5492440',
                      'record_disp': '0x190',
                      'scratch_memcpy': [681, 121, 271],
                      'scratch_memcpy_call': '0x5609efa',
                      'shape': 'X',
                      'site': '0x5609f72',
                      'tag_store': '0x5609f10',
                      'tail_memcpy': [409, 681, 271],
                      'tail_memcpy_call': '0x5609f35',
                      'wrapper': 'jc3wb'}],
 'censuses': {'decode': {'e8': {'0x2b92afb': 'dc_o1',
                                '0x2bb764b': 'sublookup_ca',
                                '0x2bb7747': 'sublookup_ca',
                                '0x2bb8052': 'sublookup_ca',
                                '0x2bb82eb': 'sublookup_ca',
                                '0x2bb83d6': 'sublookup_ca',
                                '0x2bb85ab': 'sublookup_ca',
                                '0x2bb8696': 'sublookup_ca',
                                '0x2bb8735': 'sublookup_ca',
                                '0x2bbbe7d': 'inner_ca',
                                '0x2bbbf9b': 'inner_ca',
                                '0x2bbd3ad': 'inner_s3',
                                '0x2c61d40': 'dc_o2',
                                '0x2c62b1b': 'helper_s3a',
                                '0x2c633a1': 'helper_s3a',
                                '0x2c63a66': 'helper_s3a',
                                '0x2c63c8e': 'helper_s3a',
                                '0x2dc3a96': 'dc_ca'}},
              'giant_s1a': {'e8': {'0x28ce0e4': 'giant_s1a',
                                   '0x29139e4': 'gc_a1',
                                   '0x2913fe2': 'gc_a1',
                                   '0x2bf0528': 'gc_a2'}},
              'giant_s1b': {'e8': {'0x50d41cb': 'gc_b1',
                                   '0x50d47c2': 'gc_b1',
                                   '0x538d66c': 'giant_s1b',
                                   '0x54cd7e9': 'gc_b2'}},
              'giant_s1c': {'e8': {'0x50d37bb': 'gc_c1',
                                   '0x50d3db2': 'gc_c1',
                                   '0x539848c': 'giant_s1c',
                                   '0x54cd299': 'gc_c2'}},
              'helper_s3a': {'e8': {'0x2c61a1a': '0x2c619b0',
                                    '0x2c61acb': '0x2c619b0',
                                    '0x2c65297': '0x2c64870',
                                    '0x2c65462': '0x2c64870'}},
              'helper_s3b': {'e8': {'0x55dec1a': '0x55debb0',
                                    '0x55deccb': '0x55debb0',
                                    '0x55e4397': '0x55e3770',
                                    '0x55e4562': '0x55e3770'}},
              'jc1wb': {'e8': {'0x2a86709': 'bwc_a1',
                               '0x2a86c5a': 'bwc_a1',
                               '0x2a8bdc2': 'bwc_a2',
                               '0x2c3ec71': 'bwc_a3'}},
              'jc2wb': {'e8': {'0x54d7b9a': 'bwc_b1',
                               '0x55837e5': 'bwc_b2',
                               '0x5583d36': 'bwc_b2',
                               '0x55987b1': 'bwc_b3',
                               '0x560a132': 'bwc_b4'}},
              'jc3wb': {'e8': {'0x54d1ebd': 'bwc_c1',
                               '0x55868f5': 'bwc_c2',
                               '0x5586e46': 'bwc_c2',
                               '0x559c621': 'bwc_c3',
                               '0x5609f72': 'bwc_c4'}},
              'sublookup_ca': {'e8': {'0x27626a6': '0x2762570'}},
              'sublookup_jc1': {'e8': {'0x27623ae': '0x27622f0'}}},
 'decode': {'imul_0xb8_rows': ['0x24cb10c',
                               '0x24cb124',
                               '0x24cb151',
                               '0x24cb18c',
                               '0x24cb1a4',
                               '0x24cb1bd']},
 'giant_caller_sites': [{'caller': 'gc_a1',
                         'giant': 'giant_s1a',
                         'key_rows': ['0x29139d6', '0x29139de', '0x29139e1', '0x29139e4'],
                         'rdi': 'reg:rbx',
                         'rdx': 'reg:r14',
                         'rsi': 128,
                         'site': '0x29139e4'},
                        {'caller': 'gc_a1',
                         'giant': 'giant_s1a',
                         'key_rows': ['0x2913fd4', '0x2913fdc', '0x2913fdf', '0x2913fe2'],
                         'rdi': 'reg:rbx',
                         'rdx': 'reg:r14',
                         'rsi': 128,
                         'site': '0x2913fe2'},
                        {'caller': 'gc_a2',
                         'giant': 'giant_s1a',
                         'key_rows': ['0x2bf04ff',
                                      '0x2bf0502',
                                      '0x2bf0515',
                                      '0x2bf051d',
                                      '0x2bf0520',
                                      '0x2bf0528'],
                         'rdi': 1072,
                         'rdx': None,
                         'rsi': 0,
                         'site': '0x2bf0528'},
                        {'caller': 'gc_b1',
                         'giant': 'giant_s1b',
                         'key_rows': ['0x50d4184',
                                      '0x50d4188',
                                      '0x50d41bd',
                                      '0x50d41c5',
                                      '0x50d41c8',
                                      '0x50d41cb'],
                         'rdi': 'reg:rbx',
                         'rdx': 'reg:r14',
                         'rsi': 128,
                         'site': '0x50d41cb'},
                        {'caller': 'gc_b1',
                         'giant': 'giant_s1b',
                         'key_rows': ['0x50d47b4', '0x50d47bc', '0x50d47bf', '0x50d47c2'],
                         'rdi': 'reg:rbx',
                         'rdx': 'reg:r14',
                         'rsi': 128,
                         'site': '0x50d47c2'},
                        {'caller': 'gc_b2',
                         'giant': 'giant_s1b',
                         'key_rows': ['0x54cd7a3',
                                      '0x54cd7a8',
                                      '0x54cd7ab',
                                      '0x54cd7bb',
                                      '0x54cd7c5',
                                      '0x54cd7ca',
                                      '0x54cd7d7',
                                      '0x54cd7df',
                                      '0x54cd7e4',
                                      '0x54cd7e9'],
                         'rdi': 384,
                         'rdx': None,
                         'rsi': 64,
                         'site': '0x54cd7e9'},
                        {'caller': 'gc_c1',
                         'giant': 'giant_s1c',
                         'key_rows': ['0x50d3774',
                                      '0x50d3778',
                                      '0x50d37ad',
                                      '0x50d37b5',
                                      '0x50d37b8',
                                      '0x50d37bb'],
                         'rdi': 'reg:rbx',
                         'rdx': 'reg:r14',
                         'rsi': 128,
                         'site': '0x50d37bb'},
                        {'caller': 'gc_c1',
                         'giant': 'giant_s1c',
                         'key_rows': ['0x50d3da4', '0x50d3dac', '0x50d3daf', '0x50d3db2'],
                         'rdi': 'reg:rbx',
                         'rdx': 'reg:r14',
                         'rsi': 128,
                         'site': '0x50d3db2'},
                        {'caller': 'gc_c2',
                         'giant': 'giant_s1c',
                         'key_rows': ['0x54cd253',
                                      '0x54cd258',
                                      '0x54cd25b',
                                      '0x54cd26b',
                                      '0x54cd275',
                                      '0x54cd27a',
                                      '0x54cd287',
                                      '0x54cd28f',
                                      '0x54cd294',
                                      '0x54cd299'],
                         'rdi': 384,
                         'rdx': None,
                         'rsi': 64,
                         'site': '0x54cd299'}],
 'giants': {'giant_s1a': {'argbuf_lo': 3296,
                          'argbuf_stores': [['0x28cfb61', '0xd40'],
                                            ['0x28cfb6e', '0xd30'],
                                            ['0x28cfb7b', '0xd20'],
                                            ['0x28cfb9b', '0xd10'],
                                            ['0x28cfba4', '0xd00'],
                                            ['0x28cfbad', '0xcf0'],
                                            ['0x28cfbb6', '0xce0']],
                          'frame': 3656,
                          'tail_lo': 3401},
            'giant_s1b': {'argbuf_lo': 3264,
                          'argbuf_stores': [['0x538f103', '0xd20'],
                                            ['0x538f110', '0xd10'],
                                            ['0x538f11d', '0xd00'],
                                            ['0x538f13d', '0xcf0'],
                                            ['0x538f146', '0xce0'],
                                            ['0x538f14f', '0xcd0'],
                                            ['0x538f158', '0xcc0']],
                          'frame': 3624,
                          'tail_lo': 3369},
            'giant_s1c': {'argbuf_lo': 3264,
                          'argbuf_stores': [['0x5399f23', '0xd20'],
                                            ['0x5399f30', '0xd10'],
                                            ['0x5399f3d', '0xd00'],
                                            ['0x5399f5d', '0xcf0'],
                                            ['0x5399f66', '0xce0'],
                                            ['0x5399f6f', '0xcd0'],
                                            ['0x5399f78', '0xcc0']],
                          'frame': 3624,
                          'tail_lo': 3369}},
 'helper_r14_stores': {'helper_s3a': ['0x2c64200', '0x2c6442d', '0x2c645f8', '0x2c646a6'],
                       'helper_s3b': ['0x55e3100', '0x55e332d', '0x55e34f8', '0x55e35a6']},
 'memcpy_census': {'helper_s3a': {'call_sites': ['0x2c638c3',
                                                 '0x2c64076',
                                                 '0x2c640ab',
                                                 '0x2c642de',
                                                 '0x2c64330',
                                                 '0x2c643fb',
                                                 '0x2c646ca',
                                                 '0x2c64711',
                                                 '0x2c6474c',
                                                 '0x2c64825'],
                                  'ff15_calls': ['0x2c638c3',
                                                 '0x2c64076',
                                                 '0x2c640ab',
                                                 '0x2c643fb',
                                                 '0x2c646ca',
                                                 '0x2c64711',
                                                 '0x2c6474c',
                                                 '0x2c64825'],
                                  'slot_loads': ['0x2c642d7'],
                                  'table': {'0x2c638c3': [1137, 2026, 255],
                                            '0x2c64076': [1408, 649, 167],
                                            '0x2c640ab': [961, 1408, 167],
                                            '0x2c642de': [1800, 1408, 167],
                                            '0x2c64330': [169, 'reg:rbx', 223],
                                            '0x2c643fb': [2026, 169, 255],
                                            '0x2c646ca': [2281, 2026, 223],
                                            '0x2c64711': [1577, 2281, 223],
                                            '0x2c6474c': ['lea:r15+0x9', 1577, 167],
                                            '0x2c64825': [1137, 2026, 255]}},
                   'helper_s3b': {'call_sites': ['0x55e2783',
                                                 '0x55e2f6b',
                                                 '0x55e2fa0',
                                                 '0x55e31de',
                                                 '0x55e3230',
                                                 '0x55e32fb',
                                                 '0x55e35ca',
                                                 '0x55e3611',
                                                 '0x55e364c',
                                                 '0x55e3725'],
                                  'ff15_calls': ['0x55e2783',
                                                 '0x55e2f6b',
                                                 '0x55e2fa0',
                                                 '0x55e32fb',
                                                 '0x55e35ca',
                                                 '0x55e3611',
                                                 '0x55e364c',
                                                 '0x55e3725'],
                                  'slot_loads': ['0x55e31d7'],
                                  'table': {'0x55e2783': [1153, 2042, 255],
                                            '0x55e2f6b': [1424, 665, 167],
                                            '0x55e2fa0': [977, 1424, 167],
                                            '0x55e31de': [1816, 1424, 167],
                                            '0x55e3230': [169, 'reg:rbx', 223],
                                            '0x55e32fb': [2042, 169, 255],
                                            '0x55e35ca': [2297, 2042, 223],
                                            '0x55e3611': [1593, 2297, 223],
                                            '0x55e364c': ['lea:r15+0x9', 1593, 167],
                                            '0x55e3725': [1153, 2042, 255]}},
                   'sublookup_ca': {'call_sites': ['0x2bb7dc5',
                                                   '0x2bb8b0d',
                                                   '0x2bb8b3f',
                                                   '0x2bb8d12',
                                                   '0x2bb8d64',
                                                   '0x2bb8e1f',
                                                   '0x2bb97c4',
                                                   '0x2bb9851'],
                                    'ff15_calls': ['0x2bb7dc5',
                                                   '0x2bb8e1f',
                                                   '0x2bb97c4',
                                                   '0x2bb9851'],
                                    'slot_loads': ['0x2bb8b06', '0x2bb8d0b'],
                                    'table': {'0x2bb7dc5': [1233, 1897, 255],
                                              '0x2bb8b0d': [1504, 649, 167],
                                              '0x2bb8b3f': [1057, 1504, 167],
                                              '0x2bb8d12': [1672, 1504, 167],
                                              '0x2bb8d64': [329, 'reg:r12', 223],
                                              '0x2bb8e1f': [1897, 329, 255],
                                              '0x2bb97c4': ['lea:rbx+0x8', 1232, 272],
                                              '0x2bb9851': [1233, 1897, 255]}},
                   'sublookup_jc1': {'call_sites': ['0x2bb59b0',
                                                    '0x2bb6715',
                                                    '0x2bb680c',
                                                    '0x2bb6892'],
                                     'ff15_calls': ['0x2bb59b0',
                                                    '0x2bb6715',
                                                    '0x2bb680c',
                                                    '0x2bb6892'],
                                     'slot_loads': [],
                                     'table': {'0x2bb59b0': [1401, 1673, 255],
                                               '0x2bb6715': [1673, 401, 255],
                                               '0x2bb680c': ['lea:rbx+0x8', 1400, 272],
                                               '0x2bb6892': [1401, 1673, 255]}}},
 'staging': {'sublookup_ca_inner_all_phases_count': 35,
             'sublookup_ca_inner_final_phase': [['0x2bb8d40', '0x140'],
                                                ['0x2bb8d4d', '0x148'],
                                                ['0x2bb8d67', '0x228']],
             'sublookup_ca_middle': [],
             'sublookup_ca_staging': [['0x2bb72f7', '0x4c8'],
                                      ['0x2bb7d9b', '0x4c8'],
                                      ['0x2bb7da8', '0x4d0'],
                                      ['0x2bb7dd3', '0x5d0'],
                                      ['0x2bb7de0', '0x5d8'],
                                      ['0x2bb982c', '0x4c8'],
                                      ['0x2bb9834', '0x4d0'],
                                      ['0x2bb985f', '0x5d0'],
                                      ['0x2bb986c', '0x5d8']],
             'sublookup_jc1_staging': [['0x2bb532c', '0x570'],
                                       ['0x2bb598a', '0x570'],
                                       ['0x2bb5994', '0x578'],
                                       ['0x2bb59be', '0x678'],
                                       ['0x2bb59cb', '0x680'],
                                       ['0x2bb686d', '0x570'],
                                       ['0x2bb6875', '0x578'],
                                       ['0x2bb68a0', '0x678'],
                                       ['0x2bb68ad', '0x680']],
             'sublookup_jc1_tail_beyond_head': []}}


def _hx(value):
    return f'0x{value:x}'


def _section_bytes(data, secs, start, end):
    for sec in secs:
        if sec['type'] != 8 and sec['address'] <= start \
                and end <= sec['address'] + sec['size']:
            off = sec['offset'] + (start - sec['address'])
            return data[off:off + end - start]
    raise AssertionError(f'no file-backed section covers {start:#x}..{end:#x}')


def _digest(data, secs, start, end):
    return hashlib.sha256(_section_bytes(data, secs, start, end)).hexdigest()


_LINE_RE = re.compile(r'^\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*(?:\t(.*))?$')


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
    last = None
    for line in out.splitlines():
        match = _LINE_RE.match(line)
        if not match:
            continue
        addr = int(match.group(1), 16)
        raw = re.sub(r'\s', '', match.group(2))
        text = (match.group(3) or '').strip().split('#')[0].rstrip()
        if not text and last is not None \
                and addr == last + len(bytes.fromhex(rows[last][0])):
            rows[last] = (rows[last][0] + raw, rows[last][1])
        else:
            rows[addr] = (raw, text)
            last = addr
    cursor = start
    for addr in sorted(rows):
        if addr != cursor:
            raise AssertionError(f'decode gap at {addr:#x} != {cursor:#x}')
        cursor += len(bytes.fromhex(rows[addr][0]))
    if cursor != end:
        raise AssertionError(f'decode ends at {cursor:#x} != {end:#x}')
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


def _check_pins_subset(rows, pins, what):
    for address, want in pins.items():
        if rows.get(address) != want:
            raise AssertionError(
                f'{what} instruction at {address:#x} differs: '
                f'{rows.get(address)!r} != {want!r}')
    return rows


def _rela_entries(data, secs):
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


def _slot_fact(data, secs, relas, slot, want_type, want_sym=None):
    hits = [e for e in relas if e[0] == slot]
    if len(hits) != 1:
        raise AssertionError(f'slot {_hx(slot)} has {len(hits)} relocations')
    _off, rtype, sym, addend = hits[0]
    if rtype != want_type:
        raise AssertionError(f'slot {_hx(slot)} relocation type is {rtype}')
    fact = {'slot': _hx(slot), 'rela_type': rtype}
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

_REG_WIDTH = {}
for _base in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'):
    _REG_WIDTH[_base] = 8
for _i in range(8, 16):
    _REG_WIDTH[f'r{_i}'] = 8
for _n32 in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'):
    _REG_WIDTH[_n32] = 4
for _i in range(8, 16):
    _REG_WIDTH[f'r{_i}d'] = 4
    _REG_WIDTH[f'r{_i}w'] = 2
    _REG_WIDTH[f'r{_i}b'] = 1
for _n16 in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'):
    _REG_WIDTH[_n16] = 2
for _n8 in ('al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh',
            'sil', 'dil', 'bpl', 'spl'):
    _REG_WIDTH[_n8] = 1

_MEMFULL_RE = re.compile(
    r'^(-?0x[0-9a-f]+)?\(%([a-z0-9]+)(?:,%([a-z0-9]+)(?:,([0-9]+))?)?\)$')
_STORE_BASES = {'mov', 'movabs', 'movups', 'movaps', 'movdqa', 'movdqu',
                'movupd', 'movapd', 'movsd', 'movss'}
_XMM_STORES = {'movups', 'movaps', 'movdqa', 'movdqu', 'movupd', 'movapd'}


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


def _base_mnem(mnem):
    if mnem in _STORE_BASES:
        return mnem
    if mnem and mnem[-1] in 'bwlq' and mnem[:-1] in _STORE_BASES:
        return mnem[:-1]
    return mnem


def _store_width(mnem, base_mnem, src_tok):
    if base_mnem in _XMM_STORES:
        return 16
    if mnem != base_mnem and mnem[-1] in 'bwlq':
        return {'b': 1, 'w': 2, 'l': 4, 'q': 8}[mnem[-1]]
    if src_tok.startswith('%xmm'):
        return 16
    if src_tok.startswith('%'):
        return _REG_WIDTH.get(src_tok[1:], 8)
    return 8


def _stores(rows):
    """All stores to memory: (addr, disp, base_reg, width, text)."""
    out = []
    for addr in sorted(rows):
        _b, text = rows[addr]
        mnem, ops = _split_ops(text)
        base_mnem = _base_mnem(mnem)
        if base_mnem not in _STORE_BASES or len(ops) < 2:
            continue
        match = _MEMFULL_RE.match(ops[-1])
        if not match:
            continue
        disp = int(match.group(1), 16) if match.group(1) else 0
        if match.group(1) and match.group(1).startswith('-'):
            disp = -int(match.group(1)[1:], 16)
        base = _REG64.get(match.group(2), match.group(2))
        out.append((addr, disp, base,
                    _store_width(mnem, base_mnem, ops[0]), text))
    return out


def _rsp_stores_in(rows, lo, hi):
    return [[_hx(a), _hx(d)] for (a, d, b, _w, _t) in _stores(rows)
            if b == 'rsp' and lo <= d < hi]


def _slot_refs(rows, slot):
    """(ff15 call sites, register-load sites) referencing `slot`."""
    calls, loads = [], []
    for addr in sorted(rows):
        raw, _text = rows[addr]
        blob = bytes.fromhex(raw)
        if raw.startswith('ff15') and len(blob) == 6:
            if addr + 6 + struct.unpack('<i', blob[2:6])[0] == slot:
                calls.append(addr)
        elif len(blob) == 7 and blob[0] in (0x48, 0x4C) and blob[1] == 0x8B \
                and (blob[2] & 0xC7) == 0x05:
            if addr + 7 + struct.unpack('<i', blob[3:7])[0] == slot:
                loads.append(addr)
    return calls, loads


def _binding_before(rows, reg, before, window=10):
    addrs = [a for a in sorted(rows) if a < before][-window:]
    found = {}
    for addr in addrs:
        _b, text = rows[addr]
        mnem, ops = _split_ops(text)
        if len(ops) < 2:
            continue
        dst = ops[-1]
        if not dst.startswith('%'):
            continue
        dst_reg = _REG64.get(dst[1:])
        if dst_reg is None or dst_reg == 'rsp':
            continue
        src = ops[0]
        lea = _MEMFULL_RE.match(src)
        if mnem == 'lea' and lea and _REG64.get(lea.group(2)) == 'rsp' \
                and not lea.group(3):
            disp = int(lea.group(1), 16) if lea.group(1) else 0
            found[dst_reg] = ('stack', disp)
        elif mnem == 'lea' and lea and not lea.group(3):
            base = _REG64.get(lea.group(2))
            disp = int(lea.group(1), 16) if lea.group(1) else 0
            found[dst_reg] = ('lea', base, disp)
        elif src.startswith('%'):
            src_reg = _REG64.get(src[1:])
            if src_reg == 'rsp':
                found[dst_reg] = ('stack', 0)
            elif src_reg in found:
                found[dst_reg] = found[src_reg]
            else:
                found[dst_reg] = ('reg', src_reg)
        elif src.startswith('$'):
            found[dst_reg] = ('imm', int(src[1:], 16))
        else:
            found.pop(dst_reg, None)
    return found.get(reg)


def _fmt_bind(value):
    if value is None:
        return None
    if value[0] in ('stack', 'imm'):
        return value[1]
    if value[0] == 'reg':
        return 'reg:' + value[1]
    if value[0] == 'lea':
        return f'lea:{value[1]}+{value[2]:#x}'
    return str(value)


def _memcpy_args(rows, call_addr):
    return (_fmt_bind(_binding_before(rows, 'rdi', call_addr)),
            _fmt_bind(_binding_before(rows, 'rsi', call_addr)),
            _fmt_bind(_binding_before(rows, 'rdx', call_addr)))


def _memcpy_census(rows):
    """All memcpy executions: ff15 slot calls + `call *%r14` rows (the
    slot pointer loaded into r14), as {site: [dst, src, size]}."""
    calls, loads = _slot_refs(rows, MEMCPY_SLOT)
    sites = set(calls)
    for addr in sorted(rows):
        if rows[addr][1] == 'call   *%r14':
            sites.add(addr)
    table = {}
    for site in sorted(sites):
        table[_hx(site)] = list(_memcpy_args(rows, site))
    return {'ff15_calls': [_hx(a) for a in calls],
            'slot_loads': [_hx(a) for a in loads],
            'call_sites': [_hx(a) for a in sorted(sites)],
            'table': table}


def _e8_target(rows, addr):
    raw, _text = rows[addr]
    return addr + 5 + struct.unpack('<i', bytes.fromhex(raw[2:10]))[0]


def _census(data, secs, ordered, decoded, targets):
    """Binary-wide E8/E9 census for {target_va: name}.

    Returns {name: {'e8': {site: containing packet body or FDE start},
    'e9': [site]}}. Every E8 site inside a packet body is validated
    against that body's decode.
    """
    import bisect
    text_sec = next(s for s in secs if s['name'] == '.text')
    tbody = _section_bytes(data, secs, text_sec['address'],
                           text_sec['address'] + text_sec['size'])
    tva = text_sec['address']
    starts = [o['start'] for o in ordered]
    body_of = {}
    for name, body in BODIES.items():
        lo, hi = body['range']
        body_of[name] = (lo, hi)

    def container(va):
        for name, (lo, hi) in body_of.items():
            if lo <= va < hi:
                return name
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and ordered[i]['start'] <= va < ordered[i]['end']:
            return ordered[i]['start']
        return None

    out = {name: {'e8': {}, 'e9': []} for name in targets.values()}
    for i in range(len(tbody) - 5):
        opcode = tbody[i]
        if opcode not in (0xE8, 0xE9):
            continue
        site = tva + i
        tgt = site + 5 + struct.unpack_from('<i', tbody, i + 1)[0]
        if tgt not in targets:
            continue
        name = targets[tgt]
        if opcode == 0xE9:
            out[name]['e9'].append(site)
            continue
        holder = container(site)
        if isinstance(holder, str):
            rows = decoded[holder]
            if site not in rows or not rows[site][1].startswith('call') \
                    or _e8_target(rows, site) != tgt:
                raise AssertionError(
                    f'E8 site {_hx(site)} in {holder} does not decode '
                    f'as a call to {_hx(tgt)}')
        out[name]['e8'][site] = holder
    return out


def _lea_named(decoded, target_starts):
    """Rip-relative lea rows inside packet bodies naming a target."""
    hits = []
    for name, rows in decoded.items():
        for addr in sorted(rows):
            raw, text = rows[addr]
            blob = bytes.fromhex(raw)
            if len(blob) == 7 and blob[0] in (0x48, 0x4C) \
                    and blob[1] == 0x8D and (blob[2] & 0xC7) == 0x05:
                tgt = addr + 7 + struct.unpack('<i', blob[3:7])[0]
                if tgt in target_starts:
                    hits.append([name, _hx(addr)])
    return hits


def analyze(data):
    secs = sections(data)
    _summary, ordered, _gaps = fde_extents(data)
    fde_set = {(o['start'], o['end']) for o in ordered}
    relas = _rela_entries(data, secs)

    decoded = {}
    bodies_rec = {}
    for name, body in BODIES.items():
        lo, hi = body['range']
        if (lo, hi) not in fde_set:
            raise AssertionError(f'{name} range is not an FDE extent')
        digest = _digest(data, secs, lo, hi)
        if digest != body['sha256']:
            raise AssertionError(f'{name} digest drift: {digest}')
        rows = _decode(data, secs, lo, hi)
        if name in PINNED_ROWS_FULL:
            _check_pins(rows, PINNED_ROWS_FULL[name], name)
        if name in PINNED_ROWS_PARTIAL:
            _check_pins_subset(rows, PINNED_ROWS_PARTIAL[name], name)
        decoded[name] = rows
        bodies_rec[name] = {'range': [_hx(lo), _hx(hi)],
                            'sha256': digest,
                            'role': body['role'],
                            'exported': body['exported']}

    slot_fact = _slot_fact(data, secs, relas, MEMCPY_SLOT, 6,
                           want_sym='memcpy')

    targets = {DECODE_BODY: 'decode'}
    for nm in ('jc1wb', 'jc2wb', 'jc3wb', 'giant_s1a', 'giant_s1b',
               'giant_s1c', 'sublookup_ca', 'sublookup_jc1',
               'helper_s3a', 'helper_s3b'):
        targets[BODIES[nm]['range'][0]] = nm
    census = _census(data, secs, ordered, decoded, targets)
    for nm, want in EXPECTED['censuses'].items():
        got = census[nm]
        got_e8 = {_hx(s): (h if isinstance(h, str) else _hx(h))
                  for s, h in got['e8'].items()}
        if got_e8 != want['e8'] or got['e9'] != []:
            raise AssertionError(
                f'caller census drift for {nm}: {got_e8} / {got["e9"]}')
    rela_named = [[_hx(off), _hx(add)] for (off, typ, _sym, add) in relas
                  if typ == 1 and add in targets]
    if rela_named:
        raise AssertionError(f'RELATIVE relocations name targets: {rela_named}')
    lea_named = _lea_named(decoded, set(targets))
    if lea_named:
        raise AssertionError(f'lea rows name targets: {lea_named}')

    # (ii) the decode body: a pure search.
    decode_rows = decoded['decode']
    decode_stores = _stores(decode_rows)
    if decode_stores:
        raise AssertionError(f'decode body stores: {decode_stores}')
    imul_rows = [_hx(a) for a in sorted(decode_rows)
                 if '$0xb8' in decode_rows[a][1]]
    if imul_rows != EXPECTED['decode']['imul_0xb8_rows']:
        raise AssertionError(f'decode imul rows drift: {imul_rows}')

    # memcpy censuses of the four record-chain bodies.
    memcpy_rec = {}
    for nm in ('sublookup_ca', 'sublookup_jc1', 'helper_s3a', 'helper_s3b'):
        got = _memcpy_census(decoded[nm])
        if got != EXPECTED['memcpy_census'][nm]:
            raise AssertionError(f'memcpy census drift in {nm}')
        memcpy_rec[nm] = got

    # staging / middle / inner-record store censuses.
    staging = {
        'sublookup_ca_staging': _rsp_stores_in(
            decoded['sublookup_ca'], 0x4C8, 0x5E0),
        'sublookup_ca_middle': _rsp_stores_in(
            decoded['sublookup_ca'], 0x760, 0x878),
        'sublookup_jc1_staging': _rsp_stores_in(
            decoded['sublookup_jc1'], 0x570, 0x688),
        'sublookup_jc1_tail_beyond_head': _rsp_stores_in(
            decoded['sublookup_jc1'], 0x681, 0x788),
        'sublookup_ca_inner_final_phase': [
            [_hx(a), _hx(d)] for (a, d, b, _w, _t)
            in _stores(decoded['sublookup_ca'])
            if b == 'rsp' and 0x140 <= d < 0x250
            and 0x2BB8D30 <= a < 0x2BB8E10],
        'sublookup_ca_inner_all_phases_count': len(_rsp_stores_in(
            decoded['sublookup_ca'], 0x140, 0x250)),
    }
    if staging != EXPECTED['staging']:
        raise AssertionError(f'staging census drift: {staging}')

    # (i) the giants' tail regions and argument buffers.
    giants_rec = {}
    for nm, spec in EXPECTED['giants'].items():
        rows = decoded[nm]
        frame = None
        for a in sorted(rows):
            m = re.search(r'sub\s+\$(0x[0-9a-f]+),%rsp', rows[a][1])
            if m:
                frame = int(m.group(1), 16)
                break
        tail = _rsp_stores_in(rows, spec['tail_lo'], frame)
        argbuf = _rsp_stores_in(rows, spec['argbuf_lo'],
                                spec['argbuf_lo'] + 0x140)
        if frame != spec['frame'] or tail != [] or argbuf != spec['argbuf_stores']:
            raise AssertionError(f'giant census drift in {nm}')
        giants_rec[nm] = {'frame': _hx(frame),
                          'tail_range': [_hx(spec['tail_lo']), _hx(frame)],
                          'tail_direct_stores': tail,
                          'argbuf_range': [_hx(spec['argbuf_lo']),
                                           _hx(spec['argbuf_lo'] + 0x140)],
                          'argbuf_stores': argbuf}

    # helper output-pointer store census.
    r14_rec = {}
    for nm in ('helper_s3a', 'helper_s3b'):
        got = [_hx(a) for (a, _d, b, _w, _t) in _stores(decoded[nm])
               if b == 'r14']
        if got != EXPECTED['helper_r14_stores'][nm]:
            raise AssertionError(f'r14 store census drift in {nm}')
        r14_rec[nm] = got

    # (iv) site records: validate call targets and record bindings.
    def _call_target(body_name, site):
        rows = decoded[body_name]
        if site not in rows or not rows[site][1].startswith('call'):
            raise AssertionError(f'site {_hx(site)} in {body_name} not a call')
        return _e8_target(rows, site)

    bwc_rec = []
    for site_rec in EXPECTED['b_wrapper_sites']:
        caller = site_rec['caller']
        site = int(site_rec['site'], 16)
        if _call_target(caller, site) != BODIES[site_rec['wrapper']]['range'][0]:
            raise AssertionError(f'B-wrapper site {_hx(site)} target drift')
        rows = decoded[caller]
        lea_row = rows[int(site_rec['lea_r8_row'], 16)][1]
        m = re.match(r'lea\s+(0x[0-9a-f]+)\(%rsp\),%r8', lea_row)
        if not m or int(m.group(1), 16) != int(site_rec['record_disp'], 16):
            raise AssertionError(f'lea r8 binding drift at {_hx(site)}')
        for kind in ('tag_store', 'byte_store'):
            addr = int(site_rec[kind], 16)
            want_disp = int(site_rec['record_disp'], 16) \
                + (8 if kind == 'byte_store' else 0)
            hit = [(a, d) for (a, d, b, _w, _t) in _stores(rows)
                   if a == addr and b == 'rsp' and d == want_disp]
            if not hit:
                raise AssertionError(f'{kind} drift at {_hx(site)}')
        tail = _memcpy_args(rows, int(site_rec['tail_memcpy_call'], 16))
        if list(tail) != site_rec['tail_memcpy']:
            raise AssertionError(f'tail memcpy drift at {_hx(site)}')
        if site_rec['shape'] == 'Y':
            park = _memcpy_args(rows, int(site_rec['park_memcpy_call'], 16))
            if list(park) != site_rec['park_memcpy']:
                raise AssertionError(f'park memcpy drift at {_hx(site)}')
            prod = int(site_rec['producer_call'], 16)
            if _fmt_bind(_binding_before(rows, 'rdi', prod)) \
                    != int(site_rec['record_disp'], 16):
                raise AssertionError(f'producer binding drift at {_hx(site)}')
        bwc_rec.append(site_rec)

    gc_rec = []
    for site_rec in EXPECTED['giant_caller_sites']:
        caller = site_rec['caller']
        site = int(site_rec['site'], 16)
        if _call_target(caller, site) != BODIES[site_rec['giant']]['range'][0]:
            raise AssertionError(f'giant caller site {_hx(site)} target drift')
        gc_rec.append(site_rec)

    counters = {
        'bodies': len(BODIES),
        'exported_bodies': len(EXPORTED),
        'decode_call_sites': len(census['decode']['e8']),
        'b_wrapper_call_sites': sum(
            len(census[nm]['e8']) for nm in ('jc1wb', 'jc2wb', 'jc3wb')),
        'giant_call_sites': sum(
            len(census[nm]['e8'])
            for nm in ('giant_s1a', 'giant_s1b', 'giant_s1c')),
        'b_wrapper_site_records': len(bwc_rec),
        'giant_caller_site_records': len(gc_rec),
        'memcpy_call_sites': sum(
            len(memcpy_rec[nm]['call_sites']) for nm in memcpy_rec),
        'decode_stores': len(decode_stores),
        'giant_tail_stores': sum(
            len(giants_rec[nm]['tail_direct_stores']) for nm in giants_rec),
    }

    return {
        'artifact': {'sha256': ARTIFACT_SHA256, 'size': ARTIFACT_SIZE},
        'bodies': bodies_rec,
        'memcpy_slot': slot_fact,
        'censuses': EXPECTED['censuses'],
        'rela_named_targets': rela_named,
        'lea_named_targets': lea_named,
        'decode_body': {
            'stores': len(decode_stores),
            'imul_0xb8_rows': imul_rows,
            'verdict': 'pure lower_bound over a 0xb8-stride array; '
                       'returns flag in rax and index in rdx; '
                       'produces no record',
        },
        'memcpy_census': memcpy_rec,
        'staging': staging,
        'giants': giants_rec,
        'helper_r14_stores': r14_rec,
        'b_wrapper_sites': bwc_rec,
        'giant_caller_sites': gc_rec,
        'counters': counters,
        'verdict': {
            'giants_tail_source': 'parking buffer: the only writer of '
                                  'the tail region is the park memcpy '
                                  'of the element\'s own tail; zero '
                                  'direct stores in all three giants',
            'decode_body': 'not a decode: a pure search (zero stores) '
                           'whose only outputs are the rax flag and '
                           'the rdx index consumed by the callers',
            'helper_s3_production': 'in-FDE assembly: direct tag/byte '
                                    'stores plus a ten-memcpy chain; '
                                    'the tail is copied, never built '
                                    'per field, and is not a verbatim '
                                    'copy of any single input record',
            'b_wrapper_fifth_argument': 'always a caller-frame record '
                                        '(r8 = lea rsp+disp at all 14 '
                                        'sites), assembled in the '
                                        'caller FDE in the family idiom '
                                        'or produced wholesale by a '
                                        'sibling lookup helper and '
                                        'parked/restored',
            'giant_callers': 'ordinary pointer/context arguments; '
                             'the element record is entirely the '
                             'giant\'s own construction',
            'boundary': 'the internal production of inner bodies '
                        '0x2bbbba0 and 0x2bbd0b0, and the caller '
                        'FDEs\' own lookup-phase inputs',
        },
    }


def _frames(data):
    retained = {tuple(b['range']) for b in BODIES.values()}
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
    for name in EXPORTED:
        start, end = BODIES[name]['range']
        (out_dir / _export_name(name, start, end)).write_text(
            _body_export(data, start, end))
    return records


def main(argv):
    if len(argv) != 3 or argv[1] != 'generate':
        raise SystemExit(
            'usage: innermost_records_static.py generate <out-dir>')
    artifact = ROOT / 'artifacts/node/115/hl-node'
    generate(artifact.read_bytes(), argv[2])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
