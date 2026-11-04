#!/usr/bin/env python3
"""Static evidence for the RE-006 node 115 join helper and element layout.

Answers the two questions left open by RE-006-node115-join-callee
(#2558): what body sits behind the join callee's division helper slot
0x64dfaf8, and who writes the eight element fields the callee
0x36a0d80 reads.

The helper slot resolves from the artifact: it carries exactly one
relocation, an R_X86_64_RELATIVE whose addend 0x63efec0 is an exact
FDE start, and its file-initialised content is zero. The helper body
(0x63efec0..0x63eff7e, 190 bytes) is a register-only unsigned
128-by-128 division routine in the __divti3/__udivti3 shape:
numerator in rdi (low) and rsi (high), denominator in rdx (low) and
rcx (high), quotient returned in rax (low) and rdx (high). It makes
no call, touches no memory, and contains no zero-denominator guard:
a zero denominator reaches a hardware div whose divisor is zero and
traps (#DE). Every other div is guarded by construction (the
single-div path requires numerator-high < denominator-low; the
two-step paths reduce the high half first; the normalised path
divides by a value with its top bit set). The callee's seven call
sites match this contract exactly. A binary-wide modrm census finds
305 rip-relative references to the slot (262 in call form, 43 in mov
form) and zero direct E8 calls to the body: the helper is a shared
division primitive reached only through the slot.

For the element fields, the traced window is the sibling search
0x35bf460, the family fallback 0x4556410, the join callee itself,
its four callers pinned in #2558, and all 63 sibling-search caller
FDEs pinned in #2542. Inside that window the two searches and the
callee write none of the fields (the fallback and the callee make
zero stores; the sibling stores only its four out-record fields),
the joins contain no store at any of the eight displacements
through a non-stack base, and a register-provenance census over all
63 callers finds 76 stores at the eight displacements through
non-stack bases — every one in phases whose base register is not
data-dependent on an imul $0xb0 / imul $0xb8 product in the same
body, i.e. none is an element store. All eight fields are therefore
incoming at the window: they are written before it, by whoever
builds the elements, and the 0xb0 / 0xb8 strides are not unique
enough binary-wide (589 decode-verified imul $0xb8 rows in 226
FDEs) to pin that builder from stride alone.

analyze() validates the artifact without authenticating it (any byte
flip fails the specific check); generate() authenticates first and
regenerates records.json, frames.txt and the two full-body exports
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

PACKET_ID = 'RE-006-node115-join-helper-element'
ARTIFACT_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARTIFACT_SIZE = 105896032
FDE_COUNT = 135313

HELPER_SLOT = 0x64DFAF8
HELPER = {'range': (0x63EFEC0, 0x63EFF7E),
          'sha256': '989c6ef7689fca20c83d7a615696bb50b66e6d650095192c333970f100a4668e'}
HELPER_RETS = [0x63EFF38, 0x63EFF49, 0x63EFF6A, 0x63EFF7D]
HELPER_DIVS = [0x63EFEFC, 0x63EFF44, 0x63EFF5B, 0x63EFF64, 0x63EFF6F, 0x63EFF77]
SLOT_CENSUS = {'references': 305, 'call_opcode_refs': 262,
               'mov_opcode_refs': 43, 'direct_e8_calls': 0}

CALLEE = {'range': (0x36A0D80, 0x36A0FD6),
          'sha256': '7bef359785703ce3ca6bbe09784c734204e78fc47f25759f4d14c08823b6dfc2'}
ELEMENT_OFFSETS = [0x40, 0x58, 0x60, 0x78, 0x80, 0x88, 0x90, 0x98]
ELEMENT_LOADS = {64: [57281934], 88: [57281941], 120: [57282043], 96: [57282047], 144: [57282218], 152: [57282225], 128: [57282242], 136: [57282340]}
CALLEE_HELPER_CALLS = [57281972, 57282078, 57282163, 57282266, 57282327, 57282434, 57282495]

FALLBACK = {'range': (0x4556410, 0x4556544),
            'sha256': '3d150ceb58b41495a86136ef7c0f8b007889d82daeae6284c6916d39c8408fce'}
FALLBACK_IMUL_B8 = [0x455647C, 0x4556494, 0x45564C1, 0x45564FC, 0x4556514, 0x455652D]

SIBLING = {'range': (0x35BF460, 0x35BF4F2),
           'sha256': '10b3b34cb2182f4c9bba0efbb6750ada3ec101615535406c3663df2b09f840ca'}

EXPECTED = {'callee_helper_calls': 7, 'callee_instructions': 167,
            'direct_e8_calls': 0, 'element_derived_stores': 0,
            'element_offsets': 8, 'element_range_stores': 0,
            'fallback_imul_b8': 6, 'fallback_instructions': 89,
            'fallback_stores': 0, 'fde_count': 135313,
            'helper_calls': 0, 'helper_div_sites': 6,
            'helper_instructions': 67, 'helper_memory_operands': 0,
            'helper_rets': 4, 'helper_slot_references': 305,
            'helper_slot_rela_entries': 1, 'sibling_stores': 4,
            'slot_initialised_qword': 0,
            'stores_at_eight_displacements': 76, 'window_callers': 63}

# --- pinned data (extracted from the authenticated artifact) ---
HELPER_PINS = {104791744: ('4989d0', 'mov    %rdx,%r8'),
 104791747: ('4885c9', 'test   %rcx,%rcx'),
 104791750: ('7471', 'je     0x63eff39'),
 104791752: ('4c0fbdc9', 'bsr    %rcx,%r9'),
 104791756: ('4489ca', 'mov    %r9d,%edx'),
 104791759: ('83f23f', 'xor    $0x3f,%edx'),
 104791762: ('b040', 'mov    $0x40,%al'),
 104791764: ('28d0', 'sub    %dl,%al'),
 104791766: ('4c89c2', 'mov    %r8,%rdx'),
 104791769: ('4989cb', 'mov    %rcx,%r11'),
 104791772: ('89c1', 'mov    %eax,%ecx'),
 104791774: ('4c0fadda', 'shrd   %cl,%r11,%rdx'),
 104791778: ('4d89da', 'mov    %r11,%r10'),
 104791781: ('49d3ea', 'shr    %cl,%r10'),
 104791784: ('a840', 'test   $0x40,%al'),
 104791786: ('4c0f44d2', 'cmove  %rdx,%r10'),
 104791790: ('4889f0', 'mov    %rsi,%rax'),
 104791793: ('480fa4f83f', 'shld   $0x3f,%rdi,%rax'),
 104791798: ('4889f2', 'mov    %rsi,%rdx'),
 104791801: ('48d1ea', 'shr    $1,%rdx'),
 104791804: ('49f7f2', 'div    %r10'),
 104791807: ('4989c2', 'mov    %rax,%r10'),
 104791810: ('4489c9', 'mov    %r9d,%ecx'),
 104791813: ('49d3ea', 'shr    %cl,%r10'),
 104791816: ('4983fa01', 'cmp    $0x1,%r10'),
 104791820: ('4983d2ff', 'adc    $0xffffffffffffffff,%r10'),
 104791824: ('4d89d9', 'mov    %r11,%r9'),
 104791827: ('4d0fafca', 'imul   %r10,%r9'),
 104791831: ('4c89c0', 'mov    %r8,%rax'),
 104791834: ('49f7e2', 'mul    %r10'),
 104791837: ('4889c1', 'mov    %rax,%rcx'),
 104791840: ('4c89d0', 'mov    %r10,%rax'),
 104791843: ('4c01ca', 'add    %r9,%rdx'),
 104791846: ('4829cf', 'sub    %rcx,%rdi'),
 104791849: ('4819d6', 'sbb    %rdx,%rsi'),
 104791852: ('4c39c7', 'cmp    %r8,%rdi'),
 104791855: ('4c19de', 'sbb    %r11,%rsi'),
 104791858: ('4883d8ff', 'sbb    $0xffffffffffffffff,%rax'),
 104791862: ('31d2', 'xor    %edx,%edx'),
 104791864: ('c3', 'ret'),
 104791865: ('4c39c6', 'cmp    %r8,%rsi'),
 104791868: ('730c', 'jae    0x63eff4a'),
 104791870: ('4889f8', 'mov    %rdi,%rax'),
 104791873: ('4889f2', 'mov    %rsi,%rdx'),
 104791876: ('49f7f0', 'div    %r8'),
 104791879: ('31d2', 'xor    %edx,%edx'),
 104791881: ('c3', 'ret'),
 104791882: ('4889f0', 'mov    %rsi,%rax'),
 104791885: ('4c09c0', 'or     %r8,%rax'),
 104791888: ('48c1e820', 'shr    $0x20,%rax'),
 104791892: ('7415', 'je     0x63eff6b'),
 104791894: ('4889f0', 'mov    %rsi,%rax'),
 104791897: ('31d2', 'xor    %edx,%edx'),
 104791899: ('49f7f0', 'div    %r8'),
 104791902: ('4889c1', 'mov    %rax,%rcx'),
 104791905: ('4889f8', 'mov    %rdi,%rax'),
 104791908: ('49f7f0', 'div    %r8'),
 104791911: ('4889ca', 'mov    %rcx,%rdx'),
 104791914: ('c3', 'ret'),
 104791915: ('89f0', 'mov    %esi,%eax'),
 104791917: ('31d2', 'xor    %edx,%edx'),
 104791919: ('41f7f0', 'div    %r8d'),
 104791922: ('89c1', 'mov    %eax,%ecx'),
 104791924: ('4889f8', 'mov    %rdi,%rax'),
 104791927: ('49f7f0', 'div    %r8'),
 104791930: ('4889ca', 'mov    %rcx,%rdx'),
 104791933: ('c3', 'ret')}
FALLBACK_PINS = {72705040: ('488b4718', 'mov    0x18(%rdi),%rax'),
 72705044: ('4885c0', 'test   %rax,%rax'),
 72705047: ('0f8497000000', 'je     0x45564b4'),
 72705053: ('488b17', 'mov    (%rdi),%rdx'),
 72705056: ('4c8b4f10', 'mov    0x10(%rdi),%r9'),
 72705060: ('31c9', 'xor    %ecx,%ecx'),
 72705062: ('4939d1', 'cmp    %rdx,%r9'),
 72705065: ('480f43ca', 'cmovae %rdx,%rcx'),
 72705069: ('4929c9', 'sub    %rcx,%r9'),
 72705072: ('4c29ca', 'sub    %r9,%rdx'),
 72705075: ('4989c0', 'mov    %rax,%r8'),
 72705078: ('4929d0', 'sub    %rdx,%r8'),
 72705081: ('0f867c000000', 'jbe    0x45564bb'),
 72705087: ('488b4f08', 'mov    0x8(%rdi),%rcx'),
 72705091: ('4c8b11', 'mov    (%rcx),%r10'),
 72705094: ('488b3e', 'mov    (%rsi),%rdi'),
 72705097: ('4939fa', 'cmp    %rdi,%r10'),
 72705100: ('0f97c0', 'seta   %al'),
 72705103: ('1c00', 'sbb    $0x0,%al'),
 72705105: ('0fb6c0', 'movzbl %al,%eax'),
 72705108: ('84c0', 'test   %al,%al'),
 72705110: ('0f84d0000000', 'je     0x455652c'),
 72705116: ('3dff000000', 'cmp    $0xff,%eax'),
 72705121: ('0f85c6000000', 'jne    0x455652d'),
 72705127: ('31f6', 'xor    %esi,%esi'),
 72705129: ('4983f801', 'cmp    $0x1,%r8'),
 72705133: ('7430', 'je     0x455649f'),
 72705135: ('90', 'nop'),
 72705136: ('4889f0', 'mov    %rsi,%rax'),
 72705139: ('4d89c1', 'mov    %r8,%r9'),
 72705142: ('49d1e9', 'shr    $1,%r9'),
 72705145: ('4c01ce', 'add    %r9,%rsi'),
 72705148: ('4c69d6b8000000', 'imul   $0xb8,%rsi,%r10'),
 72705155: ('4a393c11', 'cmp    %rdi,(%rcx,%r10,1)'),
 72705159: ('480f47f0', 'cmova  %rax,%rsi'),
 72705163: ('4d29c8', 'sub    %r9,%r8'),
 72705166: ('4983f801', 'cmp    $0x1,%r8'),
 72705170: ('77dc', 'ja     0x4556470'),
 72705172: ('4869c6b8000000', 'imul   $0xb8,%rsi,%rax'),
 72705179: ('4c8b1401', 'mov    (%rcx,%rax,1),%r10'),
 72705183: ('4939fa', 'cmp    %rdi,%r10'),
 72705186: ('7404', 'je     0x45564a8'),
 72705188: ('4883d600', 'adc    $0x0,%rsi'),
 72705192: ('31c0', 'xor    %eax,%eax'),
 72705194: ('4939fa', 'cmp    %rdi,%r10'),
 72705197: ('0f95c0', 'setne  %al'),
 72705200: ('4801f2', 'add    %rsi,%rdx'),
 72705203: ('c3', 'ret'),
 72705204: ('31d2', 'xor    %edx,%edx'),
 72705206: ('4531c9', 'xor    %r9d,%r9d'),
 72705209: ('eb06', 'jmp    0x45564c1'),
 72705211: ('4c01c8', 'add    %r9,%rax'),
 72705214: ('4889c2', 'mov    %rax,%rdx'),
 72705217: ('4969c9b8000000', 'imul   $0xb8,%r9,%rcx'),
 72705224: ('48034f08', 'add    0x8(%rdi),%rcx'),
 72705228: ('4c29ca', 'sub    %r9,%rdx'),
 72705231: ('b801000000', 'mov    $0x1,%eax'),
 72705236: ('4885d2', 'test   %rdx,%rdx'),
 72705239: ('7468', 'je     0x4556541'),
 72705241: ('488b36', 'mov    (%rsi),%rsi'),
 72705244: ('31ff', 'xor    %edi,%edi'),
 72705246: ('4883fa01', 'cmp    $0x1,%rdx'),
 72705250: ('7430', 'je     0x4556514'),
 72705252: ('6666662e0f1f84', 'data16 data16 cs nopw 0x0(%rax,%rax,1)'),
 72705264: ('4989f8', 'mov    %rdi,%r8'),
 72705267: ('4989d1', 'mov    %rdx,%r9'),
 72705270: ('49d1e9', 'shr    $1,%r9'),
 72705273: ('4c01cf', 'add    %r9,%rdi'),
 72705276: ('4c69d7b8000000', 'imul   $0xb8,%rdi,%r10'),
 72705283: ('4a393411', 'cmp    %rsi,(%rcx,%r10,1)'),
 72705287: ('490f47f8', 'cmova  %r8,%rdi'),
 72705291: ('4c29ca', 'sub    %r9,%rdx'),
 72705294: ('4883fa01', 'cmp    $0x1,%rdx'),
 72705298: ('77dc', 'ja     0x45564f0'),
 72705300: ('4869d7b8000000', 'imul   $0xb8,%rdi,%rdx'),
 72705307: ('48393411', 'cmp    %rsi,(%rcx,%rdx,1)'),
 72705311: ('7504', 'jne    0x4556525'),
 72705313: ('31c0', 'xor    %eax,%eax'),
 72705315: ('eb04', 'jmp    0x4556529'),
 72705317: ('4883d700', 'adc    $0x0,%rdi'),
 72705321: ('4889fa', 'mov    %rdi,%rdx'),
 72705324: ('c3', 'ret'),
 72705325: ('4969c1b8000000', 'imul   $0xb8,%r9,%rax'),
 72705332: ('4801c1', 'add    %rax,%rcx'),
 72705335: ('b801000000', 'mov    $0x1,%eax'),
 72705340: ('4885d2', 'test   %rdx,%rdx'),
 72705343: ('7598', 'jne    0x45564d9'),
 72705345: ('31d2', 'xor    %edx,%edx'),
 72705347: ('c3', 'ret')}
SIBLING_STORES = {56358107: ('48897008', 'mov    %rsi,0x8(%rax)'),
 56358111: ('48895010', 'mov    %rdx,0x10(%rax)'),
 56358115: ('48897818', 'mov    %rdi,0x18(%rax)'),
 56358119: ('488908', 'mov    %rcx,(%rax)')}
CALLERS = {44602624: ((44602624, 44605440),
            'd33c9906f43bb0c54ab7cf6a21f3b8cd465f135cb9716ea7e4991eefafbb2aa0'),
 49345456: ((49345456, 49346874),
            '2f5fe82fbc64267cdc17936d2556d8453b92cc54a3353e95535ef93ab11453ed'),
 89786336: ((89786336, 89789152),
            '41e588d7db79f90108f6981acc95af94e2534e68a0aa570c5f0270ece139ec5d'),
 89789152: ((89789152, 89791968),
            '1c2af67af44f5fe0dcb0eb706c5b9c2db8d4793c5ac01475387cfe160a6cf0ba')}
WINDOW_CALLERS = {43426704: ((43426704, 43437974),
            '06de78829e95759e4f1712935e669b993b0c04d7b2a0ff3b050c1105086984f1'),
 44305600: ((44305600, 44308339),
            '3957a3c71aafee766dcbdc8ef3ebb9077a80f93e9a6fabd3e71d5846afbce402'),
 44583312: ((44583312, 44584538),
            '468e62dba29282e47e7df69cdd3976ffe4a085f5d574bb439421a193455b7ac9'),
 44584544: ((44584544, 44597918),
            '7bca2f033becd6f8a8f0d184a434cdd74677915f45e0c9ab31aa61970bbaaace'),
 44598144: ((44598144, 44598849),
            'bcefc58ea1c13bb1206e48b94960d6e238bfd00ed0becf3c983fd902f1e705db'),
 44600048: ((44600048, 44600454),
            '2f5873c8fe528a97e867fe94f17712e87751081c2e5d1542dc1744eed214e8d4'),
 44602624: ((44602624, 44605440),
            'd33c9906f43bb0c54ab7cf6a21f3b8cd465f135cb9716ea7e4991eefafbb2aa0'),
 44613120: ((44613120, 44616627),
            '6192142ab8921f4faa4e927aa42bfa0cd9d9f3b2f836dc8f57b66e783d4d4c5f'),
 45689424: ((45689424, 45689830),
            'aedebadcafec4da400cf5d4d264dae1b3987f75683f5bb6316f58f4ec3109ad5'),
 45821632: ((45821632, 45822879),
            '5b9d36f2008924076dd06a912b4a59a9de5572d6807bcd68f0d3f1bebd19c21b'),
 45828288: ((45828288, 45830803),
            '0cf67d77a67aa7eec26d054e0170f0b32a7c78bd0a968d4f729aff2f592a27ba'),
 45830816: ((45830816, 45836502),
            '879e56724ec4d83c7b7ef7699fa08a1f6b3a12ecd72f50972d828c02a5b2fe13'),
 45836512: ((45836512, 45838947),
            '8e8ac1745c108db4edac860064774eac01df8aa454e8c628bcb92d6cf38059a3'),
 45838960: ((45838960, 45848723),
            '6dbf7f8390953d24bdd5b7a225e83f3e1614fb79ee6b3f40d423f8728d44234b'),
 45848736: ((45848736, 45850869),
            'c2a3d152b392078059824faab212a9ffbcce4fe16491afd70a968fd6cf4554e8'),
 45850880: ((45850880, 45854071),
            '19e6440ce606792af59b7315575552b625049198043174ce1c6e84eaa93e7ed1'),
 45857696: ((45857696, 45860685),
            'f3e69ec027f6e24352c49415a533d2cc5e75443ce6681b3c6b51331a3446fa35'),
 45860688: ((45860688, 45863075),
            '1e485c8260263eee0fb80e2871c1aaabde9f381b30e9159662d64e5a991a04fa'),
 45863088: ((45863088, 45865882),
            '889874f504716879ed3af8bfab1a9f7909972bfee409b4125910ce5a114c1a6e'),
 46004464: ((46004464, 46051233),
            '225649f70f438609a3bf19555e1a01ce18bee7dfa80fb5179ba16225e4fa437c'),
 46083792: ((46083792, 46107348),
            '69db6537a973f5c737607109480896d09a8a5aa73b1d7c1df62545dec93ae5b7'),
 46537520: ((46537520, 46539495),
            'fb6986607aeb4f699ed29f505bba328b2ea171995bccc10fd3e418dbed54a2b1'),
 46540832: ((46540832, 46549090),
            '9176b5c3361b91321a3b0cd99c2e90bf4538c1d7b21a68d63f68d5082e33fe96'),
 46553472: ((46553472, 46556500),
            '8a3b9f1d35680656ff9359e45e2720521adb38a8e5f1b590d9e60e66079b7232'),
 46616128: ((46616128, 46617623),
            'dc8264b6c0c30703944687f062ed27ced1685c62a3f221a68320cb65b160fa10'),
 46663280: ((46663280, 46664253),
            '4d3c4952b9d5e9d0cf88f08a64914d3dcc6a6cb100680781629a393bee76dc96'),
 47347488: ((47347488, 47348344),
            '2e3e51ea9925edc38ae111c2eed527b463dadf3d01e73342a90fdca9752a2a1c'),
 49344656: ((49344656, 49345446),
            '7527c800b5be2660d0273e6378896daedc258cd52e89367214ea60f7ac264657'),
 49345456: ((49345456, 49346874),
            '2f5fe82fbc64267cdc17936d2556d8453b92cc54a3353e95535ef93ab11453ed'),
 69317680: ((69317680, 69317780),
            'dc1d9cbbfa71e5780b263613691b403a44cdc84d28601a8b68d0eb74dd82e2e0'),
 72470976: ((72470976, 72471294),
            '483c8bd6b9d6aea9a7ec39c82f170c63b77664d1456b5a153312ab325a43becc'),
 74314096: ((74314096, 74314581),
            'ec255846b32aa9f63ae74c2d33d87ef920d7a98c28fded597398ec419d039d95'),
 88593456: ((88593456, 88594703),
            '99f251194aec2b9806f7214be9231e387233d6766fdcc361da976e4a2299c73f'),
 88594704: ((88594704, 88595951),
            '1bc71e61512042517c11585283630a37d999492fd52d680e762abfd2c08fe259'),
 88665040: ((88665040, 88667172),
            'd7152e5e368f3cc257a2043f31de8bd8d8f87909b49ef60a857da1fa330a1a39'),
 88667184: ((88667184, 88670375),
            '46ac35608029b946108866412311b1b42c3b6c4d178f143e16adbd67139148b2'),
 88671840: ((88671840, 88674702),
            '439fe08e21070afa42fb7028862c87a840aca1f68bbbabde6b6681e099899e64'),
 88674704: ((88674704, 88679476),
            '91beb13ee0905b3db7ef6e6d9d41df49af7f06195fa9f147888c866925b4ae8a'),
 88679488: ((88679488, 88682515),
            '51550e60c680bb4717b73bdacb40ffb13dbc5f8fb1a26dba33ed15356324663f'),
 88682624: ((88682624, 88685613),
            '3f64074e76c5885610e7e95dd1b66853e70f74d1e0b406fb3b9e25ac2c9abae3'),
 88685616: ((88685616, 88688410),
            'ce21c020d8136334be1bb89799253a295aeab1ab10c688d4d5ef4744294f0c9e'),
 88688416: ((88688416, 88690803),
            '22fd22d11c09bf61900af25dcb36f4d1cf63865c696382add27794a1004db4ee'),
 88775792: ((88775792, 88827554),
            'c8b4563b262d24c124d4ee54a7e00146f41aeb8dc57799cdf5db6970562fceac'),
 88827568: ((88827568, 88877800),
            '824ba23a3fbf24fe416e3f682d908c73e0c3504d82c6f1c8f20c79a61ee44d03'),
 88930960: ((88930960, 88954788),
            '824e0d4571ca1e4393eb87acd38dd36b9e9d87e1762905e464cc6942e698b1cf'),
 88954800: ((88954800, 88978548),
            '155583f5bcc0b7aff8164fb7aacf8e4792ba836bb17ae19c2d03e9e437d18ba4'),
 89659360: ((89659360, 89660586),
            '30719705ca79c9df833ed285d0bcf80f7ba0ec00945fb8fe19bb88ae9bdce553'),
 89660592: ((89660592, 89661818),
            '87177643d25d41498450e280c1bd9717c3f9ec57149ed1d7275cc2cb21afad80'),
 89661824: ((89661824, 89674371),
            '0dce413fbb40e408ffca0831ec0ee804509e99cbde0b23f565bbb9b71dd2f19f'),
 89674384: ((89674384, 89686931),
            '0c80314b405562e1053ce3a5195ee216628d43b51d5e84e4833c900b19fe051a'),
 89686944: ((89686944, 89687649),
            '470e47fdb98820789995e8af8e61c8f4b21a856b18da4819457d6753a3b2ea53'),
 89687664: ((89687664, 89688369),
            '31e53fa8e6a4361001bdad968ab282f80d77e425a208ef8b468da0e877bae528'),
 89689488: ((89689488, 89689894),
            'a4a2fc820665cd0f22bb316c80f293f916df39bf6cf3ce78b88ab8cd7f955394'),
 89689904: ((89689904, 89690310),
            'e87be4febe78f09b3bb04b4d9957f496ee75eb0ece386c3fe0a127ba0054f89f'),
 89786336: ((89786336, 89789152),
            '41e588d7db79f90108f6981acc95af94e2534e68a0aa570c5f0270ece139ec5d'),
 89789152: ((89789152, 89791968),
            '1c2af67af44f5fe0dcb0eb706c5b9c2db8d4793c5ac01475387cfe160a6cf0ba'),
 90042320: ((90042320, 90052298),
            '33773d4f76f1b5f3cb9790d204e74484410ba56dedeb90451221ee829c785c64'),
 90052304: ((90052304, 90060642),
            '22651e5a99e6a1279013c659838c4b561df8dd2d2e6ad97b0f8ce31b6b783b30'),
 90065616: ((90065616, 90068944),
            'cebedd523c557782dc620af9901085a0e2370d8e22bf45c02878e9a827bb5a3a'),
 90219856: ((90219856, 90221969),
            '7fb7199c96691c99955b22da9b1899912c4ba2c9bbb4daec7cbd673b2ff67298'),
 90221984: ((90221984, 90224097),
            'f06d8bd576730903b6ab2d962f276d79b8c14f30535152efeebdbeb8b3a11430'),
 94408912: ((94408912, 94409768),
            '31f21a47108d6f188544974541c345ef1b4259a784e42910a0adb9ddbab56bd9'),
 94573168: ((94573168, 94574141),
            '2d161898b46724d10e0874e067ed3d786838d66c7c443c5e7cda20c4b7cbff37')}
STORES8 = [(43426704, 43428392, 64, 'rbx', 'movups %xmm0,0x40(%rbx)'),
 (43426704, 43428416, 96, 'rbx', 'movups %xmm0,0x60(%rbx)'),
 (43426704, 43428436, 128, 'rbx', 'movups %xmm0,0x80(%rbx)'),
 (43426704, 43428443, 144, 'rbx', 'movups %xmm1,0x90(%rbx)'),
 (43426704, 43431847, 64, 'r13', 'mov    %rax,0x40(%r13)'),
 (43426704, 43435802, 120, 'rax', 'movsd  %xmm0,0x78(%rax)'),
 (44305600, 44307544, 96, 'rax', 'movaps %xmm0,0x60(%rax)'),
 (44305600, 44307568, 64, 'rax', 'movaps %xmm0,0x40(%rax)'),
 (45821632, 45822815, 88, 'rdi', 'mov    %r12,0x58(%rdi)'),
 (45830816, 45833723, 64, 'rcx', 'movups %xmm0,0x40(%rcx)'),
 (45830816, 45833764, 96, 'rcx', 'movups %xmm0,0x60(%rcx)'),
 (45830816, 45833802, 136, 'rcx', 'movupd %xmm1,0x88(%rcx)'),
 (45830816, 45833810, 120, 'rcx', 'movupd %xmm0,0x78(%rcx)'),
 (45830816, 45833836, 152, 'rcx', 'mov    %rax,0x98(%rcx)'),
 (45830816, 45834748, 64, 'rcx', 'movups %xmm0,0x40(%rcx)'),
 (45830816, 45834792, 96, 'rcx', 'movups %xmm0,0x60(%rcx)'),
 (45830816, 45834828, 136, 'rcx', 'movups %xmm1,0x88(%rcx)'),
 (45830816, 45834835, 120, 'rcx', 'movups %xmm0,0x78(%rcx)'),
 (45830816, 45834860, 152, 'rcx', 'mov    %rax,0x98(%rcx)'),
 (45838960, 45845000, 136, 'rdi', 'movups %xmm3,0x88(%rdi)'),
 (45838960, 45845007, 120, 'rdi', 'movups %xmm2,0x78(%rdi)'),
 (45838960, 45845040, 152, 'rdi', 'mov    %rsi,0x98(%rdi)'),
 (45838960, 45845109, 88, 'rdi', 'movups %xmm3,0x58(%rdi)'),
 (46004464, 46016102, 136, 'rax', 'mov    %rcx,0x88(%rax)'),
 (46004464, 46027917, 64, 'r13', 'mov    %rax,0x40(%r13)'),
 (46004464, 46036115, 64, 'r13', 'movups %xmm0,0x40(%r13)'),
 (46083792, 46084769, 64, 'r14', 'movups %xmm0,0x40(%r14)'),
 (46083792, 46089729, 64, 'rax', 'movups %xmm0,0x40(%rax,%rcx,1)'),
 (46083792, 46090722, 88, 'rcx', 'mov    %rax,0x58(%rcx)'),
 (46083792, 46091133, 88, 'r15', 'mov    %rax,0x58(%r15)'),
 (46083792, 46091595, 64, 'rax', 'movups %xmm0,0x40(%rax)'),
 (46540832, 46546821, 136, 'rdi', 'movups %xmm3,0x88(%rdi)'),
 (46540832, 46546828, 120, 'rdi', 'movups %xmm2,0x78(%rdi)'),
 (46540832, 46546865, 152, 'rdi', 'mov    %rsi,0x98(%rdi)'),
 (46540832, 46546934, 88, 'rdi', 'movups %xmm3,0x58(%rdi)'),
 (46616128, 46617507, 96, 'rbx', 'movaps %xmm0,0x60(%rbx)'),
 (46616128, 46617531, 64, 'rbx', 'movaps %xmm0,0x40(%rbx)'),
 (49345456, 49346806, 64, 'r15', 'movsd  %xmm7,0x40(%r15)'),
 (49345456, 49346824, 88, 'r15', 'movsd  %xmm3,0x58(%r15)'),
 (88593456, 88594639, 88, 'rdi', 'mov    %r12,0x58(%rdi)'),
 (88594704, 88595887, 88, 'rdi', 'mov    %r12,0x58(%rdi)'),
 (88674704, 88676902, 136, 'rdx', 'movups %xmm1,0x88(%rdx)'),
 (88674704, 88676909, 120, 'rdx', 'movups %xmm0,0x78(%rdx)'),
 (88674704, 88676932, 152, 'rdx', 'mov    %rax,0x98(%rdx)'),
 (88674704, 88677001, 88, 'rdx', 'movupd %xmm2,0x58(%rdx)'),
 (88775792, 88788150, 136, 'rax', 'mov    %rcx,0x88(%rax)'),
 (88775792, 88792412, 64, 'rdx', 'mov    %eax,0x40(%rdx)'),
 (88775792, 88800569, 96, 'rbx', 'movups %xmm0,0x60(%rbx)'),
 (88775792, 88800593, 64, 'rbx', 'movups %xmm0,0x40(%rbx)'),
 (88775792, 88809155, 64, 'r13', 'movups %xmm0,0x40(%r13)'),
 (88827568, 88839270, 136, 'rax', 'mov    %rcx,0x88(%rax)'),
 (88827568, 88851481, 96, 'rbx', 'movups %xmm0,0x60(%rbx)'),
 (88827568, 88851505, 64, 'rbx', 'movups %xmm0,0x40(%rbx)'),
 (88827568, 88859907, 64, 'r13', 'movups %xmm0,0x40(%r13)'),
 (88930960, 88932016, 64, 'rbx', 'movups %xmm0,0x40(%rbx)'),
 (88930960, 88937089, 64, 'rax', 'movups %xmm0,0x40(%rax,%rcx,1)'),
 (88930960, 88938322, 88, 'rcx', 'mov    %rax,0x58(%rcx)'),
 (88930960, 88938735, 88, 'r15', 'mov    %rax,0x58(%r15)'),
 (88930960, 88940777, 64, 'rax', 'movups %xmm0,0x40(%rax)'),
 (88954800, 88955866, 64, 'r14', 'movups %xmm0,0x40(%r14)'),
 (88954800, 88960865, 64, 'rax', 'movups %xmm0,0x40(%rax,%rcx,1)'),
 (88954800, 88962098, 88, 'rcx', 'mov    %rax,0x58(%rcx)'),
 (88954800, 88962511, 88, 'r15', 'mov    %rax,0x58(%r15)'),
 (88954800, 88964532, 64, 'rax', 'movups %xmm0,0x40(%rax)'),
 (90042320, 90049404, 136, 'rdi', 'movups %xmm3,0x88(%rdi)'),
 (90042320, 90049411, 120, 'rdi', 'movups %xmm2,0x78(%rdi)'),
 (90042320, 90049445, 152, 'rdi', 'mov    %rsi,0x98(%rdi)'),
 (90042320, 90049514, 88, 'rdi', 'movups %xmm3,0x58(%rdi)'),
 (90052304, 90058357, 136, 'rdi', 'movups %xmm3,0x88(%rdi)'),
 (90052304, 90058364, 120, 'rdi', 'movups %xmm2,0x78(%rdi)'),
 (90052304, 90058401, 152, 'rdi', 'mov    %rsi,0x98(%rdi)'),
 (90052304, 90058470, 88, 'rdi', 'movups %xmm3,0x58(%rdi)'),
 (90219856, 90221813, 96, 'rbx', 'movaps %xmm0,0x60(%rbx)'),
 (90219856, 90221837, 64, 'rbx', 'movaps %xmm0,0x40(%rbx)'),
 (90221984, 90223941, 96, 'rbx', 'movaps %xmm0,0x60(%rbx)'),
 (90221984, 90223965, 64, 'rbx', 'movaps %xmm0,0x40(%rbx)')]


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


def _stores(rows):
    """Memory-destination instructions (any mnemonic but cmp/test/lea)."""
    out = []
    for address in sorted(rows):
        text = rows[address][1]
        if ',' not in text:
            continue
        if text.split()[0].rstrip('bwlq') in ('cmp', 'test', 'lea'):
            continue
        dest = text[text.rfind(',') + 1:].strip()
        if '(%r' in dest:
            out.append((address, text))
    return out


_REG64 = {
    'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
    'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
    'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
    'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
    'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
    'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
    'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
    'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
}
for _i in range(8, 16):
    for _suf in ('', 'd', 'w', 'b'):
        _REG64[f'r{_i}{_suf}'] = f'r{_i}'

_MEMFULL_RE = re.compile(
    r'^(-?0x[0-9a-f]+)?\(%([a-z0-9]+)(?:,%([a-z0-9]+)(?:,([0-9]+))?)?\)$')
_EIGHT = {0x40, 0x58, 0x60, 0x78, 0x80, 0x88, 0x90, 0x98}


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
    if len(parts) == 1:
        return parts[0], []
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


def _census_fde(data, secs, start, end):
    """Store census over one FDE with the linear provenance tracker.

    Taint bits per 64-bit register: B0 = value data-dependent on an
    imul $0xb0 result in this body; B8 = same for imul $0xb8.
    Propagation: mov/movabs copies the source register's taint, lea
    unions its base/index taints, add/sub union the source register
    into the destination's, an imul $0xb0/$0xb8 sets the bit on its
    destination, any other register write clears, and a call clears
    the caller-saved registers (callee-saved registers keep taint:
    the ABI preserves them). A store is element-derived when its
    base register is tainted at the store.
    """
    rows = _decode(data, secs, start, end)
    taint = {r: set() for r in set(_REG64.values())}
    stores_eight, stores_elem, stores_range = [], [], []
    caller_saved = {'rax', 'rcx', 'rdx', 'rsi', 'rdi',
                    'r8', 'r9', 'r10', 'r11'}
    for a in sorted(rows):
        text = rows[a][1]
        mnem, ops = _split_ops(text)
        base_mnem = mnem.rstrip('bwlq')
        if ops:
            dest = ops[-1]
            pm = _parse_mem(dest)
            if pm and len(ops) >= 2 and base_mnem not in ('cmp', 'test', 'lea'):
                disp, basereg, _idx = pm
                if disp is not None and basereg not in (None, 'rsp'):
                    t = taint.get(basereg, set())
                    rec = (start, a, disp, basereg, text)
                    if disp in _EIGHT:
                        stores_eight.append(rec)
                        if t:
                            stores_elem.append(rec)
                    if 0x40 <= disp < 0xA0 and t:
                        stores_range.append(rec)
        if base_mnem == 'imul' and len(ops) >= 2 \
                and ops[0] in ('$0xb0', '$0xb8'):
            dst = _reg_of(ops[-1])
            if dst:
                taint[dst] = {'B0' if ops[0] == '$0xb0' else 'B8'}
            continue
        if base_mnem in ('mov', 'movabs', 'lea', 'add', 'sub', 'xor', 'or',
                         'and', 'shl', 'shr', 'sar', 'neg', 'not', 'inc', 'dec'):
            if base_mnem == 'xor' and len(ops) == 2 and ops[0] == ops[1]:
                dst = _reg_of(ops[1])
                if dst:
                    taint[dst] = set()
                continue
            if ops:
                dst = _reg_of(ops[-1])
                if dst and dst != 'rsp':
                    newt = set()
                    if base_mnem in ('mov', 'movabs') and len(ops) == 2:
                        src = _reg_of(ops[0])
                        newt = set(taint.get(src, set())) if src else set()
                    elif base_mnem == 'lea' and len(ops) == 2:
                        pm = _parse_mem(ops[0])
                        if pm:
                            _d, b1, b2 = pm
                            for b in (b1, b2):
                                if b:
                                    newt |= taint.get(b, set())
                    elif base_mnem in ('add', 'sub') and len(ops) == 2:
                        src = _reg_of(ops[0])
                        newt = set(taint.get(dst, set()))
                        if src:
                            newt |= taint.get(src, set())
                    taint[dst] = newt
            continue
        if base_mnem == 'call':
            for r in caller_saved:
                taint[r] = set()
            continue
        if ops and base_mnem not in ('cmp', 'test', 'jmp', 'je', 'jne', 'ja',
                                     'jae', 'jb', 'jbe', 'jg', 'jge', 'jl',
                                     'jle', 'jo', 'jno', 'js', 'jns', 'jnp',
                                     'jp', 'ret', 'nop', 'push', 'leave'):
            dst = _reg_of(ops[-1])
            if dst and dst != 'rsp' and '(%' not in ops[-1]:
                taint[dst] = set()
    return rows, stores_eight, stores_elem, stores_range


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

    # --- the helper slot: relocation + initialised content ---
    entries = _rela_entries(data, secs)
    helper_hits = [e for e in entries if e[0] == HELPER_SLOT]
    if helper_hits != [(HELPER_SLOT, 8, 0, HELPER['range'][0])]:
        raise AssertionError(
            f'helper slot {HELPER_SLOT:#x} relocation differs: {helper_hits!r}')
    slot_qword = struct.unpack_from(
        '<Q', _section_bytes(data, secs, HELPER_SLOT, HELPER_SLOT + 8), 0)[0]
    if slot_qword != 0:
        raise AssertionError('helper slot initialised content is not zero')

    # --- the helper body ---
    hs, he = HELPER['range']
    if extents.get(hs) != (hs, he):
        raise AssertionError('helper range is not an exact FDE extent')
    if _digest(data, secs, hs, he) != HELPER['sha256']:
        raise AssertionError('helper differs from its pinned digest')
    rows = _decode(data, secs, hs, he)
    _check_pins(rows, HELPER_PINS, 'helper')
    for address in sorted(rows):
        parts = rows[address][1].split()
        if parts and parts[0].startswith('j') and len(parts) == 2 \
                and parts[1].startswith('0x'):
            if not (hs <= int(parts[1], 16) < he):
                raise AssertionError(
                    f'helper branch at {address:#x} leaves the body')
    if rows[hs][1] != 'mov    %rdx,%r8':
        raise AssertionError('helper does not save denominator-low at entry')
    if rows[0x63EFEC3][1] != 'test   %rcx,%rcx' \
            or rows[0x63EFEC6][1] != 'je     0x63eff39':
        raise AssertionError('helper denominator-high dispatch differs')
    helper_calls = [a for a in sorted(rows)
                    if rows[a][1].startswith('call')]
    if helper_calls:
        raise AssertionError(f'helper makes calls: {helper_calls!r}')
    helper_mem = [a for a in sorted(rows) if '(%' in rows[a][1]]
    if helper_mem:
        raise AssertionError(f'helper touches memory: {helper_mem!r}')
    helper_rets = [a for a in sorted(rows) if rows[a][1] == 'ret']
    if helper_rets != HELPER_RETS:
        raise AssertionError(f'helper ret census differs: {helper_rets!r}')
    helper_divs = [a for a in sorted(rows)
                   if rows[a][1].startswith('div')]
    if helper_divs != HELPER_DIVS:
        raise AssertionError(f'helper div census differs: {helper_divs!r}')

    # --- binary-wide census of references to the helper slot ---
    hits = {}
    opcodes = {}
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
            for k in (0, 1, 2, 4):
                if sec['address'] + pos + 5 + k + disp == HELPER_SLOT:
                    hits.setdefault(sec['address'] + pos, set()).add(k)
                    opcodes[sec['address'] + pos] = blob[pos - 1]
    if len(hits) != SLOT_CENSUS['references'] \
            or any(ks != {0} for ks in hits.values()):
        raise AssertionError(
            f'helper slot census differs: {len(hits)} references')
    n_call = sum(1 for b in opcodes.values() if b == 0xFF)
    n_mov = sum(1 for b in opcodes.values() if b == 0x8B)
    if (n_call, n_mov) != (SLOT_CENSUS['call_opcode_refs'],
                           SLOT_CENSUS['mov_opcode_refs']):
        raise AssertionError(
            f'helper slot opcode census differs: {n_call}/{n_mov}')
    text_sec = next(s for s in secs if s['name'] == '.text')
    text_blob = _section_bytes(data, secs, text_sec['address'],
                               text_sec['address'] + text_sec['size'])
    direct = []
    i = text_blob.find(b'\xe8')
    while i != -1:
        if i + 5 <= len(text_blob):
            rel = struct.unpack_from('<i', text_blob, i + 1)[0]
            if text_sec['address'] + i + 5 + rel == hs:
                direct.append(text_sec['address'] + i)
        i = text_blob.find(b'\xe8', i + 1)
    if direct:
        raise AssertionError(f'direct calls to the helper body: {direct!r}')

    # --- the callee (cross-pinned from #2558, re-derived here) ---
    cs, ce = CALLEE['range']
    if extents.get(cs) != (cs, ce):
        raise AssertionError('callee range is not an exact FDE extent')
    if _digest(data, secs, cs, ce) != CALLEE['sha256']:
        raise AssertionError('callee differs from its pinned digest')
    crows = _decode(data, secs, cs, ce)
    loads, cstores = {}, []
    for address in sorted(crows):
        text = crows[address][1]
        for match in _MEM_RE.finditer(text):
            offset = int(match.group(1), 16)
            if ',' in text and match.start() > text.rfind(','):
                cstores.append((address, offset))
            else:
                loads.setdefault(offset, []).append(address)
    if loads != ELEMENT_LOADS:
        raise AssertionError(f'callee element loads differ: {loads!r}')
    if cstores:
        raise AssertionError(f'callee writes through the element: {cstores!r}')
    callee_helper_calls = []
    for address in sorted(crows):
        text = crows[address][1]
        if text.startswith('call') and '(%rip)' in text:
            if f'# {HELPER_SLOT:#x}' not in text:
                raise AssertionError(
                    f'callee indirect call at {address:#x} names another slot')
            callee_helper_calls.append(address)
    if callee_helper_calls != CALLEE_HELPER_CALLS:
        raise AssertionError(
            f'callee helper call census differs: {callee_helper_calls!r}')

    # --- the fallback ---
    fs, fe = FALLBACK['range']
    if extents.get(fs) != (fs, fe):
        raise AssertionError('fallback range is not an exact FDE extent')
    if _digest(data, secs, fs, fe) != FALLBACK['sha256']:
        raise AssertionError('fallback differs from its pinned digest')
    frows = _decode(data, secs, fs, fe)
    _check_pins(frows, FALLBACK_PINS, 'fallback')
    if _stores(frows):
        raise AssertionError(f'fallback stores: {_stores(frows)!r}')
    fallback_imul = [a for a in sorted(frows)
                     if frows[a][1].startswith('imul')
                     and '$0xb8' in frows[a][1].split(',')[0]]
    if fallback_imul != FALLBACK_IMUL_B8:
        raise AssertionError(f'fallback imul census differs: {fallback_imul!r}')

    # --- the sibling search ---
    ss, se = SIBLING['range']
    if extents.get(ss) != (ss, se):
        raise AssertionError('sibling range is not an exact FDE extent')
    if _digest(data, secs, ss, se) != SIBLING['sha256']:
        raise AssertionError('sibling differs from its pinned digest')
    srows = _decode(data, secs, ss, se)
    sibling_stores = {a: srows[a] for a, _t in _stores(srows)}
    if sibling_stores != SIBLING_STORES:
        raise AssertionError(f'sibling stores differ: {sibling_stores!r}')

    # --- the four callee callers (boundaries from #2558) ---
    for caller, ((cstart, cend), caller_sha) in CALLERS.items():
        if extents.get(cstart) != (cstart, cend):
            raise AssertionError(
                f'caller {caller:#x} range is not an exact FDE extent')
        if _digest(data, secs, cstart, cend) != caller_sha:
            raise AssertionError(
                f'caller {caller:#x} differs from its pinned digest')

    # --- the traced window: all 63 sibling-search callers from #2542 ---
    all_eight, all_elem, all_range = [], [], []
    for wstart in sorted(WINDOW_CALLERS):
        (ws, we), wsha = WINDOW_CALLERS[wstart]
        if extents.get(ws) != (ws, we):
            raise AssertionError(
                f'window caller {ws:#x} range is not an exact FDE extent')
        if _digest(data, secs, ws, we) != wsha:
            raise AssertionError(
                f'window caller {ws:#x} differs from its pinned digest')
        _rows, se8, sel, sr = _census_fde(data, secs, ws, we)
        all_eight.extend(se8)
        all_elem.extend(sel)
        all_range.extend(sr)
    if all_eight != [tuple(x) for x in STORES8]:
        raise AssertionError(
            f'window store census differs: {len(all_eight)} stores, '
            f'expected {len(STORES8)}')
    if all_elem:
        raise AssertionError(f'element-derived stores found: {all_elem!r}')
    if all_range:
        raise AssertionError(f'element-range tainted stores found: {all_range!r}')

    counters = {
        'callee_helper_calls': len(callee_helper_calls),
        'callee_instructions': len(crows),
        'direct_e8_calls': len(direct),
        'element_derived_stores': len(all_elem),
        'element_offsets': len(loads),
        'element_range_stores': len(all_range),
        'fallback_imul_b8': len(fallback_imul),
        'fallback_instructions': len(frows),
        'fallback_stores': len(_stores(frows)),
        'fde_count': len(fdes),
        'helper_calls': len(helper_calls),
        'helper_div_sites': len(helper_divs),
        'helper_instructions': len(rows),
        'helper_memory_operands': len(helper_mem),
        'helper_rets': len(helper_rets),
        'helper_slot_references': len(hits),
        'helper_slot_rela_entries': len(helper_hits),
        'sibling_stores': len(sibling_stores),
        'slot_initialised_qword': slot_qword,
        'stores_at_eight_displacements': len(all_eight),
        'window_callers': len(WINDOW_CALLERS),
    }
    if counters != EXPECTED:
        raise AssertionError(f'counters differ: {counters} != {EXPECTED}')

    return {
        'boundaries': {
            f'caller_{caller:#x}': {'range': [_hx(rng[0]), _hx(rng[1])],
                                    'sha256': sha}
            for caller, (rng, sha) in CALLERS.items()},
        'callee': {
            'element_loads': {_hx(off): [_hx(a) for a in addrs]
                              for off, addrs in ELEMENT_LOADS.items()},
            'element_stores': 0,
            'helper_calls': [_hx(a) for a in CALLEE_HELPER_CALLS],
            'helper_slot': _hx(HELPER_SLOT),
            'range': [_hx(cs), _hx(ce)],
            'sha256': CALLEE['sha256'],
            'size': ce - cs,
        },
        'counters': counters,
        'extractor': 'tools/join_helper_element_static.py',
        'fallback': {
            'imul_b8_sites': [_hx(a) for a in FALLBACK_IMUL_B8],
            'range': [_hx(fs), _hx(fe)],
            'sha256': FALLBACK['sha256'],
            'size': fe - fs,
            'stores': 0,
        },
        'field_verdicts': {
            _hx(off): 'incoming: no store in the traced window writes '
                      'this field through an element-derived pointer'
            for off in ELEMENT_OFFSETS},
        'helper': {
            'calls': 0,
            'contract': {
                'arguments': 'numerator in rdi (low) and rsi (high); '
                             'denominator in rdx (low) and rcx (high)',
                'edge_behaviour': 'no zero-denominator guard: with '
                                  'rcx = 0 and rdx = 0 the low path is '
                                  'always taken to a hardware div whose '
                                  'divisor is zero, which traps (#DE); '
                                  'every other div is guarded by '
                                  'construction, so no quotient-overflow '
                                  'trap is reachable',
                'kind': 'unsigned 128-by-128 division (__udivti3 shape)',
                'memory_operands': 0,
                'results': 'quotient in rax (low) and rdx (high)',
            },
            'div_sites': [_hx(a) for a in HELPER_DIVS],
            'range': [_hx(hs), _hx(he)],
            'ret_sites': [_hx(a) for a in HELPER_RETS],
            'sha256': HELPER['sha256'],
            'size': he - hs,
        },
        'layouts': {
            'flat': {
                'callee_element': 'base + index x 0xb8 + 8',
                'field_record_offsets': {
                    _hx(off): _hx(off + 8) for off in ELEMENT_OFFSETS},
                'key_offset': '0x0',
                'stride': '0xb8',
            },
            'node': {
                'callee_element': 'node + position x 0xb0',
                'field_offsets': [_hx(off) for off in ELEMENT_OFFSETS],
                'stride': '0xb0',
            },
        },
        'node': {'artifact_sha256': ARTIFACT_SHA256,
                 'artifact_size': ARTIFACT_SIZE,
                 'fde_count': len(fdes)},
        'packet': PACKET_ID,
        'sibling': {
            'range': [_hx(ss), _hx(se)],
            'sha256': SIBLING['sha256'],
            'stores': {_hx(a): SIBLING_STORES[a][1]
                       for a in sorted(SIBLING_STORES)},
        },
        'slot': {
            'address': _hx(HELPER_SLOT),
            'census': {
                'call_opcode_references': n_call,
                'direct_e8_calls': len(direct),
                'mov_opcode_references': n_mov,
                'rip_relative_references': len(hits),
            },
            'initialised_qword': slot_qword,
            'mechanism': 'R_X86_64_RELATIVE addend in a static PIE; the '
                         'slot content is initialised to zero, so the '
                         'addend alone carries the target',
            'rela_addend': _hx(hs),
            'rela_entries': len(helper_hits),
        },
        'verdict': 'the join callee division helper is the 190-byte '
                   'register-only unsigned 128-bit divider at 0x63efec0, '
                   'reached only through GOT slot 0x64dfaf8, with no '
                   'zero-denominator guard (a zero denominator traps); '
                   'none of the eight element fields is written anywhere '
                   'in the traced consumption window, so all eight are '
                   'incoming at the window',
        'window': {
            'callers': len(WINDOW_CALLERS),
            'element_derived_stores': 0,
            'element_range_stores': 0,
            'method': 'whole-FDE store census over the 63 sibling-search '
                      'caller FDEs pinned in #2542, with a linear '
                      'register-provenance tracker marking a store '
                      'element-derived when its base register is '
                      'data-dependent on an imul $0xb0 / imul $0xb8 '
                      'product in the same body',
            'stores_at_eight_displacements': [
                {'addr': _hx(a), 'base': b, 'disp': _hx(d),
                 'fde': _hx(f), 'text': t} for f, a, d, b, t in STORES8],
        },
    }


def _frames(data):
    retained = {HELPER['range'], FALLBACK['range'], SIBLING['range'],
                CALLEE['range']} | {rng for rng, _sha in WINDOW_CALLERS.values()}
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
    for body, (start, end) in (('helper', HELPER['range']),
                               ('fallback', FALLBACK['range'])):
        name = f'{body}_full_body_{start:x}_{end:x}_objdump.txt'
        (out_dir / name).write_text(_body_export(data, start, end))
    return records


def main(argv):
    if len(argv) != 3 or argv[1] != 'generate':
        raise SystemExit('usage: join_helper_element_static.py generate <out-dir>')
    artifact = ROOT / 'artifacts/node/115/hl-node'
    generate(artifact.read_bytes(), argv[2])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
