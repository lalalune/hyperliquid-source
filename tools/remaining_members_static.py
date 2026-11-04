"""Static evidence for the six remaining RE-006 cursor-search members.

The RE-006 family census in packet RE-006-node115-variant-cursor-searches
(#2530) lists thirteen standalone search bodies. Seven packets pin the
other twelve records (#2416, #2427, #2493, #2503, #2530, #2542, #2546,
#2548). This packet pins the six members that were left: two-site and
one-site bodies at 0x35bd8a0, 0x35bddb0, 0x35be3b0, 0x35bf3c0, 0x1d65b20
and 0x4d380a0. Two census corrections fall out of the byte scan: the last
two bodies have two direct call sites each, not one, and they are
byte-identical clones of one another at two addresses. For every body
the tool authenticates the body bytes against the node 115 artifact,
checks the node layout instruction by instruction, censuses the direct
call sites (E8), tail calls (E9) and R_X86_64_RELATIVE references,
verifies what each caller does with the returned record field by field
over the whole caller FDE, and classifies every read of the record's
height slot. ``analyze`` performs every check without authenticating
the artifact first, so a flipped byte fails the specific check that
covers it; ``generate`` authenticates the artifact, then regenerates
the packet records byte for byte.
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

PACKET_ID = 'RE-006-node115-remaining-members'
ARTIFACT_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARTIFACT_SIZE = 105896032
FDE_COUNT = 135313
RECORD_LAYOUT = {'size': 32, 'flag': 0x0, 'node': 0x8, 'height': 0x10,
                 'position': 0x18}
VECTOR_MNEMONICS = {'movaps', 'movups', 'movdqa', 'movdqu', 'movsd', 'movss'}
FIELDS = ('flag', 'node', 'height', 'position')
FIELD_OFFSETS = {'flag': 0x0, 'node': 0x8, 'height': 0x10, 'position': 0x18}
_STORE_RE = re.compile(r'^mov\w*\s+[^,]+,\s*0x[0-9a-f]+\(%rsp\)$')
_LINE_RE = re.compile(r'^\s+([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$')

BODIES = {'gapless27_search': {'range': (56350880, 56351026), 'sha256': '499fcf8ff6b95a70aa3be671ee130d699c83c694ff57a9af4f2e05d45ce7a848', 'layout': {'key_offset': 8, 'key_size': 8, 'keys_per_node': 27, 'count_offset': 230, 'edge_base': 232, 'child_index_offset': 228, 'trailer': 'gapless'}, 'landmarks': {'count_load': 56350886, 'key_compare': 56350917, 'descent_load': 56350988, 'hit_flag_zero': 56351001, 'miss_flag_one': 56351019, 'key_deref': 56350883}, 'compare': 'unsigned'}, 'gapped_offset_search': {'range': (56352176, 56352322), 'sha256': '30f297e738540fa348b161115181d87d0a28167d35a6bc1086a8f701e8793058', 'layout': {'key_offset': 536, 'key_size': 8, 'keys_per_node': 11, 'count_offset': 626, 'edge_base': 632, 'child_index_offset': 624, 'trailer': 'gapped'}, 'landmarks': {'count_load': 56352182, 'key_compare': 56352213, 'descent_load': 56352284, 'hit_flag_zero': 56352297, 'miss_flag_one': 56352315, 'key_deref': 56352179}, 'compare': 'unsigned'}, 'signed_u32_search': {'range': (56353712, 56353858), 'sha256': '0a725341981473211a1f193625896b37ba3fbaaa69354f56b7b222651d9db4b8', 'layout': {'key_offset': 184, 'key_size': 4, 'keys_per_node': 11, 'count_offset': 230, 'edge_base': 232, 'child_index_offset': 228, 'trailer': 'u32'}, 'landmarks': {'count_load': 56353717, 'key_compare': 56353749, 'descent_load': 56353820, 'hit_flag_zero': 56353833, 'miss_flag_one': 56353851, 'key_deref': 56353715}, 'compare': 'signed'}, 'gapless38_search': {'range': (56357824, 56357970), 'sha256': '89516192c291c89a0ae1ee5c9a2a0783b50e2b61be0187805455e6ba2a30c229', 'layout': {'key_offset': 8, 'key_size': 8, 'keys_per_node': 38, 'count_offset': 318, 'edge_base': 320, 'child_index_offset': 316, 'trailer': 'gapless'}, 'landmarks': {'count_load': 56357830, 'key_compare': 56357861, 'descent_load': 56357932, 'hit_flag_zero': 56357945, 'miss_flag_one': 56357963, 'key_deref': 56357827}, 'compare': 'unsigned'}, 'wide110_search': {'range': (30825248, 30825394), 'sha256': 'b1d2c6ba43757c25e56ffeef32b4ee8127289eb49a3361b808cb361b5fd8866d', 'layout': {'key_offset': 8, 'key_size': 8, 'keys_per_node': 110, 'count_offset': 890, 'edge_base': 896, 'child_index_offset': 888, 'trailer': 'gapped'}, 'landmarks': {'count_load': 30825254, 'key_compare': 30825285, 'descent_load': 30825356, 'hit_flag_zero': 30825369, 'miss_flag_one': 30825387, 'key_deref': 30825251}, 'compare': 'unsigned'}, 'wide110_clone_search': {'range': (80969888, 80970034), 'sha256': 'b1d2c6ba43757c25e56ffeef32b4ee8127289eb49a3361b808cb361b5fd8866d', 'layout': {'key_offset': 8, 'key_size': 8, 'keys_per_node': 110, 'count_offset': 890, 'edge_base': 896, 'child_index_offset': 888, 'trailer': 'gapped'}, 'landmarks': {'count_load': 80969894, 'key_compare': 80969925, 'descent_load': 80969996, 'hit_flag_zero': 80970009, 'miss_flag_one': 80970027, 'key_deref': 80969891}, 'compare': 'unsigned'}}

BODY_PINS = {'gapless27_search': {56350880: ('4889f8', 'mov    %rdi,%rax'), 56350883: ('488b09', 'mov    (%rcx),%rcx'), 56350886: ('440fb786e60000', 'movzwl 0xe6(%rsi),%r8d'), 56350894: ('4589c1', 'mov    %r8d,%r9d'), 56350897: ('41c1e103', 'shl    $0x3,%r9d'), 56350901: ('48c7c7ffffffff', 'mov    $0xffffffffffffffff,%rdi'), 56350908: ('0f1f4000', 'nopl   0x0(%rax)'), 56350912: ('4d85c9', 'test   %r9,%r9'), 56350915: ('743b', 'je     0x35bd900'), 56350917: ('483b4cfe10', 'cmp    0x10(%rsi,%rdi,8),%rcx'), 56350922: ('410f97c2', 'seta   %r10b'), 56350926: ('4180da00', 'sbb    $0x0,%r10b'), 56350930: ('48ffc7', 'inc    %rdi'), 56350933: ('4983c1f8', 'add    $0xfffffffffffffff8,%r9'), 56350937: ('4180fa01', 'cmp    $0x1,%r10b'), 56350941: ('74e1', 'je     0x35bd8c0'), 56350943: ('450fb6c2', 'movzbl %r10b,%r8d'), 56350947: ('4585c0', 'test   %r8d,%r8d'), 56350950: ('7431', 'je     0x35bd919'), 56350952: ('4989d0', 'mov    %rdx,%r8'), 56350955: ('4983e801', 'sub    $0x1,%r8'), 56350959: ('731b', 'jae    0x35bd90c'), 56350961: ('eb38', 'jmp    0x35bd92b'), 56350963: ('666666662e0f1f', 'data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'), 56350976: ('4c89c7', 'mov    %r8,%rdi'), 56350979: ('4989d0', 'mov    %rdx,%r8'), 56350982: ('4983e801', 'sub    $0x1,%r8'), 56350986: ('721f', 'jb     0x35bd92b'), 56350988: ('488bb4fee80000', 'mov    0xe8(%rsi,%rdi,8),%rsi'), 56350996: ('4c89c2', 'mov    %r8,%rdx'), 56350999: ('eb8d', 'jmp    0x35bd8a6'), 56351001: ('31c9', 'xor    %ecx,%ecx'), 56351003: ('48897008', 'mov    %rsi,0x8(%rax)'), 56351007: ('48895010', 'mov    %rdx,0x10(%rax)'), 56351011: ('48897818', 'mov    %rdi,0x18(%rax)'), 56351015: ('488908', 'mov    %rcx,(%rax)'), 56351018: ('c3', 'ret'), 56351019: ('b901000000', 'mov    $0x1,%ecx'), 56351024: ('ebe9', 'jmp    0x35bd91b')}, 'gapped_offset_search': {56352176: ('4889f8', 'mov    %rdi,%rax'), 56352179: ('488b09', 'mov    (%rcx),%rcx'), 56352182: ('440fb786720200', 'movzwl 0x272(%rsi),%r8d'), 56352190: ('4589c1', 'mov    %r8d,%r9d'), 56352193: ('41c1e103', 'shl    $0x3,%r9d'), 56352197: ('48c7c7ffffffff', 'mov    $0xffffffffffffffff,%rdi'), 56352204: ('0f1f4000', 'nopl   0x0(%rax)'), 56352208: ('4d85c9', 'test   %r9,%r9'), 56352211: ('743b', 'je     0x35bde10'), 56352213: ('483b8cfe200200', 'cmp    0x220(%rsi,%rdi,8),%rcx'), 56352221: ('410f97c2', 'seta   %r10b'), 56352225: ('4180da00', 'sbb    $0x0,%r10b'), 56352229: ('48ffc7', 'inc    %rdi'), 56352232: ('4983c1f8', 'add    $0xfffffffffffffff8,%r9'), 56352236: ('4180fa01', 'cmp    $0x1,%r10b'), 56352240: ('74de', 'je     0x35bddd0'), 56352242: ('450fb6c2', 'movzbl %r10b,%r8d'), 56352246: ('4585c0', 'test   %r8d,%r8d'), 56352249: ('742e', 'je     0x35bde29'), 56352251: ('4989d0', 'mov    %rdx,%r8'), 56352254: ('4983e801', 'sub    $0x1,%r8'), 56352258: ('7318', 'jae    0x35bde1c'), 56352260: ('eb35', 'jmp    0x35bde3b'), 56352262: ('662e0f1f840000', 'cs nopw 0x0(%rax,%rax,1)'), 56352272: ('4c89c7', 'mov    %r8,%rdi'), 56352275: ('4989d0', 'mov    %rdx,%r8'), 56352278: ('4983e801', 'sub    $0x1,%r8'), 56352282: ('721f', 'jb     0x35bde3b'), 56352284: ('488bb4fe780200', 'mov    0x278(%rsi,%rdi,8),%rsi'), 56352292: ('4c89c2', 'mov    %r8,%rdx'), 56352295: ('eb8d', 'jmp    0x35bddb6'), 56352297: ('31c9', 'xor    %ecx,%ecx'), 56352299: ('48897008', 'mov    %rsi,0x8(%rax)'), 56352303: ('48895010', 'mov    %rdx,0x10(%rax)'), 56352307: ('48897818', 'mov    %rdi,0x18(%rax)'), 56352311: ('488908', 'mov    %rcx,(%rax)'), 56352314: ('c3', 'ret'), 56352315: ('b901000000', 'mov    $0x1,%ecx'), 56352320: ('ebe9', 'jmp    0x35bde2b')}, 'signed_u32_search': {56353712: ('4889f8', 'mov    %rdi,%rax'), 56353715: ('8b09', 'mov    (%rcx),%ecx'), 56353717: ('440fb786e60000', 'movzwl 0xe6(%rsi),%r8d'), 56353725: ('4589c1', 'mov    %r8d,%r9d'), 56353728: ('41c1e102', 'shl    $0x2,%r9d'), 56353732: ('48c7c7ffffffff', 'mov    $0xffffffffffffffff,%rdi'), 56353739: ('0f1f440000', 'nopl   0x0(%rax,%rax,1)'), 56353744: ('4d85c9', 'test   %r9,%r9'), 56353747: ('743b', 'je     0x35be410'), 56353749: ('3b8cbebc000000', 'cmp    0xbc(%rsi,%rdi,4),%ecx'), 56353756: ('410f9cc3', 'setl   %r11b'), 56353760: ('410f9fc2', 'setg   %r10b'), 56353764: ('4528da', 'sub    %r11b,%r10b'), 56353767: ('48ffc7', 'inc    %rdi'), 56353770: ('4983c1fc', 'add    $0xfffffffffffffffc,%r9'), 56353774: ('4180fa01', 'cmp    $0x1,%r10b'), 56353778: ('74dc', 'je     0x35be3d0'), 56353780: ('450fb6c2', 'movzbl %r10b,%r8d'), 56353784: ('4585c0', 'test   %r8d,%r8d'), 56353787: ('742c', 'je     0x35be429'), 56353789: ('4989d0', 'mov    %rdx,%r8'), 56353792: ('4983e801', 'sub    $0x1,%r8'), 56353796: ('7316', 'jae    0x35be41c'), 56353798: ('eb33', 'jmp    0x35be43b'), 56353800: ('0f1f8400000000', 'nopl   0x0(%rax,%rax,1)'), 56353808: ('4c89c7', 'mov    %r8,%rdi'), 56353811: ('4989d0', 'mov    %rdx,%r8'), 56353814: ('4983e801', 'sub    $0x1,%r8'), 56353818: ('721f', 'jb     0x35be43b'), 56353820: ('488bb4fee80000', 'mov    0xe8(%rsi,%rdi,8),%rsi'), 56353828: ('4c89c2', 'mov    %r8,%rdx'), 56353831: ('eb8c', 'jmp    0x35be3b5'), 56353833: ('31c9', 'xor    %ecx,%ecx'), 56353835: ('48897008', 'mov    %rsi,0x8(%rax)'), 56353839: ('48895010', 'mov    %rdx,0x10(%rax)'), 56353843: ('48897818', 'mov    %rdi,0x18(%rax)'), 56353847: ('488908', 'mov    %rcx,(%rax)'), 56353850: ('c3', 'ret'), 56353851: ('b901000000', 'mov    $0x1,%ecx'), 56353856: ('ebe9', 'jmp    0x35be42b')}, 'gapless38_search': {56357824: ('4889f8', 'mov    %rdi,%rax'), 56357827: ('488b09', 'mov    (%rcx),%rcx'), 56357830: ('440fb7863e0100', 'movzwl 0x13e(%rsi),%r8d'), 56357838: ('4589c1', 'mov    %r8d,%r9d'), 56357841: ('41c1e103', 'shl    $0x3,%r9d'), 56357845: ('48c7c7ffffffff', 'mov    $0xffffffffffffffff,%rdi'), 56357852: ('0f1f4000', 'nopl   0x0(%rax)'), 56357856: ('4d85c9', 'test   %r9,%r9'), 56357859: ('743b', 'je     0x35bf420'), 56357861: ('483b4cfe10', 'cmp    0x10(%rsi,%rdi,8),%rcx'), 56357866: ('410f97c2', 'seta   %r10b'), 56357870: ('4180da00', 'sbb    $0x0,%r10b'), 56357874: ('48ffc7', 'inc    %rdi'), 56357877: ('4983c1f8', 'add    $0xfffffffffffffff8,%r9'), 56357881: ('4180fa01', 'cmp    $0x1,%r10b'), 56357885: ('74e1', 'je     0x35bf3e0'), 56357887: ('450fb6c2', 'movzbl %r10b,%r8d'), 56357891: ('4585c0', 'test   %r8d,%r8d'), 56357894: ('7431', 'je     0x35bf439'), 56357896: ('4989d0', 'mov    %rdx,%r8'), 56357899: ('4983e801', 'sub    $0x1,%r8'), 56357903: ('731b', 'jae    0x35bf42c'), 56357905: ('eb38', 'jmp    0x35bf44b'), 56357907: ('666666662e0f1f', 'data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'), 56357920: ('4c89c7', 'mov    %r8,%rdi'), 56357923: ('4989d0', 'mov    %rdx,%r8'), 56357926: ('4983e801', 'sub    $0x1,%r8'), 56357930: ('721f', 'jb     0x35bf44b'), 56357932: ('488bb4fe400100', 'mov    0x140(%rsi,%rdi,8),%rsi'), 56357940: ('4c89c2', 'mov    %r8,%rdx'), 56357943: ('eb8d', 'jmp    0x35bf3c6'), 56357945: ('31c9', 'xor    %ecx,%ecx'), 56357947: ('48897008', 'mov    %rsi,0x8(%rax)'), 56357951: ('48895010', 'mov    %rdx,0x10(%rax)'), 56357955: ('48897818', 'mov    %rdi,0x18(%rax)'), 56357959: ('488908', 'mov    %rcx,(%rax)'), 56357962: ('c3', 'ret'), 56357963: ('b901000000', 'mov    $0x1,%ecx'), 56357968: ('ebe9', 'jmp    0x35bf43b')}, 'wide110_search': {30825248: ('4889f8', 'mov    %rdi,%rax'), 30825251: ('488b09', 'mov    (%rcx),%rcx'), 30825254: ('440fb7867a0300', 'movzwl 0x37a(%rsi),%r8d'), 30825262: ('4589c1', 'mov    %r8d,%r9d'), 30825265: ('41c1e103', 'shl    $0x3,%r9d'), 30825269: ('48c7c7ffffffff', 'mov    $0xffffffffffffffff,%rdi'), 30825276: ('0f1f4000', 'nopl   0x0(%rax)'), 30825280: ('4d85c9', 'test   %r9,%r9'), 30825283: ('743b', 'je     0x1d65b80'), 30825285: ('483b4cfe10', 'cmp    0x10(%rsi,%rdi,8),%rcx'), 30825290: ('410f97c2', 'seta   %r10b'), 30825294: ('4180da00', 'sbb    $0x0,%r10b'), 30825298: ('48ffc7', 'inc    %rdi'), 30825301: ('4983c1f8', 'add    $0xfffffffffffffff8,%r9'), 30825305: ('4180fa01', 'cmp    $0x1,%r10b'), 30825309: ('74e1', 'je     0x1d65b40'), 30825311: ('450fb6c2', 'movzbl %r10b,%r8d'), 30825315: ('4585c0', 'test   %r8d,%r8d'), 30825318: ('7431', 'je     0x1d65b99'), 30825320: ('4989d0', 'mov    %rdx,%r8'), 30825323: ('4983e801', 'sub    $0x1,%r8'), 30825327: ('731b', 'jae    0x1d65b8c'), 30825329: ('eb38', 'jmp    0x1d65bab'), 30825331: ('666666662e0f1f', 'data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'), 30825344: ('4c89c7', 'mov    %r8,%rdi'), 30825347: ('4989d0', 'mov    %rdx,%r8'), 30825350: ('4983e801', 'sub    $0x1,%r8'), 30825354: ('721f', 'jb     0x1d65bab'), 30825356: ('488bb4fe800300', 'mov    0x380(%rsi,%rdi,8),%rsi'), 30825364: ('4c89c2', 'mov    %r8,%rdx'), 30825367: ('eb8d', 'jmp    0x1d65b26'), 30825369: ('31c9', 'xor    %ecx,%ecx'), 30825371: ('48897008', 'mov    %rsi,0x8(%rax)'), 30825375: ('48895010', 'mov    %rdx,0x10(%rax)'), 30825379: ('48897818', 'mov    %rdi,0x18(%rax)'), 30825383: ('488908', 'mov    %rcx,(%rax)'), 30825386: ('c3', 'ret'), 30825387: ('b901000000', 'mov    $0x1,%ecx'), 30825392: ('ebe9', 'jmp    0x1d65b9b')}, 'wide110_clone_search': {80969888: ('4889f8', 'mov    %rdi,%rax'), 80969891: ('488b09', 'mov    (%rcx),%rcx'), 80969894: ('440fb7867a0300', 'movzwl 0x37a(%rsi),%r8d'), 80969902: ('4589c1', 'mov    %r8d,%r9d'), 80969905: ('41c1e103', 'shl    $0x3,%r9d'), 80969909: ('48c7c7ffffffff', 'mov    $0xffffffffffffffff,%rdi'), 80969916: ('0f1f4000', 'nopl   0x0(%rax)'), 80969920: ('4d85c9', 'test   %r9,%r9'), 80969923: ('743b', 'je     0x4d38100'), 80969925: ('483b4cfe10', 'cmp    0x10(%rsi,%rdi,8),%rcx'), 80969930: ('410f97c2', 'seta   %r10b'), 80969934: ('4180da00', 'sbb    $0x0,%r10b'), 80969938: ('48ffc7', 'inc    %rdi'), 80969941: ('4983c1f8', 'add    $0xfffffffffffffff8,%r9'), 80969945: ('4180fa01', 'cmp    $0x1,%r10b'), 80969949: ('74e1', 'je     0x4d380c0'), 80969951: ('450fb6c2', 'movzbl %r10b,%r8d'), 80969955: ('4585c0', 'test   %r8d,%r8d'), 80969958: ('7431', 'je     0x4d38119'), 80969960: ('4989d0', 'mov    %rdx,%r8'), 80969963: ('4983e801', 'sub    $0x1,%r8'), 80969967: ('731b', 'jae    0x4d3810c'), 80969969: ('eb38', 'jmp    0x4d3812b'), 80969971: ('666666662e0f1f', 'data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'), 80969984: ('4c89c7', 'mov    %r8,%rdi'), 80969987: ('4989d0', 'mov    %rdx,%r8'), 80969990: ('4983e801', 'sub    $0x1,%r8'), 80969994: ('721f', 'jb     0x4d3812b'), 80969996: ('488bb4fe800300', 'mov    0x380(%rsi,%rdi,8),%rsi'), 80970004: ('4c89c2', 'mov    %r8,%rdx'), 80970007: ('eb8d', 'jmp    0x4d380a6'), 80970009: ('31c9', 'xor    %ecx,%ecx'), 80970011: ('48897008', 'mov    %rsi,0x8(%rax)'), 80970015: ('48895010', 'mov    %rdx,0x10(%rax)'), 80970019: ('48897818', 'mov    %rdi,0x18(%rax)'), 80970023: ('488908', 'mov    %rcx,(%rax)'), 80970026: ('c3', 'ret'), 80970027: ('b901000000', 'mov    $0x1,%ecx'), 80970032: ('ebe9', 'jmp    0x4d3811b')}}

BOUNDARIES = {72401968: ((72401968, 72402780), 'b3320778c8daebf09ab5d059088b1e4d7a85afb3df29baf55cf1e86f08bbcdfa'), 71838032: ((71838032, 71839987), '3cdc2e9b414cb0c6c988bfffce5e65248b54a4cf0b4b88adc3b23950fb03f2b2'), 46665856: ((46665856, 46668736), 'd6e9ffe3a869f0dc517c4ea79cfdabbd6d3a94cb820df1a2201b653c7027058b'), 71777552: ((71777552, 71790821), '31333cd99fd618320ec49b1d8ade330be707c538f05f7f2bc8e63752896ac6fc'), 45808864: ((45808864, 45809530), '6b3ac03678d2cbe0566b18eed78ca0682790030df74515c24da5b1d9659cb6e0'), 45809536: ((45809536, 45810202), '97d7151e2e3baf6e6816f8104f50d922b491583045e0d3f17d5c3030ad8e9f9e'), 92050480: ((92050480, 92051131), '479d86a863c188a9d872cad0172d49b74be5980dc3456307ec8896d6ca6ebbb4'), 92051136: ((92051136, 92051787), '902c28b31e9bada1d2b340206bec33163e8e0dc63b91a1c0670a087c5ca4d6d9')}

SITES = {72402090: {'body': 'gapless27_search', 'caller': 72401968, 'base': 40, 'flag': 72402100, 'flag_form': 'register', 'presentation': 'handle_stack', 'record_form': 'lea', 'fallback': None, 'test': 72402114, 'class': 'flag_only'}, 72402411: {'body': 'gapless27_search', 'caller': 72401968, 'base': 40, 'flag': 72402421, 'flag_form': 'register', 'presentation': 'handle_stack', 'record_form': 'lea', 'fallback': None, 'test': 72402435, 'class': 'flag_only'}, 71838123: {'body': 'gapped_offset_search', 'caller': 71838032, 'base': 32, 'flag': 71838128, 'flag_form': 'dword', 'presentation': 'handle_register', 'record_form': 'lea', 'fallback': 72685584, 'hit_start': 71838139, 'class': 'node_position', 'consumption': {'position': 71838139, 'scale': [71838144, 71838148], 'add': 71838152, 'node': None, 'stride': 48}, 'element_bias': None, 'fallback_call': 71838170}, 46666358: {'body': 'signed_u32_search', 'caller': 46665856, 'base': 48, 'flag': 46666363, 'flag_form': 'dword', 'presentation': 'handle_register', 'record_form': 'lea', 'fallback': 72686624, 'hit_start': 46666374, 'class': 'node_position', 'consumption': {'position': 46666374, 'scale': [46666379], 'add': 46666383, 'node': None, 'stride': 16}, 'element_bias': None, 'fallback_call': 46666409}, 46667185: {'body': 'signed_u32_search', 'caller': 46665856, 'base': 48, 'flag': 46667190, 'flag_form': 'dword', 'presentation': 'handle_register', 'record_form': 'lea', 'fallback': 72686624, 'hit_start': 46667197, 'class': 'node_position', 'consumption': {'position': 46667197, 'scale': [46667202], 'add': 46667206, 'node': None, 'stride': 16}, 'element_bias': None, 'fallback_call': 46667225}, 71781975: {'body': 'gapless38_search', 'caller': 71777552, 'base': 272, 'flag': 71781980, 'flag_form': 'dword', 'presentation': 'handle_stack', 'record_form': 'register', 'fallback': 72713696, 'hit_start': 71782096, 'class': 'node_position', 'consumption': {'position': 71782104, 'scale': [71782112], 'add': 71782116, 'node': 71782096, 'stride': 20}, 'element_bias': 96, 'fallback_call': 71782011}, 71783529: {'body': 'gapless38_search', 'caller': 71777552, 'base': 272, 'flag': 71783534, 'flag_form': 'dword', 'presentation': 'handle_stack', 'record_form': 'lea', 'fallback': 72713696, 'hit_start': 71783756, 'class': 'node_position', 'consumption': {'position': 71783764, 'scale': [71783772], 'add': 71783776, 'node': 71783756, 'stride': 20}, 'element_bias': 96, 'fallback_call': 71783685}, 45808944: {'body': 'wide110_search', 'caller': 45808864, 'base': 104, 'flag': 45808949, 'flag_form': 'dword', 'presentation': 'handle_register', 'record_form': 'lea', 'fallback': 38572544, 'hit_start': 45808960, 'class': 'node_position', 'consumption': {'position': 45808965, 'scale': [45808973], 'add': 45808977, 'node': 45808960, 'stride': 72}, 'element_bias': 96, 'fallback_call': 45809008}, 45809616: {'body': 'wide110_search', 'caller': 45809536, 'base': 104, 'flag': 45809621, 'flag_form': 'dword', 'presentation': 'handle_register', 'record_form': 'lea', 'fallback': 38572544, 'hit_start': 45809632, 'class': 'node_position', 'consumption': {'position': 45809637, 'scale': [45809645], 'add': 45809649, 'node': 45809632, 'stride': 72}, 'element_bias': 96, 'fallback_call': 45809680}, 92050560: {'body': 'wide110_clone_search', 'caller': 92050480, 'base': 120, 'flag': 92050565, 'flag_form': 'dword', 'presentation': 'handle_register', 'record_form': 'lea', 'fallback': 92238352, 'hit_start': 92050576, 'class': 'node_position', 'consumption': {'position': 92050584, 'scale': [92050592], 'add': 92050596, 'node': 92050576, 'stride': 72}, 'element_bias': 96, 'fallback_call': 92050627}, 92051216: {'body': 'wide110_clone_search', 'caller': 92051136, 'base': 120, 'flag': 92051221, 'flag_form': 'dword', 'presentation': 'handle_register', 'record_form': 'lea', 'fallback': 92238352, 'hit_start': 92051232, 'class': 'node_position', 'consumption': {'position': 92051240, 'scale': [92051248], 'add': 92051252, 'node': 92051232, 'stride': 72}, 'element_bias': 96, 'fallback_call': 92051283}}

WINDOWS = {'site_0x450c4aa': {'range': (72402077, 72402118), 'calls': {72402090: '0x35bd8a0'}, 'pins': {72402077: ('488d7c2428', 'lea    0x28(%rsp),%rdi'), 72402082: ('488b542410', 'mov    0x10(%rsp),%rdx'), 72402087: ('4889e1', 'mov    %rsp,%rcx'), 72402090: ('e8f1130bff', 'call   0x35bd8a0'), 72402095: ('488b742408', 'mov    0x8(%rsp),%rsi'), 72402100: ('0fb6442428', 'movzbl 0x28(%rsp),%eax'), 72402105: ('4883c5ff', 'add    $0xffffffffffffffff,%rbp'), 72402109: ('7307', 'jae    0x450c4c6'), 72402111: ('4c89f9', 'mov    %r15,%rcx'), 72402114: ('84c0', 'test   %al,%al'), 72402116: ('75ba', 'jne    0x450c480')}}, 'site_0x450c5eb': {'range': (72402398, 72402441), 'calls': {72402411: '0x35bd8a0'}, 'pins': {72402398: ('488d7c2428', 'lea    0x28(%rsp),%rdi'), 72402403: ('488b542410', 'mov    0x10(%rsp),%rdx'), 72402408: ('4889e1', 'mov    %rsp,%rcx'), 72402411: ('e8b0120bff', 'call   0x35bd8a0'), 72402416: ('488b742408', 'mov    0x8(%rsp),%rsi'), 72402421: ('0fb6442428', 'movzbl 0x28(%rsp),%eax'), 72402426: ('4983c5ff', 'add    $0xffffffffffffffff,%r13'), 72402430: ('7307', 'jae    0x450c607'), 72402432: ('4c89e1', 'mov    %r12,%rcx'), 72402435: ('84c0', 'test   %al,%al'), 72402437: ('75b9', 'jne    0x450c5c0'), 72402439: ('89c1', 'mov    %eax,%ecx')}}, 'site_0x44829ab': {'range': (71838093, 71838157), 'calls': {71838123: '0x35bddb0'}, 'pins': {71838093: ('488b7308', 'mov    0x8(%rbx),%rsi'), 71838097: ('4885f6', 'test   %rsi,%rsi'), 71838100: ('0f84aa000000', 'je     0x4482a44'), 71838106: ('488b5310', 'mov    0x10(%rbx),%rdx'), 71838110: ('488d7c2420', 'lea    0x20(%rsp),%rdi'), 71838115: ('488d8c24a00000', 'lea    0xa0(%rsp),%rcx'), 71838123: ('e800b413ff', 'call   0x35bddb0'), 71838128: ('837c242001', 'cmpl   $0x1,0x20(%rsp)'), 71838133: ('0f8489000000', 'je     0x4482a44'), 71838139: ('488b442438', 'mov    0x38(%rsp),%rax'), 71838144: ('4c8d0440', 'lea    (%rax,%rax,2),%r8'), 71838148: ('49c1e004', 'shl    $0x4,%r8'), 71838152: ('4c03442428', 'add    0x28(%rsp),%r8')}}, 'fallback_0x44829ab': {'range': (71838159, 71838175), 'calls': {71838170: '0x4551810'}, 'pins': {71838159: ('488db424a00000', 'lea    0xa0(%rsp),%rsi'), 71838167: ('4889df', 'mov    %rbx,%rdi'), 71838170: ('e831ee0c00', 'call   0x4551810')}}, 'site_0x2c81276': {'range': (46666331, 46666388), 'calls': {46666358: '0x35be3b0'}, 'pins': {46666331: ('498b7728', 'mov    0x28(%r15),%rsi'), 46666335: ('4885f6', 'test   %rsi,%rsi'), 46666338: ('0f8428010000', 'je     0x2c81390'), 46666344: ('498b5730', 'mov    0x30(%r15),%rdx'), 46666348: ('488d7c2430', 'lea    0x30(%rsp),%rdi'), 46666353: ('488d4c2410', 'lea    0x10(%rsp),%rcx'), 46666358: ('e835d19300', 'call   0x35be3b0'), 46666363: ('837c243001', 'cmpl   $0x1,0x30(%rsp)'), 46666368: ('0f840a010000', 'je     0x2c81390'), 46666374: ('488b442448', 'mov    0x48(%rsp),%rax'), 46666379: ('48c1e004', 'shl    $0x4,%rax'), 46666383: ('4803442438', 'add    0x38(%rsp),%rax')}}, 'fallback_0x2c81276': {'range': (46666400, 46666414), 'calls': {46666409: '0x4551c20'}, 'pins': {46666400: ('498d7f20', 'lea    0x20(%r15),%rdi'), 46666404: ('488d742410', 'lea    0x10(%rsp),%rsi'), 46666409: ('e872098d01', 'call   0x4551c20')}}, 'site_0x2c815b1': {'range': (46667158, 46667211), 'calls': {46667185: '0x35be3b0'}, 'pins': {46667158: ('498b7730', 'mov    0x30(%r15),%rsi'), 46667162: ('4885f6', 'test   %rsi,%rsi'), 46667165: ('0f847d000000', 'je     0x2c81620'), 46667171: ('498b5738', 'mov    0x38(%r15),%rdx'), 46667175: ('488d7c2430', 'lea    0x30(%rsp),%rdi'), 46667180: ('488d4c2410', 'lea    0x10(%rsp),%rcx'), 46667185: ('e8facd9300', 'call   0x35be3b0'), 46667190: ('837c243001', 'cmpl   $0x1,0x30(%rsp)'), 46667195: ('7463', 'je     0x2c81620'), 46667197: ('488b442448', 'mov    0x48(%rsp),%rax'), 46667202: ('48c1e004', 'shl    $0x4,%rax'), 46667206: ('4803442438', 'add    0x38(%rsp),%rax')}}, 'fallback_0x2c815b1': {'range': (46667211, 46667230), 'calls': {46667225: '0x4551c20'}, 'pins': {46667211: ('eb45', 'jmp    0x2c81612'), 46667213: ('0f1f00', 'nopl   (%rax)'), 46667216: ('498d7f28', 'lea    0x28(%r15),%rdi'), 46667220: ('488d742410', 'lea    0x10(%rsp),%rsi'), 46667225: ('e842068d01', 'call   0x4551c20')}}, 'site_0x4474e57': {'range': (71781784, 71781995), 'calls': {71781975: '0x35bf3c0'}, 'pins': {71781784: ('488d9c24100100', 'lea    0x110(%rsp),%rbx'), 71781792: ('4c8dbc24300200', 'lea    0x230(%rsp),%r15'), 71781800: ('4883fe02', 'cmp    $0x2,%rsi'), 71781804: ('0f851e020000', 'jne    0x4474fd0'), 71781810: ('66666666662e0f', 'data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)'), 71781824: ('488b442458', 'mov    0x58(%rsp),%rax'), 71781829: ('488b4c2460', 'mov    0x60(%rsp),%rcx'), 71781834: ('4839c8', 'cmp    %rcx,%rax'), 71781837: ('7526', 'jne    0x4474df5'), 71781839: ('488d542458', 'lea    0x58(%rsp),%rdx'), 71781844: ('0f104210', 'movups 0x10(%rdx),%xmm0'), 71781848: ('0f1102', 'movups %xmm0,(%rdx)'), 71781851: ('4889442468', 'mov    %rax,0x68(%rsp)'), 71781856: ('48894c2470', 'mov    %rcx,0x70(%rsp)'), 71781861: ('488b442458', 'mov    0x58(%rsp),%rax'), 71781866: ('483b442460', 'cmp    0x60(%rsp),%rax'), 71781871: ('0f849b010000', 'je     0x4474f90'), 71781877: ('488d4820', 'lea    0x20(%rax),%rcx'), 71781881: ('48894c2458', 'mov    %rcx,0x58(%rsp)'), 71781886: ('488d5008', 'lea    0x8(%rax),%rdx'), 71781890: ('4885c0', 'test   %rax,%rax'), 71781893: ('0f84d8010000', 'je     0x4474fe3'), 71781899: ('4c8b30', 'mov    (%rax),%r14'), 71781902: ('488b02', 'mov    (%rdx),%rax'), 71781905: ('48898424b00100', 'mov    %rax,0x1b0(%rsp)'), 71781913: ('4c8b6a08', 'mov    0x8(%rdx),%r13'), 71781917: ('4c89b424300200', 'mov    %r14,0x230(%rsp)'), 71781925: ('48b80000000000', 'movabs $0x8000000000000000,%rax'), 71781935: ('4839442420', 'cmp    %rax,0x20(%rsp)'), 71781940: ('753a', 'jne    0x4474e70'), 71781942: ('488b442410', 'mov    0x10(%rsp),%rax'), 71781947: ('48837c243800', 'cmpq   $0x0,0x38(%rsp)'), 71781953: ('0f84a9000000', 'je     0x4474ef0'), 71781959: ('4889df', 'mov    %rbx,%rdi'), 71781962: ('488b742438', 'mov    0x38(%rsp),%rsi'), 71781967: ('488b542440', 'mov    0x40(%rsp),%rdx'), 71781972: ('4c89f9', 'mov    %r15,%rcx'), 71781975: ('e864a514ff', 'call   0x35bf3c0'), 71781980: ('83bc2410010000', 'cmpl   $0x1,0x110(%rsp)'), 71781988: ('756a', 'jne    0x4474ed0'), 71781990: ('488b442410', 'mov    0x10(%rsp),%rax')}}, 'hit_0x4474e57': {'range': (71782096, 71782124), 'calls': {}, 'pins': {71782096: ('488b8424180100', 'mov    0x118(%rsp),%rax'), 71782104: ('488b8c24280100', 'mov    0x128(%rsp),%rcx'), 71782112: ('488d0c89', 'lea    (%rcx,%rcx,4),%rcx'), 71782116: ('488d0488', 'lea    (%rax,%rcx,4),%rax'), 71782120: ('4883c060', 'add    $0x60,%rax')}}, 'fallback_0x4474e57': {'range': (71782000, 71782016), 'calls': {71782011: '0x45585e0'}, 'pins': {71782000: ('488bbc24f00000', 'mov    0xf0(%rsp),%rdi'), 71782008: ('4c89fe', 'mov    %r15,%rsi'), 71782011: ('e860370e00', 'call   0x45585e0')}}, 'site_0x4475469': {'range': (71783503, 71783548), 'calls': {71783529: '0x35bf3c0'}, 'pins': {71783503: ('488dbc24100100', 'lea    0x110(%rsp),%rdi'), 71783511: ('488b742438', 'mov    0x38(%rsp),%rsi'), 71783516: ('488b542440', 'mov    0x40(%rsp),%rdx'), 71783521: ('488d8c24400300', 'lea    0x340(%rsp),%rcx'), 71783529: ('e8529f14ff', 'call   0x35bf3c0'), 71783534: ('83bc2410010000', 'cmpl   $0x1,0x110(%rsp)'), 71783542: ('0f85d0000000', 'jne    0x447554c')}}, 'hit_0x4475469': {'range': (71783756, 71783784), 'calls': {}, 'pins': {71783756: ('488b8424180100', 'mov    0x118(%rsp),%rax'), 71783764: ('488b8c24280100', 'mov    0x128(%rsp),%rcx'), 71783772: ('488d0c89', 'lea    (%rcx,%rcx,4),%rcx'), 71783776: ('488d0488', 'lea    (%rax,%rcx,4),%rax'), 71783780: ('4883c060', 'add    $0x60,%rax')}}, 'fallback_0x4475469': {'range': (71783669, 71783690), 'calls': {71783685: '0x45585e0'}, 'pins': {71783669: ('488bbc24f00000', 'mov    0xf0(%rsp),%rdi'), 71783677: ('488db424400300', 'lea    0x340(%rsp),%rsi'), 71783685: ('e8d6300e00', 'call   0x45585e0')}}, 'site_0x2bafd30': {'range': (45808917, 45808985), 'calls': {45808944: '0x1d65b20'}, 'pins': {45808917: ('498b7620', 'mov    0x20(%r14),%rsi'), 45808921: ('4885f6', 'test   %rsi,%rsi'), 45808924: ('0f849b010000', 'je     0x2bafebd'), 45808930: ('498b5628', 'mov    0x28(%r14),%rdx'), 45808934: ('488d7c2468', 'lea    0x68(%rsp),%rdi'), 45808939: ('488d4c2408', 'lea    0x8(%rsp),%rcx'), 45808944: ('e8eb5d1bff', 'call   0x1d65b20'), 45808949: ('837c246801', 'cmpl   $0x1,0x68(%rsp)'), 45808954: ('0f847d010000', 'je     0x2bafebd'), 45808960: ('488b442470', 'mov    0x70(%rsp),%rax'), 45808965: ('488b8c24800000', 'mov    0x80(%rsp),%rcx'), 45808973: ('488d0cc9', 'lea    (%rcx,%rcx,8),%rcx'), 45808977: ('4c8d34c8', 'lea    (%rax,%rcx,8),%r14'), 45808981: ('4983c660', 'add    $0x60,%r14')}}, 'fallback_0x2bafd30': {'range': (45808999, 45809013), 'calls': {45809008: '0x24c9200'}, 'pins': {45808999: ('498d7e18', 'lea    0x18(%r14),%rdi'), 45809003: ('488d742408', 'lea    0x8(%rsp),%rsi'), 45809008: ('e88b9491ff', 'call   0x24c9200')}}, 'site_0x2baffd0': {'range': (45809589, 45809657), 'calls': {45809616: '0x1d65b20'}, 'pins': {45809589: ('498b7620', 'mov    0x20(%r14),%rsi'), 45809593: ('4885f6', 'test   %rsi,%rsi'), 45809596: ('0f849b010000', 'je     0x2bb015d'), 45809602: ('498b5628', 'mov    0x28(%r14),%rdx'), 45809606: ('488d7c2468', 'lea    0x68(%rsp),%rdi'), 45809611: ('488d4c2408', 'lea    0x8(%rsp),%rcx'), 45809616: ('e84b5b1bff', 'call   0x1d65b20'), 45809621: ('837c246801', 'cmpl   $0x1,0x68(%rsp)'), 45809626: ('0f847d010000', 'je     0x2bb015d'), 45809632: ('488b442470', 'mov    0x70(%rsp),%rax'), 45809637: ('488b8c24800000', 'mov    0x80(%rsp),%rcx'), 45809645: ('488d0cc9', 'lea    (%rcx,%rcx,8),%rcx'), 45809649: ('4c8d34c8', 'lea    (%rax,%rcx,8),%r14'), 45809653: ('4983c660', 'add    $0x60,%r14')}}, 'fallback_0x2baffd0': {'range': (45809671, 45809685), 'calls': {45809680: '0x24c9200'}, 'pins': {45809671: ('498d7e18', 'lea    0x18(%r14),%rdi'), 45809675: ('488d742408', 'lea    0x8(%rsp),%rsi'), 45809680: ('e8eb9191ff', 'call   0x24c9200')}}, 'site_0x57c9480': {'range': (92050533, 92050604), 'calls': {92050560: '0x4d380a0'}, 'pins': {92050533: ('498b7720', 'mov    0x20(%r15),%rsi'), 92050537: ('4885f6', 'test   %rsi,%rsi'), 92050540: ('0f8431020000', 'je     0x57c96a3'), 92050546: ('498b5728', 'mov    0x28(%r15),%rdx'), 92050550: ('488d7c2478', 'lea    0x78(%rsp),%rdi'), 92050555: ('488d4c2418', 'lea    0x18(%rsp),%rcx'), 92050560: ('e81bec56ff', 'call   0x4d380a0'), 92050565: ('837c247801', 'cmpl   $0x1,0x78(%rsp)'), 92050570: ('0f8413020000', 'je     0x57c96a3'), 92050576: ('488b8424800000', 'mov    0x80(%rsp),%rax'), 92050584: ('488b8c24900000', 'mov    0x90(%rsp),%rcx'), 92050592: ('488d0cc9', 'lea    (%rcx,%rcx,8),%rcx'), 92050596: ('4c8d3cc8', 'lea    (%rax,%rcx,8),%r15'), 92050600: ('4983c760', 'add    $0x60,%r15')}}, 'fallback_0x57c9480': {'range': (92050618, 92050632), 'calls': {92050627: '0x57f7210'}, 'pins': {92050618: ('498d7f18', 'lea    0x18(%r15),%rdi'), 92050622: ('488d742418', 'lea    0x18(%rsp),%rsi'), 92050627: ('e848dd0200', 'call   0x57f7210')}}, 'site_0x57c9710': {'range': (92051189, 92051260), 'calls': {92051216: '0x4d380a0'}, 'pins': {92051189: ('498b7720', 'mov    0x20(%r15),%rsi'), 92051193: ('4885f6', 'test   %rsi,%rsi'), 92051196: ('0f8431020000', 'je     0x57c9933'), 92051202: ('498b5728', 'mov    0x28(%r15),%rdx'), 92051206: ('488d7c2478', 'lea    0x78(%rsp),%rdi'), 92051211: ('488d4c2418', 'lea    0x18(%rsp),%rcx'), 92051216: ('e88be956ff', 'call   0x4d380a0'), 92051221: ('837c247801', 'cmpl   $0x1,0x78(%rsp)'), 92051226: ('0f8413020000', 'je     0x57c9933'), 92051232: ('488b8424800000', 'mov    0x80(%rsp),%rax'), 92051240: ('488b8c24900000', 'mov    0x90(%rsp),%rcx'), 92051248: ('488d0cc9', 'lea    (%rcx,%rcx,8),%rcx'), 92051252: ('4c8d3cc8', 'lea    (%rax,%rcx,8),%r15'), 92051256: ('4983c760', 'add    $0x60,%r15')}}, 'fallback_0x57c9710': {'range': (92051274, 92051288), 'calls': {92051283: '0x57f7210'}, 'pins': {92051274: ('498d7f18', 'lea    0x18(%r15),%rdi'), 92051278: ('488d742418', 'lea    0x18(%rsp),%rsi'), 92051283: ('e8b8da0200', 'call   0x57f7210')}}, 'caller_0x4473d10_height_0x4474af8': {'range': (71781081, 71781137), 'calls': {}, 'pins': {71781081: ('752e', 'jne    0x4474b09'), 71781083: ('488b8424180100', 'mov    0x118(%rsp),%rax'), 71781091: ('31c9', 'xor    %ecx,%ecx'), 71781093: ('4889c7', 'mov    %rax,%rdi'), 71781096: ('4885c0', 'test   %rax,%rax'), 71781099: ('0f95c2', 'setne  %dl'), 71781102: ('7408', 'je     0x4474af8'), 71781104: ('488bbc24280100', 'mov    0x128(%rsp),%rdi'), 71781112: ('488bb424200100', 'mov    0x120(%rsp),%rsi'), 71781120: ('88d1', 'mov    %dl,%cl'), 71781122: ('31d2', 'xor    %edx,%edx'), 71781124: ('4989c8', 'mov    %rcx,%r8'), 71781127: ('eb62', 'jmp    0x4474b6b'), 71781129: ('488bb424280100', 'mov    0x128(%rsp),%rsi')}}, 'caller_0x4473d10_height_0x4474b16': {'range': (71781112, 71781168), 'calls': {}, 'pins': {71781112: ('488bb424200100', 'mov    0x120(%rsp),%rsi'), 71781120: ('88d1', 'mov    %dl,%cl'), 71781122: ('31d2', 'xor    %edx,%edx'), 71781124: ('4989c8', 'mov    %rcx,%r8'), 71781127: ('eb62', 'jmp    0x4474b6b'), 71781129: ('488bb424280100', 'mov    0x128(%rsp),%rsi'), 71781137: ('4885f6', 'test   %rsi,%rsi'), 71781140: ('742c', 'je     0x4474b42'), 71781142: ('488b9424200100', 'mov    0x120(%rsp),%rdx'), 71781150: ('31c9', 'xor    %ecx,%ecx'), 71781152: ('4839c2', 'cmp    %rax,%rdx'), 71781155: ('480f43c8', 'cmovae %rax,%rcx'), 71781159: ('4829ca', 'sub    %rcx,%rdx'), 71781162: ('4889c7', 'mov    %rax,%rdi'), 71781165: ('4829d7', 'sub    %rdx,%rdi')}}, 'caller_0x4473d10_height_0x44754b3': {'range': (71783576, 71783630), 'calls': {71783581: '0x3905a40'}, 'pins': {71783576: ('488d742450', 'lea    0x50(%rsp),%rsi'), 71783581: ('e89e0549ff', 'call   0x3905a40'), 71783586: ('488b8424100100', 'mov    0x110(%rsp),%rax'), 71783594: ('4885c0', 'test   %rax,%rax'), 71783597: ('0f848b020000', 'je     0x447573e'), 71783603: ('488b8c24200100', 'mov    0x120(%rsp),%rcx'), 71783611: ('4c8b7cc808', 'mov    0x8(%rax,%rcx,8),%r15'), 71783616: ('488d0c49', 'lea    (%rcx,%rcx,2),%rcx'), 71783620: ('488b54c860', 'mov    0x60(%rax,%rcx,8),%rdx'), 71783625: ('4889542448', 'mov    %rdx,0x48(%rsp)')}}, 'caller_0x4473d10_height_0x4475f09': {'range': (71786217, 71786280), 'calls': {}, 'pins': {71786217: ('7535', 'jne    0x4475f20'), 71786219: ('4c8bbc24180100', 'mov    0x118(%rsp),%r15'), 71786227: ('31c9', 'xor    %ecx,%ecx'), 71786229: ('4c89fe', 'mov    %r15,%rsi'), 71786232: ('4d85ff', 'test   %r15,%r15'), 71786235: ('400f95c7', 'setne  %dil'), 71786239: ('7408', 'je     0x4475f09'), 71786241: ('488bb424280100', 'mov    0x128(%rsp),%rsi'), 71786249: ('488b9424200100', 'mov    0x120(%rsp),%rdx'), 71786257: ('4088f9', 'mov    %dil,%cl'), 71786260: ('31ff', 'xor    %edi,%edi'), 71786262: ('4989c8', 'mov    %rcx,%r8'), 71786265: ('eb6c', 'jmp    0x4475f87'), 71786267: ('0f1f440000', 'nopl   0x0(%rax,%rax,1)'), 71786272: ('488b9424280100', 'mov    0x128(%rsp),%rdx')}}, 'caller_0x4473d10_height_0x4475f2d': {'range': (71786257, 71786311), 'calls': {}, 'pins': {71786257: ('4088f9', 'mov    %dil,%cl'), 71786260: ('31ff', 'xor    %edi,%edi'), 71786262: ('4989c8', 'mov    %rcx,%r8'), 71786265: ('eb6c', 'jmp    0x4475f87'), 71786267: ('0f1f440000', 'nopl   0x0(%rax,%rax,1)'), 71786272: ('488b9424280100', 'mov    0x128(%rsp),%rdx'), 71786280: ('4885d2', 'test   %rdx,%rdx'), 71786283: ('742d', 'je     0x4475f5a'), 71786285: ('488b8c24200100', 'mov    0x120(%rsp),%rcx'), 71786293: ('4c39c1', 'cmp    %r8,%rcx'), 71786296: ('be00000000', 'mov    $0x0,%esi'), 71786301: ('490f43f0', 'cmovae %r8,%rsi'), 71786305: ('4829f1', 'sub    %rsi,%rcx'), 71786308: ('4c89c7', 'mov    %r8,%rdi')}}, 'caller_0x4473d10_height_0x44761ea': {'range': (71786954, 71787010), 'calls': {}, 'pins': {71786954: ('48b80000000000', 'movabs $0x8000000000000000,%rax'), 71786964: ('4939c6', 'cmp    %rax,%r14'), 71786967: ('7557', 'jne    0x4476230'), 71786969: ('488bb424180100', 'mov    0x118(%rsp),%rsi'), 71786977: ('4885f6', 'test   %rsi,%rsi'), 71786980: ('0f84a6000000', 'je     0x4476290'), 71786986: ('488b9424200100', 'mov    0x120(%rsp),%rdx'), 71786994: ('488dbc24b00100', 'lea    0x1b0(%rsp),%rdi'), 71787002: ('488d8c24280200', 'lea    0x228(%rsp),%rcx')}}, 'caller_0x4473d10_height_0x4476258': {'range': (71787064, 71787127), 'calls': {71787072: '0x455cb20'}, 'pins': {71787064: ('488db424280200', 'lea    0x228(%rsp),%rsi'), 71787072: ('e8db680e00', 'call   0x455cb20'), 71787077: ('a801', 'test   $0x1,%al'), 71787079: ('7547', 'jne    0x4476290'), 71787081: ('bb00000000', 'mov    $0x0,%ebx'), 71787086: ('483b9424280100', 'cmp    0x128(%rsp),%rdx'), 71787094: ('733a', 'jae    0x4476292'), 71787096: ('48039424200100', 'add    0x120(%rsp),%rdx'), 71787104: ('4c39f2', 'cmp    %r14,%rdx'), 71787107: ('b800000000', 'mov    $0x0,%eax'), 71787112: ('490f43c6', 'cmovae %r14,%rax'), 71787116: ('4829c2', 'sub    %rax,%rdx'), 71787119: ('488b8424180100', 'mov    0x118(%rsp),%rax')}}, 'caller_0x4482950_height_0x4482cda': {'range': (71838908, 71838965), 'calls': {}, 'pins': {71838908: ('4885c0', 'test   %rax,%rax'), 71838911: ('0f8449030000', 'je     0x448300e'), 71838917: ('488b4c2438', 'mov    0x38(%rsp),%rcx'), 71838922: ('488d5101', 'lea    0x1(%rcx),%rdx'), 71838926: ('488b742428', 'mov    0x28(%rsp),%rsi'), 71838931: ('4839f2', 'cmp    %rsi,%rdx'), 71838934: ('490f42f7', 'cmovb  %r15,%rsi'), 71838938: ('488b542430', 'mov    0x30(%rsp),%rdx'), 71838943: ('48f7de', 'neg    %rsi'), 71838946: ('4801ce', 'add    %rcx,%rsi'), 71838949: ('48ffc6', 'inc    %rsi'), 71838952: ('4889742438', 'mov    %rsi,0x38(%rsp)'), 71838957: ('48ffc8', 'dec    %rax'), 71838960: ('4889442440', 'mov    %rax,0x40(%rsp)')}}, 'caller_0x4482950_height_0x4483022': {'range': (71839746, 71839809), 'calls': {}, 'pins': {71839746: ('e946feffff', 'jmp    0x4482e4d'), 71839751: ('837c242002', 'cmpl   $0x2,0x20(%rsp)'), 71839756: ('752b', 'jne    0x4483039'), 71839758: ('488b442428', 'mov    0x28(%rsp),%rax'), 71839763: ('4885c0', 'test   %rax,%rax'), 71839766: ('488b6c2408', 'mov    0x8(%rsp),%rbp'), 71839771: ('4c8b6c2410', 'mov    0x10(%rsp),%r13'), 71839776: ('7444', 'je     0x4483066'), 71839778: ('488b7c2430', 'mov    0x30(%rsp),%rdi'), 71839783: ('48c1e003', 'shl    $0x3,%rax'), 71839787: ('488d3480', 'lea    (%rax,%rax,4),%rsi'), 71839791: ('31d2', 'xor    %edx,%edx'), 71839793: ('ff1569c40502', 'call   *0x205c469(%rip)        # 0x64df4a0'), 71839799: ('eb2d', 'jmp    0x4483066'), 71839801: ('488d9c24a00000', 'lea    0xa0(%rsp),%rbx')}}}

SLOT_CENSUS = {'0x2bafce0|0x68': {'flag': [45808949], 'node': [45808960], 'height': [], 'position': [45808965]}, '0x2baff80|0x68': {'flag': [45809621], 'node': [45809632], 'height': [], 'position': [45809637]}, '0x2c81080|0x30': {'flag': [46666363, 46667190], 'node': [46666383, 46667206], 'height': [], 'position': [46666374, 46667197]}, '0x4473d10|0x110': {'flag': [71779337, 71781060, 71781355, 71781980, 71782960, 71783534, 71783586, 71784523, 71786196, 71786946, 71789115, 71790185], 'node': [71781083, 71781192, 71782096, 71782943, 71783756, 71786219, 71786337, 71786969, 71787119], 'height': [71781112, 71781142, 71781363, 71783603, 71786249, 71786285, 71786986, 71787096], 'position': [71781104, 71781129, 71782104, 71783764, 71786241, 71786272, 71787086]}, '0x4482950|0x20': {'flag': [71838128, 71838896, 71839751], 'node': [71838152, 71838926, 71839758], 'height': [71838938, 71839778], 'position': [71838139, 71838917]}, '0x450c430|0x28': {'flag': [72402100, 72402421], 'node': [], 'height': [], 'position': []}, '0x57c9430|0x78': {'flag': [92050565], 'node': [92050576], 'height': [], 'position': [92050584]}, '0x57c96c0|0x78': {'flag': [92051221], 'node': [92051232], 'height': [], 'position': [92051240]}}

HEIGHT_READS = {'0x2bafce0|0x68': {}, '0x2baff80|0x68': {}, '0x2c81080|0x30': {}, '0x4473d10|0x110': {71781112: 'other_phase', 71781142: 'other_phase', 71781363: 'vector_copy', 71783603: 'other_phase', 71786249: 'other_phase', 71786285: 'other_phase', 71786986: 'other_phase', 71787096: 'other_phase'}, '0x4482950|0x20': {71838938: 'other_phase', 71839778: 'other_phase'}, '0x450c430|0x28': {}, '0x57c9430|0x78': {}, '0x57c96c0|0x78': {}}

EXPECTED = {'bodies': 6, 'body_bytes': 876, 'distinct_body_digests': 5, 'clone_body_pairs': 1, 'call_sites': 11, 'tail_call_sites': 0, 'rela_hits': 0, 'callers': 8, 'census_units': 8, 'flag_only_sites': 2, 'node_position_sites': 9, 'flag_dword_sites': 9, 'flag_byte_sites': 0, 'flag_register_sites': 2, 'distinct_strides': 4, 'distinct_fallbacks': 5, 'sites_without_fallback': 2, 'height_slot_reads': 10, 'vector_copy_reads': 1, 'other_phase_reads': 9, 'height_consumed_reads': 0, 'height_never_read_units': 6}


BODY_BY_START = {info['range'][0]: slug for slug, info in BODIES.items()}
FALLBACK_SET = {info['fallback'] for info in SITES.values() if info['fallback']}


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


def _slot_reads(rows, slot):
    needle = f'{slot:#x}(%rsp)'
    return [address for address in sorted(rows)
            if needle in rows[address][1]
            and not rows[address][1].startswith('lea')
            and not _STORE_RE.match(rows[address][1])]


def _scale_factor(text, current):
    match = re.match(r'shl\s+\$0x([0-9a-f]+),%(\w+)$', text)
    if match:
        if match.group(2) != current:
            raise AssertionError(f'scale instruction {text!r} leaves the value chain')
        return 1 << int(match.group(1), 16), current
    match = re.match(r'imul\s+\$0x([0-9a-f]+),%(\w+)$', text)
    if match:
        if match.group(2) != current:
            raise AssertionError(f'scale instruction {text!r} leaves the value chain')
        return int(match.group(1), 16), current
    match = re.match(r'imul\s+\$0x([0-9a-f]+),%(\w+),%(\w+)$', text)
    if match:
        if match.group(2) != current:
            raise AssertionError(f'scale instruction {text!r} leaves the value chain')
        return int(match.group(1), 16), match.group(3)
    match = re.match(r'lea\s+\(%(\w+),%\w+,(\d+)\),%(\w+)$', text)
    if match:
        if match.group(1) != current:
            raise AssertionError(f'scale instruction {text!r} leaves the value chain')
        return int(match.group(2)) + 1, match.group(3)
    match = re.match(r'lea\s+0x0\(,%(\w+),(\d+)\),%(\w+)$', text)
    if match:
        if match.group(1) != current:
            raise AssertionError(f'scale instruction {text!r} leaves the value chain')
        return int(match.group(2)), match.group(3)
    raise AssertionError(f'unhandled scale instruction {text!r}')


def _row_end(rows, address, fde_end):
    later = [a for a in rows if a > address]
    return min(later) if later else fde_end


def _flag_jump(rows, flag, fde_end):
    """Find the conditional jump consuming a flag comparison.

    Scans forward from the flag test over instructions that cannot
    affect the flags (mov, lea, nop, data16) and returns
    (jump address, mnemonic, target)."""
    addr = _row_end(rows, flag, fde_end)
    for _ in range(14):
        row = rows.get(addr)
        if row is None:
            break
        text = row[1]
        mnemonic = text.split()[0] if text.split() else ''
        if mnemonic.startswith('j'):
            parts = text.split()
            if len(parts) == 2 and parts[1].startswith('0x'):
                return addr, mnemonic, int(parts[1], 16)
            break
        if mnemonic not in ('mov', 'lea', 'nop', 'data16'):
            break
        addr = _row_end(rows, addr, fde_end)
    raise AssertionError(f'no conditional jump consumes the flag test at {flag:#x}')


def _reaches(rows, start, goal):
    for address in sorted(a for a in rows if a >= start):
        if address == goal:
            return True
        if address > goal:
            return False
        mnemonic = rows[address][1].split()[0] if rows[address][1].split() else ''
        if mnemonic.startswith(('j', 'loop')) or mnemonic in ('call', 'ret'):
            return False
    return False


def _consumption_on_hit(rows, flag, add, flag_form, fde_end):
    """Prove the node+position add sits on the flag test's hit side."""
    jaddr, mnemonic, target = _flag_jump(rows, flag, fde_end)
    fall = _row_end(rows, jaddr, fde_end)
    if flag_form == 'dword':
        hit_is_target = mnemonic in ('jne', 'jnz')
    else:
        hit_is_target = mnemonic in ('je', 'jz')
    hit_start = target if hit_is_target else fall
    miss_start = fall if hit_is_target else target
    return _reaches(rows, hit_start, add) and not _reaches(rows, miss_start, add)


def analyze(data):
    secs = sections(data)
    _summary, fdes, _gaps = fde_extents(data)
    if len(fdes) != FDE_COUNT:
        raise AssertionError(f'FDE census is {len(fdes)}, expected {FDE_COUNT}')
    if len({f['start'] for f in fdes}) != FDE_COUNT:
        raise AssertionError('FDE starts are not unique')
    extents = {f['start']: (f['start'], f['end']) for f in fdes}

    # --- bodies: extents, digests, pins, layout evidence ---
    body_sites = {slug: [] for slug in BODIES}
    for site, info in SITES.items():
        body_sites[info['body']].append(site)
    for slug, info in BODIES.items():
        start, end = info['range']
        if extents.get(start) != (start, end):
            raise AssertionError(f'{slug} range is not an exact FDE extent')
        if _digest(data, secs, start, end) != info['sha256']:
            raise AssertionError(f'{slug} body differs from its pinned digest')
        rows = _decode(data, secs, start, end)
        _check_pins(rows, BODY_PINS[slug], slug)
        if any(text.startswith('call') for _raw, text in rows.values()):
            raise AssertionError(f'{slug} body contains a call')
        for address, (_raw, text) in rows.items():
            parts = text.split()
            if parts and (parts[0].startswith('j') or parts[0].startswith('loop')):
                if len(parts) == 2 and re.fullmatch(r'0x[0-9a-f]+', parts[1]):
                    if not start <= int(parts[1], 16) < end:
                        raise AssertionError(
                            f'{slug} branch at {address:#x} leaves the body')
        layout = info['layout']
        landmarks = info['landmarks']
        count_text = rows[landmarks['count_load']][1]
        if f"{layout['count_offset']:#x}(%rsi)" not in count_text:
            raise AssertionError(f'{slug} count load does not pin the count offset')
        compare_text = rows[landmarks['key_compare']][1]
        scan_disp = layout['key_offset'] + layout['key_size']
        if f"{scan_disp:#x}(%rsi,%rdi,{layout['key_size']})" not in compare_text:
            raise AssertionError(f'{slug} key compare does not pin the key layout')
        descent_text = rows[landmarks['descent_load']][1]
        if f"{layout['edge_base']:#x}(%rsi,%rdi,8)" not in descent_text:
            raise AssertionError(f'{slug} descent load does not pin the edge base')
        if layout['child_index_offset'] != layout['count_offset'] - 2:
            raise AssertionError(f'{slug} child-index offset breaks the family position')
        if layout['trailer'] == 'gapped':
            if layout['edge_base'] != layout['count_offset'] + 6:
                raise AssertionError(f'{slug} edge base breaks the gapped trailer')
            span = layout['count_offset'] - 2 - layout['key_offset']
        elif layout['trailer'] == 'u32':
            if layout['edge_base'] != layout['count_offset'] + 2:
                raise AssertionError(f'{slug} edge base breaks the u32 trailer')
            span = layout['count_offset'] - 2 - layout['key_offset']
        else:
            if layout['edge_base'] != layout['count_offset'] + 2:
                raise AssertionError(f'{slug} edge base breaks the gapless trailer')
            span = layout['count_offset'] - 6 - layout['key_offset']
        if span != layout['keys_per_node'] * layout['key_size']:
            raise AssertionError(f'{slug} keys-per-node arithmetic does not close')
        signed = any(text.startswith('setl') for _raw, text in rows.values())
        if signed != (info['compare'] == 'signed'):
            raise AssertionError(f'{slug} compare form differs')

    # --- callers ---
    caller_rows = {}
    for caller, ((start, end), caller_sha) in BOUNDARIES.items():
        if extents.get(start) != (start, end):
            raise AssertionError(f'caller {caller:#x} range is not an exact FDE extent')
        if _digest(data, secs, start, end) != caller_sha:
            raise AssertionError(f'caller {caller:#x} differs from its pinned digest')
        caller_rows[caller] = _decode(data, secs, start, end)

    # --- direct call / tail call / relocation census per body ---
    census = {slug: {'e8': [], 'e9': []} for slug in BODIES}
    for sec in secs:
        if sec['type'] == 8 or sec['size'] == 0:
            continue
        blob = _section_bytes(data, secs, sec['address'], sec['address'] + sec['size'])
        for opcode, key in ((0xE8, 'e8'), (0xE9, 'e9')):
            pos = 0
            while True:
                pos = blob.find(bytes([opcode]), pos)
                if pos < 0 or pos + 5 > len(blob):
                    break
                rel = struct.unpack_from('<i', blob, pos + 1)[0]
                target = sec['address'] + pos + 5 + rel
                if target in BODY_BY_START:
                    census[BODY_BY_START[target]][key].append(sec['address'] + pos)
                pos += 1
    rela_hits = {slug: 0 for slug in BODIES}
    for sec in secs:
        if sec['type'] != 4:
            continue
        blob = _section_bytes(data, secs, sec['address'], sec['address'] + sec['size'])
        for off in range(0, len(blob) - 23, 24):
            _r_offset, r_info, r_addend = struct.unpack_from('<QQq', blob, off)
            if r_info & 0xFFFFFFFF == 8 and r_addend in BODY_BY_START:
                rela_hits[BODY_BY_START[r_addend]] += 1
    for slug in BODIES:
        if sorted(census[slug]['e8']) != sorted(body_sites[slug]):
            raise AssertionError(f'{slug} direct call census differs')
        if census[slug]['e9']:
            raise AssertionError(f'{slug} has tail-call sites')
        if rela_hits[slug]:
            raise AssertionError(f'{slug} has R_X86_64_RELATIVE references')

    _check_windows(data, secs)

    # --- sites ---
    for site, info in SITES.items():
        slug = info['body']
        body_start = BODIES[slug]['range'][0]
        rows = caller_rows[info['caller']]
        row = rows.get(site)
        if row is None or row[1].split() != ['call', f'{body_start:#x}']:
            raise AssertionError(f'site {site:#x} is not a call to {body_start:#x}')
        base = info['base']
        flag_text = rows[info['flag']][1]
        flag_slot = f"{base + RECORD_LAYOUT['flag']:#x}(%rsp)"
        if info['flag_form'] == 'dword':
            if not (flag_text.startswith('cmpl') and '$0x1' in flag_text
                    and flag_slot in flag_text):
                raise AssertionError(f'site {site:#x} flag test differs')
        elif info['flag_form'] == 'byte':
            if not (flag_text.startswith('cmpb') and flag_slot in flag_text):
                raise AssertionError(f'site {site:#x} flag test differs')
        else:
            if not (flag_text.startswith('movzbl') and flag_slot in flag_text):
                raise AssertionError(f'site {site:#x} flag load differs')
            test_text = rows[info['test']][1]
            if not test_text.startswith('test') or info['test'] <= info['flag']:
                raise AssertionError(f'site {site:#x} flag register test differs')
        if info['fallback'] is not None:
            frow = rows.get(info['fallback_call'])
            if frow is None or frow[1].split() != ['call', f"{info['fallback']:#x}"]:
                raise AssertionError(f'site {site:#x} fallback call differs')
        else:
            for _a, (_r, text) in rows.items():
                parts = text.split()
                if len(parts) == 2 and parts[0] == 'call' and parts[1].startswith('0x'):
                    if int(parts[1], 16) in FALLBACK_SET:
                        raise AssertionError(
                            f'site {site:#x} caller uses a family fallback after all')
        if info['class'] == 'flag_only':
            window = WINDOWS[f'site_{site:#x}']
            wend = window['range'][1]
            wrows = {a: rows[a] for a in rows if site < a < wend}
            for field in ('node', 'height', 'position'):
                if _slot_reads(wrows, base + FIELD_OFFSETS[field]):
                    raise AssertionError(
                        f'flag-only site {site:#x} reads the record {field} after the call')
        else:
            cons = info['consumption']
            pos_text = rows[cons['position']][1]
            pos_slot = f"{base + RECORD_LAYOUT['position']:#x}(%rsp)"
            if not (pos_text.startswith('mov') and pos_slot in pos_text):
                raise AssertionError(f'site {site:#x} position load differs')
            current = pos_text.split(',')[-1].strip().lstrip('%')
            stride = 1
            for scale_addr in cons['scale']:
                factor, current = _scale_factor(rows[scale_addr][1], current)
                stride *= factor
            add_text = rows[cons['add']][1]
            node_slot = f"{base + RECORD_LAYOUT['node']:#x}(%rsp)"
            if add_text.startswith('add'):
                if node_slot not in add_text or \
                        add_text.split(',')[-1].strip() != f'%{current}':
                    raise AssertionError(f'site {site:#x} node add differs')
            else:
                match = re.match(r'lea\s+\(%(\w+),%(\w+),(\d+)\),%(\w+)$', add_text)
                if not match or match.group(2) != current:
                    raise AssertionError(f'site {site:#x} node add differs')
                stride *= int(match.group(3))
                if cons['node'] is None:
                    raise AssertionError(f'site {site:#x} lea add lacks a node load')
                node_text = rows[cons['node']][1]
                if not (node_text.startswith('mov') and node_slot in node_text):
                    raise AssertionError(f'site {site:#x} node load differs')
            if stride != cons['stride']:
                raise AssertionError(f'site {site:#x} element stride differs')
            fde_end = BOUNDARIES[info['caller']][0][1]
            if not _consumption_on_hit(rows, info['flag'], cons['add'],
                                        info['flag_form'], fde_end):
                raise AssertionError(
                    f'site {site:#x} consumption is not on the hit side')
            jaddr, mnemonic, target = _flag_jump(rows, info['flag'], fde_end)
            fall = _row_end(rows, jaddr, fde_end)
            hit_is_target = mnemonic in ('jne', 'jnz') if info['flag_form'] == 'dword' \
                else mnemonic in ('je', 'jz')
            if (target if hit_is_target else fall) != info['hit_start']:
                raise AssertionError(f'site {site:#x} hit block start differs')

    # --- whole-FDE slot census ---
    for key, expected in SLOT_CENSUS.items():
        caller_hex, base_hex = key.split('|')
        caller, base = int(caller_hex, 16), int(base_hex, 16)
        rows = caller_rows[caller]
        actual = {field: _slot_reads(rows, base + FIELD_OFFSETS[field])
                  for field in FIELDS}
        if actual != expected:
            raise AssertionError(f'slot census differs for unit {key}')

    # --- height attribution ---
    for key, reads in HEIGHT_READS.items():
        caller = int(key.split('|')[0], 16)
        rows = caller_rows[caller]
        if sorted(reads) != SLOT_CENSUS[key]['height']:
            raise AssertionError(f'height attribution does not cover unit {key}')
        for address, cls in reads.items():
            mnemonic = rows[address][1].split()[0]
            if cls == 'vector_copy':
                if mnemonic not in VECTOR_MNEMONICS:
                    raise AssertionError(
                        f'height read {address:#x} is classed vector_copy but is {mnemonic}')
            elif cls == 'other_phase':
                window = WINDOWS.get(f'caller_{caller:#x}_height_{address:#x}')
                if window is None or address not in window['pins']:
                    raise AssertionError(
                        f'height read {address:#x} lacks an attribution window')
            else:
                raise AssertionError(f'unknown height read class {cls!r}')

    # --- height is never consumed: no census height read lies inside a
    # site's own call window or hit window ---
    unit_windows = {}
    for site, info in SITES.items():
        key = f"{info['caller']:#x}|{info['base']:#x}"
        ranges = unit_windows.setdefault(key, [])
        ranges.append(WINDOWS[f'site_{site:#x}']['range'])
        if f'hit_{site:#x}' in WINDOWS:
            ranges.append(WINDOWS[f'hit_{site:#x}']['range'])
    for key, census_entry in SLOT_CENSUS.items():
        for read in census_entry['height']:
            for (ws, we) in unit_windows.get(key, []):
                if ws <= read < we:
                    raise AssertionError(
                        f'height read {read:#x} lies inside a consumption window')

    counters = {
        'bodies': len(BODIES),
        'body_bytes': sum(info['range'][1] - info['range'][0]
                          for info in BODIES.values()),
        'distinct_body_digests': len({info['sha256'] for info in BODIES.values()}),
        'clone_body_pairs': len(BODIES) - len({info['sha256']
                                               for info in BODIES.values()}),
        'call_sites': len(SITES),
        'tail_call_sites': sum(len(census[s]['e9']) for s in BODIES),
        'rela_hits': sum(rela_hits.values()),
        'callers': len(BOUNDARIES),
        'census_units': len(SLOT_CENSUS),
        'flag_only_sites': sum(1 for i in SITES.values() if i['class'] == 'flag_only'),
        'node_position_sites': sum(1 for i in SITES.values()
                                   if i['class'] == 'node_position'),
        'flag_dword_sites': sum(1 for i in SITES.values()
                                if i['flag_form'] == 'dword'),
        'flag_byte_sites': sum(1 for i in SITES.values() if i['flag_form'] == 'byte'),
        'flag_register_sites': sum(1 for i in SITES.values()
                                   if i['flag_form'] == 'register'),
        'distinct_strides': len({i['consumption']['stride'] for i in SITES.values()
                                 if i['class'] == 'node_position'}),
        'distinct_fallbacks': len(FALLBACK_SET),
        'sites_without_fallback': sum(1 for i in SITES.values() if not i['fallback']),
        'height_slot_reads': sum(len(c['height']) for c in SLOT_CENSUS.values()),
        'vector_copy_reads': sum(1 for u in HEIGHT_READS.values()
                                 for c in u.values() if c == 'vector_copy'),
        'other_phase_reads': sum(1 for u in HEIGHT_READS.values()
                                 for c in u.values() if c == 'other_phase'),
        'height_consumed_reads': 0,
        'height_never_read_units': sum(1 for c in SLOT_CENSUS.values()
                                       if not c['height']),
    }
    if counters != EXPECTED:
        raise AssertionError(f'counters differ: {counters} != {EXPECTED}')

    bodies_record = {}
    for slug, info in BODIES.items():
        start, end = info['range']
        layout = info['layout']
        bodies_record[slug] = {
            'call_sites': len(body_sites[slug]),
            'compare': info['compare'],
            'landmarks': {name: _hx(a) for name, a in info['landmarks'].items()},
            'node_layout': {
                'child_index_offset': _hx(layout['child_index_offset']),
                'count_offset': _hx(layout['count_offset']),
                'edge_base': _hx(layout['edge_base']),
                'key_offset': _hx(layout['key_offset']),
                'key_size': layout['key_size'],
                'keys_per_node': layout['keys_per_node'],
                'trailer': layout['trailer'],
            },
            'range': [_hx(start), _hx(end)],
            'rela_sites': rela_hits[slug],
            'sha256': info['sha256'],
            'size': end - start,
            'tail_call_sites': len(census[slug]['e9']),
        }
    sites_record = {}
    for site, info in SITES.items():
        entry = {
            'body': info['body'],
            'caller': _hx(info['caller']),
            'class': info['class'],
            'fallback': _hx(info['fallback']) if info['fallback'] else None,
            'flag': _hx(info['flag']),
            'flag_form': info['flag_form'],
            'presentation': info['presentation'],
            'record_base': _hx(info['base']),
            'record_form': info['record_form'],
        }
        if info['class'] == 'flag_only':
            entry['test'] = _hx(info['test'])
        else:
            cons = info['consumption']
            entry['consumption'] = {
                'add': _hx(cons['add']),
                'node': _hx(cons['node']) if cons['node'] is not None else None,
                'position': _hx(cons['position']),
                'scale': [_hx(a) for a in cons['scale']],
                'stride': _hx(cons['stride']),
            }
            entry['element_bias'] = _hx(info['element_bias']) \
                if info['element_bias'] else None
            entry['fallback_call'] = _hx(info['fallback_call'])
            entry['hit_start'] = _hx(info['hit_start'])
        sites_record[_hx(site)] = entry
    return {
        'boundaries': {
            f'caller_{caller:#x}': {'range': [_hx(rng[0]), _hx(rng[1])],
                                    'sha256': sha}
            for caller, (rng, sha) in BOUNDARIES.items()},
        'bodies': bodies_record,
        'call_sites': sites_record,
        'counters': counters,
        'extractor': 'tools/remaining_members_static.py',
        'height_reads': {
            key: {_hx(a): cls for a, cls in reads.items()}
            for key, reads in HEIGHT_READS.items()},
        'height_verdict': 'never consumed as a number in any census unit',
        'packet': PACKET_ID,
        'record_layout': RECORD_LAYOUT,
        'slot_census': {
            key: {field: [_hx(a) for a in addrs] for field, addrs in entry.items()}
            for key, entry in SLOT_CENSUS.items()},
        'windows': sorted(WINDOWS),
    }


def _frames(data):
    retained = {info['range'] for info in BODIES.values()}
    retained |= {rng for rng, _sha in BOUNDARIES.values()}
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
    for slug, info in BODIES.items():
        start, end = info['range']
        name = f'{slug}_full_body_{start:x}_{end:x}_objdump.txt'
        (out_dir / name).write_text(_body_export(data, start, end))
    return records


def main(argv):
    if len(argv) != 3 or argv[1] != 'generate':
        raise SystemExit('usage: remaining_members_static.py generate <out-dir>')
    artifact = ROOT / 'artifacts/node/115/hl-node'
    generate(artifact.read_bytes(), argv[2])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
