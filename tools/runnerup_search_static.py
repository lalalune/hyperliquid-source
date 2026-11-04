#!/usr/bin/env python3
"""RE-006 node #115 runner-up cursor search (0x35be560): retained static packet tool.

The body at 0x35be560 is the fifth cursor-search shape of the RE-006 family,
after the clones (RE-006 main packet), variants A and B (#2530) and the
sibling (#2542) -- the family census in the variant packet counted it
second only to the sibling, with 50 direct call sites.  It walks a node
layout whose u64 keys sit at node + 0x2c8 (11 per node, count word at
node + 0x322, child edges from node + 0x328) and returns the same 32-byte
caller record as the rest of the family (flag +0x0, node +0x8, height
+0x10, position +0x18).  Its 50 direct call sites sit in 29 caller FDEs.
This tool retains, per call site, the record base on the caller's stack,
the setup window, the flag test and the consumption class of the record,
plus a whole-FDE slot census per (caller, base) unit that settles whether
any consumer reads the record's height field as a number (none does:
every height-slot read in the 31 census units is a wholesale vector copy
or belongs to another phase of the caller's own frame slot).

analyze() decodes and checks everything without authenticating the artifact,
so counterfactual byte flips surface as the specific failed check.
generate() authenticates the artifact first, then regenerates records.json,
frames.txt and the runner-up's full-body disassembly export byte-for-byte.
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

PACKET_ID = 'RE-006-node115-runnerup-search'
PACKET_DIR = ROOT / 'research' / 'work-items' / PACKET_ID

RUNNERUP_START = 0x35be560
RUNNERUP_END = 0x35be5f2
RUNNERUP_NAME = 'runnerup_search'
ARTIFACT_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARTIFACT_SIZE = 105896032

# Body landmarks (all pinned again in RUNNERUP_PINS).
KEY_DEREF = 0x35be563        # mov (%rcx),%rcx -- the key is dereferenced once
COUNT_LOAD = 0x35be566       # movzwl 0x322(%rsi),%r8d -- count word at node + 0x322
KEY_COMPARE = 0x35be585      # cmp 0x2d0(%rsi,%rdi,8),%rcx -- scan index from -1: keys at +0x2c8
DESCENT_LOAD = 0x35be5cc     # mov 0x328(%rsi,%rdi,8),%rsi -- child edges from +0x328
FLAG_ZERO = 0x35be5d9        # xor %ecx,%ecx -- hit epilogue: flag 0
NODE_STORE = 0x35be5db       # mov %rsi,0x8(%rax)
HEIGHT_STORE = 0x35be5df     # mov %rdx,0x10(%rax)
POSITION_STORE = 0x35be5e3   # mov %rdi,0x18(%rax)
FLAG_STORE = 0x35be5e7       # mov %rcx,(%rax)
FLAG_ONE = 0x35be5eb         # mov $0x1,%ecx -- miss epilogue: flag 1

NODE_LAYOUT = {
    'keys_per_node': 11,
    'key_offset': 0x2c8,
    'key_size': 8,
    'count_offset': 0x322,
    'edge_base': 0x328,
    'child_index_offset': 0x320,
}
RECORD_LAYOUT = {'size': 32, 'flag': 0x0, 'node': 0x8, 'height': 0x10, 'position': 0x18}
ELEMENT_STRIDE = 0x40
VECTOR_MNEMONICS = ('movups', 'movupd', 'movapd', 'movaps', 'movdqu', 'movdqa')
FDE_COUNT = 135313

EXPECTED = {
    'call_sites': 50,
    'caller_fdes': 29,
    'census_units': 31,
    'node_position_sites': 49,
    'flag_only_sites': 1,
    'flag_node_addr_sites': 0,
    'flag_dword_sites': 48,
    'flag_byte_sites': 2,
    'presentations': {'handle_register': 43, 'handle_stack': 4,
                      'register_pair': 2, 'split_handle': 1},
    'record_forms': {'lea': 48, 'register': 2},
    'height_read_units': 15,
    'height_never_read_units': 16,
    'height_reads': 81,
    'height_vector_copy_reads': 28,
    'height_other_phase_reads': 53,
    'height_consumed_reads': 0,
    'windows': 103,
    'site_windows': 50,
    'attribution_windows': 53,
    'tail_call_sites': 0,
    'rela_relative_hits': 0,
}

RUNNERUP_BODY_SHA256 = 'b9544e43306382e72df633265f96c279104a2f0a6fe9170b3b6ec175efe4e79d'
RUNNERUP_PINS = {
    0x35be560: ('4889f8', 'mov    %rdi,%rax'),
    0x35be563: ('488b09', 'mov    (%rcx),%rcx'),
    0x35be566: ('440fb786220300', 'movzwl 0x322(%rsi),%r8d'),
    0x35be56e: ('4589c1', 'mov    %r8d,%r9d'),
    0x35be571: ('41c1e103', 'shl    $0x3,%r9d'),
    0x35be575: ('48c7c7ffffffff', 'mov    $0xffffffffffffffff,%rdi'),
    0x35be57c: ('0f1f4000', 'nopl   0x0(%rax)'),
    0x35be580: ('4d85c9', 'test   %r9,%r9'),
    0x35be583: ('743b', 'je     0x35be5c0'),
    0x35be585: ('483b8cfed00200', 'cmp    0x2d0(%rsi,%rdi,8),%rcx'),
    0x35be58d: ('410f97c2', 'seta   %r10b'),
    0x35be591: ('4180da00', 'sbb    $0x0,%r10b'),
    0x35be595: ('48ffc7', 'inc    %rdi'),
    0x35be598: ('4983c1f8', 'add    $0xfffffffffffffff8,%r9'),
    0x35be59c: ('4180fa01', 'cmp    $0x1,%r10b'),
    0x35be5a0: ('74de', 'je     0x35be580'),
    0x35be5a2: ('450fb6c2', 'movzbl %r10b,%r8d'),
    0x35be5a6: ('4585c0', 'test   %r8d,%r8d'),
    0x35be5a9: ('742e', 'je     0x35be5d9'),
    0x35be5ab: ('4989d0', 'mov    %rdx,%r8'),
    0x35be5ae: ('4983e801', 'sub    $0x1,%r8'),
    0x35be5b2: ('7318', 'jae    0x35be5cc'),
    0x35be5b4: ('eb35', 'jmp    0x35be5eb'),
    0x35be5b6: ('662e0f1f840000', 'cs nopw 0x0(%rax,%rax,1)'),
    0x35be5c0: ('4c89c7', 'mov    %r8,%rdi'),
    0x35be5c3: ('4989d0', 'mov    %rdx,%r8'),
    0x35be5c6: ('4983e801', 'sub    $0x1,%r8'),
    0x35be5ca: ('721f', 'jb     0x35be5eb'),
    0x35be5cc: ('488bb4fe280300', 'mov    0x328(%rsi,%rdi,8),%rsi'),
    0x35be5d4: ('4c89c2', 'mov    %r8,%rdx'),
    0x35be5d7: ('eb8d', 'jmp    0x35be566'),
    0x35be5d9: ('31c9', 'xor    %ecx,%ecx'),
    0x35be5db: ('48897008', 'mov    %rsi,0x8(%rax)'),
    0x35be5df: ('48895010', 'mov    %rdx,0x10(%rax)'),
    0x35be5e3: ('48897818', 'mov    %rdi,0x18(%rax)'),
    0x35be5e7: ('488908', 'mov    %rcx,(%rax)'),
    0x35be5ea: ('c3', 'ret'),
    0x35be5eb: ('b901000000', 'mov    $0x1,%ecx'),
    0x35be5f0: ('ebe9', 'jmp    0x35be5db'),
}
BOUNDARIES = {
    0x23fdb60: ((0x23fdb60, 0x23fea14), '62aed9b5e67ded3fd7f9743acc9fd3f7cf96e1852180752531ab53438508e425'),
    0x26c9440: ((0x26c9440, 0x26c9cc9), 'b72354d2826c0d2f8f45914c00bb213d31b7bef04cec6f9b22a780beef856a42'),
    0x2bf2ed0: ((0x2bf2ed0, 0x2bf8ad4), '69db6537a973f5c737607109480896d09a8a5aa73b1d7c1df62545dec93ae5b7'),
    0x446b840: ((0x446b840, 0x446bc30), 'acb834a5c1a66553104254771182ae04dc74ab64ee355e26410e5d4cb9a35066'),
    0x446bcd0: ((0x446bcd0, 0x446bdcd), '8f39c668452f6111ebc4ea3647d172b9bffd7ace17aea8898aac95e5ebe5d6c9'),
    0x446c200: ((0x446c200, 0x4472001), 'ef1188179ce0c34ee813bdc8880b31c4f502203717c75570878ff16480346e2d'),
    0x4472010: ((0x4472010, 0x4472b92), 'ac92f91ef9286db95a0e53714de60de7b3dc91f4e07b1811026440f07179adc4'),
    0x4473440: ((0x4473440, 0x4473d07), '911c20776df3201464959b26700d9ebadee31abdc8356f32ea911d141aa88d83'),
    0x4473d10: ((0x4473d10, 0x44770e5), '31333cd99fd618320ec49b1d8ade330be707c538f05f7f2bc8e63752896ac6fc'),
    0x4477d00: ((0x4477d00, 0x4478667), '0c2b0e3b67ebac65d2343bc4b23507c504e896ce0751853fe5ee4095086b22d4'),
    0x447adf0: ((0x447adf0, 0x447c3a4), 'cacf36f2a844e42d29719d92aff99187655f8d633bae779738075eabd5fe27da'),
    0x447df40: ((0x447df40, 0x447e7b7), '81f5305ec67d9e731cbdf1df5f55462dafb755f714c7b3dc6c7686f09b3dec0b'),
    0x447e810: ((0x447e810, 0x447ebee), 'f4f69103f75d09652137330b831abbca10d913ac1d1f64f2cd59e9314756246e'),
    0x447fe90: ((0x447fe90, 0x44810cf), '615ce3aeb6a8c73768f9b8f9c6dede4a82c4d838a10d444d62b2b13351632c08'),
    0x44868f0: ((0x44868f0, 0x4487597), '1524a3d4f7240b351793fb9044b864bc95124921e3a7f806ac5bcab4a55a91b6'),
    0x44875a0: ((0x44875a0, 0x4487901), 'cdddde3878c0d1ed742001c84cc8540250017865ec5d76cee7da93677302dfb2'),
    0x4487db0: ((0x4487db0, 0x4487f9a), 'e868d36c074312b8d965d5d615b4341bf24dd811e0342542f011daebd2dc2988'),
    0x44881b0: ((0x44881b0, 0x44882ff), 'a0f01b265642fbb320920d7e5cd8077e97ef7f3202583b856a9cb37312a9bd29'),
    0x4488820: ((0x4488820, 0x44889e4), 'e7da4638ee7c9db780a2af0a9f1072c334ce4029e0004eecbacda3c81123c717'),
    0x44895f0: ((0x44895f0, 0x44896ed), 'ddfc05291c223d752a264e95431ec7042fa97d95d46ee155f4188f48c9b6e7a9'),
    0x448a370: ((0x448a370, 0x448a475), 'fd7cf23504f9b8396fc33b519d5cb87e5409c8920f25d744d912edb19de59ae6'),
    0x4e86260: ((0x4e86260, 0x4e87a51), '382d37a09c65da4e9ef28281f5197acb537e13b6fb123a0340c5212bf550f4b0'),
    0x4e98260: ((0x4e98260, 0x4e99a51), '579a640c8098aa515d71136252336e78712c66590aa9f43944f5c2f64351066d'),
    0x4f53680: ((0x4f53680, 0x4f54e76), '2c0d89695f88c9e8beb03eaed2081a32cea18541a4deb07263ba91aa5d603b2a'),
    0x4f9e290: ((0x4f9e290, 0x4f9fa86), 'a1d3e69caf5c73bde163702ca48be08572ce89d26f6d5857952dce977490dbdd'),
    0x54cfa90: ((0x54cfa90, 0x54d57a4), '824e0d4571ca1e4393eb87acd38dd36b9e9d87e1762905e464cc6942e698b1cf'),
    0x54d57b0: ((0x54d57b0, 0x54db474), '155583f5bcc0b7aff8164fb7aacf8e4792ba836bb17ae19c2d03e9e437d18ba4'),
    0x591b240: ((0x591b240, 0x591c1d3), '7dcab403ac2de83fad4c66a58a721d442429fc20d7746675e868eefa78f8c234'),
    0x591c1e0: ((0x591c1e0, 0x591d173), '96141040c9294cd4a3a972a76a404a272e008ecc32a5dc71b87bea928e4e8d18'),
}
SITES = {
    0x23fe63e: {"caller": 0x23fdb60, "base": 0x80, "class": 'node_position', "flag": 0x23fe643, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x23fe651, 0x23fe659, 0x23fe65d)},
    0x26c9883: {"caller": 0x26c9440, "base": 0x20, "class": 'node_position', "flag": 0x26c9888, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x26c988f, 0x26c9894, 0x26c9898)},
    0x26c9a6d: {"caller": 0x26c9440, "base": 0x20, "class": 'node_position', "flag": 0x26c9a72, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x26c9b3c, 0x26c9b41, 0x26c9b45)},
    0x2bf5edd: {"caller": 0x2bf2ed0, "base": 0x250, "class": 'node_position', "flag": 0x2bf5ee2, "presentation": 'handle_stack', "record_form": 'lea', "triple": (0x2bf5ef0, 0x2bf5ef8, 0x2bf5efc)},
    0x446b8a4: {"caller": 0x446b840, "base": 0x40, "class": 'node_position', "flag": 0x446b8a9, "presentation": 'register_pair', "record_form": 'lea', "triple": (0x446b8b4, 0x446b8b9, 0x446b8bd)},
    0x446b988: {"caller": 0x446b840, "base": 0x40, "class": 'node_position', "flag": 0x446b98d, "presentation": 'register_pair', "record_form": 'lea', "triple": (0x446b998, 0x446b99d, 0x446b9a1)},
    0x446bd23: {"caller": 0x446bcd0, "base": 0x8, "class": 'node_position', "flag": 0x446bd28, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x446bd2f, 0x446bd34, 0x446bd38)},
    0x446cd9d: {"caller": 0x446c200, "base": 0x430, "class": 'node_position', "flag": 0x446cda2, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x446cdb0, 0x446cdb8, 0x446cdbc)},
    0x446dc81: {"caller": 0x446c200, "base": 0x430, "class": 'node_position', "flag": 0x446dc86, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x446dc94, 0x446dc9c, 0x446dca0)},
    0x446dea2: {"caller": 0x446c200, "base": 0x430, "class": 'node_position', "flag": 0x446dea7, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x446deb5, 0x446debd, 0x446dec1)},
    0x446f3be: {"caller": 0x446c200, "base": 0x430, "class": 'node_position', "flag": 0x446f3c3, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x446f3d1, 0x446f3d9, 0x446f3dd)},
    0x4472331: {"caller": 0x4472010, "base": 0x30, "class": 'node_position', "flag": 0x4472336, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x447237f, 0x4472384, 0x4472388)},
    0x4473681: {"caller": 0x4473440, "base": 0x180, "class": 'node_position', "flag": 0x4473686, "presentation": 'handle_register', "record_form": 'register', "triple": (0x4473694, 0x447369c, 0x44736a0)},
    0x4474575: {"caller": 0x4473d10, "base": 0x50, "class": 'node_position', "flag": 0x447457a, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4474585, 0x447458a, 0x447458e)},
    0x4476202: {"caller": 0x4473d10, "base": 0x1b0, "class": 'node_position', "flag": 0x4476207, "presentation": 'handle_stack', "record_form": 'lea', "triple": (0x4476211, 0x4476219, 0x447621d)},
    0x44762e0: {"caller": 0x4473d10, "base": 0x1b0, "class": 'node_position', "flag": 0x44762e5, "presentation": 'split_handle', "record_form": 'lea', "triple": (0x44762f3, 0x44762fb, 0x44762ff)},
    0x44781ad: {"caller": 0x4477d00, "base": 0x20, "class": 'flag_only', "flag": 0x44781b2, "presentation": 'handle_register', "record_form": 'register', "triple": None},
    0x447b460: {"caller": 0x447adf0, "base": 0x278, "class": 'node_position', "flag": 0x447b465, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x447b473, 0x447b47b, 0x447b47f)},
    0x447b876: {"caller": 0x447adf0, "base": 0x278, "class": 'node_position', "flag": 0x447b87b, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x447b91a, 0x447b922, 0x447b926)},
    0x447baf7: {"caller": 0x447adf0, "base": 0x70, "class": 'node_position', "flag": 0x447bafc, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x447bb03, 0x447bb0b, 0x447bb0f)},
    0x447e20a: {"caller": 0x447df40, "base": 0x40, "class": 'node_position', "flag": 0x447e20f, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x447e21a, 0x447e21f, 0x447e223)},
    0x447e910: {"caller": 0x447e810, "base": 0x30, "class": 'node_position', "flag": 0x447e915, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x447e920, 0x447e925, 0x447e929)},
    0x4480a2a: {"caller": 0x447fe90, "base": 0x130, "class": 'node_position', "flag": 0x4480a2f, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4480a39, 0x4480a41, 0x4480a45)},
    0x4486ac2: {"caller": 0x44868f0, "base": 0x40, "class": 'node_position', "flag": 0x4486ac7, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4486ad2, 0x4486ad7, 0x4486adb)},
    0x4487708: {"caller": 0x44875a0, "base": 0x40, "class": 'node_position', "flag": 0x448770d, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4487718, 0x448771d, 0x4487721)},
    0x4487e33: {"caller": 0x4487db0, "base": 0x8, "class": 'node_position', "flag": 0x4487e38, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4487e3f, 0x4487e44, 0x4487e48)},
    0x4488213: {"caller": 0x44881b0, "base": 0x18, "class": 'node_position', "flag": 0x4488218, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x448821f, 0x4488224, 0x4488228)},
    0x44888ad: {"caller": 0x4488820, "base": 0x18, "class": 'node_position', "flag": 0x44888b2, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x44888b9, 0x44888be, 0x44888c2)},
    0x4489643: {"caller": 0x44895f0, "base": 0x8, "class": 'node_position', "flag": 0x4489648, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x448964f, 0x4489654, 0x4489658)},
    0x448a3c6: {"caller": 0x448a370, "base": 0x8, "class": 'node_position', "flag": 0x448a3cb, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x448a3d2, 0x448a3d7, 0x448a3db)},
    0x4e86c60: {"caller": 0x4e86260, "base": 0x60, "class": 'node_position', "flag": 0x4e86c65, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4e86c6c, 0x4e86c71, 0x4e86c75)},
    0x4e86e28: {"caller": 0x4e86260, "base": 0x60, "class": 'node_position', "flag": 0x4e86e2d, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4e86e38, 0x4e86e3d, 0x4e86e41)},
    0x4e873f0: {"caller": 0x4e86260, "base": 0x60, "class": 'node_position', "flag": 0x4e873f5, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4e873fc, 0x4e87401, 0x4e87405)},
    0x4e8757a: {"caller": 0x4e86260, "base": 0x60, "class": 'node_position', "flag": 0x4e8757f, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4e87586, 0x4e8758b, 0x4e8758f)},
    0x4e98c60: {"caller": 0x4e98260, "base": 0x60, "class": 'node_position', "flag": 0x4e98c65, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4e98c6c, 0x4e98c71, 0x4e98c75)},
    0x4e98e28: {"caller": 0x4e98260, "base": 0x60, "class": 'node_position', "flag": 0x4e98e2d, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4e98e38, 0x4e98e3d, 0x4e98e41)},
    0x4e993f0: {"caller": 0x4e98260, "base": 0x60, "class": 'node_position', "flag": 0x4e993f5, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4e993fc, 0x4e99401, 0x4e99405)},
    0x4e9957a: {"caller": 0x4e98260, "base": 0x60, "class": 'node_position', "flag": 0x4e9957f, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4e99586, 0x4e9958b, 0x4e9958f)},
    0x4f542de: {"caller": 0x4f53680, "base": 0x60, "class": 'node_position', "flag": 0x4f542e3, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4f542ea, 0x4f542ef, 0x4f542f3)},
    0x4f544fc: {"caller": 0x4f53680, "base": 0x60, "class": 'node_position', "flag": 0x4f54501, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4f545c7, 0x4f545cc, 0x4f545d0)},
    0x4f548df: {"caller": 0x4f53680, "base": 0x60, "class": 'node_position', "flag": 0x4f548e4, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4f548eb, 0x4f548f0, 0x4f548f4)},
    0x4f54afe: {"caller": 0x4f53680, "base": 0x60, "class": 'node_position', "flag": 0x4f54b03, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4f54bc2, 0x4f54bc7, 0x4f54bcb)},
    0x4f9eeee: {"caller": 0x4f9e290, "base": 0x60, "class": 'node_position', "flag": 0x4f9eef3, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4f9eefa, 0x4f9eeff, 0x4f9ef03)},
    0x4f9f10c: {"caller": 0x4f9e290, "base": 0x60, "class": 'node_position', "flag": 0x4f9f111, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4f9f1d7, 0x4f9f1dc, 0x4f9f1e0)},
    0x4f9f4ef: {"caller": 0x4f9e290, "base": 0x60, "class": 'node_position', "flag": 0x4f9f4f4, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4f9f4fb, 0x4f9f500, 0x4f9f504)},
    0x4f9f70e: {"caller": 0x4f9e290, "base": 0x60, "class": 'node_position', "flag": 0x4f9f713, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x4f9f7d2, 0x4f9f7d7, 0x4f9f7db)},
    0x54d2ee0: {"caller": 0x54cfa90, "base": 0xb0, "class": 'node_position', "flag": 0x54d2ee5, "presentation": 'handle_stack', "record_form": 'lea', "triple": (0x54d2ef3, 0x54d2efb, 0x54d2eff)},
    0x54d8b80: {"caller": 0x54d57b0, "base": 0xa0, "class": 'node_position', "flag": 0x54d8b85, "presentation": 'handle_stack', "record_form": 'lea', "triple": (0x54d8b93, 0x54d8b9b, 0x54d8b9f)},
    0x591bd9b: {"caller": 0x591b240, "base": 0x80, "class": 'node_position', "flag": 0x591bda0, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x591bdae, 0x591bdb6, 0x591bdba)},
    0x591cd3b: {"caller": 0x591c1e0, "base": 0x80, "class": 'node_position', "flag": 0x591cd40, "presentation": 'handle_register', "record_form": 'lea', "triple": (0x591cd4e, 0x591cd56, 0x591cd5a)},
}
WINDOWS = {
    'site_0x23fe63e': {"range": (0x23fe620, 0x23fe665), "calls": {}, "pins": {
        0x23fe620: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x23fe62d: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x23fe631: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        0x23fe639: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        0x23fe63e: ('e81dff1b01', 'call   0x35be560'),
        0x23fe643: ('83bc2480000000', 'cmpl   $0x1,0x80(%rsp)'),
        0x23fe651: ('488b8424980000', 'mov    0x98(%rsp),%rax'),
        0x23fe659: ('48c1e006', 'shl    $0x6,%rax'),
        0x23fe65d: ('48038424880000', 'add    0x88(%rsp),%rax'),
    }},
    'site_0x26c9883': {"range": (0x26c9868, 0x26c989d), "calls": {}, "pins": {
        0x26c9868: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x26c9875: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x26c9879: ('488d7c2420', 'lea    0x20(%rsp),%rdi'),
        0x26c987e: ('488d4c2408', 'lea    0x8(%rsp),%rcx'),
        0x26c9883: ('e8d84cef00', 'call   0x35be560'),
        0x26c9888: ('837c242001', 'cmpl   $0x1,0x20(%rsp)'),
        0x26c988f: ('488b442438', 'mov    0x38(%rsp),%rax'),
        0x26c9894: ('48c1e006', 'shl    $0x6,%rax'),
        0x26c9898: ('4803442428', 'add    0x28(%rsp),%rax'),
    }},
    'site_0x26c9a6d': {"range": (0x26c9a52, 0x26c9b4e), "calls": {0x26c9ab8: 0x455cb20}, "pins": {
        0x26c9a52: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x26c9a5f: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x26c9a63: ('488d7c2420', 'lea    0x20(%rsp),%rdi'),
        0x26c9a68: ('488d4c2408', 'lea    0x8(%rsp),%rcx'),
        0x26c9a6d: ('e8ee4aef00', 'call   0x35be560'),
        0x26c9a72: ('837c242001', 'cmpl   $0x1,0x20(%rsp)'),
        0x26c9b3c: ('488b4c2438', 'mov    0x38(%rsp),%rcx'),
        0x26c9b41: ('48c1e106', 'shl    $0x6,%rcx'),
        0x26c9b45: ('48034c2428', 'add    0x28(%rsp),%rcx'),
    }},
    'site_0x2bf5edd': {"range": (0x2bf5eb4, 0x2bf5f04), "calls": {}, "pins": {
        0x2bf5eb4: ('488bb424c80500', 'mov    0x5c8(%rsp),%rsi'),
        0x2bf5ec5: ('488b9424d00500', 'mov    0x5d0(%rsp),%rdx'),
        0x2bf5ecd: ('488dbc24500200', 'lea    0x250(%rsp),%rdi'),
        0x2bf5ed5: ('488d8c24f00100', 'lea    0x1f0(%rsp),%rcx'),
        0x2bf5edd: ('e87e869c00', 'call   0x35be560'),
        0x2bf5ee2: ('83bc2450020000', 'cmpl   $0x1,0x250(%rsp)'),
        0x2bf5ef0: ('488b8424680200', 'mov    0x268(%rsp),%rax'),
        0x2bf5ef8: ('48c1e006', 'shl    $0x6,%rax'),
        0x2bf5efc: ('48038424580200', 'add    0x258(%rsp),%rax'),
    }},
    'site_0x446b8a4': {"range": (0x446b894, 0x446b8c2), "calls": {}, "pins": {
        0x446b894: ('488d7c2440', 'lea    0x40(%rsp),%rdi'),
        0x446b899: ('488d4c2420', 'lea    0x20(%rsp),%rcx'),
        0x446b89e: ('4c89e6', 'mov    %r12,%rsi'),
        0x446b8a1: ('4c89f2', 'mov    %r14,%rdx'),
        0x446b8a4: ('e8b72c15ff', 'call   0x35be560'),
        0x446b8a9: ('837c244001', 'cmpl   $0x1,0x40(%rsp)'),
        0x446b8b4: ('488b442458', 'mov    0x58(%rsp),%rax'),
        0x446b8b9: ('48c1e006', 'shl    $0x6,%rax'),
        0x446b8bd: ('4803442448', 'add    0x48(%rsp),%rax'),
    }},
    'site_0x446b988': {"range": (0x446b978, 0x446b9a6), "calls": {}, "pins": {
        0x446b978: ('488d7c2440', 'lea    0x40(%rsp),%rdi'),
        0x446b97d: ('488d4c2420', 'lea    0x20(%rsp),%rcx'),
        0x446b982: ('4c89e6', 'mov    %r12,%rsi'),
        0x446b985: ('4c89f2', 'mov    %r14,%rdx'),
        0x446b988: ('e8d32b15ff', 'call   0x35be560'),
        0x446b98d: ('837c244001', 'cmpl   $0x1,0x40(%rsp)'),
        0x446b998: ('488b442458', 'mov    0x58(%rsp),%rax'),
        0x446b99d: ('48c1e006', 'shl    $0x6,%rax'),
        0x446b9a1: ('4803442448', 'add    0x48(%rsp),%rax'),
    }},
    'site_0x446bd23': {"range": (0x446bd0e, 0x446bd3d), "calls": {}, "pins": {
        0x446bd0e: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x446bd17: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x446bd1b: ('488d7c2408', 'lea    0x8(%rsp),%rdi'),
        0x446bd20: ('4889e1', 'mov    %rsp,%rcx'),
        0x446bd23: ('e8382815ff', 'call   0x35be560'),
        0x446bd28: ('837c240801', 'cmpl   $0x1,0x8(%rsp)'),
        0x446bd2f: ('488b442420', 'mov    0x20(%rsp),%rax'),
        0x446bd34: ('48c1e006', 'shl    $0x6,%rax'),
        0x446bd38: ('4803442410', 'add    0x10(%rsp),%rax'),
    }},
    'site_0x446cd9d': {"range": (0x446cd7c, 0x446cdc4), "calls": {}, "pins": {
        0x446cd7c: ('488b7508', 'mov    0x8(%rbp),%rsi'),
        0x446cd89: ('488b5510', 'mov    0x10(%rbp),%rdx'),
        0x446cd8d: ('488dbc24300400', 'lea    0x430(%rsp),%rdi'),
        0x446cd95: ('488d8c24a00700', 'lea    0x7a0(%rsp),%rcx'),
        0x446cd9d: ('e8be1715ff', 'call   0x35be560'),
        0x446cda2: ('83bc2430040000', 'cmpl   $0x1,0x430(%rsp)'),
        0x446cdb0: ('488b8424480400', 'mov    0x448(%rsp),%rax'),
        0x446cdb8: ('48c1e006', 'shl    $0x6,%rax'),
        0x446cdbc: ('48038424380400', 'add    0x438(%rsp),%rax'),
    }},
    'site_0x446dc81': {"range": (0x446dc65, 0x446dca8), "calls": {}, "pins": {
        0x446dc65: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x446dc72: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x446dc76: ('488dbc24300400', 'lea    0x430(%rsp),%rdi'),
        0x446dc7e: ('4889e9', 'mov    %rbp,%rcx'),
        0x446dc81: ('e8da0815ff', 'call   0x35be560'),
        0x446dc86: ('83bc2430040000', 'cmpl   $0x1,0x430(%rsp)'),
        0x446dc94: ('488b8424480400', 'mov    0x448(%rsp),%rax'),
        0x446dc9c: ('48c1e006', 'shl    $0x6,%rax'),
        0x446dca0: ('48038424380400', 'add    0x438(%rsp),%rax'),
    }},
    'site_0x446dea2': {"range": (0x446de84, 0x446ded5), "calls": {}, "pins": {
        0x446de84: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x446de91: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x446de95: ('488dbc24300400', 'lea    0x430(%rsp),%rdi'),
        0x446de9d: ('488d4c2470', 'lea    0x70(%rsp),%rcx'),
        0x446dea2: ('e8b90615ff', 'call   0x35be560'),
        0x446dea7: ('83bc2430040000', 'cmpl   $0x1,0x430(%rsp)'),
        0x446deb5: ('488b8424480400', 'mov    0x448(%rsp),%rax'),
        0x446debd: ('48c1e006', 'shl    $0x6,%rax'),
        0x446dec1: ('48038424380400', 'add    0x438(%rsp),%rax'),
    }},
    'site_0x446f3be': {"range": (0x446f3a2, 0x446f3ed), "calls": {}, "pins": {
        0x446f3a2: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x446f3af: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x446f3b3: ('488dbc24300400', 'lea    0x430(%rsp),%rdi'),
        0x446f3bb: ('4889e9', 'mov    %rbp,%rcx'),
        0x446f3be: ('e89df114ff', 'call   0x35be560'),
        0x446f3c3: ('83bc2430040000', 'cmpl   $0x1,0x430(%rsp)'),
        0x446f3d1: ('488b8424480400', 'mov    0x448(%rsp),%rax'),
        0x446f3d9: ('48c1e006', 'shl    $0x6,%rax'),
        0x446f3dd: ('48038424380400', 'add    0x438(%rsp),%rax'),
    }},
    'site_0x4472331': {"range": (0x4472317, 0x4472396), "calls": {0x447234c: 0x455cb20}, "pins": {
        0x4472317: ('498b7508', 'mov    0x8(%r13),%rsi'),
        0x4472320: ('498b5510', 'mov    0x10(%r13),%rdx'),
        0x4472324: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        0x4472329: ('488d8c24c80000', 'lea    0xc8(%rsp),%rcx'),
        0x4472331: ('e82ac214ff', 'call   0x35be560'),
        0x4472336: ('837c243001', 'cmpl   $0x1,0x30(%rsp)'),
        0x447237f: ('488b442448', 'mov    0x48(%rsp),%rax'),
        0x4472384: ('48c1e006', 'shl    $0x6,%rax'),
        0x4472388: ('4803442438', 'add    0x38(%rsp),%rax'),
    }},
    'site_0x4473681': {"range": (0x447359d, 0x44736ac), "calls": {0x44735db: 0x39094e0, 0x4473626: 0x4716be0}, "pins": {
        0x447359d: ('488d9c24800100', 'lea    0x180(%rsp),%rbx'),
        0x4473665: ('498b7508', 'mov    0x8(%r13),%rsi'),
        0x4473672: ('498b5510', 'mov    0x10(%r13),%rdx'),
        0x4473676: ('4889df', 'mov    %rbx,%rdi'),
        0x4473679: ('488d8c24b00000', 'lea    0xb0(%rsp),%rcx'),
        0x4473681: ('e8daae14ff', 'call   0x35be560'),
        0x4473686: ('83bc2480010000', 'cmpl   $0x1,0x180(%rsp)'),
        0x4473694: ('488b8424980100', 'mov    0x198(%rsp),%rax'),
        0x447369c: ('48c1e006', 'shl    $0x6,%rax'),
        0x44736a0: ('48038424880100', 'add    0x188(%rsp),%rax'),
    }},
    'site_0x4474575': {"range": (0x4474557, 0x4474593), "calls": {}, "pins": {
        0x4474557: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x4474564: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x4474568: ('488d7c2450', 'lea    0x50(%rsp),%rdi'),
        0x447456d: ('488d8c24100100', 'lea    0x110(%rsp),%rcx'),
        0x4474575: ('e8e69f14ff', 'call   0x35be560'),
        0x447457a: ('837c245001', 'cmpl   $0x1,0x50(%rsp)'),
        0x4474585: ('488b4c2468', 'mov    0x68(%rsp),%rcx'),
        0x447458a: ('48c1e106', 'shl    $0x6,%rcx'),
        0x447458e: ('48034c2458', 'add    0x58(%rsp),%rcx'),
    }},
    'site_0x4476202': {"range": (0x44761d9, 0x4476225), "calls": {}, "pins": {
        0x44761d9: ('488bb424180100', 'mov    0x118(%rsp),%rsi'),
        0x44761ea: ('488b9424200100', 'mov    0x120(%rsp),%rdx'),
        0x44761f2: ('488dbc24b00100', 'lea    0x1b0(%rsp),%rdi'),
        0x44761fa: ('488d8c24280200', 'lea    0x228(%rsp),%rcx'),
        0x4476202: ('e8598314ff', 'call   0x35be560'),
        0x4476207: ('80bc24b0010000', 'cmpb   $0x0,0x1b0(%rsp)'),
        0x4476211: ('488b9c24c80100', 'mov    0x1c8(%rsp),%rbx'),
        0x4476219: ('48c1e306', 'shl    $0x6,%rbx'),
        0x447621d: ('48039c24b80100', 'add    0x1b8(%rsp),%rbx'),
    }},
    'site_0x44762e0': {"range": (0x44762bb, 0x4476307), "calls": {}, "pins": {
        0x44762bb: ('488b30', 'mov    (%rax),%rsi'),
        0x44762cc: ('488b5010', 'mov    0x10(%rax),%rdx'),
        0x44762d0: ('488dbc24b00100', 'lea    0x1b0(%rsp),%rdi'),
        0x44762d8: ('488d8c24280200', 'lea    0x228(%rsp),%rcx'),
        0x44762e0: ('e87b8214ff', 'call   0x35be560'),
        0x44762e5: ('80bc24b0010000', 'cmpb   $0x0,0x1b0(%rsp)'),
        0x44762f3: ('4c8ba424c80100', 'mov    0x1c8(%rsp),%r12'),
        0x44762fb: ('49c1e406', 'shl    $0x6,%r12'),
        0x44762ff: ('4c03a424b80100', 'add    0x1b8(%rsp),%r12'),
    }},
    'site_0x44781ad': {"range": (0x4478001, 0x44781b9), "calls": {0x4478067: 0x3708fc0, 0x4478091: 0x39094e0, 0x44780e1: 0x4717440, 0x447810f: 0x3ee6740, 0x447816a: 0x4717ed0}, "pins": {
        0x4478001: ('488d6c2420', 'lea    0x20(%rsp),%rbp'),
        0x4478196: ('498b7508', 'mov    0x8(%r13),%rsi'),
        0x44781a3: ('498b5510', 'mov    0x10(%r13),%rdx'),
        0x44781a7: ('4889ef', 'mov    %rbp,%rdi'),
        0x44781aa: ('4c89e1', 'mov    %r12,%rcx'),
        0x44781ad: ('e8ae6314ff', 'call   0x35be560'),
        0x44781b2: ('837c242001', 'cmpl   $0x1,0x20(%rsp)'),
    }},
    'site_0x447b460': {"range": (0x447b43f, 0x447b487), "calls": {}, "pins": {
        0x447b43f: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x447b44c: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x447b450: ('488dbc24780200', 'lea    0x278(%rsp),%rdi'),
        0x447b458: ('488d8c24e00000', 'lea    0xe0(%rsp),%rcx'),
        0x447b460: ('e8fb3014ff', 'call   0x35be560'),
        0x447b465: ('83bc2478020000', 'cmpl   $0x1,0x278(%rsp)'),
        0x447b473: ('488b8424900200', 'mov    0x290(%rsp),%rax'),
        0x447b47b: ('48c1e006', 'shl    $0x6,%rax'),
        0x447b47f: ('48038424800200', 'add    0x280(%rsp),%rax'),
    }},
    'site_0x447b876': {"range": (0x447b855, 0x447b933), "calls": {0x447b8c1: 0x455cb20}, "pins": {
        0x447b855: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x447b862: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x447b866: ('488dbc24780200', 'lea    0x278(%rsp),%rdi'),
        0x447b86e: ('488d8c24e00000', 'lea    0xe0(%rsp),%rcx'),
        0x447b876: ('e8e52c14ff', 'call   0x35be560'),
        0x447b87b: ('83bc2478020000', 'cmpl   $0x1,0x278(%rsp)'),
        0x447b91a: ('488b8424900200', 'mov    0x290(%rsp),%rax'),
        0x447b922: ('48c1e006', 'shl    $0x6,%rax'),
        0x447b926: ('48038424800200', 'add    0x280(%rsp),%rax'),
    }},
    'site_0x447baf7': {"range": (0x447bae0, 0x447bb14), "calls": {}, "pins": {
        0x447bae0: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x447bae9: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x447baed: ('488d7c2470', 'lea    0x70(%rsp),%rdi'),
        0x447baf2: ('488d4c2438', 'lea    0x38(%rsp),%rcx'),
        0x447baf7: ('e8642a14ff', 'call   0x35be560'),
        0x447bafc: ('837c247001', 'cmpl   $0x1,0x70(%rsp)'),
        0x447bb03: ('488b8424880000', 'mov    0x88(%rsp),%rax'),
        0x447bb0b: ('48c1e006', 'shl    $0x6,%rax'),
        0x447bb0f: ('4803442478', 'add    0x78(%rsp),%rax'),
    }},
    'site_0x447e20a': {"range": (0x447e1ec, 0x447e22d), "calls": {}, "pins": {
        0x447e1ec: ('488b7108', 'mov    0x8(%rcx),%rsi'),
        0x447e1f9: ('488b5110', 'mov    0x10(%rcx),%rdx'),
        0x447e1fd: ('488d7c2440', 'lea    0x40(%rsp),%rdi'),
        0x447e202: ('488d8c24200100', 'lea    0x120(%rsp),%rcx'),
        0x447e20a: ('e8510314ff', 'call   0x35be560'),
        0x447e20f: ('837c244001', 'cmpl   $0x1,0x40(%rsp)'),
        0x447e21a: ('488b442458', 'mov    0x58(%rsp),%rax'),
        0x447e21f: ('48c1e006', 'shl    $0x6,%rax'),
        0x447e223: ('4803442448', 'add    0x48(%rsp),%rax'),
    }},
    'site_0x447e910': {"range": (0x447e8f3, 0x447e92e), "calls": {}, "pins": {
        0x447e8f3: ('498b742408', 'mov    0x8(%r12),%rsi'),
        0x447e901: ('498b542410', 'mov    0x10(%r12),%rdx'),
        0x447e906: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        0x447e90b: ('488d4c2410', 'lea    0x10(%rsp),%rcx'),
        0x447e910: ('e84bfc13ff', 'call   0x35be560'),
        0x447e915: ('837c243001', 'cmpl   $0x1,0x30(%rsp)'),
        0x447e920: ('488b4c2448', 'mov    0x48(%rsp),%rcx'),
        0x447e925: ('48c1e106', 'shl    $0x6,%rcx'),
        0x447e929: ('48034c2438', 'add    0x38(%rsp),%rcx'),
    }},
    'site_0x4480a2a': {"range": (0x4480a09, 0x4480a4d), "calls": {}, "pins": {
        0x4480a09: ('498b7608', 'mov    0x8(%r14),%rsi'),
        0x4480a16: ('498b5610', 'mov    0x10(%r14),%rdx'),
        0x4480a1a: ('488dbc24300100', 'lea    0x130(%rsp),%rdi'),
        0x4480a22: ('488d8c24c80000', 'lea    0xc8(%rsp),%rcx'),
        0x4480a2a: ('e831db13ff', 'call   0x35be560'),
        0x4480a2f: ('83bc2430010000', 'cmpl   $0x1,0x130(%rsp)'),
        0x4480a39: ('488b8424480100', 'mov    0x148(%rsp),%rax'),
        0x4480a41: ('48c1e006', 'shl    $0x6,%rax'),
        0x4480a45: ('48038424380100', 'add    0x138(%rsp),%rax'),
    }},
    'site_0x4486ac2': {"range": (0x4486aa5, 0x4486ae0), "calls": {}, "pins": {
        0x4486aa5: ('498b742408', 'mov    0x8(%r12),%rsi'),
        0x4486ab3: ('498b542410', 'mov    0x10(%r12),%rdx'),
        0x4486ab8: ('488d7c2440', 'lea    0x40(%rsp),%rdi'),
        0x4486abd: ('488d4c2428', 'lea    0x28(%rsp),%rcx'),
        0x4486ac2: ('e8997a13ff', 'call   0x35be560'),
        0x4486ac7: ('837c244001', 'cmpl   $0x1,0x40(%rsp)'),
        0x4486ad2: ('488b442458', 'mov    0x58(%rsp),%rax'),
        0x4486ad7: ('48c1e006', 'shl    $0x6,%rax'),
        0x4486adb: ('4803442448', 'add    0x48(%rsp),%rax'),
    }},
    'site_0x4487708': {"range": (0x44876ed, 0x4487726), "calls": {}, "pins": {
        0x44876ed: ('488b7508', 'mov    0x8(%rbp),%rsi'),
        0x44876fa: ('488b5510', 'mov    0x10(%rbp),%rdx'),
        0x44876fe: ('488d7c2440', 'lea    0x40(%rsp),%rdi'),
        0x4487703: ('488d4c2428', 'lea    0x28(%rsp),%rcx'),
        0x4487708: ('e8536e13ff', 'call   0x35be560'),
        0x448770d: ('837c244001', 'cmpl   $0x1,0x40(%rsp)'),
        0x4487718: ('488b4c2458', 'mov    0x58(%rsp),%rcx'),
        0x448771d: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4487721: ('48034c2448', 'add    0x48(%rsp),%rcx'),
    }},
    'site_0x4487e33': {"range": (0x4487e1e, 0x4487e4d), "calls": {}, "pins": {
        0x4487e1e: ('498b7608', 'mov    0x8(%r14),%rsi'),
        0x4487e27: ('498b5610', 'mov    0x10(%r14),%rdx'),
        0x4487e2b: ('488d7c2408', 'lea    0x8(%rsp),%rdi'),
        0x4487e30: ('4889e1', 'mov    %rsp,%rcx'),
        0x4487e33: ('e8286713ff', 'call   0x35be560'),
        0x4487e38: ('837c240801', 'cmpl   $0x1,0x8(%rsp)'),
        0x4487e3f: ('488b442420', 'mov    0x20(%rsp),%rax'),
        0x4487e44: ('48c1e006', 'shl    $0x6,%rax'),
        0x4487e48: ('4803442410', 'add    0x10(%rsp),%rax'),
    }},
    'site_0x4488213': {"range": (0x44881f8, 0x448822d), "calls": {}, "pins": {
        0x44881f8: ('498b7608', 'mov    0x8(%r14),%rsi'),
        0x4488205: ('498b5610', 'mov    0x10(%r14),%rdx'),
        0x4488209: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        0x448820e: ('488d4c2410', 'lea    0x10(%rsp),%rcx'),
        0x4488213: ('e8486313ff', 'call   0x35be560'),
        0x4488218: ('837c241801', 'cmpl   $0x1,0x18(%rsp)'),
        0x448821f: ('488b442430', 'mov    0x30(%rsp),%rax'),
        0x4488224: ('48c1e006', 'shl    $0x6,%rax'),
        0x4488228: ('4803442420', 'add    0x20(%rsp),%rax'),
    }},
    'site_0x44888ad': {"range": (0x4488896, 0x44888c7), "calls": {}, "pins": {
        0x4488896: ('498b7508', 'mov    0x8(%r13),%rsi'),
        0x448889f: ('498b5510', 'mov    0x10(%r13),%rdx'),
        0x44888a3: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        0x44888a8: ('488d4c2408', 'lea    0x8(%rsp),%rcx'),
        0x44888ad: ('e8ae5c13ff', 'call   0x35be560'),
        0x44888b2: ('837c241801', 'cmpl   $0x1,0x18(%rsp)'),
        0x44888b9: ('488b442430', 'mov    0x30(%rsp),%rax'),
        0x44888be: ('48c1e006', 'shl    $0x6,%rax'),
        0x44888c2: ('4803442420', 'add    0x20(%rsp),%rax'),
    }},
    'site_0x4489643': {"range": (0x448962e, 0x448965d), "calls": {}, "pins": {
        0x448962e: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x4489637: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x448963b: ('488d7c2408', 'lea    0x8(%rsp),%rdi'),
        0x4489640: ('4889e1', 'mov    %rsp,%rcx'),
        0x4489643: ('e8184f13ff', 'call   0x35be560'),
        0x4489648: ('837c240801', 'cmpl   $0x1,0x8(%rsp)'),
        0x448964f: ('488b442420', 'mov    0x20(%rsp),%rax'),
        0x4489654: ('48c1e006', 'shl    $0x6,%rax'),
        0x4489658: ('4803442410', 'add    0x10(%rsp),%rax'),
    }},
    'site_0x448a3c6': {"range": (0x448a3b1, 0x448a3e0), "calls": {}, "pins": {
        0x448a3b1: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x448a3ba: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x448a3be: ('488d7c2408', 'lea    0x8(%rsp),%rdi'),
        0x448a3c3: ('4889e1', 'mov    %rsp,%rcx'),
        0x448a3c6: ('e8954113ff', 'call   0x35be560'),
        0x448a3cb: ('837c240801', 'cmpl   $0x1,0x8(%rsp)'),
        0x448a3d2: ('488b442420', 'mov    0x20(%rsp),%rax'),
        0x448a3d7: ('48c1e006', 'shl    $0x6,%rax'),
        0x448a3db: ('4803442410', 'add    0x10(%rsp),%rax'),
    }},
    'site_0x4e86c60': {"range": (0x4e86c45, 0x4e86c7a), "calls": {}, "pins": {
        0x4e86c45: ('498b7508', 'mov    0x8(%r13),%rsi'),
        0x4e86c52: ('498b5510', 'mov    0x10(%r13),%rdx'),
        0x4e86c56: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4e86c5b: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x4e86c60: ('e8fb7873fe', 'call   0x35be560'),
        0x4e86c65: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4e86c6c: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4e86c71: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4e86c75: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4e86e28': {"range": (0x4e86e0d, 0x4e86e46), "calls": {}, "pins": {
        0x4e86e0d: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x4e86e1a: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x4e86e1e: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4e86e23: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x4e86e28: ('e8337773fe', 'call   0x35be560'),
        0x4e86e2d: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4e86e38: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4e86e3d: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4e86e41: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4e873f0': {"range": (0x4e873d5, 0x4e8740a), "calls": {}, "pins": {
        0x4e873d5: ('488b7508', 'mov    0x8(%rbp),%rsi'),
        0x4e873e2: ('488b5510', 'mov    0x10(%rbp),%rdx'),
        0x4e873e6: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4e873eb: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x4e873f0: ('e86b7173fe', 'call   0x35be560'),
        0x4e873f5: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4e873fc: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4e87401: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4e87405: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4e8757a': {"range": (0x4e8755f, 0x4e87594), "calls": {}, "pins": {
        0x4e8755f: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x4e8756c: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x4e87570: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4e87575: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x4e8757a: ('e8e16f73fe', 'call   0x35be560'),
        0x4e8757f: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4e87586: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4e8758b: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4e8758f: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4e98c60': {"range": (0x4e98c45, 0x4e98c7a), "calls": {}, "pins": {
        0x4e98c45: ('498b7508', 'mov    0x8(%r13),%rsi'),
        0x4e98c52: ('498b5510', 'mov    0x10(%r13),%rdx'),
        0x4e98c56: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4e98c5b: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x4e98c60: ('e8fb5872fe', 'call   0x35be560'),
        0x4e98c65: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4e98c6c: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4e98c71: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4e98c75: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4e98e28': {"range": (0x4e98e0d, 0x4e98e46), "calls": {}, "pins": {
        0x4e98e0d: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x4e98e1a: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x4e98e1e: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4e98e23: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x4e98e28: ('e8335772fe', 'call   0x35be560'),
        0x4e98e2d: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4e98e38: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4e98e3d: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4e98e41: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4e993f0': {"range": (0x4e993d5, 0x4e9940a), "calls": {}, "pins": {
        0x4e993d5: ('488b7508', 'mov    0x8(%rbp),%rsi'),
        0x4e993e2: ('488b5510', 'mov    0x10(%rbp),%rdx'),
        0x4e993e6: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4e993eb: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x4e993f0: ('e86b5172fe', 'call   0x35be560'),
        0x4e993f5: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4e993fc: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4e99401: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4e99405: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4e9957a': {"range": (0x4e9955f, 0x4e99594), "calls": {}, "pins": {
        0x4e9955f: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x4e9956c: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x4e99570: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4e99575: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x4e9957a: ('e8e14f72fe', 'call   0x35be560'),
        0x4e9957f: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4e99586: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4e9958b: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4e9958f: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4f542de': {"range": (0x4f542c3, 0x4f54302), "calls": {}, "pins": {
        0x4f542c3: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x4f542d0: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x4f542d4: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4f542d9: ('488d4c2438', 'lea    0x38(%rsp),%rcx'),
        0x4f542de: ('e87da266fe', 'call   0x35be560'),
        0x4f542e3: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4f542ea: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4f542ef: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4f542f3: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4f544fc': {"range": (0x4f544e1, 0x4f545e1), "calls": {0x4f54548: 0x455cb20}, "pins": {
        0x4f544e1: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x4f544ee: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x4f544f2: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4f544f7: ('488d4c2438', 'lea    0x38(%rsp),%rcx'),
        0x4f544fc: ('e85fa066fe', 'call   0x35be560'),
        0x4f54501: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4f545c7: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4f545cc: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4f545d0: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4f548df': {"range": (0x4f548c4, 0x4f54903), "calls": {}, "pins": {
        0x4f548c4: ('488b7508', 'mov    0x8(%rbp),%rsi'),
        0x4f548d1: ('488b5510', 'mov    0x10(%rbp),%rdx'),
        0x4f548d5: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4f548da: ('488d4c2438', 'lea    0x38(%rsp),%rcx'),
        0x4f548df: ('e87c9c66fe', 'call   0x35be560'),
        0x4f548e4: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4f548eb: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4f548f0: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4f548f4: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4f54afe': {"range": (0x4f54ae3, 0x4f54bd4), "calls": {0x4f54b48: 0x455cb20}, "pins": {
        0x4f54ae3: ('488b7508', 'mov    0x8(%rbp),%rsi'),
        0x4f54af0: ('488b5510', 'mov    0x10(%rbp),%rdx'),
        0x4f54af4: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4f54af9: ('488d4c2438', 'lea    0x38(%rsp),%rcx'),
        0x4f54afe: ('e85d9a66fe', 'call   0x35be560'),
        0x4f54b03: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4f54bc2: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4f54bc7: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4f54bcb: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4f9eeee': {"range": (0x4f9eed3, 0x4f9ef12), "calls": {}, "pins": {
        0x4f9eed3: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x4f9eee0: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x4f9eee4: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4f9eee9: ('488d4c2438', 'lea    0x38(%rsp),%rcx'),
        0x4f9eeee: ('e86df661fe', 'call   0x35be560'),
        0x4f9eef3: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4f9eefa: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4f9eeff: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4f9ef03: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4f9f10c': {"range": (0x4f9f0f1, 0x4f9f1f1), "calls": {0x4f9f158: 0x455cb20}, "pins": {
        0x4f9f0f1: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x4f9f0fe: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x4f9f102: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4f9f107: ('488d4c2438', 'lea    0x38(%rsp),%rcx'),
        0x4f9f10c: ('e84ff461fe', 'call   0x35be560'),
        0x4f9f111: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4f9f1d7: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4f9f1dc: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4f9f1e0: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4f9f4ef': {"range": (0x4f9f4d4, 0x4f9f513), "calls": {}, "pins": {
        0x4f9f4d4: ('488b7508', 'mov    0x8(%rbp),%rsi'),
        0x4f9f4e1: ('488b5510', 'mov    0x10(%rbp),%rdx'),
        0x4f9f4e5: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4f9f4ea: ('488d4c2438', 'lea    0x38(%rsp),%rcx'),
        0x4f9f4ef: ('e86cf061fe', 'call   0x35be560'),
        0x4f9f4f4: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4f9f4fb: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4f9f500: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4f9f504: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x4f9f70e': {"range": (0x4f9f6f3, 0x4f9f7e4), "calls": {0x4f9f758: 0x455cb20}, "pins": {
        0x4f9f6f3: ('488b7508', 'mov    0x8(%rbp),%rsi'),
        0x4f9f700: ('488b5510', 'mov    0x10(%rbp),%rdx'),
        0x4f9f704: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x4f9f709: ('488d4c2438', 'lea    0x38(%rsp),%rcx'),
        0x4f9f70e: ('e84dee61fe', 'call   0x35be560'),
        0x4f9f713: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x4f9f7d2: ('488b4c2478', 'mov    0x78(%rsp),%rcx'),
        0x4f9f7d7: ('48c1e106', 'shl    $0x6,%rcx'),
        0x4f9f7db: ('48034c2468', 'add    0x68(%rsp),%rcx'),
    }},
    'site_0x54d2ee0': {"range": (0x54d2eb7, 0x54d2f07), "calls": {}, "pins": {
        0x54d2eb7: ('488bb424380700', 'mov    0x738(%rsp),%rsi'),
        0x54d2ec8: ('488b9424400700', 'mov    0x740(%rsp),%rdx'),
        0x54d2ed0: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        0x54d2ed8: ('488d8c24480300', 'lea    0x348(%rsp),%rcx'),
        0x54d2ee0: ('e87bb60efe', 'call   0x35be560'),
        0x54d2ee5: ('83bc24b0000000', 'cmpl   $0x1,0xb0(%rsp)'),
        0x54d2ef3: ('488b8424c80000', 'mov    0xc8(%rsp),%rax'),
        0x54d2efb: ('48c1e006', 'shl    $0x6,%rax'),
        0x54d2eff: ('48038424b80000', 'add    0xb8(%rsp),%rax'),
    }},
    'site_0x54d8b80': {"range": (0x54d8b57, 0x54d8ba7), "calls": {}, "pins": {
        0x54d8b57: ('488bb424380700', 'mov    0x738(%rsp),%rsi'),
        0x54d8b68: ('488b9424400700', 'mov    0x740(%rsp),%rdx'),
        0x54d8b70: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x54d8b78: ('488d8c24380300', 'lea    0x338(%rsp),%rcx'),
        0x54d8b80: ('e8db590efe', 'call   0x35be560'),
        0x54d8b85: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x54d8b93: ('488b8424b80000', 'mov    0xb8(%rsp),%rax'),
        0x54d8b9b: ('48c1e006', 'shl    $0x6,%rax'),
        0x54d8b9f: ('48038424a80000', 'add    0xa8(%rsp),%rax'),
    }},
    'site_0x591bd9b': {"range": (0x591bd7d, 0x591bdc2), "calls": {}, "pins": {
        0x591bd7d: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x591bd8a: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x591bd8e: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        0x591bd96: ('488d4c2450', 'lea    0x50(%rsp),%rcx'),
        0x591bd9b: ('e8c027cafd', 'call   0x35be560'),
        0x591bda0: ('83bc2480000000', 'cmpl   $0x1,0x80(%rsp)'),
        0x591bdae: ('488b8424980000', 'mov    0x98(%rsp),%rax'),
        0x591bdb6: ('48c1e006', 'shl    $0x6,%rax'),
        0x591bdba: ('48038424880000', 'add    0x88(%rsp),%rax'),
    }},
    'site_0x591cd3b': {"range": (0x591cd1d, 0x591cd62), "calls": {}, "pins": {
        0x591cd1d: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x591cd2a: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x591cd2e: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        0x591cd36: ('488d4c2450', 'lea    0x50(%rsp),%rcx'),
        0x591cd3b: ('e82018cafd', 'call   0x35be560'),
        0x591cd40: ('83bc2480000000', 'cmpl   $0x1,0x80(%rsp)'),
        0x591cd4e: ('488b8424980000', 'mov    0x98(%rsp),%rax'),
        0x591cd56: ('48c1e006', 'shl    $0x6,%rax'),
        0x591cd5a: ('48038424880000', 'add    0x88(%rsp),%rax'),
    }},
    'caller_0x2bf2ed0_height_0x2bf344e': {"range": (0x2bf342b, 0x2bf346a), "calls": {}, "pins": {
        0x2bf344e: ('488bb424600200', 'mov    0x260(%rsp),%rsi'),
    }},
    'caller_0x2bf2ed0_height_0x2bf3a10': {"range": (0x2bf39eb, 0x2bf3a20), "calls": {}, "pins": {
        0x2bf39eb: ('e8605485ff', 'call   0x2448e50'),
        0x2bf3a10: ('488b8424600200', 'mov    0x260(%rsp),%rax'),
    }},
    'caller_0x2bf2ed0_height_0x2bf3c31': {"range": (0x2bf3c1b, 0x2bf3c42), "calls": {}, "pins": {
        0x2bf3c1b: ('e8f0d584ff', 'call   0x2441210'),
        0x2bf3c31: ('488b8c24600200', 'mov    0x260(%rsp),%rcx'),
    }},
    'caller_0x2bf2ed0_height_0x2bf5b25': {"range": (0x2bf5b0f, 0x2bf5b35), "calls": {}, "pins": {
        0x2bf5b0f: ('e89cff84ff', 'call   0x2445ab0'),
        0x2bf5b25: ('488b8c24600200', 'mov    0x260(%rsp),%rcx'),
    }},
    'caller_0x2bf2ed0_height_0x2bf6836': {"range": (0x2bf6808, 0x2bf6843), "calls": {}, "pins": {
        0x2bf6836: ('488b8c24600200', 'mov    0x260(%rsp),%rcx'),
    }},
    'caller_0x2bf2ed0_height_0x2bf6874': {"range": (0x2bf6841, 0x2bf687e), "calls": {}, "pins": {
        0x2bf6874: ('483b8424600200', 'cmp    0x260(%rsp),%rax'),
    }},
    'caller_0x2bf2ed0_height_0x2bf6fc9': {"range": (0x2bf6fb3, 0x2bf6fd9), "calls": {}, "pins": {
        0x2bf6fb3: ('e8f8ea84ff', 'call   0x2445ab0'),
        0x2bf6fc9: ('488b8c24600200', 'mov    0x260(%rsp),%rcx'),
    }},
    'caller_0x446c200_height_0x446cc59': {"range": (0x446cc56, 0x446cc71), "calls": {}, "pins": {
        0x446cc59: ('488b8424400400', 'mov    0x440(%rsp),%rax'),
    }},
    'caller_0x446c200_height_0x446d05a': {"range": (0x446d02d, 0x446d067), "calls": {}, "pins": {
        0x446d05a: ('488b8c24400400', 'mov    0x440(%rsp),%rcx'),
    }},
    'caller_0x446c200_height_0x446d08e': {"range": (0x446d062, 0x446d09c), "calls": {}, "pins": {
        0x446d08e: ('483b8424400400', 'cmp    0x440(%rsp),%rax'),
    }},
    'caller_0x446c200_height_0x446d98a': {"range": (0x446d975, 0x446d99a), "calls": {}, "pins": {
        0x446d975: ('e836dc49ff', 'call   0x390b5b0'),
        0x446d98a: ('488b8c24400400', 'mov    0x440(%rsp),%rcx'),
    }},
    'caller_0x446c200_height_0x446e071': {"range": (0x446e044, 0x446e087), "calls": {}, "pins": {
        0x446e071: ('8b842440040000', 'mov    0x440(%rsp),%eax'),
    }},
    'caller_0x446c200_height_0x446f000': {"range": (0x446efe2, 0x446f014), "calls": {}, "pins": {
        0x446efe2: ('e8c9c549ff', 'call   0x390b5b0'),
        0x446f000: ('488b8c24400400', 'mov    0x440(%rsp),%rcx'),
    }},
    'caller_0x446c200_height_0x4470351': {"range": (0x4470328, 0x447035f), "calls": {}, "pins": {
        0x4470351: ('488bb424400400', 'mov    0x440(%rsp),%rsi'),
    }},
    'caller_0x446c200_height_0x4470a96': {"range": (0x4470a84, 0x4470aa6), "calls": {}, "pins": {
        0x4470a84: ('e8d7eb1100', 'call   0x458f660'),
        0x4470a96: ('488bbc24400400', 'mov    0x440(%rsp),%rdi'),
    }},
    'caller_0x446c200_height_0x4471036': {"range": (0x447100d, 0x4471046), "calls": {}, "pins": {
        0x4471036: ('488bbc24400400', 'mov    0x440(%rsp),%rdi'),
    }},
    'caller_0x446c200_height_0x44713fc': {"range": (0x44713e6, 0x447140c), "calls": {}, "pins": {
        0x44713e6: ('e875e21100', 'call   0x458f660'),
        0x44713fc: ('488bbc24400400', 'mov    0x440(%rsp),%rdi'),
    }},
    'caller_0x446c200_height_0x4471449': {"range": (0x447142e, 0x4471456), "calls": {}, "pins": {
        0x447142e: ('e8cda64cff', 'call   0x393bb00'),
        0x4471449: ('488bbc24400400', 'mov    0x440(%rsp),%rdi'),
    }},
    'caller_0x4472010_height_0x4472574': {"range": (0x447256e, 0x447257f), "calls": {}, "pins": {
        0x4472574: ('4c8b642440', 'mov    0x40(%rsp),%r12'),
    }},
    'caller_0x4473440_height_0x4473514': {"range": (0x44734f2, 0x447352b), "calls": {}, "pins": {
        0x4473514: ('488bb424900100', 'mov    0x190(%rsp),%rsi'),
    }},
    'caller_0x4473440_height_0x44735f1': {"range": (0x44735db, 0x4473602), "calls": {}, "pins": {
        0x44735db: ('e8005f49ff', 'call   0x39094e0'),
        0x44735f1: ('488b8c24900100', 'mov    0x190(%rsp),%rcx'),
    }},
    'caller_0x4473440_height_0x4473897': {"range": (0x4473865, 0x44738a8), "calls": {}, "pins": {
        0x4473897: ('8b842490010000', 'mov    0x190(%rsp),%eax'),
    }},
    'caller_0x4473d10_height_0x4473dce': {"range": (0x4473dc4, 0x4473ddc), "calls": {}, "pins": {
        0x4473dc4: ('e8c77577ff', 'call   0x3beb390'),
        0x4473dce: ('488b442460', 'mov    0x60(%rsp),%rax'),
    }},
    'caller_0x4473d10_height_0x4474956': {"range": (0x447494b, 0x447496b), "calls": {}, "pins": {
        0x4474956: ('488b4c2460', 'mov    0x60(%rsp),%rcx'),
    }},
    'caller_0x4473d10_height_0x4474dc5': {"range": (0x4474d8f, 0x4474dcf), "calls": {}, "pins": {
        0x4474dc5: ('488b4c2460', 'mov    0x60(%rsp),%rcx'),
    }},
    'caller_0x4473d10_height_0x4474dea': {"range": (0x4474dca, 0x4474df5), "calls": {}, "pins": {
        0x4474dea: ('483b442460', 'cmp    0x60(%rsp),%rax'),
    }},
    'caller_0x4473d10_height_0x44751ac': {"range": (0x447517d, 0x44751b6), "calls": {}, "pins": {
        0x44751ac: ('488b4c2460', 'mov    0x60(%rsp),%rcx'),
    }},
    'caller_0x4473d10_height_0x44751d1': {"range": (0x44751b1, 0x44751d8), "calls": {}, "pins": {
        0x44751d1: ('483b442460', 'cmp    0x60(%rsp),%rax'),
    }},
    'caller_0x4473d10_height_0x44753dd': {"range": (0x44753b7, 0x44753ea), "calls": {}, "pins": {
        0x44753dd: ('488b7c2460', 'mov    0x60(%rsp),%rdi'),
    }},
    'caller_0x4473d10_height_0x4475757': {"range": (0x447572f, 0x4475762), "calls": {}, "pins": {
        0x4475757: ('488b7c2460', 'mov    0x60(%rsp),%rdi'),
    }},
    'caller_0x4473d10_height_0x4475c25': {"range": (0x4475c0d, 0x4475c36), "calls": {}, "pins": {
        0x4475c0d: ('e88ed249ff', 'call   0x3912ea0'),
        0x4475c25: ('488b4c2460', 'mov    0x60(%rsp),%rcx'),
    }},
    'caller_0x4473d10_height_0x4475dd0': {"range": (0x4475db2, 0x4475ddf), "calls": {}, "pins": {
        0x4475dd0: ('8b8424c0010000', 'mov    0x1c0(%rsp),%eax'),
    }},
    'caller_0x4473d10_height_0x44761a8': {"range": (0x4476192, 0x44761ba), "calls": {}, "pins": {
        0x4476192: ('e8997149ff', 'call   0x390d330'),
        0x44761a8: ('488b8c24c00100', 'mov    0x1c0(%rsp),%rcx'),
    }},
    'caller_0x4473d10_height_0x4476710': {"range": (0x44766ec, 0x447671e), "calls": {}, "pins": {
        0x44766ec: ('e8afc749ff', 'call   0x3912ea0'),
        0x4476710: ('486b4c246078', 'imul   $0x78,0x60(%rsp),%rcx'),
    }},
    'caller_0x4477d00_height_0x44780a4': {"range": (0x4478091, 0x44780b2), "calls": {}, "pins": {
        0x4478091: ('e84a1449ff', 'call   0x39094e0'),
        0x44780a4: ('488b4c2430', 'mov    0x30(%rsp),%rcx'),
    }},
    'caller_0x447adf0_height_0x447b2b6': {"range": (0x447b2a0, 0x447b2c8), "calls": {}, "pins": {
        0x447b2a0: ('e88b2049ff', 'call   0x390d330'),
        0x447b2b6: ('488b8c24880200', 'mov    0x288(%rsp),%rcx'),
    }},
    'caller_0x44868f0_height_0x4487098': {"range": (0x4487092, 0x44870a3), "calls": {}, "pins": {
        0x4487098: ('488b4c2450', 'mov    0x50(%rsp),%rcx'),
    }},
    'caller_0x54cfa90_height_0x54d0064': {"range": (0x54d0041, 0x54d0080), "calls": {}, "pins": {
        0x54d0064: ('488bb424c00000', 'mov    0xc0(%rsp),%rsi'),
    }},
    'caller_0x54cfa90_height_0x54d0625': {"range": (0x54d0600, 0x54d0635), "calls": {}, "pins": {
        0x54d0600: ('e82bcdd0ff', 'call   0x51dd330'),
        0x54d0625: ('488b8424c00000', 'mov    0xc0(%rsp),%rax'),
    }},
    'caller_0x54cfa90_height_0x54d0851': {"range": (0x54d083b, 0x54d0862), "calls": {}, "pins": {
        0x54d083b: ('e820ecd0ff', 'call   0x51df460'),
        0x54d0851: ('488b8c24c00000', 'mov    0xc0(%rsp),%rcx'),
    }},
    'caller_0x54cfa90_height_0x54d2c4f': {"range": (0x54d2c39, 0x54d2c5f), "calls": {}, "pins": {
        0x54d2c39: ('e8c202d1ff', 'call   0x51e2f00'),
        0x54d2c4f: ('488b8c24c00000', 'mov    0xc0(%rsp),%rcx'),
    }},
    'caller_0x54cfa90_height_0x54d3666': {"range": (0x54d363d, 0x54d3673), "calls": {}, "pins": {
        0x54d3666: ('488b8c24c00000', 'mov    0xc0(%rsp),%rcx'),
    }},
    'caller_0x54cfa90_height_0x54d369b': {"range": (0x54d366e, 0x54d36a9), "calls": {}, "pins": {
        0x54d369b: ('483b8424c00000', 'cmp    0xc0(%rsp),%rax'),
    }},
    'caller_0x54cfa90_height_0x54d3e0f': {"range": (0x54d3df9, 0x54d3e1f), "calls": {}, "pins": {
        0x54d3df9: ('e802f1d0ff', 'call   0x51e2f00'),
        0x54d3e0f: ('488b8c24c00000', 'mov    0xc0(%rsp),%rcx'),
    }},
    'caller_0x54d57b0_height_0x54d5d8f': {"range": (0x54d5d6c, 0x54d5dab), "calls": {}, "pins": {
        0x54d5d8f: ('488bb424b00000', 'mov    0xb0(%rsp),%rsi'),
    }},
    'caller_0x54d57b0_height_0x54d6340': {"range": (0x54d631b, 0x54d6350), "calls": {}, "pins": {
        0x54d631b: ('e81070d0ff', 'call   0x51dd330'),
        0x54d6340: ('488b8424b00000', 'mov    0xb0(%rsp),%rax'),
    }},
    'caller_0x54d57b0_height_0x54d6571': {"range": (0x54d655b, 0x54d6582), "calls": {}, "pins": {
        0x54d655b: ('e8008fd0ff', 'call   0x51df460'),
        0x54d6571: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx'),
    }},
    'caller_0x54d57b0_height_0x54d88f3': {"range": (0x54d88dd, 0x54d8903), "calls": {}, "pins": {
        0x54d88dd: ('e81ea6d0ff', 'call   0x51e2f00'),
        0x54d88f3: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx'),
    }},
    'caller_0x54d57b0_height_0x54d9336': {"range": (0x54d9305, 0x54d9343), "calls": {}, "pins": {
        0x54d9336: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx'),
    }},
    'caller_0x54d57b0_height_0x54d936b': {"range": (0x54d933e, 0x54d9379), "calls": {}, "pins": {
        0x54d936b: ('483b8424b00000', 'cmp    0xb0(%rsp),%rax'),
    }},
    'caller_0x54d57b0_height_0x54d9acf': {"range": (0x54d9ab9, 0x54d9adf), "calls": {}, "pins": {
        0x54d9ab9: ('e84294d0ff', 'call   0x51e2f00'),
        0x54d9acf: ('488b8c24b00000', 'mov    0xb0(%rsp),%rcx'),
    }},
    'caller_0x591b240_height_0x591b5b7': {"range": (0x591b589, 0x591b5c5), "calls": {}, "pins": {
        0x591b5b7: ('8b8c2490000000', 'mov    0x90(%rsp),%ecx'),
    }},
    'caller_0x591c1e0_height_0x591c557': {"range": (0x591c529, 0x591c565), "calls": {}, "pins": {
        0x591c557: ('8b8c2490000000', 'mov    0x90(%rsp),%ecx'),
    }},
}
SLOT_CENSUS = {
    '0x23fdb60|0x80': {"flag": [0x23fe643], "node": [0x23fe65d], "height": [], "position": [0x23fe651]},
    '0x26c9440|0x20': {"flag": [0x26c9888, 0x26c9a72], "node": [0x26c9898, 0x26c9b45], "height": [], "position": [0x26c988f, 0x26c9b3c]},
    '0x2bf2ed0|0x250': {"flag": [0x2bf2fec, 0x2bf32a6, 0x2bf3431, 0x2bf39f0, 0x2bf3c20, 0x2bf43b0, 0x2bf4407, 0x2bf44ff, 0x2bf4b0b, 0x2bf4d4f, 0x2bf5b14, 0x2bf5ee2, 0x2bf60a6, 0x2bf65b1, 0x2bf662e, 0x2bf6820, 0x2bf69be, 0x2bf6c05, 0x2bf6ec8, 0x2bf6fb8, 0x2bf73f5, 0x2bf83e2], "node": [0x2bf2fa8, 0x2bf3439, 0x2bf4434, 0x2bf5efc, 0x2bf661d, 0x2bf682e, 0x2bf686c, 0x2bf69ad], "height": [0x2bf32af, 0x2bf344e, 0x2bf3a10, 0x2bf3c31, 0x2bf43b9, 0x2bf4508, 0x2bf4b13, 0x2bf4d58, 0x2bf5b25, 0x2bf65ba, 0x2bf6836, 0x2bf6874, 0x2bf6ed1, 0x2bf6fc9, 0x2bf83eb], "position": [0x2bf5ef0]},
    '0x446b840|0x40': {"flag": [0x446b8a9, 0x446b98d, 0x446bac8], "node": [0x446b8bd, 0x446b9a1], "height": [], "position": [0x446b8b4, 0x446b998]},
    '0x446bcd0|0x8': {"flag": [0x446bd28], "node": [0x446bd38], "height": [], "position": [0x446bd2f]},
    '0x446c200|0x430': {"flag": [0x446c4f0, 0x446cc69, 0x446cda2, 0x446d040, 0x446d2d2, 0x446d97a, 0x446db08, 0x446dc86, 0x446dea7, 0x446e07f, 0x446efe7, 0x446f049, 0x446f3c3, 0x44704b8, 0x4470a72, 0x44713d4], "node": [0x446cdbc, 0x446d052, 0x446d086, 0x446dca0, 0x446dec1, 0x446f3dd, 0x447033d, 0x4470a89, 0x447100d, 0x44713eb, 0x4471438], "height": [0x446c4f8, 0x446cc59, 0x446d05a, 0x446d08e, 0x446d98a, 0x446e071, 0x446f000, 0x4470351, 0x4470a96, 0x4471036, 0x44713fc, 0x4471449], "position": [0x446cdb0, 0x446dc94, 0x446deb5, 0x446f3d1, 0x4470331]},
    '0x4472010|0x30': {"flag": [0x4472290, 0x4472336], "node": [0x4472388], "height": [0x4472574], "position": [0x447237f]},
    '0x4473440|0x180': {"flag": [0x44734f7, 0x44735e0, 0x4473686, 0x4473887, 0x4473afb], "node": [0x44734ff, 0x44736a0], "height": [0x4473514, 0x44735f1, 0x4473897], "position": [0x4473694]},
    '0x4473d10|0x1b0': {"flag": [0x4475ab5, 0x4475ddf, 0x4476197, 0x4476207, 0x44762e5, 0x4476552], "node": [0x447621d, 0x44762ff], "height": [0x4475dd0, 0x44761a8], "position": [0x4476211, 0x44762f3]},
    '0x4473d10|0x50': {"flag": [0x4473e1b, 0x44741de, 0x4474280, 0x447457a, 0x44745b4, 0x4474951, 0x4474f80, 0x44751a0, 0x44753b2, 0x447573e, 0x4475c12, 0x44766f1, 0x447672e], "node": [0x4473dc9, 0x447458e, 0x4474dc0, 0x4474de5, 0x44751a7, 0x44751cc, 0x44753d8, 0x4475749], "height": [0x4473dce, 0x4474285, 0x4474956, 0x4474dc5, 0x4474dea, 0x44751ac, 0x44751d1, 0x44753dd, 0x4475757, 0x4475c25, 0x4476710], "position": [0x4474585, 0x44753cf]},
    '0x4477d00|0x20': {"flag": [0x4478096, 0x44781b2, 0x44784eb, 0x44785bb], "node": [], "height": [0x44780a4], "position": []},
    '0x447adf0|0x278': {"flag": [0x447b2a5, 0x447b465, 0x447b87b, 0x447c18b], "node": [0x447b47f, 0x447b926], "height": [0x447b2b6], "position": [0x447b473, 0x447b91a]},
    '0x447adf0|0x70': {"flag": [0x447bafc], "node": [0x447bb0f], "height": [], "position": [0x447bb03]},
    '0x447df40|0x40': {"flag": [0x447e20f, 0x447e725], "node": [0x447e223], "height": [0x447e72a], "position": [0x447e21a]},
    '0x447e810|0x30': {"flag": [0x447e915, 0x447ea80, 0x447ead9], "node": [0x447e929], "height": [0x447eadf], "position": [0x447e920]},
    '0x447fe90|0x130': {"flag": [0x4480328, 0x4480a2f], "node": [0x4480330, 0x4480a45], "height": [], "position": [0x4480a39]},
    '0x44868f0|0x40': {"flag": [0x4486ac7], "node": [0x4486adb], "height": [0x4487098], "position": [0x4486ad2]},
    '0x44875a0|0x40': {"flag": [0x448770d], "node": [0x4487721], "height": [], "position": [0x4487718]},
    '0x4487db0|0x8': {"flag": [0x4487e38], "node": [0x4487e48], "height": [], "position": [0x4487e3f]},
    '0x44881b0|0x18': {"flag": [0x4488218], "node": [0x4488228], "height": [], "position": [0x448821f]},
    '0x4488820|0x18': {"flag": [0x44888b2], "node": [0x44888c2], "height": [], "position": [0x44888b9]},
    '0x44895f0|0x8': {"flag": [0x4489648], "node": [0x4489658], "height": [], "position": [0x448964f]},
    '0x448a370|0x8': {"flag": [0x448a3cb], "node": [0x448a3db], "height": [], "position": [0x448a3d2]},
    '0x4e86260|0x60': {"flag": [0x4e86c65, 0x4e86e2d, 0x4e873f5, 0x4e8757f], "node": [0x4e86c75, 0x4e86e41, 0x4e87405, 0x4e8758f], "height": [], "position": [0x4e86c6c, 0x4e86e38, 0x4e873fc, 0x4e87586]},
    '0x4e98260|0x60': {"flag": [0x4e98c65, 0x4e98e2d, 0x4e993f5, 0x4e9957f], "node": [0x4e98c75, 0x4e98e41, 0x4e99405, 0x4e9958f], "height": [], "position": [0x4e98c6c, 0x4e98e38, 0x4e993fc, 0x4e99586]},
    '0x4f53680|0x60': {"flag": [0x4f542e3, 0x4f54501, 0x4f548e4, 0x4f54b03], "node": [0x4f542f3, 0x4f545d0, 0x4f548f4, 0x4f54bcb], "height": [], "position": [0x4f542ea, 0x4f545c7, 0x4f548eb, 0x4f54bc2]},
    '0x4f9e290|0x60': {"flag": [0x4f9eef3, 0x4f9f111, 0x4f9f4f4, 0x4f9f713], "node": [0x4f9ef03, 0x4f9f1e0, 0x4f9f504, 0x4f9f7db], "height": [], "position": [0x4f9eefa, 0x4f9f1d7, 0x4f9f4fb, 0x4f9f7d2]},
    '0x54cfa90|0xb0': {"flag": [0x54cfbfb, 0x54cfeb4, 0x54d0047, 0x54d0605, 0x54d0840, 0x54d1000, 0x54d105a, 0x54d117f, 0x54d1707, 0x54d187d, 0x54d20ed, 0x54d2c3e, 0x54d2ee5, 0x54d30cf, 0x54d3414, 0x54d3491, 0x54d3650, 0x54d37ee, 0x54d3a45, 0x54d3d12, 0x54d3dfe, 0x54d40e5, 0x54d50d3], "node": [0x54cfbb7, 0x54d004f, 0x54d1087, 0x54d2eff, 0x54d3480, 0x54d365e, 0x54d3693, 0x54d37dd], "height": [0x54cfebd, 0x54d0064, 0x54d0625, 0x54d0851, 0x54d1009, 0x54d1188, 0x54d1885, 0x54d20f6, 0x54d2c4f, 0x54d341d, 0x54d3666, 0x54d369b, 0x54d3d1b, 0x54d3e0f, 0x54d50dc], "position": [0x54d2ef3]},
    '0x54d57b0|0xa0': {"flag": [0x54d5917, 0x54d5bdf, 0x54d5d72, 0x54d6320, 0x54d6560, 0x54d6ce0, 0x54d6d3a, 0x54d6e5f, 0x54d73e7, 0x54d755d, 0x54d7db8, 0x54d88e2, 0x54d8b85, 0x54d8d86, 0x54d90d7, 0x54d9154, 0x54d9320, 0x54d94c1, 0x54d9705, 0x54d99ce, 0x54d9abe, 0x54d9da5, 0x54dad88], "node": [0x54d58d3, 0x54d5d7a, 0x54d6d67, 0x54d8b9f, 0x54d9143, 0x54d932e, 0x54d9363, 0x54d94b0], "height": [0x54d5be8, 0x54d5d8f, 0x54d6340, 0x54d6571, 0x54d6ce9, 0x54d6e68, 0x54d7565, 0x54d7dc1, 0x54d88f3, 0x54d90e0, 0x54d9336, 0x54d936b, 0x54d99d7, 0x54d9acf, 0x54dad91], "position": [0x54d8b93]},
    '0x591b240|0x80': {"flag": [0x591b5a8, 0x591bda0], "node": [0x591bdba], "height": [0x591b5b7], "position": [0x591bdae]},
    '0x591c1e0|0x80': {"flag": [0x591c548, 0x591cd40], "node": [0x591cd5a], "height": [0x591c557], "position": [0x591cd4e]},
}
HEIGHT_READS = {
    '0x23fdb60|0x80': {},
    '0x26c9440|0x20': {},
    '0x2bf2ed0|0x250': {0x2bf32af: 'vector_copy', 0x2bf344e: 'other_phase', 0x2bf3a10: 'other_phase', 0x2bf3c31: 'other_phase', 0x2bf43b9: 'vector_copy', 0x2bf4508: 'vector_copy', 0x2bf4b13: 'vector_copy', 0x2bf4d58: 'vector_copy', 0x2bf5b25: 'other_phase', 0x2bf65ba: 'vector_copy', 0x2bf6836: 'other_phase', 0x2bf6874: 'other_phase', 0x2bf6ed1: 'vector_copy', 0x2bf6fc9: 'other_phase', 0x2bf83eb: 'vector_copy'},
    '0x446b840|0x40': {},
    '0x446bcd0|0x8': {},
    '0x446c200|0x430': {0x446c4f8: 'vector_copy', 0x446cc59: 'other_phase', 0x446d05a: 'other_phase', 0x446d08e: 'other_phase', 0x446d98a: 'other_phase', 0x446e071: 'other_phase', 0x446f000: 'other_phase', 0x4470351: 'other_phase', 0x4470a96: 'other_phase', 0x4471036: 'other_phase', 0x44713fc: 'other_phase', 0x4471449: 'other_phase'},
    '0x4472010|0x30': {0x4472574: 'other_phase'},
    '0x4473440|0x180': {0x4473514: 'other_phase', 0x44735f1: 'other_phase', 0x4473897: 'other_phase'},
    '0x4473d10|0x1b0': {0x4475dd0: 'other_phase', 0x44761a8: 'other_phase'},
    '0x4473d10|0x50': {0x4473dce: 'other_phase', 0x4474285: 'vector_copy', 0x4474956: 'other_phase', 0x4474dc5: 'other_phase', 0x4474dea: 'other_phase', 0x44751ac: 'other_phase', 0x44751d1: 'other_phase', 0x44753dd: 'other_phase', 0x4475757: 'other_phase', 0x4475c25: 'other_phase', 0x4476710: 'other_phase'},
    '0x4477d00|0x20': {0x44780a4: 'other_phase'},
    '0x447adf0|0x278': {0x447b2b6: 'other_phase'},
    '0x447adf0|0x70': {},
    '0x447df40|0x40': {0x447e72a: 'vector_copy'},
    '0x447e810|0x30': {0x447eadf: 'vector_copy'},
    '0x447fe90|0x130': {},
    '0x44868f0|0x40': {0x4487098: 'other_phase'},
    '0x44875a0|0x40': {},
    '0x4487db0|0x8': {},
    '0x44881b0|0x18': {},
    '0x4488820|0x18': {},
    '0x44895f0|0x8': {},
    '0x448a370|0x8': {},
    '0x4e86260|0x60': {},
    '0x4e98260|0x60': {},
    '0x4f53680|0x60': {},
    '0x4f9e290|0x60': {},
    '0x54cfa90|0xb0': {0x54cfebd: 'vector_copy', 0x54d0064: 'other_phase', 0x54d0625: 'other_phase', 0x54d0851: 'other_phase', 0x54d1009: 'vector_copy', 0x54d1188: 'vector_copy', 0x54d1885: 'vector_copy', 0x54d20f6: 'vector_copy', 0x54d2c4f: 'other_phase', 0x54d341d: 'vector_copy', 0x54d3666: 'other_phase', 0x54d369b: 'other_phase', 0x54d3d1b: 'vector_copy', 0x54d3e0f: 'other_phase', 0x54d50dc: 'vector_copy'},
    '0x54d57b0|0xa0': {0x54d5be8: 'vector_copy', 0x54d5d8f: 'other_phase', 0x54d6340: 'other_phase', 0x54d6571: 'other_phase', 0x54d6ce9: 'vector_copy', 0x54d6e68: 'vector_copy', 0x54d7565: 'vector_copy', 0x54d7dc1: 'vector_copy', 0x54d88f3: 'other_phase', 0x54d90e0: 'vector_copy', 0x54d9336: 'other_phase', 0x54d936b: 'other_phase', 0x54d99d7: 'vector_copy', 0x54d9acf: 'other_phase', 0x54dad91: 'vector_copy'},
    '0x591b240|0x80': {0x591b5b7: 'other_phase'},
    '0x591c1e0|0x80': {0x591c557: 'other_phase'},
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


def _consumption_on_hit(rows, flag_addr, goal, flag_form):
    """Block-walk from the flag test's jump: the goal block must be reached
    on exactly the hit side of the branch.  For a dword test (cmpl $0x1)
    equality is the miss; for a byte test (cmpb $0x0) equality is the hit."""
    addrs = sorted(rows)
    # The conditional jump on the flag test's flags may sit a few
    # flag-preserving instructions later (site 0x26c9a6d defers its jne
    # across a movabs and six loads); scan forward over mov/lea/nop only.
    jcc = None
    for a in addrs[addrs.index(flag_addr) + 1:][:13]:
        mn = rows[a][1].split(' ', 1)[0].split('\t')[0]
        if mn.startswith('j'):
            jcc = a
            break
        if mn.startswith(('mov', 'lea', 'nop')) or mn in ('data16',):
            continue
        raise PacketError(f'flag-affecting instruction {rows[a][1]!r} between the '
                          f'flag test at {flag_addr:#x} and its conditional jump')
    if jcc is None:
        raise PacketError(f'no conditional jump after the flag test at {flag_addr:#x}')
    m = re.match(r'^(j\w+)\s+(0x[0-9a-f]+)$', rows[jcc][1])
    if not m:
        raise PacketError(f'no conditional jump after the flag test at {flag_addr:#x}')
    mnemonic, target = m.group(1), int(m.group(2), 16)
    fall = addrs[addrs.index(jcc) + 1]

    def reaches(start, goal_):
        i = addrs.index(start)
        for a in addrs[i:]:
            if a == goal_:
                return True
            mn = rows[a][1].split(' ', 1)[0]
            if mn.startswith('j') or mn in ('call', 'ret') or a > goal_:
                return False
        return False

    if flag_form == 'dword':
        hit_is_target = mnemonic in ('jne', 'jnz')
    else:
        hit_is_target = mnemonic in ('je', 'jz')
    in_target = reaches(target, goal)
    in_fall = reaches(fall, goal)
    if hit_is_target:
        return in_target and not in_fall
    return in_fall and not in_target


def analyze(data):
    secs = sections(data)
    _summary, fdes, _gaps = fde_extents(data)
    if len(fdes) != FDE_COUNT:
        raise PacketError(f'FDE census mismatch: {len(fdes)} != {FDE_COUNT}')
    starts = [f['start'] for f in fdes]
    if len(set(starts)) != len(starts):
        raise PacketError('FDE starts are not unique')
    extents = {f['start']: (f['start'], f['end']) for f in fdes}

    # --- the runner-up body
    body = _section_bytes(secs, data, RUNNERUP_START, RUNNERUP_END)
    if _sha256(body) != RUNNERUP_BODY_SHA256:
        raise PacketError('runnerup body differs from its pinned digest')
    rows = _decode(secs, data, RUNNERUP_START, RUNNERUP_END)
    _check_pins(rows, RUNNERUP_PINS, 'runnerup body')
    for addr, (_raw, text) in rows.items():
        if text.startswith('call'):
            raise PacketError(f'runnerup body is not call-free: call at {addr:#x}')
        m = re.match(r'^(?:jmp|j\w+)\s+(0x[0-9a-f]+)$', text)
        if m and not (RUNNERUP_START <= int(m.group(1), 16) < RUNNERUP_END):
            raise PacketError(f'runnerup body branches outside itself at {addr:#x}')

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
    direct, tail = _branch_sites(data, secs, RUNNERUP_START)
    if tail:
        raise PacketError('runnerup search has tail-call sites')
    if direct != set(SITES):
        raise PacketError('call-site census mismatch: byte scan disagrees with the retained sites')
    rela_hits = 0
    for sec in secs:
        if sec['name'] != '.rela.dyn':
            continue
        raw = data[sec['offset']:sec['offset'] + sec['size']]
        for off in range(0, len(raw) - 23, 24):
            _r_off, r_type, r_add = struct.unpack_from('<QQq', raw, off)
            if r_type == 8 and r_add == RUNNERUP_START:  # R_X86_64_RELATIVE
                rela_hits += 1
    if rela_hits != EXPECTED['rela_relative_hits']:
        raise PacketError('R_X86_64_RELATIVE census mismatch for the runnerup body')

    # --- per-site records, windows, flag tests, consumption direction
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
        if call_row is None or call_row[1] != 'call   0x35be560':
            raise PacketError(f'site {site:#x} is not a runnerup call in its caller decode')
        flag_row = rows[info['flag']]
        if flag_row[1].startswith('cmpl'):
            form = 'dword'
        elif flag_row[1].startswith('cmpb'):
            form = 'byte'
        else:
            raise PacketError(f'site {site:#x}: unrecognised flag test {flag_row[1]!r}')
        if info['class'] == 'node_position':
            triple = info['triple']
            if triple is None:
                raise PacketError(f'site {site:#x}: node_position class without a consumption triple')
            pos_a, shl_a, add_a = triple
            for a in triple:
                if a not in win['pins']:
                    raise PacketError(f'site {site:#x}: consumption instruction {a:#x} is not a window pin')
            pos_row, shl_row, add_row = rows[pos_a], rows[shl_a], rows[add_a]
            if not pos_row[1].startswith('mov') or f'{info["base"] + 0x18:#x}(%rsp)' not in pos_row[1]:
                raise PacketError(f'site {site:#x}: position pin does not load the position slot')
            if not shl_row[1].startswith('shl') or '$0x6' not in shl_row[1]:
                raise PacketError(f'site {site:#x}: scale pin is not a shift by 6 (x0x40)')
            dst = shl_row[1].rsplit(',', 1)[-1].strip()
            if pos_row[1].rsplit(',', 1)[-1].strip() != dst or add_row[1].rsplit(',', 1)[-1].strip() != dst:
                raise PacketError(f'site {site:#x}: consumption triple does not share one register')
            if not add_row[1].startswith('add') or f'{info["base"] + 0x8:#x}(%rsp)' not in add_row[1]:
                raise PacketError(f'site {site:#x}: add pin does not add the node slot')
            if not _consumption_on_hit(rows, info['flag'], add_a, form):
                raise PacketError(f'site {site:#x}: node+position consumption is not on the hit branch')
        elif info['triple'] is not None:
            raise PacketError(f'site {site:#x}: consumption triple retained for a non-consuming class')
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
            'tool': 'tools/runnerup_search_static.py',
            'test': 'tests/test_runnerup_search_static.py',
            'authentication_inside_analyze': False,
        },
        'node': {
            'artifact_sha256': ARTIFACT_SHA256,
            'artifact_size': ARTIFACT_SIZE,
            'fde_records': FDE_COUNT,
        },
        'runnerup': {
            'range': [hex(RUNNERUP_START), hex(RUNNERUP_END)],
            'length_bytes': RUNNERUP_END - RUNNERUP_START,
            'sha256': RUNNERUP_BODY_SHA256,
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
        'element_stride': hex(ELEMENT_STRIDE),
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
            'statement': 'no consumer reads the runnerup record height field as a number: '
                         'in every census unit the height slot reads are wholesale vector '
                         'copies of the record or belong to other phases of the same frame slot',
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
    ranges = [(RUNNERUP_START, RUNNERUP_END)] + [v[0] for v in BOUNDARIES.values()]
    kept = []
    for line in out.splitlines():
        m = re.match(r'^([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+FDE\s+cie=[0-9a-f]+\s+pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
        if m:
            pc = (int(m.group(4), 16), int(m.group(5), 16))
            if pc in ranges:
                kept.append(line.replace(path, '<authenticated-node115>'))
    return ('\n'.join(kept) + '\n').encode()


def _runnerup_export(data):
    """Full-body export in the chain's format: intel-syntax objdump of the
    authenticated ELF itself, with the source path normalised."""
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as handle:
        handle.write(data)
        path = handle.name
    try:
        out = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={RUNNERUP_START:#x}',
             f'--stop-address={RUNNERUP_END:#x}', path], text=True)
    finally:
        Path(path).unlink()
    if f'{RUNNERUP_START:x}:' not in out:
        raise PacketError('runnerup export does not cover the body')
    return out.replace(path, '<authenticated-node115>').encode()


def generate(data, out_dir):
    if _sha256(data) != ARTIFACT_SHA256 or len(data) != ARTIFACT_SIZE:
        raise PacketError('artifact SHA-256 mismatch')
    records = analyze(data)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json.dumps(records, indent=1, sort_keys=True) + '\n')
    (out / 'frames.txt').write_bytes(_frames(data))
    (out / 'runnerup_search_full_body_35be560_35be5f2_objdump.txt').write_bytes(_runnerup_export(data))
    return records


def main(argv):
    if len(argv) != 3 or argv[1] != 'generate':
        print('usage: runnerup_search_static.py generate <output-dir>', file=sys.stderr)
        return 2
    artifact = ROOT / 'artifacts/node/115/hl-node'
    generate(artifact.read_bytes(), argv[2])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
