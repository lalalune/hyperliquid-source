#!/usr/bin/env python3
"""RE-006 node #115 sibling cursor search (0x35bf460): retained static packet tool.

The body at 0x35bf460 is the third cursor-search shape of the RE-006 family,
sibling to the clones (RE-006 main packet), variant A and variant B (#2530).
It walks a node layout whose u64 keys sit at node + 0x798 (11 per node, count
word at node + 0x7f2, child edges from node + 0x7f8) and returns the same
32-byte caller record as the rest of the family (flag +0x0, node +0x8, height
+0x10, position +0x18).  It has 99 direct call sites in 63 caller FDEs -- more
than the clones and both variants combined.  This tool retains, per call site,
the record base on the caller's stack, the setup window, the flag test and the
consumption class of the record, plus a whole-FDE slot census per
(caller, base) unit that settles whether any consumer reads the record's
height field as a number (none does: every height-slot read in the 67 census
units is a wholesale vector copy or belongs to another phase of the caller's
own frame slot).

analyze() decodes and checks everything without authenticating the artifact,
so counterfactual byte flips surface as the specific failed check.
generate() authenticates the artifact first, then regenerates records.json,
frames.txt and the sibling's full-body disassembly export byte-for-byte.
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

PACKET_ID = 'RE-006-node115-sibling-search'
PACKET_DIR = ROOT / 'research' / 'work-items' / PACKET_ID

SIBLING_START = 0x35bf460
SIBLING_END = 0x35bf4f2
SIBLING_NAME = 'sibling_search'
ARTIFACT_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARTIFACT_SIZE = 105896032

# Body landmarks (all pinned again in SIBLING_PINS).
KEY_DEREF = 0x35bf463        # mov (%rcx),%rcx -- the key is dereferenced once
COUNT_LOAD = 0x35bf466       # movzwl 0x7f2(%rsi),%r8d -- count word at node + 0x7f2
KEY_COMPARE = 0x35bf485      # cmp 0x7a0(%rsi,%rdi,8),%rcx -- scan index from -1: keys at +0x798
DESCENT_LOAD = 0x35bf4cc     # mov 0x7f8(%rsi,%rdi,8),%rsi -- child edges from +0x7f8
FLAG_ZERO = 0x35bf4d9        # xor %ecx,%ecx -- hit epilogue: flag 0
NODE_STORE = 0x35bf4db       # mov %rsi,0x8(%rax)
HEIGHT_STORE = 0x35bf4df     # mov %rdx,0x10(%rax)
POSITION_STORE = 0x35bf4e3   # mov %rdi,0x18(%rax)
FLAG_STORE = 0x35bf4e7       # mov %rcx,(%rax)
FLAG_ONE = 0x35bf4eb         # mov $0x1,%ecx -- miss epilogue: flag 1

NODE_LAYOUT = {
    'keys_per_node': 11,
    'key_offset': 0x798,
    'key_size': 8,
    'count_offset': 0x7f2,
    'edge_base': 0x7f8,
    'child_index_offset': 0x7f0,
}
RECORD_LAYOUT = {'size': 32, 'flag': 0x0, 'node': 0x8, 'height': 0x10, 'position': 0x18}
ELEMENT_STRIDE = 0xb0
JOIN_INDIRECT_CALL_SLOT = 0x64e7198
JOIN_SITES = (0x2a89910, 0x55a0bf0, 0x55a16f0)
VECTOR_MNEMONICS = ('movups', 'movupd', 'movapd', 'movaps', 'movdqu', 'movdqa')
FDE_COUNT = 135313

EXPECTED = {
    'call_sites': 99,
    'caller_fdes': 63,
    'census_units': 67,
    'node_position_sites': 60,
    'flag_only_sites': 38,
    'flag_node_addr_sites': 1,
    'join_sites': 3,
    'flag_dword_sites': 60,
    'flag_byte_sites': 39,
    'presentations': {'embedded_0x6c8': 52, 'embedded_0x58': 6, 'pointer': 37,
                      'pointer_spilled_height': 4},
    'height_read_units': 20,
    'height_never_read_units': 47,
    'height_reads': 137,
    'height_vector_copy_reads': 38,
    'height_other_phase_reads': 99,
    'height_consumed_reads': 0,
    'windows': 204,
    'site_windows': 99,
    'attribution_windows': 99,
    'overwrite_windows': 6,
    'tail_call_sites': 0,
    'rela_relative_hits': 0,
}

SIBLING_BODY_SHA256 = '10b3b34cb2182f4c9bba0efbb6750ada3ec101615535406c3663df2b09f840ca'
SIBLING_PINS = {
    0x35bf460: ('4889f8', 'mov    %rdi,%rax'),
    0x35bf463: ('488b09', 'mov    (%rcx),%rcx'),
    0x35bf466: ('440fb786f20700', 'movzwl 0x7f2(%rsi),%r8d'),
    0x35bf46e: ('4589c1', 'mov    %r8d,%r9d'),
    0x35bf471: ('41c1e103', 'shl    $0x3,%r9d'),
    0x35bf475: ('48c7c7ffffffff', 'mov    $0xffffffffffffffff,%rdi'),
    0x35bf47c: ('0f1f4000', 'nopl   0x0(%rax)'),
    0x35bf480: ('4d85c9', 'test   %r9,%r9'),
    0x35bf483: ('743b', 'je     0x35bf4c0'),
    0x35bf485: ('483b8cfea00700', 'cmp    0x7a0(%rsi,%rdi,8),%rcx'),
    0x35bf48d: ('410f97c2', 'seta   %r10b'),
    0x35bf491: ('4180da00', 'sbb    $0x0,%r10b'),
    0x35bf495: ('48ffc7', 'inc    %rdi'),
    0x35bf498: ('4983c1f8', 'add    $0xfffffffffffffff8,%r9'),
    0x35bf49c: ('4180fa01', 'cmp    $0x1,%r10b'),
    0x35bf4a0: ('74de', 'je     0x35bf480'),
    0x35bf4a2: ('450fb6c2', 'movzbl %r10b,%r8d'),
    0x35bf4a6: ('4585c0', 'test   %r8d,%r8d'),
    0x35bf4a9: ('742e', 'je     0x35bf4d9'),
    0x35bf4ab: ('4989d0', 'mov    %rdx,%r8'),
    0x35bf4ae: ('4983e801', 'sub    $0x1,%r8'),
    0x35bf4b2: ('7318', 'jae    0x35bf4cc'),
    0x35bf4b4: ('eb35', 'jmp    0x35bf4eb'),
    0x35bf4b6: ('662e0f1f840000', 'cs nopw 0x0(%rax,%rax,1)'),
    0x35bf4c0: ('4c89c7', 'mov    %r8,%rdi'),
    0x35bf4c3: ('4989d0', 'mov    %rdx,%r8'),
    0x35bf4c6: ('4983e801', 'sub    $0x1,%r8'),
    0x35bf4ca: ('721f', 'jb     0x35bf4eb'),
    0x35bf4cc: ('488bb4fef80700', 'mov    0x7f8(%rsi,%rdi,8),%rsi'),
    0x35bf4d4: ('4c89c2', 'mov    %r8,%rdx'),
    0x35bf4d7: ('eb8d', 'jmp    0x35bf466'),
    0x35bf4d9: ('31c9', 'xor    %ecx,%ecx'),
    0x35bf4db: ('48897008', 'mov    %rsi,0x8(%rax)'),
    0x35bf4df: ('48895010', 'mov    %rdx,0x10(%rax)'),
    0x35bf4e3: ('48897818', 'mov    %rdi,0x18(%rax)'),
    0x35bf4e7: ('488908', 'mov    %rcx,(%rax)'),
    0x35bf4ea: ('c3', 'ret'),
    0x35bf4eb: ('b901000000', 'mov    $0x1,%ecx'),
    0x35bf4f0: ('ebe9', 'jmp    0x35bf4db'),
}
BOUNDARIES = {
    0x296a390: ((0x296a390, 0x296cf96), '06de78829e95759e4f1712935e669b993b0c04d7b2a0ff3b050c1105086984f1'),
    0x2a40cc0: ((0x2a40cc0, 0x2a41773), '3957a3c71aafee766dcbdc8ef3ebb9077a80f93e9a6fabd3e71d5846afbce402'),
    0x2a84990: ((0x2a84990, 0x2a84e5a), '468e62dba29282e47e7df69cdd3976ffe4a085f5d574bb439421a193455b7ac9'),
    0x2a84e60: ((0x2a84e60, 0x2a8829e), '7bca2f033becd6f8a8f0d184a434cdd74677915f45e0c9ab31aa61970bbaaace'),
    0x2a88380: ((0x2a88380, 0x2a88641), 'bcefc58ea1c13bb1206e48b94960d6e238bfd00ed0becf3c983fd902f1e705db'),
    0x2a88af0: ((0x2a88af0, 0x2a88c86), '2f5873c8fe528a97e867fe94f17712e87751081c2e5d1542dc1744eed214e8d4'),
    0x2a89500: ((0x2a89500, 0x2a8a000), 'd33c9906f43bb0c54ab7cf6a21f3b8cd465f135cb9716ea7e4991eefafbb2aa0'),
    0x2a8be00: ((0x2a8be00, 0x2a8cbb3), '6192142ab8921f4faa4e927aa42bfa0cd9d9f3b2f836dc8f57b66e783d4d4c5f'),
    0x2b92a50: ((0x2b92a50, 0x2b92be6), 'aedebadcafec4da400cf5d4d264dae1b3987f75683f5bb6316f58f4ec3109ad5'),
    0x2bb2ec0: ((0x2bb2ec0, 0x2bb339f), '5b9d36f2008924076dd06a912b4a59a9de5572d6807bcd68f0d3f1bebd19c21b'),
    0x2bb48c0: ((0x2bb48c0, 0x2bb5293), '0cf67d77a67aa7eec26d054e0170f0b32a7c78bd0a968d4f729aff2f592a27ba'),
    0x2bb52a0: ((0x2bb52a0, 0x2bb68d6), '879e56724ec4d83c7b7ef7699fa08a1f6b3a12ecd72f50972d828c02a5b2fe13'),
    0x2bb68e0: ((0x2bb68e0, 0x2bb7263), '8e8ac1745c108db4edac860064774eac01df8aa454e8c628bcb92d6cf38059a3'),
    0x2bb7270: ((0x2bb7270, 0x2bb9893), '6dbf7f8390953d24bdd5b7a225e83f3e1614fb79ee6b3f40d423f8728d44234b'),
    0x2bb98a0: ((0x2bb98a0, 0x2bba0f5), 'c2a3d152b392078059824faab212a9ffbcce4fe16491afd70a968fd6cf4554e8'),
    0x2bba100: ((0x2bba100, 0x2bbad77), '19e6440ce606792af59b7315575552b625049198043174ce1c6e84eaa93e7ed1'),
    0x2bbbba0: ((0x2bbbba0, 0x2bbc74d), 'f3e69ec027f6e24352c49415a533d2cc5e75443ce6681b3c6b51331a3446fa35'),
    0x2bbc750: ((0x2bbc750, 0x2bbd0a3), '1e485c8260263eee0fb80e2871c1aaabde9f381b30e9159662d64e5a991a04fa'),
    0x2bbd0b0: ((0x2bbd0b0, 0x2bbdb9a), '889874f504716879ed3af8bfab1a9f7909972bfee409b4125910ce5a114c1a6e'),
    0x2bdf8f0: ((0x2bdf8f0, 0x2beafa1), '225649f70f438609a3bf19555e1a01ce18bee7dfa80fb5179ba16225e4fa437c'),
    0x2bf2ed0: ((0x2bf2ed0, 0x2bf8ad4), '69db6537a973f5c737607109480896d09a8a5aa73b1d7c1df62545dec93ae5b7'),
    0x2c61b30: ((0x2c61b30, 0x2c622e7), 'fb6986607aeb4f699ed29f505bba328b2ea171995bccc10fd3e418dbed54a2b1'),
    0x2c62820: ((0x2c62820, 0x2c64862), '9176b5c3361b91321a3b0cd99c2e90bf4538c1d7b21a68d63f68d5082e33fe96'),
    0x2c65980: ((0x2c65980, 0x2c66554), '8a3b9f1d35680656ff9359e45e2720521adb38a8e5f1b590d9e60e66079b7232'),
    0x2c74e40: ((0x2c74e40, 0x2c75417), 'dc8264b6c0c30703944687f062ed27ced1685c62a3f221a68320cb65b160fa10'),
    0x2c80670: ((0x2c80670, 0x2c80a3d), '4d3c4952b9d5e9d0cf88f08a64914d3dcc6a6cb100680781629a393bee76dc96'),
    0x2d27720: ((0x2d27720, 0x2d27a78), '2e3e51ea9925edc38ae111c2eed527b463dadf3d01e73342a90fdca9752a2a1c'),
    0x2f0f090: ((0x2f0f090, 0x2f0f3a6), '7527c800b5be2660d0273e6378896daedc258cd52e89367214ea60f7ac264657'),
    0x2f0f3b0: ((0x2f0f3b0, 0x2f0f93a), '2f5fe82fbc64267cdc17936d2556d8453b92cc54a3353e95535ef93ab11453ed'),
    0x421b430: ((0x421b430, 0x421b494), 'dc1d9cbbfa71e5780b263613691b403a44cdc84d28601a8b68d0eb74dd82e2e0'),
    0x451d1c0: ((0x451d1c0, 0x451d2fe), '483c8bd6b9d6aea9a7ec39c82f170c63b77664d1456b5a153312ab325a43becc'),
    0x46df170: ((0x46df170, 0x46df355), 'ec255846b32aa9f63ae74c2d33d87ef920d7a98c28fded597398ec419d039d95'),
    0x547d430: ((0x547d430, 0x547d90f), '99f251194aec2b9806f7214be9231e387233d6766fdcc361da976e4a2299c73f'),
    0x547d910: ((0x547d910, 0x547ddef), '1bc71e61512042517c11585283630a37d999492fd52d680e762abfd2c08fe259'),
    0x548ebd0: ((0x548ebd0, 0x548f424), 'd7152e5e368f3cc257a2043f31de8bd8d8f87909b49ef60a857da1fa330a1a39'),
    0x548f430: ((0x548f430, 0x54900a7), '46ac35608029b946108866412311b1b42c3b6c4d178f143e16adbd67139148b2'),
    0x5490660: ((0x5490660, 0x549118e), '439fe08e21070afa42fb7028862c87a840aca1f68bbbabde6b6681e099899e64'),
    0x5491190: ((0x5491190, 0x5492434), '91beb13ee0905b3db7ef6e6d9d41df49af7f06195fa9f147888c866925b4ae8a'),
    0x5492440: ((0x5492440, 0x5493013), '51550e60c680bb4717b73bdacb40ffb13dbc5f8fb1a26dba33ed15356324663f'),
    0x5493080: ((0x5493080, 0x5493c2d), '3f64074e76c5885610e7e95dd1b66853e70f74d1e0b406fb3b9e25ac2c9abae3'),
    0x5493c30: ((0x5493c30, 0x549471a), 'ce21c020d8136334be1bb89799253a295aeab1ab10c688d4d5ef4744294f0c9e'),
    0x5494720: ((0x5494720, 0x5495073), '22fd22d11c09bf61900af25dcb36f4d1cf63865c696382add27794a1004db4ee'),
    0x54a9c70: ((0x54a9c70, 0x54b66a2), 'c8b4563b262d24c124d4ee54a7e00146f41aeb8dc57799cdf5db6970562fceac'),
    0x54b66b0: ((0x54b66b0, 0x54c2ae8), '824ba23a3fbf24fe416e3f682d908c73e0c3504d82c6f1c8f20c79a61ee44d03'),
    0x54cfa90: ((0x54cfa90, 0x54d57a4), '824e0d4571ca1e4393eb87acd38dd36b9e9d87e1762905e464cc6942e698b1cf'),
    0x54d57b0: ((0x54d57b0, 0x54db474), '155583f5bcc0b7aff8164fb7aacf8e4792ba836bb17ae19c2d03e9e437d18ba4'),
    0x55817e0: ((0x55817e0, 0x5581caa), '30719705ca79c9df833ed285d0bcf80f7ba0ec00945fb8fe19bb88ae9bdce553'),
    0x5581cb0: ((0x5581cb0, 0x558217a), '87177643d25d41498450e280c1bd9717c3f9ec57149ed1d7275cc2cb21afad80'),
    0x5582180: ((0x5582180, 0x5585283), '0dce413fbb40e408ffca0831ec0ee804509e99cbde0b23f565bbb9b71dd2f19f'),
    0x5585290: ((0x5585290, 0x5588393), '0c80314b405562e1053ce3a5195ee216628d43b51d5e84e4833c900b19fe051a'),
    0x55883a0: ((0x55883a0, 0x5588661), '470e47fdb98820789995e8af8e61c8f4b21a856b18da4819457d6753a3b2ea53'),
    0x5588670: ((0x5588670, 0x5588931), '31e53fa8e6a4361001bdad968ab282f80d77e425a208ef8b468da0e877bae528'),
    0x5588d90: ((0x5588d90, 0x5588f26), 'a4a2fc820665cd0f22bb316c80f293f916df39bf6cf3ce78b88ab8cd7f955394'),
    0x5588f30: ((0x5588f30, 0x55890c6), 'e87be4febe78f09b3bb04b4d9957f496ee75eb0ece386c3fe0a127ba0054f89f'),
    0x55a07e0: ((0x55a07e0, 0x55a12e0), '41e588d7db79f90108f6981acc95af94e2534e68a0aa570c5f0270ece139ec5d'),
    0x55a12e0: ((0x55a12e0, 0x55a1de0), '1c2af67af44f5fe0dcb0eb706c5b9c2db8d4793c5ac01475387cfe160a6cf0ba'),
    0x55defd0: ((0x55defd0, 0x55e16ca), '33773d4f76f1b5f3cb9790d204e74484410ba56dedeb90451221ee829c785c64'),
    0x55e16d0: ((0x55e16d0, 0x55e3762), '22651e5a99e6a1279013c659838c4b561df8dd2d2e6ad97b0f8ce31b6b783b30'),
    0x55e4ad0: ((0x55e4ad0, 0x55e57d0), 'cebedd523c557782dc620af9901085a0e2370d8e22bf45c02878e9a827bb5a3a'),
    0x560a550: ((0x560a550, 0x560ad91), '7fb7199c96691c99955b22da9b1899912c4ba2c9bbb4daec7cbd673b2ff67298'),
    0x560ada0: ((0x560ada0, 0x560b5e1), 'f06d8bd576730903b6ab2d962f276d79b8c14f30535152efeebdbeb8b3a11430'),
    0x5a090d0: ((0x5a090d0, 0x5a09428), '31f21a47108d6f188544974541c345ef1b4259a784e42910a0adb9ddbab56bd9'),
    0x5a31270: ((0x5a31270, 0x5a3163d), '2d161898b46724d10e0874e067ed3d786838d66c7c443c5e7cda20c4b7cbff37'),
}
SITES = {
    0x296c266: {"caller": 0x296a390, "base": 0x130, "class": 'node_position', "flag": 0x296c26b, "presentation": 'embedded_0x6c8', "join": False},
    0x2a414f0: {"caller": 0x2a40cc0, "base": 0x20, "class": 'flag_node_addr', "flag": 0x2a414f5, "presentation": 'embedded_0x6c8', "join": False},
    0x2a41569: {"caller": 0x2a40cc0, "base": 0x20, "class": 'flag_only', "flag": 0x2a4156e, "presentation": 'embedded_0x6c8', "join": False},
    0x2a84a2f: {"caller": 0x2a84990, "base": 0xa0, "class": 'flag_only', "flag": 0x2a84a34, "presentation": 'embedded_0x6c8', "join": False},
    0x2a84a79: {"caller": 0x2a84990, "base": 0xa0, "class": 'flag_only', "flag": 0x2a84a7e, "presentation": 'embedded_0x6c8', "join": False},
    0x2a84cb4: {"caller": 0x2a84990, "base": 0xa0, "class": 'flag_only', "flag": 0x2a84cb9, "presentation": 'embedded_0x6c8', "join": False},
    0x2a86300: {"caller": 0x2a84e60, "base": 0xd0, "class": 'flag_only', "flag": 0x2a86305, "presentation": 'embedded_0x6c8', "join": False},
    0x2a88469: {"caller": 0x2a88380, "base": 0x90, "class": 'flag_only', "flag": 0x2a8846e, "presentation": 'embedded_0x6c8', "join": False},
    0x2a88b59: {"caller": 0x2a88af0, "base": 0x10, "class": 'flag_only', "flag": 0x2a88b5e, "presentation": 'embedded_0x6c8', "join": False},
    0x2a89910: {"caller": 0x2a89500, "base": 0x80, "class": 'node_position', "flag": 0x2a89915, "presentation": 'embedded_0x6c8', "join": True},
    0x2a8bf7b: {"caller": 0x2a8be00, "base": 0x10, "class": 'node_position', "flag": 0x2a8bf80, "presentation": 'embedded_0x6c8', "join": False},
    0x2b92b60: {"caller": 0x2b92a50, "base": 0x18, "class": 'node_position', "flag": 0x2b92b65, "presentation": 'pointer', "join": False},
    0x2bb2faf: {"caller": 0x2bb2ec0, "base": 0x40, "class": 'flag_only', "flag": 0x2bb2fb7, "presentation": 'embedded_0x6c8', "join": False},
    0x2bb3020: {"caller": 0x2bb2ec0, "base": 0x40, "class": 'flag_only', "flag": 0x2bb3028, "presentation": 'embedded_0x6c8', "join": False},
    0x2bb4c93: {"caller": 0x2bb48c0, "base": 0xf0, "class": 'node_position', "flag": 0x2bb4c98, "presentation": 'pointer', "join": False},
    0x2bb5618: {"caller": 0x2bb52a0, "base": 0x188, "class": 'node_position', "flag": 0x2bb561d, "presentation": 'pointer', "join": False},
    0x2bb5721: {"caller": 0x2bb52a0, "base": 0x188, "class": 'node_position', "flag": 0x2bb5726, "presentation": 'pointer', "join": False},
    0x2bb6c68: {"caller": 0x2bb68e0, "base": 0xf8, "class": 'node_position', "flag": 0x2bb6c6d, "presentation": 'pointer', "join": False},
    0x2bb793c: {"caller": 0x2bb7270, "base": 0x140, "class": 'node_position', "flag": 0x2bb7941, "presentation": 'pointer', "join": False},
    0x2bb8423: {"caller": 0x2bb7270, "base": 0x140, "class": 'node_position', "flag": 0x2bb8428, "presentation": 'pointer', "join": False},
    0x2bb86ef: {"caller": 0x2bb7270, "base": 0x140, "class": 'node_position', "flag": 0x2bb86f4, "presentation": 'pointer', "join": False},
    0x2bb87cb: {"caller": 0x2bb7270, "base": 0x140, "class": 'node_position', "flag": 0x2bb87d0, "presentation": 'pointer', "join": False},
    0x2bb9948: {"caller": 0x2bb98a0, "base": 0x80, "class": 'node_position', "flag": 0x2bb994d, "presentation": 'pointer', "join": False},
    0x2bba195: {"caller": 0x2bba100, "base": 0x60, "class": 'node_position', "flag": 0x2bba19a, "presentation": 'pointer', "join": False},
    0x2bba458: {"caller": 0x2bba100, "base": 0x60, "class": 'node_position', "flag": 0x2bba45d, "presentation": 'pointer_spilled_height', "join": False},
    0x2bbc00a: {"caller": 0x2bbbba0, "base": 0xf8, "class": 'node_position', "flag": 0x2bbc00f, "presentation": 'pointer', "join": False},
    0x2bbc97b: {"caller": 0x2bbc750, "base": 0xe8, "class": 'node_position', "flag": 0x2bbc980, "presentation": 'pointer_spilled_height', "join": False},
    0x2bbd43a: {"caller": 0x2bbd0b0, "base": 0xe8, "class": 'node_position', "flag": 0x2bbd43f, "presentation": 'pointer', "join": False},
    0x2be955a: {"caller": 0x2bdf8f0, "base": 0x3f0, "class": 'node_position', "flag": 0x2be955f, "presentation": 'embedded_0x6c8', "join": False},
    0x2bf60a1: {"caller": 0x2bf2ed0, "base": 0x250, "class": 'flag_only', "flag": 0x2bf60a6, "presentation": 'embedded_0x6c8', "join": False},
    0x2c61da6: {"caller": 0x2c61b30, "base": 0x30, "class": 'node_position', "flag": 0x2c61dab, "presentation": 'pointer', "join": False},
    0x2c6289f: {"caller": 0x2c62820, "base": 0x468, "class": 'flag_only', "flag": 0x2c628a4, "presentation": 'pointer', "join": False},
    0x2c62b9e: {"caller": 0x2c62820, "base": 0xa0, "class": 'node_position', "flag": 0x2c62ba3, "presentation": 'pointer', "join": False},
    0x2c63414: {"caller": 0x2c62820, "base": 0xa0, "class": 'node_position', "flag": 0x2c63419, "presentation": 'pointer', "join": False},
    0x2c63aec: {"caller": 0x2c62820, "base": 0xa0, "class": 'node_position', "flag": 0x2c63af1, "presentation": 'pointer', "join": False},
    0x2c63cfd: {"caller": 0x2c62820, "base": 0xa0, "class": 'node_position', "flag": 0x2c63d02, "presentation": 'pointer', "join": False},
    0x2c65b6b: {"caller": 0x2c65980, "base": 0x80, "class": 'flag_only', "flag": 0x2c65b70, "presentation": 'embedded_0x6c8', "join": False},
    0x2c74f81: {"caller": 0x2c74e40, "base": 0x70, "class": 'flag_only', "flag": 0x2c74f86, "presentation": 'embedded_0x6c8', "join": False},
    0x2c8074b: {"caller": 0x2c80670, "base": 0x270, "class": 'node_position', "flag": 0x2c80750, "presentation": 'embedded_0x6c8', "join": False},
    0x2d277c1: {"caller": 0x2d27720, "base": 0x48, "class": 'node_position', "flag": 0x2d277c6, "presentation": 'embedded_0x6c8', "join": False},
    0x2d27954: {"caller": 0x2d27720, "base": 0x48, "class": 'node_position', "flag": 0x2d27959, "presentation": 'embedded_0x6c8', "join": False},
    0x2f0f0ef: {"caller": 0x2f0f090, "base": 0x30, "class": 'node_position', "flag": 0x2f0f0f4, "presentation": 'embedded_0x58', "join": False},
    0x2f0f251: {"caller": 0x2f0f090, "base": 0x30, "class": 'node_position', "flag": 0x2f0f256, "presentation": 'embedded_0x58', "join": False},
    0x2f0f3fc: {"caller": 0x2f0f3b0, "base": 0x88, "class": 'node_position', "flag": 0x2f0f401, "presentation": 'embedded_0x58', "join": False},
    0x421b45d: {"caller": 0x421b430, "base": 0x8, "class": 'flag_only', "flag": 0x421b462, "presentation": 'pointer', "join": False},
    0x451d280: {"caller": 0x451d1c0, "base": 0x8, "class": 'node_position', "flag": 0x451d285, "presentation": 'embedded_0x58', "join": False},
    0x46df1da: {"caller": 0x46df170, "base": 0x28, "class": 'node_position', "flag": 0x46df1df, "presentation": 'embedded_0x58', "join": False},
    0x46df29a: {"caller": 0x46df170, "base": 0x28, "class": 'node_position', "flag": 0x46df29f, "presentation": 'embedded_0x58', "join": False},
    0x547d51f: {"caller": 0x547d430, "base": 0x40, "class": 'flag_only', "flag": 0x547d527, "presentation": 'embedded_0x6c8', "join": False},
    0x547d590: {"caller": 0x547d430, "base": 0x40, "class": 'flag_only', "flag": 0x547d598, "presentation": 'embedded_0x6c8', "join": False},
    0x547d9ff: {"caller": 0x547d910, "base": 0x40, "class": 'flag_only', "flag": 0x547da07, "presentation": 'embedded_0x6c8', "join": False},
    0x547da70: {"caller": 0x547d910, "base": 0x40, "class": 'flag_only', "flag": 0x547da78, "presentation": 'embedded_0x6c8', "join": False},
    0x548ec67: {"caller": 0x548ebd0, "base": 0x90, "class": 'node_position', "flag": 0x548ec6c, "presentation": 'pointer', "join": False},
    0x548f4c5: {"caller": 0x548f430, "base": 0x60, "class": 'node_position', "flag": 0x548f4ca, "presentation": 'pointer', "join": False},
    0x548f788: {"caller": 0x548f430, "base": 0x60, "class": 'node_position', "flag": 0x548f78d, "presentation": 'pointer_spilled_height', "join": False},
    0x5490a78: {"caller": 0x5490660, "base": 0x110, "class": 'node_position', "flag": 0x5490a7d, "presentation": 'pointer', "join": False},
    0x549153c: {"caller": 0x5491190, "base": 0xc0, "class": 'node_position', "flag": 0x5491541, "presentation": 'pointer', "join": False},
    0x5491643: {"caller": 0x5491190, "base": 0xc0, "class": 'node_position', "flag": 0x5491648, "presentation": 'pointer', "join": False},
    0x54928d1: {"caller": 0x5492440, "base": 0x120, "class": 'node_position', "flag": 0x54928d6, "presentation": 'pointer', "join": False},
    0x54934ea: {"caller": 0x5493080, "base": 0xf8, "class": 'node_position', "flag": 0x54934ef, "presentation": 'pointer', "join": False},
    0x5493fba: {"caller": 0x5493c30, "base": 0xe8, "class": 'node_position', "flag": 0x5493fbf, "presentation": 'pointer', "join": False},
    0x549494b: {"caller": 0x5494720, "base": 0xe8, "class": 'node_position', "flag": 0x5494950, "presentation": 'pointer_spilled_height', "join": False},
    0x54b282a: {"caller": 0x54a9c70, "base": 0x60, "class": 'node_position', "flag": 0x54b282f, "presentation": 'embedded_0x6c8', "join": False},
    0x54b4b67: {"caller": 0x54a9c70, "base": 0x470, "class": 'node_position', "flag": 0x54b4b6c, "presentation": 'embedded_0x6c8', "join": False},
    0x54bee54: {"caller": 0x54b66b0, "base": 0x60, "class": 'node_position', "flag": 0x54bee59, "presentation": 'embedded_0x6c8', "join": False},
    0x54c10da: {"caller": 0x54b66b0, "base": 0x3c0, "class": 'node_position', "flag": 0x54c10df, "presentation": 'embedded_0x6c8', "join": False},
    0x54d1702: {"caller": 0x54cfa90, "base": 0xb0, "class": 'flag_only', "flag": 0x54d1707, "presentation": 'embedded_0x6c8', "join": False},
    0x54d30ca: {"caller": 0x54cfa90, "base": 0xb0, "class": 'flag_only', "flag": 0x54d30cf, "presentation": 'embedded_0x6c8', "join": False},
    0x54d73e2: {"caller": 0x54d57b0, "base": 0xa0, "class": 'flag_only', "flag": 0x54d73e7, "presentation": 'embedded_0x6c8', "join": False},
    0x54d8d81: {"caller": 0x54d57b0, "base": 0xa0, "class": 'flag_only', "flag": 0x54d8d86, "presentation": 'embedded_0x6c8', "join": False},
    0x558187f: {"caller": 0x55817e0, "base": 0xa0, "class": 'flag_only', "flag": 0x5581884, "presentation": 'embedded_0x6c8', "join": False},
    0x55818c9: {"caller": 0x55817e0, "base": 0xa0, "class": 'flag_only', "flag": 0x55818ce, "presentation": 'embedded_0x6c8', "join": False},
    0x5581b04: {"caller": 0x55817e0, "base": 0xa0, "class": 'flag_only', "flag": 0x5581b09, "presentation": 'embedded_0x6c8', "join": False},
    0x5581d4f: {"caller": 0x5581cb0, "base": 0xa0, "class": 'flag_only', "flag": 0x5581d54, "presentation": 'embedded_0x6c8', "join": False},
    0x5581d99: {"caller": 0x5581cb0, "base": 0xa0, "class": 'flag_only', "flag": 0x5581d9e, "presentation": 'embedded_0x6c8', "join": False},
    0x5581fd4: {"caller": 0x5581cb0, "base": 0xa0, "class": 'flag_only', "flag": 0x5581fd9, "presentation": 'embedded_0x6c8', "join": False},
    0x5583409: {"caller": 0x5582180, "base": 0xb0, "class": 'flag_only', "flag": 0x558340e, "presentation": 'embedded_0x6c8', "join": False},
    0x5586519: {"caller": 0x5585290, "base": 0xb0, "class": 'flag_only', "flag": 0x558651e, "presentation": 'embedded_0x6c8', "join": False},
    0x5588489: {"caller": 0x55883a0, "base": 0x90, "class": 'flag_only', "flag": 0x558848e, "presentation": 'embedded_0x6c8', "join": False},
    0x5588759: {"caller": 0x5588670, "base": 0x90, "class": 'flag_only', "flag": 0x558875e, "presentation": 'embedded_0x6c8', "join": False},
    0x5588df9: {"caller": 0x5588d90, "base": 0x10, "class": 'flag_only', "flag": 0x5588dfe, "presentation": 'embedded_0x6c8', "join": False},
    0x5588f99: {"caller": 0x5588f30, "base": 0x10, "class": 'flag_only', "flag": 0x5588f9e, "presentation": 'embedded_0x6c8', "join": False},
    0x55a0bf0: {"caller": 0x55a07e0, "base": 0x80, "class": 'node_position', "flag": 0x55a0bf5, "presentation": 'embedded_0x6c8', "join": True},
    0x55a16f0: {"caller": 0x55a12e0, "base": 0x80, "class": 'node_position', "flag": 0x55a16f5, "presentation": 'embedded_0x6c8', "join": True},
    0x55df5e3: {"caller": 0x55defd0, "base": 0xa0, "class": 'node_position', "flag": 0x55df5e8, "presentation": 'pointer', "join": False},
    0x55dfde7: {"caller": 0x55defd0, "base": 0xa0, "class": 'node_position', "flag": 0x55dfdec, "presentation": 'pointer', "join": False},
    0x55e0624: {"caller": 0x55defd0, "base": 0xa0, "class": 'node_position', "flag": 0x55e0629, "presentation": 'pointer', "join": False},
    0x55e0923: {"caller": 0x55defd0, "base": 0xa0, "class": 'node_position', "flag": 0x55e0928, "presentation": 'pointer', "join": False},
    0x55e174f: {"caller": 0x55e16d0, "base": 0x478, "class": 'flag_only', "flag": 0x55e1754, "presentation": 'pointer', "join": False},
    0x55e1a5e: {"caller": 0x55e16d0, "base": 0xa0, "class": 'node_position', "flag": 0x55e1a63, "presentation": 'pointer', "join": False},
    0x55e22d4: {"caller": 0x55e16d0, "base": 0xa0, "class": 'node_position', "flag": 0x55e22d9, "presentation": 'pointer', "join": False},
    0x55e29ac: {"caller": 0x55e16d0, "base": 0xa0, "class": 'node_position', "flag": 0x55e29b1, "presentation": 'pointer', "join": False},
    0x55e2bed: {"caller": 0x55e16d0, "base": 0xa0, "class": 'node_position', "flag": 0x55e2bf2, "presentation": 'pointer', "join": False},
    0x55e4e0d: {"caller": 0x55e4ad0, "base": 0x80, "class": 'flag_only', "flag": 0x55e4e12, "presentation": 'embedded_0x6c8', "join": False},
    0x560a716: {"caller": 0x560a550, "base": 0xf0, "class": 'flag_only', "flag": 0x560a71b, "presentation": 'embedded_0x6c8', "join": False},
    0x560af66: {"caller": 0x560ada0, "base": 0xf0, "class": 'flag_only', "flag": 0x560af6b, "presentation": 'embedded_0x6c8', "join": False},
    0x5a09171: {"caller": 0x5a090d0, "base": 0x48, "class": 'node_position', "flag": 0x5a09176, "presentation": 'embedded_0x6c8', "join": False},
    0x5a09304: {"caller": 0x5a090d0, "base": 0x48, "class": 'node_position', "flag": 0x5a09309, "presentation": 'embedded_0x6c8', "join": False},
    0x5a3134b: {"caller": 0x5a31270, "base": 0x270, "class": 'node_position', "flag": 0x5a31350, "presentation": 'embedded_0x6c8', "join": False},
}
WINDOWS = {
    'site_0x296c266': {"range": (0x296c23d, 0x296c28d), "calls": {}, "pins": {
        0x296c23d: ('498bb424d00600', 'mov    0x6d0(%r12),%rsi'),
        0x296c24e: ('498b9424d80600', 'mov    0x6d8(%r12),%rdx'),
        0x296c256: ('488dbc24300100', 'lea    0x130(%rsp),%rdi'),
        0x296c25e: ('488d8c24600100', 'lea    0x160(%rsp),%rcx'),
        0x296c266: ('e8f531c500', 'call   0x35bf460'),
        0x296c26b: ('83bc2430010000', 'cmpl   $0x1,0x130(%rsp)'),
        0x296c279: ('48698424480100', 'imul   $0xb0,0x148(%rsp),%rax'),
        0x296c285: ('48038424380100', 'add    0x138(%rsp),%rax'),
    }},
    'site_0x2a414f0': {"range": (0x2a414cc, 0x2a41500), "calls": {}, "pins": {
        0x2a414cc: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x2a414dc: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x2a414e3: ('488d7c2420', 'lea    0x20(%rsp),%rdi'),
        0x2a414e8: ('488d8c24c00000', 'lea    0xc0(%rsp),%rcx'),
        0x2a414f0: ('e86bdfb700', 'call   0x35bf460'),
        0x2a414f5: ('807c242000', 'cmpb   $0x0,0x20(%rsp)'),
    }},
    'site_0x2a41569': {"range": (0x2a41543, 0x2a41575), "calls": {}, "pins": {
        0x2a41543: ('498bb424d00600', 'mov    0x6d0(%r12),%rsi'),
        0x2a41554: ('498b9424d80600', 'mov    0x6d8(%r12),%rdx'),
        0x2a4155c: ('488d7c2420', 'lea    0x20(%rsp),%rdi'),
        0x2a41561: ('488d8c24c00000', 'lea    0xc0(%rsp),%rcx'),
        0x2a41569: ('e8f2deb700', 'call   0x35bf460'),
        0x2a4156e: ('807c242000', 'cmpb   $0x0,0x20(%rsp)'),
    }},
    'site_0x2a84a2f': {"range": (0x2a84a0b, 0x2a84a42), "calls": {}, "pins": {
        0x2a84a0b: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x2a84a1b: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x2a84a22: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x2a84a2a: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x2a84a2f: ('e82caab300', 'call   0x35bf460'),
        0x2a84a34: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x2a84a79': {"range": (0x2a84a55, 0x2a84a88), "calls": {}, "pins": {
        0x2a84a55: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x2a84a65: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x2a84a6c: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x2a84a74: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x2a84a79: ('e8e2a9b300', 'call   0x35bf460'),
        0x2a84a7e: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x2a84cb4': {"range": (0x2a84c90, 0x2a84cc3), "calls": {}, "pins": {
        0x2a84c90: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x2a84ca0: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x2a84ca7: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x2a84caf: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x2a84cb4: ('e8a7a7b300', 'call   0x35bf460'),
        0x2a84cb9: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x2a86300': {"range": (0x2a862d9, 0x2a86313), "calls": {}, "pins": {
        0x2a862d9: ('498bb5d0060000', 'mov    0x6d0(%r13),%rsi'),
        0x2a862e9: ('498b95d8060000', 'mov    0x6d8(%r13),%rdx'),
        0x2a862f0: ('488dbc24d00000', 'lea    0xd0(%rsp),%rdi'),
        0x2a862f8: ('488d8c24600300', 'lea    0x360(%rsp),%rcx'),
        0x2a86300: ('e85b91b300', 'call   0x35bf460'),
        0x2a86305: ('80bc24d0000000', 'cmpb   $0x0,0xd0(%rsp)'),
    }},
    'site_0x2a88469': {"range": (0x2a88445, 0x2a88478), "calls": {}, "pins": {
        0x2a88445: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x2a88455: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x2a8845c: ('488dbc24900000', 'lea    0x90(%rsp),%rdi'),
        0x2a88464: ('488d4c2420', 'lea    0x20(%rsp),%rcx'),
        0x2a88469: ('e8f26fb300', 'call   0x35bf460'),
        0x2a8846e: ('80bc2490000000', 'cmpb   $0x0,0x90(%rsp)'),
    }},
    'site_0x2a88b59': {"range": (0x2a88b39, 0x2a88b65), "calls": {}, "pins": {
        0x2a88b39: ('488bb5d0060000', 'mov    0x6d0(%rbp),%rsi'),
        0x2a88b45: ('488b95d8060000', 'mov    0x6d8(%rbp),%rdx'),
        0x2a88b4c: ('488d7c2410', 'lea    0x10(%rsp),%rdi'),
        0x2a88b51: ('488d8c24800000', 'lea    0x80(%rsp),%rcx'),
        0x2a88b59: ('e80269b300', 'call   0x35bf460'),
        0x2a88b5e: ('807c241000', 'cmpb   $0x0,0x10(%rsp)'),
    }},
    'site_0x2a89910': {"range": (0x2a898ec, 0x2a8997e), "calls": {}, "pins": {
        0x2a898ec: ('488bb3d0060000', 'mov    0x6d0(%rbx),%rsi'),
        0x2a898fc: ('488b93d8060000', 'mov    0x6d8(%rbx),%rdx'),
        0x2a89903: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        0x2a8990b: ('488d4c2420', 'lea    0x20(%rsp),%rcx'),
        0x2a89910: ('e84b5bb300', 'call   0x35bf460'),
        0x2a89915: ('83bc2480000000', 'cmpl   $0x1,0x80(%rsp)'),
        0x2a8991f: ('4869bc24980000', 'imul   $0xb0,0x98(%rsp),%rdi'),
        0x2a8992b: ('4803bc24880000', 'add    0x88(%rsp),%rdi'),
        0x2a89946: ('483b93e0060000', 'cmp    0x6e0(%rbx),%rdx'),
        0x2a89969: ('4869cab8000000', 'imul   $0xb8,%rdx,%rcx'),
        0x2a89978: ('ff151ad8a503', 'call   *0x3a5d81a(%rip)        # 0x64e7198'),
    }},
    'site_0x2a8bf7b': {"range": (0x2a8bf57, 0x2a8bf99), "calls": {}, "pins": {
        0x2a8bf57: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x2a8bf67: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x2a8bf6e: ('488d7c2410', 'lea    0x10(%rsp),%rdi'),
        0x2a8bf73: ('488d8c24900000', 'lea    0x90(%rsp),%rcx'),
        0x2a8bf7b: ('e8e034b300', 'call   0x35bf460'),
        0x2a8bf80: ('837c241001', 'cmpl   $0x1,0x10(%rsp)'),
        0x2a8bf8b: ('4c69642428b000', 'imul   $0xb0,0x28(%rsp),%r12'),
        0x2a8bf94: ('4c03642418', 'add    0x18(%rsp),%r12'),
    }},
    'site_0x2b92b60': {"range": (0x2b92b49, 0x2b92b7a), "calls": {}, "pins": {
        0x2b92b49: ('498b7608', 'mov    0x8(%r14),%rsi'),
        0x2b92b52: ('498b5610', 'mov    0x10(%r14),%rdx'),
        0x2b92b56: ('488d7c2418', 'lea    0x18(%rsp),%rdi'),
        0x2b92b5b: ('488d4c2408', 'lea    0x8(%rsp),%rcx'),
        0x2b92b60: ('e8fbc8a200', 'call   0x35bf460'),
        0x2b92b65: ('837c241801', 'cmpl   $0x1,0x18(%rsp)'),
        0x2b92b6c: ('4869442430b000', 'imul   $0xb0,0x30(%rsp),%rax'),
        0x2b92b75: ('4803442420', 'add    0x20(%rsp),%rax'),
    }},
    'site_0x2bb2faf': {"range": (0x2bb2f88, 0x2bb2fbe), "calls": {}, "pins": {
        0x2bb2f88: ('498bb5d0060000', 'mov    0x6d0(%r13),%rsi'),
        0x2bb2f98: ('498b95d8060000', 'mov    0x6d8(%r13),%rdx'),
        0x2bb2fa4: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x2bb2fac: ('4889c7', 'mov    %rax,%rdi'),
        0x2bb2faf: ('e8acc4a000', 'call   0x35bf460'),
        0x2bb2fb7: ('807c244000', 'cmpb   $0x0,0x40(%rsp)'),
    }},
    'site_0x2bb3020': {"range": (0x2bb2ff9, 0x2bb302f), "calls": {}, "pins": {
        0x2bb2ff9: ('498bb5d0060000', 'mov    0x6d0(%r13),%rsi'),
        0x2bb3009: ('498b95d8060000', 'mov    0x6d8(%r13),%rdx'),
        0x2bb3015: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x2bb301d: ('4889c7', 'mov    %rax,%rdi'),
        0x2bb3020: ('e83bc4a000', 'call   0x35bf460'),
        0x2bb3028: ('807c244000', 'cmpb   $0x0,0x40(%rsp)'),
    }},
    'site_0x2bb4c93': {"range": (0x2bb4c75, 0x2bb4cba), "calls": {}, "pins": {
        0x2bb4c75: ('488b7708', 'mov    0x8(%rdi),%rsi'),
        0x2bb4c82: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x2bb4c86: ('488dbc24f00000', 'lea    0xf0(%rsp),%rdi'),
        0x2bb4c8e: ('488d4c2468', 'lea    0x68(%rsp),%rcx'),
        0x2bb4c93: ('e8c8a7a000', 'call   0x35bf460'),
        0x2bb4c98: ('83bc24f0000000', 'cmpl   $0x1,0xf0(%rsp)'),
        0x2bb4ca6: ('48698424080100', 'imul   $0xb0,0x108(%rsp),%rax'),
        0x2bb4cb2: ('48038424f80000', 'add    0xf8(%rsp),%rax'),
    }},
    'site_0x2bb5618': {"range": (0x2bb55f5, 0x2bb563f), "calls": {}, "pins": {
        0x2bb55f5: ('488b7708', 'mov    0x8(%rdi),%rsi'),
        0x2bb5607: ('488b5010', 'mov    0x10(%rax),%rdx'),
        0x2bb560b: ('488dbc24880100', 'lea    0x188(%rsp),%rdi'),
        0x2bb5613: ('488d4c2460', 'lea    0x60(%rsp),%rcx'),
        0x2bb5618: ('e8439ea000', 'call   0x35bf460'),
        0x2bb561d: ('83bc2488010000', 'cmpl   $0x1,0x188(%rsp)'),
        0x2bb562b: ('48698424a00100', 'imul   $0xb0,0x1a0(%rsp),%rax'),
        0x2bb5637: ('48038424900100', 'add    0x190(%rsp),%rax'),
    }},
    'site_0x2bb5721': {"range": (0x2bb56fe, 0x2bb5748), "calls": {}, "pins": {
        0x2bb56fe: ('488b7708', 'mov    0x8(%rdi),%rsi'),
        0x2bb5710: ('488b5010', 'mov    0x10(%rax),%rdx'),
        0x2bb5714: ('488dbc24880100', 'lea    0x188(%rsp),%rdi'),
        0x2bb571c: ('488d4c2460', 'lea    0x60(%rsp),%rcx'),
        0x2bb5721: ('e83a9da000', 'call   0x35bf460'),
        0x2bb5726: ('83bc2488010000', 'cmpl   $0x1,0x188(%rsp)'),
        0x2bb5734: ('4c69a424a00100', 'imul   $0xb0,0x1a0(%rsp),%r12'),
        0x2bb5740: ('4c03a424900100', 'add    0x190(%rsp),%r12'),
    }},
    'site_0x2bb6c68': {"range": (0x2bb6c4a, 0x2bb6c8f), "calls": {}, "pins": {
        0x2bb6c4a: ('488b7708', 'mov    0x8(%rdi),%rsi'),
        0x2bb6c57: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x2bb6c5b: ('488dbc24f80000', 'lea    0xf8(%rsp),%rdi'),
        0x2bb6c63: ('488d4c2468', 'lea    0x68(%rsp),%rcx'),
        0x2bb6c68: ('e8f387a000', 'call   0x35bf460'),
        0x2bb6c6d: ('83bc24f8000000', 'cmpl   $0x1,0xf8(%rsp)'),
        0x2bb6c7b: ('48698424100100', 'imul   $0xb0,0x110(%rsp),%rax'),
        0x2bb6c87: ('48038424000100', 'add    0x100(%rsp),%rax'),
    }},
    'site_0x2bb793c': {"range": (0x2bb7920, 0x2bb7968), "calls": {}, "pins": {
        0x2bb7920: ('498b7608', 'mov    0x8(%r14),%rsi'),
        0x2bb792d: ('498b5610', 'mov    0x10(%r14),%rdx'),
        0x2bb7931: ('4889ef', 'mov    %rbp,%rdi'),
        0x2bb7934: ('488d8c24800200', 'lea    0x280(%rsp),%rcx'),
        0x2bb793c: ('e81f7ba000', 'call   0x35bf460'),
        0x2bb7941: ('83bc2440010000', 'cmpl   $0x1,0x140(%rsp)'),
        0x2bb794f: ('4c69ac24580100', 'imul   $0xb0,0x158(%rsp),%r13'),
        0x2bb795b: ('4c03ac24480100', 'add    0x148(%rsp),%r13'),
    }},
    'site_0x2bb8423': {"range": (0x2bb8407, 0x2bb844a), "calls": {}, "pins": {
        0x2bb8407: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x2bb8414: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x2bb8418: ('4889ef', 'mov    %rbp,%rdi'),
        0x2bb841b: ('488d8c24800200', 'lea    0x280(%rsp),%rcx'),
        0x2bb8423: ('e83870a000', 'call   0x35bf460'),
        0x2bb8428: ('83bc2440010000', 'cmpl   $0x1,0x140(%rsp)'),
        0x2bb8436: ('48698424580100', 'imul   $0xb0,0x158(%rsp),%rax'),
        0x2bb8442: ('48038424480100', 'add    0x148(%rsp),%rax'),
    }},
    'site_0x2bb86ef': {"range": (0x2bb86d3, 0x2bb8716), "calls": {}, "pins": {
        0x2bb86d3: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x2bb86e0: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x2bb86e4: ('4889ef', 'mov    %rbp,%rdi'),
        0x2bb86e7: ('488d8c24800200', 'lea    0x280(%rsp),%rcx'),
        0x2bb86ef: ('e86c6da000', 'call   0x35bf460'),
        0x2bb86f4: ('83bc2440010000', 'cmpl   $0x1,0x140(%rsp)'),
        0x2bb8702: ('4c69b424580100', 'imul   $0xb0,0x158(%rsp),%r14'),
        0x2bb870e: ('4c03b424480100', 'add    0x148(%rsp),%r14'),
    }},
    'site_0x2bb87cb': {"range": (0x2bb87af, 0x2bb87fc), "calls": {}, "pins": {
        0x2bb87af: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x2bb87bc: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x2bb87c0: ('4889ef', 'mov    %rbp,%rdi'),
        0x2bb87c3: ('488d8c24800200', 'lea    0x280(%rsp),%rcx'),
        0x2bb87cb: ('e8906ca000', 'call   0x35bf460'),
        0x2bb87d0: ('83bc2440010000', 'cmpl   $0x1,0x140(%rsp)'),
        0x2bb87de: ('4c69a424580100', 'imul   $0xb0,0x158(%rsp),%r12'),
        0x2bb87ea: ('4c03a424480100', 'add    0x148(%rsp),%r12'),
    }},
    'site_0x2bb9948': {"range": (0x2bb9927, 0x2bb9977), "calls": {}, "pins": {
        0x2bb9927: ('498b7508', 'mov    0x8(%r13),%rsi'),
        0x2bb9934: ('498b5510', 'mov    0x10(%r13),%rdx'),
        0x2bb9938: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        0x2bb9940: ('488d8c24b00100', 'lea    0x1b0(%rsp),%rcx'),
        0x2bb9948: ('e8135ba000', 'call   0x35bf460'),
        0x2bb994d: ('83bc2480000000', 'cmpl   $0x1,0x80(%rsp)'),
        0x2bb9963: ('4c69a424980000', 'imul   $0xb0,0x98(%rsp),%r12'),
        0x2bb996f: ('4c03a424880000', 'add    0x88(%rsp),%r12'),
    }},
    'site_0x2bba195': {"range": (0x2bba17f, 0x2bba1bd), "calls": {}, "pins": {
        0x2bba17f: ('488b5710', 'mov    0x10(%rdi),%rdx'),
        0x2bba183: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x2bba188: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        0x2bba18d: ('4889de', 'mov    %rbx,%rsi'),
        0x2bba195: ('e8c652a000', 'call   0x35bf460'),
        0x2bba19a: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x2bba1aa: ('4869442478b000', 'imul   $0xb0,0x78(%rsp),%rax'),
        0x2bba1b3: ('4803442468', 'add    0x68(%rsp),%rax'),
    }},
    'site_0x2bba458': {"range": (0x2bba446, 0x2bba480), "calls": {}, "pins": {
        0x2bba446: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x2bba44b: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        0x2bba450: ('4889de', 'mov    %rbx,%rsi'),
        0x2bba453: ('488b542438', 'mov    0x38(%rsp),%rdx'),
        0x2bba458: ('e80350a000', 'call   0x35bf460'),
        0x2bba45d: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x2bba46d: ('4869542478b000', 'imul   $0xb0,0x78(%rsp),%rdx'),
        0x2bba476: ('4803542468', 'add    0x68(%rsp),%rdx'),
    }},
    'site_0x2bbc00a': {"range": (0x2bbbfec, 0x2bbc031), "calls": {}, "pins": {
        0x2bbbfec: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x2bbbff9: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x2bbbffd: ('488dbc24f80000', 'lea    0xf8(%rsp),%rdi'),
        0x2bbc005: ('488d4c2478', 'lea    0x78(%rsp),%rcx'),
        0x2bbc00a: ('e85134a000', 'call   0x35bf460'),
        0x2bbc00f: ('83bc24f8000000', 'cmpl   $0x1,0xf8(%rsp)'),
        0x2bbc01d: ('4c69bc24100100', 'imul   $0xb0,0x110(%rsp),%r15'),
        0x2bbc029: ('4c03bc24000100', 'add    0x100(%rsp),%r15'),
    }},
    'site_0x2bbc97b': {"range": (0x2bbc966, 0x2bbc9a2), "calls": {}, "pins": {
        0x2bbc966: ('488dbc24e80000', 'lea    0xe8(%rsp),%rdi'),
        0x2bbc96e: ('4c89e6', 'mov    %r12,%rsi'),
        0x2bbc971: ('488b542458', 'mov    0x58(%rsp),%rdx'),
        0x2bbc976: ('488d4c2468', 'lea    0x68(%rsp),%rcx'),
        0x2bbc97b: ('e8e02aa000', 'call   0x35bf460'),
        0x2bbc980: ('83bc24e8000000', 'cmpl   $0x1,0xe8(%rsp)'),
        0x2bbc98e: ('48699c24000100', 'imul   $0xb0,0x100(%rsp),%rbx'),
        0x2bbc99a: ('48039c24f00000', 'add    0xf0(%rsp),%rbx'),
    }},
    'site_0x2bbd43a': {"range": (0x2bbd41c, 0x2bbd467), "calls": {}, "pins": {
        0x2bbd41c: ('488b7708', 'mov    0x8(%rdi),%rsi'),
        0x2bbd429: ('488b5710', 'mov    0x10(%rdi),%rdx'),
        0x2bbd42d: ('488dbc24e80000', 'lea    0xe8(%rsp),%rdi'),
        0x2bbd435: ('488d4c2470', 'lea    0x70(%rsp),%rcx'),
        0x2bbd43a: ('e82120a000', 'call   0x35bf460'),
        0x2bbd43f: ('83bc24e8000000', 'cmpl   $0x1,0xe8(%rsp)'),
        0x2bbd453: ('4c69bc24000100', 'imul   $0xb0,0x100(%rsp),%r15'),
        0x2bbd45f: ('4c03bc24f00000', 'add    0xf0(%rsp),%r15'),
    }},
    'site_0x2be955a': {"range": (0x2be9538, 0x2be9581), "calls": {}, "pins": {
        0x2be9538: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x2be9548: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x2be954f: ('4889ef', 'mov    %rbp,%rdi'),
        0x2be9552: ('488d8c24600400', 'lea    0x460(%rsp),%rcx'),
        0x2be955a: ('e8015f9d00', 'call   0x35bf460'),
        0x2be955f: ('83bc24f0030000', 'cmpl   $0x1,0x3f0(%rsp)'),
        0x2be956d: ('48698c24080400', 'imul   $0xb0,0x408(%rsp),%rcx'),
        0x2be9579: ('48038c24f80300', 'add    0x3f8(%rsp),%rcx'),
    }},
    'site_0x2bf60a1': {"range": (0x2bf607e, 0x2bf60b0), "calls": {}, "pins": {
        0x2bf607e: ('488bb5d0060000', 'mov    0x6d0(%rbp),%rsi'),
        0x2bf608a: ('488b95d8060000', 'mov    0x6d8(%rbp),%rdx'),
        0x2bf6091: ('488dbc24500200', 'lea    0x250(%rsp),%rdi'),
        0x2bf6099: ('488d8c24f00100', 'lea    0x1f0(%rsp),%rcx'),
        0x2bf60a1: ('e8ba939c00', 'call   0x35bf460'),
        0x2bf60a6: ('80bc2450020000', 'cmpb   $0x0,0x250(%rsp)'),
    }},
    'site_0x2c61da6': {"range": (0x2c61d89, 0x2c61dc9), "calls": {}, "pins": {
        0x2c61d89: ('498b742408', 'mov    0x8(%r12),%rsi'),
        0x2c61d97: ('498b542410', 'mov    0x10(%r12),%rdx'),
        0x2c61d9c: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        0x2c61da1: ('488d4c2410', 'lea    0x10(%rsp),%rcx'),
        0x2c61da6: ('e8b5d69500', 'call   0x35bf460'),
        0x2c61dab: ('837c243001', 'cmpl   $0x1,0x30(%rsp)'),
        0x2c61dbb: ('4869442448b000', 'imul   $0xb0,0x48(%rsp),%rax'),
        0x2c61dc4: ('4803442438', 'add    0x38(%rsp),%rax'),
    }},
    'site_0x2c6289f': {"range": (0x2c6287e, 0x2c628b2), "calls": {}, "pins": {
        0x2c6287e: ('488b7708', 'mov    0x8(%rdi),%rsi'),
        0x2c6288b: ('488b5710', 'mov    0x10(%rdi),%rdx'),
        0x2c6288f: ('488dbc24680400', 'lea    0x468(%rsp),%rdi'),
        0x2c62897: ('488d8c24a00000', 'lea    0xa0(%rsp),%rcx'),
        0x2c6289f: ('e8bccb9500', 'call   0x35bf460'),
        0x2c628a4: ('80bc2468040000', 'cmpb   $0x0,0x468(%rsp)'),
    }},
    'site_0x2c62b9e': {"range": (0x2c62b7b, 0x2c62bc5), "calls": {}, "pins": {
        0x2c62b7b: ('498b742408', 'mov    0x8(%r12),%rsi'),
        0x2c62b89: ('498b542410', 'mov    0x10(%r12),%rdx'),
        0x2c62b8e: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x2c62b96: ('488d8c24800200', 'lea    0x280(%rsp),%rcx'),
        0x2c62b9e: ('e8bdc89500', 'call   0x35bf460'),
        0x2c62ba3: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x2c62bb1: ('4c69b424b80000', 'imul   $0xb0,0xb8(%rsp),%r14'),
        0x2c62bbd: ('4c03b424a80000', 'add    0xa8(%rsp),%r14'),
    }},
    'site_0x2c63414': {"range": (0x2c633f1, 0x2c6343b), "calls": {}, "pins": {
        0x2c633f1: ('498b742408', 'mov    0x8(%r12),%rsi'),
        0x2c633ff: ('498b542410', 'mov    0x10(%r12),%rdx'),
        0x2c63404: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x2c6340c: ('488d8c24800200', 'lea    0x280(%rsp),%rcx'),
        0x2c63414: ('e847c09500', 'call   0x35bf460'),
        0x2c63419: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x2c63427: ('4869ac24b80000', 'imul   $0xb0,0xb8(%rsp),%rbp'),
        0x2c63433: ('4803ac24a80000', 'add    0xa8(%rsp),%rbp'),
    }},
    'site_0x2c63aec': {"range": (0x2c63ad0, 0x2c63b90), "calls": {0x2c63b23: 0x4556410}, "pins": {
        0x2c63ad0: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x2c63add: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x2c63ae1: ('4c89e7', 'mov    %r12,%rdi'),
        0x2c63ae4: ('488d8c24800200', 'lea    0x280(%rsp),%rcx'),
        0x2c63aec: ('e86fb99500', 'call   0x35bf460'),
        0x2c63af1: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x2c63b77: ('48698424b80000', 'imul   $0xb0,0xb8(%rsp),%rax'),
        0x2c63b83: ('48038424a80000', 'add    0xa8(%rsp),%rax'),
    }},
    'site_0x2c63cfd': {"range": (0x2c63cdc, 0x2c63e66), "calls": {0x2c63d31: 0x4556410, 0x2c63df0: 0x2465020, 0x2c63e22: 0x24f1660}, "pins": {
        0x2c63cdc: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x2c63ce9: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x2c63ced: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x2c63cf5: ('488d8c24800200', 'lea    0x280(%rsp),%rcx'),
        0x2c63cfd: ('e85eb79500', 'call   0x35bf460'),
        0x2c63d02: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x2c63e52: ('4c69a424b80000', 'imul   $0xb0,0xb8(%rsp),%r12'),
        0x2c63e5e: ('4c03a424a80000', 'add    0xa8(%rsp),%r12'),
    }},
    'site_0x2c65b6b': {"range": (0x2c65b3f, 0x2c65b7e), "calls": {}, "pins": {
        0x2c65b3f: ('488bb3d0060000', 'mov    0x6d0(%rbx),%rsi'),
        0x2c65b54: ('488b93d8060000', 'mov    0x6d8(%rbx),%rdx'),
        0x2c65b5b: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        0x2c65b63: ('488d8c24c00100', 'lea    0x1c0(%rsp),%rcx'),
        0x2c65b6b: ('e8f0989500', 'call   0x35bf460'),
        0x2c65b70: ('80bc2480000000', 'cmpb   $0x0,0x80(%rsp)'),
    }},
    'site_0x2c74f81': {"range": (0x2c74f5d, 0x2c74f91), "calls": {}, "pins": {
        0x2c74f5d: ('498bb6d0060000', 'mov    0x6d0(%r14),%rsi'),
        0x2c74f6d: ('498b96d8060000', 'mov    0x6d8(%r14),%rdx'),
        0x2c74f74: ('488d7c2470', 'lea    0x70(%rsp),%rdi'),
        0x2c74f79: ('488d8c24e00000', 'lea    0xe0(%rsp),%rcx'),
        0x2c74f81: ('e8daa49400', 'call   0x35bf460'),
        0x2c74f86: ('807c247000', 'cmpb   $0x0,0x70(%rsp)'),
    }},
    'site_0x2c8074b': {"range": (0x2c80727, 0x2c80772), "calls": {}, "pins": {
        0x2c80727: ('488bb5d0060000', 'mov    0x6d0(%rbp),%rsi'),
        0x2c80737: ('488b95d8060000', 'mov    0x6d8(%rbp),%rdx'),
        0x2c8073e: ('488dbc24700200', 'lea    0x270(%rsp),%rdi'),
        0x2c80746: ('488d4c2420', 'lea    0x20(%rsp),%rcx'),
        0x2c8074b: ('e810ed9300', 'call   0x35bf460'),
        0x2c80750: ('83bc2470020000', 'cmpl   $0x1,0x270(%rsp)'),
        0x2c8075e: ('48698424880200', 'imul   $0xb0,0x288(%rsp),%rax'),
        0x2c8076a: ('48038424780200', 'add    0x278(%rsp),%rax'),
    }},
    'site_0x2d277c1': {"range": (0x2d277a0, 0x2d277df), "calls": {}, "pins": {
        0x2d277a0: ('498bb6d0060000', 'mov    0x6d0(%r14),%rsi'),
        0x2d277b0: ('498b96d8060000', 'mov    0x6d8(%r14),%rdx'),
        0x2d277b7: ('488d7c2448', 'lea    0x48(%rsp),%rdi'),
        0x2d277bc: ('488d4c2410', 'lea    0x10(%rsp),%rcx'),
        0x2d277c1: ('e89a7c8900', 'call   0x35bf460'),
        0x2d277c6: ('837c244801', 'cmpl   $0x1,0x48(%rsp)'),
        0x2d277d1: ('4869442460b000', 'imul   $0xb0,0x60(%rsp),%rax'),
        0x2d277da: ('4803442450', 'add    0x50(%rsp),%rax'),
    }},
    'site_0x2d27954': {"range": (0x2d27933, 0x2d27972), "calls": {}, "pins": {
        0x2d27933: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x2d27943: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x2d2794a: ('488d7c2448', 'lea    0x48(%rsp),%rdi'),
        0x2d2794f: ('488d4c2410', 'lea    0x10(%rsp),%rcx'),
        0x2d27954: ('e8077b8900', 'call   0x35bf460'),
        0x2d27959: ('837c244801', 'cmpl   $0x1,0x48(%rsp)'),
        0x2d27964: ('4869442460b000', 'imul   $0xb0,0x60(%rsp),%rax'),
        0x2d2796d: ('4803442450', 'add    0x50(%rsp),%rax'),
    }},
    'site_0x2f0f0ef': {"range": (0x2f0f0d2, 0x2f0f10d), "calls": {}, "pins": {
        0x2f0f0d2: ('498b742460', 'mov    0x60(%r12),%rsi'),
        0x2f0f0e0: ('498b542468', 'mov    0x68(%r12),%rdx'),
        0x2f0f0e5: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        0x2f0f0ea: ('488d4c2408', 'lea    0x8(%rsp),%rcx'),
        0x2f0f0ef: ('e86c036b00', 'call   0x35bf460'),
        0x2f0f0f4: ('837c243001', 'cmpl   $0x1,0x30(%rsp)'),
        0x2f0f0ff: ('48694c2448b000', 'imul   $0xb0,0x48(%rsp),%rcx'),
        0x2f0f108: ('48034c2438', 'add    0x38(%rsp),%rcx'),
    }},
    'site_0x2f0f251': {"range": (0x2f0f234, 0x2f0f26f), "calls": {}, "pins": {
        0x2f0f234: ('498b742460', 'mov    0x60(%r12),%rsi'),
        0x2f0f242: ('498b542468', 'mov    0x68(%r12),%rdx'),
        0x2f0f247: ('488d7c2430', 'lea    0x30(%rsp),%rdi'),
        0x2f0f24c: ('488d4c2408', 'lea    0x8(%rsp),%rcx'),
        0x2f0f251: ('e80a026b00', 'call   0x35bf460'),
        0x2f0f256: ('837c243001', 'cmpl   $0x1,0x30(%rsp)'),
        0x2f0f261: ('48694c2448b000', 'imul   $0xb0,0x48(%rsp),%rcx'),
        0x2f0f26a: ('48034c2438', 'add    0x38(%rsp),%rcx'),
    }},
    'site_0x2f0f3fc': {"range": (0x2f0f3de, 0x2f0f42c), "calls": {}, "pins": {
        0x2f0f3de: ('498b7560', 'mov    0x60(%r13),%rsi'),
        0x2f0f3eb: ('498b5568', 'mov    0x68(%r13),%rdx'),
        0x2f0f3ef: ('488dbc24880000', 'lea    0x88(%rsp),%rdi'),
        0x2f0f3f7: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x2f0f3fc: ('e85f006b00', 'call   0x35bf460'),
        0x2f0f401: ('83bc2488000000', 'cmpl   $0x1,0x88(%rsp)'),
        0x2f0f418: ('4c69ac24a00000', 'imul   $0xb0,0xa0(%rsp),%r13'),
        0x2f0f424: ('4c03ac24900000', 'add    0x90(%rsp),%r13'),
    }},
    'site_0x421b45d': {"range": (0x421b448, 0x421b469), "calls": {}, "pins": {
        0x421b448: ('488b7208', 'mov    0x8(%rdx),%rsi'),
        0x421b451: ('488b5210', 'mov    0x10(%rdx),%rdx'),
        0x421b455: ('488d7c2408', 'lea    0x8(%rsp),%rdi'),
        0x421b45a: ('4889e1', 'mov    %rsp,%rcx'),
        0x421b45d: ('e8fe3f3aff', 'call   0x35bf460'),
        0x421b462: ('807c240800', 'cmpb   $0x0,0x8(%rsp)'),
    }},
    'site_0x451d280': {"range": (0x451d267, 0x451d29a), "calls": {}, "pins": {
        0x451d267: ('498b7060', 'mov    0x60(%r8),%rsi'),
        0x451d274: ('498b5068', 'mov    0x68(%r8),%rdx'),
        0x451d278: ('488d7c2408', 'lea    0x8(%rsp),%rdi'),
        0x451d27d: ('4889e1', 'mov    %rsp,%rcx'),
        0x451d280: ('e8db210aff', 'call   0x35bf460'),
        0x451d285: ('837c240801', 'cmpl   $0x1,0x8(%rsp)'),
        0x451d28c: ('4869442420b000', 'imul   $0xb0,0x20(%rsp),%rax'),
        0x451d295: ('4803442410', 'add    0x10(%rsp),%rax'),
    }},
    'site_0x46df1da': {"range": (0x46df1bf, 0x46df1f4), "calls": {}, "pins": {
        0x46df1bf: ('498b7660', 'mov    0x60(%r14),%rsi'),
        0x46df1cc: ('498b5668', 'mov    0x68(%r14),%rdx'),
        0x46df1d0: ('488d7c2428', 'lea    0x28(%rsp),%rdi'),
        0x46df1d5: ('488d4c2408', 'lea    0x8(%rsp),%rcx'),
        0x46df1da: ('e88102eefe', 'call   0x35bf460'),
        0x46df1df: ('837c242801', 'cmpl   $0x1,0x28(%rsp)'),
        0x46df1e6: ('48694c2440b000', 'imul   $0xb0,0x40(%rsp),%rcx'),
        0x46df1ef: ('48034c2430', 'add    0x30(%rsp),%rcx'),
    }},
    'site_0x46df29a': {"range": (0x46df27f, 0x46df2b4), "calls": {}, "pins": {
        0x46df27f: ('498b7660', 'mov    0x60(%r14),%rsi'),
        0x46df28c: ('498b5668', 'mov    0x68(%r14),%rdx'),
        0x46df290: ('488d7c2428', 'lea    0x28(%rsp),%rdi'),
        0x46df295: ('488d4c2408', 'lea    0x8(%rsp),%rcx'),
        0x46df29a: ('e8c101eefe', 'call   0x35bf460'),
        0x46df29f: ('837c242801', 'cmpl   $0x1,0x28(%rsp)'),
        0x46df2a6: ('48694c2440b000', 'imul   $0xb0,0x40(%rsp),%rcx'),
        0x46df2af: ('48034c2430', 'add    0x30(%rsp),%rcx'),
    }},
    'site_0x547d51f': {"range": (0x547d4f8, 0x547d52e), "calls": {}, "pins": {
        0x547d4f8: ('498bb5d0060000', 'mov    0x6d0(%r13),%rsi'),
        0x547d508: ('498b95d8060000', 'mov    0x6d8(%r13),%rdx'),
        0x547d514: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x547d51c: ('4889c7', 'mov    %rax,%rdi'),
        0x547d51f: ('e83c1f14fe', 'call   0x35bf460'),
        0x547d527: ('807c244000', 'cmpb   $0x0,0x40(%rsp)'),
    }},
    'site_0x547d590': {"range": (0x547d569, 0x547d59f), "calls": {}, "pins": {
        0x547d569: ('498bb5d0060000', 'mov    0x6d0(%r13),%rsi'),
        0x547d579: ('498b95d8060000', 'mov    0x6d8(%r13),%rdx'),
        0x547d585: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x547d58d: ('4889c7', 'mov    %rax,%rdi'),
        0x547d590: ('e8cb1e14fe', 'call   0x35bf460'),
        0x547d598: ('807c244000', 'cmpb   $0x0,0x40(%rsp)'),
    }},
    'site_0x547d9ff': {"range": (0x547d9d8, 0x547da0e), "calls": {}, "pins": {
        0x547d9d8: ('498bb5d0060000', 'mov    0x6d0(%r13),%rsi'),
        0x547d9e8: ('498b95d8060000', 'mov    0x6d8(%r13),%rdx'),
        0x547d9f4: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x547d9fc: ('4889c7', 'mov    %rax,%rdi'),
        0x547d9ff: ('e85c1a14fe', 'call   0x35bf460'),
        0x547da07: ('807c244000', 'cmpb   $0x0,0x40(%rsp)'),
    }},
    'site_0x547da70': {"range": (0x547da49, 0x547da7f), "calls": {}, "pins": {
        0x547da49: ('498bb5d0060000', 'mov    0x6d0(%r13),%rsi'),
        0x547da59: ('498b95d8060000', 'mov    0x6d8(%r13),%rdx'),
        0x547da65: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x547da6d: ('4889c7', 'mov    %rax,%rdi'),
        0x547da70: ('e8eb1914fe', 'call   0x35bf460'),
        0x547da78: ('807c244000', 'cmpb   $0x0,0x40(%rsp)'),
    }},
    'site_0x548ec67': {"range": (0x548ec3f, 0x548ec96), "calls": {}, "pins": {
        0x548ec3f: ('498b742408', 'mov    0x8(%r12),%rsi'),
        0x548ec52: ('498b542410', 'mov    0x10(%r12),%rdx'),
        0x548ec57: ('488dbc24900000', 'lea    0x90(%rsp),%rdi'),
        0x548ec5f: ('488d8c24c00100', 'lea    0x1c0(%rsp),%rcx'),
        0x548ec67: ('e8f40713fe', 'call   0x35bf460'),
        0x548ec6c: ('83bc2490000000', 'cmpl   $0x1,0x90(%rsp)'),
        0x548ec82: ('4869ac24a80000', 'imul   $0xb0,0xa8(%rsp),%rbp'),
        0x548ec8e: ('4803ac24980000', 'add    0x98(%rsp),%rbp'),
    }},
    'site_0x548f4c5': {"range": (0x548f4af, 0x548f4ed), "calls": {}, "pins": {
        0x548f4af: ('488b5710', 'mov    0x10(%rdi),%rdx'),
        0x548f4b3: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x548f4b8: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        0x548f4bd: ('4889de', 'mov    %rbx,%rsi'),
        0x548f4c5: ('e896ff12fe', 'call   0x35bf460'),
        0x548f4ca: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x548f4da: ('4869442478b000', 'imul   $0xb0,0x78(%rsp),%rax'),
        0x548f4e3: ('4803442468', 'add    0x68(%rsp),%rax'),
    }},
    'site_0x548f788': {"range": (0x548f776, 0x548f7b0), "calls": {}, "pins": {
        0x548f776: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x548f77b: ('488d4c2440', 'lea    0x40(%rsp),%rcx'),
        0x548f780: ('4889de', 'mov    %rbx,%rsi'),
        0x548f783: ('488b542438', 'mov    0x38(%rsp),%rdx'),
        0x548f788: ('e8d3fc12fe', 'call   0x35bf460'),
        0x548f78d: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x548f79d: ('4869542478b000', 'imul   $0xb0,0x78(%rsp),%rdx'),
        0x548f7a6: ('4803542468', 'add    0x68(%rsp),%rdx'),
    }},
    'site_0x5490a78': {"range": (0x5490a5a, 0x5490a9f), "calls": {}, "pins": {
        0x5490a5a: ('488b7708', 'mov    0x8(%rdi),%rsi'),
        0x5490a67: ('498b5610', 'mov    0x10(%r14),%rdx'),
        0x5490a6b: ('488dbc24100100', 'lea    0x110(%rsp),%rdi'),
        0x5490a73: ('488d4c2468', 'lea    0x68(%rsp),%rcx'),
        0x5490a78: ('e8e3e912fe', 'call   0x35bf460'),
        0x5490a7d: ('83bc2410010000', 'cmpl   $0x1,0x110(%rsp)'),
        0x5490a8b: ('48698424280100', 'imul   $0xb0,0x128(%rsp),%rax'),
        0x5490a97: ('48038424180100', 'add    0x118(%rsp),%rax'),
    }},
    'site_0x549153c': {"range": (0x549151b, 0x5491563), "calls": {}, "pins": {
        0x549151b: ('488b7508', 'mov    0x8(%rbp),%rsi'),
        0x5491528: ('488b5510', 'mov    0x10(%rbp),%rdx'),
        0x549152c: ('488dbc24c00000', 'lea    0xc0(%rsp),%rdi'),
        0x5491534: ('488d8c24300200', 'lea    0x230(%rsp),%rcx'),
        0x549153c: ('e81fdf12fe', 'call   0x35bf460'),
        0x5491541: ('83bc24c0000000', 'cmpl   $0x1,0xc0(%rsp)'),
        0x549154f: ('48698424d80000', 'imul   $0xb0,0xd8(%rsp),%rax'),
        0x549155b: ('48038424c80000', 'add    0xc8(%rsp),%rax'),
    }},
    'site_0x5491643': {"range": (0x5491622, 0x549166a), "calls": {}, "pins": {
        0x5491622: ('488b7508', 'mov    0x8(%rbp),%rsi'),
        0x549162f: ('488b5510', 'mov    0x10(%rbp),%rdx'),
        0x5491633: ('488dbc24c00000', 'lea    0xc0(%rsp),%rdi'),
        0x549163b: ('488d8c24300200', 'lea    0x230(%rsp),%rcx'),
        0x5491643: ('e818de12fe', 'call   0x35bf460'),
        0x5491648: ('83bc24c0000000', 'cmpl   $0x1,0xc0(%rsp)'),
        0x5491656: ('48699c24d80000', 'imul   $0xb0,0xd8(%rsp),%rbx'),
        0x5491662: ('48039c24c80000', 'add    0xc8(%rsp),%rbx'),
    }},
    'site_0x54928d1': {"range": (0x54928b3, 0x5492969), "calls": {0x54928f8: 0x4556410}, "pins": {
        0x54928b3: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x54928c0: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x54928c4: ('488dbc24200100', 'lea    0x120(%rsp),%rdi'),
        0x54928cc: ('488d4c2468', 'lea    0x68(%rsp),%rcx'),
        0x54928d1: ('e88acb12fe', 'call   0x35bf460'),
        0x54928d6: ('83bc2420010000', 'cmpl   $0x1,0x120(%rsp)'),
        0x549294d: ('48698424380100', 'imul   $0xb0,0x138(%rsp),%rax'),
        0x5492959: ('48038424280100', 'add    0x128(%rsp),%rax'),
    }},
    'site_0x54934ea': {"range": (0x54934cc, 0x5493511), "calls": {}, "pins": {
        0x54934cc: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x54934d9: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x54934dd: ('488dbc24f80000', 'lea    0xf8(%rsp),%rdi'),
        0x54934e5: ('488d4c2478', 'lea    0x78(%rsp),%rcx'),
        0x54934ea: ('e871bf12fe', 'call   0x35bf460'),
        0x54934ef: ('83bc24f8000000', 'cmpl   $0x1,0xf8(%rsp)'),
        0x54934fd: ('4c69bc24100100', 'imul   $0xb0,0x110(%rsp),%r15'),
        0x5493509: ('4c03bc24000100', 'add    0x100(%rsp),%r15'),
    }},
    'site_0x5493fba': {"range": (0x5493f9c, 0x5493fe7), "calls": {}, "pins": {
        0x5493f9c: ('488b7708', 'mov    0x8(%rdi),%rsi'),
        0x5493fa9: ('488b5710', 'mov    0x10(%rdi),%rdx'),
        0x5493fad: ('488dbc24e80000', 'lea    0xe8(%rsp),%rdi'),
        0x5493fb5: ('488d4c2470', 'lea    0x70(%rsp),%rcx'),
        0x5493fba: ('e8a1b412fe', 'call   0x35bf460'),
        0x5493fbf: ('83bc24e8000000', 'cmpl   $0x1,0xe8(%rsp)'),
        0x5493fd3: ('4c69bc24000100', 'imul   $0xb0,0x100(%rsp),%r15'),
        0x5493fdf: ('4c03bc24f00000', 'add    0xf0(%rsp),%r15'),
    }},
    'site_0x549494b': {"range": (0x5494936, 0x5494972), "calls": {}, "pins": {
        0x5494936: ('488dbc24e80000', 'lea    0xe8(%rsp),%rdi'),
        0x549493e: ('4c89e6', 'mov    %r12,%rsi'),
        0x5494941: ('488b542458', 'mov    0x58(%rsp),%rdx'),
        0x5494946: ('488d4c2468', 'lea    0x68(%rsp),%rcx'),
        0x549494b: ('e810ab12fe', 'call   0x35bf460'),
        0x5494950: ('83bc24e8000000', 'cmpl   $0x1,0xe8(%rsp)'),
        0x549495e: ('48699c24000100', 'imul   $0xb0,0x100(%rsp),%rbx'),
        0x549496a: ('48039c24f00000', 'add    0xf0(%rsp),%rbx'),
    }},
    'site_0x54b282a': {"range": (0x54b2806, 0x54b2848), "calls": {}, "pins": {
        0x54b2806: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x54b2816: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x54b281d: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x54b2822: ('488d8c24600100', 'lea    0x160(%rsp),%rcx'),
        0x54b282a: ('e831cc10fe', 'call   0x35bf460'),
        0x54b282f: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x54b283a: ('4c69742478b000', 'imul   $0xb0,0x78(%rsp),%r14'),
        0x54b2843: ('4c03742468', 'add    0x68(%rsp),%r14'),
    }},
    'site_0x54b4b67': {"range": (0x54b4b45, 0x54b4b8e), "calls": {}, "pins": {
        0x54b4b45: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x54b4b55: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x54b4b5c: ('4c89f7', 'mov    %r14,%rdi'),
        0x54b4b5f: ('488d8c24d00400', 'lea    0x4d0(%rsp),%rcx'),
        0x54b4b67: ('e8f4a810fe', 'call   0x35bf460'),
        0x54b4b6c: ('83bc2470040000', 'cmpl   $0x1,0x470(%rsp)'),
        0x54b4b7a: ('48698c24880400', 'imul   $0xb0,0x488(%rsp),%rcx'),
        0x54b4b86: ('48038c24780400', 'add    0x478(%rsp),%rcx'),
    }},
    'site_0x54bee54': {"range": (0x54bee30, 0x54bee72), "calls": {}, "pins": {
        0x54bee30: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x54bee40: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x54bee47: ('488d7c2460', 'lea    0x60(%rsp),%rdi'),
        0x54bee4c: ('488d8c24200100', 'lea    0x120(%rsp),%rcx'),
        0x54bee54: ('e8070610fe', 'call   0x35bf460'),
        0x54bee59: ('837c246001', 'cmpl   $0x1,0x60(%rsp)'),
        0x54bee64: ('4c69642478b000', 'imul   $0xb0,0x78(%rsp),%r12'),
        0x54bee6d: ('4c03642468', 'add    0x68(%rsp),%r12'),
    }},
    'site_0x54c10da': {"range": (0x54c10b8, 0x54c1101), "calls": {}, "pins": {
        0x54c10b8: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x54c10c8: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x54c10cf: ('4c89f7', 'mov    %r14,%rdi'),
        0x54c10d2: ('488d8c24600400', 'lea    0x460(%rsp),%rcx'),
        0x54c10da: ('e881e30ffe', 'call   0x35bf460'),
        0x54c10df: ('83bc24c0030000', 'cmpl   $0x1,0x3c0(%rsp)'),
        0x54c10ed: ('48698c24d80300', 'imul   $0xb0,0x3d8(%rsp),%rcx'),
        0x54c10f9: ('48038c24c80300', 'add    0x3c8(%rsp),%rcx'),
    }},
    'site_0x54d1702': {"range": (0x54d16d6, 0x54d1715), "calls": {}, "pins": {
        0x54d16d6: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x54d16eb: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x54d16f2: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        0x54d16fa: ('488d8c24300700', 'lea    0x730(%rsp),%rcx'),
        0x54d1702: ('e859dd0efe', 'call   0x35bf460'),
        0x54d1707: ('80bc24b0000000', 'cmpb   $0x0,0xb0(%rsp)'),
    }},
    'site_0x54d30ca': {"range": (0x54d30a7, 0x54d30d9), "calls": {}, "pins": {
        0x54d30a7: ('498bb5d0060000', 'mov    0x6d0(%r13),%rsi'),
        0x54d30b3: ('498b95d8060000', 'mov    0x6d8(%r13),%rdx'),
        0x54d30ba: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        0x54d30c2: ('488d8c24480300', 'lea    0x348(%rsp),%rcx'),
        0x54d30ca: ('e891c30efe', 'call   0x35bf460'),
        0x54d30cf: ('80bc24b0000000', 'cmpb   $0x0,0xb0(%rsp)'),
    }},
    'site_0x54d73e2': {"range": (0x54d73b6, 0x54d73f5), "calls": {}, "pins": {
        0x54d73b6: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x54d73cb: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x54d73d2: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x54d73da: ('488d8c24300700', 'lea    0x730(%rsp),%rcx'),
        0x54d73e2: ('e879800efe', 'call   0x35bf460'),
        0x54d73e7: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x54d8d81': {"range": (0x54d8d59, 0x54d8d90), "calls": {}, "pins": {
        0x54d8d59: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x54d8d6a: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x54d8d71: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x54d8d79: ('488d8c24380300', 'lea    0x338(%rsp),%rcx'),
        0x54d8d81: ('e8da660efe', 'call   0x35bf460'),
        0x54d8d86: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x558187f': {"range": (0x558185b, 0x5581892), "calls": {}, "pins": {
        0x558185b: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x558186b: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x5581872: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x558187a: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x558187f: ('e8dcdb03fe', 'call   0x35bf460'),
        0x5581884: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x55818c9': {"range": (0x55818a5, 0x55818d8), "calls": {}, "pins": {
        0x55818a5: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x55818b5: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x55818bc: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x55818c4: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x55818c9: ('e892db03fe', 'call   0x35bf460'),
        0x55818ce: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x5581b04': {"range": (0x5581ae0, 0x5581b13), "calls": {}, "pins": {
        0x5581ae0: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x5581af0: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x5581af7: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x5581aff: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x5581b04: ('e857d903fe', 'call   0x35bf460'),
        0x5581b09: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x5581d4f': {"range": (0x5581d2b, 0x5581d62), "calls": {}, "pins": {
        0x5581d2b: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x5581d3b: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x5581d42: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x5581d4a: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x5581d4f: ('e80cd703fe', 'call   0x35bf460'),
        0x5581d54: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x5581d99': {"range": (0x5581d75, 0x5581da8), "calls": {}, "pins": {
        0x5581d75: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x5581d85: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x5581d8c: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x5581d94: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x5581d99: ('e8c2d603fe', 'call   0x35bf460'),
        0x5581d9e: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x5581fd4': {"range": (0x5581fb0, 0x5581fe3), "calls": {}, "pins": {
        0x5581fb0: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x5581fc0: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x5581fc7: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x5581fcf: ('488d4c2430', 'lea    0x30(%rsp),%rcx'),
        0x5581fd4: ('e887d403fe', 'call   0x35bf460'),
        0x5581fd9: ('80bc24a0000000', 'cmpb   $0x0,0xa0(%rsp)'),
    }},
    'site_0x5583409': {"range": (0x55833e2, 0x558341c), "calls": {}, "pins": {
        0x55833e2: ('498bb5d0060000', 'mov    0x6d0(%r13),%rsi'),
        0x55833f2: ('498b95d8060000', 'mov    0x6d8(%r13),%rdx'),
        0x55833f9: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        0x5583401: ('488d8c24e00200', 'lea    0x2e0(%rsp),%rcx'),
        0x5583409: ('e852c003fe', 'call   0x35bf460'),
        0x558340e: ('80bc24b0000000', 'cmpb   $0x0,0xb0(%rsp)'),
    }},
    'site_0x5586519': {"range": (0x55864f2, 0x558652c), "calls": {}, "pins": {
        0x55864f2: ('498bb5d0060000', 'mov    0x6d0(%r13),%rsi'),
        0x5586502: ('498b95d8060000', 'mov    0x6d8(%r13),%rdx'),
        0x5586509: ('488dbc24b00000', 'lea    0xb0(%rsp),%rdi'),
        0x5586511: ('488d8c24e00200', 'lea    0x2e0(%rsp),%rcx'),
        0x5586519: ('e8428f03fe', 'call   0x35bf460'),
        0x558651e: ('80bc24b0000000', 'cmpb   $0x0,0xb0(%rsp)'),
    }},
    'site_0x5588489': {"range": (0x5588465, 0x5588498), "calls": {}, "pins": {
        0x5588465: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x5588475: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x558847c: ('488dbc24900000', 'lea    0x90(%rsp),%rdi'),
        0x5588484: ('488d4c2420', 'lea    0x20(%rsp),%rcx'),
        0x5588489: ('e8d26f03fe', 'call   0x35bf460'),
        0x558848e: ('80bc2490000000', 'cmpb   $0x0,0x90(%rsp)'),
    }},
    'site_0x5588759': {"range": (0x5588735, 0x5588768), "calls": {}, "pins": {
        0x5588735: ('498bb7d0060000', 'mov    0x6d0(%r15),%rsi'),
        0x5588745: ('498b97d8060000', 'mov    0x6d8(%r15),%rdx'),
        0x558874c: ('488dbc24900000', 'lea    0x90(%rsp),%rdi'),
        0x5588754: ('488d4c2420', 'lea    0x20(%rsp),%rcx'),
        0x5588759: ('e8026d03fe', 'call   0x35bf460'),
        0x558875e: ('80bc2490000000', 'cmpb   $0x0,0x90(%rsp)'),
    }},
    'site_0x5588df9': {"range": (0x5588dd9, 0x5588e05), "calls": {}, "pins": {
        0x5588dd9: ('488bb5d0060000', 'mov    0x6d0(%rbp),%rsi'),
        0x5588de5: ('488b95d8060000', 'mov    0x6d8(%rbp),%rdx'),
        0x5588dec: ('488d7c2410', 'lea    0x10(%rsp),%rdi'),
        0x5588df1: ('488d8c24800000', 'lea    0x80(%rsp),%rcx'),
        0x5588df9: ('e8626603fe', 'call   0x35bf460'),
        0x5588dfe: ('807c241000', 'cmpb   $0x0,0x10(%rsp)'),
    }},
    'site_0x5588f99': {"range": (0x5588f79, 0x5588fa5), "calls": {}, "pins": {
        0x5588f79: ('488bb5d0060000', 'mov    0x6d0(%rbp),%rsi'),
        0x5588f85: ('488b95d8060000', 'mov    0x6d8(%rbp),%rdx'),
        0x5588f8c: ('488d7c2410', 'lea    0x10(%rsp),%rdi'),
        0x5588f91: ('488d8c24800000', 'lea    0x80(%rsp),%rcx'),
        0x5588f99: ('e8c26403fe', 'call   0x35bf460'),
        0x5588f9e: ('807c241000', 'cmpb   $0x0,0x10(%rsp)'),
    }},
    'site_0x55a0bf0': {"range": (0x55a0bcc, 0x55a0c5e), "calls": {}, "pins": {
        0x55a0bcc: ('488bb3d0060000', 'mov    0x6d0(%rbx),%rsi'),
        0x55a0bdc: ('488b93d8060000', 'mov    0x6d8(%rbx),%rdx'),
        0x55a0be3: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        0x55a0beb: ('488d4c2420', 'lea    0x20(%rsp),%rcx'),
        0x55a0bf0: ('e86be801fe', 'call   0x35bf460'),
        0x55a0bf5: ('83bc2480000000', 'cmpl   $0x1,0x80(%rsp)'),
        0x55a0bff: ('4869bc24980000', 'imul   $0xb0,0x98(%rsp),%rdi'),
        0x55a0c0b: ('4803bc24880000', 'add    0x88(%rsp),%rdi'),
        0x55a0c26: ('483b93e0060000', 'cmp    0x6e0(%rbx),%rdx'),
        0x55a0c49: ('4869cab8000000', 'imul   $0xb8,%rdx,%rcx'),
        0x55a0c58: ('ff153a65f400', 'call   *0xf4653a(%rip)        # 0x64e7198'),
    }},
    'site_0x55a16f0': {"range": (0x55a16cc, 0x55a175e), "calls": {}, "pins": {
        0x55a16cc: ('488bb3d0060000', 'mov    0x6d0(%rbx),%rsi'),
        0x55a16dc: ('488b93d8060000', 'mov    0x6d8(%rbx),%rdx'),
        0x55a16e3: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        0x55a16eb: ('488d4c2420', 'lea    0x20(%rsp),%rcx'),
        0x55a16f0: ('e86bdd01fe', 'call   0x35bf460'),
        0x55a16f5: ('83bc2480000000', 'cmpl   $0x1,0x80(%rsp)'),
        0x55a16ff: ('4869bc24980000', 'imul   $0xb0,0x98(%rsp),%rdi'),
        0x55a170b: ('4803bc24880000', 'add    0x88(%rsp),%rdi'),
        0x55a1726: ('483b93e0060000', 'cmp    0x6e0(%rbx),%rdx'),
        0x55a1749: ('4869cab8000000', 'imul   $0xb8,%rdx,%rcx'),
        0x55a1758: ('ff153a5af400', 'call   *0xf45a3a(%rip)        # 0x64e7198'),
    }},
    'site_0x55df5e3': {"range": (0x55df5c2, 0x55df60f), "calls": {}, "pins": {
        0x55df5c2: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x55df5cf: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x55df5d3: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x55df5db: ('488d8c24200300', 'lea    0x320(%rsp),%rcx'),
        0x55df5e3: ('e878fefdfd', 'call   0x35bf460'),
        0x55df5e8: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x55df5f6: ('4c69a424b80000', 'imul   $0xb0,0xb8(%rsp),%r12'),
        0x55df602: ('4c03a424a80000', 'add    0xa8(%rsp),%r12'),
    }},
    'site_0x55dfde7': {"range": (0x55dfdc6, 0x55dfe0e), "calls": {}, "pins": {
        0x55dfdc6: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x55dfdd3: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x55dfdd7: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x55dfddf: ('488d8c24200300', 'lea    0x320(%rsp),%rcx'),
        0x55dfde7: ('e874f6fdfd', 'call   0x35bf460'),
        0x55dfdec: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x55dfdfa: ('4c69b424b80000', 'imul   $0xb0,0xb8(%rsp),%r14'),
        0x55dfe06: ('4c03b424a80000', 'add    0xa8(%rsp),%r14'),
    }},
    'site_0x55e0624': {"range": (0x55e0608, 0x55e0fc4), "calls": {0x55e0654: 0x4556410, 0x55e07be: 0x57f3ba0, 0x55e089f: 0x57f3ba0, 0x55e0923: 0x35bf460, 0x55e094b: 0x4556410, 0x55e0a09: 0x522eeb0, 0x55e0a27: 0x5853850, 0x55e0af1: 0x4dc8a10, 0x55e0af9: 0x4da7270, 0x55e0c32: 0x5a0b300, 0x55e0dc0: 0x51e06d0}, "pins": {
        0x55e0608: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x55e0615: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x55e0619: ('4c89ef', 'mov    %r13,%rdi'),
        0x55e061c: ('488d8c24200300', 'lea    0x320(%rsp),%rcx'),
        0x55e0624: ('e837eefdfd', 'call   0x35bf460'),
        0x55e0629: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x55e0fab: ('48698424b80000', 'imul   $0xb0,0xb8(%rsp),%rax'),
        0x55e0fb7: ('48038424a80000', 'add    0xa8(%rsp),%rax'),
    }},
    'site_0x55e0923': {"range": (0x55e0902, 0x55e0fe5), "calls": {0x55e094b: 0x4556410, 0x55e0a09: 0x522eeb0, 0x55e0a27: 0x5853850, 0x55e0af1: 0x4dc8a10, 0x55e0af9: 0x4da7270, 0x55e0c32: 0x5a0b300, 0x55e0dc0: 0x51e06d0}, "pins": {
        0x55e0902: ('498b7708', 'mov    0x8(%r15),%rsi'),
        0x55e090f: ('498b5710', 'mov    0x10(%r15),%rdx'),
        0x55e0913: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x55e091b: ('488d8c24200300', 'lea    0x320(%rsp),%rcx'),
        0x55e0923: ('e838ebfdfd', 'call   0x35bf460'),
        0x55e0928: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x55e0fd1: ('4c69ac24b80000', 'imul   $0xb0,0xb8(%rsp),%r13'),
        0x55e0fdd: ('4c03ac24a80000', 'add    0xa8(%rsp),%r13'),
    }},
    'site_0x55e174f': {"range": (0x55e172e, 0x55e1762), "calls": {}, "pins": {
        0x55e172e: ('488b7708', 'mov    0x8(%rdi),%rsi'),
        0x55e173b: ('488b5710', 'mov    0x10(%rdi),%rdx'),
        0x55e173f: ('488dbc24780400', 'lea    0x478(%rsp),%rdi'),
        0x55e1747: ('488d8c24a00000', 'lea    0xa0(%rsp),%rcx'),
        0x55e174f: ('e80cddfdfd', 'call   0x35bf460'),
        0x55e1754: ('80bc2478040000', 'cmpb   $0x0,0x478(%rsp)'),
    }},
    'site_0x55e1a5e': {"range": (0x55e1a3b, 0x55e1a85), "calls": {}, "pins": {
        0x55e1a3b: ('498b742408', 'mov    0x8(%r12),%rsi'),
        0x55e1a49: ('498b542410', 'mov    0x10(%r12),%rdx'),
        0x55e1a4e: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x55e1a56: ('488d8c24900200', 'lea    0x290(%rsp),%rcx'),
        0x55e1a5e: ('e8fdd9fdfd', 'call   0x35bf460'),
        0x55e1a63: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x55e1a71: ('4c69b424b80000', 'imul   $0xb0,0xb8(%rsp),%r14'),
        0x55e1a7d: ('4c03b424a80000', 'add    0xa8(%rsp),%r14'),
    }},
    'site_0x55e22d4': {"range": (0x55e22b1, 0x55e22fb), "calls": {}, "pins": {
        0x55e22b1: ('498b742408', 'mov    0x8(%r12),%rsi'),
        0x55e22bf: ('498b542410', 'mov    0x10(%r12),%rdx'),
        0x55e22c4: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x55e22cc: ('488d8c24900200', 'lea    0x290(%rsp),%rcx'),
        0x55e22d4: ('e887d1fdfd', 'call   0x35bf460'),
        0x55e22d9: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x55e22e7: ('4869ac24b80000', 'imul   $0xb0,0xb8(%rsp),%rbp'),
        0x55e22f3: ('4803ac24a80000', 'add    0xa8(%rsp),%rbp'),
    }},
    'site_0x55e29ac': {"range": (0x55e2990, 0x55e2a50), "calls": {0x55e29e3: 0x4556410}, "pins": {
        0x55e2990: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x55e299d: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x55e29a1: ('4c89e7', 'mov    %r12,%rdi'),
        0x55e29a4: ('488d8c24900200', 'lea    0x290(%rsp),%rcx'),
        0x55e29ac: ('e8afcafdfd', 'call   0x35bf460'),
        0x55e29b1: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x55e2a37: ('48698424b80000', 'imul   $0xb0,0xb8(%rsp),%rax'),
        0x55e2a43: ('48038424a80000', 'add    0xa8(%rsp),%rax'),
    }},
    'site_0x55e2bed': {"range": (0x55e2bcc, 0x55e2d56), "calls": {0x55e2c21: 0x4556410, 0x55e2ce0: 0x522eeb0, 0x55e2d12: 0x5853850}, "pins": {
        0x55e2bcc: ('488b7308', 'mov    0x8(%rbx),%rsi'),
        0x55e2bd9: ('488b5310', 'mov    0x10(%rbx),%rdx'),
        0x55e2bdd: ('488dbc24a00000', 'lea    0xa0(%rsp),%rdi'),
        0x55e2be5: ('488d8c24900200', 'lea    0x290(%rsp),%rcx'),
        0x55e2bed: ('e86ec8fdfd', 'call   0x35bf460'),
        0x55e2bf2: ('83bc24a0000000', 'cmpl   $0x1,0xa0(%rsp)'),
        0x55e2d42: ('4c69a424b80000', 'imul   $0xb0,0xb8(%rsp),%r12'),
        0x55e2d4e: ('4c03a424a80000', 'add    0xa8(%rsp),%r12'),
    }},
    'site_0x55e4e0d': {"range": (0x55e4de1, 0x55e4e20), "calls": {}, "pins": {
        0x55e4de1: ('488bb3d0060000', 'mov    0x6d0(%rbx),%rsi'),
        0x55e4df6: ('488b93d8060000', 'mov    0x6d8(%rbx),%rdx'),
        0x55e4dfd: ('488dbc24800000', 'lea    0x80(%rsp),%rdi'),
        0x55e4e05: ('488d8c24c00100', 'lea    0x1c0(%rsp),%rcx'),
        0x55e4e0d: ('e84ea6fdfd', 'call   0x35bf460'),
        0x55e4e12: ('80bc2480000000', 'cmpb   $0x0,0x80(%rsp)'),
    }},
    'site_0x560a716': {"range": (0x560a6ef, 0x560a729), "calls": {}, "pins": {
        0x560a6ef: ('498bb6d0060000', 'mov    0x6d0(%r14),%rsi'),
        0x560a6ff: ('498b96d8060000', 'mov    0x6d8(%r14),%rdx'),
        0x560a706: ('488dbc24f00000', 'lea    0xf0(%rsp),%rdi'),
        0x560a70e: ('488d8c24800000', 'lea    0x80(%rsp),%rcx'),
        0x560a716: ('e8454dfbfd', 'call   0x35bf460'),
        0x560a71b: ('80bc24f0000000', 'cmpb   $0x0,0xf0(%rsp)'),
    }},
    'site_0x560af66': {"range": (0x560af3f, 0x560af79), "calls": {}, "pins": {
        0x560af3f: ('498bb6d0060000', 'mov    0x6d0(%r14),%rsi'),
        0x560af4f: ('498b96d8060000', 'mov    0x6d8(%r14),%rdx'),
        0x560af56: ('488dbc24f00000', 'lea    0xf0(%rsp),%rdi'),
        0x560af5e: ('488d8c24800000', 'lea    0x80(%rsp),%rcx'),
        0x560af66: ('e8f544fbfd', 'call   0x35bf460'),
        0x560af6b: ('80bc24f0000000', 'cmpb   $0x0,0xf0(%rsp)'),
    }},
    'site_0x5a09171': {"range": (0x5a09150, 0x5a0918f), "calls": {}, "pins": {
        0x5a09150: ('498bb6d0060000', 'mov    0x6d0(%r14),%rsi'),
        0x5a09160: ('498b96d8060000', 'mov    0x6d8(%r14),%rdx'),
        0x5a09167: ('488d7c2448', 'lea    0x48(%rsp),%rdi'),
        0x5a0916c: ('488d4c2410', 'lea    0x10(%rsp),%rcx'),
        0x5a09171: ('e8ea62bbfd', 'call   0x35bf460'),
        0x5a09176: ('837c244801', 'cmpl   $0x1,0x48(%rsp)'),
        0x5a09181: ('4869442460b000', 'imul   $0xb0,0x60(%rsp),%rax'),
        0x5a0918a: ('4803442450', 'add    0x50(%rsp),%rax'),
    }},
    'site_0x5a09304': {"range": (0x5a092e3, 0x5a09322), "calls": {}, "pins": {
        0x5a092e3: ('488bb0d0060000', 'mov    0x6d0(%rax),%rsi'),
        0x5a092f3: ('488b90d8060000', 'mov    0x6d8(%rax),%rdx'),
        0x5a092fa: ('488d7c2448', 'lea    0x48(%rsp),%rdi'),
        0x5a092ff: ('488d4c2410', 'lea    0x10(%rsp),%rcx'),
        0x5a09304: ('e85761bbfd', 'call   0x35bf460'),
        0x5a09309: ('837c244801', 'cmpl   $0x1,0x48(%rsp)'),
        0x5a09314: ('4869442460b000', 'imul   $0xb0,0x60(%rsp),%rax'),
        0x5a0931d: ('4803442450', 'add    0x50(%rsp),%rax'),
    }},
    'site_0x5a3134b': {"range": (0x5a31327, 0x5a31372), "calls": {}, "pins": {
        0x5a31327: ('488bb5d0060000', 'mov    0x6d0(%rbp),%rsi'),
        0x5a31337: ('488b95d8060000', 'mov    0x6d8(%rbp),%rdx'),
        0x5a3133e: ('488dbc24700200', 'lea    0x270(%rsp),%rdi'),
        0x5a31346: ('488d4c2420', 'lea    0x20(%rsp),%rcx'),
        0x5a3134b: ('e810e1b8fd', 'call   0x35bf460'),
        0x5a31350: ('83bc2470020000', 'cmpl   $0x1,0x270(%rsp)'),
        0x5a3135e: ('48698424880200', 'imul   $0xb0,0x288(%rsp),%rax'),
        0x5a3136a: ('48038424780200', 'add    0x278(%rsp),%rax'),
    }},
    'caller_0x296a390_height_0x296c182': {"range": (0x296c149, 0x296c192), "calls": {}, "pins": {
        0x296c182: ('488b8424400100', 'mov    0x140(%rsp),%rax'),
    }},
    'caller_0x2a40cc0_height_0x2a40ec4': {"range": (0x2a40e8c, 0x2a40ed9), "calls": {}, "pins": {
        0x2a40ec4: ('f20f2a442430', 'cvtsi2sdl 0x30(%rsp),%xmm0'),
    }},
    'caller_0x2a40cc0_height_0x2a40f69': {"range": (0x2a40f64, 0x2a40f77), "calls": {}, "pins": {
        0x2a40f64: ('e8a7322403', 'call   0x5c84210'),
        0x2a40f69: ('8b4c2430', 'mov    0x30(%rsp),%ecx'),
    }},
    'caller_0x2a40cc0_height_0x2a41255': {"range": (0x2a41236, 0x2a4126a), "calls": {}, "pins": {
        0x2a41236: ('e8d52f2403', 'call   0x5c84210'),
        0x2a41255: ('f20f2a442430', 'cvtsi2sdl 0x30(%rsp),%xmm0'),
    }},
    'caller_0x2a84e60_height_0x2a8549b': {"range": (0x2a85486, 0x2a854a8), "calls": {}, "pins": {
        0x2a85486: ('e8c5cf82ff', 'call   0x22b2450'),
        0x2a8549b: ('4c8ba424e00000', 'mov    0xe0(%rsp),%r12'),
    }},
    'caller_0x2a84e60_height_0x2a85995': {"range": (0x2a85980, 0x2a859a9), "calls": {}, "pins": {
        0x2a85980: ('e88bbf9bff', 'call   0x2441910'),
        0x2a85995: ('488b8c24e00000', 'mov    0xe0(%rsp),%rcx'),
    }},
    'caller_0x2a84e60_height_0x2a86fd6': {"range": (0x2a86fc0, 0x2a86fe7), "calls": {}, "pins": {
        0x2a86fc0: ('e84ba99bff', 'call   0x2441910'),
        0x2a86fd6: ('488b8c24e00000', 'mov    0xe0(%rsp),%rcx'),
    }},
    'caller_0x2a8be00_height_0x2a8bea7': {"range": (0x2a8be8a, 0x2a8beb5), "calls": {}, "pins": {
        0x2a8bea7: ('488b442420', 'mov    0x20(%rsp),%rax'),
    }},
    'caller_0x2a8be00_height_0x2a8c977': {"range": (0x2a8c955, 0x2a8c983), "calls": {}, "pins": {
        0x2a8c977: ('488b7c2420', 'mov    0x20(%rsp),%rdi'),
    }},
    'caller_0x2a8be00_height_0x2a8ca67': {"range": (0x2a8ca44, 0x2a8ca72), "calls": {}, "pins": {
        0x2a8ca67: ('488b7c2420', 'mov    0x20(%rsp),%rdi'),
    }},
    'caller_0x2a8be00_height_0x2a8ca8b': {"range": (0x2a8ca72, 0x2a8ca96), "calls": {}, "pins": {
        0x2a8ca8b: ('488b7c2420', 'mov    0x20(%rsp),%rdi'),
    }},
    'caller_0x2bb2ec0_height_0x2bb3269': {"range": (0x2bb3245, 0x2bb3278), "calls": {}, "pins": {
        0x2bb3269: ('488b4c2450', 'mov    0x50(%rsp),%rcx'),
    }},
    'caller_0x2bdf8f0_height_0x2be305a': {"range": (0x2be3026, 0x2be3073), "calls": {}, "pins": {
        0x2be305a: ('488b9424000400', 'mov    0x400(%rsp),%rdx'),
    }},
    'caller_0x2bdf8f0_height_0x2be373a': {"range": (0x2be3725, 0x2be3754), "calls": {}, "pins": {
        0x2be3725: ('e8d6170b00', 'call   0x2c94f00'),
        0x2be373a: ('488b8c24000400', 'mov    0x400(%rsp),%rcx'),
    }},
    'caller_0x2bdf8f0_height_0x2be4ac4': {"range": (0x2be4abf, 0x2be4add), "calls": {}, "pins": {
        0x2be4abf: ('e8ecb61400', 'call   0x2d301b0'),
        0x2be4ac4: ('488b8424000400', 'mov    0x400(%rsp),%rax'),
    }},
    'caller_0x2bdf8f0_height_0x2be59a2': {"range": (0x2be5990, 0x2be59b6), "calls": {}, "pins": {
        0x2be59a2: ('8b842400040000', 'mov    0x400(%rsp),%eax'),
    }},
    'caller_0x2bdf8f0_height_0x2be850a': {"range": (0x2be84da, 0x2be851e), "calls": {}, "pins": {
        0x2be850a: ('8b942400040000', 'mov    0x400(%rsp),%edx'),
    }},
    'caller_0x2bdf8f0_height_0x2be85d7': {"range": (0x2be85a9, 0x2be85ee), "calls": {}, "pins": {
        0x2be85d7: ('8b842400040000', 'mov    0x400(%rsp),%eax'),
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
    'caller_0x547d430_height_0x547d7d9': {"range": (0x547d7b5, 0x547d7e8), "calls": {}, "pins": {
        0x547d7d9: ('488b4c2450', 'mov    0x50(%rsp),%rcx'),
    }},
    'caller_0x547d910_height_0x547dcb9': {"range": (0x547dc95, 0x547dcc8), "calls": {}, "pins": {
        0x547dcb9: ('488b4c2450', 'mov    0x50(%rsp),%rcx'),
    }},
    'caller_0x54a9c70_height_0x54aa6c7': {"range": (0x54aa6a6, 0x54aa6dc), "calls": {}, "pins": {
        0x54aa6a6: ('e8659b7d00', 'call   0x5c84210'),
        0x54aa6c7: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54a9c70_height_0x54aabf8': {"range": (0x54aabf3, 0x54aac11), "calls": {}, "pins": {
        0x54aabf3: ('e848231a00', 'call   0x564cf40'),
        0x54aabf8: ('488b442470', 'mov    0x70(%rsp),%rax'),
    }},
    'caller_0x54a9c70_height_0x54ab126': {"range": (0x54ab105, 0x54ab13b), "calls": {}, "pins": {
        0x54ab105: ('e806917d00', 'call   0x5c84210'),
        0x54ab126: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54a9c70_height_0x54ab969': {"range": (0x54ab948, 0x54ab97e), "calls": {}, "pins": {
        0x54ab948: ('e8c3887d00', 'call   0x5c84210'),
        0x54ab969: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54a9c70_height_0x54abef9': {"range": (0x54abed8, 0x54abf0e), "calls": {}, "pins": {
        0x54abed8: ('e833837d00', 'call   0x5c84210'),
        0x54abef9: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54a9c70_height_0x54ad013': {"range": (0x54acffb, 0x54ad024), "calls": {}, "pins": {
        0x54acffb: ('e8d036d3ff', 'call   0x51e06d0'),
        0x54ad013: ('488b4c2470', 'mov    0x70(%rsp),%rcx'),
    }},
    'caller_0x54a9c70_height_0x54ad59c': {"range": (0x54ad56b, 0x54ad5b5), "calls": {}, "pins": {
        0x54ad59c: ('488b9424800400', 'mov    0x480(%rsp),%rdx'),
    }},
    'caller_0x54a9c70_height_0x54adc82': {"range": (0x54adc6d, 0x54adc9c), "calls": {}, "pins": {
        0x54adc6d: ('e88e231800', 'call   0x5630000'),
        0x54adc82: ('488b8c24800400', 'mov    0x480(%rsp),%rcx'),
    }},
    'caller_0x54a9c70_height_0x54af291': {"range": (0x54af28c, 0x54af2aa), "calls": {}, "pins": {
        0x54af28c: ('e8bf385600', 'call   0x5a12b50'),
        0x54af291: ('488b8424800400', 'mov    0x480(%rsp),%rax'),
    }},
    'caller_0x54a9c70_height_0x54afe20': {"range": (0x54afe03, 0x54afe2d), "calls": {}, "pins": {
        0x54afe03: ('e85873d3ff', 'call   0x51e7160'),
        0x54afe20: ('488b4c2470', 'mov    0x70(%rsp),%rcx'),
    }},
    'caller_0x54a9c70_height_0x54b0158': {"range": (0x54b0132, 0x54b0169), "calls": {}, "pins": {
        0x54b0158: ('488b8c24800400', 'mov    0x480(%rsp),%rcx'),
    }},
    'caller_0x54a9c70_height_0x54b1284': {"range": (0x54b1263, 0x54b1299), "calls": {}, "pins": {
        0x54b1263: ('e8a82f7d00', 'call   0x5c84210'),
        0x54b1284: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54a9c70_height_0x54b1e24': {"range": (0x54b1e0b, 0x54b1e32), "calls": {}, "pins": {
        0x54b1e0b: ('e8b05ad3ff', 'call   0x51e78c0'),
        0x54b1e24: ('488b442470', 'mov    0x70(%rsp),%rax'),
    }},
    'caller_0x54a9c70_height_0x54b2030': {"range": (0x54b2005, 0x54b203e), "calls": {}, "pins": {
        0x54b2005: ('e8b658d3ff', 'call   0x51e78c0'),
        0x54b2030: ('486b4c247068', 'imul   $0x68,0x70(%rsp),%rcx'),
    }},
    'caller_0x54a9c70_height_0x54b20e3': {"range": (0x54b20c2, 0x54b20f8), "calls": {}, "pins": {
        0x54b20c2: ('e849217d00', 'call   0x5c84210'),
        0x54b20e3: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54a9c70_height_0x54b2775': {"range": (0x54b2759, 0x54b2783), "calls": {}, "pins": {
        0x54b2775: ('488b442470', 'mov    0x70(%rsp),%rax'),
    }},
    'caller_0x54a9c70_height_0x54b2d17': {"range": (0x54b2d08, 0x54b2d22), "calls": {}, "pins": {
        0x54b2d08: ('e8f3376d00', 'call   0x5b86500'),
        0x54b2d17: ('488b442470', 'mov    0x70(%rsp),%rax'),
    }},
    'caller_0x54a9c70_height_0x54b34ae': {"range": (0x54b348d, 0x54b34c3), "calls": {}, "pins": {
        0x54b348d: ('e87e0d7d00', 'call   0x5c84210'),
        0x54b34ae: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54a9c70_height_0x54b39f5': {"range": (0x54b39c7, 0x54b3a09), "calls": {}, "pins": {
        0x54b39f5: ('8b942480040000', 'mov    0x480(%rsp),%edx'),
    }},
    'caller_0x54a9c70_height_0x54b3ac4': {"range": (0x54b3a96, 0x54b3adb), "calls": {}, "pins": {
        0x54b3ac4: ('8b842480040000', 'mov    0x480(%rsp),%eax'),
    }},
    'caller_0x54a9c70_height_0x54b52ce': {"range": (0x54b52a9, 0x54b52da), "calls": {}, "pins": {
        0x54b52ce: ('488b7c2470', 'mov    0x70(%rsp),%rdi'),
    }},
    'caller_0x54a9c70_height_0x54b531f': {"range": (0x54b5309, 0x54b5331), "calls": {}, "pins": {
        0x54b5309: ('e85266d2ff', 'call   0x51db960'),
        0x54b531f: ('488b8c24800400', 'mov    0x480(%rsp),%rcx'),
    }},
    'caller_0x54a9c70_height_0x54b5394': {"range": (0x54b536b, 0x54b539f), "calls": {}, "pins": {
        0x54b5394: ('488b7c2470', 'mov    0x70(%rsp),%rdi'),
    }},
    'caller_0x54a9c70_height_0x54b53cb': {"range": (0x54b539f, 0x54b53d6), "calls": {}, "pins": {
        0x54b53cb: ('488b7c2470', 'mov    0x70(%rsp),%rdi'),
    }},
    'caller_0x54b66b0_height_0x54b70e7': {"range": (0x54b70c6, 0x54b70fc), "calls": {}, "pins": {
        0x54b70c6: ('e845d17c00', 'call   0x5c84210'),
        0x54b70e7: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54b66b0_height_0x54b7618': {"range": (0x54b7613, 0x54b7631), "calls": {}, "pins": {
        0x54b7613: ('e828591900', 'call   0x564cf40'),
        0x54b7618: ('488b442470', 'mov    0x70(%rsp),%rax'),
    }},
    'caller_0x54b66b0_height_0x54b7b46': {"range": (0x54b7b25, 0x54b7b5b), "calls": {}, "pins": {
        0x54b7b25: ('e8e6c67c00', 'call   0x5c84210'),
        0x54b7b46: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54b66b0_height_0x54b8316': {"range": (0x54b82f5, 0x54b832b), "calls": {}, "pins": {
        0x54b82f5: ('e816bf7c00', 'call   0x5c84210'),
        0x54b8316: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54b66b0_height_0x54b8870': {"range": (0x54b884f, 0x54b8885), "calls": {}, "pins": {
        0x54b884f: ('e8bcb97c00', 'call   0x5c84210'),
        0x54b8870: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54b66b0_height_0x54b9903': {"range": (0x54b98eb, 0x54b9914), "calls": {}, "pins": {
        0x54b98eb: ('e8e06dd2ff', 'call   0x51e06d0'),
        0x54b9903: ('488b4c2470', 'mov    0x70(%rsp),%rcx'),
    }},
    'caller_0x54b66b0_height_0x54b9e8d': {"range": (0x54b9e61, 0x54b9ea6), "calls": {}, "pins": {
        0x54b9e8d: ('488b9424d00300', 'mov    0x3d0(%rsp),%rdx'),
    }},
    'caller_0x54b66b0_height_0x54ba518': {"range": (0x54ba503, 0x54ba532), "calls": {}, "pins": {
        0x54ba503: ('e8f85a1700', 'call   0x5630000'),
        0x54ba518: ('488b8c24d00300', 'mov    0x3d0(%rsp),%rcx'),
    }},
    'caller_0x54b66b0_height_0x54bbb01': {"range": (0x54bbafc, 0x54bbb1a), "calls": {}, "pins": {
        0x54bbafc: ('e8cf695500', 'call   0x5a124d0'),
        0x54bbb01: ('488b8424d00300', 'mov    0x3d0(%rsp),%rax'),
    }},
    'caller_0x54b66b0_height_0x54bc500': {"range": (0x54bc4e3, 0x54bc50d), "calls": {}, "pins": {
        0x54bc4e3: ('e878acd2ff', 'call   0x51e7160'),
        0x54bc500: ('488b4c2470', 'mov    0x70(%rsp),%rcx'),
    }},
    'caller_0x54b66b0_height_0x54bc917': {"range": (0x54bc905, 0x54bc92b), "calls": {}, "pins": {
        0x54bc917: ('8b8424d0030000', 'mov    0x3d0(%rsp),%eax'),
    }},
    'caller_0x54b66b0_height_0x54bd8c4': {"range": (0x54bd8a3, 0x54bd8d9), "calls": {}, "pins": {
        0x54bd8a3: ('e868697c00', 'call   0x5c84210'),
        0x54bd8c4: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54b66b0_height_0x54be464': {"range": (0x54be44b, 0x54be472), "calls": {}, "pins": {
        0x54be44b: ('e87094d2ff', 'call   0x51e78c0'),
        0x54be464: ('488b442470', 'mov    0x70(%rsp),%rax'),
    }},
    'caller_0x54b66b0_height_0x54be670': {"range": (0x54be645, 0x54be67e), "calls": {}, "pins": {
        0x54be645: ('e87692d2ff', 'call   0x51e78c0'),
        0x54be670: ('486b4c247068', 'imul   $0x68,0x70(%rsp),%rcx'),
    }},
    'caller_0x54b66b0_height_0x54be726': {"range": (0x54be705, 0x54be73b), "calls": {}, "pins": {
        0x54be705: ('e8065b7c00', 'call   0x5c84210'),
        0x54be726: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54b66b0_height_0x54bed9f': {"range": (0x54bed82, 0x54bedad), "calls": {}, "pins": {
        0x54bed9f: ('488b442470', 'mov    0x70(%rsp),%rax'),
    }},
    'caller_0x54b66b0_height_0x54bf347': {"range": (0x54bf338, 0x54bf352), "calls": {}, "pins": {
        0x54bf338: ('e8c3716c00', 'call   0x5b86500'),
        0x54bf347: ('488b442470', 'mov    0x70(%rsp),%rax'),
    }},
    'caller_0x54b66b0_height_0x54bfac7': {"range": (0x54bfaa6, 0x54bfadc), "calls": {}, "pins": {
        0x54bfaa6: ('e865477c00', 'call   0x5c84210'),
        0x54bfac7: ('f20f2a442470', 'cvtsi2sdl 0x70(%rsp),%xmm0'),
    }},
    'caller_0x54b66b0_height_0x54bffde': {"range": (0x54bffb0, 0x54bfff2), "calls": {}, "pins": {
        0x54bffde: ('8b9424d0030000', 'mov    0x3d0(%rsp),%edx'),
    }},
    'caller_0x54b66b0_height_0x54c00ad': {"range": (0x54c007f, 0x54c00c4), "calls": {}, "pins": {
        0x54c00ad: ('8b8424d0030000', 'mov    0x3d0(%rsp),%eax'),
    }},
    'caller_0x54b66b0_height_0x54c183e': {"range": (0x54c1819, 0x54c184a), "calls": {}, "pins": {
        0x54c183e: ('488b7c2470', 'mov    0x70(%rsp),%rdi'),
    }},
    'caller_0x54b66b0_height_0x54c188f': {"range": (0x54c1879, 0x54c18a1), "calls": {}, "pins": {
        0x54c1879: ('e8e2a0d1ff', 'call   0x51db960'),
        0x54c188f: ('488b8c24d00300', 'mov    0x3d0(%rsp),%rcx'),
    }},
    'caller_0x54b66b0_height_0x54c18ff': {"range": (0x54c18de, 0x54c190a), "calls": {}, "pins": {
        0x54c18ff: ('488b7c2470', 'mov    0x70(%rsp),%rdi'),
    }},
    'caller_0x54b66b0_height_0x54c1933': {"range": (0x54c190a, 0x54c193e), "calls": {}, "pins": {
        0x54c1933: ('488b7c2470', 'mov    0x70(%rsp),%rdi'),
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
    'caller_0x5582180_height_0x55827a0': {"range": (0x558278b, 0x55827ad), "calls": {}, "pins": {
        0x558278b: ('e860765400', 'call   0x5ac9df0'),
        0x55827a0: ('4c8ba424c00000', 'mov    0xc0(%rsp),%r12'),
    }},
    'caller_0x5582180_height_0x5582c55': {"range": (0x5582c40, 0x5582c69), "calls": {}, "pins": {
        0x5582c40: ('e82b15c6ff', 'call   0x51e4170'),
        0x5582c55: ('488b8c24c00000', 'mov    0xc0(%rsp),%rcx'),
    }},
    'caller_0x5582180_height_0x5584082': {"range": (0x5584070, 0x5584093), "calls": {}, "pins": {
        0x5584070: ('e8fb00c6ff', 'call   0x51e4170'),
        0x5584082: ('488b8c24c00000', 'mov    0xc0(%rsp),%rcx'),
    }},
    'caller_0x5582180_height_0x5584398': {"range": (0x5584373, 0x55843a5), "calls": {}, "pins": {
        0x5584373: ('e86821bbff', 'call   0x51364e0'),
        0x5584398: ('488b8c24c00000', 'mov    0xc0(%rsp),%rcx'),
    }},
    'caller_0x5582180_height_0x55843c8': {"range": (0x5584398, 0x55843d2), "calls": {}, "pins": {
        0x55843c8: ('483b8424c00000', 'cmp    0xc0(%rsp),%rax'),
    }},
    'caller_0x5585290_height_0x55858b0': {"range": (0x558589b, 0x55858bd), "calls": {}, "pins": {
        0x558589b: ('e850455400', 'call   0x5ac9df0'),
        0x55858b0: ('4c8ba424c00000', 'mov    0xc0(%rsp),%r12'),
    }},
    'caller_0x5585290_height_0x5585d65': {"range": (0x5585d50, 0x5585d79), "calls": {}, "pins": {
        0x5585d50: ('e81be4c5ff', 'call   0x51e4170'),
        0x5585d65: ('488b8c24c00000', 'mov    0xc0(%rsp),%rcx'),
    }},
    'caller_0x5585290_height_0x5587192': {"range": (0x5587180, 0x55871a3), "calls": {}, "pins": {
        0x5587180: ('e8ebcfc5ff', 'call   0x51e4170'),
        0x5587192: ('488b8c24c00000', 'mov    0xc0(%rsp),%rcx'),
    }},
    'caller_0x5585290_height_0x55874a8': {"range": (0x5587483, 0x55874b5), "calls": {}, "pins": {
        0x5587483: ('e858f0baff', 'call   0x51364e0'),
        0x55874a8: ('488b8c24c00000', 'mov    0xc0(%rsp),%rcx'),
    }},
    'caller_0x5585290_height_0x55874d8': {"range": (0x55874a8, 0x55874e2), "calls": {}, "pins": {
        0x55874d8: ('483b8424c00000', 'cmp    0xc0(%rsp),%rax'),
    }},
    'caller_0x2bb2ec0_record_overwrite_1': {"range": (0x2bb305e, 0x2bb3075), "calls": {}, "pins": {
        0x2bb305e: ('410f100424', 'movups (%r12),%xmm0'),
        0x2bb3063: ('0f29442440', 'movaps %xmm0,0x40(%rsp)'),
        0x2bb3068: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        0x2bb306d: ('4c89ef', 'mov    %r13,%rdi'),
        0x2bb3070: ('e8fb76edff', 'call   0x2a8a770'),
    }},
    'caller_0x2bb2ec0_record_overwrite_2': {"range": (0x2bb309c, 0x2bb30b1), "calls": {}, "pins": {
        0x2bb309c: ('410f100424', 'movups (%r12),%xmm0'),
        0x2bb30a1: ('0f29442440', 'movaps %xmm0,0x40(%rsp)'),
        0x2bb30a6: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        0x2bb30ab: ('ff15e7339303', 'call   *0x39333e7(%rip)        # 0x64e6498'),
    }},
    'caller_0x547d430_record_overwrite_1': {"range": (0x547d5ce, 0x547d5e5), "calls": {}, "pins": {
        0x547d5ce: ('410f100424', 'movups (%r12),%xmm0'),
        0x547d5d3: ('0f29442440', 'movaps %xmm0,0x40(%rsp)'),
        0x547d5d8: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        0x547d5dd: ('4c89ef', 'mov    %r13,%rdi'),
        0x547d5e0: ('e82b151800', 'call   0x55feb10'),
    }},
    'caller_0x547d430_record_overwrite_2': {"range": (0x547d60c, 0x547d621), "calls": {}, "pins": {
        0x547d60c: ('410f100424', 'movups (%r12),%xmm0'),
        0x547d611: ('0f29442440', 'movaps %xmm0,0x40(%rsp)'),
        0x547d616: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        0x547d61b: ('ff15778e0601', 'call   *0x1068e77(%rip)        # 0x64e6498'),
    }},
    'caller_0x547d910_record_overwrite_1': {"range": (0x547daae, 0x547dac5), "calls": {}, "pins": {
        0x547daae: ('410f100424', 'movups (%r12),%xmm0'),
        0x547dab3: ('0f29442440', 'movaps %xmm0,0x40(%rsp)'),
        0x547dab8: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        0x547dabd: ('4c89ef', 'mov    %r13,%rdi'),
        0x547dac0: ('e8cb0f1800', 'call   0x55fea90'),
    }},
    'caller_0x547d910_record_overwrite_2': {"range": (0x547daec, 0x547db01), "calls": {}, "pins": {
        0x547daec: ('410f100424', 'movups (%r12),%xmm0'),
        0x547daf1: ('0f29442440', 'movaps %xmm0,0x40(%rsp)'),
        0x547daf6: ('488d742440', 'lea    0x40(%rsp),%rsi'),
        0x547dafb: ('ff1597890601', 'call   *0x1068997(%rip)        # 0x64e6498'),
    }},
}
SLOT_CENSUS = {
    '0x296a390|0x130': {"flag": [0x296aa14, 0x296b69c, 0x296c14f, 0x296c26b], "node": [0x296c17a, 0x296c285], "height": [0x296aa1c, 0x296b6a5, 0x296c182], "position": [0x296c279]},
    '0x2a40cc0|0x20': {"flag": [0x2a40daa, 0x2a40e3f, 0x2a40f89, 0x2a4123b, 0x2a4136b, 0x2a414f5, 0x2a4156e, 0x2a41686, 0x2a416d6], "node": [0x2a40e52, 0x2a40ebb, 0x2a40f72, 0x2a4124c], "height": [0x2a40e57, 0x2a40ec4, 0x2a40f69, 0x2a41255, 0x2a41371], "position": []},
    '0x2a84990|0xa0': {"flag": [0x2a84a34, 0x2a84a7e, 0x2a84cb9], "node": [], "height": [], "position": []},
    '0x2a84e60|0xd0': {"flag": [0x2a8548b, 0x2a85985, 0x2a85bc9, 0x2a86305, 0x2a86777, 0x2a86865, 0x2a86fc5], "node": [0x2a85493, 0x2a85bb8, 0x2a86785, 0x2a8687b], "height": [0x2a8549b, 0x2a85995, 0x2a86fd6], "position": [0x2a8678d, 0x2a8686f]},
    '0x2a88380|0x90': {"flag": [0x2a8846e], "node": [], "height": [], "position": []},
    '0x2a88af0|0x10': {"flag": [0x2a88b5e, 0x2a88b97], "node": [0x2a88ba1], "height": [], "position": []},
    '0x2a89500|0x80': {"flag": [0x2a89915, 0x2a89a35, 0x2a89d2b], "node": [0x2a8992b, 0x2a89c54, 0x2a89d80], "height": [], "position": [0x2a8991f, 0x2a89c48, 0x2a89d74]},
    '0x2a8be00|0x10': {"flag": [0x2a8be69, 0x2a8bf80, 0x2a8c950, 0x2a8ca52, 0x2a8ca7a], "node": [0x2a8be76, 0x2a8bf94, 0x2a8c972, 0x2a8ca59, 0x2a8ca81], "height": [0x2a8bea7, 0x2a8c977, 0x2a8ca67, 0x2a8ca8b], "position": [0x2a8bf8b, 0x2a8c969]},
    '0x2b92a50|0x18': {"flag": [0x2b92b65], "node": [0x2b92b75], "height": [], "position": [0x2b92b6c]},
    '0x2bb2ec0|0x40': {"flag": [0x2bb2fb7, 0x2bb3028, 0x2bb3191, 0x2bb320c], "node": [0x2bb3196, 0x2bb3217, 0x2bb3264], "height": [0x2bb3269], "position": [0x2bb3273]},
    '0x2bb48c0|0xf0': {"flag": [0x2bb4c98, 0x2bb4da7, 0x2bb4f10], "node": [0x2bb4cb2, 0x2bb4daf, 0x2bb4f18], "height": [], "position": [0x2bb4ca6, 0x2bb4ea1]},
    '0x2bb52a0|0x188': {"flag": [0x2bb561d, 0x2bb5726, 0x2bb57c4, 0x2bb5917, 0x2bb66f0], "node": [0x2bb5637, 0x2bb5740, 0x2bb589a, 0x2bb66f8], "height": [], "position": [0x2bb562b, 0x2bb5734, 0x2bb6302]},
    '0x2bb68e0|0xf8': {"flag": [0x2bb6c6d, 0x2bb6d7d, 0x2bb6ee0], "node": [0x2bb6c87, 0x2bb6d85, 0x2bb6ee8], "height": [], "position": [0x2bb6c7b, 0x2bb6e71]},
    '0x2bb7270|0x140': {"flag": [0x2bb7941, 0x2bb7bbe, 0x2bb8428, 0x2bb86f4, 0x2bb87d0, 0x2bb8860, 0x2bb88e6, 0x2bb8df9, 0x2bb8f91, 0x2bb91ec, 0x2bb951a], "node": [0x2bb795b, 0x2bb7c86, 0x2bb8442, 0x2bb870e, 0x2bb87ea, 0x2bb8878, 0x2bb8e01, 0x2bb8f9f, 0x2bb91fa, 0x2bb9528], "height": [], "position": [0x2bb794f, 0x2bb7c93, 0x2bb8436, 0x2bb8702, 0x2bb87de, 0x2bb8d8c, 0x2bb90c2, 0x2bb954a]},
    '0x2bb98a0|0x80': {"flag": [0x2bb994d, 0x2bb99ea, 0x2bb9a7d, 0x2bb9e24, 0x2bb9f84], "node": [0x2bb996f, 0x2bb9a1b, 0x2bb9a85, 0x2bb9e34, 0x2bb9f95], "height": [], "position": [0x2bb9963, 0x2bb9a95, 0x2bb9fb7]},
    '0x2bba100|0x60': {"flag": [0x2bba19a, 0x2bba405, 0x2bba45d, 0x2bba84c, 0x2bba974], "node": [0x2bba1b3, 0x2bba417, 0x2bba476, 0x2bba857, 0x2bba987], "height": [], "position": [0x2bba1aa, 0x2bba41c, 0x2bba46d, 0x2bbac43]},
    '0x2bbbba0|0xf8': {"flag": [0x2bbc00f], "node": [0x2bbc029], "height": [], "position": [0x2bbc01d]},
    '0x2bbc750|0xe8': {"flag": [0x2bbc980], "node": [0x2bbc99a], "height": [], "position": [0x2bbc98e]},
    '0x2bbd0b0|0xe8': {"flag": [0x2bbd43f], "node": [0x2bbd45f], "height": [], "position": [0x2bbd453]},
    '0x2bdf8f0|0x3f0': {"flag": [0x2bdfea4, 0x2be301e, 0x2be372a, 0x2be4ad4, 0x2be59ad, 0x2be7498, 0x2be8515, 0x2be85e5, 0x2be955f], "node": [0x2bdfeb1, 0x2be3039, 0x2be3204, 0x2be3732, 0x2be9579], "height": [0x2be305a, 0x2be373a, 0x2be4ac4, 0x2be59a2, 0x2be74a1, 0x2be850a, 0x2be85d7], "position": [0x2be3062, 0x2be3742, 0x2be956d]},
    '0x2bf2ed0|0x250': {"flag": [0x2bf2fec, 0x2bf32a6, 0x2bf3431, 0x2bf39f0, 0x2bf3c20, 0x2bf43b0, 0x2bf4407, 0x2bf44ff, 0x2bf4b0b, 0x2bf4d4f, 0x2bf5b14, 0x2bf5ee2, 0x2bf60a6, 0x2bf65b1, 0x2bf662e, 0x2bf6820, 0x2bf69be, 0x2bf6c05, 0x2bf6ec8, 0x2bf6fb8, 0x2bf73f5, 0x2bf83e2], "node": [0x2bf2fa8, 0x2bf3439, 0x2bf4434, 0x2bf5efc, 0x2bf661d, 0x2bf682e, 0x2bf686c, 0x2bf69ad], "height": [0x2bf32af, 0x2bf344e, 0x2bf3a10, 0x2bf3c31, 0x2bf43b9, 0x2bf4508, 0x2bf4b13, 0x2bf4d58, 0x2bf5b25, 0x2bf65ba, 0x2bf6836, 0x2bf6874, 0x2bf6ed1, 0x2bf6fc9, 0x2bf83eb], "position": [0x2bf5ef0]},
    '0x2c61b30|0x30': {"flag": [0x2c61dab, 0x2c61e64], "node": [0x2c61bf5, 0x2c61dc4, 0x2c61ec7], "height": [], "position": [0x2c61dbb, 0x2c61ebe]},
    '0x2c62820|0x468': {"flag": [0x2c628a4], "node": [], "height": [], "position": []},
    '0x2c62820|0xa0': {"flag": [0x2c62ba3, 0x2c62ffd, 0x2c63419, 0x2c6358b, 0x2c63787, 0x2c63af1, 0x2c63d02, 0x2c63d8b, 0x2c63e27, 0x2c643d2, 0x2c64460, 0x2c644d7], "node": [0x2c62bbd, 0x2c6300b, 0x2c63433, 0x2c63599, 0x2c63955, 0x2c63b83, 0x2c63da6, 0x2c63e5e, 0x2c643da, 0x2c64476, 0x2c64536], "height": [], "position": [0x2c62bb1, 0x2c63018, 0x2c63427, 0x2c635b5, 0x2c63b77, 0x2c63e52, 0x2c64361, 0x2c64558]},
    '0x2c65980|0x80': {"flag": [0x2c65a82, 0x2c65b70], "node": [], "height": [0x2c65a8a], "position": []},
    '0x2c74e40|0x70': {"flag": [0x2c74f86, 0x2c7522d, 0x2c75348, 0x2c753f6], "node": [], "height": [0x2c7534d], "position": []},
    '0x2c80670|0x270': {"flag": [0x2c80750, 0x2c809bb], "node": [0x2c8076a], "height": [], "position": [0x2c8075e]},
    '0x2d27720|0x48': {"flag": [0x2d277c6, 0x2d27959], "node": [0x2d277da, 0x2d2796d], "height": [], "position": [0x2d277d1, 0x2d27964]},
    '0x2f0f090|0x30': {"flag": [0x2f0f0f4, 0x2f0f256], "node": [0x2f0f108, 0x2f0f26a], "height": [], "position": [0x2f0f0ff, 0x2f0f261]},
    '0x2f0f3b0|0x88': {"flag": [0x2f0f401], "node": [0x2f0f424], "height": [], "position": [0x2f0f418]},
    '0x421b430|0x8': {"flag": [0x421b462], "node": [], "height": [], "position": []},
    '0x451d1c0|0x8': {"flag": [0x451d285], "node": [0x451d295], "height": [], "position": [0x451d28c]},
    '0x46df170|0x28': {"flag": [0x46df1df, 0x46df29f], "node": [0x46df1ef, 0x46df2af], "height": [], "position": [0x46df1e6, 0x46df2a6]},
    '0x547d430|0x40': {"flag": [0x547d527, 0x547d598, 0x547d701, 0x547d77c], "node": [0x547d706, 0x547d787, 0x547d7d4], "height": [0x547d7d9], "position": [0x547d7e3]},
    '0x547d910|0x40': {"flag": [0x547da07, 0x547da78, 0x547dbe1, 0x547dc5c], "node": [0x547dbe6, 0x547dc67, 0x547dcb4], "height": [0x547dcb9], "position": [0x547dcc3]},
    '0x548ebd0|0x90': {"flag": [0x548ec6c, 0x548ed11, 0x548ed94, 0x548f20b, 0x548f27d], "node": [0x548ec8e, 0x548ed42, 0x548ed9c, 0x548f21e, 0x548f28e], "height": [], "position": [0x548ec82, 0x548edac, 0x548f2b8]},
    '0x548f430|0x60': {"flag": [0x548f4ca, 0x548f735, 0x548f78d, 0x548fb7c, 0x548fca4], "node": [0x548f4e3, 0x548f747, 0x548f7a6, 0x548fb87, 0x548fcb7], "height": [], "position": [0x548f4da, 0x548f74c, 0x548f79d, 0x548ff73]},
    '0x5490660|0x110': {"flag": [0x5490a7d, 0x5490b8d, 0x5490cf0], "node": [0x5490a97, 0x5490b95, 0x5490cf8], "height": [], "position": [0x5490a8b, 0x5490c81]},
    '0x5491190|0xc0': {"flag": [0x5491541, 0x5491648, 0x5491763, 0x54918ba, 0x5491e3a, 0x549235b], "node": [0x549155b, 0x5491662, 0x549184a, 0x5491e42], "height": [], "position": [0x549154f, 0x5491656, 0x5491dc4]},
    '0x5492440|0x120': {"flag": [0x54928d6, 0x5492a07, 0x5492b0e], "node": [0x5492959, 0x5492a0f, 0x5492b16], "height": [], "position": [0x549294d, 0x5492aab]},
    '0x5493080|0xf8': {"flag": [0x54934ef], "node": [0x5493509], "height": [], "position": [0x54934fd]},
    '0x5493c30|0xe8': {"flag": [0x5493fbf], "node": [0x5493fdf], "height": [], "position": [0x5493fd3]},
    '0x5494720|0xe8': {"flag": [0x5494950], "node": [0x549496a], "height": [], "position": [0x549495e]},
    '0x54a9c70|0x470': {"flag": [0x54ad56b, 0x54adc72, 0x54af2a1, 0x54b0138, 0x54b1ec8, 0x54b3a00, 0x54b3ad2, 0x54b4b6c, 0x54b530e, 0x54b5443, 0x54b54f7], "node": [0x54ad586, 0x54ad769, 0x54adc7a, 0x54b0148, 0x54b4b86], "height": [0x54ad59c, 0x54adc82, 0x54af291, 0x54b0158, 0x54b1ed1, 0x54b39f5, 0x54b3ac4, 0x54b531f], "position": [0x54ad5a4, 0x54adc8a, 0x54b4b7a]},
    '0x54a9c70|0x60': {"flag": [0x54aa129, 0x54aa6ab, 0x54ab10a, 0x54ab94d, 0x54abedd, 0x54ad000, 0x54ad300, 0x54ae174, 0x54ae2de, 0x54ae8f3, 0x54afe08, 0x54b0048, 0x54b0e4a, 0x54b105d, 0x54b1268, 0x54b1922, 0x54b1ba9, 0x54b1e10, 0x54b200a, 0x54b204e, 0x54b20c7, 0x54b261b, 0x54b272a, 0x54b282f, 0x54b2d0d, 0x54b328d, 0x54b3492, 0x54b3a35, 0x54b3d5a, 0x54b52a4, 0x54b537b, 0x54b53aa, 0x54b5e3a], "node": [0x54aa6be, 0x54ab11d, 0x54ab960, 0x54abef0, 0x54ac7c3, 0x54ad305, 0x54ae137, 0x54ae2a1, 0x54ae8fd, 0x54afd91, 0x54b0e0d, 0x54b127b, 0x54b18e1, 0x54b20da, 0x54b2620, 0x54b272f, 0x54b2843, 0x54b2d12, 0x54b32ba, 0x54b34a5, 0x54b3c48, 0x54b3d73, 0x54b52c9, 0x54b5386, 0x54b53b5, 0x54b5e48], "height": [0x54aa12f, 0x54aa6c7, 0x54aabf8, 0x54ab126, 0x54ab969, 0x54abef9, 0x54ad013, 0x54afe20, 0x54b1063, 0x54b1284, 0x54b1e24, 0x54b2030, 0x54b20e3, 0x54b2775, 0x54b2d17, 0x54b34ae, 0x54b52ce, 0x54b5394, 0x54b53cb], "position": [0x54ae8d9, 0x54afd9b, 0x54b283a, 0x54b32bf, 0x54b52c0]},
    '0x54b66b0|0x3c0': {"flag": [0x54b6c64, 0x54b9e4f, 0x54ba508, 0x54bbb11, 0x54bc922, 0x54be508, 0x54bffe9, 0x54c00bb, 0x54c10df, 0x54c187e, 0x54c1961, 0x54c1a09], "node": [0x54b6c71, 0x54b9e6a, 0x54ba05e, 0x54ba510, 0x54c10f9], "height": [0x54b9e8d, 0x54ba518, 0x54bbb01, 0x54bc917, 0x54be511, 0x54bffde, 0x54c00ad, 0x54c188f], "position": [0x54b9e95, 0x54ba520, 0x54c10ed]},
    '0x54b66b0|0x60': {"flag": [0x54b6b69, 0x54b70cb, 0x54b7b2a, 0x54b82fa, 0x54b8854, 0x54b98f0, 0x54b9bf7, 0x54baa26, 0x54bab9a, 0x54bb17f, 0x54bc4e8, 0x54bc728, 0x54bd47d, 0x54bd69f, 0x54bd8a8, 0x54bdf63, 0x54be1e7, 0x54be450, 0x54be64a, 0x54be68e, 0x54be70a, 0x54bec2d, 0x54bed53, 0x54bee59, 0x54bf33d, 0x54bf8ae, 0x54bfaab, 0x54c001e, 0x54c034a, 0x54c1814, 0x54c18ee, 0x54c1912, 0x54c22a5], "node": [0x54b70de, 0x54b7b3d, 0x54b830d, 0x54b8867, 0x54b8f3b, 0x54b9bfc, 0x54ba9e9, 0x54bab5d, 0x54bb189, 0x54bc471, 0x54bd440, 0x54bd8bb, 0x54bdf22, 0x54be71d, 0x54bec40, 0x54bed58, 0x54bee6d, 0x54bf342, 0x54bf8d3, 0x54bfabe, 0x54c0231, 0x54c0363, 0x54c1839, 0x54c18f5, 0x54c191d, 0x54c22b3], "height": [0x54b6b6f, 0x54b70e7, 0x54b7618, 0x54b7b46, 0x54b8316, 0x54b8870, 0x54b9903, 0x54bc500, 0x54bd6a5, 0x54bd8c4, 0x54be464, 0x54be670, 0x54be726, 0x54bed9f, 0x54bf347, 0x54bfac7, 0x54c183e, 0x54c18ff, 0x54c1933], "position": [0x54bb165, 0x54bc47b, 0x54bee64, 0x54bf8d8, 0x54c1830]},
    '0x54cfa90|0xb0': {"flag": [0x54cfbfb, 0x54cfeb4, 0x54d0047, 0x54d0605, 0x54d0840, 0x54d1000, 0x54d105a, 0x54d117f, 0x54d1707, 0x54d187d, 0x54d20ed, 0x54d2c3e, 0x54d2ee5, 0x54d30cf, 0x54d3414, 0x54d3491, 0x54d3650, 0x54d37ee, 0x54d3a45, 0x54d3d12, 0x54d3dfe, 0x54d40e5, 0x54d50d3], "node": [0x54cfbb7, 0x54d004f, 0x54d1087, 0x54d2eff, 0x54d3480, 0x54d365e, 0x54d3693, 0x54d37dd], "height": [0x54cfebd, 0x54d0064, 0x54d0625, 0x54d0851, 0x54d1009, 0x54d1188, 0x54d1885, 0x54d20f6, 0x54d2c4f, 0x54d341d, 0x54d3666, 0x54d369b, 0x54d3d1b, 0x54d3e0f, 0x54d50dc], "position": [0x54d2ef3]},
    '0x54d57b0|0xa0': {"flag": [0x54d5917, 0x54d5bdf, 0x54d5d72, 0x54d6320, 0x54d6560, 0x54d6ce0, 0x54d6d3a, 0x54d6e5f, 0x54d73e7, 0x54d755d, 0x54d7db8, 0x54d88e2, 0x54d8b85, 0x54d8d86, 0x54d90d7, 0x54d9154, 0x54d9320, 0x54d94c1, 0x54d9705, 0x54d99ce, 0x54d9abe, 0x54d9da5, 0x54dad88], "node": [0x54d58d3, 0x54d5d7a, 0x54d6d67, 0x54d8b9f, 0x54d9143, 0x54d932e, 0x54d9363, 0x54d94b0], "height": [0x54d5be8, 0x54d5d8f, 0x54d6340, 0x54d6571, 0x54d6ce9, 0x54d6e68, 0x54d7565, 0x54d7dc1, 0x54d88f3, 0x54d90e0, 0x54d9336, 0x54d936b, 0x54d99d7, 0x54d9acf, 0x54dad91], "position": [0x54d8b93]},
    '0x55817e0|0xa0': {"flag": [0x5581884, 0x55818ce, 0x5581b09], "node": [], "height": [], "position": []},
    '0x5581cb0|0xa0': {"flag": [0x5581d54, 0x5581d9e, 0x5581fd9], "node": [], "height": [], "position": []},
    '0x5582180|0xb0': {"flag": [0x5582790, 0x5582c45, 0x5582e89, 0x558340e, 0x5583854, 0x5583941, 0x5584075, 0x55843f6], "node": [0x5582798, 0x5582e78, 0x5583862, 0x5583957, 0x5584390, 0x55843c0], "height": [0x55827a0, 0x5582c55, 0x5584082, 0x5584398, 0x55843c8], "position": [0x558386a, 0x558394b]},
    '0x5585290|0xb0': {"flag": [0x55858a0, 0x5585d55, 0x5585f99, 0x558651e, 0x5586964, 0x5586a51, 0x5587185, 0x5587506], "node": [0x55858a8, 0x5585f88, 0x5586972, 0x5586a67, 0x55874a0, 0x55874d0], "height": [0x55858b0, 0x5585d65, 0x5587192, 0x55874a8, 0x55874d8], "position": [0x558697a, 0x5586a5b]},
    '0x55883a0|0x90': {"flag": [0x558848e], "node": [], "height": [], "position": []},
    '0x5588670|0x90': {"flag": [0x558875e], "node": [], "height": [], "position": []},
    '0x5588d90|0x10': {"flag": [0x5588dfe, 0x5588e37], "node": [0x5588e41], "height": [], "position": []},
    '0x5588f30|0x10': {"flag": [0x5588f9e, 0x5588fd7], "node": [0x5588fe1], "height": [], "position": []},
    '0x55a07e0|0x80': {"flag": [0x55a0bf5, 0x55a0d15, 0x55a100b], "node": [0x55a0c0b, 0x55a0f34, 0x55a1060], "height": [], "position": [0x55a0bff, 0x55a0f28, 0x55a1054]},
    '0x55a12e0|0x80': {"flag": [0x55a16f5, 0x55a1815, 0x55a1b0b], "node": [0x55a170b, 0x55a1a34, 0x55a1b60], "height": [], "position": [0x55a16ff, 0x55a1a28, 0x55a1b54]},
    '0x55defd0|0xa0': {"flag": [0x55df5e8, 0x55dfb4d, 0x55dfdec, 0x55dff52, 0x55e01e1, 0x55e0629, 0x55e0928, 0x55e09a5, 0x55e0a2c, 0x55e1043, 0x55e10be, 0x55e1234, 0x55e154b], "node": [0x55df602, 0x55dfb5b, 0x55dfe06, 0x55dff60, 0x55e03a3, 0x55e09c0, 0x55e0fb7, 0x55e0fdd, 0x55e105a, 0x55e111d, 0x55e123c], "height": [], "position": [0x55df5f6, 0x55dfb68, 0x55dfdfa, 0x55dff7c, 0x55e0f6e, 0x55e0fab, 0x55e0fd1, 0x55e113f]},
    '0x55e16d0|0x478': {"flag": [0x55e1754], "node": [], "height": [], "position": []},
    '0x55e16d0|0xa0': {"flag": [0x55e1a63, 0x55e1ebd, 0x55e22d9, 0x55e244b, 0x55e2647, 0x55e29b1, 0x55e2bf2, 0x55e2c7b, 0x55e2d17, 0x55e32d2, 0x55e3360, 0x55e33d7], "node": [0x55e1a7d, 0x55e1ecb, 0x55e22f3, 0x55e2459, 0x55e2815, 0x55e2a43, 0x55e2c96, 0x55e2d4e, 0x55e32da, 0x55e3376, 0x55e3436], "height": [], "position": [0x55e1a71, 0x55e1ed8, 0x55e22e7, 0x55e2475, 0x55e2a37, 0x55e2d42, 0x55e3261, 0x55e3458]},
    '0x55e4ad0|0x80': {"flag": [0x55e4d25, 0x55e4e12], "node": [], "height": [0x55e4d2d], "position": []},
    '0x560a550|0xf0': {"flag": [0x560a71b], "node": [], "height": [], "position": []},
    '0x560ada0|0xf0': {"flag": [0x560af6b], "node": [], "height": [], "position": []},
    '0x5a090d0|0x48': {"flag": [0x5a09176, 0x5a09309], "node": [0x5a0918a, 0x5a0931d], "height": [], "position": [0x5a09181, 0x5a09314]},
    '0x5a31270|0x270': {"flag": [0x5a31350, 0x5a315bb], "node": [0x5a3136a], "height": [], "position": [0x5a3135e]},
}
HEIGHT_READS = {
    '0x296a390|0x130': {0x296aa1c: 'vector_copy', 0x296b6a5: 'vector_copy', 0x296c182: 'other_phase'},
    '0x2a40cc0|0x20': {0x2a40e57: 'vector_copy', 0x2a40ec4: 'other_phase', 0x2a40f69: 'other_phase', 0x2a41255: 'other_phase', 0x2a41371: 'vector_copy'},
    '0x2a84990|0xa0': {},
    '0x2a84e60|0xd0': {0x2a8549b: 'other_phase', 0x2a85995: 'other_phase', 0x2a86fd6: 'other_phase'},
    '0x2a88380|0x90': {},
    '0x2a88af0|0x10': {},
    '0x2a89500|0x80': {},
    '0x2a8be00|0x10': {0x2a8bea7: 'other_phase', 0x2a8c977: 'other_phase', 0x2a8ca67: 'other_phase', 0x2a8ca8b: 'other_phase'},
    '0x2b92a50|0x18': {},
    '0x2bb2ec0|0x40': {0x2bb3269: 'other_phase'},
    '0x2bb48c0|0xf0': {},
    '0x2bb52a0|0x188': {},
    '0x2bb68e0|0xf8': {},
    '0x2bb7270|0x140': {},
    '0x2bb98a0|0x80': {},
    '0x2bba100|0x60': {},
    '0x2bbbba0|0xf8': {},
    '0x2bbc750|0xe8': {},
    '0x2bbd0b0|0xe8': {},
    '0x2bdf8f0|0x3f0': {0x2be305a: 'other_phase', 0x2be373a: 'other_phase', 0x2be4ac4: 'other_phase', 0x2be59a2: 'other_phase', 0x2be74a1: 'vector_copy', 0x2be850a: 'other_phase', 0x2be85d7: 'other_phase'},
    '0x2bf2ed0|0x250': {0x2bf32af: 'vector_copy', 0x2bf344e: 'other_phase', 0x2bf3a10: 'other_phase', 0x2bf3c31: 'other_phase', 0x2bf43b9: 'vector_copy', 0x2bf4508: 'vector_copy', 0x2bf4b13: 'vector_copy', 0x2bf4d58: 'vector_copy', 0x2bf5b25: 'other_phase', 0x2bf65ba: 'vector_copy', 0x2bf6836: 'other_phase', 0x2bf6874: 'other_phase', 0x2bf6ed1: 'vector_copy', 0x2bf6fc9: 'other_phase', 0x2bf83eb: 'vector_copy'},
    '0x2c61b30|0x30': {},
    '0x2c62820|0x468': {},
    '0x2c62820|0xa0': {},
    '0x2c65980|0x80': {0x2c65a8a: 'vector_copy'},
    '0x2c74e40|0x70': {0x2c7534d: 'vector_copy'},
    '0x2c80670|0x270': {},
    '0x2d27720|0x48': {},
    '0x2f0f090|0x30': {},
    '0x2f0f3b0|0x88': {},
    '0x421b430|0x8': {},
    '0x451d1c0|0x8': {},
    '0x46df170|0x28': {},
    '0x547d430|0x40': {0x547d7d9: 'other_phase'},
    '0x547d910|0x40': {0x547dcb9: 'other_phase'},
    '0x548ebd0|0x90': {},
    '0x548f430|0x60': {},
    '0x5490660|0x110': {},
    '0x5491190|0xc0': {},
    '0x5492440|0x120': {},
    '0x5493080|0xf8': {},
    '0x5493c30|0xe8': {},
    '0x5494720|0xe8': {},
    '0x54a9c70|0x470': {0x54ad59c: 'other_phase', 0x54adc82: 'other_phase', 0x54af291: 'other_phase', 0x54b0158: 'other_phase', 0x54b1ed1: 'vector_copy', 0x54b39f5: 'other_phase', 0x54b3ac4: 'other_phase', 0x54b531f: 'other_phase'},
    '0x54a9c70|0x60': {0x54aa12f: 'vector_copy', 0x54aa6c7: 'other_phase', 0x54aabf8: 'other_phase', 0x54ab126: 'other_phase', 0x54ab969: 'other_phase', 0x54abef9: 'other_phase', 0x54ad013: 'other_phase', 0x54afe20: 'other_phase', 0x54b1063: 'vector_copy', 0x54b1284: 'other_phase', 0x54b1e24: 'other_phase', 0x54b2030: 'other_phase', 0x54b20e3: 'other_phase', 0x54b2775: 'other_phase', 0x54b2d17: 'other_phase', 0x54b34ae: 'other_phase', 0x54b52ce: 'other_phase', 0x54b5394: 'other_phase', 0x54b53cb: 'other_phase'},
    '0x54b66b0|0x3c0': {0x54b9e8d: 'other_phase', 0x54ba518: 'other_phase', 0x54bbb01: 'other_phase', 0x54bc917: 'other_phase', 0x54be511: 'vector_copy', 0x54bffde: 'other_phase', 0x54c00ad: 'other_phase', 0x54c188f: 'other_phase'},
    '0x54b66b0|0x60': {0x54b6b6f: 'vector_copy', 0x54b70e7: 'other_phase', 0x54b7618: 'other_phase', 0x54b7b46: 'other_phase', 0x54b8316: 'other_phase', 0x54b8870: 'other_phase', 0x54b9903: 'other_phase', 0x54bc500: 'other_phase', 0x54bd6a5: 'vector_copy', 0x54bd8c4: 'other_phase', 0x54be464: 'other_phase', 0x54be670: 'other_phase', 0x54be726: 'other_phase', 0x54bed9f: 'other_phase', 0x54bf347: 'other_phase', 0x54bfac7: 'other_phase', 0x54c183e: 'other_phase', 0x54c18ff: 'other_phase', 0x54c1933: 'other_phase'},
    '0x54cfa90|0xb0': {0x54cfebd: 'vector_copy', 0x54d0064: 'other_phase', 0x54d0625: 'other_phase', 0x54d0851: 'other_phase', 0x54d1009: 'vector_copy', 0x54d1188: 'vector_copy', 0x54d1885: 'vector_copy', 0x54d20f6: 'vector_copy', 0x54d2c4f: 'other_phase', 0x54d341d: 'vector_copy', 0x54d3666: 'other_phase', 0x54d369b: 'other_phase', 0x54d3d1b: 'vector_copy', 0x54d3e0f: 'other_phase', 0x54d50dc: 'vector_copy'},
    '0x54d57b0|0xa0': {0x54d5be8: 'vector_copy', 0x54d5d8f: 'other_phase', 0x54d6340: 'other_phase', 0x54d6571: 'other_phase', 0x54d6ce9: 'vector_copy', 0x54d6e68: 'vector_copy', 0x54d7565: 'vector_copy', 0x54d7dc1: 'vector_copy', 0x54d88f3: 'other_phase', 0x54d90e0: 'vector_copy', 0x54d9336: 'other_phase', 0x54d936b: 'other_phase', 0x54d99d7: 'vector_copy', 0x54d9acf: 'other_phase', 0x54dad91: 'vector_copy'},
    '0x55817e0|0xa0': {},
    '0x5581cb0|0xa0': {},
    '0x5582180|0xb0': {0x55827a0: 'other_phase', 0x5582c55: 'other_phase', 0x5584082: 'other_phase', 0x5584398: 'other_phase', 0x55843c8: 'other_phase'},
    '0x5585290|0xb0': {0x55858b0: 'other_phase', 0x5585d65: 'other_phase', 0x5587192: 'other_phase', 0x55874a8: 'other_phase', 0x55874d8: 'other_phase'},
    '0x55883a0|0x90': {},
    '0x5588670|0x90': {},
    '0x5588d90|0x10': {},
    '0x5588f30|0x10': {},
    '0x55a07e0|0x80': {},
    '0x55a12e0|0x80': {},
    '0x55defd0|0xa0': {},
    '0x55e16d0|0x478': {},
    '0x55e16d0|0xa0': {},
    '0x55e4ad0|0x80': {0x55e4d2d: 'vector_copy'},
    '0x560a550|0xf0': {},
    '0x560ada0|0xf0': {},
    '0x5a090d0|0x48': {},
    '0x5a31270|0x270': {},
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


def _consumption_on_hit(rows, site_row, flag_addr, imul_addr):
    """Block-walk from the flag test's jump: the imul block must be reached on
    exactly the flag==0 (hit) side of the branch."""
    addrs = sorted(rows)
    jcc = addrs[addrs.index(flag_addr) + 1]
    m = re.match(r'^(j\w+)\s+(0x[0-9a-f]+)$', rows[jcc][1])
    if not m:
        raise PacketError(f'site {site_row:#x}: no conditional jump after the flag test')
    mnemonic, target = m.group(1), int(m.group(2), 16)
    fall = addrs[addrs.index(jcc) + 1]

    def reaches(start, goal):
        i = addrs.index(start)
        for a in addrs[i:]:
            if a == goal:
                return True
            mn = rows[a][1].split(' ', 1)[0]
            if mn.startswith('j') or mn in ('call', 'ret') or a > goal:
                return False
        return False

    in_target = reaches(target, imul_addr)
    in_fall = reaches(fall, imul_addr)
    if mnemonic in ('jne', 'jnz'):
        return in_target and not in_fall
    if mnemonic in ('je', 'jz'):
        return in_fall and not in_target
    return False


def analyze(data):
    secs = sections(data)
    _summary, fdes, _gaps = fde_extents(data)
    if len(fdes) != FDE_COUNT:
        raise PacketError(f'FDE census mismatch: {len(fdes)} != {FDE_COUNT}')
    starts = [f['start'] for f in fdes]
    if len(set(starts)) != len(starts):
        raise PacketError('FDE starts are not unique')
    extents = {f['start']: (f['start'], f['end']) for f in fdes}

    # --- the sibling body
    body = _section_bytes(secs, data, SIBLING_START, SIBLING_END)
    if _sha256(body) != SIBLING_BODY_SHA256:
        raise PacketError('sibling body differs from its pinned digest')
    rows = _decode(secs, data, SIBLING_START, SIBLING_END)
    _check_pins(rows, SIBLING_PINS, 'sibling body')
    for addr, (_raw, text) in rows.items():
        if text.startswith('call'):
            raise PacketError(f'sibling body is not call-free: call at {addr:#x}')
        m = re.match(r'^(?:jmp|j\w+)\s+(0x[0-9a-f]+)$', text)
        if m and not (SIBLING_START <= int(m.group(1), 16) < SIBLING_END):
            raise PacketError(f'sibling body branches outside itself at {addr:#x}')

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
    direct, tail = _branch_sites(data, secs, SIBLING_START)
    if tail:
        raise PacketError('sibling search has tail-call sites')
    if direct != set(SITES):
        raise PacketError('call-site census mismatch: byte scan disagrees with the retained sites')
    rela_hits = 0
    for sec in secs:
        if sec['name'] != '.rela.dyn':
            continue
        raw = data[sec['offset']:sec['offset'] + sec['size']]
        for off in range(0, len(raw) - 23, 24):
            _r_off, r_type, r_add = struct.unpack_from('<QQq', raw, off)
            if r_type == 8 and r_add == SIBLING_START:  # R_X86_64_RELATIVE
                rela_hits += 1
    if rela_hits != EXPECTED['rela_relative_hits']:
        raise PacketError('R_X86_64_RELATIVE census mismatch for the sibling body')

    # --- per-site records, windows, flag tests, consumption direction
    classes = Counter()
    presentations = Counter()
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
        if call_row is None or call_row[1] != 'call   0x35bf460':
            raise PacketError(f'site {site:#x} is not a sibling call in its caller decode')
        flag_row = rows[info['flag']]
        if flag_row[1].startswith('cmpl'):
            form = 'dword'
            if info['class'] != 'node_position':
                raise PacketError(f'site {site:#x}: dword flag test without node+position consumption')
            imul = next(a for a in win['pins'] if rows[a][1].startswith('imul'))
            if f'{info["base"] + 0x18:#x}(%rsp)' not in rows[imul][1] or '$0xb0' not in rows[imul][1]:
                raise PacketError(f'site {site:#x}: imul pin does not scale the position slot by 0xb0')
            if not _consumption_on_hit(rows, site, info['flag'], imul):
                raise PacketError(f'site {site:#x}: node+position consumption is not on the hit branch')
        elif flag_row[1].startswith('cmpb'):
            form = 'byte'
            if info['class'] == 'node_position':
                raise PacketError(f'site {site:#x}: byte flag test with node+position consumption')
        else:
            raise PacketError(f'site {site:#x}: unrecognised flag test {flag_row[1]!r}')
        flag_forms[form] += 1
        classes[info['class']] += 1
        presentations[info['presentation']] += 1
        if info['join'] != (site in JOIN_SITES):
            raise PacketError(f'site {site:#x}: join flag disagrees with the retained join set')

    # --- attribution and overwrite windows
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
        'join_sites': sum(1 for i in SITES.values() if i['join']),
        'flag_dword_sites': flag_forms['dword'],
        'flag_byte_sites': flag_forms['byte'],
        'presentations': dict(presentations),
        'height_read_units': h_units,
        'height_never_read_units': len(units) - h_units,
        'height_reads': h_reads,
        'height_vector_copy_reads': h_classes['vector_copy'],
        'height_other_phase_reads': h_classes['other_phase'],
        'height_consumed_reads': 0,
        'windows': len(WINDOWS),
        'site_windows': sum(1 for n in WINDOWS if n.startswith('site_')),
        'attribution_windows': sum(1 for n in WINDOWS if '_height_' in n),
        'overwrite_windows': sum(1 for n in WINDOWS if '_record_overwrite_' in n),
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
            'tool': 'tools/sibling_search_static.py',
            'test': 'tests/test_sibling_search_static.py',
            'authentication_inside_analyze': False,
        },
        'node': {
            'artifact_sha256': ARTIFACT_SHA256,
            'artifact_size': ARTIFACT_SIZE,
            'fde_records': FDE_COUNT,
        },
        'sibling': {
            'range': [hex(SIBLING_START), hex(SIBLING_END)],
            'length_bytes': SIBLING_END - SIBLING_START,
            'sha256': SIBLING_BODY_SHA256,
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
        'join_indirect_call_slot': hex(JOIN_INDIRECT_CALL_SLOT),
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
                'join': info['join'],
                'window': f'site_{site:#x}',
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
            'statement': 'no consumer reads the sibling record height field as a number: '
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
    ranges = [(SIBLING_START, SIBLING_END)] + [v[0] for v in BOUNDARIES.values()]
    kept = []
    for line in out.splitlines():
        m = re.match(r'^([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+FDE\s+cie=[0-9a-f]+\s+pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
        if m:
            pc = (int(m.group(4), 16), int(m.group(5), 16))
            if pc in ranges:
                kept.append(line.replace(path, '<authenticated-node115>'))
    return ('\n'.join(kept) + '\n').encode()


def _sibling_export(data):
    """Full-body export in the chain's format: intel-syntax objdump of the
    authenticated ELF itself, with the source path normalised."""
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as handle:
        handle.write(data)
        path = handle.name
    try:
        out = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={SIBLING_START:#x}',
             f'--stop-address={SIBLING_END:#x}', path], text=True)
    finally:
        Path(path).unlink()
    if f'{SIBLING_START:x}:' not in out:
        raise PacketError('sibling export does not cover the body')
    return out.replace(path, '<authenticated-node115>').encode()


def generate(data, out_dir):
    if _sha256(data) != ARTIFACT_SHA256 or len(data) != ARTIFACT_SIZE:
        raise PacketError('artifact SHA-256 mismatch')
    records = analyze(data)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json.dumps(records, indent=1, sort_keys=True) + '\n')
    (out / 'frames.txt').write_bytes(_frames(data))
    (out / 'sibling_search_full_body_35bf460_35bf4f2_objdump.txt').write_bytes(_sibling_export(data))
    return records


def main(argv):
    if len(argv) != 3 or argv[1] != 'generate':
        print('usage: sibling_search_static.py generate <output-dir>', file=sys.stderr)
        return 2
    artifact = ROOT / 'artifacts/node/115/hl-node'
    generate(artifact.read_bytes(), argv[2])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
