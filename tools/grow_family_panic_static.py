#!/usr/bin/env python3
"""Close the panic side of the whole S-map grow family at once.

Three bodies in the cluster load the shared "Hash table capacity
overflow" message (binary-wide lea census: exactly three sites in the
0x4740000..0x474c000 cluster): the FNV grow at 0x4742aa0, the sibling
grow at 0x4743990, and a third grow variant at 0x4743350 that neither
predecessor packet examined.  The two earlier packets settled the
question one body at a time -- the map-grow panic packet
(RE-015-node115-map-grow-panic) for the grow and its insert caller,
the sibling-hasher packet (RE-015-node115-sibling-hasher-panic) for
the sibling's seeded hasher -- and each left the family boundary open:
the variant's own panic side, the two neighbouring hash bodies that
share the buffered absorb, and the first-frame callers of everything
except the grow and the hasher.

This packet closes the family as one unit.  Its verdicts:

(a) The variant at 0x4743350 has the grow's exact failure shape: three
pre-split sizing branches to a fallibility dispatch (0x474348a) and a
fresh-path null-allocation block (0x47438e9) are its only routes to
the failure tail at 0x474395b, all before any record is marked; its
slot inventory is the grow's six slots verbatim.  It differs from the
grow in one way that matters: it calls the hash body at 0x4744600 once
per record in both paths (fresh at 0x474358e, in-place at 0x4743700),
the second of them inside the marking window -- the sibling's exact
exposure -- yet its frame is the plain-'zR' frame with no LSDA.

(b) That is sound because the callee cannot panic.  The hash bodies
at 0x4744330, 0x4744490 and 0x4744600 are three instantiations of one
seeded SipHash body over the shared buffered absorb at 0x4744980:
byte-exact decode shows no branch, no division and no trap in any of
them, and their only calls are the two absorb calls each.  The absorb
is a leaf.  A behavioural differential over 20,000 frozen cases runs
all three bodies natively and finds one output stream.  No panic can
be raised inside any marking window of the family, and no unwind can
arrive from below one.

(c) Every first-frame caller is accounted for.  The grow's slot call
in the insert (pad, settled), the sibling's slot call in the caller
at 0x474ba60 (range 0x474bc81..0x474bc97, pad 0x474bcb4, which frees
only the caller's pending buffer), the variant's slot call in the
padded caller at 0x4747a70 (range 0x4747b4d..0x4747b75, pad 0x4747b79,
which drops the caller's stack descriptor through 0x4742810), the
variant's second slot call in the plain-'zR' caller at 0x474bce0 (no
pad exists; none is needed map-side, per (a) and (b)), and the two
hash-A callers at 0x4749d80 and 0x4749f70, whose call sites precede
their first LSDA ranges and so carry no pad -- moot, per (b).  The
hasher's callers are re-pinned from the sibling-hasher packet's
decodings.

(d) The family boundary is censused, not assumed: the three grows'
addresses occur as qwords only inside their own .rela.dyn records,
each home slot is referenced only by its pinned call sites, no
movabs immediate names any family body or the panic message, and the
neighbouring 5,696-byte body at 0x4744b60 with its four pad shims
makes no call to any family body or family slot -- it is a different
map's business and stays outside.
"""
import ctypes
import hashlib
import json
import random
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from elf_index import sections
from fde_extents import eh_frame_records
from foundation_millis import decode_export, require

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_DISPLAY = 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

ZR_CIE = 0xca6ed8
ZPLR_CIE = 0x103d604
PERSONALITY_SLOT = 0x64efa28
UNWIND_RESUME = 0x63f0a50
CLUSTER = (0x4740000, 0x474c000)

# Bodies this packet proves new facts about.
OWNERS = {
    'variant_grow': (0x4743350, 0x474398c,
                     'bc09ee782d62721d2cbc93cc2e52d6f447caebbf7ef36da1'
                     '9f5ae89cfef84ae4'),
    'hash_a': (0x4744330, 0x4744490,
               '6a63f80b87467acfa021f1e6f6348428254af8bf6eb366a'
               '0b6c23c762053df69'),
    'hash_b': (0x4744600, 0x474476a,
               '45b8c11384591251d95dfd535ffa593b439d7f0f2673e14'
               '1dcd44888e88bcdc1'),
}
# Bodies whose panic facts were settled by the two predecessor
# packets; re-pinned here by extent and SHA-256 because this packet's
# family verdict rests on them.
SETTLED = {
    'map_grow': (0x4742aa0, 0x4743347,
                 'dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed'
                 '5d56d0ac4a67'),
    'sibling_grow': (0x4743990, 0x4743ff0,
                     'eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60'
                     'f2220d564f961eef'),
    'sibling_hasher': (0x4744490, 0x47445fb,
                       'a63e8df74f90feb19a2edfb54c63f81974bac2b7c325c3'
                       '63bc7fe23f9c757f62'),
    'absorb': (0x4744980, 0x4744b57,
               '2de0e4e06f65af3f729cc6b2a4d12d7dcbbcb25902272a15c5f238'
               'c5096ed8b0'),
    'marked_cleanup': (0x47425c0, 0x4742676,
                       'a27501e59ce2fa4fc610ed13d3da63c01ea578963bec73'
                       'd983d86b584a3e49e4'),
    'pad_helper': (0x4742680, 0x47426d1,
                   'da0038dfd88d2675f82db29375445a91dc3116e140ab87ae0'
                   '2e1c6eac7fb3401'),
}
# First-frame callers of family bodies.
CALLERS = {
    'map_insert': (0x474b620, 0x474ba5d,
                   'f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9'
                   'bcb0b1739cd6658'),
    'caller_a': (0x4748500, 0x4749aa9,
                 '7b1d3b86c285b089e030cba72aa9fc2b71cba2009d2849c91'
                 'ec06977ea9b2691'),
    'caller_b': (0x474a160, 0x474a36c,
                 'a2ca8b7c65a4ed7eb69ff5fb090acb7daead9c234e681b086'
                 '7b3d0c70a1b5d7d'),
    'caller_c': (0x474ba60, 0x474bcd3,
                 '4527e1e0d1ad267cdd6951f2eb2898a962a2124d6096038fd'
                 '63087ea43637d44'),
    'hash_a_caller_1': (0x4749d80, 0x4749f6e,
                        '013503c907293d54e1826ea124ba61578b152e6b9ae'
                        '6abb2655e19a8b0d714e1'),
    'hash_a_caller_2': (0x4749f70, 0x474a15e,
                        'ea0826a03cce2cdafa2284acb2eb19257ce802723a71'
                        '087246eb6ee88717597c'),
    'variant_caller_padded': (0x4747a70, 0x4747b8c,
                              '94e2a7361dea19622e98cd267c3079c6f5ef77'
                              'aaf99c24a6af8c1692a8a1a734'),
    'variant_caller_plain': (0x474bce0, 0x474bf2c,
                             '3f90106dd6d57d477b44d82c7e1e0a5da00051d'
                             '4b9a2d73d2dd4a079d1912a21'),
}
SHIMS = {
    'rust_personality': (0x5cad7b0, 0x5cadd4f,
                         'fc2600274388c9ee5a7c1aec72fae9aebbb6dffb18ee'
                         '91059e8b3679ec92d677'),
    'panic_formatter': (0x1680e80, 0x1680eac,
                        '28fc3434a04bb9e49d5a0164306a5c31abf6bce26425'
                        'd99d27031ac1c9beb2e3'),
    'panic_impl_shim': (0x5c826c0, 0x5c826dd,
                        'ae57c1f06e3254ce7cd3518d42154be71831103b748b6'
                        'f19f74cacc64c5fb766'),
    'alloc_error_adapter': (0x141e251, 0x141e264,
                            '8443a2a6c5074055f5abdf1b4b2041c6434ff00ba2'
                            '3ebfcb33a91176170035b9'),
    'alloc_handler_shim': (0x5c827a0, 0x5c827b3,
                           '0c812a743791010c3c3ec26bb02400d2081851a700c'
                           '58237af89161da151228e'),
    'cleanup_guard': (0x1680cab, 0x1680cbf,
                      '7604c0d4f26a7d70e59c5dcb8a39928bfd7207a5d4439d9'
                      '1d8fb1e50be9846e7'),
    'guard_panic_entry': (0x1680e40, 0x1680e5e,
                          '8506c2e60ef3206c2566cee1c87d5709e1a0b465109'
                          '4519c2d07355a9deec427'),
}

# Type-8 (RELATIVE) slot bindings read back from .rela.dyn.
SLOT_BINDINGS = {
    0x64eaf78: 0x4742aa0,   # grow home slot
    0x64eaf80: 0x4743350,   # variant home slot
    0x64eaf88: 0x4743990,   # sibling home slot
    0x64df480: 0x6355830,   # allocation shim
    0x64df4a0: 0x635de30,   # deallocation shim
    0x64df490: 0x141e251,   # allocation-error adapter
    0x64df6b8: 0x1680e80,   # panic formatter
    0x64df4c0: 0x1680cab,   # panic-in-cleanup guard
    PERSONALITY_SLOT: 0x5cad7b0,
}
# Type-6 (GLOB_DAT) slots bound by symbol name.
GLOB_SLOTS = {0x64df568: 'memmove', 0x64df750: 'memset'}

PANIC_MESSAGE_VA = 0x49bd80
PANIC_MESSAGE = b'Hash table capacity overflow'
GUARD_STRING_VA = 0x46e9bd
GUARD_STRING = b'panic in a destructor during cleanup'
SIPHASH_CONST_A = (0x4522f0, '75657370656d6f736172656e6567796c')
SIPHASH_CONST_B = (0x4511c0, '6d6f646e61726f647365747962646574')

# LSDA call-site tables: (lsda va, blob sha256, action-table head,
# entries (start, length, landing pad or 0, action)).
LSDAS = {
    'sibling_grow': (0x34c4f8,
                     '3533100047f67ca002e96d6c230f3bec06297b95d72'
                     'cf23b5fd79031b5ea1087', '7f00', [
                         (0x4743990, 0x24f, 0, 0),
                         (0x4743bdf, 0xa, 0x4743fc0, 0),
                         (0x4743be9, 0x16f, 0, 0),
                         (0x4743d58, 0xa, 0x4743fd5, 0),
                         (0x4743d62, 0x276, 0, 0),
                         (0x4743fd8, 0xa, 0x4743fea, 1),
                         (0x4743fe2, 0xe, 0, 0)]),
    'map_insert': (0x34caf4,
                   'f7779adae3e80355c13d4a1a156d4d089fdaf7a4320d33'
                   'e04ff22060062e0b6b', '7f00', [
                       (0x474b620, 0x3ce, 0, 0),
                       (0x474b9ee, 0x23, 0x474ba2e, 0),
                       (0x474ba31, 0xa, 0x474ba57, 1),
                       (0x474ba3b, 0x22, 0, 0)]),
    'caller_a': (0x34c818,
                 '582dacc3fa8508b8e3bee377480c8c57cb2248588752de'
                 '6f2c226a819702a6a0', '7f00', [
                     (0x4748500, 0x235, 0, 0),
                     (0x4748735, 0x12, 0x4749995, 0),
                     (0x474875b, 0xb, 0x4749870, 0),
                     (0x47487aa, 0x5, 0x47498ab, 0),
                     (0x47487e5, 0xd, 0x4749906, 0),
                     (0x4748836, 0xe, 0x4749875, 0),
                     (0x474885a, 0xa, 0x4749809, 0),
                     (0x4748977, 0x12, 0x4749948, 0),
                     (0x4748aa6, 0xe, 0x4749869, 0),
                     (0x4748af1, 0xb, 0x4749895, 0),
                     (0x4748afc, 0x2a8, 0, 0),
                     (0x4748da4, 0xf, 0x47498f6, 0),
                     (0x4748dce, 0xb, 0x47497e6, 0),
                     (0x4748dd9, 0x1e4, 0, 0),
                     (0x4748fbd, 0xb, 0x47497a6, 0),
                     (0x47491a3, 0x15, 0x4749814, 0),
                     (0x47492e6, 0xe, 0x47497a4, 0),
                     (0x4749344, 0xb, 0x47497d7, 0),
                     (0x474944a, 0xe, 0x474978f, 0),
                     (0x474945d, 0xd, 0x47497cf, 0),
                     (0x474946a, 0x2a2, 0, 0),
                     (0x474970c, 0x10, 0x47499e8, 0),
                     (0x474971e, 0xc, 0x474977f, 0),
                     (0x474972f, 0xc, 0x4749774, 0),
                     (0x4749745, 0xe, 0x4749943, 0),
                     (0x4749755, 0xe, 0x474986b, 0),
                     (0x474983e, 0xa, 0x4749aa3, 1),
                     (0x474987d, 0xd, 0x474988f, 1),
                     (0x47498df, 0x19d, 0x4749aa3, 1),
                     (0x4749a7c, 0x2d, 0, 0)]),
    'caller_b': (0x34c9a0,
                 '1b8d6aea1187660e9f7aa9097c078775483860bdb291ff'
                 'aa53b61e1a893d233f', '0000', [
                     (0x474a160, 0x60, 0, 0),
                     (0x474a1c0, 0x8, 0x474a361, 0),
                     (0x474a1c8, 0x15e, 0, 0),
                     (0x474a326, 0xf, 0x474a361, 0),
                     (0x474a335, 0x37, 0, 0)]),
    'caller_c': (0x34cb18,
                 'd1b07b2d7321a9ded8198f8be00bb42d2d5667cf287c3'
                 'ec0e3254e2c848ad247', '0000', [
                     (0x474ba7b, 0x8, 0x474bcb4, 0),
                     (0x474ba83, 0x1fe, 0, 0),
                     (0x474bc81, 0x16, 0x474bcb4, 0),
                     (0x474bc97, 0x3c, 0, 0)]),
    'variant_caller_padded': (0x34c774,
                              'f24f8868a4357c665ae85e97d1bdb7a82bc0af'
                              '00e03050a0f391ecc9b8c6028b', '0000', [
                                  (0x4747ae8, 0xb, 0x4747b77, 0),
                                  (0x4747af3, 0x5a, 0, 0),
                                  (0x4747b4d, 0x28, 0x4747b79, 0),
                                  (0x4747b75, 0x17, 0, 0)]),
    'hash_a_caller_1': (0x34c95c,
                        '3a707707ddca318ec685a45db2d97e19ac754da2a5'
                        'c6ba56306521949380df35', '00ff', [
                            (0x4749f36, 0x19, 0x4749f63, 0),
                            (0x4749f4f, 0x1f, 0, 0)]),
    'hash_a_caller_2': (0x34c990,
                        '3a707707ddca318ec685a45db2d97e19ac754da2a5'
                        'c6ba56306521949380df35', '00ff', [
                            (0x474a126, 0x19, 0x474a153, 0),
                            (0x474a13f, 0x1f, 0, 0)]),
}
# Call-site coverage the family verdict relies on: caller role ->
# {call site: landing pad or None}.  None means no LSDA range covers
# the site, asserted against the decoded table.
COVERAGE = {
    'map_insert': {0x474ba06: 0x474ba2e},
    'caller_a': {0x4748984: 0x4749948, 0x47491b3: 0x4749814},
    'caller_b': {0x474a1c3: 0x474a361},
    'caller_c': {0x474ba7e: 0x474bcb4, 0x474bc91: 0x474bcb4},
    'variant_caller_padded': {0x4747b5d: 0x4747b79},
    'hash_a_caller_1': {0x4749f0a: None},
    'hash_a_caller_2': {0x474a0fa: None},
    'sibling_grow': {0x4743be4: 0x4743fc0, 0x4743d5d: 0x4743fd5},
}

# The variant grow, instruction-pinned.
V_DISPATCH = 0x474348a        # fallibility dispatch (grow: 0x4742bd1)
V_TAIL = 0x474395b            # failure tail head
V_TAIL_HALF = 0x4743974       # the tail's allocation-error half
V_FAILURE_BRANCHES = {
    0x4743370: V_DISPATCH,    # entry checked-add jb
    0x4743413: V_DISPATCH,    # capacity-cap ja
    0x4743457: V_DISPATCH,    # size-overflow jo
    0x474348d: V_TAIL,        # the dispatch's own jne
    0x47438ee: V_TAIL_HALF,   # null-allocation block's jne
}
V_ALLOC_SITE = 0x47434ac
V_NULL_BLOCK = 0x47438e9
V_SLOT_CALLS = {
    0x47434ac: (0x64df480, 'alloc'),
    0x47434f1: (0x64df750, 'memset'),
    0x47436e0: (0x64df568, 'memmove'),
    0x4743946: (0x64df4a0, 'dealloc'),
    0x474396e: (0x64df6b8, 'panic formatter'),
    0x474397c: (0x64df490, 'allocation error'),
}
V_HASH_CALLS = {0x474358e: 'fresh', 0x4743700: 'in-place'}
V_MARK_CONVERT = 0x4743670    # SIMD control-byte conversion loop head
V_SCAN_HEAD = 0x4743836       # in-place relocation scan head

PINS = [
    # The variant's failure wiring.
    (0x4743370, '0f8214010000', 'variant checked-add jb to dispatch'),
    (0x4743413, '7775', 'variant capacity-cap ja to dispatch'),
    (0x4743457, '7031', 'variant size-overflow jo to dispatch'),
    (V_DISPATCH, '4584c0', 'dispatch tests the fallibility byte'),
    (0x474348d, '0f85c8040000', 'dispatch jne to the failure tail'),
    (V_NULL_BLOCK, '807c240800', 'null block tests its fallibility copy'),
    (0x47438ee, '0f8580000000', 'null block jne into the tail half'),
    (V_TAIL, '488d3d1e84d5fb', 'tail loads the capacity-overflow message'),
    (0x4743962, '488d152f93cd01', 'tail loads its location object'),
    (0x4743969, 'be39000000', 'tail loads the message length 0x39'),
    # The variant's marking machinery.
    (V_MARK_CONVERT, '660fefc9', 'conversion loop zeroes its accumulator'),
    (V_SCAN_HEAD, '433a442500', 'relocation scan compares a control byte'),
    # The sibling's failure tail (same message, same location object).
    (0x4743f8f, '488d3dea7dd5fb', 'sibling tail loads the message'),
    (0x4743f96, '488d15fb8ccd01', 'sibling tail loads the location'),
    # The hash bodies' shared prologue shape.
    (0x4744330, '534883ec60f30f6f07', 'hash-A prologue mixes a record'),
    (0x4744490, '534883ec60f30f6f07', 'hasher prologue mixes a record'),
    (0x4744600, '534883ec60f30f6f07', 'hash-B prologue mixes a record'),
    # Caller C's shared pad and the padded variant caller's pad.
    (0x474bcb4, '4889c3', 'caller C pad saves the exception object'),
    (0x474bcbf, '498b7e08', 'caller C pad loads the pending buffer'),
    (0x4747b77, 'eb00', 'variant caller pad trampoline'),
    (0x4747b79, '4889c3', 'variant caller pad saves the exception'),
    (0x4747b7c, '4889e7', 'variant caller pad loads its stack descriptor'),
]
DIRECT_CALL_PINS = [
    (0x474358e, 0x4744600, 'variant fresh path calls hash B'),
    (0x4743700, 0x4744600, 'variant in-place scan calls hash B'),
    (0x4744380, 0x4744980, 'hash A absorb call 1'),
    (0x4744397, 0x4744980, 'hash A absorb call 2'),
    (0x47444eb, 0x4744980, 'hasher absorb call 1'),
    (0x4744502, 0x4744980, 'hasher absorb call 2'),
    (0x474465a, 0x4744980, 'hash B absorb call 1'),
    (0x4744671, 0x4744980, 'hash B absorb call 2'),
    (0x4747b7f, 0x4742810, 'variant caller pad drops via its cleanup'),
    (0x4747b87, UNWIND_RESUME, 'variant caller pad resumes the unwind'),
    (0x474bcce, UNWIND_RESUME, 'caller C pad resumes the unwind'),
]
SLOT_CALL_PINS = [
    (0x4743946, 0x64df4a0, 'variant frees the old table (dealloc slot)'),
    (0x474396e, 0x64df6b8, 'variant tail calls the panic formatter'),
    (0x474397c, 0x64df490, 'variant tail calls allocation error'),
    (0x474bcc5, 0x64df4a0, 'caller C pad frees through the dealloc slot'),
]
# Binary-wide direct-call censuses.
DIRECT_CALL_CENSUS = {
    0x4744490: [0x4743be4, 0x4743d5d, 0x4748984, 0x47491b3,
                0x474a1c3, 0x474ba7e],
    0x4744330: [0x4749f0a, 0x474a0fa],
    0x4744600: [0x474358e, 0x4743700, 0x474bd13],
    0x4744980: [0x4744380, 0x4744397, 0x47444eb, 0x4744502,
                0x474465a, 0x4744671],
    0x47425c0: [0x4743fdd],
    0x4742680: [0x4743fc8],
}
# Binary-wide slot-call censuses over the three home slots.
HOME_SLOTS = {0x64eaf78: [0x474ba06], 0x64eaf80: [0x4747b5d, 0x474bf02],
              0x64eaf88: [0x474bc91]}
FAMILY_BODIES = [0x4742aa0, 0x4743350, 0x4743990, 0x4744330, 0x4744490,
                 0x4744600, 0x4744980, 0x47425c0, 0x4742680]
NEIGHBOUR = (0x4744b60, 0x47461a0)   # the other map's main body

# Behavioural differential over the three hash bodies.
BEHAVIOR_SEEDS = [
    '000102030405060708090a0b0c0d0e0f',
    '00000000000000000000000000000000',
    'ffffffffffffffffffffffffffffffff',
    'a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a',
]
BEHAVIOR_CASES = 20000
BEHAVIOR_STREAM_SEED = 20261105
SPAN = (0x451000, 0x4745000)

WINDOWS = [
    ('variant_entry_objdump.txt', 0x4743350, 0x47434c0,
     [0x4743370, 0x4743413, 0x4743457, V_DISPATCH, 0x474348d,
      V_ALLOC_SITE]),
    ('variant_fresh_rehash_objdump.txt', 0x4743514, 0x4743620,
     [0x474358e]),
    ('variant_inplace_objdump.txt', 0x4743640, 0x4743890,
     [V_MARK_CONVERT, 0x47436e0, 0x4743700, V_SCAN_HEAD]),
    ('variant_install_tail_objdump.txt', 0x47438e0, 0x474398c,
     [V_NULL_BLOCK, 0x47438ee, 0x4743946, V_TAIL, 0x474396e, 0x474397c]),
    ('hash_bodies_objdump.txt', 0x4744330, 0x474476a,
     [0x4744330, 0x4744380, 0x4744397, 0x4744490, 0x47444eb, 0x4744502,
      0x4744600, 0x474465a, 0x4744671]),
    ('caller_pads_objdump.txt', 0x4747b40, 0x4747b8c,
     [0x4747b5d, 0x4747b77, 0x4747b79, 0x4747b7f, 0x4747b87]),
    ('caller_c_pad_objdump.txt', 0x474bcb4, 0x474bcd3,
     [0x474bcb4, 0x474bcc5, 0x474bcce]),
]
CLASSIFY = {
    'variant_grow': (0x4743350, 0x474398c),
    'hash_a': (0x4744330, 0x4744490),
    'sibling_hasher': (0x4744490, 0x47445fb),
    'hash_b': (0x4744600, 0x474476a),
    'absorb': (0x4744980, 0x4744b57),
}


def _sections(data):
    secs = {}
    for section in sections(data):
        secs.setdefault(section['name'], section)
    return secs


def _reader(secs, data):
    def read(va, count):
        for name in ('.text', '.eh_frame', '.rodata', '.gcc_except_table',
                     '.data.rel.ro', '.data'):
            section = secs.get(name)
            if section is None:
                continue
            start = section['address']
            if section['type'] != 8 and start <= va < start + section['size']:
                offset = section['offset'] + va - start
                return offset, data[offset:offset + count]
        raise ValueError(f'address {va:#x} is not file-backed')
    return read


def _relocations(secs, data):
    rela = secs['.rela.dyn']
    out = {}
    for offset in range(rela['offset'], rela['offset'] + rela['size'], 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, offset)
        out[r_offset] = (r_info & 0xffffffff, r_addend, r_info >> 32)
    return out


def _dynsym_names(secs, data):
    dynsym, dynstr = secs['.dynsym'], secs['.dynstr']
    names = []
    for index in range(dynsym['size'] // 24):
        st_name, _info, _other, _shndx, _value, _size = \
            struct.unpack_from('<IBBHQQ', data,
                               dynsym['offset'] + index * 24)
        end = data.index(b'\0', dynstr['offset'] + st_name)
        names.append(data[dynstr['offset'] + st_name:end].decode())
    return names


def _slot_bytes(site, slot):
    disp = slot - (site + 6)
    return b'\xff\x15' + struct.pack('<i', disp)


def _direct_call(site, target):
    return b'\xe8' + struct.pack('<i', target - (site + 5))


def _iter_pattern(blob, base_va, first):
    """Yield VAs of every occurrence of byte `first` in blob."""
    pos = blob.find(bytes([first]))
    while pos != -1:
        yield base_va + pos
        pos = blob.find(bytes([first]), pos + 1)


def _branch_scan(body, start, targets):
    """Every rel8/rel32 branch in the body whose target is in targets,
    found by a raw byte scan (same method and caveat as the grow-panic
    packet: every returned site is pinned by its full encoding)."""
    found = {}
    for i in range(len(body) - 1):
        va = start + i
        opcode = body[i]
        target = None
        if opcode in (0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                      0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
                      0xeb):
            disp = struct.unpack_from('<b', body, i + 1)[0]
            target = va + 2 + disp
        elif opcode == 0x0f and i + 5 < len(body) and \
                0x80 <= body[i + 1] <= 0x8f:
            disp = struct.unpack_from('<i', body, i + 2)[0]
            target = va + 6 + disp
            if target in targets:
                found[va] = target
            continue
        elif opcode == 0xe9 and i + 4 < len(body):
            disp = struct.unpack_from('<i', body, i + 1)[0]
            target = va + 5 + disp
        if target in targets:
            found[va] = target
    return found


def _uleb(blob, pos):
    result, shift = 0, 0
    while True:
        byte = blob[pos]
        pos += 1
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _decode_lsda(read, lsda_va, fde_start):
    """Decode one LSDA under either header shape the cluster uses
    (ttype encoding 0x9b with a type table, or 0xff with the type
    table omitted); anything else fails closed.  The pinned blob is
    the header plus the call-site table, extended to the type-table
    base when one is declared."""
    _off, blob = read(lsda_va, 0x400)
    pos = 0
    lp_enc = blob[pos]
    pos += 1
    if lp_enc != 0xff:
        raise ValueError('unexpected LSDA lpstart encoding')
    tt_enc = blob[pos]
    pos += 1
    tt_base = None
    if tt_enc == 0x9b:
        tt_off, pos = _uleb(blob, pos)
        tt_base = lsda_va + pos + tt_off
    elif tt_enc != 0xff:
        raise ValueError('unexpected LSDA ttype encoding')
    cs_enc = blob[pos]
    pos += 1
    if cs_enc != 0x01:
        raise ValueError('unexpected LSDA call-site encoding')
    cs_len, pos = _uleb(blob, pos)
    header_end = pos
    entries = []
    end = header_end + cs_len
    while pos < end:
        start_off, pos = _uleb(blob, pos)
        length, pos = _uleb(blob, pos)
        pad_off, pos = _uleb(blob, pos)
        action, pos = _uleb(blob, pos)
        entries.append((fde_start + start_off, length,
                        fde_start + pad_off if pad_off else 0, action))
    if pos != end:
        raise ValueError('LSDA call-site table overruns its length')
    raw = blob[:(tt_base - lsda_va) if tt_base else end]
    return {
        'lsda': hex(lsda_va),
        'lpstart_encoding': lp_enc,
        'ttype_encoding': tt_enc,
        'ttype_base': hex(tt_base) if tt_base else None,
        'call_site_encoding': cs_enc,
        'call_site_table_bytes': cs_len,
        'action_table': hex(lsda_va + end),
        'action_table_head_hex': blob[end:end + 2].hex(),
        'raw_bytes_hex': raw.hex(),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'entries': [{'start': hex(s), 'length': ln,
                     'landing_pad': hex(p) if p else None,
                     'action': a} for s, ln, p, a in entries],
    }, entries


def _covered(entries, site):
    for start, length, pad, _action in entries:
        if start <= site < start + length:
            return pad if pad else None
    return None


def _rip_refs(text_bytes, text_va, targets):
    """Every RIP-relative reference (call/jump/lea/mov/cmp forms) in
    .text resolving to one of targets: {site: target}."""
    found = {}
    i = text_bytes.find(b'\xff')
    while i != -1:
        if i + 5 < len(text_bytes) and text_bytes[i + 1] in (0x15, 0x25):
            site = text_va + i
            disp = struct.unpack_from('<i', text_bytes, i + 2)[0]
            target = site + 6 + disp
            if target in targets:
                found[site] = target
        i = text_bytes.find(b'\xff', i + 1)
    for prefix in (0x48, 0x4c):
        i = text_bytes.find(bytes([prefix]))
        while i != -1:
            if i + 6 < len(text_bytes) and text_bytes[i + 1] in \
                    (0x8d, 0x8b, 0x3b, 0x39) and \
                    (text_bytes[i + 2] & 0xc7) == 0x05:
                site = text_va + i
                disp = struct.unpack_from('<i', text_bytes, i + 3)[0]
                target = site + 7 + disp
                if target in targets:
                    found[site] = target
            i = text_bytes.find(bytes([prefix]), i + 1)
    return found


def _direct_calls(text_bytes, text_va, targets):
    found = {}
    i = text_bytes.find(b'\xe8')
    while i != -1:
        if i + 4 < len(text_bytes):
            site = text_va + i
            disp = struct.unpack_from('<i', text_bytes, i + 1)[0]
            target = site + 5 + disp
            if target in targets:
                found.setdefault(target, []).append(site)
        i = text_bytes.find(b'\xe8', i + 1)
    return found


def analyze(data=None):
    # No whole-file gate here on purpose: every byte a verdict rests
    # on is pinned below by its own extent/SHA-256/census check, so a
    # one-byte counterfactual fails at the specific check it attacks.
    # The test suite pins the whole artifact separately.
    if data is None:
        data = TARGET.read_bytes()
    secs = _sections(data)
    read = _reader(secs, data)
    text = secs['.text']
    text_bytes = data[text['offset']:text['offset'] + text['size']]
    text_va = text['address']
    cies, fde_list = eh_frame_records(data)
    frames = {f['start']: f for f in fde_list}
    relocations = _relocations(secs, data)
    dynsyms = _dynsym_names(secs, data)

    bodies = {}
    specs = {}
    for table, cie_want in ((OWNERS, ZR_CIE), (SETTLED, None),
                            (CALLERS, None), (SHIMS, None)):
        for role, spec in table.items():
            specs[role] = spec
    for role, (start, end, digest) in specs.items():
        _off, blob = read(start, end - start)
        require(hashlib.sha256(blob).hexdigest() == digest,
                f'{role} body bytes changed')
        record = frames[start]
        require(record['end'] == end, f'{role} FDE extent changed')
        bodies[role] = {'start': hex(start), 'end': hex(end),
                        'sha256': digest, 'cie': hex(record['cie']),
                        'lsda': hex(record['lsda']) if record.get('lsda')
                        else None}
    # Frame kinds the verdict relies on.
    for role in OWNERS:
        require(frames[OWNERS[role][0]]['cie'] == ZR_CIE and
                not frames[OWNERS[role][0]].get('lsda'),
                f'{role} must be a plain-zR frame with no LSDA')
    for role, cie in (('map_grow', ZR_CIE), ('sibling_hasher', ZR_CIE),
                      ('absorb', ZR_CIE), ('sibling_grow', ZPLR_CIE),
                      ('map_insert', ZPLR_CIE), ('caller_a', ZPLR_CIE),
                      ('caller_b', ZPLR_CIE), ('caller_c', ZPLR_CIE),
                      ('hash_a_caller_1', ZPLR_CIE),
                      ('hash_a_caller_2', ZPLR_CIE),
                      ('variant_caller_padded', ZPLR_CIE),
                      ('variant_caller_plain', ZR_CIE)):
        require(frames[specs[role][0]]['cie'] == cie,
                f'{role} frame kind changed')
    require(not frames[specs['variant_caller_plain'][0]].get('lsda'),
            'the plain variant caller must have no LSDA')
    # One personality for every personality-bearing family frame.
    require(relocations[PERSONALITY_SLOT][0] == 8 and
            relocations[PERSONALITY_SLOT][1] == 0x5cad7b0,
            'the shared personality slot binding changed')
    for role in LSDAS:
        require(cies[frames[specs[role][0]]['cie']]['personality_slot'] ==
                PERSONALITY_SLOT, f'{role} personality slot changed')

    # Slot bindings.
    slot_bindings = {}
    for slot, target in SLOT_BINDINGS.items():
        require(relocations[slot][0] == 8 and
                relocations[slot][1] == target,
                f'slot {slot:#x} binding changed')
        slot_bindings[hex(slot)] = hex(target)
    glob_slots = {}
    for slot, name in GLOB_SLOTS.items():
        require(relocations[slot][0] == 6 and
                dynsyms[relocations[slot][2]] == name,
                f'slot {slot:#x} must bind {name}')
        glob_slots[hex(slot)] = name

    # Byte pins.
    for site, want, _label in PINS:
        _off, got = read(site, len(bytes.fromhex(want)))
        require(got.hex() == want, f'pinned bytes changed at {site:#x}')
    for site, target, _label in DIRECT_CALL_PINS:
        _off, got = read(site, 5)
        require(got == _direct_call(site, target),
                f'direct call changed at {site:#x}')
    for site, slot, _label in SLOT_CALL_PINS:
        _off, got = read(site, 6)
        require(got == _slot_bytes(site, slot),
                f'slot call changed at {site:#x}')
    for site, (slot, _role) in V_SLOT_CALLS.items():
        _off, got = read(site, 6)
        require(got == _slot_bytes(site, slot),
                f'variant slot call changed at {site:#x}')

    # The variant's failure wiring, from a raw branch scan.
    v_start, v_end, _d = OWNERS['variant_grow']
    _off, v_body = read(v_start, v_end - v_start)
    branches = _branch_scan(v_body, v_start,
                            {V_DISPATCH, V_TAIL, V_TAIL_HALF})
    require(branches == V_FAILURE_BRANCHES,
            'variant failure-branch census changed')
    # The variant's slot-call inventory (raw pattern scan; every site
    # is byte-pinned above, and generate() re-derives the same set
    # from the instruction-exact decode).
    v_slots = {}
    for site, target in _rip_refs(v_body, v_start,
                                  set(SLOT_BINDINGS) | set(GLOB_SLOTS)
                                  ).items():
        v_slots[site] = target
    require(v_slots == {s: slot for s, (slot, _r) in V_SLOT_CALLS.items()},
            'variant slot-call census changed')
    # The variant's direct calls to FDE starts.
    v_direct = {}
    for site in _iter_pattern(v_body, v_start, 0xe8):
        disp = struct.unpack_from('<i', v_body, site - v_start + 1)[0]
        target = site + 5 + disp
        if target in frames:
            v_direct[site] = target
    require(v_direct == {s: OWNERS['hash_b'][0] for s in V_HASH_CALLS},
            'variant direct-call census changed')

    # The panic message and its cluster census.
    _off, message = read(PANIC_MESSAGE_VA, len(PANIC_MESSAGE))
    require(message == PANIC_MESSAGE, 'the panic message text changed')
    _off, guard = read(GUARD_STRING_VA, len(GUARD_STRING))
    require(guard == GUARD_STRING, 'the cleanup-guard string changed')
    lea_sites = {}
    for prefix in (0x48, 0x4c):
        for site in _iter_pattern(text_bytes, text_va, prefix):
            i = site - text_va
            if i + 6 < len(text_bytes) and text_bytes[i + 1] == 0x8d and \
                    (text_bytes[i + 2] & 0xc7) == 0x05:
                disp = struct.unpack_from('<i', text_bytes, i + 3)[0]
                if site + 7 + disp == PANIC_MESSAGE_VA:
                    lea_sites[site] = PANIC_MESSAGE_VA
    cluster_sites = sorted(s for s in lea_sites
                           if CLUSTER[0] <= s < CLUSTER[1])
    require(cluster_sites == [0x4743316, 0x474395b, 0x4743f8f],
            'cluster panic-message lea census changed')

    # SipHash constant blocks shared by the three hash bodies.
    constants = {}
    for va, want in (SIPHASH_CONST_A, SIPHASH_CONST_B):
        _off, got = read(va, 16)
        require(got.hex() == want, 'a SipHash constant block changed')
        constants[hex(va)] = want

    # Binary-wide call censuses.
    direct = _direct_calls(text_bytes, text_va, set(DIRECT_CALL_CENSUS))
    require({t: sorted(s) for t, s in direct.items()} ==
            {t: sorted(s) for t, s in DIRECT_CALL_CENSUS.items()},
            'direct-call census changed')
    home_refs = _rip_refs(text_bytes, text_va, set(HOME_SLOTS))
    require({slot: sorted(s for s, t in home_refs.items() if t == slot)
             for slot in HOME_SLOTS} ==
            {slot: sorted(sites) for slot, sites in HOME_SLOTS.items()},
            'home-slot reference census changed')

    # Address-taken censuses: family VAs as qwords outside .text, and
    # as movabs immediates inside it.
    slot_of = {target: slot for slot, target in SLOT_BINDINGS.items()}
    address_census = {}
    imm64_census = {}
    for va in FAMILY_BODIES + [PANIC_MESSAGE_VA]:
        needle = struct.pack('<Q', va)
        hits = []
        for name, section in secs.items():
            if name == '.text' or section['type'] == 8:
                continue
            blob = data[section['offset']:section['offset'] +
                        section['size']]
            pos = blob.find(needle)
            while pos != -1:
                hits.append([name, hex(section['address'] + pos)])
                pos = blob.find(needle, pos + 1)
        address_census[hex(va)] = hits
        count, pos = 0, text_bytes.find(needle)
        while pos != -1:
            count += 1
            pos = text_bytes.find(needle, pos + 1)
        imm64_census[hex(va)] = count
    for role in ('map_grow', 'variant_grow', 'sibling_grow'):
        start = specs[role][0]
        slot = slot_of[start]
        # The addend field of the body's own .rela.dyn record is the
        # only legal qword occurrence of the body address.
        rela = secs['.rela.dyn']
        index = (slot and [i for i in range(rela['size'] // 24)
                           if struct.unpack_from(
                               '<Q', data, rela['offset'] + i * 24)[0]
                           == slot])
        require(len(index) == 1, 'home relocation not unique')
        expect = [['.rela.dyn', hex(rela['address'] + index[0] * 24 + 16)]]
        require(address_census[hex(start)] == expect,
                f'{role} address occurs outside its relocation record')
    for va in (0x4744330, 0x4744490, 0x4744600, 0x4744980, 0x47425c0,
               0x4742680, PANIC_MESSAGE_VA):
        require(address_census[hex(va)] == [],
                f'address {va:#x} is taken somewhere unexpected')
    require(all(count == 0 for count in imm64_census.values()),
            'a movabs immediate names a family body or the message')

    # LSDA tables and coverage.
    lsda_records, decoded = {}, {}
    for role, (lsda_va, digest, head, entries) in LSDAS.items():
        record, got = _decode_lsda(read, lsda_va, specs[role][0])
        require(record['sha256'] == digest and
                record['action_table_head_hex'] == head and
                got == list(entries), f'{role} LSDA changed')
        lsda_records[role] = record
        decoded[role] = got
    coverage = {}
    for role, sites in COVERAGE.items():
        coverage[role] = {}
        for site, pad in sites.items():
            got = _covered(decoded[role], site)
            require(got == pad, f'{role} coverage changed at {site:#x}')
            coverage[role][hex(site)] = hex(pad) if pad else None

    # The cluster-wide LSDA sweep: no pad anywhere in the band leaves
    # its own body.
    sweep = {'fdes_with_lsda': 0, 'entries': 0, 'landing_pads': 0,
             'pads_outside_own_body': 0}
    for start, record in frames.items():
        if not (CLUSTER[0] <= start < CLUSTER[1]) or \
                not record.get('lsda'):
            continue
        sweep['fdes_with_lsda'] += 1
        _rec, entries = _decode_lsda(read, record['lsda'], start)
        sweep['entries'] += len(entries)
        for _s, _l, pad, _a in entries:
            if pad:
                sweep['landing_pads'] += 1
                if not (start <= pad < record['end']):
                    sweep['pads_outside_own_body'] += 1
    require(sweep == {'fdes_with_lsda': 56, 'entries': 270,
                      'landing_pads': 169, 'pads_outside_own_body': 0},
            'cluster LSDA sweep changed')

    # The neighbouring map body and the sibling-adjacent body touch
    # nothing in the family.
    neighbour = {}
    for start, end in (NEIGHBOUR, (0x4743ff0, 0x4744180)):
        _off, blob = read(start, end - start)
        calls = [hex(s) for s in _iter_pattern(blob, start, 0xe8)
                 if start <= s and
                 s + 5 + struct.unpack_from('<i', blob, s - start + 1)[0]
                 in FAMILY_BODIES]
        slots = [hex(s) for s, t in
                 _rip_refs(blob, start, set(HOME_SLOTS)).items()]
        require(calls == [] and slots == [],
                f'body at {start:#x} touches the family')
        neighbour[hex(start)] = {'direct_calls_to_family': calls,
                                 'family_slot_calls': slots}

    return {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'sha256': SHA},
        'bodies': bodies,
        'slot_bindings': slot_bindings,
        'glob_slots': glob_slots,
        'variant_failure_branches': {hex(s): hex(t) for s, t in
                                     sorted(branches.items())},
        'variant_slot_calls': {hex(s): {'slot': hex(slot), 'role': role}
                               for s, (slot, role) in
                               sorted(V_SLOT_CALLS.items())},
        'variant_direct_calls': {hex(s): hex(t) for s, t in
                                 sorted(v_direct.items())},
        'panic_message': {'va': hex(PANIC_MESSAGE_VA),
                          'cluster_lea_sites': [hex(s) for s in
                                                cluster_sites]},
        'siphash_constants': constants,
        'direct_call_census': {hex(t): [hex(s) for s in sites]
                               for t, sites in
                               sorted(DIRECT_CALL_CENSUS.items())},
        'home_slot_call_census': {hex(slot): [hex(s) for s in sites]
                                  for slot, sites in
                                  sorted(HOME_SLOTS.items())},
        'address_census': address_census,
        'imm64_census': imm64_census,
        'lsda': lsda_records,
        'coverage': coverage,
        'cluster_lsda_sweep': sweep,
        'neighbour_contact': neighbour,
        'personality': {'slot': hex(PERSONALITY_SLOT),
                        'target': hex(0x5cad7b0)},
    }


def behavioral(data=None):
    """Run hash A, the sibling hasher and hash B natively over the
    frozen case stream and compare their complete output streams.

    The three bodies take the same seed in rdi and the key bytes in
    three different argument shapes (hash A: rsi=ptr, rdx=len; the
    hasher: [rsi+8]=ptr, [rsi+0x10]=len; hash B: [rsi]=ptr,
    [rsi+8]=len).  The image span holding the SipHash constants and
    the three bodies plus the absorb is mapped privately from the
    artifact itself, so no initialiser of the original binary runs.
    """
    if data is None:
        data = TARGET.read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA,
            'The pinned node #115 artifact changed')
    secs = _sections(data)
    span_lo, span_hi = SPAN
    image = bytearray(span_hi - span_lo)
    for section in secs.values():
        # Only allocated sections live at their addresses; a
        # non-allocated section (debug, symbol table) has address 0
        # and must never be smeared over the span.
        if section['type'] == 8 or not section['size'] or \
                not (section['flags'] & 0x2) or not section['address']:
            continue
        lo = max(section['address'], span_lo)
        hi = min(section['address'] + section['size'], span_hi)
        if lo < hi:
            off = section['offset'] + lo - section['address']
            image[lo - span_lo:hi - span_lo] = data[off:off + hi - lo]

    rng = random.Random(BEHAVIOR_STREAM_SEED)
    cases = []
    for index in range(BEHAVIOR_CASES):
        length = rng.randrange(0, 289)
        cases.append((index % len(BEHAVIOR_SEEDS),
                      rng.randbytes(length)))

    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    base = libc.mmap(None, span_hi - span_lo, 0x1 | 0x2, 0x2 | 0x20,
                     -1, 0)
    require(base and base != 0xffffffffffffffff, 'span mmap failed')
    try:
        ctypes.memmove(base, bytes(image), len(image))
        require(libc.mprotect(ctypes.c_void_p(base), span_hi - span_lo,
                              0x1 | 0x4) == 0, 'span mprotect failed')

        def fn(va, *argtypes):
            proto = ctypes.CFUNCTYPE(ctypes.c_uint64, *argtypes)
            return proto(base + va - span_lo)

        hash_a = fn(OWNERS['hash_a'][0], ctypes.c_void_p, ctypes.c_void_p,
                    ctypes.c_size_t)
        hasher = fn(SETTLED['sibling_hasher'][0], ctypes.c_void_p,
                    ctypes.c_void_p)
        hash_b = fn(OWNERS['hash_b'][0], ctypes.c_void_p, ctypes.c_void_p)

        seed_buf = ctypes.create_string_buffer(16)
        data_buf = ctypes.create_string_buffer(289 + 32)
        pair = ctypes.create_string_buffer(24)
        data_addr = ctypes.addressof(data_buf)
        streams = {'hash_a': [], 'sibling_hasher': [], 'hash_b': []}
        for seed_index, blob in cases:
            seed = bytes.fromhex(BEHAVIOR_SEEDS[seed_index])
            ctypes.memmove(seed_buf, seed, 16)
            if blob:
                ctypes.memmove(data_buf, blob, len(blob))
            seed_addr = ctypes.addressof(seed_buf)
            streams['hash_a'].append(
                hash_a(seed_addr, data_addr, len(blob)))
            struct.pack_into('<Q', pair, 8, data_addr)
            struct.pack_into('<Q', pair, 16, len(blob))
            streams['sibling_hasher'].append(
                hasher(seed_addr, ctypes.addressof(pair)))
            struct.pack_into('<Q', pair, 0, data_addr)
            struct.pack_into('<Q', pair, 8, len(blob))
            streams['hash_b'].append(
                hash_b(seed_addr, ctypes.addressof(pair)))
    finally:
        libc.munmap(ctypes.c_void_p(base), span_hi - span_lo)

    digests = {}
    for role, outputs in streams.items():
        packed = b''.join(struct.pack('<Q', value) for value in outputs)
        digests[role] = hashlib.sha256(packed).hexdigest()
    require(len(set(digests.values())) == 1,
            'the three hash bodies disagree on the frozen stream')
    return {
        'cases': BEHAVIOR_CASES,
        'stream_seed': BEHAVIOR_STREAM_SEED,
        'seed_set': BEHAVIOR_SEEDS,
        'key_lengths': '0..288 from the frozen stream',
        'span': [hex(span_lo), hex(span_hi)],
        'outputs_sha256': digests,
        'streams_equal': True,
    }


def _objdump(start, end):
    return subprocess.run(
        ['objdump', '-d', '--start-address', hex(start),
         '--stop-address', hex(end), str(TARGET)],
        check=True, capture_output=True, text=True).stdout


def _classify(start, end, data):
    read = _reader(_sections(data), data)
    _off, body = read(start, end - start)
    ins = decode_export(_objdump(start, end), start, end, body)
    calls, branches_outside, divisions, traps = {}, [], [], []
    for va, raw in sorted(ins.items()):
        if raw[0] == 0xe8:
            disp = struct.unpack_from('<i', raw, 1)[0]
            calls[hex(va)] = {'kind': 'direct',
                              'target': hex(va + 5 + disp)}
        elif raw[:2] == b'\xff\x15':
            disp = struct.unpack_from('<i', raw, 2)[0]
            calls[hex(va)] = {'kind': 'slot', 'slot': hex(va + 6 + disp)}
        elif raw[0] in (0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
                        0xeb):
            disp = struct.unpack_from('<b', raw, 1)[0]
            if not (start <= va + 2 + disp < end):
                branches_outside.append(hex(va))
        elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            disp = struct.unpack_from('<i', raw, 2)[0]
            if not (start <= va + 6 + disp < end):
                branches_outside.append(hex(va))
        elif raw[0] == 0xe9:
            disp = struct.unpack_from('<i', raw, 1)[0]
            if not (start <= va + 5 + disp < end):
                branches_outside.append(hex(va))
        if raw[0] in (0xf6, 0xf7) and (raw[1] >> 3) & 7 in (6, 7):
            divisions.append(hex(va))
        if raw[0] == 0xcc or raw[:2] == b'\x0f\x0b' or raw[0] == 0xcd:
            traps.append(hex(va))
    return {'instructions': len(ins), 'calls': calls,
            'branches_outside': branches_outside,
            'divisions': divisions, 'traps': traps}


def generate(out_dir=None):
    data = TARGET.read_bytes()
    records = analyze(data)
    out = Path(out_dir) if out_dir else \
        ROOT / 'research/work-items/RE-015-node115-grow-family-panic-closure'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    classification = {role: _classify(start, end, data)
                      for role, (start, end) in CLASSIFY.items()}
    (out / 'classification.json').write_text(
        json.dumps(classification, indent=1, sort_keys=True) + '\n')
    (out / 'behavior.json').write_text(
        json.dumps(behavioral(data), indent=1, sort_keys=True) + '\n')
    frames_raw = subprocess.run(
        ['readelf', '--debug-dump=frames-interp', str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    extents = {(spec[0], spec[1]) for table in
               (OWNERS, SETTLED, CALLERS, SHIMS) for spec in
               table.values()}
    frame_lines = []
    for line in frames_raw.splitlines():
        match = re.search(r'pc=([0-9a-f]{16})\.\.([0-9a-f]{16})', line)
        if match and (int(match.group(1), 16),
                      int(match.group(2), 16)) in extents:
            frame_lines.append(line)
    require(len(frame_lines) == len(extents),
            'a pinned body is missing from the frame dump')
    (out / 'frames.txt').write_text('\n'.join(frame_lines) + '\n')
    read = _reader(_sections(data), data)
    for name, start, end, sites in WINDOWS:
        output = _objdump(start, end)
        _off, body = read(start, end - start)
        decoded = decode_export(output, start, end, body)
        for site in sites:
            require(site in decoded, f'window site {site:#x} missing')
        # objdump's header names the file it was given; committed evidence
        # must carry the repository-relative path, not this checkout's
        # absolute one.
        (out / name).write_text(output.replace(str(TARGET), TARGET_DISPLAY))
    return records


if __name__ == '__main__':
    generate()
