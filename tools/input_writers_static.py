#!/usr/bin/env python3
"""Trace the first writers of the RE-005 dispatcher derivation inputs.

The limit-writers packet (research/work-items/RE-005-node115-limit-writers,
built from PR #2527) pinned the four top dispatchers -- bulk a `0x2b67e50`,
twin a `0x2b69d20`, bulk b `0x5a64aa0`, twin b `0x5a6a640` -- and left two
questions open.  This packet answers them at the next level out:

1. Who first sets the derivation inputs: the bulk selector bytes
   ([rbx+0x1e8] / [r13+0xc08]), the twin sibling slots (+0x178 / +0xa58),
   the twin source-object fields (tag, start, end) and the incoming limit
   value a downstream stage receives.

2. The writer of the twin-a stage result's +0x28 field (the unanswered
   half of the state-construction packet's question, PR #2501).

Answer shape.  On the a side, every dispatcher caller gives the dispatcher
an object it has just built on its own stack.  The object's tail, from
+0x70 on, is a verbatim copy of a descriptor block inside the caller's
context struct (bulk block 0x4e0 bytes, twin block 0x428 bytes), so the
object offsets map to block offsets shifted by 0x70.  Censusing every
direct access to the mapped struct offsets inside both callers of each
a-side dispatcher shows: the twin source-object pointer IS written by the
twin callers themselves, on one entry arm, as a self-pointer to the
caller's own head triple (struct +0x20..+0x38 receives the struct's first
three qwords), while the bulk selector byte, both sibling slots and both
incoming limits are never stored -- and never even read -- anywhere in
the caller bodies.  They are the incoming contents of the descriptor
blocks.  On the b side, one shared caller initialises only the head
fields of each embedded object; a census over every base register finds
no access at all to the input offsets or to their arena-mapped offsets,
so the inputs are likewise the arena's incoming contents.  The first
writer of the selector bytes, the sibling slots and the incoming limits
therefore sits above the traced window: in whoever fills the caller
context structs' descriptor blocks and the shared arena.

For question 2, the twin-a stage function `0x2e466b0` has exactly one
store to the result's +0x28, at `0x2e46968`, inside the shared store
block at `0x2e46949`.  On the nested-decode arm the stored qword is the
nested decoder `0x2ce1730` result's own +0x28 field, loaded at
`0x2e467a8` and forwarded verbatim through the constructor reloads the
state-construction packet pinned -- plus a third reload at `0x26ff66c`
that packet did not name.  On the marker-byte-zero arm the same store
executes with the register never loaded inside the stage body.

Every fact is mechanical.  Nine functions are pinned by exact FDE
extent, body SHA-256 and per-instruction byte pins; six small bodies
retain full objdump exports, the three large caller bodies are retained
as hash plus pins.  The census tables below are re-derived from fresh
objdump text on every run, and a binary-wide E8 caller census re-derives
the builder, stage and constructor caller sets.  Captured code is never
executed; byte values are recorded exactly as decoded.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import struct
import subprocess
from pathlib import Path

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = (
    'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-input-writers'
OUT = ROOT / 'research/work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'
COPY_SLOT = 0x64DF508

EXPORTED = {
    'caller_twin_a_1', 'caller_twin_a_2', 'builder_twin_a',
    'builder_bulk_a', 'ctor_twin_a', 'stage_twin_a',
}

CALL_TARGETS = {
    'caller_twin_a_1': {0x2AE0454: 0x2B69D20},
    'caller_twin_a_2': {0x2CB20B3: 0x2B146A0, 0x2CB2101: 0x2B69D20},
    'builder_twin_a': {0x2B146C6: 0x5C842E0},
    'builder_bulk_a': {0x2B14546: 0x5C842E0},
    'caller_bulk_a_1': {0x2AD7FF7: 0x2B67E50, 0x2AD9452: 0x2B788E0},
    'caller_bulk_a_2': {0x2CC5265: 0x2B14520, 0x2CC52BF: 0x2B67E50},
    'caller_b_side': {0x5A83698: 0x5A6A640, 0x5A856D1: 0x5A64AA0,
                      0x5A85A2C: 0x5A6A640},
    'ctor_twin_a': {0x26FF308: 0x2E466B0, 0x26FF3B3: 0x2E466B0,
                    0x26FF616: 0x2E466B0},
    'stage_twin_a': {0x2E466C0: 0x2CD79C0, 0x2E46771: 0x2CE1730,
                     0x2E467EA: 0x2DD2980},
}

# Caller-set census subjects: function start -> record name.
CENSUS_SUBJECTS = {
    0x2B146A0: 'builder_twin_a', 0x2B14520: 'builder_bulk_a',
    0x2E466B0: 'stage_twin_a', 0x26FF210: 'ctor_twin_a',
}
EXPECTED_CALLERS = {
    'builder_twin_a': [
        {'containing_fde': '0x2cb1eb0..0x2cb2563', 'site': '0x2cb20b3'}],
    'builder_bulk_a': [
        {'containing_fde': '0x2cc1120..0x2cc971b', 'site': '0x2cc5265'}],
    'stage_twin_a': [
        {'containing_fde': '0x26ff210..0x26ff830', 'site': '0x26ff308'},
        {'containing_fde': '0x26ff210..0x26ff830', 'site': '0x26ff3b3'},
        {'containing_fde': '0x26ff210..0x26ff830', 'site': '0x26ff616'}],
    'ctor_twin_a': [
        {'containing_fde': '0x2b69d20..0x2b6ae9f', 'site': '0x2b6aa53'}],
}

# Direct-access census over each owner body's objdump text.  A zero entry
# means the substring never appears; an exact entry pins the hit count.
ZERO_PATTERNS = {
    'caller_twin_a_1': ['[rbx+0x150]', '[rbx+0x158]',
                        '[rbx+0x5b0]', '[rbx+0x5b8]'],
    'caller_twin_a_2': ['[rbx+0x150]', '[rbx+0x158]',
                        '[rbx+0x5b0]', '[rbx+0x5b8]'],
    'caller_bulk_a_1': ['[rbx+0x210]', '[rbx+0x248]', '[rbx+0x730]',
                        '[r14+0x178]', '[r14+0x1b0]'],
    'caller_bulk_a_2': ['[r15+0x2c8]', '[r15+0x300]',
                        '[r15+0x7b0]', '[r15+0x7e8]',
                        '[r12+0x178]', '[r12+0x1b0]'],
    'caller_b_side': ['+0xc08]', '+0xc40]', '+0x958]', '+0xa58]',
                      '+0xa60]', '[rbx+0x2900]', '[rbx+0x2a00]',
                      '[rbx+0x2a08]', '[rbx+0xeb8]', '[rbx+0xef0]',
                      '[rbx+0xc18]', '[rbx+0xd18]', '[rbx+0xd20]'],
    'builder_twin_a': [], 'builder_bulk_a': [], 'ctor_twin_a': [],
    'stage_twin_a': ['XMMWORD PTR [rbx+0x20]', 'XMMWORD PTR [rbx+0x28]'],
}
EXACT_COUNTS = {
    'caller_bulk_a_1': {'[rbx+0x6f8]': 1},
    'stage_twin_a': {'[rbx+0x28]': 1},
    'ctor_twin_a': {'[rsp+0x38]': 5},
}

DISPATCHERS = {
    'bulk_a': {
        'entry': '0x2b67e50', 'limit_field': '+0x220',
        'selector_byte': '+0x1e8',
        'call_sites': [
            {'site': '0x2ad7ff7', 'caller': '0x2ad7140..0x2adce3a',
             'object': 'caller struct (entry rsi, rbx) + 0xa80',
             'object_image_bytes': '0x550',
             'image': 'stack image built inline: a 0x70-byte head, '
                      'then the caller block copied to image +0x70',
             'block': '0x4e0 bytes at struct +0x98, duplicated to '
                      'struct +0x580 before the stack copies',
             'selector_struct_offset': '+0x210',
             'incoming_limit_struct_offset': '+0x248'},
            {'site': '0x2cc52bf', 'caller': '0x2cc1120..0x2cc971b',
             'object': 'caller struct (entry rsi, r15) + 0xb38',
             'object_image_bytes': '0x550',
             'image': 'stack image built by builder 0x2b14520 from '
                      'the caller block',
             'block': '0x4e0 bytes at struct +0x150, duplicated to '
                      'struct +0x638, then copied twice on the stack',
             'selector_struct_offset': '+0x2c8',
             'incoming_limit_struct_offset': '+0x300'}],
        'first_writer': 'no direct store to -- and no read of -- the '
                        'selector byte or the incoming limit exists in '
                        'either caller body; both arrive as the '
                        'incoming contents of the caller struct block '
                        '(block offsets +0x178 and +0x1b0), so the '
                        'writer is whoever fills the blocks, above '
                        'the traced window'},
    'twin_a': {
        'entry': '0x2b69d20', 'limit_field': '+0x180',
        'sibling_slot': '+0x178', 'source_pointer': '+0x78',
        'call_sites': [
            {'site': '0x2ae0454', 'caller': '0x2ae0100..0x2ae0917',
             'object': 'caller struct (entry rsi, rbx) + 0x8e0',
             'object_image_bytes': '0x498',
             'image': 'stack image built inline: a 0x70-byte head, '
                      'then the caller block copied to image +0x70',
             'block': '0x428 bytes at struct +0x48, duplicated to '
                      'struct +0x4a8 before the stack copies',
             'source_pointer_struct_offset': '+0x50',
             'sibling_struct_offset': '+0x150',
             'incoming_limit_struct_offset': '+0x158'},
            {'site': '0x2cb2101', 'caller': '0x2cb1eb0..0x2cb2563',
             'object': 'caller struct (entry rsi, rbx) + 0x8e0',
             'object_image_bytes': '0x498',
             'image': 'stack image built by builder 0x2b146a0 from '
                      'the caller block',
             'block': '0x428 bytes at struct +0x48, duplicated to '
                      'struct +0x4a8, then copied twice on the stack',
             'source_pointer_struct_offset': '+0x50',
             'sibling_struct_offset': '+0x150',
             'incoming_limit_struct_offset': '+0x158'}],
        'source_object': 'the source pointer is the one input the '
                         'callers write themselves: on the first entry '
                         'arm, both callers store struct +0x20 into '
                         'the block pointer slot (struct +0x50) and '
                         'copy the struct head triple into +0x20 '
                         '(tag), +0x28 (start) and +0x30 (end), so '
                         'the source tag/start/end are the caller '
                         "struct's own first three qwords; on the "
                         'other entry arm the pointer keeps its '
                         'incoming block value',
        'first_writer': 'the sibling slot and the incoming limit are '
                        'never stored -- and never even read -- in '
                        'either caller body, nor through the '
                        'duplicate-block aliases; they are the '
                        "block's incoming values at struct +0x150 "
                        'and +0x158'},
    'bulk_b': {
        'entry': '0x5a64aa0', 'limit_field': '+0xc40',
        'selector_byte': '+0xc08',
        'call_sites': [
            {'site': '0x5a856d1', 'caller': '0x5a82670..0x5a89535',
             'object': 'shared arena (entry rsi, rbx) + 0x2b0; the '
                       'caller initialises only head fields at the '
                       'call, there is no image copy',
             'selector_arena_offset': '+0xeb8',
             'incoming_limit_arena_offset': '+0xef0'}],
        'first_writer': 'no access to the selector byte or the '
                        'incoming limit exists anywhere in the caller '
                        'body, through any base register; both are '
                        'the arena\'s incoming contents, written '
                        'above the traced window'},
    'twin_b': {
        'entry': '0x5a6a640', 'limit_field': '+0xa60',
        'sibling_slot': '+0xa58', 'source_pointer': '+0x958',
        'call_sites': [
            {'site': '0x5a83698', 'caller': '0x5a82670..0x5a89535',
             'object': 'shared arena (entry rsi, rbx) + 0x1fa8',
             'source_pointer_arena_offset': '+0x2900',
             'sibling_arena_offset': '+0x2a00',
             'incoming_limit_arena_offset': '+0x2a08'},
            {'site': '0x5a85a2c', 'caller': '0x5a82670..0x5a89535',
             'object': 'shared arena (entry rsi, rbx) + 0x2c0',
             'source_pointer_arena_offset': '+0xc18',
             'sibling_arena_offset': '+0xd18',
             'incoming_limit_arena_offset': '+0xd20'}],
        'first_writer': 'no access to the source pointer, the sibling '
                        'slot or the incoming limit exists anywhere '
                        'in the caller body, through any base '
                        'register; all three are the arena\'s '
                        'incoming contents, written above the '
                        'traced window'},
}

IMAGE_BUILDERS = {
    'builder_twin_a': {
        'entry': '0x2b146a0', 'sole_call_site': '0x2cb20b3',
        'block_bytes': '0x428',
        'behaviour': 'copies the caller block verbatim to image +0x70 '
                     'through the copy slot and builds the 0x70-byte '
                     'head from a slot-call result pair and constants; '
                     'it writes no input offset directly'},
    'builder_bulk_a': {
        'entry': '0x2b14520', 'sole_call_site': '0x2cc5265',
        'block_bytes': '0x4e0',
        'behaviour': 'copies the caller block verbatim to image +0x70 '
                     'through the copy slot and builds the 0x70-byte '
                     'head from a slot-call result pair and constants; '
                     'it writes no input offset directly'},
}

TWIN_A_RESULT_0X28 = {
    'field': 'twin-a stage result +0x28',
    'writer': 'the stage function 0x2e466b0 (0x2e466b0..0x2e469a9) '
              'itself, at its sole +0x28 store 0x2e46968 inside the '
              'shared result store block at 0x2e46949',
    'defined_value_arm': 'first decoder result discriminant 2 and '
                         'state cursor marker byte 1: the nested '
                         'decoder 0x2ce1730 runs on the state '
                         '(call 0x2e46771) and, when its result tag '
                         'is not 2, the stored qword is the nested '
                         "result's own +0x28 field, loaded at "
                         '0x2e467a8 and forwarded verbatim',
    'marker_zero_arm': 'the same store executes when the marker byte '
                       'is 0 (result tag forced to 2 at 0x2e46943), '
                       'but the stored register is never loaded '
                       'anywhere in the stage body on that arm, so '
                       'the value is not determined inside the stage',
    'other_arms': 'the first-result copy arm, the discriminant-0 '
                  'arms, the discriminant-1 arm through the twin '
                  'wrapper 0x2dd2980 and the error arms through the '
                  'store block at 0x2e4697b never store +0x28',
    'consumers': 'the constructor 0x26ff210 reloads its limit '
                 'register from the stage result +0x28 slot at '
                 '0x26ff330, 0x26ff3fd and 0x26ff66c (the third '
                 'reload is new here) whenever the result tag is not '
                 '5, and stores it to the saved and final record '
                 '+0x28 slots at 0x26ff357, 0x26ff424, 0x26ff480 '
                 'and 0x26ff68d',
    'next_level': 'what writes the nested decoder 0x2ce1730 '
                  "result's +0x28 field, which the stage forwards, "
                  'is the next question down',
}
OWNERS = {
 'caller_bulk_a_1': ('0x2ad7140', '0x2adce3a',
            'eab07e49a79bfe3de2f5e51d312ef9163f4a5f78f04240982b6a3e5b9c922e7e'),
 'caller_bulk_a_2': ('0x2cc1120', '0x2cc971b',
            '3efcb009eaf0ab2e2a477d73edbf7834894109e9fdcd943460d2bce59b9a0c57'),
 'caller_twin_a_1': ('0x2ae0100', '0x2ae0917',
            '17ba33c03bd1b37e26619290295566665c7d760d7de93ebb1929f4fb7311a5f9'),
 'caller_twin_a_2': ('0x2cb1eb0', '0x2cb2563',
            '4606344649429fe2625ca1780a562e7049d7ec4281aac77199715c2a0ecfb7d0'),
 'builder_twin_a': ('0x2b146a0', '0x2b14816',
            '2cfe7b7421563522e8f17cb6ae0e74c3689d0815690776a7b89a40ed9610a31c'),
 'builder_bulk_a': ('0x2b14520', '0x2b14696',
            '5f1fb5091cde76fb59571f6934060d996e09c0c44238bfe9971d53ed5908deb0'),
 'caller_b_side': ('0x5a82670', '0x5a89535',
            '993bd9a168f2e37e4cdc80092c5ea5e68a3bc0225098621c57e89fccb7bf57fc'),
 'ctor_twin_a': ('0x26ff210', '0x26ff830',
            'b96ec36847823c98c649950413f331a366379f343daa14bfd7606d1c70591923'),
 'stage_twin_a': ('0x2e466b0', '0x2e469a9',
            'e83dbe8a5a053e1c87c7d7ca300a681891cb1a58bf2ac5303c8acc01159ca8e1')}
FRAMES = {
 'caller_bulk_a_1': {'fde': {'va': '0x117c1fc', 'bytes_hex': '54000000fceb13003caf9501fa5c000004931b0eff410e10420e18420e20420e28420e30410e38470eb8204f0eb03283078c068d058e048f038602039d4c0e38410e30420e28420e20420e18420e10410e08410eb0320000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'caller_bulk_a_2': {'fde': {'va': '0x1196e60', 'bytes_hex': '5800000060981500b8a2b201fb8500000457f30dff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0ea04383078c068d058e048f03860203ee810e38410e30420e28420e20420e18420e10410e08410ea0430000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'caller_twin_a_1': {'fde': {'va': '0x117c2a8', 'bytes_hex': '50000000a8ec1300503e96011708000004cf220eff410e10420e18420e20420e28420e30410e38470e801e83078c068d058e048f038602039d060e38410e30420e28420e20420e18420e10410e08410e801e0000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'caller_twin_a_2': {'fde': {'va': '0x11967dc', 'bytes_hex': '54000000dc911500ccb6b101b3060000043bea0dff410e10420e18420e20420e28420e30410e38470eb8204f0e802683078c068d058e048f0386020373050e38410e30420e28420e20420e18420e10410e08410e80260000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'builder_twin_a': {'fde': {'va': '0x117d974', 'bytes_hex': '5000000074031400246d99017601000004e7420eff410e10420e18420e20420e28420e30410e38470ec00183078c068d058e048f0386020314010e38410e30420e28420e20420e18420e10410e08410ec0010000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'builder_bulk_a': {'fde': {'va': '0x117d920', 'bytes_hex': '5000000020031400f86b990176010000040f430eff410e10420e18420e20420e28420e30410e38470ec00183078c068d058e048f0386020314010e38410e30420e28420e20420e18420e10410e08410ec0010000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'caller_b_side': {'fde': {'va': '0x13aa93c', 'bytes_hex': '5c0000003cd336002c7d6d04c56e000004f3fc03ff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb07f83078c068d058e048f038602031a620e38410e30420e28420e20420e18420e10410e08410eb07f0000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'ctor_twin_a': {'fde': {'va': '0x1132a60', 'bytes_hex': '5000000060540f00a8c75c01200600000433de0fff410e10420e18420e20420e28420e30410e38470eb00283078c068d058e048f03860203d4020e38410e30420e28420e20420e18420e10410e08410eb0020000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'stage_twin_a': {'fde': {'va': '0xd9964c', 'bytes_hex': '2800000078270f005cd00a02f902000000420e10410e18440e900183038e0203ee020e18410e10420e080000'}, 'cie': {'va': '0xca6ed8', 'bytes_hex': '1400000000000000017a5200017810011b0c070890010000'}}}
PINS = {
 'caller_twin_a_1': [
     (17, '4889f3', 'object struct register rbx is the entry rsi'),
     (55, '488d4b20', 'lea of the source-object base at struct +0x20 into rcx'),
     (62, '0f114320', 'arm-1 store copying the struct head pair to +0x20 (source tag and start)'),
     (70, '48895330', 'arm-1 store copying the struct +0x10 qword to +0x30 (source end)'),
     (102, '48894348', 'arm-1 store of the saved head qword at block +0x0 (struct +0x48)'),
     (106, '48894b50', 'arm-1 store at block +0x8 (struct +0x50): the source-object pointer slot'),
     (246, '488d7348', 'lea of the block at struct +0x48 for block copy 1'),
     (264, '488dbba8040000', 'lea of the duplicate block at struct +0x4a8 for block copy 1'),
     (271, 'ba28040000', 'block copy length 0x428'),
     (276, 'ff15eef29f03', 'block copy 1 call through the copy slot'),
     (346, '488dbc24a00a0000', 'lea of the stack block buffer for block copy 2'),
     (359, 'ff159bf29f03', 'block copy 2 call through the copy slot'),
     (806, '488dbbe0080000', 'lea of the dispatcher object at struct +0x8e0 for the final image copy'),
     (821, 'ba98040000', 'image copy length 0x498'),
     (849, '4c89f6', 'dispatcher object register rsi is r14 (struct +0x8e0)')],
 'caller_twin_a_2': [
     (32, '4889f3', 'object struct register rbx is the entry rsi'),
     (68, '488d4b20', 'lea of the source-object base at struct +0x20 into rcx'),
     (75, '0f114320', 'arm-1 store copying the struct head pair to +0x20 (source tag and start)'),
     (83, '48895330', 'arm-1 store copying the struct +0x10 qword to +0x30 (source end)'),
     (115, '48894348', 'arm-1 store of the saved head qword at block +0x0 (struct +0x48)'),
     (119, '48894b50', 'arm-1 store at block +0x8 (struct +0x50): the source-object pointer slot'),
     (257, '488d7348', 'lea of the block at struct +0x48 for block copy 1'),
     (275, '488dbba8040000', 'lea of the duplicate block at struct +0x4a8 for block copy 1'),
     (287, 'ff1533d58203', 'block copy 1 call through the copy slot'),
     (357, '488dbc24a00e0000', 'lea of the stack block buffer for block copy 2'),
     (370, 'ff15e0d48203', 'block copy 2 call through the copy slot'),
     (512, '4c89e1', 'builder block argument rcx is the stack block copy'),
     (554, '488dbbe0080000', 'lea of the dispatcher object at struct +0x8e0 for the final image copy'),
     (575, '488dabe0080000', 'lea of the dispatcher object at struct +0x8e0 into rbp'),
     (590, '4889ee', 'dispatcher object register rsi is rbp (struct +0x8e0)')],
 'builder_twin_a': [
     (20, '48890c24', 'block pointer saved from rcx'),
     (176, '4889442418', 'head qword store from the slot-call result pair'),
     (186, '48c744242802000000', 'head constant 2 store'),
     (195, '498d7e70', 'lea of image +0x70 for the block copy'),
     (199, 'ba28040000', 'block copy length 0x428'),
     (208, 'ff1592ad9c03', 'block copy call through the copy slot'),
     (234, '410f1106', 'head copy to image +0x0')],
 'builder_bulk_a': [
     (20, '48890c24', 'block pointer saved from rcx'),
     (176, '4889442418', 'head qword store from the slot-call result pair'),
     (186, '48c744242802000000', 'head constant 2 store'),
     (195, '498d7e70', 'lea of image +0x70 for the block copy'),
     (199, 'bae0040000', 'block copy length 0x4e0'),
     (208, 'ff1512af9c03', 'block copy call through the copy slot'),
     (234, '410f1106', 'head copy to image +0x0')],
 'caller_bulk_a_1': [
     (3076, '899308020000', 'neighbour dword store at block +0x170 (struct +0x208), not an input field'),
     (3144, '488db398000000', 'lea of the block at struct +0x98 for block copy 1'),
     (3151, '4c8db380050000', 'lea of the duplicate block at struct +0x580 for block copy 1'),
     (3158, 'bae0040000', 'block copy length 0x4e0'),
     (3166, 'ff156477a003', 'block copy 1 call through the copy slot'),
     (3237, '488dbc24f0120000', 'lea of the stack block buffer for block copy 2'),
     (3258, 'ff150877a003', 'block copy 2 call through the copy slot'),
     (3562, '488dbc24c0030000', 'lea of the image tail for the stack block copy'),
     (3590, '41ffd6', 'image tail copy call through r14 (the copy slot)'),
     (3713, '488dbb800a0000', 'lea of the dispatcher object at struct +0xa80 for the final image copy'),
     (3728, 'ba50050000', 'image copy length 0x550'),
     (3749, '4c8da3800a0000', 'lea of the dispatcher object at struct +0xa80 into r12'),
     (3764, '4c89e6', 'dispatcher object register rsi is r12 (struct +0xa80)'),
     (8918, '8893f8060000', 'byte store at struct +0x6f8 in the separate record phase (parse-helper record at +0x6c0), not on the call path')],
 'caller_bulk_a_2': [
     (16365, '418997c0020000', 'neighbour dword store at block +0x170 (struct +0x2c0), not an input field'),
     (16445, '498db750010000', 'lea of the block at struct +0x150 for block copy 1'),
     (16452, '4d8da738060000', 'lea of the duplicate block at struct +0x638 for block copy 1'),
     (16467, 'ff158fa38103', 'block copy 1 call through the copy slot'),
     (16541, '488dbc24b0160000', 'lea of the stack block buffer for block copy 2'),
     (16562, 'ff1530a38103', 'block copy 2 call through the copy slot'),
     (16656, '4c8db424c00e0000', 'lea of the second stack block copy for the builder'),
     (16680, 'ff15baa28103', 'block copy 3 call through the copy slot'),
     (16706, '4c89f1', 'builder block argument rcx is the stack block copy'),
     (16748, '498dbf380b0000', 'lea of the dispatcher object at struct +0xb38 for the final image copy'),
     (16776, '498daf380b0000', 'lea of the dispatcher object at struct +0xb38 into rbp'),
     (16791, '4889ee', 'dispatcher object register rsi is rbp (struct +0xb38)')],
 'caller_b_side': [
     (4072, '48c783a81f000000000000', 'twin_b object 1 head store at +0x0 (arena +0x1fa8)'),
     (4083, '488983b01f0000', 'twin_b object 1 head store at +0x8 (arena +0x1fb0)'),
     (4090, '488993b81f0000', 'twin_b object 1 head store at +0x10 (arena +0x1fb8)'),
     (4097, '48898bc01f0000', 'twin_b object 1 head store at +0x18 (arena +0x1fc0)'),
     (4111, '4c8da3a81f0000', 'lea of twin_b object 1 at arena +0x1fa8'),
     (4129, '4c89e6', 'twin_b object 1 register rsi is r12'),
     (12327, '4889b3b8020000', 'bulk_b head store at object +0x8 (arena +0x2b8)'),
     (12334, '8993c0020000', 'bulk_b head store at object +0x10 (arena +0x2c0)'),
     (12360, '488dabb0020000', 'lea of the bulk_b object at arena +0x2b0'),
     (12378, '4889ee', 'bulk_b object register rsi is rbp'),
     (13153, '8983b0020000', 'head store at arena +0x2b0 beside twin_b object 2'),
     (13197, '48c783c002000001000000', 'twin_b object 2 tag store at object +0x0 (arena +0x2c0)'),
     (13208, '4889abd8020000', 'twin_b object 2 head store at +0x18 (arena +0x2d8)'),
     (13226, '4c8dabc0020000', 'lea of twin_b object 2 at arena +0x2c0'),
     (13241, '4c89ee', 'twin_b object 2 register rsi is r13')],
 'ctor_twin_a': [
     (20, '4989cd', 'limit register r13 is the entry rcx'),
     (212, '48c744247001000000', 'site 1 state mode store: immediate 1'),
     (221, '4c896c2478', 'site 1 state limit store from r13'),
     (288, '4c8b6c2438', 'first reload of r13 from the stage result +0x28 slot'),
     (327, '4c89ac24c0000000', 'first reloaded value stored to the saved record +0x28 slot'),
     (493, '4c8b6c2438', 'second reload of r13 from the stage result +0x28 slot'),
     (532, '4c89ac24c0000000', 'second reloaded value stored to the saved record +0x28 slot'),
     (624, '4c896c2438', 'final record +0x28 store from r13'),
     (985, '48c784249800000001000000', 'site 3 state mode store: immediate 1'),
     (997, '4c89ac24a0000000', 'site 3 state limit store from r13'),
     (1116, '4c8b6c2438', 'third reload of r13 from the stage result +0x28 slot'),
     (1149, '4c896c2438', 'third reloaded value stored to the final record +0x28 slot')],
 'stage_twin_a': [
     (7, '4989f6', 'state register r14 is the entry rsi'),
     (10, '4889fb', 'result register rbx is the entry rdi'),
     (33, '8b442404', 'stage discriminant load from the first decoder result'),
     (54, '83f802', 'stage discriminant compare with 2'),
     (248, '4c8b5c2428', 'nested result +0x28 load into r11'),
     (659, '41ba02000000', 'marker-zero arm sets the result tag 2 before the shared store block'),
     (696, '4c895b28', 'the sole stage-result +0x28 store'),
     (715, '40887308', 'first store of the result block that never writes +0x28')]}


LIMITS = (
    'Static trace only: no captured instruction was executed and no '
    'concrete input values were observed.  The access census covers '
    'direct accesses in the nine pinned bodies through the struct or '
    'arena register and the pinned block-alias registers; whole-block '
    'copies move the input bytes without naming them, so for the '
    'copied fields the census is a statement about direct accesses in '
    'the traced bodies, not about the copies.  The copy target at '
    f'slot {COPY_SLOT:#x} is identified by argument shape only.  Who '
    'fills the a-side caller structs\' descriptor blocks and the '
    'b-side shared arena sits above the traced window; the nested '
    'decoder 0x2ce1730\'s own +0x28 writer sits below it.  Raw values '
    'are recorded mechanically; no field types are guessed.')


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
    return records


def check_call(data, va, target):
    disp = struct.unpack('<i', read(va + 1, data, 4)[1])[0]
    check(read(va, data, 1)[1] == b'\xe8' and va + 5 + disp == target,
          f'call target mismatch at {va:#x}')


def check_call_targets(data):
    for role, mapping in CALL_TARGETS.items():
        for va, target in mapping.items():
            check_call(data, va, target)


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


def access_census(data):
    records = {}
    for role in OWNERS:
        text = objdump_text(data, role)
        zero, exact = {}, {}
        for pattern in ZERO_PATTERNS[role]:
            count = text.count(pattern)
            check(count == 0,
                  f'census pattern {pattern} hit in {role}: {count}')
            zero[pattern] = 0
        for pattern, want in EXACT_COUNTS.get(role, {}).items():
            count = text.count(pattern)
            check(count == want,
                  f'census count {pattern} in {role}: {count} != {want}')
            exact[pattern] = count
        records[role] = {'zero_patterns': zero, 'exact_counts': exact}
    return records


def exports(data, role):
    start, end = OWNERS[role][0], OWNERS[role][1]
    text = subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
         '--start-address', start, '--stop-address', end, str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def caller_census(data):
    _, fdes, _ = fde_extents(data)
    ordered = sorted((f['start'], f['end']) for f in fdes)
    starts = [s for s, _ in ordered]

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and ordered[i][0] <= va < ordered[i][1]:
            return f'{ordered[i][0]:#x}..{ordered[i][1]:#x}'
        return None

    text_sec = next(s for s in sections(data) if s['name'] == '.text')
    base, off, size = (text_sec['address'], text_sec['offset'],
                       text_sec['size'])
    body = bytes(data[off:off + size])
    calls = {name: [] for name in CENSUS_SUBJECTS.values()}
    i = body.find(b'\xe8')
    while i != -1:
        va = base + i
        target = va + 5 + struct.unpack_from('<i', body, i + 1)[0]
        if target in CENSUS_SUBJECTS:
            calls[CENSUS_SUBJECTS[target]].append(
                {'site': hex(va), 'containing_fde': containing(va)})
        i = body.find(b'\xe8', i + 1)
    lea_refs = {name: [] for name in CENSUS_SUBJECTS.values()}
    for prefix in (b'\x48\x8d', b'\x4c\x8d'):
        j = body.find(prefix)
        while j != -1:
            if j + 7 <= size:
                target = (base + j + 7 +
                          struct.unpack_from('<i', body, j + 3)[0])
                if target in CENSUS_SUBJECTS:
                    lea_refs[CENSUS_SUBJECTS[target]].append(hex(base + j))
            j = body.find(prefix, j + 1)
    lea_refs = {k: sorted(set(v)) for k, v in lea_refs.items()}
    for name, sites in calls.items():
        check(sites == EXPECTED_CALLERS[name],
              f'caller census mismatch for {name}: {sites}')
        check(lea_refs[name] == [], f'lea reference to {name}')
    return {'direct_call_sites': calls, 'lea_references': lea_refs}


def analyze(data=None):
    data = TARGET.read_bytes() if data is None else data
    owner_records = owners(data)
    pin_records = check_pins(data)
    check_call_targets(data)
    census = caller_census(data)
    access = access_census(data)
    return {
        'artifact': {
            'path': 'artifacts/node/115/hl-node', 'size': TARGET_SIZE,
            'sha256': TARGET_SHA256},
        'packet': WORK_ITEM,
        'captured_code_executed': False,
        'copy_slot': hex(COPY_SLOT),
        'owners': owner_records,
        'pins': pin_records,
        'call_census': census,
        'access_census': access,
        'dispatchers': DISPATCHERS,
        'image_builders': IMAGE_BUILDERS,
        'twin_a_result_0x28': TWIN_A_RESULT_0X28,
        'boundaries': {
            'first_writer_of_selector_sibling_and_incoming_limit':
                'above the traced window: whoever fills the a-side '
                'caller context structs\' descriptor blocks and the '
                'b-side shared arena',
            'stage_result_0x28_chain_bottom':
                'the nested decoder 0x2ce1730 result +0x28 writer, '
                'not traced here'},
        'limits': LIMITS,
    }


def generate():
    data = TARGET.read_bytes()
    OUT.mkdir(parents=True, exist_ok=True)
    payload = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(payload, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines(data)))
    for role in sorted(EXPORTED):
        (OUT / f'{role}.objdump.txt').write_text(exports(data, role))
    print(f'wrote packet payloads to {OUT}')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--generate', action='store_true')
    args = parser.parse_args()
    if args.generate:
        generate()
    else:
        print(json.dumps(analyze(), indent=1, sort_keys=True))
