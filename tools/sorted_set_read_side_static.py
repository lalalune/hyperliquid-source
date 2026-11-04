#!/usr/bin/env python3
"""Trace the read side of the node 115 forward-2 sorted set.

RE-006's forward-callee packet proved forward_2 (0x51d1b00) is a
sorted-set insert over a B-tree node layout shared with the split
helper: handle {root at +0x0, height at +0x8, total at +0x10};
node {parent at +0x0, sorted qword keys from +0x8 (at most 11),
child-index word at +0x60, count word at +0x62, child edges from
+0x68}; leaf nodes are 0x68 bytes, internal nodes 0xc8.  In the
book record the set handle sits at record + 0x40, next to the
forward-1 map at record + 0x0.  This packet answers the remaining
question: who consumes the set's member keys on the read side,
and whether a member key is ever read back as a value.

Method: census first.  An instruction-start-validated scan of
every FDE body for the walk signature (count-word load at +0x62,
child-edge load at +0x68 with scale 8, key compare at +0x10 with
scale 8, seta/sbb three-way branch) finds 126 carrier FDEs.
Among FDEs of at most 350 bytes the signature carriers are
exactly sixteen: three byte-identical find clones, one boolean
contains, two byte-identical cursor searches, and ten remove
bodies.  Everything larger is a consumer with an inlined walk or
a writer; the read side of this set instance is the five owners
below plus the inlined walks named in the boundaries.

Owners (the standalone readers and the two lead consumers):
- find 0x51d1a80..0x51d1afb (123 bytes): walks the layout for a
  key taken by pointer, returns node + 0x64 on a hit and 0 on a
  miss or an empty handle.  Three byte-identical clones exist
  (0x243ca40, 0x39007b0); the seven call sites between them use
  the result only as a null test (test %rax,%rax at a pinned
  instruction start after every call) and never dereference it.
- contains 0x243d260..0x243d309 (169 bytes): a boolean probe
  over the same layout with the key passed by value, unique in
  the binary.  Its only two callers are the consumer parents
  0x23ebea0 / 0x23f0a80, which pass the set handle as a slab
  lookup result + 0x40 - the same +0x40 handle the insert and
  remove paths use.  On a miss it materialises a five-qword
  cursor record {handle, key, final node, 0, final position},
  calls 0x26d4b60 with it, and returns 0.
- remove 0x51d5010..0x51d5121 (273 bytes): walks for a key taken
  by pointer; on a hit it builds a {node, height, position}
  cursor, calls the node-remove helper 0x4d2fe70, decrements
  the handle total at +0x10, promotes child 0 if the root
  emptied, and returns 1 (0 when absent).  Its only callers are
  the four book remove consumers that also call the forward-1
  map remove.  Nine sibling remove bodies serve other clusters.
- consumer_a 0x23e4340..0x23e47d3 (1,171 bytes): probes the
  forward-1 map inlined (length-1 fast path, otherwise the
  scrambled-hash helper 0x26f5c10), and on the map-miss side
  resolves a record through a second tree and walks the set
  inlined (root and height arrive as arguments) for the qword
  at that record + 0x28.  A set hit only reaches a gated log
  call (global flag dword at 0x64f01d8 must be nonzero); a set
  miss calls the two map-side helpers 0x23d4140 / 0x23cdb30
  with the same key.  Member keys are only compared, never
  loaded as values.
- consumer_b 0x23e4c80..0x23e58e5 (3,173 bytes): #2478's
  inlined map consumer.  It also traverses the set in order:
  descending child edges (+0x68), ascending via the parent
  (+0x0) and the child-index word (+0x60), bounding the index
  by the count word (+0x62), and loading each member key at
  node + 0x8 + index * 8 (pin at 0x23e542c).  Each member key
  is used as a key for an inlined forward-1 map probe (the
  length-1 entry-key compare, otherwise the scrambled hash
  0xf1357aea2e62a9c5), the map value supplies the slab slot
  index, the slab order copy is read, a numeric test is
  applied, and one 0x20-byte record per passing member is
  appended to an output vector.  The traversal frees every
  node it ascends from through the allocator slot 0x64df4a0.

Read-back verdict: no point reader (find, contains, remove, or
consumer_a's probe) ever loads a member key as a value; keys
are only compared against the probe key, and find's non-null
return is a node pointer used purely as a boolean.  The one
place a member key is loaded as a value is consumer_b's
traversal, and there it is consumed as a lookup key into the
forward-1 map - the slab slot index always comes from the
map's value slot, never from the member itself.

Every cited byte is pinned and validated as a native
instruction start; the reference censuses are re-derived from
raw scans and every E8 site is re-validated as an instruction
start inside its containing FDE.
"""

import hashlib
import json
import os
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

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = (ROOT / 'research/work-items'
          / 'RE-006-node115-sorted-set-read-side')
EXPECTED_SHA256 = (
    'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
TEXT_FILE_OFFSET_DIFFERENCE = 0x1000
FREE_SLOT = 0x64df4a0
FREE_TARGET = 0x635de30
LOG_SLOT = 0x64df9f0
SET_FLAG = 0x64f01d8

OWNERS = {
    'find': {
        'range': (0x51d1a80, 0x51d1afb),
        'sha256': '46b83804c37ee1e4667c35161e74896eb3d3f11f3b'
                  '46bed08b5ad3a21b6e3bc0',
        'pins': {
            0x51d1a80: '488b0f',        # root = handle[0]
            0x51d1a88: '488b5708',      # height = handle + 0x8
            0x51d1a8c: '488b36',        # key value = *key_ptr
            0x51d1a91: '440fb74162',    # count word at node + 0x62
            0x51d1ab5: '483b74f910',    # key compare at +0x10 scale 8
            0x51d1ae9: '488b4cf968',    # child edge at +0x68 scale 8
            0x51d1af0: '4883c164',      # found: return node + 0x64
            0x51d1af8: '31c0',          # miss: return 0
        },
        'calls': {},
    },
    'contains': {
        'range': (0x243d260, 0x243d309),
        'sha256': 'dea729dd80ca2d0e602f6e11f5db901d900d393a0c'
                  '03dc74c6c9ff764d11c06c',
        'pins': {
            0x243d264: '488b07',        # root = handle[0]
            0x243d26c: '488b4f08',      # height = handle + 0x8
            0x243d270: '440fb74062',    # count word at node + 0x62
            0x243d295: '483b74d010',    # key compare (key by value)
            0x243d2c9: '488b44d068',    # child edge at +0x68 scale 8
            0x243d2d0: 'b001',          # found: return 1
            0x243d2fd: 'e85e782900',    # miss: call cursor callee
        },
        'calls': {0x243d2fd: 0x26d4b60},
    },
    'remove': {
        'range': (0x51d5010, 0x51d5121),
        'sha256': '9045b724ca123fc5cfea3777b54a45c3946c1dfd8'
                  '619ffa524f7569d2045d023',
        'pins': {
            0x51d5015: '488b07',        # root = handle[0]
            0x51d5024: '488b4f08',      # height = handle + 0x8
            0x51d5028: '488b16',        # key value = *key_ptr
            0x51d502b: '0fb77862',      # count word at node + 0x62
            0x51d5045: '483b54f010',    # key compare at +0x10 scale 8
            0x51d5079: '488b44f068',    # child edge at +0x68 scale 8
            0x51d50a8: 'e8c3adb5ff',    # call node-remove helper
            0x51d50ad: '48ff4b10',      # handle total -= 1 at +0x10
            0x51d50e5: 'ff15b5a33001',  # free old root via free slot
        },
        'calls': {0x51d50a8: 0x4d2fe70},
    },
    'consumer_a': {
        'range': (0x23e4340, 0x23e47d3),
        'sha256': '0de834f2749e167d1604e489cd04dfd697844910d'
                  'b0d6ec6fbc8ab7c33a0aec6',
        'pins': {
            0x23e436a: '488b5f10',      # map length at book + 0x10
            0x23e4387: '498b4508',      # map entries pointer at +0x8
            0x23e43d4: 'e837183100',    # call scrambled-hash helper
            0x23e46b5: '488b5828',      # probe key = record + 0x28
            0x23e46c2: '410fb74862',    # walk count word at +0x62
            0x23e46e5: '493b5cc010',    # walk key compare at +0x10
            0x23e4712: '4d8b44c068',    # walk child edge at +0x68
            0x23e4719: '8b05b9ba1004',  # hit: load global flag dword
            0x23e475c: 'ff158eb20f04',  # hit: gated log call via slot
            0x23e478d: 'e8aef9feff',    # miss: call map-side helper A
            0x23e47a3: '41b90b000000',  # miss: argument 0xb
            0x23e47a9: 'e88293feff',    # miss: call map-side helper B
        },
        'calls': {
            0x23e43d4: 0x26f5c10,
            0x23e478d: 0x23d4140,
            0x23e47a9: 0x23cdb30,
        },
    },
    'consumer_b': {
        'range': (0x23e4c80, 0x23e58e5),
        'sha256': '1ab3f271a6948b076f8b9727aa1bc4bf5cca56c6e'
                  'f60543349de6bb89c78aa9d',
        'pins': {
            0x23e4d9f: '4c8b3dfaa60f04',  # free fn ptr from free slot
            0x23e51a9: 'e8e251edff',      # call cursor-state helper
            0x23e528e: '0fb74562',        # walk count word at +0x62
            0x23e5361: '0fb75d60',        # child-index word at +0x60
            0x23e537b: '41ffd7',          # ascent free call *%r15
            0x23e5384: '66413b5c2462',    # index vs parent count word
            0x23e542c: '4d8b64dc08',      # member key = node+8+idx*8
            0x23e5444: '4c3b6008',        # fast path: entry key cmp
            0x23e5503: '48b8c5a9622eea7a35f1',  # map hash constant
        },
        'calls': {0x23e51a9: 0x22ba390},
    },
}

BOUNDARIES = {
    'find_clone_a': {
        'range': (0x243ca40, 0x243cabb),
        'sha256': '46b83804c37ee1e4667c35161e74896eb3d3f11f3b'
                  '46bed08b5ad3a21b6e3bc0',
    },
    'find_clone_b': {
        'range': (0x39007b0, 0x390082b),
        'sha256': '46b83804c37ee1e4667c35161e74896eb3d3f11f3b'
                  '46bed08b5ad3a21b6e3bc0',
    },
    'cursor_search_a': {
        'range': (0x1d65920, 0x1d659af),
        'sha256': '4f7a495bf20876b0606bf10b74cbbce7d6b8a1ebc5'
                  'b55e2be63d6f7bac1297ac',
    },
    'cursor_search_b': {
        'range': (0x35bdd20, 0x35bddaf),
        'sha256': '4f7a495bf20876b0606bf10b74cbbce7d6b8a1ebc5'
                  'b55e2be63d6f7bac1297ac',
    },
    'consumer_a_twin': {
        'range': (0x23e47e0, 0x23e4c73),
        'sha256': '3533d1e33457cce515af457e1e523f225a1a75aa6'
                  'fd0c073cd4c799a38b62f96',
    },
    'remove_clone_a': {
        'range': (0x51d6a30, 0x51d6b41),
        'sha256': '5364c640c5dc9a4576cb697d81d25dc3304836701d'
                  'd8cadda1fb25a6122f5344',
    },
    'remove_clone_b': {
        'range': (0x51d7780, 0x51d7891),
        'sha256': '1de224b51c1758e15a030eabec58313bc1ec68af'
                  '6621fad4ea1c91003cce1e02',
    },
    'remove_clone_c': {
        'range': (0x51d87e0, 0x51d88f1),
        'sha256': 'c0e46036a4e4fc242b2dda321252e68e60127ef08'
                  '7b2bd236ccd0c546f876a20',
    },
    'remove_x_a': {
        'range': (0x243eea0, 0x243efb1),
        'sha256': '1e6a3d2da44265720f17464b9a298bb865bd9ba2fd'
                  'd053a4f2996f45e7eaddd4',
    },
    'remove_x_b': {
        'range': (0x243efc0, 0x243f0d1),
        'sha256': '4633fe2dd119fbaafdaae95ba2dd9a6dd4140b0e2fe'
                  '1571c79967baa2e7b5297',
    },
    'remove_x_c': {
        'range': (0x243fb20, 0x243fc31),
        'sha256': '801fdd948ef0ca0a4870dd0fea3084c7a6161952fdf'
                  '5c1ce8c01a707c507615f',
    },
    'remove_x_d': {
        'range': (0x3901bf0, 0x3901d01),
        'sha256': '2c4001043a4ef7b3cd8e9ff9d372e5b522dd8561fdd'
                  '7936a8cae931bf7aafa73',
    },
    'remove_x_e': {
        'range': (0x3902c90, 0x3902da1),
        'sha256': '04ebc9164d2d7195aa7c2e6f4359cd8867d15045ddf'
                  '16b40e578350caea7818d',
    },
    'remove_x_f': {
        'range': (0x3903c70, 0x3903d81),
        'sha256': 'b6c691dd40b4f4db70b6d607ca592908304f39657164'
                  'c4053c3cb2ad59fe025c',
    },
    'node_remove_helper': {
        'range': (0x4d2fe70, 0x4d30055),
        'sha256': '3f4eba69a0feaf47082c0ce25eeefaba8c2307702'
                  '035eb75df7d0278e8193476',
    },
    'forward_2': {
        'range': (0x51d1b00, 0x51d1c5f),
        'sha256': 'b94dcaca1a7e4fadeb833f24fa47bd30eb9bab8b4'
                  '900a14b314e6b3f19eff3c6',
    },
    'node_insert': {
        'range': (0x4c49f90, 0x4c4a737),
        'sha256': 'b56c5f0edade1f99c0dc818624d46c29912660b712'
                  'b382cdd0cfb206c861f265',
    },
    'map_contains': {
        'range': (0x4ef4010, 0x4ef414f),
        'sha256': '05b749456b1fccdfb9adc166530c85cc87c16c30f'
                  '5827934ae82a484e0abe891',
    },
    'map_remove': {
        'range': (0x4e37a10, 0x4e37e5c),
        'sha256': '7198d869bf8f939a3f953b36c4e1279a6849240e68cd'
                  '86dc39518509843a2385',
    },
    'twin_lookup': {
        'range': (0x4eeed90, 0x4eef13b),
        'sha256': '399e403494b758bc98103adc72979271e0d22326'
                  '718a30881de3f904b812e015',
    },
    'consumer_parent_a': {
        'range': (0x23ebea0, 0x23f0a75),
        'sha256': 'b30cb747f2d0c666463e9bd1526e45307180f14486'
                  '23ef95ad096e7ef8f6a243',
    },
    'consumer_parent_b': {
        'range': (0x23f0a80, 0x23f5453),
        'sha256': '245abb3ed083a95251a605466765556269870430135'
                  '4618bb7fda6204149f9d6',
    },
    'consumer_b_caller': {
        'range': (0x2bdf8f0, 0x2beafa1),
        'sha256': '225649f70f438609a3bf19555e1a01ce18bee7dfa'
                  '80fb5179ba16225e4fa437c',
    },
    'miss_helper_a': {
        'range': (0x23d4140, 0x23d4784),
        'sha256': '8f464e112ecf7b078609433d3844ca82cbf7066c0d8'
                  '63cc5b8d4a00dd91fcc1c',
    },
    'miss_helper_b': {
        'range': (0x23cdb30, 0x23cdf69),
        'sha256': 'd561d741b6f2c7f7caa935533925b623e36571e7ab'
                  '4978d764e298755e4bf299',
    },
    'contains_miss_callee': {
        'range': (0x26d4b60, 0x26d4c4c),
        'sha256': '3fc741675a5fd33a9b78b87dffd55ea9b2bfcc7449'
                  '240b7a790d25368b9df987',
    },
    'cursor_helper': {
        'range': (0x22ba390, 0x22bad85),
        'sha256': '2f9caae07a0ba86b241c6f868624d62d2ddeb2cd689c'
                  '49d1b0a40df88fee89e8',
    },
    'map_probe_helper': {
        'range': (0x26f5c10, 0x26f5d04),
        'sha256': 'fd30cb8ea382eb0f9b75050f380e2b95c4acfbf90e'
                  '76252b01ea138c6a32e22d',
    },
    'book_consumer_a': {
        'range': (0x58f5c30, 0x58f6075),
        'sha256': '6c1c77fdd42357d522e20530164573d8a5fc42e326f'
                  '43b01ef37af9b48b45d2b',
    },
    'book_consumer_b': {
        'range': (0x58f6080, 0x58f64c5),
        'sha256': '1bf21933372b70f02ac80c057e30a6777403c96cd21'
                  '49094a99f726d451017d2',
    },
    'book_consumer_c': {
        'range': (0x58f64d0, 0x58f6915),
        'sha256': 'a7f7d572ff9381595dcbf98500daa5b8385583828541'
                  '9ed5c24869210a950f38',
    },
    'book_consumer_d': {
        'range': (0x58f6920, 0x58f6d65),
        'sha256': 'af09fbd88c64ceca2d3dc24de68d1f11828dcb4995634a'
                  'ee14b0eeacb9de30a9',
    },
    'insert_fwd2_caller_x_a': {
        'range': (0x481fb70, 0x481fc6b),
        'sha256': 'd0bd2104681214dbc61011bc6341bb0ceec211bfca'
                  'ad4d56ec998f4517934620',
    },
    'insert_fwd2_caller_x_b': {
        'range': (0x4a44620, 0x4a44e6e),
        'sha256': '000a4493e454ea92b508984458eba07c204aa9022d'
                  '98fa728f148c0481b36a6b',
    },
    'insert_split_caller_b': {
        'range': (0x51d4920, 0x51d4a7f),
        'sha256': '6e804480706fcb2e7960c50cde70086f397e8c46e0'
                  'fbf38235ee596c134ff5f0',
    },
    'insert_split_caller_c': {
        'range': (0x51d4a80, 0x51d4bdf),
        'sha256': '751a976452aec3763c669701315f6e862d064693d9'
                  'bd6b462576f51fb838d484',
    },
}

# Decoded windows inside boundary FDEs, with their own pins.
WINDOWS = {
    'consumer_parent_a': {
        'range': (0x23eeb70, 0x23eeba0),
        'pins': {
            0x23eeb82: 'e849410300',    # call slab lookup 0x2422cd0
            0x23eeb87: '4883c040',      # handle = lookup result + 0x40
            0x23eeb94: 'e8c7e60400',    # call contains
        },
        'calls': {0x23eeb94: 0x243d260},
    },
    'miss_helper_a': {
        'range': (0x23d4180, 0x23d41c0),
        'pins': {
            0x23d4196: '488b4cc810',    # map slot load, key * 3 stride
            0x23d41a9: '48bec5a9622eea7a35f1',  # map hash constant
        },
        'calls': {},
    },
    'miss_helper_b': {
        'range': (0x23cdb80, 0x23cdbc0),
        'pins': {
            0x23cdb95: '488b4cc810',    # map slot load, key * 3 stride
            0x23cdba8: '48bec5a9622eea7a35f1',  # map hash constant
        },
        'calls': {},
    },
    'book_consumer_b': {
        'range': (0x58f63a0, 0x58f6410),
        'pins': {
            0x58f63b2: '410fb74d62',    # inlined walk count word
            0x58f63d5: '493b5cc510',    # inlined walk key compare
            0x58f6402: '4d8b6cc568',    # inlined walk child edge
        },
        'calls': {},
    },
}

# Exact expected direct-call sites (site -> containing FDE start)
# for the standalone readers and the cited callees.
EXPECTED_SITES = {
    0x51d1a80: {   # find
        0x5392879: 0x538cd30, 0x539d699: 0x5397b50,
        0x55af04d: 0x55aca20, 0x55b4d4d: 0x55b2720,
    },
    0x243ca40: {   # find clone A
        0x28d37b2: 0x28cd7a0, 0x2c49c8d: 0x2c47660,
    },
    0x39007b0: {   # find clone B
        0x3c0984a: 0x3c09590,
    },
    0x243d260: {   # contains
        0x23eeb94: 0x23ebea0, 0x23f3c25: 0x23f0a80,
    },
    0x51d5010: {   # remove (the book cluster body)
        0x58e1d31: 0x58e1400, 0x58e2871: 0x58e1f40,
        0x58e3440: 0x58e2a80, 0x58e4080: 0x58e36c0,
    },
    0x23e4340: {   # consumer_a
        0x23edcf9: 0x23ebea0, 0x23ee475: 0x23ebea0,
    },
    0x23e47e0: {   # consumer_a twin
        0x23f2d92: 0x23f0a80, 0x23f3508: 0x23f0a80,
    },
    0x23e4c80: {   # consumer_b
        0x2be146f: 0x2bdf8f0,
    },
    0x51d1b00: {   # forward_2 (citation re-check)
        0x590408b: 0x5901dd0, 0x59082f1: 0x5905cf0,
        0x590bdeb: 0x5909b30, 0x5910051: 0x590da50,
        0x481fbe2: 0x481fb70, 0x4a44879: 0x4a44620,
    },
}

# Caller FDE sets (sites computed) for the remove clone family and
# the shared helpers.
EXPECTED_CALLER_SETS = {
    0x51d6a30: {0x54c9810, 0x54c9950},                    # remove clone A
    0x51d7780: {0x5921480, 0x5921e20},                    # remove clone B
    0x51d87e0: {0x55c3680, 0x55c3ea0, 0x55cd8a0,
                0x55cdd30},                               # remove clone C
    0x4d2fe70: {0x51d5010, 0x51d6a30, 0x51d7780,
                0x51d87e0},                               # node-remove helper
    0x4c49f90: {0x51d1b00, 0x51d4920, 0x51d4a80},         # split helper
}

# After every find-family call site the result is consumed by a
# test %rax,%rax at exactly this instruction start in the caller.
FIND_RESULT_TESTS = {
    0x5392879: 0x539287e, 0x539d699: 0x539d69e,
    0x55af04d: 0x55af055, 0x55b4d4d: 0x55b4d55,
    0x28d37b2: 0x28d37b7, 0x2c49c8d: 0x2c49c95,
    0x3c0984a: 0x3c0984f,
}
RESULT_TEST_BYTES = '4885c0'

FIND_FAMILY = (0x51d1a80, 0x243ca40, 0x39007b0)
CURSOR_FAMILY = (0x1d65920, 0x35bdd20)
REMOVE_FAMILY_273 = (
    0x51d5010, 0x51d6a30, 0x51d7780, 0x51d87e0,
    0x243eea0, 0x243efc0, 0x243fb20,
    0x3901bf0, 0x3902c90, 0x3903c70,
)
SMALL_READER_SET = frozenset(
    FIND_FAMILY + CURSOR_FAMILY + (0x243d260,) + REMOVE_FAMILY_273)
EXPECTED_WALK_SIGNATURE_COUNT = 126

COUNT_RE = re.compile(r'movzwl\s+0x62\(%r')
CHILD_RE = re.compile(r'mov\s+0x68\(%r\w+,\s?%r\w+,8\)')
KEYCMP_RE = re.compile(
    r'cmp\s+0x10\(%r\w+,\s?%r\w+,8\)|cmp\s+%r\w+,\s?0x10\(%r\w+,'
    r'\s?%r\w+,8\)')
SETA_RE = re.compile(r'seta\s')
SBB_RE = re.compile(r'sbb\s')


class PacketError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise PacketError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(value):
    return f'0x{value:x}'


def authenticate(data):
    digest = sha(data)
    require(digest == EXPECTED_SHA256,
            f'Artifact hash mismatch: {digest}')
    return digest


_LINE = re.compile(r'^\s+([0-9a-f]+):\t[0-9a-f ]+\t(.*)$')


def decode_body(data, start, end):
    """objdump-decode one FDE body from a temp copy of the data.

    Returns (rows, texts): rows maps each native instruction
    start to its full bytes (via the shared foundation decoder,
    which merges objdump's wrapped byte rows and requires the
    decode to tile the body exactly); texts maps each start to
    its mnemonic text.
    """
    body = data[start - TEXT_FILE_OFFSET_DIFFERENCE:
                end - TEXT_FILE_OFFSET_DIFFERENCE]
    with tempfile.NamedTemporaryFile(
            suffix='.bin', delete=False) as handle:
        handle.write(body)
        path = handle.name
    try:
        output = subprocess.check_output([
            'objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
            f'--adjust-vma={start:#x}', path,
        ], text=True)
    finally:
        os.unlink(path)
    rows = _foundation_decode(output, start, end, body)
    texts = {}
    for line in output.splitlines():
        match = _LINE.match(line)
        if match:
            texts[int(match.group(1), 16)] = match.group(2).strip()
    return rows, texts


def check_pins(name, spec, rows):
    for address, expected in spec.get('pins', {}).items():
        raw = rows.get(address)
        require(raw is not None,
                f'{name} pin is not an instruction start: '
                f'{hx(address)}')
        require(raw == bytes.fromhex(expected),
                f'{name} pin bytes changed at {hx(address)}: '
                f'{raw.hex()} != {expected}')
    for address, target in spec.get('calls', {}).items():
        raw = rows.get(address)
        require(raw is not None,
                f'{name} call is not an instruction start: '
                f'{hx(address)}')
        require(raw[0] == 0xE8,
                f'{name} call opcode changed at {hx(address)}')
        displacement = struct.unpack('<i', raw[1:5])[0]
        require(address + 5 + displacement == target,
                f'{name} call target changed at {hx(address)}')


def walk_signature(texts):
    joined = '\n'.join(texts.values())
    return {
        'count': bool(COUNT_RE.search(joined)),
        'child': bool(CHILD_RE.search(joined)),
        'keycmp': bool(KEYCMP_RE.search(joined)),
        'seta_sbb': bool(SETA_RE.search(joined)
                         and SBB_RE.search(joined)),
    }


def raw_candidates(text_bytes, text_va):
    """FDE-candidate addresses from raw pattern scans of .text.

    Mirrors the lane census: word accesses at displacement 0x62,
    scale-8 loads at displacement 0x68, and scale-8 compares at
    displacement 0x8 / 0x10.  Raw hits are only a superset; every
    candidate is instruction-validated by decoding its FDE.
    """
    raw = set()
    for match in re.finditer(rb'\x0f\xb7|\x66[\x8b\x89\x83\x39\x3b]',
                             text_bytes):
        i = match.start()
        if i + 4 >= len(text_bytes):
            continue
        modrm = text_bytes[i + 2]
        mod, rm = modrm >> 6, modrm & 7
        if mod == 1:
            disp = text_bytes[i + 4] if rm == 4 else text_bytes[i + 3]
            if disp == 0x62:
                raw.add(text_va + i)
    for match in re.finditer(rb'[\x48\x4c\x49\x4d][\x8b\x39\x3b]',
                             text_bytes):
        i = match.start()
        if i + 5 >= len(text_bytes):
            continue
        modrm = text_bytes[i + 2]
        if ((modrm >> 6) == 1 and (modrm & 7) == 4
                and (text_bytes[i + 3] >> 6) == 3
                and text_bytes[i + 4] == 0x68):
            raw.add(text_va + i)
    for match in re.finditer(rb'[\x48\x4c][\x3b\x39]', text_bytes):
        i = match.start()
        if i + 5 >= len(text_bytes):
            continue
        modrm = text_bytes[i + 2]
        if ((modrm >> 6) in (1, 2) and (modrm & 7) == 4
                and (text_bytes[i + 3] >> 6) == 3):
            if (modrm >> 6) == 1 and text_bytes[i + 4] in (0x08, 0x10):
                raw.add(text_va + i)
    return raw


def load_fdes(data):
    summary, fdes, gaps = fde_extents(data)
    starts = sorted(fde['start'] for fde in fdes)
    by_start = {fde['start']: fde for fde in fdes}
    return summary, fdes, starts, by_start


def find_fde(starts, by_start, va):
    import bisect
    index = bisect.bisect_right(starts, va) - 1
    if index < 0:
        return None
    fde = by_start[starts[index]]
    return fde if fde['start'] <= va < fde['end'] else None


def call_site_census(data, starts, by_start):
    """Every direct E8 site for every target of interest.

    Each site is re-validated as an instruction start inside its
    containing FDE (decoded once per distinct caller).
    """
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    text_bytes = data[text['offset']:text['offset'] + text['size']]
    text_va = text['address']
    targets = (set(EXPECTED_SITES) | set(EXPECTED_CALLER_SETS))
    sites = {target: {} for target in targets}
    for match in re.finditer(rb'\xe8', text_bytes):
        i = match.start()
        if i + 5 > len(text_bytes):
            continue
        displacement = struct.unpack_from('<i', text_bytes, i + 1)[0]
        target = text_va + i + 5 + displacement
        if target in targets:
            site = text_va + i
            fde = find_fde(starts, by_start, site)
            require(fde is not None,
                    f'Call site outside any FDE: {hx(site)}')
            sites[target][site] = fde['start']
    decoded = {}

    def caller_lines(start):
        if start not in decoded:
            fde = by_start[start]
            decoded[start] = decode_body(data, start, fde['end'])[0]
        return decoded[start]

    for target, site_map in sites.items():
        for site, caller in site_map.items():
            raw = caller_lines(caller).get(site)
            require(raw is not None,
                    f'Call site is not an instruction start: '
                    f'{hx(site)}')
            require(raw[0] == 0xE8,
                    f'Call site opcode changed: {hx(site)}')
            displacement = struct.unpack('<i', raw[1:5])[0]
            require(site + 5 + displacement == target,
                    f'Call site target changed: {hx(site)}')
    for target, expected in EXPECTED_SITES.items():
        require(sites[target] == expected,
                f'Call sites changed for {hx(target)}: '
                f'{sites[target]} != {expected}')
    for target, expected_callers in EXPECTED_CALLER_SETS.items():
        callers = set(sites[target].values())
        require(callers == expected_callers,
                f'Caller set changed for {hx(target)}: '
                f'{callers} != {expected_callers}')
    return sites, caller_lines


def find_result_tests(data, caller_lines):
    """Pin the test %rax,%rax consuming each find-family result."""
    checked = {}
    for site, test_va in FIND_RESULT_TESTS.items():
        caller = None
        for target, site_map in EXPECTED_SITES.items():
            if site in site_map:
                caller = site_map[site]
        require(caller is not None, f'Unknown find site {hx(site)}')
        raw = caller_lines(caller).get(test_va)
        require(raw is not None,
                f'Result test is not an instruction start: '
                f'{hx(test_va)}')
        require(raw == bytes.fromhex(RESULT_TEST_BYTES),
                f'Result test bytes changed at {hx(test_va)}')
        checked[hx(site)] = hx(test_va)
    return checked


def rela_census(data):
    """R_X86_64_RELATIVE entries of .rela.dyn: offset -> addend,
    plus the inverse map addend -> [offsets]."""
    relas = {}
    for section in sections(data):
        if section['name'] == '.rela.dyn':
            blob = data[section['offset']:
                        section['offset'] + section['size']]
            for cursor in range(0, len(blob), 24):
                offset, info, addend = struct.unpack_from(
                    '<QQq', blob, cursor)
                if info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
                    relas[offset] = addend
    by_addend = {}
    for offset, addend in relas.items():
        by_addend.setdefault(addend, []).append(offset)
    return relas, by_addend


SET_FAMILY = frozenset(
    FIND_FAMILY + CURSOR_FAMILY + (0x243d260,) + REMOVE_FAMILY_273
    + (0x51d1b00, 0x4c49f90, 0x4d2fe70))


def decoded_call_targets(data, start, end):
    rows, _texts = decode_body(data, start, end)
    targets = set()
    for address, raw in rows.items():
        if raw[0] == 0xE8 and len(raw) >= 5:
            displacement = struct.unpack('<i', raw[1:5])[0]
            targets.add(address + 5 + displacement)
    return targets


def walk_census(data, starts, by_start):
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    text_bytes = data[text['offset']:text['offset'] + text['size']]
    candidates = set()
    for va in raw_candidates(text_bytes, text['address']):
        fde = find_fde(starts, by_start, va)
        if fde is not None:
            candidates.add(fde['start'])
    carriers = {}
    for start in sorted(candidates):
        fde = by_start[start]
        signature = walk_signature(
            decode_body(data, start, fde['end'])[1])
        if all(signature.values()):
            carriers[start] = fde['end'] - start
    require(len(carriers) == EXPECTED_WALK_SIGNATURE_COUNT,
            f'Walk-signature census changed: {len(carriers)} != '
            f'{EXPECTED_WALK_SIGNATURE_COUNT}')
    small = {start for start, size in carriers.items() if size <= 350}
    require(small == set(SMALL_READER_SET),
            f'Small reader census changed: '
            f'{sorted(hx(s) for s in small)}')
    return carriers


def hash_families(data, fdes):
    families = {}
    for fde in fdes:
        body = data[fde['start'] - TEXT_FILE_OFFSET_DIFFERENCE:
                    fde['end'] - TEXT_FILE_OFFSET_DIFFERENCE]
        families.setdefault(sha(body), []).append(fde['start'])
    find_family = sorted(families[OWNERS['find']['sha256']])
    require(find_family == sorted(FIND_FAMILY),
            f'Find family changed: {find_family}')
    contains_family = sorted(families[OWNERS['contains']['sha256']])
    require(contains_family == [0x243d260],
            f'Contains family changed: {contains_family}')
    cursor_family = sorted(
        families[BOUNDARIES['cursor_search_a']['sha256']])
    require(cursor_family == sorted(CURSOR_FAMILY),
            f'Cursor family changed: {cursor_family}')
    return {
        'find': [hx(v) for v in find_family],
        'contains': [hx(v) for v in contains_family],
        'cursor_search': [hx(v) for v in cursor_family],
    }


def analyze(data, binary):
    # No whole-artifact authentication here: generate() authenticates
    # first, and analyze() reports the first specific check a mutated
    # byte fails (the counterfactual tests rely on that order).
    digest = sha(data)
    summary, fdes, starts, by_start = load_fdes(data)

    owners = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        fde = by_start.get(start)
        require(fde is not None and fde['end'] == end,
                f'Owner FDE changed: {name}')
        body = data[start - TEXT_FILE_OFFSET_DIFFERENCE:
                    end - TEXT_FILE_OFFSET_DIFFERENCE]
        rows, _texts = decode_body(data, start, end)
        check_pins(name, spec, rows)
        require(sha(body) == spec['sha256'],
                f'Owner body hash changed: {name}')
        owners[name] = {
            'range': [hx(start), hx(end)],
            'size': end - start,
            'sha256': spec['sha256'],
            'pins': {hx(k): v for k, v in spec['pins'].items()},
            'calls': {hx(k): hx(v)
                      for k, v in spec['calls'].items()},
        }

    boundaries = {}
    for name, spec in BOUNDARIES.items():
        start, end = spec['range']
        fde = by_start.get(start)
        require(fde is not None and fde['end'] == end,
                f'Boundary FDE changed: {name}')
        body = data[start - TEXT_FILE_OFFSET_DIFFERENCE:
                    end - TEXT_FILE_OFFSET_DIFFERENCE]
        require(sha(body) == spec['sha256'],
                f'Boundary body hash changed: {name}')
        boundaries[name] = {
            'range': [hx(start), hx(end)],
            'size': end - start,
            'sha256': spec['sha256'],
        }

    windows = {}
    for name, spec in WINDOWS.items():
        start, end = spec['range']
        rows, _texts = decode_body(data, start, end)
        check_pins(f'window {name}', spec, rows)
        windows[name] = {
            'range': [hx(start), hx(end)],
            'pins': {hx(k): v for k, v in spec['pins'].items()},
            'calls': {hx(k): hx(v)
                      for k, v in spec['calls'].items()},
        }

    miss_targets = {}
    for name in ('miss_helper_a', 'miss_helper_b'):
        start, end = BOUNDARIES[name]['range']
        hits = decoded_call_targets(data, start, end) & SET_FAMILY
        require(not hits,
                f'{name} unexpectedly calls a set-family body: '
                f'{sorted(hx(h) for h in hits)}')
        miss_targets[name] = []

    sites, caller_lines = call_site_census(data, starts, by_start)
    result_tests = find_result_tests(data, caller_lines)
    families = hash_families(data, fdes)
    carriers = walk_census(data, starts, by_start)

    relas, by_addend = rela_census(data)
    for name, spec in OWNERS.items():
        start = spec['range'][0]
        require(start not in by_addend,
                f'Unexpected rela slot for {name}')
    require(relas.get(FREE_SLOT) == FREE_TARGET,
            'Free slot relocation changed')

    call_sites = {}
    for target, site_map in sites.items():
        call_sites[hx(target)] = {
            hx(site): hx(caller)
            for site, caller in sorted(site_map.items())
        }

    counters = {
        'find_call_sites': sum(
            len(EXPECTED_SITES[t]) for t in FIND_FAMILY),
        'find_family_fdes': len(FIND_FAMILY),
        'contains_call_sites': len(EXPECTED_SITES[0x243d260]),
        'remove_call_sites': len(EXPECTED_SITES[0x51d5010]),
        'remove_clone_call_sites': sum(
            len(sites[t]) for t in
            (0x51d6a30, 0x51d7780, 0x51d87e0)),
        'node_remove_helper_call_sites': len(sites[0x4d2fe70]),
        'forward_2_call_sites': len(EXPECTED_SITES[0x51d1b00]),
        'consumer_a_call_sites': len(EXPECTED_SITES[0x23e4340]),
        'consumer_b_call_sites': len(EXPECTED_SITES[0x23e4c80]),
        'walk_signature_fdes': len(carriers),
        'small_reader_fdes': len(SMALL_READER_SET),
        'find_result_tests': len(result_tests),
    }

    frames = [list(spec['range']) for spec in
              list(OWNERS.values()) + list(BOUNDARIES.values())]
    return {
        'artifact': {
            'sha256': digest,
            'fde_records': summary['fde_records'],
            'unique_fde_starts': len(by_start),
        },
        'owners': owners,
        'boundaries': boundaries,
        'windows': windows,
        'miss_helper_set_family_targets': miss_targets,
        'call_sites': call_sites,
        'find_result_tests': result_tests,
        'hash_families': families,
        'rela_slots': {
            'owners_with_slots': [],
            'free_slot': hx(FREE_SLOT),
            'free_target': hx(FREE_TARGET),
            'log_slot': hx(LOG_SLOT),
            'set_flag': hx(SET_FLAG),
        },
        'counters': counters,
        'frames': frames,
    }


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    report = analyze(data, binary)
    output.mkdir(parents=True, exist_ok=True)
    raw = subprocess.check_output(
        ['readelf', '-wf', str(binary)], text=True)
    ranges = [spec['range'] for spec in
              list(OWNERS.values()) + list(BOUNDARIES.values())]
    lines = [
        line.replace(str(binary), '<authenticated-node115>')
        for line in raw.splitlines()
        if any(f'pc={start:016x}..{end:016x}' in line
               for start, end in ranges)
    ]
    require(len(lines) == len(report['frames']),
            'Retained readelf frame changed')
    (output / 'frames.txt').write_text('\n'.join(lines) + '\n')
    exports = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}',
            f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        safe_name = f'{name}_full_body_{start:x}_{end:x}_objdump.txt'
        rendered = asm.replace(str(binary), '<authenticated-node115>')
        (output / safe_name).write_text(rendered)
        exports[name] = {
            'full_body': {
                'file': safe_name,
                'sha256': sha(rendered.encode()),
                'range': [hx(start), hx(end)],
            },
        }
    report['source_exports'] = exports
    (output / 'records.json').write_text(
        json.dumps(report, indent=2) + '\n')
    return report


def main():
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else TARGET
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else PACKET
    generate(binary, output)
    print(output / 'records.json')


if __name__ == '__main__':
    main()
