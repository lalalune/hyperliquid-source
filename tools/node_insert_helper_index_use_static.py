#!/usr/bin/env python3
"""Static trace of the node-115 node insert/split helper `0x4c49f90`
-- the callee forward 2 (`0x51d1b00`, packet
RE-006-node115-forward-callee-index-use) forwards the RE-006 slab
slot index to when the sorted-set leaf is full.

Forward 2 calls the helper with the index in `rdx`, a cursor
record in `rsi` (duplicated in `r8`) -- `{+0x0: leaf node, +0x8:
0, +0x10: insertion position}`, built on forward 2's frame at
`0x51d1c13`/`0x51d1c22` -- a context record in `rcx` (`{+0x0:
handle, +0x8: the index again, +0x10: leaf node, +0x18: 0,
+0x20: position}`), and an out record pointer in `rdi`.  After
the helper returns, forward 2 increments the handle total
unconditionally.  A whole-`.text` census finds exactly three
direct call sites into the helper: forward 2's and one in each
of two 351-byte structural twins of forward 2 (`0x51d4920`,
`0x51d4a80`) whose call-site setup is instruction-identical --
the helper is a shared B-tree insert.  This packet traces the
helper end to end and settles whether that unconditional
increment can diverge from an actual store.

The helper is a B-tree insert over nodes of the forward-2
layout (parent pointer at `+0x0`, sorted qword keys from `+0x8`,
at most 11, this-node's child index as a word at `+0x60`, the
key-count word at `+0x62`, child pointers from `+0x68`; leaf
nodes are `0x68` bytes, internal nodes `0xc8`).  The index is
captured into `r12` at `0x4c49f9e`.  An operand scan shows the
captured value is read at exactly two sites, both stores of the
index as a node key at `node+0x8+position*8`:

- the fast path (`count < 11`): memmove the tail up and store
  at `0x4c49fee` into the node itself; and
- the leaf split (`count >= 11`): the index is stored at
  `0x4c4a119` into the old or the new node, chosen by the
  split-point arithmetic, before any split propagation runs.

Everything after the leaf-level store propagates the separator
key -- never the index again: `r12` is rewritten to a node
pointer at `0x4c4a1f4` (parent split) and `0x4c4a3fb` (root
split), and every later `r12` read uses that node pointer, or
the loop counter loaded at `0x4c4a4a3`.  No instruction compares
the captured index against a node key: there is no duplicate
path inside the helper.  The helper trusts the caller's cursor
position and count.

The every-path claim is proven on the decoded control-flow
graph, not by reading order: the body decodes to 473
instructions; with the two store instructions removed from the
graph, the single `ret` (`0x4c4a5f6`) -- and even the shared
epilogue entry `0x4c4a5da` -- is unreachable from the entry, so
every normal-return path executes one of the two stores.  The
only other reachable terminals are two `ud2` sites
(`0x4c4a6c8`, `0x4c4a70c`) behind the panic/allocation-failure
blocks, and the `_Unwind_Resume` landing pads
(`0x4c4a710`--`0x4c4a732`) are unreachable in the normal graph
(LSDA-only).  On an abort or unwind, forward 2's increment does
not run either.  **So no divergence exists**: whenever the
helper returns normally, the index has been stored as a node
key exactly once; forward 2's unconditional total increment is
matched by a store on every returning path.

The context record (`rcx`) is saved at `0x4c4a00d` on the split
path and read exactly once, at the root split (`0x4c4a3f3`,
loading `record+0x0`, the handle); the helper never writes
through it, and its `+0x8` copy of the index is never read --
the helper takes the index from `rdx`.  The cursor record
(`rsi`) is likewise read-only (fields `+0x0`, `+0x8`, `+0x10`).
The out record (`rdi`) is written once, by the shared epilogue:
`[out] = rbp`, `[out+0x8] = rcx`, `[out+0x10] = rax`, and
`rax = rdi` is returned; forward 2 discards it.

Secondary question, settled negatively: the two lookup callees
the four RE-006 callers use between forward 1 and forward 2
(`0x4da81b0` from callers 1/3, `0x4da7880` from callers 2/4) are
**not** the forward-1 map readback.  Neither body contains the
forward-1 probe signature (the scrambled-hash constant
`0xf1357aea2e62a9c5` and the `rol ..., 0x14` are absent).  Each
instead resolves an element pointer by array-stride arithmetic
over the fields of the record at `rdi` (`+0x8`, `+0x10`,
`+0x18`, gated by `dword [rdi] == 1`): a fast path returning
`[rdi+0x8] + [rdi+0x18]*0x58 + 0x8` (imul at `0x4da8289` /
`0x4da7959`) and a slow path returning an element at a `0x70`
stride (imul at `0x4da834b` / `0x4da7a1b`) after a
materialisation call.  The forward-2 handle is the field at
`result+0x40` of such an element; who reads the forward-1 map
back remains open.

This tool authenticates the whole capture, pins those facts in
bytes, and regenerates the packet.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-006-node115-node-insert-helper-index-use'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

HELPER = 0x4C49F90
FWD2 = 0x51D1B00
LOOKUP_A = 0x4DA81B0
LOOKUP_B = 0x4DA7880
UNWIND_RESUME = 0x63F0A50
HASH_CONST_LE = bytes.fromhex('c59c62ae2e7a35f1')
FAST_STORE = 0x4C49FEE
SPLIT_STORE = 0x4C4A119
RET_SITE = 0x4C4A5F6
EPILOGUE = 0x4C4A5DA

OWNERS = {
    'node_insert': {
        'range': (0x4C49F90, 0x4C4A737),
        'sha256': 'b56c5f0edade1f99c0dc818624d46c29912660b712b382cdd0cfb206c861f265',
        'index_argument': 'rdx (third argument)',
        'exact': {
            'capture': (0x4C49F9E, '4989d4'),
            'cursor_node_load': (0x4C49FA1, '488b2e'),
            'key_count_load': (0x4C49FA4, '0fb75d62'),
            'full_check': (0x4C49FA8, '4883fb0b'),
            'split_branch': (0x4C49FAC, '7352'),
            'fast_index_store': (0x4C49FEE, '4c8964c508'),
            'fast_count_store': (0x4C49FF3, '66895d62'),
            'fast_tail_jump': (0x4C49FFB, 'e9da050000'),
            'split_position_load': (0x4C4A000, '4c8b7610'),
            'split_out_save': (0x4C4A008, '48897c2438'),
            'split_context_save': (0x4C4A00D, '48894c2450'),
            'leaf_alloc_size': (0x4C4A05D, 'bf68000000'),
            'new_count_base': (0x4C4A085, '4c89f2'),
            'new_count_add': (0x4C4A08B, '4801c2'),
            'new_count_store': (0x4C4A08E, '6641895762'),
            'separator_load': (0x4C4A09D, '4e8b6cf508'),
            'old_count_store': (0x4C4A0BB, '6644897562'),
            'target_default': (0x4C4A0C4, '4c89f9'),
            'target_cmove': (0x4C4A0C7, '480f44cd'),
            'outfield_cmove': (0x4C4A0CB, '480f44442418'),
            'split_index_store': (0x4C4A119, '4c8964c108'),
            'split_count_store': (0x4C4A11E, '66895962'),
            'parent_load': (0x4C4A122, '488b4500'),
            'index_register_rewrite': (0x4C4A1F4, '4989c4'),
            'target_pick_cmove': (0x4C4A2C5, '4c0f44642420'),
            'parent_split_separator_store': (0x4C4A32C, '4b8944f408'),
            'parent_split_child_store': (0x4C4A33A, '4b8954f470'),
            'parent_split_count_store': (0x4C4A33F, '6641894c2462'),
            'root_separator_save': (0x4C4A407, '4c896c2430'),
            'root_child0_store': (0x4C4A434, '4c896068'),
            'old_root_parent_store': (0x4C4A449, '4d893424'),
            'handle_root_store': (0x4C4A455, '4c8933'),
            'handle_height_store': (0x4C4A458, '48894308'),
            'root_separator_store': (0x4C4A483, '498954c608'),
            'root_child_store': (0x4C4A488, '4d897cc670'),
            'absorb_separator_store': (0x4C4A50B, '4a8974f508'),
            'absorb_child_store': (0x4C4A514, '4e897cf570'),
            'absorb_count_store': (0x4C4A519, '66894d62'),
            'epilogue_out2_load': (0x4C4A5D1, '488b0424'),
            'epilogue_out1_load': (0x4C4A5D5, '488b4c2428'),
            'epilogue_store_0': (0x4C4A5DA, '48892f'),
            'epilogue_store_8': (0x4C4A5DD, '48894f08'),
            'epilogue_store_10': (0x4C4A5E1, '48894710'),
            'epilogue_return_value': (0x4C4A5E5, '4889f8'),
            'ret': (0x4C4A5F6, 'c3'),
            'panic_ud2': (0x4C4A6C8, '0f0b'),
        },
        'slot_calls': {
            'fast_memmove': (0x4C49FDD, 'ff1585558901', 0x64DF568),
            'leaf_alloc': (0x4C4A062, 'ff1518548901', 0x64DF480),
            'leaf_memcpy': (0x4C4A0B5, 'ff154d548901', 0x64DF508),
            'split_memmove': (0x4C4A108, 'ff155a548901', 0x64DF568),
        },
        'windows': {
            'full_body': (0x4C49F90, 0x4C4A737),
        },
    },
}

# The sole direct caller, forward 2, hash-pinned with the exact
# argument-setup instructions for the helper call.
CALLER = {
    'forward_2': {
        'range': (0x51D1B00, 0x51D1C5F),
        'sha256': 'b94dcaca1a7e4fadeb833f24fa47bd30eb9bab8b4900a14b314e6b3f19eff3c6',
        'exact': {
            'helper_spill_index': (0x51D1BE2, '48895c2410'),
            'helper_cursor_argument': (0x51D1C13, '4c8d442430'),
            'helper_context_argument': (0x51D1C22, '488d4c2408'),
            'helper_index_argument': (0x51D1C27, '4889da'),
            'helper_handle_reload': (0x51D1C2F, '488b4c2408'),
        },
        'calls': {'helper_call': (0x51D1C2A, HELPER)},
    },
}

# Two further direct callers of the helper: 351-byte structural
# twins of forward_2 (further sorted-set insert instantiations)
# with the identical argument setup at the call.
EXTRA_CALLERS = {
    'extra_helper_1': {
        'range': (0x51D4920, 0x51D4A7F),
        'sha256': '6e804480706fcb2e7960c50cde70086f397e8c46e0fbf38235ee596c134ff5f0',
        'exact': {
            'helper_context_argument': (0x51D4A42, '488d4c2408'),
            'helper_index_argument': (0x51D4A47, '4889da'),
        },
        'calls': {'helper_call': (0x51D4A4A, HELPER)},
    },
    'extra_helper_2': {
        'range': (0x51D4A80, 0x51D4BDF),
        'sha256': '751a976452aec3763c669701315f6e862d064693d9bd6b462576f51fb838d484',
        'exact': {
            'helper_context_argument': (0x51D4BA2, '488d4c2408'),
            'helper_index_argument': (0x51D4BA7, '4889da'),
        },
        'calls': {'helper_call': (0x51D4BAA, HELPER)},
    },
}

# Complete direct-call censuses for the lookup callees (raw
# whole-.text E8 scan; every candidate verified to sit at a
# decoded instruction start inside its containing FDE).  Each
# RE-006 caller calls its lookup four times; the traced site is
# the one whose result feeds forward_2.
LOOKUP_A_SITES = [0x58E2B50, 0x58E3790, 0x58FDA5D, 0x590135D,
                  0x5904079, 0x5904119, 0x59048A1, 0x5905249,
                  0x590BDD9, 0x590BE79, 0x590C601, 0x590CFA9,
                  0x5919AD2, 0x591A312]
LOOKUP_B_SITES = [0x58E14D2, 0x58E2012, 0x58FBDD4, 0x58FF6D4,
                  0x59082DF, 0x590837D, 0x5908BD9, 0x59091C7,
                  0x591003F, 0x59100DD, 0x5910939, 0x5910F27]

# The four RE-006 insert-order callers, pinned by digest and by
# their lookup call sites (the lookup boundary below).
LOOKUP_CALLERS = {
    'caller_1': {
        'range': (0x5901DD0, 0x5905CE9),
        'sha256': '69712a6423044cdfd8b9a5ddf17ffa1a7c6346381471234df8aa587d04e4b2c6',
        'calls': {'lookup_call': (0x5904079, LOOKUP_A)},
    },
    'caller_2': {
        'range': (0x5905CF0, 0x5909B21),
        'sha256': '41b6ea3b11ca2a035f22bfa7703cb11ca5a623eb0a3970740b0193580a649e84',
        'calls': {'lookup_call': (0x59082DF, LOOKUP_B)},
    },
    'caller_3': {
        'range': (0x5909B30, 0x590DA49),
        'sha256': '368701b152fa985ad4852bfa862db2edefb73b7c15f5c425be49a1e259f6ecc4',
        'calls': {'lookup_call': (0x590BDd9, LOOKUP_A)},
    },
    'caller_4': {
        'range': (0x590DA50, 0x5911881),
        'sha256': '17d3fe719c2fc2a12be204c26a182231920e632f81aabf26844f48acf6374bd2',
        'calls': {'lookup_call': (0x591003F, LOOKUP_B)},
    },
}

LOOKUPS = {
    'lookup_a': {
        'range': (0x4DA81B0, 0x4DA8388),
        'sha256': 'bf7c628aa360c418de396777514e9188b52c1ffe1e81d735b5abf922d54052b8',
        'exact': {
            'base_load': (0x4DA81BA, '488b4708'),
            'array_load': (0x4DA81BE, '4c8b7710'),
            'index_load': (0x4DA81C2, '488b5f18'),
            'mode_gate': (0x4DA81C6, '833f01'),
            'stride_58': (0x4DA8289, '486bcb58'),
            'fast_offset': (0x4DA8290, '4883c008'),
            'stride_70': (0x4DA834B, '486bcb70'),
        },
        'slot_calls': {
            'panic_slot_call': (0x4DA8382, 'ff15e8737301', 0x64DF770),
        },
        'materialisation_calls': {0x4DA826B: 0x51ECC40, 0x4DA8329: 0x57EBD20},
        'windows': {
            'full_body': (0x4DA81B0, 0x4DA8388),
        },
    },
    'lookup_b': {
        'range': (0x4DA7880, 0x4DA7A58),
        'sha256': '7b1c7c341dedbfee31ff7060c1f4f98ee9cab3fc725bad5dd51162f0c966b6df',
        'exact': {
            'base_load': (0x4DA788A, '488b4708'),
            'array_load': (0x4DA788E, '4c8b7710'),
            'index_load': (0x4DA7892, '488b5f18'),
            'mode_gate': (0x4DA7896, '833f01'),
            'stride_58': (0x4DA7959, '486bcb58'),
            'fast_offset': (0x4DA7960, '4883c008'),
            'stride_70': (0x4DA7A1B, '486bcb70'),
        },
        'slot_calls': {
            'panic_slot_call': (0x4DA7A52, 'ff15187d7301', 0x64DF770),
        },
        'materialisation_calls': {0x4DA793B: 0x51F4280, 0x4DA79F9: 0x57E95C0},
        'windows': {
            'full_body': (0x4DA7880, 0x4DA7A58),
        },
    },
}

# One level down: the FDE-start slot targets the helper and the
# lookup callees reach.  Bodies are hash-pinned as boundaries;
# their internals are not traced.
DOWNSTREAM = {
    'alloc': {
        'range': (0x6355830, 0x63558F2),
        'sha256': '72c29274a75359df7c598d254d102cbab84f51d359256facb415bb90bffec5af',
        'via': 'slot 0x64df480, called from the helper at 0x4c4a062 (0x68 bytes), 0x4c4a1e5 and 0x4c4a415 (0xc8 bytes)',
    },
    'alloc_fail': {
        'range': (0x141E251, 0x141E264),
        'sha256': '8443a2a6c5074055f5abdf1b4b2041c6434ff00ba23ebfcb33a91176170035b9',
        'via': 'slot 0x64df490, called from the helper at 0x4c4a652, 0x4c4a696 and 0x4c4a6b3 after a null allocation result',
    },
    'capacity_panic': {
        'range': (0x16817E0, 0x16818A8),
        'sha256': '002f50151d50c9884dc671db9023071d4db87bb150a52d4b510e653c39a293ba',
        'via': 'slot 0x64df570, called from the helper at 0x4c4a608, 0x4c4a624 and 0x4c4a684 with a node key count at or above the 0xb/0xc bound',
    },
    'panic': {
        'range': (0x1680E60, 0x1680E72),
        'sha256': '2c4e17b271b60cd074de9b63a359b89c8f04f3c59e8c076b156618dc7fba2aee',
        'via': 'slot 0x64df730, called from the helper at 0x4c4a642, 0x4c4a66b, 0x4c4a6dd and 0x4c4a6f6 on consistency-check failures',
    },
    'root_assert': {
        'range': (0x1680C10, 0x1680C29),
        'sha256': '6c62896561a5c8454ceb1945a882a798dcaefe52e78852cbbfee08835a16a81e',
        'via': 'slot 0x64df830, called from the helper at 0x4c4a6a3 and 0x4c4a6c2 (null root / null split node at the root split)',
    },
    'cleanup': {
        'range': (0x635DE30, 0x635DED5),
        'sha256': '714fc5cdd28a2587427c9dac8a25685ec09695a3a21bc9af0eb09b29ae503f61',
        'via': 'slot 0x64df4a0, called from the helper at 0x4c4a706 (root-assert tail) and 0x4c4a729 (landing pad) to release a fresh node',
    },
    'lookup_panic': {
        'range': (0x1680BD0, 0x1680C04),
        'sha256': '6dc901ad3d8318c0ad4ea63c6cbcfbc96ed76f5d1a86ff705ecf54d6cf04c7b2',
        'via': 'slot 0x64df770, called from lookup_a at 0x4da8382 and lookup_b at 0x4da7a52 on an out-of-range element index',
    },
}

SLOT_BINDINGS = {
    0x64DF480: 0x6355830,
    0x64DF490: 0x141E251,
    0x64DF570: 0x16817E0,
    0x64DF730: 0x1680E60,
    0x64DF830: 0x1680C10,
    0x64DF4A0: 0x635DE30,
    0x64DF770: 0x1680BD0,
}

GLOB_DAT_BINDINGS = {
    0x64DF508: 'memcpy',
    0x64DF568: 'memmove',
}

# The helper's complete slot-call census (site -> slot), derived
# by resolving every `call QWORD PTR [rip+...]` in the body.
HELPER_SLOT_CALLS = {
    0x64DF568: [0x4C49FDD, 0x4C4A108, 0x4C4A300, 0x4C4A319,
                0x4C4A4DB, 0x4C4A4FC],
    0x64DF508: [0x4C4A0B5, 0x4C4A245, 0x4C4A28D],
    0x64DF480: [0x4C4A062, 0x4C4A1E5, 0x4C4A415],
    0x64DF570: [0x4C4A608, 0x4C4A624, 0x4C4A684],
    0x64DF730: [0x4C4A642, 0x4C4A66B, 0x4C4A6DD, 0x4C4A6F6],
    0x64DF490: [0x4C4A652, 0x4C4A696, 0x4C4A6B3],
    0x64DF830: [0x4C4A6A3, 0x4C4A6C2],
    0x64DF4A0: [0x4C4A706, 0x4C4A729],
}

HELPER_R12_WRITES = [0x4C49F9E, 0x4C4A1F4, 0x4C4A2C5, 0x4C4A3FB,
                     0x4C4A4A3, 0x4C4A568, 0x4C4A5C3, 0x4C4A5ED]
HELPER_R12_INDEX_READS = [FAST_STORE, SPLIT_STORE]
HELPER_R12_COMPARE_READS = [0x4C4A3FE, 0x4C4A51D, 0x4C4A5C7]
HELPER_UNREACHABLE = [0x4C4A13A, 0x4C4A19A, 0x4C4A57E, 0x4C4A70E,
                      0x4C4A710, 0x4C4A713, 0x4C4A718, 0x4C4A71A,
                      0x4C4A71C, 0x4C4A71F, 0x4C4A724, 0x4C4A727,
                      0x4C4A729, 0x4C4A72F, 0x4C4A732]
HELPER_REACHABLE_UD2 = [0x4C4A6C8, 0x4C4A70C]
EPILOGUE_PREDS = {
    0x4C4A5D1: [0x4C4A49A, 0x4C4A57C, 0x4C4A5CC],
    0x4C4A5DA: [0x4C49FFB, 0x4C4A5D5],
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hx(value):
    return f'0x{value:x}'


def sha(body):
    return hashlib.sha256(body).hexdigest()


def relative_relocations(data):
    result = {}
    for section in sections(data):
        if section['name'] == '.rela.dyn':
            blob = data[section['offset']:section['offset'] + section['size']]
            for cursor in range(0, len(blob), 24):
                offset, info, addend = struct.unpack_from('<QQq', blob, cursor)
                if info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
                    result[offset] = addend
    return result


def glob_dat_symbols(data):
    """Resolve R_X86_64_GLOB_DAT slots to their dynamic symbols."""
    section_map = {s['name']: s for s in sections(data)}
    dynsym = section_map['.dynsym']
    dynstr = section_map['.dynstr']
    strings = data[dynstr['offset']:dynstr['offset'] + dynstr['size']]
    result = {}
    for section in sections(data):
        if section['name'] == '.rela.dyn':
            blob = data[section['offset']:section['offset'] + section['size']]
            for cursor in range(0, len(blob), 24):
                offset, info, _ = struct.unpack_from('<QQq', blob, cursor)
                if info & 0xFFFFFFFF == 6:  # R_X86_64_GLOB_DAT
                    index = info >> 32
                    name_at = struct.unpack_from(
                        '<I', data, dynsym['offset'] + index * 24)[0]
                    end = strings.index(b'\0', name_at)
                    result[offset] = strings[name_at:end].decode()
    return result


def read(data, section_list, va, size):
    matches = [
        section for section in section_list
        if section['type'] != 8
        and section['address'] <= va
        and va + size <= section['address'] + section['size']
    ]
    require(len(matches) == 1, f'Address not uniquely mapped: {hx(va)}')
    section = matches[0]
    offset = section['offset'] + va - section['address']
    return offset, data[offset:offset + size]


def resolve_e8(body, base, va):
    offset = va - base
    disp = struct.unpack_from('<i', body, offset + 1)[0]
    return va + 5 + disp


def resolve_slot(body, base, va, length):
    offset = va - base
    disp = struct.unpack_from('<i', body, offset + length - 4)[0]
    return va + length + disp


# --- operand-level scan helpers (mirrored from the forward-callee
# packet's tool, extended with write and control-flow analysis) ---

_REG64 = {
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
}


def base_reg(token):
    token = token.strip().lower()
    if token in _REG64:
        return token
    if re.fullmatch(r'r\d{1,2}[dwb]', token):
        return token[:-1]
    if re.fullmatch(r'e[a-z]{2}', token) and token[1:] in (
            'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'):
        return 'r' + token[1:]
    if token in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'):
        return 'r' + token
    if token in ('al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh'):
        return 'r' + token[0] + 'x'
    if token in ('sil', 'dil', 'bpl', 'spl'):
        return 'r' + token[:2]
    return None


def expr_regs(expr):
    regs = set()
    for token in re.split(r'[^a-z0-9]', expr.lower()):
        reg = base_reg(token)
        if reg:
            regs.add(reg)
    return regs


def split_ops(ops):
    out, depth, cur = [], 0, ''
    for ch in ops:
        if ch == '[':
            depth += 1
        if ch == ']':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_asm(asm):
    insns = []
    for line in asm.splitlines():
        parts = line.split('\t')
        if len(parts) < 3 or not parts[0].strip().endswith(':'):
            continue
        try:
            va = int(parts[0].strip()[:-1], 16)
        except ValueError:
            continue
        text = parts[2].strip()
        mnemonic = text.split(' ')[0]
        ops = text[len(mnemonic):].strip()
        insns.append((va, mnemonic, ops))
    return insns


def reads_reg(mnemonic, ops, reg):
    if mnemonic in ('push', 'pop', 'call', 'ret') or mnemonic.startswith('j'):
        return False
    opl = split_ops(ops) if ops else []
    if not opl:
        return False
    if mnemonic in ('mov', 'movzx', 'movsx', 'movq', 'movdqa', 'movdqu',
                    'movups', 'movaps', 'lea') or mnemonic.startswith('cmov'):
        return len(opl) >= 2 and reg in expr_regs(opl[1])
    return any(reg in expr_regs(op) for op in opl)


def writes_reg(mnemonic, ops, reg):
    opl = split_ops(ops) if ops else []
    if not opl:
        return False
    if mnemonic == 'pop':
        return reg in expr_regs(opl[0])
    if mnemonic in ('mov', 'movzx', 'movsx', 'movq', 'lea', 'xor', 'add',
                    'sub', 'inc', 'dec', 'imul', 'shl', 'shr', 'sar',
                    'rol', 'ror', 'and', 'or', 'not', 'neg',
                    'movups', 'movaps', 'movdqa', 'movdqu') \
            or mnemonic.startswith('cmov'):
        return (len(opl) >= 1 and reg in expr_regs(opl[0])
                and '[' not in opl[0])
    return False


def branch_target(ops):
    token = ops.split(',')[0].strip().split(' ')[0]
    try:
        return int(token, 16)
    except ValueError:
        return None


def build_cfg(insns):
    by_va = {va: (mn, ops) for va, mn, ops in insns}
    order = [va for va, _, _ in insns]
    next_va = {order[i]: order[i + 1] for i in range(len(order) - 1)}
    succ = {}
    for va, mn, ops in insns:
        nxt = next_va.get(va)
        if mn in ('ret', 'ud2'):
            succ[va] = []
        elif mn == 'jmp':
            target = branch_target(ops)
            succ[va] = [target] if target in by_va else []
        elif mn.startswith('j'):
            edges = []
            target = branch_target(ops)
            if target in by_va:
                edges.append(target)
            if nxt is not None:
                edges.append(nxt)
            succ[va] = edges
        else:
            succ[va] = [nxt] if nxt is not None else []
    return succ


def reachable(succ, start, blocked=frozenset()):
    seen = set()
    stack = [start]
    while stack:
        node = stack.pop()
        if node in seen or node in blocked or node not in succ:
            continue
        seen.add(node)
        stack.extend(succ[node])
    return seen


def helper_verdict(store_dominates_ret, index_compares, exits_clean):
    """Classification of the helper's store behaviour versus the
    caller's unconditional total increment."""
    if store_dominates_ret and index_compares == 0 and exits_clean:
        return ('no divergence: the index is stored as a node '
                'key on every path that returns; forward_2\'s '
                'unconditional total increment is matched by a '
                'store on every returning path')
    if not store_dominates_ret:
        return 'store-less returning path exists'
    return 'unresolved divergence surface'


def lookup_verdict(hash_constant_present, stride_58, stride_70):
    """Classification of a lookup callee versus the forward-1
    map readback hypothesis."""
    if not hash_constant_present and stride_58 and stride_70:
        return ('not the forward-1 map readback: an array '
                'element resolver (0x58/0x70 strides), with no '
                'scrambled-hash probe')
    if hash_constant_present:
        return 'map readback candidate'
    return 'inconclusive element resolution'


def authenticate(data):
    require(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
            'Node 115 artifact authentication failed')


def check_spec_pins(spec, body, start):
    for site_name, (va, expected) in spec.get('exact', {}).items():
        want = bytes.fromhex(expected)
        require(body[va - start:va - start + len(want)] == want,
                f'Pinned instruction changed at {hx(va)}')
    for site_name, (va, target) in spec.get('calls', {}).items():
        require(body[va - start] == 0xE8,
                f'Pinned call opcode changed at {hx(va)}')
        require(resolve_e8(body, start, va) == target,
                f'Resolved target changed at {hx(va)}')
    for site_name, (va, expected, slot) in spec.get('slot_calls', {}).items():
        want = bytes.fromhex(expected)
        require(body[va - start:va - start + len(want)] == want,
                f'Pinned instruction changed at {hx(va)}')
        require(resolve_slot(body, start, va, len(want)) == slot,
                f'Slot call target changed at {hx(va)}')


def analyze(data, binary=TARGET):
    section_list = sections(data)
    frames, fdes, extents = fde_extents(data)
    by_range = {(item['start'], item['end']): item for item in fdes}
    relas = relative_relocations(data)
    for slot, target in SLOT_BINDINGS.items():
        require(relas.get(slot) == target,
                f'Slot binding changed: {hx(slot)}')
    symbols = glob_dat_symbols(data)
    for slot, name in GLOB_DAT_BINDINGS.items():
        require(symbols.get(slot) == name,
                f'GLOB_DAT binding changed: {hx(slot)}')
    specs = {}
    specs.update(OWNERS)
    specs.update(CALLER)
    specs.update(EXTRA_CALLERS)
    specs.update(LOOKUP_CALLERS)
    specs.update(LOOKUPS)
    specs.update(DOWNSTREAM)
    for name, spec in specs.items():
        start, end = spec['range']
        require((start, end) in by_range, f'{name} is not an exact FDE body')
    all_ranges = [spec['range'] for spec in specs.values()]
    body_refs = [
        hx(offset) for offset in sorted(relas)
        if any(start <= offset < end for start, end in all_ranges)
    ]
    bound_targets = set(SLOT_BINDINGS.values())
    addend_refs = [
        hx(value) for value in sorted(set(relas.values()))
        if value not in bound_targets
        and any(value == start for start, _ in all_ranges)
    ]
    require(not body_refs,
            'An owner, caller or downstream body holds a relocation slot')
    require(not addend_refs,
            'An owner, caller or downstream body is reached through an '
            'unrecorded relocation')
    text = next(section for section in section_list if section['name'] == '.text')
    text_body = data[text['offset']:text['offset'] + text['size']]

    def census(opcode, targets):
        hits = {target: [] for target in targets}
        cursor = text_body.find(bytes([opcode]))
        while cursor != -1:
            site = text['address'] + cursor
            target = site + 5 + struct.unpack_from('<i', text_body,
                                                    cursor + 1)[0]
            if target in hits:
                hits[target].append(site)
            cursor = text_body.find(bytes([opcode]), cursor + 1)
        return hits

    census_targets = (HELPER, LOOKUP_A, LOOKUP_B)
    call_census = census(0xE8, census_targets)
    jump_census = census(0xE9, census_targets)
    want_sites = {
        HELPER: sorted(
            [spec['calls']['helper_call'][0] for spec in CALLER.values()]
            + [spec['calls']['helper_call'][0]
               for spec in EXTRA_CALLERS.values()]),
        LOOKUP_A: sorted(LOOKUP_A_SITES),
        LOOKUP_B: sorted(LOOKUP_B_SITES),
    }
    for spec in LOOKUP_CALLERS.values():
        site, target = spec['calls']['lookup_call']
        require(site in want_sites[target],
                'A traced lookup call site is missing from the census')
    for target in census_targets:
        require(sorted(call_census[target]) == want_sites[target],
                f'direct caller census changed for {hx(target)}')
        require(not jump_census[target],
                f'{hx(target)} gained a direct jump reference')

    frame_records = {}
    bodies = {}
    for name, spec in specs.items():
        start, end = spec['range']
        offset, body = read(data, section_list, start, end - start)
        bodies[name] = body
        record = by_range[(start, end)]
        frame_records[name] = {
            'fde': hx(record['fde']),
            'cie': hx(record['cie']),
            'lsda': hx(record['lsda']) if record['lsda'] is not None else None,
            'range': [hx(record['start']), hx(record['end'])],
            'bytes': end - start,
            'file_offset': hx(offset),
            'sha256': spec['sha256'],
        }

    def decode(name):
        spec = specs[name]
        start, end = spec['range']
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}', f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        rows = decode_export(asm, start, end, bodies[name])
        return asm, rows

    # Byte pins and resolved call targets first; the
    # disassembly-based scans run afterwards, so a mutated
    # byte is reported by the pin that covers it.
    for name, spec in specs.items():
        if 'exact' in spec or 'calls' in spec or 'slot_calls' in spec:
            check_spec_pins(spec, bodies[name], spec['range'][0])

    # ---- the helper: control-flow and index-lifetime proof ----
    spec = OWNERS['node_insert']
    start, end = spec['range']
    body = bodies['node_insert']
    asm, rows = decode(name='node_insert')
    site_vas = [va for va, _ in spec['exact'].values()]
    site_vas += [va for va, _, _ in spec['slot_calls'].values()]
    for va in site_vas:
        require(va in rows,
                f'node_insert pinned site is not a native instruction '
                f'start: {hx(va)}')
    insns = parse_asm(asm)
    require(insns[0][0] == start and insns[-1][0] + 5 == end,
            'node_insert decode does not cover the FDE body')
    by_va = {va for va, _, _ in insns}
    for va, mn, ops in insns:
        if mn.startswith('j'):
            target = branch_target(ops)
            if target is not None and start <= target < end:
                require(target in by_va,
                        f'branch target is not an instruction start: '
                        f'{hx(target)}')
    succ = build_cfg(insns)
    full = reachable(succ, start)
    unreachable = sorted(va for va, _, _ in insns if va not in full)
    require(unreachable == HELPER_UNREACHABLE,
            'Unreachable instruction set changed in node_insert')
    ret_sites = [va for va, mn, _ in insns if mn == 'ret']
    require(ret_sites == [RET_SITE], 'Return site set changed in node_insert')
    terminals = sorted(va for va in full if not succ[va])
    require(terminals == sorted([RET_SITE] + HELPER_REACHABLE_UD2),
            'Reachable terminal set changed in node_insert')
    no_store = reachable(succ, start, blocked=frozenset({FAST_STORE,
                                                         SPLIT_STORE}))
    store_dominates = RET_SITE not in no_store and EPILOGUE not in no_store
    require(store_dominates,
            'A store-less path to the return exists in node_insert')
    preds = {}
    for target in EPILOGUE_PREDS:
        found = sorted(va for va, _, _ in insns if target in succ.get(va, []))
        require(found == EPILOGUE_PREDS[target],
                f'Epilogue entry set changed for {hx(target)}')
        preds[target] = found
    r12_writes = [va for va, mn, ops in insns if writes_reg(mn, ops, 'r12')]
    require(r12_writes == HELPER_R12_WRITES,
            'Index register write set changed in node_insert')
    r12_reads = [va for va, mn, ops in insns if reads_reg(mn, ops, 'r12')]
    index_reach = reachable(
        succ, start,
        blocked=frozenset(w for w in r12_writes if w != 0x4C49F9E))
    index_reads = [va for va in r12_reads if va in index_reach]
    require(index_reads == HELPER_R12_INDEX_READS,
            'Index-valued read set changed in node_insert')
    compare_reads = [
        va for va, mn, ops in insns
        if mn in ('cmp', 'test') and reads_reg(mn, ops, 'r12')
    ]
    require(compare_reads == HELPER_R12_COMPARE_READS,
            'Index register compare set changed in node_insert')
    index_compares = [va for va in compare_reads if va in index_reach]
    require(not index_compares,
            'The helper compares the captured index against a key')
    slot_calls = {}
    direct_calls = {}
    order = [va for va, _, _ in insns]
    next_va = {order[i]: order[i + 1] for i in range(len(order) - 1)}
    for va, mn, ops in insns:
        if mn != 'call':
            continue
        length = next_va[va] - va if va in next_va else 5
        if 'rip' in ops:
            slot = resolve_slot(body, start, va, length)
            slot_calls.setdefault(slot, []).append(va)
        else:
            direct_calls[va] = branch_target(ops)
    require(slot_calls == HELPER_SLOT_CALLS,
            'Slot call census changed in node_insert')
    require(direct_calls == {0x4C4A732: UNWIND_RESUME},
            'Direct call set changed in node_insert')
    require(0x4C4A732 not in full,
            'The _Unwind_Resume call became reachable in normal flow')
    context_uses = [va for va, mn, ops in insns if '[rsp+0x50]' in ops]
    require(context_uses == [0x4C4A00D, 0x4C4A3F3],
            'Saved context record use set changed in node_insert')
    cursor_stores = [
        va for va, mn, ops in insns
        if mn in ('mov', 'movq') and ops.startswith('[')
        and 'rsi' in expr_regs(split_ops(ops)[0])
    ]
    require(not cursor_stores,
            'The helper writes through the cursor record')
    context_stores = [
        va for va, mn, ops in insns
        if mn in ('mov', 'movq') and ops.startswith('[rcx')
    ]
    require(not context_stores,
            'The helper writes through the context record pointer')
    helper_trace = {
        'index_argument': spec['index_argument'],
        'argument_contract': {
            'rdi': 'the out record pointer (saved at 0x4c4a008 on the split path; written once by the shared epilogue)',
            'rsi': 'the cursor record: {+0x0: leaf node, +0x8: 0, +0x10: insertion position} (read at 0x4c49fa1, 0x4c4a000, 0x4c49ff7 and 0x4c4a054; never written through)',
            'rdx': 'the slab slot index forwarded by forward_2',
            'rcx': 'the context record: {+0x0: sorted-set handle, +0x8: the index again, +0x10: leaf node, +0x18: 0, +0x20: position} (saved at 0x4c4a00d; only +0x0 is ever read, at the root split)',
            'r8': 'a duplicate of the cursor record pointer (set at forward_2 0x51d1c13); never read by the helper before it is overwritten',
        },
        'caller_setup': {
            'spill_index': hx(0x51D1BE2),
            'cursor_argument': hx(0x51D1C13),
            'context_argument': hx(0x51D1C22),
            'index_argument': hx(0x51D1C27),
            'call_site': hx(0x51D1C2A),
            'handle_reload': hx(0x51D1C2F),
            'form': ('after the call, forward_2 reloads the '
                     'handle and jumps to its shared total '
                     'increment (0x51d1bcf); the helper return '
                     'value and out record are discarded'),
            'other_call_sites': [hx(0x51D4A4A), hx(0x51D4BAA)],
            'other_callers_form': ('two 351-byte structural '
                                   'twins of forward_2 '
                                   '(0x51d4920, 0x51d4a80) call '
                                   'the helper with the '
                                   'instruction-identical setup; '
                                   'the values they pass are '
                                   'not traced'),
        },
        'capture': {
            'site': hx(0x4C49F9E),
            'register': 'r12',
            'instruction': 'mov r12, rdx',
            'index_valued_read_sites': [hx(va) for va in index_reads],
            'write_sites': [hx(va) for va in r12_writes],
            'rewrite_form': ('after the leaf-level store, r12 '
                             'is rewritten to a node pointer at '
                             '0x4c4a1f4 (parent split) and '
                             '0x4c4a3fb (root split), picked as '
                             'an insert target at 0x4c4a2c5, and '
                             'reused as a fixup-loop counter '
                             'from 0x4c4a4a3; every later read '
                             'uses one of those values'),
            'compare_sites': [hx(va) for va in compare_reads],
            'duplicate_check': ('no instruction compares the '
                                'captured index against a node '
                                'key; the helper has no duplicate '
                                'path and trusts the caller\'s '
                                'cursor position and counts'),
        },
        'node_layout': {
            'plus_0x0': 'parent node pointer (0 at the root)',
            'keys': 'sorted qword keys from node+0x8, at most 11',
            'child_index_word': 'node+0x60: this node\'s index in its parent\'s child array',
            'key_count_word': 'node+0x62',
            'child_edges': 'from node+0x68, at most 12',
            'leaf_bytes': 0x68,
            'internal_bytes': 0xC8,
        },
        'fast_path': {
            'gate': 'key count (word at node+0x62, loaded at 0x4c49fa4) below 0xb at 0x4c49fa8/0x4c49fac',
            'shift': 'memmove (slot 0x64df568, call at 0x4c49fdd) moves keys[position..count) one slot up when position+1 <= count',
            'index_store': hx(FAST_STORE),
            'store_form': 'mov QWORD PTR [rbp+rax*8+0x8], r12 -- the index becomes the key at node+0x8+position*8',
            'count_store': hx(0x4C49FF3),
            'exit': 'jmp 0x4c4a5da (0x4c49ffb), entering the epilogue past the out-field reloads with rax = position and rcx = [cursor+0x8]',
        },
        'leaf_split': {
            'gate': 'key count at least 0xb',
            'split_points': ('separator index S and target by '
                             'insertion position P: P < 5 -> '
                             'S = 4, insert into the old node at '
                             'P; P = 5 -> S = 5, old node at 5; '
                             'P = 6 -> S = 5, new node at 0; '
                             'P >= 7 -> S = 6, new node at P-7'),
            'alloc': 'a fresh 0x68-byte node via slot 0x64df480 at 0x4c4a062; a null result diverts to the allocation-failure blocks (slot 0x64df490) and the ud2 terminal',
            'new_node_count': 'count-S-1 (computed by the not/add idiom at 0x4c4a085/0x4c4a088/0x4c4a08b, stored at 0x4c4a08e); a count of 0xc or more diverts to the capacity panic (slot 0x64df570)',
            'key_copy': 'memcpy (slot 0x64df508, call at 0x4c4a0b5) copies keys[S+1..count) into the new node; the separator keys[S] is loaded into r13 at 0x4c4a09d',
            'old_node_count': 'S, stored at 0x4c4a0bb before the insert',
            'target_pick': 'cmove at 0x4c4a0c7 selects the old node (rbp) or the new node (r15) as rcx',
            'index_store': hx(SPLIT_STORE),
            'store_form': 'mov QWORD PTR [rcx+rax*8+0x8], r12 -- the index becomes the key at target+0x8+position*8, before any propagation',
            'count_store': hx(0x4C4A11E),
            'memmove': 'slot 0x64df568, call at 0x4c4a108, shifts the target tail when its count exceeds the position',
        },
        'propagation': {
            'form': ('after the leaf store, the separator key '
                     '(never the index) is inserted into the '
                     'parent; a full parent (count >= 0xb) is '
                     'split the same way -- fresh 0xc8 node via '
                     'slot 0x64df480 at 0x4c4a1e5, keys and '
                     'children copied via slot 0x64df508 at '
                     '0x4c4a245/0x4c4a28d -- and the loop at '
                     '0x4c4a140 climbs; the level counter '
                     'seeded from [cursor+0x8] is incremented '
                     'once per split level (0x4c4a273)'),
            'precondition': ('the propagation head panics '
                             '(slot 0x64df730 at 0x4c4a642) if '
                             'the level counter seed is nonzero '
                             'on the first climb -- unreachable '
                             'from forward_2, whose cursor+0x8 '
                             'is 0 -- but only after the leaf '
                             'store has executed'),
            'absorb_separator_store': hx(0x4C4A50B),
            'absorb_child_store': hx(0x4C4A514),
            'absorb_count_store': hx(0x4C4A519),
            'split_separator_store': hx(0x4C4A32C),
            'split_child_store': hx(0x4C4A33A),
            'split_count_store': hx(0x4C4A33F),
        },
        'root_split': {
            'entry': 'the split node\'s parent pointer is 0 (leaf-as-root via 0x4c4a3ea, or the climb reaches the root)',
            'context_use': 'the saved context record pointer ([rsp+0x50], stored at 0x4c4a00d) is read at 0x4c4a3f3; record+0x0 is the handle',
            'asserts': ('a null current root (slot 0x64df830 '
                        'at 0x4c4a6a3), a null split node '
                        '(0x4c4a6c2), a level counter unequal '
                        'to the handle height (slot 0x64df730 '
                        'at 0x4c4a6dd) and a new-root count at '
                        'or above 0xb (0x4c4a6f6) all abort; '
                        'none returns'),
            'alloc': 'a fresh 0xc8-byte root via slot 0x64df480 at 0x4c4a415',
            'stores': {
                'old_root_as_child_0': hx(0x4C4A434),
                'old_root_parent': hx(0x4C4A449),
                'handle_root': hx(0x4C4A455),
                'handle_height': hx(0x4C4A458),
                'separator_key': hx(0x4C4A483),
                'new_node_child': hx(0x4C4A488),
            },
            'form': 'the new root receives exactly one key -- the separator -- and two children; the handle root and height are updated in place',
        },
        'exits': {
            'ret': hx(RET_SITE),
            'epilogue_entries': {hx(k): [hx(v) for v in vals]
                                 for k, vals in preds.items()},
            'epilogue_form': ('[out] = rbp, [out+0x8] = rcx, '
                              '[out+0x10] = rax at '
                              '0x4c4a5da/0x4c4a5dd/0x4c4a5e1; '
                              'rax = rdi at 0x4c4a5e5; on the '
                              'fast path the record is {node, '
                              '[cursor+0x8], position}'),
            'reachable_ud2_terminals': [hx(va) for va in
                                        HELPER_REACHABLE_UD2],
            'unreachable_from_entry': [hx(va) for va in unreachable],
            'unreachable_form': ('the two _Unwind_Resume '
                                 'landing pads '
                                 '(0x4c4a710--0x4c4a732, cleanup '
                                 'via slot 0x64df4a0) are '
                                 'LSDA-only; the remaining '
                                 'unreachable instructions are '
                                 'three NOP alignment pads '
                                 '(0x4c4a13a, 0x4c4a19a, '
                                 '0x4c4a57e) and the second pad '
                                 'ud2 at 0x4c4a70e'),
            'instruction_count': len(insns),
            'reachable_instruction_count': len(full),
        },
        'context_record_fate': ('saved once (0x4c4a00d), read '
                                'once (0x4c4a3f3, field +0x0 '
                                'only); never written through; '
                                'its +0x8 copy of the index is '
                                'never read -- the index comes '
                                'from rdx'),
        'cursor_record_fate': ('read-only: fields +0x0, +0x8 '
                               'and +0x10; no store through rsi '
                               'exists in the body'),
        'slot_call_census': {hx(k): [hx(v) for v in vals]
                             for k, vals in slot_calls.items()},
        'slot_bindings_used': {
            hx(k): hx(v) for k, v in SLOT_BINDINGS.items()
            if k in slot_calls or k == 0x64DF770
        },
        'glob_dat_bindings_used': {
            hx(k): v for k, v in GLOB_DAT_BINDINGS.items()
            if k in slot_calls
        },
        'every_path_store_proof': {
            'method': ('instruction-level control-flow graph '
                       'over the 473 decoded instructions; '
                       'with the two index store instructions '
                       'removed, neither the epilogue entry '
                       '0x4c4a5da nor the single ret 0x4c4a5f6 '
                       'is reachable from the entry; calls are '
                       'modelled as fall-through, and every '
                       'reachable non-returning terminal is a '
                       'ud2 behind a panic or '
                       'allocation-failure block'),
            'store_sites': [hx(FAST_STORE), hx(SPLIT_STORE)],
        },
        'verdict': helper_verdict(True, 0, True),
    }

    # ---- the lookup callees: not the forward-1 map readback ---
    import bisect
    fde_ends = {start: end for start, end in by_range}
    fde_starts = sorted(fde_ends)

    def containing_fde(va):
        idx = bisect.bisect_right(fde_starts, va) - 1
        if idx < 0:
            return None
        start = fde_starts[idx]
        return start if start <= va < fde_ends[start] else None

    lookup_traces = {}
    for name, spec in LOOKUPS.items():
        lstart, lend = spec['range']
        lbody = bodies[name]
        lasm, lrows = decode(name)
        site_vas = [va for va, _ in spec['exact'].values()]
        site_vas += [va for va, _, _ in spec['slot_calls'].values()]
        site_vas += list(spec['materialisation_calls'])
        for va in site_vas:
            require(va in lrows,
                    f'{name} pinned site is not a native instruction '
                    f'start: {hx(va)}')
        linsns = parse_asm(lasm)
        direct = {}
        lslot = {}
        lorder = [va for va, _, _ in linsns]
        lnext = {lorder[i]: lorder[i + 1] for i in range(len(lorder) - 1)}
        for va, mn, ops in linsns:
            if mn != 'call':
                continue
            length = lnext[va] - va if va in lnext else 6
            if 'rip' in ops:
                lslot.setdefault(
                    resolve_slot(lbody, lstart, va, length), []).append(va)
            else:
                direct[va] = branch_target(ops)
        require(direct == spec['materialisation_calls'],
                f'Direct call set changed in {name}')
        panic_sites = [va for _, (va, _, _) in spec['slot_calls'].items()]
        require(lslot == {0x64DF770: panic_sites},
                f'Slot call census changed in {name}')
        hash_present = HASH_CONST_LE in lbody
        require(not hash_present,
                f'{name} gained the forward-1 hash constant')
        rol14 = [va for va, mn, ops in linsns
                 if mn == 'rol' and '0x14' in ops]
        require(not rol14, f'{name} gained a rol-by-0x14 probe rotation')
        stride58 = spec['exact']['stride_58'][0]
        stride70 = spec['exact']['stride_70'][0]
        lookup_traces[name] = {
            'range': [hx(lstart), hx(lend)],
            'bytes': lend - lstart,
            'sha256': spec['sha256'],
            'argument': 'rdi: a container record pointer',
            'entry_loads': {
                'plus_0x8': hx(spec['exact']['base_load'][0]),
                'plus_0x10': hx(spec['exact']['array_load'][0]),
                'plus_0x18': hx(spec['exact']['index_load'][0]),
                'mode_gate': hx(spec['exact']['mode_gate'][0]),
            },
            'fast_path': {
                'form': ('when dword [rdi] == 1 and [rdi+0x8] '
                         'is nonzero (or after the '
                         'materialisation call returns a base), '
                         'returns [rdi+0x8] + [rdi+0x18]*0x58 + '
                         '0x8 -- an element pointer, not a '
                         'stored value'),
                'stride_site': hx(stride58),
                'offset_site': hx(spec['exact']['fast_offset'][0]),
            },
            'slow_path': {
                'form': ('otherwise a descriptor is built '
                         'from the record (fields +0x20.. and '
                         'the dwords at +0x34/+0x3c) and passed '
                         'to a materialisation call; the '
                         'result is indexed at a 0x70 stride '
                         'with the element at +0x18, after a '
                         'bounds check against the array count '
                         'that aborts via slot 0x64df770'),
                'stride_site': hx(stride70),
                'materialisation_calls': {hx(k): hx(v)
                                          for k, v in direct.items()},
            },
            'probe_signature': {
                'hash_constant_present': hash_present,
                'rol_0x14_sites': [hx(va) for va in rol14],
                'entry_stride_bytes': [0x58, 0x70],
                'forward_1_entry_bytes': 24,
            },
            'call_census': {
                'direct_e8_call_sites': [
                    hx(va) for va in want_sites[lstart]
                ],
                'containing_fdes': {
                    hx(va): hx(containing_fde(va))
                    for va in want_sites[lstart]
                },
                'form': ('a shared container accessor: each '
                         'RE-006 caller calls its lookup four '
                         'times, and further FDEs call it too; '
                         'the site traced by the twin-caller '
                         'packet is the one whose result feeds '
                         'forward_2'),
            },
            'verdict': lookup_verdict(False, True, True),
        }

    # Body digests verified after pin/scan checks so a mutated
    # byte is reported by the check that pins it.
    for name, spec in specs.items():
        require(sha(bodies[name]) == spec['sha256'],
                f'{name} body changed')

    callers_record = {}
    for name, spec in CALLER.items():
        callers_record[name] = {
            'range': [hx(spec['range'][0]), hx(spec['range'][1])],
            'bytes': spec['range'][1] - spec['range'][0],
            'sha256': spec['sha256'],
            'call_sites': {
                site_name: hx(va)
                for site_name, (va, _) in spec['calls'].items()
            },
        }
    for name, spec in LOOKUP_CALLERS.items():
        callers_record[name] = {
            'range': [hx(spec['range'][0]), hx(spec['range'][1])],
            'bytes': spec['range'][1] - spec['range'][0],
            'sha256': spec['sha256'],
            'call_sites': {
                site_name: hx(va)
                for site_name, (va, _) in spec['calls'].items()
            },
        }
    for name, spec in EXTRA_CALLERS.items():
        callers_record[name] = {
            'range': [hx(spec['range'][0]), hx(spec['range'][1])],
            'bytes': spec['range'][1] - spec['range'][0],
            'sha256': spec['sha256'],
            'call_sites': {
                site_name: hx(va)
                for site_name, (va, _) in spec['calls'].items()
            },
            'note': ('structural twin of forward_2 with the '
                     'identical helper argument setup; the '
                     'values it passes are not traced'),
        }
    downstream_record = {
        name: {
            'range': [hx(spec['range'][0]), hx(spec['range'][1])],
            'bytes': spec['range'][1] - spec['range'][0],
            'sha256': spec['sha256'],
            'via': spec['via'],
        }
        for name, spec in DOWNSTREAM.items()
    }
    return {
        'schema': 1,
        'target': {
            'release': 115,
            'bytes': TARGET_SIZE,
            'sha256': TARGET_SHA256,
        },
        'relocation_diagnostics': {
            'relative_relocation_count': len(relas),
            'body_slot_references': body_refs,
            'body_addend_references': addend_refs,
            'slot_bindings': {hx(k): hx(v) for k, v in SLOT_BINDINGS.items()},
            'glob_dat_bindings': {hx(k): v for k, v in
                                  GLOB_DAT_BINDINGS.items()},
        },
        'capture': {
            'fde_count': len(fdes),
            'cie_records': frames['cie_records'],
            'fde_records': frames['fde_records'],
            'unique_fde_starts': frames['unique_fde_starts'],
            'gap_extents_outside_fdes': len(extents),
        },
        'scope': {
            'instruction': (
                'Trace the node insert/split helper 0x4c49f90 '
                'end to end: its argument contract, and on '
                'every path (non-full insert, leaf split, '
                'split propagation, root split, duplicate or '
                'error paths) whether and where the forwarded '
                'slab slot index (rdx, plus a copy in the '
                'context record at rcx) is written as a node '
                'key -- and whether forward_2\'s unconditional '
                'handle-total increment after the call can '
                'diverge from an actual store.  Secondary: '
                'whether the caller lookup callees 0x4da81b0 / '
                '0x4da7880 are the forward-1 map readback.'
            ),
            'measured_denominator_bytes': sum(
                spec['range'][1] - spec['range'][0]
                for spec in OWNERS.values()
            ),
            'owners': list(OWNERS),
            'complete_fdes': len(OWNERS),
            'owner_body_bytes': sum(
                spec['range'][1] - spec['range'][0]
                for spec in OWNERS.values()
            ),
        },
        'frames': frame_records,
        'owners': {
            name: {
                'range': [hx(spec['range'][0]), hx(spec['range'][1])],
                'bytes': spec['range'][1] - spec['range'][0],
                'sha256': spec['sha256'],
                'index_argument': spec['index_argument'],
            }
            for name, spec in OWNERS.items()
        },
        'boundaries': {
            'callers': callers_record,
            'lookups': {
                name: {
                    'range': [hx(spec['range'][0]),
                              hx(spec['range'][1])],
                    'bytes': spec['range'][1] - spec['range'][0],
                    'sha256': spec['sha256'],
                }
                for name, spec in LOOKUPS.items()
            },
            'downstream': downstream_record,
            'direct_e8_call_sites': {
                hx(target): [hx(va) for va in want_sites[target]]
                for target in census_targets
            },
            'direct_e9_references': {hx(target): []
                                     for target in census_targets},
        },
        'trace': {
            'node_insert': helper_trace,
            'lookup_a': lookup_traces['lookup_a'],
            'lookup_b': lookup_traces['lookup_b'],
        },
    }


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    report = analyze(data, binary)
    output.mkdir(parents=True, exist_ok=True)
    raw = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    ranges = [
        spec['range']
        for spec in (list(OWNERS.values()) + list(CALLER.values())
                     + list(EXTRA_CALLERS.values())
                     + list(LOOKUP_CALLERS.values())
                     + list(LOOKUPS.values())
                     + list(DOWNSTREAM.values()))
    ]
    lines = [
        line.replace(str(binary), '<authenticated-node115>')
        for line in raw.splitlines()
        if any(f'pc={start:016x}..{end:016x}' in line for start, end in ranges)
    ]
    require(len(lines) == len(report['frames']),
            'Retained readelf frame changed')
    (output / 'frames.txt').write_text('\n'.join(lines) + '\n')
    exports = {}
    for name, spec in list(OWNERS.items()) + list(LOOKUPS.items()):
        owner_exports = {}
        for window_name, (win_start, win_end) in spec['windows'].items():
            asm = subprocess.check_output([
                'objdump', '-d', '-M', 'intel', '--insn-width=16',
                f'--start-address={win_start:#x}',
                f'--stop-address={win_end:#x}',
                str(binary),
            ], text=True)
            safe_name = f'{name}_{window_name}_{win_start:x}_{win_end:x}_objdump.txt'
            rendered = asm.replace(str(binary), '<authenticated-node115>')
            (output / safe_name).write_text(rendered)
            owner_exports[window_name] = {
                'file': safe_name,
                'sha256': sha(rendered.encode()),
                'range': [hx(win_start), hx(win_end)],
            }
        exports[name] = owner_exports
    report['source_exports'] = exports
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else TARGET
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else PACKET
    generate(binary, output)
    print(output / 'records.json')


if __name__ == '__main__':
    main()
