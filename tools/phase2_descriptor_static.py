#!/usr/bin/env python3
"""Static evidence for the RE-015 phase-2 descriptor emission.

The RE-015 map-owner packet (#2479) pinned the large consumer's
phase-2 probe walk: it loads only the found entry's capacity word
and compares it against the sentinel 0x8000000000000000 at
0x15a45e0, and it left open what the probe's two branches emit.
This packet traces that emission end to end.

The compare's fall-through (capacity == sentinel) branch and the
0x15a4840 (capacity != sentinel) branch first execute a
byte-identical build: a 0x38-byte descriptor record assembled at
[rsp+0x20] from the 48-byte .rodata log-format string at 0x468adf
('{d(%Y-%m-%d %H:%M:%S.%f)} {l} {f}:{L} >>> {m}{n}'), handed with
the consumer's r12 (the scratch header block at [rsp+0x90] on
every path into phase 2) to the descriptor stream collect
function 0x474d890; then a second record is built from the three
words the collect call has just written at [rsp+0x90] plus a
boxed copy of the same format string.  The byte streams of the
two builds agree outside their displacement fields, which decode
to the same targets.

0x474d890 itself is a stream collector.  It seeds a cursor from
the descriptor record it receives (the record's first 0x38 bytes
are copied to its stack; the record itself is stored nowhere),
repeatedly expands the cursor through the function behind slot
0x64eafb0 (0x4744b60) and yields 0x58-byte element records
through the function behind slot 0x64eaf10 (0x4735b30); a tag of
5 (a dword in the expanded state, a qword in the yielded record)
ends the walk, every yielded record is appended verbatim to a
growable vector (element size 0x58, initial capacity 4, initial
allocation 0x160, growth through 0x474e640), and the vector
header {capacity, buffer, count} is written to its first
argument and returned.  An immediately-terminal stream stores
the empty header {0, 8, 0}.

Only after that identical prefix do the branches diverge.  The
sentinel branch rewrites the second record's header in place to
{boxed string record, 0x63ffbd0, word 0} and calls the function
bound to slot 0x64e1458 (0x47473c0) with the descriptor record,
which that function overwrites in place with a six-field record
built from the second record's first two words, its +0x10/+0x11
bytes, and a global configuration lookup (once-initialised state
at 0x64fdbe0/0x64fdbe8/0x64fe408/0x64fe440 plus isatty behind
GLOB_DAT slot 0x64eaf90); it then stores a 0x30-byte heap copy of
the transformed descriptor into the consumer's second structure
under tag 0x63ffbf8.  The non-sentinel branch instead stores the
boxed second record into the scratch block at [rsp+0x90] under
the same 0x63ffbd0 word with flag byte 1 at +0x10, reads the
found entry's pointer/length words (the only read of the entry
beyond the capacity word), runs the format consumer behind slot
0x64df6e8 over the '_overflow{}' piece with those words as its
argument, calls the function behind slot 0x64e1460 (0x473c130)
with the descriptor record, inserts the descriptor into a map
through 0x156f680 (its only direct caller in the binary), and
stores a 0x70-byte heap snapshot of [rsp+0x20..0x90] into the
second structure under tag 0x63ffc70.  So the branch changes
what is emitted after the shared prefix -- destination, extra
callees, and the second-structure payload -- but not the
descriptor record's contents, the collect call, or its result.

No captured code was executed.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export, require


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-015-node115-phase2-descriptor-emission'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SENTINEL = 0x8000000000000000

CONSUMER = 0x15a3b90
CONSUMER_END = 0x15a6509
CONSUMER_SHA = '7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb'
COLLECT = 0x474d890
COLLECT_END = 0x474dadd
COLLECT_SHA = '4514bf01206da3b66445a38797f30810be0986c60d0b603943f25bb5bd551102'
BIND = 0x47473c0
BIND_END = 0x47475b9
BIND_SHA = 'b520689de276f092431c1551c2de71915a728cc43666c51b1ff5b9a92766db26'

FORMAT_STRING = 0x468adf
FORMAT_STRING_BYTES = b'{d(%Y-%m-%d %H:%M:%S.%f)} {l} {f}:{L} >>> {m}{n}'
FORMAT_PIECE2 = 0x468b0f
OVERFLOW_PIECE = 0x445923
OVERFLOW_PIECE_BYTES = bytes.fromhex('c00b') + b'_overflow{}'
RECORD_TAG_WORD = 0x63ffbd0
PAYLOAD_TAG_SENTINEL = 0x63ffbf8
PAYLOAD_TAG_PRESENT = 0x63ffc70
INSERT_TAG = 0x63ffc28
DEFAULT_RECORD_TAG = 0x6495038
BIND_TABLE_OBJECT = 0x64fe408
BIND_SLOT_OBJECT = 0x6500060
BIND_STATE_WORD = 0x64fdbe0
BIND_CONFIG_BYTE = 0x64fdbe8
BIND_TABLE_DWORD = 0x64fe440

OWNERS = {
    'large_consumer': (CONSUMER, CONSUMER_END, CONSUMER_SHA),
    'descriptor_stream_collect': (COLLECT, COLLECT_END, COLLECT_SHA),
    'descriptor_record_bind': (BIND, BIND_END, BIND_SHA),
}

BOUNDARIES = {
    'stream_visit': (0x4744b60, 0x47461a0,
                     '46b34fdd460b872f3185b17a926718f502cab985d13c23b72cf6a949d8fd95f5'),
    'stream_next': (0x4735b30, 0x47369f5,
                    'df0ae0145e912e7429f45c17380cb1764bfdd4e9e4bc6a72ed7eb1412973d107'),
    'collect_grow': (0x474e640, 0x474e6bf,
                     '43935a1cdae8c5854d4a239f0992801b4808673b0bb5ff24da951160a868e8bf'),
    'collect_cleanup_a': (0x474dc90, 0x474dcca,
                          '94793d642a473b6e95b51ca6230d5d4669f9615a94af178549d9ff3097d8f9d2'),
    'collect_cleanup_b': (0x474e050, 0x474e0ac,
                          '91b4d30f40c6b7bdc620f7e6e286bb7547861e8e5fecf2507b0bf75f193b5006'),
    'bind_once_init': (0x4752c90, 0x4752cd7,
                       'f8129a3041146c7dd1184471e57f0e2cec74d585b66caaca22aff179c8db4f6d'),
    'bind_table_init': (0x5c6c15a, 0x5c6c1ae,
                        'a32a6ff3dec82ef5d016ddaa52d1a0fbf751712134decf6c08570ba2b0ffe184'),
    'bind_default_producer': (0x4739ff0, 0x473a0f8,
                              'a5606da75247dacef820881ce0450a16f0631b5817d79acae77f40cb98823406'),
    'descriptor_emit': (0x473c130, 0x473c63f,
                        '9b97c0e64ab18d276a48d9477ffba097ca349189c06a2f6d0da3478fb4571515'),
    'format_consumer': (0x141e3a0, 0x141e538,
                        'aa4d4d0611c533e38c65e1577c0426b5163846c01225556743d4d4345cadd1fe'),
    'descriptor_map_insert': (0x156f680, 0x15709e9,
                              '7aaeefbdcb060aba7030de2292e09df0cc20dca32f20fca54689eea5940f2d6c'),
    'second_tree_insert': (0x1497040, 0x1497c54,
                           'e5bff7414cd63e3f4e74c81467ee0d344f5cfbee64df648d7ee2ab0454191b26'),
    'alloc': (0x6355830, 0x63558f2,
              '72c29274a75359df7c598d254d102cbab84f51d359256facb415bb90bffec5af'),
    'dealloc': (0x635de30, 0x635ded5,
                '714fc5cdd28a2587427c9dac8a25685ec09695a3a21bc9af0eb09b29ae503f61'),
    'format_args_drop': (0x15ebba0, 0x15ebbb3,
                         'd6974989f446c3a376ca22e23d3f5d3c3744b9d15284072762999e6ccc1198bc'),
}

SLOT_BINDINGS = {
    'stream_visit': (0x64eafb0, 8, 0x4744b60),
    'stream_next': (0x64eaf10, 8, 0x4735b30),
    'descriptor_bind': (0x64e1458, 8, BIND),
    'descriptor_emit': (0x64e1460, 8, 0x473c130),
    'bind_default_record': (0x64e12f8, 8, 0x4739ff0),
    'bind_object_pointer': (0x64eaf58, 8, BIND_SLOT_OBJECT),
    'alloc': (0x64df480, 8, 0x6355830),
    'dealloc': (0x64df4a0, 8, 0x635de30),
    'format_consumer': (0x64df6e8, 8, 0x141e3a0),
    'alloc_error': (0x64df498, 8, 0x141e264),
}
ISATTY_SLOT = 0x64eaf90
ISATTY_RELOCATION = (6, 74)
ISATTY_NAME = 'isatty'

WINDOWS = [
    ('consumer_entry', 0x15a3b90, 0x15a3bf7),
    ('consumer_phase2_branch_a', 0x15a44e0, 0x15a4737),
    ('consumer_phase2_tail_a', 0x15a4737, 0x15a4840),
    ('consumer_phase2_branch_b', 0x15a4840, 0x15a4ca2),
]
FULL_EXPORTS = [
    ('descriptor_stream_collect', COLLECT, COLLECT_END),
    ('descriptor_record_bind', BIND, BIND_END),
]

CONSUMER_PINS = {
    'entry_rdi_save': (0x15a3ba1, '4889bc2478020000'),
    'sentinel_load': (0x15a3bd5, '48bd0000000000000080'),
    'scalar_save': (0x15a3c29, '898c242c020000'),
    'lea_r12_scratch': (0x15a42be, '4c8da42490000000'),
    'phase2_tree_init': (0x15a44e0, '48c78424b801000000000000'),
    'probe_compare': (0x15a45e0, '48392b'),
    'build_a_lea_fmt': (0x15a45e9, '488d05ef44ecfe'),
    'build_a_tagword': (0x15a4618, 'c744245001001100'),
    'collect_call_a': (0x15a4626, 'e865921a03'),
    'second_len_a': (0x15a467c, '48c78424d800000030000000'),
    'second_strptr_a': (0x15a4688, '48898424e0000000'),
    'bind_hdr_a': (0x15a46d0, '48898424c0000000'),
    'bind_word_a': (0x15a46df, '48898424c8000000'),
    'bind_zero_a': (0x15a46e7, '66c78424d00000000000'),
    'bind_call': (0x15a46fc, 'ff1556cdf304'),
    'payload_tag_a': (0x15a4730, '488d1dc1b4e504'),
    'build_b_lea_fmt': (0x15a4840, '488d059842ecfe'),
    'collect_call_b': (0x15a487d, 'e80e901a03'),
    'boxed_store_b': (0x15a492a, '4889842490000000'),
    'block_flag_b': (0x15a4941, 'c68424a000000001'),
    'entry_words_b': (0x15a4949, '0f104308'),
    'format_call_b': (0x15a498b, 'ff1557adf304'),
    'emit_call_b': (0x15a49b1, 'ff15a9caf304'),
    'insert_call_b': (0x15a4ab4, 'e8c7abfcff'),
    'snapshot_size_b': (0x15a4b29, 'bf70000000'),
    'payload_tag_b': (0x15a4b8f, '488d1ddab0e504'),
}
COLLECT_PINS = {
    'visit_call_1': (0x474d8ac, 'ff15fed6d901'),
    'tag_check_state_1': (0x474d8b2, '837c242005'),
    'next_call_1': (0x474d8c3, 'ff1547d6d901'),
    'tag_check_elem_1': (0x474d8c9, '48837c247805'),
    'empty_store_cap': (0x474d8d1, '48c70300000000'),
    'empty_store_buf': (0x474d8d8, '48c7430808000000'),
    'initial_alloc': (0x474d8ed, 'bf60010000'),
    'header_capacity': (0x474d94d, '48c744240804000000'),
    'header_count': (0x474d95b, '48c744241801000000'),
    'seed_copy': (0x474d98e, '0f298424d0000000'),
    'grow_compare': (0x474da38, '4c3b7c2408'),
    'grow_call': (0x474da57, 'e8e40b0000'),
    'result_store': (0x474da6b, '48894310'),
}
BIND_PINS = {
    'path_byte': (0x47473db, '807e1001'),
    'word2_slot_load': (0x47473f2, '4c8b3d5f3bda01'),
    'word2_table_lea': (0x4747438, '4c8d3dc96fdb01'),
    'isatty_arg2': (0x4747461, 'bf02000000'),
    'isatty_arg1': (0x474747f, 'bf01000000'),
    'flag_load': (0x47474ab, '410fb66e11'),
    'input_word0': (0x47474ba, '4d8b3e'),
    'default_call': (0x47474e4, 'ff150e9ed901'),
    'default_tag': (0x4747507, '488d052adbd401'),
    'out_flag_store': (0x4747525, '40886b28'),
}

COLLECT_CFG = {
    (0x474d8b7, 0x474d8d1), (0x474d8cf, 0x474d8ed),
    (0x474d8e8, 0x474da77), (0x474d8fb, 0x474da8c),
    (0x474d9b1, 0x474da0c), (0x474da20, 0x474da66),
    (0x474da36, 0x474da66), (0x474da3d, 0x474d9c0),
    (0x474da57, 0x474e640), (0x474da61, 0x474d9c0),
    (0x474daa6, 0x474dc90), (0x474daab, 0x474dacf),
    (0x474dab5, 0x474dc90), (0x474daba, 0x474dac5),
    (0x474daca, 0x474e050), (0x474dad2, 0x63f0a50),
}
BIND_CFG = {
    (0x47473df, 0x4747420), (0x47473e5, 0x474753b),
    (0x4747400, 0x4747461), (0x474740f, 0x47474ab),
    (0x474741b, 0x47474ba), (0x4747424, 0x474754f),
    (0x4747433, 0x474747f), (0x4747442, 0x4747496),
    (0x4747453, 0x4747573), (0x474745f, 0x47474ba),
    (0x4747475, 0x47474ab), (0x474747d, 0x47474ba),
    (0x4747494, 0x4747444), (0x47474a2, 0x474757d),
    (0x47474c0, 0x47474c8), (0x47474c6, 0x474750e),
    (0x47474d6, 0x4747563), (0x4747545, 0x4752c90),
    (0x474754a, 0x47473eb), (0x4747559, 0x4752c90),
    (0x474755e, 0x474742a), (0x4747573, 0x5c6c15a),
    (0x4747578, 0x4747459), (0x474757d, 0x5c6c15a),
    (0x4747582, 0x47474a8), (0x4747591, 0x4746670),
    (0x4747596, 0x47475b1), (0x47475b4, 0x63f0a50),
}

# The two branch builds, as (start, end) byte ranges in the
# consumer body.  Segment 1 is the descriptor build plus the
# collect call; segment 2 is the boxing of the format string,
# the second-record build, and its boxing allocation.  Inside a
# segment the branches are byte-identical outside the listed
# displacement fields (segment-relative byte ranges).
BUILD_SEGMENTS = [
    {'a': (0x15a45e9, 0x15a462b), 'b': (0x15a4840, 0x15a4882),
     'displacements': [(3, 7), (29, 33), (62, 66)]},
    {'a': (0x15a462b, 0x15a46ad), 'b': (0x15a4882, 0x15a4904),
     'displacements': [(0x0d, 0x11), (0x14, 0x18), (0x1f, 0x23),
                       (0x2a, 0x2e), (0x7e, 0x82)]},
]


def branch_for(capacity_word):
    """The phase-2 branch taken for a found entry, modelling
    the pinned compare at 0x15a45e0 against the sentinel the
    consumer loads at its entry: capacity == sentinel selects
    the fall-through descriptor-bind branch; any other capacity
    selects the 0x15a4840 entry-format branch."""
    return 'sentinel_bind' if capacity_word == SENTINEL else 'present_format'


def descriptor_record_fields():
    """The descriptor record both branches build at [rsp+0x20],
    as the written (offset, value) fields.  The collect function
    consumes the record's first 0x38 bytes; the branch builds
    write every field below and never write offset +0x28."""
    return {0x00: FORMAT_STRING, 0x08: 0x30,
            0x10: FORMAT_STRING, 0x18: FORMAT_PIECE2,
            0x20: 0, 0x30: 0x110001}


def collect_model():
    """The collect function's pinned constants: element size,
    initial capacity and allocation, the terminal tag, and the
    empty-stream result header."""
    return {'element_bytes': 0x58, 'initial_capacity': 4,
            'initial_allocation': 0x160, 'terminal_tag': 5,
            'empty_header': (0, 8, 0)}


def collect_header(capacity, buffer, count):
    """The 24-byte vector header the collect function stores
    to its first argument: {capacity, buffer, count}."""
    return (capacity, buffer, count)


def second_record_fields(header, string_copy):
    """The second record, built identically on both branches
    from the collect result header's three words plus the boxed
    format-string copy: (cap, buffer, count, 0x30, copy, 0x30).
    """
    capacity, buffer, count = header
    return (capacity, buffer, count, 0x30, string_copy, 0x30)


def bind_path(second_byte_0x10):
    """The bind function's path selection on the second
    record's +0x10 byte: 1 selects the slot-object word
    (0x6500060), anything else the global-table word
    (0x64fe408)."""
    return 'slot_object' if second_byte_0x10 == 1 else 'global_table'


def bind_consumer_call_output(boxed_record):
    """The record the bind function writes over the descriptor
    record for the consumer's sentinel-branch call, under the
    file-initial global state (state word 0, config byte 3,
    table dword 3): the call takes the global-table path, the
    isatty arms are not reached, and the output is {1, 0,
    0x64fe408, boxed record, 0x63ffbd0, flag byte 1}."""
    return {'word_0x00': 1, 'word_0x08': 0,
            'word_0x10': BIND_TABLE_OBJECT,
            'word_0x18': boxed_record,
            'word_0x20': RECORD_TAG_WORD, 'byte_0x28': 1}


def second_structure_payload(branch):
    """What each branch stores into the consumer's second
    structure: the sentinel branch a 0x30-byte heap copy of the
    bind-transformed descriptor record under tag 0x63ffbf8, the
    present branch a 0x70-byte heap snapshot of
    [rsp+0x20..0x90] under tag 0x63ffc70."""
    if branch == 'sentinel_bind':
        return {'bytes': 0x30, 'tag': PAYLOAD_TAG_SENTINEL}
    if branch == 'present_format':
        return {'bytes': 0x70, 'tag': PAYLOAD_TAG_PRESENT}
    raise ValueError('unknown phase-2 branch')


def read(data, va, n):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va
               and va + n <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected one file-backed mapping')
    s = matches[0]
    o = s['offset'] + va - s['address']
    return o, bytes(data[o:o + n])


def relocations(data):
    sec = next((s for s in sections(data) if s['name'] == '.rela.dyn'), None)
    if sec is None:
        raise ValueError('missing.rela.dyn section')
    if sec['size'] % 24:
        raise ValueError('truncated.rela.dyn section')
    by_offset = {}
    for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
        by_offset.setdefault(a, []).append((i & 0xffffffff, i >> 32, v))
    return by_offset


def dynsym_name(data, index):
    ds = next((s for s in sections(data) if s['name'] == '.dynsym'), None)
    st = next((s for s in sections(data) if s['name'] == '.dynstr'), None)
    if ds is None:
        raise ValueError('missing.dynsym section')
    if st is None:
        raise ValueError('missing.dynstr section')
    name_off = struct.unpack_from('<I', data, ds['offset'] + 24 * index)[0]
    end = data.find(b'\0', st['offset'] + name_off)
    try:
        return data[st['offset'] + name_off:end].decode('ascii')
    except UnicodeDecodeError:
        raise ValueError('dynamic symbol name is not valid ASCII')


def slot_bindings(data):
    by_offset = relocations(data)
    out = {}
    for role, (slot, rtype, addend) in SLOT_BINDINGS.items():
        if by_offset.get(slot, []) != [(rtype, 0, addend)]:
            raise ValueError('slot binding changed')
        out[role] = {'slot': hex(slot), 'type': rtype,
                     'type_name': 'R_X86_64_RELATIVE',
                     'addend': hex(addend)}
    entries = by_offset.get(ISATTY_SLOT, [])
    if len(entries) != 1 or entries[0][0] != ISATTY_RELOCATION[0] \
            or entries[0][1] != ISATTY_RELOCATION[1] or entries[0][2] != 0:
        raise ValueError('isatty binding changed')
    if dynsym_name(data, ISATTY_RELOCATION[1]) != ISATTY_NAME:
        raise ValueError('isatty binding changed')
    out['isatty'] = {'slot': hex(ISATTY_SLOT), 'section': '.got',
                     'relocation_type': ISATTY_RELOCATION[0],
                     'relocation_type_name': 'R_X86_64_GLOB_DAT',
                     'symbol_index': ISATTY_RELOCATION[1],
                     'symbol': ISATTY_NAME}
    return out


def _pin(data, site, expected, label):
    raw = read(data, site, len(bytes.fromhex(expected)))[1]
    if raw.hex() != expected:
        raise ValueError(f'{label} changed')
    return hex(site)


def _pins(data, table):
    return {name: _pin(data, site, expected, f'{name} pin')
            for name, (site, expected) in table.items()}


def _rip_target(data, site, insn_len):
    raw = read(data, site, insn_len)[1]
    disp = struct.unpack_from('<i', raw, insn_len - 4)[0]
    return site + insn_len + disp


def branch_stream_identity(data):
    """Compare the two branch build segments byte for byte.

    Each segment pair has the same length; outside the listed
    displacement fields the bytes must be identical.  The
    segment-1 fields decode to the same two string addresses
    and the same collect target on both branches; the
    segment-2 fields decode to the same three format-string
    piece addresses on both branches (the two conditional-jump
    fields point into each branch's own out-of-line
    continuation region and are reported, not equated).
    """
    out = []
    for index, seg in enumerate(BUILD_SEGMENTS):
        a0, a1 = seg['a']
        b0, b1 = seg['b']
        raw_a = read(data, a0, a1 - a0)[1]
        raw_b = read(data, b0, b1 - b0)[1]
        if len(raw_a) != len(raw_b):
            raise ValueError('branch build segment length changed')
        masked = set()
        for lo, hi in seg['displacements']:
            masked.update(range(lo, hi))
        differing = [i for i in range(len(raw_a))
                     if raw_a[i] != raw_b[i]]
        if any(i not in masked for i in differing):
            raise ValueError('branch build streams differ outside '
                             'displacement fields')
        entry = {'segment': index + 1,
                 'a': (hex(a0), hex(a1)), 'b': (hex(b0), hex(b1)),
                 'bytes': len(raw_a),
                 'differing_bytes': len(differing),
                 'displacement_fields': [(hex(lo), hex(hi))
                                         for lo, hi in seg['displacements']]}
        if index == 0:
            entry['lea_targets_a'] = [hex(_rip_target(data, a0, 7)),
                                      hex(_rip_target(data, a0 + 26, 7))]
            entry['lea_targets_b'] = [hex(_rip_target(data, b0, 7)),
                                      hex(_rip_target(data, b0 + 26, 7))]
            entry['call_target_a'] = hex(_rip_target(data, a0 + 61, 5))
            entry['call_target_b'] = hex(_rip_target(data, b0 + 61, 5))
            if entry['lea_targets_a'] != [hex(FORMAT_STRING), hex(FORMAT_PIECE2)] \
                    or entry['lea_targets_b'] != entry['lea_targets_a'] \
                    or entry['call_target_a'] != hex(COLLECT) \
                    or entry['call_target_b'] != hex(COLLECT):
                raise ValueError('branch build displacement targets changed')
        else:
            loads_a = [_rip_target(data, a0 + off, 7)
                       for off in (0x11, 0x1c, 0x27)]
            loads_b = [_rip_target(data, b0 + off, 7)
                       for off in (0x11, 0x1c, 0x27)]
            if loads_a != loads_b or loads_a != [0x468aff, 0x468aef, FORMAT_STRING]:
                raise ValueError('branch string-copy targets changed')
            entry['string_load_targets'] = [hex(x) for x in loads_a]
            entry['jump_targets_a'] = [hex(_rip_target(data, a0 + 0x0b, 6)),
                                       hex(_rip_target(data, a0 + 0x7c, 6))]
            entry['jump_targets_b'] = [hex(_rip_target(data, b0 + 0x0b, 6)),
                                       hex(_rip_target(data, b0 + 0x7c, 6))]
        out.append(entry)
    return out


def direct_call_census(data):
    """One pass over .text: every E8 rel32 site for the traced
    targets, each attributed to its containing FDE."""
    sec = next((s for s in sections(data) if s['name'] == '.text'), None)
    if sec is None:
        raise ValueError('missing.text section')
    body = bytes(data[sec['offset']:sec['offset'] + sec['size']])
    base = sec['address']
    targets = {COLLECT: 'descriptor_stream_collect',
               BIND: 'descriptor_record_bind',
               0x156f680: 'descriptor_map_insert'}
    found = {role: [] for role in targets.values()}
    index = body.find(b'\xe8')
    while index != -1:
        if index + 5 <= len(body):
            rel = struct.unpack_from('<i', body, index + 1)[0]
            target = base + index + 5 + rel
            if target in targets:
                found[targets[target]].append(base + index)
        index = body.find(b'\xe8', index + 1)
    _, fs, _ = fde_extents(data)
    starts = sorted(f['start'] for f in fs)
    ends = {f['start']: f['end'] for f in fs}

    def containing(site):
        i = bisect.bisect_right(starts, site) - 1
        if i < 0 or site >= ends[starts[i]]:
            return None
        return starts[i]

    return {role: {'sites': [hex(s) for s in sites],
                   'containing_fdes': [hex(containing(s)) if containing(s) else None
                                       for s in sites]}
            for role, sites in found.items()}


def consumer_trace(data):
    pins = _pins(data, CONSUMER_PINS)
    identity = branch_stream_identity(data)
    fmt = read(data, FORMAT_STRING, len(FORMAT_STRING_BYTES))[1]
    if fmt != FORMAT_STRING_BYTES:
        raise ValueError('phase-2 format string changed')
    piece = read(data, OVERFLOW_PIECE, len(OVERFLOW_PIECE_BYTES))[1]
    if piece != OVERFLOW_PIECE_BYTES:
        raise ValueError('overflow format piece changed')
    return {
        'pins': pins,
        'sentinel_provenance': (
            'rbp holds the sentinel at the probe compare: the '
            'only write to rbp between the consumer entry and '
            '0x15a45e0 is the entry movabs at 0x15a3bd5 (pinned); '
            'every other rbp mention in that range is a read.'),
        'collect_argument': (
            'On every path into the phase-2 initialisation at '
            '0x15a44e0 the last write to r12 is a lea '
            'r12,[rsp+0x90] (last site pinned at 0x15a42be); the '
            'collect calls on both branches pass r12 as the '
            'output argument, so the collect result header lands '
            'in the scratch block at [rsp+0x90], whose three '
            'words the second record then copies.'),
        'descriptor_record': {
            'stack_base': 'rsp+0x20', 'consumed_bytes': '0x38',
            'written_fields': {hex(k): hex(v) for k, v
                               in descriptor_record_fields().items()},
            'unwritten_offset': '0x28',
            'format_string': {'va': hex(FORMAT_STRING),
                              'bytes': len(FORMAT_STRING_BYTES),
                              'text': FORMAT_STRING_BYTES.decode('ascii')},
            'second_piece': hex(FORMAT_PIECE2)},
        'branch_identity': identity,
        'divergence': {
            'first_differing_sites': ('0x15a46ad', '0x15a4904'),
            'sentinel_bind': {
                'second_record_header': (
                    'rewritten in place at [rsp+0xc0]: {boxed '
                    'record, 0x63ffbd0, word 0 at +0x10}'),
                'extra_callee': 'descriptor_record_bind via slot 0x64e1458',
                'entry_words_read': 'none beyond the capacity word',
                'payload': second_structure_payload('sentinel_bind')},
            'present_format': {
                'second_record_destination': (
                    'boxed pointer stored into the scratch block '
                    'at [rsp+0x90] with 0x63ffbd0 at +0x8 and '
                    'flag byte 1 at +0x10'),
                'extra_callees': [
                    'format_consumer via slot 0x64df6e8',
                    'descriptor_emit via slot 0x64e1460',
                    'descriptor_map_insert (direct call)'],
                'overflow_piece': {'va': hex(OVERFLOW_PIECE),
                                   'legible': '_overflow{}'},
                'entry_words_read': (
                    'the found entry pointer/length words at '
                    '+0x8/+0x10, copied to [rsp+0x338] as the '
                    'format argument'),
                'payload': second_structure_payload('present_format')},
        }}


def collect_trace(data):
    pins = _pins(data, COLLECT_PINS)
    return {
        'pins': pins,
        'model': collect_model(),
        'protocol': (
            'visit (slot 0x64eafb0) expands the seed into a '
            '0x58-byte state at [rsp+0x20]; a dword tag of 5 '
            'there ends the walk before any allocation.  next '
            '(slot 0x64eaf10) yields the first element record at '
            '[rsp+0x78]; a qword tag of 5 there also ends it.  '
            'Both terminal cases store the empty header '
            '{0, 8, 0} to the output and return it.  Otherwise '
            'the function allocates 0x160 bytes, stores the '
            'first element verbatim, initialises the header '
            '{capacity 4, buffer, count 1} on its stack, copies '
            'the input descriptor record\'s first 0x38 bytes '
            'into a stack cursor at [rsp+0xd0], and loops: '
            'visit expands the cursor into a state at '
            '[rsp+0x108] (dword tag 5 ends), next yields the '
            'next element at [rsp+0x20] (qword tag 5 ends), the '
            'element is appended verbatim at stride 0x58, '
            'growing through 0x474e640 when count == capacity.  '
            'The finished header {capacity, buffer, count} is '
            'stored to the first argument and returned in rax.  '
            'The input record is consumed as the cursor seed '
            'only: no field of it is copied into any element '
            'or into the output header.'),
        'cfg_edges': sorted((hex(s), hex(t)) for s, t in COLLECT_CFG),
    }


def bind_trace(data):
    pins = _pins(data, BIND_PINS)
    state = struct.unpack('<Q', read(data, BIND_STATE_WORD, 8)[1])[0]
    config_byte = read(data, BIND_CONFIG_BYTE, 1)[1][0]
    table_dword = struct.unpack('<I', read(data, BIND_TABLE_DWORD, 4)[1])[0]
    if (state, config_byte, table_dword) != (0, 3, 3):
        raise ValueError('bind global initial state changed')
    return {
        'pins': pins,
        'globals_file_initial': {'state_word': state,
                                 'config_byte': config_byte,
                                 'table_dword': table_dword},
        'transformation': (
            'The function overwrites its first argument (the '
            'descriptor record) in place and returns it: word '
            '+0x00 and word +0x08 are configuration outputs '
            '(each 0 or 1 on the traced arms), word +0x10 is '
            'the slot-object address 0x6500060 when the second '
            'record\'s +0x10 byte is 1 and the global-table '
            'address 0x64fe408 otherwise, word +0x18 is the '
            'second record\'s word +0x00 (or, when that is 0, a '
            'fresh 0x30-byte heap copy of the default record '
            'produced through slot 0x64e12f8), word +0x20 is '
            'the second record\'s word +0x08 (or the static '
            '0x6495038 on the default arm), and byte +0x28 is '
            'the configuration flag -- on the default arm the '
            'second record\'s +0x11 byte XOR 1.  The second '
            'record itself is only read (words +0x00/+0x08 and '
            'bytes +0x10/+0x11); it is neither stored into the '
            'output beyond those words nor freed.  The '
            'configuration lookup consults the once-initialised '
            'state at 0x64fdbe0 (initialiser 0x4752c90), the '
            'config byte at 0x64fdbe8, the table at 0x64fe408 '
            'with its dword at 0x64fe440 (initialiser '
            '0x5c6c15a), and isatty(1)/isatty(2) through '
            'GLOB_DAT slot 0x64eaf90 on the arms where the '
            'consulted byte is 0.'),
        'consumer_call': {
            'path': bind_path(0),
            'output_under_file_initial_state':
                {k: (hex(v) if isinstance(v, int) else v)
                 for k, v in bind_consumer_call_output(0).items()
                 if k != 'word_0x18'},
            'note': ('word +0x18 is the boxed second record '
                     'pointer supplied by the consumer; the '
                     'remaining fields are the pinned model '
                     'output for that call.'),
        },
        'cfg_edges': sorted((hex(s), hex(t)) for s, t in BIND_CFG),
    }


def analyze(data):
    bindings = slot_bindings(data)
    trace = {'consumer': consumer_trace(data),
             'collect': collect_trace(data),
             'bind': bind_trace(data),
             'direct_calls': direct_call_census(data)}
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}

    def frame_records(a, b, sha, role):
        if (a, b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset, raw = read(data, a, b - a)
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError(f'{role} body changed')
        records = {}
        for kind in ['fde', 'cie']:
            va = fdes[(a, b)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(data, va, n)[1].hex()}
        return {'role': role, 'start': hex(a), 'end': hex(b),
                'file_offset': hex(offset), 'bytes': b - a,
                'sha256': sha, 'frames': records}

    owners = [frame_records(a, b, sha, role)
              for role, (a, b, sha) in OWNERS.items()]
    boundaries = [frame_records(a, b, sha, role)
                  for role, (a, b, sha) in BOUNDARIES.items()]
    census = trace['direct_calls']
    if census['descriptor_stream_collect']['sites'] != \
            ['0x15a4626', '0x15a487d', '0x473a03b']:
        raise ValueError('collect call-site census changed')
    if census['descriptor_record_bind']['sites'] != []:
        raise ValueError('bind must be reached only through its slot')
    if census['descriptor_map_insert']['sites'] != ['0x15a4ab4']:
        raise ValueError('descriptor map insert census changed')
    return {'target_sha256': SHA, 'owners': owners,
            'phase2': trace,
            'slot_bindings': bindings,
            'boundaries': boundaries,
            'phase2_verdict':
                'The phase-2 probe\'s two branches emit the '
                'same descriptor record into the same collect '
                'call: the record builds and the string boxing '
                'are byte-identical outside displacement fields '
                'decoding to the same targets, and the collect '
                'function turns the record into a vector of '
                'streamed 0x58-byte element records whose header '
                'lands at [rsp+0x90] on both branches.  The '
                'sentinel (capacity == 0x8000000000000000) branch '
                'then binds the descriptor in place through '
                '0x47473c0 (slot 0x64e1458) and stores a '
                '0x30-byte copy under tag 0x63ffbf8; the '
                'non-sentinel branch formats the found entry\'s '
                'stored text through the format consumer with '
                'the \'_overflow{}\' piece, emits through '
                '0x473c130 (slot 0x64e1460), inserts the '
                'descriptor through 0x156f680, and stores a '
                '0x70-byte snapshot under tag 0x63ffc70.  The '
                'branch therefore changes the destination and '
                'the downstream emissions, not the descriptor '
                'record or the collect result.',
            'phase2_limits':
                'Static trace only.  The functions behind slots '
                '0x64eafb0 (stream visit, 5,696 bytes) and '
                '0x64eaf10 (stream next, 3,781 bytes) are '
                'hash-pinned boundaries: how they expand the '
                'cursor, whether the visit function mutates the '
                'cursor in place between loop iterations, and '
                'which element records a given descriptor '
                'produces are NOT traced.  The bind function\'s '
                'configuration outputs are modelled under the '
                'file-initial global values (state 0, config '
                'byte 3, table dword 3), under which neither '
                'isatty arm is reached for the consumer\'s call; '
                'runtime mutation of those globals by other '
                'callers, and the exact outputs on the isatty '
                'arms, are NOT traced.  The descriptor-emit '
                'function behind slot 0x64e1460 (1,295 bytes), '
                'the map insert 0x156f680 (4,969 bytes), the '
                'second-tree insert 0x1497040 (3,092 bytes), the '
                'grow helper, the two collect cleanup helpers, '
                'the two bind initialisers, and the '
                'default-record producer are hash-pinned '
                'boundaries; the producer is itself the third '
                'direct caller of the collect function '
                '(0x473a03b), which is recorded as census, not '
                'traced.  The format consumer is the RE-015 '
                'owner traced by #2408 and is a boundary here.  '
                'What the second structure\'s readers do with '
                'the two payload kinds (tag 0x63ffbf8 versus tag '
                '0x63ffc70), and who consumes the vector the '
                'collect call leaves at [rsp+0x90] after phase '
                '2, are the next questions.  No captured code '
                'executed, no runtime value beyond the pinned '
                'file-initial globals, or reconstruction gate is '
                'claimed.'}


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)], text=True)


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('expected pinned node115')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    lines = []
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node115.elf'
        snapshot.write_bytes(data)
        native = subprocess.check_output(['readelf', '-wf', str(snapshot)],
                                         text=True)
        for role, (a, b, _) in list(OWNERS.items()) + list(BOUNDARIES.items()):
            rows = [l for l in native.splitlines()
                    if f'pc={a:016x}..{b:016x}' in l]
            if len(rows) != 1:
                raise ValueError('native FDE disagreement')
            lines.extend(rows)
        # Every pinned consumer site must be a native
        # instruction start in the full owner body.
        asm = _objdump(snapshot, CONSUMER, CONSUMER_END)
        ins = decode_export(asm, CONSUMER, CONSUMER_END,
                            read(data, CONSUMER, CONSUMER_END - CONSUMER)[1])
        sites = {site for site, _ in CONSUMER_PINS.values()}
        if not sites <= set(ins):
            raise ValueError('consumer evidence site not native instruction start')
        for name, wa, wb in WINDOWS:
            wasm = _objdump(snapshot, wa, wb)
            decode_export(wasm, wa, wb, read(data, wa, wb - wa)[1])
            (output / f'{name}_window_{wa:x}_{wb:x}_objdump.txt').write_bytes(
                wasm.replace(str(snapshot), '<authenticated-node115>').encode('utf-8'))
        # Full exports for the two smaller owners, with every
        # pinned site validated as an instruction start.
        pin_tables = {'descriptor_stream_collect': COLLECT_PINS,
                      'descriptor_record_bind': BIND_PINS}
        for name, a, b in FULL_EXPORTS:
            easm = _objdump(snapshot, a, b)
            eins = decode_export(easm, a, b, read(data, a, b - a)[1])
            esites = {site for site, _ in pin_tables[name].values()}
            if not esites <= set(eins):
                raise ValueError(f'{name} evidence site not native instruction start')
            (output / f'{name}_objdump.txt').write_bytes(
                easm.replace(str(snapshot), '<authenticated-node115>').encode('utf-8'))
        # The third collect call site, inside the
        # default-record producer boundary, must be a native
        # instruction start in its FDE.
        pa, pb, _ = BOUNDARIES['bind_default_producer']
        pasm = _objdump(snapshot, pa, pb)
        pins = decode_export(pasm, pa, pb, read(data, pa, pb - pa)[1])
        if 0x473a03b not in pins:
            raise ValueError('producer collect call site not native instruction start')
    (output / 'frames.txt').write_bytes(('\n'.join(lines) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes(
        (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--output', type=Path,
                   default=ROOT / 'work/phase2-descriptor115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
