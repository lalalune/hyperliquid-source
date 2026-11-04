#!/usr/bin/env python3
"""Static trace of the two node-115 shared book insert routines.

Both 1,067-byte FDE bodies (0x58df360 and 0x58df790) are called only by
the RE-006 ring-append twins, in their registration and append arms.
Each routine first folds the order qword at +0xe0 into the accumulator
behind its fifth argument, builds a 77-byte-written event record from
the order fields into the collection behind its fourth argument,
rewrites the order's first four qwords, and inserts the order into the
0x110-byte-entry slab behind its first argument.  This packet pins the
return contract: the routine returns the slab head field [rdi+0x20] as
it stood before the insertion -- the index of the slot that receives
the order copy -- with an append case (head == length), a vacant-slot
reuse case (head < length), and a non-returning vacant-entry panic
otherwise.  The two stack arguments select link writes and the order
rewrite only; they never change the returned index.  This tool
authenticates the whole capture, pins those facts in bytes, and
regenerates the packet.
"""

import hashlib
import json
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
PACKET = ROOT / 'research/work-items/RE-006-node115-shared-insert-return'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

OWNERS = {
    'shared_a': {
        'range': (0x58DF360, 0x58DF78B),
        'sha256': '9885b0a31f873965b33690748e029b2539e0398c6e9d48f1eca3a5dc61f96e29',
        'frame_bytes': 0x408,
        'event_element_bytes': 0x2B8,
        'event_grow_slot': 0x64E5A28,
        'event_grow_target': 0x59630A0,
        'slab_grow_slot': 0x64E5A30,
        'slab_grow_target': 0x43BBD40,
        'unwind_destructor': 0x5947550,
    },
    'shared_b': {
        'range': (0x58DF790, 0x58DFBBB),
        'sha256': '1c933868b0d8b192a97c7454766e2b0b3dfd17879d851ed5a0d58ab9c6a2d077',
        'frame_bytes': 0x418,
        'event_element_bytes': 0x2C8,
        'event_grow_slot': 0x64E4F88,
        'event_grow_target': 0x5962310,
        'slab_grow_slot': 0x64E5A38,
        'slab_grow_target': 0x43BBD40,
        'unwind_destructor': 0x5948DB0,
    },
}
CALLERS = {
    'twin_a': {
        'range': (0x5911890, 0x5911B27),
        'sha256': '08e8b4239e731ee50d74c945e5fe6ae3f8e18d12a5ee8c6ab8725363260558b6',
        'owner': 'shared_a',
        'sites': {'registration_arm': 0x59119D1, 'append_arm': 0x5911A3F},
    },
    'twin_b': {
        'range': (0x5911B30, 0x5911DC7),
        'sha256': 'cecc9282e700d4433aa077e63b65b50eaa287b16d6de32964b7bbb743f5b3223',
        'owner': 'shared_b',
        'sites': {'registration_arm': 0x5911C71, 'append_arm': 0x5911CDF},
    },
}
COPY_SLOT = 0x64DF508
ASSERT_SLOT = 0x64DF830
ASSERT_TARGET = 0x1680C10
PANIC_SLOT = 0x64DF6B8
PANIC_TARGET = 0x1680E80
PANIC_WORD_SLOT = 0x64DF6C8
PANIC_WORD_TARGET = 0x1689420
OVERFLOW_SLOT = 0x64E4EA8
OVERFLOW_TARGET = 0x4524E40
PAD_SLOT = 0x64DF4C0
PAD_TARGET = 0x1680CAB
ORDER_DROP_GLUE = 0x5957F70
UNWIND_RESUME = 0x63F0A50
VACANT_MESSAGE_VA = 0x4339B2
# The panic block's lea target holds a length byte 0x16 followed by the
# 22-byte message text.
VACANT_MESSAGE = b'\x16expected vacant entry '
VACANT_MESSAGE_TEXT = 'expected vacant entry '
OVERFLOW_LOCATION_VA = 0x64B64B0
OVERFLOW_LOCATION = {'file': 'l1/src/qtys/mod.rs', 'line': 831, 'column': 1}
OVERFLOW2_LOCATION_VA = 0x64A34D8
VACANT_LOCATION_VA = 0x64B6630
VACANT_LOCATION = {'file': 'l1/src/slab/slab.rs', 'line': 78, 'column': 21}
ASSERT_LOCATION_1_VA = 0x64B64C8
ASSERT_LOCATION_1 = {'file': 'l1/src/book/book_orders.rs', 'line': 81,
                     'column': 40}
ASSERT_LOCATION_2_VA = 0x64B64E0
ASSERT_LOCATION_2 = {'file': 'l1/src/book/book_orders.rs', 'line': 89,
                     'column': 40}

# Exact instruction bytes at these owner-relative offsets in both
# routine bodies (205 of the 236 instructions are byte-identical).
EXACT_SITES = (
    (0x0, '55'),
    (0x1, '4157'),
    (0x3, '4156'),
    (0x5, '4155'),
    (0x7, '4154'),
    (0x9, '53'),
    (0x11, '4c89cb'),
    (0x14, '4d89c4'),
    (0x17, '4989cd'),
    (0x1a, '4889542430'),
    (0x1f, '4989f7'),
    (0x22, '4989fe'),
    (0x25, '488b8ee0000000'),
    (0x2c, '498b28'),
    (0x2f, '488d4620'),
    (0x33, '4889442418'),
    (0x38, '4889e8'),
    (0x3b, '48890c24'),
    (0x3f, '4801c8'),
    (0x42, '726f'),
    (0x4c, '49890424'),
    (0x50, '4883f901'),
    (0x54, '0f858d000000'),
    (0x62, '4d3b4610'),
    (0x66, '488b3c24'),
    (0x6a, '731a'),
    (0x6c, '498b4608'),
    (0x70, '4969c810010000'),
    (0x77, '488b3408'),
    (0x7b, '4889742408'),
    (0x80, '4883fe02'),
    (0x84, '7512'),
    (0x86, '488b4310'),
    (0x8a, '4889442408'),
    (0x8f, '488d4318'),
    (0x93, '4531c0'),
    (0x96, 'eb63'),
    (0x98, '4c89442420'),
    (0x9d, '4801c8'),
    (0xa0, '488b88f0000000'),
    (0xa7, '4883c008'),
    (0xab, '41b801000000'),
    (0xb1, 'eb48'),
    (0xba, '31ff'),
    (0xc2, '48032c24'),
    (0xc6, '48c7c0ffffffff'),
    (0xcd, '480f43c5'),
    (0xd9, '49890424'),
    (0xdd, '4883f901'),
    (0xe1, '0f8473ffffff'),
    (0xe7, '488b4310'),
    (0xeb, '4889442408'),
    (0xf0, '488d4318'),
    (0xf4, '4531c0'),
    (0xf7, '488b3c24'),
    (0xfb, '488b00'),
    (0xfe, '4889442410'),
    (0x103, '418b8708010000'),
    (0x10a, '89842488000000'),
    (0x111, '410f1087f8000000'),
    (0x119, '0f11442478'),
    (0x11e, '498b87f0000000'),
    (0x125, '410fb697d2000000'),
    (0x12d, '498bb7b0000000'),
    (0x134, '4c89442428'),
    (0x139, '4c89442448'),
    (0x13e, '48894c2450'),
    (0x143, '48897c2458'),
    (0x148, '4889742460'),
    (0x14d, '488b4c2430'),
    (0x152, '48894c2468'),
    (0x157, '4889442470'),
    (0x15c, '8894248c000000'),
    (0x163, '48c744244002000000'),
    (0x16c, '498b6d10'),
    (0x170, '493b6d00'),
    (0x174, '7509'),
    (0x176, '4c89ef'),
    (0x186, '49037d08'),
    (0x18a, '488d742440'),
    (0x19b, '41ffd4'),
    (0x19e, '48ffc5'),
    (0x1a1, '49896d10'),
    (0x1a5, '488b442408'),
    (0x1aa, '498907'),
    (0x1ad, '488b442410'),
    (0x1b2, '49894708'),
    (0x1b6, '488b442428'),
    (0x1bb, '49894710'),
    (0x1bf, '488b442420'),
    (0x1c4, '49894718'),
    (0x1d0, 'ba10010000'),
    (0x1d5, '4c89fe'),
    (0x1d8, '41ffd4'),
    (0x1db, '4d8b6e20'),
    (0x1df, '4c896c2438'),
    (0x1e4, '498b6e10'),
    (0x1e8, '498b4618'),
    (0x1ec, '48ffc0'),
    (0x1ef, '48c7c1ffffffff'),
    (0x1f6, '480f45c8'),
    (0x1fa, '49894e18'),
    (0x1fe, '4939ed'),
    (0x201, '0f85a8000000'),
    (0x207, '488d7c2440'),
    (0x20c, 'ba10010000'),
    (0x211, '4c89fe'),
    (0x21a, '4d3b2e'),
    (0x21d, '750e'),
    (0x21f, '4c8d642460'),
    (0x224, '4c89f7'),
    (0x22d, '4969fd10010000'),
    (0x234, '49037e08'),
    (0x238, 'ba10010000'),
    (0x23d, '4c89fe'),
    (0x246, '498d6d01'),
    (0x24a, '49896e10'),
    (0x24e, '49896e20'),
    (0x252, '48837c242800'),
    (0x258, '0f8491000000'),
    (0x25e, '488b4c2420'),
    (0x263, '4839e9'),
    (0x266, '0f8345010000'),
    (0x26c, '498b4608'),
    (0x270, '4869c910010000'),
    (0x277, '833c0802'),
    (0x27b, '0f8430010000'),
    (0x281, '4801c8'),
    (0x284, '48c70001000000'),
    (0x28b, '4c896808'),
    (0x28f, '488b4c2410'),
    (0x294, '837c240801'),
    (0x299, '4c8b3c24'),
    (0x29d, '746c'),
    (0x29f, '48c70301000000'),
    (0x2a6, '4c896b08'),
    (0x2aa, 'e98a000000'),
    (0x2af, '0f83c3000000'),
    (0x2b5, '498b7e08'),
    (0x2b9, '4969c510010000'),
    (0x2c0, '833c0702'),
    (0x2c4, '0f85ae000000'),
    (0x2ca, '4801c7'),
    (0x2cd, '488b4708'),
    (0x2d1, '49894620'),
    (0x2d5, 'ba10010000'),
    (0x2da, '4c89fe'),
    (0x2e3, '48837c242800'),
    (0x2e9, '0f856fffffff'),
    (0x2ef, '48c7431001000000'),
    (0x2f7, '4c896b18'),
    (0x2fb, '488b4c2410'),
    (0x300, '837c240801'),
    (0x305, '4c8b3c24'),
    (0x309, '7594'),
    (0x30b, '493b4e10'),
    (0x30f, '0f83a9000000'),
    (0x315, '498b4608'),
    (0x319, '4869c910010000'),
    (0x320, '833c0802'),
    (0x324, '0f8494000000'),
    (0x32a, '4801c8'),
    (0x32d, '48c7401001000000'),
    (0x335, '4c896818'),
    (0x339, '4c8b7370'),
    (0x33d, '4c89f0'),
    (0x340, '4c01f8'),
    (0x343, '0f8282000000'),
    (0x349, '48894370'),
    (0x34d, '488b4378'),
    (0x351, '48ffc0'),
    (0x354, '48c7c1ffffffff'),
    (0x35b, '480f45c8'),
    (0x35f, '48894b78'),
    (0x363, '4c89e8'),
    (0x36d, '5b'),
    (0x36e, '415c'),
    (0x370, '415d'),
    (0x372, '415e'),
    (0x374, '415f'),
    (0x376, '5d'),
    (0x377, 'c3'),
    (0x380, '488d442438'),
    (0x385, '4889442440'),
    (0x391, '4889442448'),
    (0x3a4, '488d742440'),
    (0x3af, '0f0b'),
    (0x3d2, '31ff'),
    (0x3da, '4d01fe'),
    (0x3dd, '48c7c0ffffffff'),
    (0x3e4, '490f43c6'),
    (0x3e8, 'e95cffffff'),
    (0x3ed, '4889c3'),
    (0x3f0, 'eb19'),
    (0x3f2, '4889c3'),
    (0x3f5, '837c244002'),
    (0x3fa, '751f'),
    (0x3fc, 'eb25'),
    (0x3fe, '4889c3'),
    (0x401, '488d7c2440'),
    (0x40b, '4c8b642418'),
    (0x410, 'eb09'),
    (0x418, '4889c3'),
    (0x41b, '4c89e7'),
    (0x423, '4889df'),
)

# The remaining 31 instructions differ between the twins.  Entry forms:
# (offset, kind, instruction length, payload) with kind-specific payload:
# exact_owner -> {owner: hex bytes}; rip/e8 -> resolved target;
# slot -> (slot, relative-relocation target or None);
# slot_owner -> {owner: (slot, bound target)}; e8_owner -> {owner: target}.
DIFF_SITES = (
    (0xa, 'exact_owner', 7, {'shared_a': '4881ec08040000', 'shared_b': '4881ec18040000'}),
    (0x44, 'exact_owner', 8, {'shared_a': '488b8c2440040000', 'shared_b': '488b8c2450040000'}),
    (0x5a, 'exact_owner', 8, {'shared_a': '4c8b842448040000', 'shared_b': '4c8b842458040000'}),
    (0xb3, 'rip', 7, 0x64b64b0),
    (0xbc, 'slot', 6, (0x64e4ea8, 0x4524e40)),
    (0xd1, 'exact_owner', 8, {'shared_a': '488b8c2440040000', 'shared_b': '488b8c2450040000'}),
    (0x179, 'slot_owner', 6, {'shared_a': (0x64e5a28, 0x59630a0), 'shared_b': (0x64e4f88, 0x5962310)}),
    (0x17f, 'exact_owner', 7, {'shared_a': '4869fdb8020000', 'shared_b': '4869fdc8020000'}),
    (0x18f, 'slot', 7, (0x64df508, None)),
    (0x196, 'exact_owner', 5, {'shared_a': 'bab8020000', 'shared_b': 'bac8020000'}),
    (0x1c8, 'exact_owner', 8, {'shared_a': '488dbc24f8020000', 'shared_b': '488dbc2408030000'}),
    (0x214, 'slot', 6, (0x64df508, None)),
    (0x227, 'slot_owner', 6, {'shared_a': (0x64e5a30, 0x43bbd40), 'shared_b': (0x64e5a38, 0x43bbd40)}),
    (0x240, 'slot', 6, (0x64df508, None)),
    (0x2dd, 'slot', 6, (0x64df508, None)),
    (0x366, 'exact_owner', 7, {'shared_a': '4881c408040000', 'shared_b': '4881c418040000'}),
    (0x378, 'exact_owner', 8, {'shared_a': '4c8da42418030000', 'shared_b': '4c8da42428030000'}),
    (0x38a, 'slot', 7, (0x64df6c8, 0x1689420)),
    (0x396, 'rip', 7, 0x4339b2),
    (0x39d, 'rip', 7, 0x64b6630),
    (0x3a9, 'slot', 6, (0x64df6b8, 0x1680e80)),
    (0x3b1, 'rip', 7, 0x64b64c8),
    (0x3b8, 'slot', 6, (0x64df830, 0x1680c10)),
    (0x3be, 'rip', 7, 0x64b64e0),
    (0x3c5, 'slot', 6, (0x64df830, 0x1680c10)),
    (0x3cb, 'rip', 7, 0x64a34d8),
    (0x3d4, 'slot', 6, (0x64e4ea8, 0x4524e40)),
    (0x406, 'e8_owner', 5, {'shared_a': 0x5947550, 'shared_b': 0x5948db0}),
    (0x412, 'slot', 6, (0x64df4c0, 0x1680cab)),
    (0x41e, 'e8', 5, 0x5957f70),
    (0x426, 'e8', 5, 0x63f0a50),
)

# Intra-body branches: (offset, displacement offset within the
# instruction, displacement size, target owner-relative offset).
# The instruction length is disp_at + size in every entry.
BRANCH_SITES = (
    (0x42, 1, 1, 0xb3),
    (0x54, 2, 4, 0xe7),
    (0x6a, 1, 1, 0x86),
    (0x84, 1, 1, 0x98),
    (0x96, 1, 1, 0xfb),
    (0xb1, 1, 1, 0xfb),
    (0xe1, 2, 4, 0x5a),
    (0x174, 1, 1, 0x17f),
    (0x201, 2, 4, 0x2af),
    (0x21d, 1, 1, 0x22d),
    (0x258, 2, 4, 0x2ef),
    (0x266, 2, 4, 0x3b1),
    (0x27b, 2, 4, 0x3b1),
    (0x29d, 1, 1, 0x30b),
    (0x2aa, 1, 4, 0x339),
    (0x2af, 2, 4, 0x378),
    (0x2c4, 2, 4, 0x378),
    (0x2e9, 2, 4, 0x25e),
    (0x309, 1, 1, 0x29f),
    (0x30f, 2, 4, 0x3be),
    (0x324, 2, 4, 0x3be),
    (0x343, 2, 4, 0x3cb),
    (0x3e8, 1, 4, 0x349),
    (0x3f0, 1, 1, 0x40b),
    (0x3fa, 1, 1, 0x41b),
    (0x3fc, 1, 1, 0x423),
    (0x410, 1, 1, 0x41b),
)


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


def location(data, section_list, relas, record_va):
    _, raw = read(data, section_list, record_va, 24)
    _, length, packed = struct.unpack('<QQQ', raw)
    file_va = relas.get(record_va)
    require(file_va is not None, f'Location has no file relocation: {hx(record_va)}')
    _, raw_path = read(data, section_list, file_va, length)
    return {
        'record': hx(record_va),
        'file': raw_path.decode(),
        'line': packed & 0xFFFFFFFF,
        'column': packed >> 32,
    }


def saturating_add(a, b):
    """The pinned fall-through of both checked-add arms: the plain sum
    when it does not carry, else u64::MAX."""
    total = a + b
    return total if total < 1 << 64 else (1 << 64) - 1


def effective_mode(stack_arg_1, stack_arg_2, slab_length, linked_first_qword):
    """The pinned mode rule: link mode (1) iff the first stack argument
    equals 1, the second is an in-range slab index, and the qword at
    that slab slot does not equal 2; every other combination falls back
    to fresh mode (0)."""
    if stack_arg_1 != 1:
        return 0
    if stack_arg_2 >= slab_length:
        return 0
    if linked_first_qword == 2:
        return 0
    return 1


def slot_decision(head, length, vacant_first_dword):
    """The pinned return-path split on the slab head field [rdi+0x20]
    against the length field [rdi+0x10].  Returns (case, index): the
    append and reuse cases return the pre-insert head; the panic case
    never returns."""
    if head == length:
        return ('append', head)
    if head > length:
        return ('panic', None)
    if vacant_first_dword != 2:
        return ('panic', None)
    return ('reuse', head)


def resolve(body, base, offset, length):
    """Resolve a rip-relative or E8 target; every pinned site of those
    kinds carries its disp32 in the last four instruction bytes."""
    ins = body[offset:offset + length]
    disp = struct.unpack_from('<i', ins, length - 4)[0]
    return base + offset + length + disp


def owner_trace(body, base, name, spec, relas):
    for offset, expected in EXACT_SITES:
        want = bytes.fromhex(expected)
        require(body[offset:offset + len(want)] == want,
                f'Pinned instruction changed at {hx(base + offset)}')
    resolved = {}
    for offset, kind, length, payload in DIFF_SITES:
        va = base + offset
        if kind == 'exact_owner':
            want = bytes.fromhex(payload[name])
            require(body[offset:offset + len(want)] == want,
                    f'Pinned instruction changed at {hx(va)}')
        elif kind == 'rip':
            require(resolve(body, base, offset, length) == payload,
                    f'Resolved target changed at {hx(va)}')
            resolved[hx(offset)] = hx(payload)
        elif kind == 'slot':
            slot, bound = payload
            require(resolve(body, base, offset, length) == slot,
                    f'Resolved target changed at {hx(va)}')
            require(relas.get(slot) == bound,
                    f'Slot binding changed at {hx(va)}')
            resolved[hx(offset)] = hx(slot)
        elif kind == 'slot_owner':
            slot, target = payload[name]
            require(resolve(body, base, offset, length) == slot,
                    f'Resolved target changed at {hx(va)}')
            require(relas.get(slot) == target,
                    f'Slot binding changed at {hx(va)}')
            resolved[hx(offset)] = hx(slot)
        elif kind == 'e8':
            require(resolve(body, base, offset, length) == payload,
                    f'Resolved target changed at {hx(va)}')
            resolved[hx(offset)] = hx(payload)
        elif kind == 'e8_owner':
            require(resolve(body, base, offset, length) == payload[name],
                    f'Resolved target changed at {hx(va)}')
            resolved[hx(offset)] = hx(payload[name])
        else:
            raise AssertionError(f'unknown diff kind {kind}')
    for offset, disp_at, size, target_offset in BRANCH_SITES:
        length = disp_at + size
        ins = body[offset:offset + length]
        if size == 1:
            disp = struct.unpack_from('<b', ins, disp_at)[0]
        else:
            disp = struct.unpack_from('<i', ins, disp_at)[0]
        require(base + offset + length + disp == base + target_offset,
                f'Branch target changed at {hx(base + offset)}')
    return {
        'frame_bytes': spec['frame_bytes'],
        'event_element_bytes': spec['event_element_bytes'],
        'event_grow_slot': hx(spec['event_grow_slot']),
        'event_grow_target': hx(spec['event_grow_target']),
        'slab_grow_slot': hx(spec['slab_grow_slot']),
        'slab_grow_target': hx(spec['slab_grow_target']),
        'unwind_destructor': hx(spec['unwind_destructor']),
        'exact_sites_checked': len(EXACT_SITES),
        'diff_sites_checked': len(DIFF_SITES),
        'branch_sites_checked': len(BRANCH_SITES),
    }


def authenticate(data):
    require(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
            'Node 115 artifact authentication failed')


def analyze(data):
    section_list = sections(data)
    frames, fdes, extents = fde_extents(data)
    by_range = {(item['start'], item['end']): item for item in fdes}
    relas = relative_relocations(data)
    names = list(OWNERS) + list(CALLERS)
    specs = dict(OWNERS)
    specs.update(CALLERS)
    for name in names:
        start, end = specs[name]['range']
        require((start, end) in by_range, f'{name} is not an exact FDE body')
    body_refs = [
        hx(offset) for offset in sorted(relas)
        if any(spec['range'][0] <= offset < spec['range'][1]
               for spec in specs.values())
    ]
    addend_refs = [
        hx(value) for value in sorted(set(relas.values()))
        if any(value == spec['range'][0] for spec in specs.values())
    ]
    require(not body_refs,
            'A routine or caller body holds a relocation slot')
    require(not addend_refs,
            'A routine or caller body is reached through a relocation')
    text = next(section for section in section_list if section['name'] == '.text')
    text_body = data[text['offset']:text['offset'] + text['size']]
    census = {spec['range'][0]: [] for spec in OWNERS.values()}
    cursor = text_body.find(b'\xe8')
    while cursor != -1:
        site = text['address'] + cursor
        target = site + 5 + struct.unpack_from('<i', text_body, cursor + 1)[0]
        if target in census:
            census[target].append(site)
        cursor = text_body.find(b'\xe8', cursor + 1)
    for name, spec in OWNERS.items():
        want = sorted(
            site for caller in CALLERS.values() if caller['owner'] == name
            for site in caller['sites'].values()
        )
        require(sorted(census[spec['range'][0]]) == want,
                f'{name} direct caller census changed')
    message_offset, message = read(data, section_list, VACANT_MESSAGE_VA,
                                   len(VACANT_MESSAGE))
    require(message == VACANT_MESSAGE, 'Vacant-entry panic message changed')
    overflow_location = location(data, section_list, relas,
                                 OVERFLOW_LOCATION_VA)
    require({key: overflow_location[key] for key in ('file', 'line', 'column')}
            == OVERFLOW_LOCATION, 'Overflow panic location changed')
    overflow2_location = location(data, section_list, relas,
                                  OVERFLOW2_LOCATION_VA)
    require({key: overflow2_location[key] for key in ('file', 'line', 'column')}
            == OVERFLOW_LOCATION, 'Overflow panic location changed')
    vacant_location = location(data, section_list, relas, VACANT_LOCATION_VA)
    require({key: vacant_location[key] for key in ('file', 'line', 'column')}
            == VACANT_LOCATION, 'Vacant-entry panic location changed')
    assert_location_1 = location(data, section_list, relas,
                                 ASSERT_LOCATION_1_VA)
    require({key: assert_location_1[key] for key in ('file', 'line', 'column')}
            == ASSERT_LOCATION_1, 'Link assertion location changed')
    assert_location_2 = location(data, section_list, relas,
                                 ASSERT_LOCATION_2_VA)
    require({key: assert_location_2[key] for key in ('file', 'line', 'column')}
            == ASSERT_LOCATION_2, 'Link assertion location changed')
    bindings = {
        hx(slot): (hx(relas[slot]) if slot in relas else None)
        for slot in (COPY_SLOT, ASSERT_SLOT, PANIC_SLOT, PANIC_WORD_SLOT,
                     OVERFLOW_SLOT, PAD_SLOT)
    }
    require(bindings[hx(ASSERT_SLOT)] == hx(ASSERT_TARGET),
            'Assertion helper slot binding changed')
    require(bindings[hx(PANIC_SLOT)] == hx(PANIC_TARGET),
            'Panic helper slot binding changed')
    require(bindings[hx(PANIC_WORD_SLOT)] == hx(PANIC_WORD_TARGET),
            'Panic record slot binding changed')
    require(bindings[hx(OVERFLOW_SLOT)] == hx(OVERFLOW_TARGET),
            'Overflow helper slot binding changed')
    require(bindings[hx(PAD_SLOT)] == hx(PAD_TARGET),
            'Unwind pad slot binding changed')
    require(bindings[hx(COPY_SLOT)] is None,
            'Copy slot unexpectedly bound by a relative relocation')
    traces = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        _, body = read(data, section_list, start, end - start)
        traces[name] = owner_trace(body, start, name, spec, relas)
    for name in names:
        start, end = specs[name]['range']
        _, body = read(data, section_list, start, end - start)
        require(sha(body) == specs[name]['sha256'], f'{name} body changed')
    frame_records = {}
    for name in names:
        start, end = specs[name]['range']
        offset, body = read(data, section_list, start, end - start)
        record = by_range[(start, end)]
        frame_records[name] = {
            'fde': hx(record['fde']),
            'cie': hx(record['cie']),
            'lsda': hx(record['lsda']),
            'range': [hx(record['start']), hx(record['end'])],
            'bytes': end - start,
            'file_offset': hx(offset),
            'sha256': specs[name]['sha256'],
        }
    owners = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        offset, _ = read(data, section_list, start, end - start)
        owners[name] = {
            'range': [hx(start), hx(end)],
            'file_offset': hx(offset),
            'bytes': end - start,
            'sha256': spec['sha256'],
            'direct_callers': [
                caller_name for caller_name, caller in CALLERS.items()
                if caller['owner'] == name
            ],
            'direct_e8_call_sites': [
                hx(site) for caller in CALLERS.values()
                if caller['owner'] == name
                for site in caller['sites'].values()
            ],
        }
    callers = {
        name: {
            'range': [hx(spec['range'][0]), hx(spec['range'][1])],
            'bytes': spec['range'][1] - spec['range'][0],
            'sha256': spec['sha256'],
            'calls': spec['owner'],
            'call_sites': {key: hx(value)
                           for key, value in spec['sites'].items()},
        }
        for name, spec in CALLERS.items()
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
                'Trace the return contract of the two shared book insert '
                'routines: the slab slot index they return, its append / '
                'reuse / panic cases, and the stack-argument mode '
                'selection that does not affect it, with the two '
                'ring-append twins as the boundary.'
            ),
            'measured_denominator_bytes': sum(
                spec['range'][1] - spec['range'][0] for spec in OWNERS.values()
            ),
            'owners': list(OWNERS),
            'complete_fdes': len(OWNERS),
            'owner_body_bytes': sum(
                spec['range'][1] - spec['range'][0] for spec in OWNERS.values()
            ),
        },
        'frames': frame_records,
        'owners': owners,
        'callers': callers,
        'slot_bindings': bindings,
        'source_locations': {
            'overflow_entry': overflow_location,
            'overflow_totals': overflow2_location,
            'vacant_entry_panic': vacant_location,
            'link_assertion_1': assert_location_1,
            'link_assertion_2': assert_location_2,
            'vacant_message': {
                'va': hx(VACANT_MESSAGE_VA),
                'file_offset': hx(message_offset),
                'bytes': len(VACANT_MESSAGE),
                'length_byte': VACANT_MESSAGE[0],
                'text': VACANT_MESSAGE_TEXT,
            },
        },
        'trace': {
            'arguments': {
                'rdi': ('slab collection of 0x110-byte entries: capacity '
                        '+0x0, buffer +0x8, length +0x10, counter +0x18, '
                        'head +0x20'),
                'rsi': 'order record (0x110 bytes) being inserted',
                'rdx': ('caller qword copied into the event record at '
                        '+0x28; not otherwise read by this routine'),
                'rcx': ('event collection (capacity +0x0, buffer +0x8, '
                        'length +0x10) receiving one record per call'),
                'r8': 'pointer to the quantity accumulator qword',
                'r9': ('level record: link fields +0x0/+0x8/+0x10/+0x18, '
                       'totals +0x70/+0x78'),
                'stack_1': ('mode selector: the registration arm of each '
                            'twin passes 0; the append arm passes its '
                            'flag qword (1 when its derivation lookup '
                            'returned nonzero, else the qword at level '
                            '+0x20)'),
                'stack_2': ('link index: the append arm passes the '
                            'cached result of the previous call (the '
                            'value this routine returned last time); '
                            'unused in fresh mode'),
            },
            'entry_accumulator': {
                'update': '*r8 := *r8 + [order+0xe0] as a checked add',
                'overflow_arm': (
                    'on carry the cold block calls the helper behind '
                    'slot 0x64e4ea8 with edi = 0 and the location record '
                    'at 0x64b64b0, then stores the saturating sum (the '
                    'recomputed sum when it does not carry, else '
                    'u64::MAX)'
                ),
                'timing': 'before the mode selection and all other effects',
                'location': 'l1/src/qtys/mod.rs:831:1',
            },
            'mode_selection': {
                'rule': (
                    'link mode iff stack_1 == 1, stack_2 < [rdi+0x10], '
                    'and the qword at [rdi+0x8] + stack_2 * 0x110 does '
                    'not equal 2; every other combination falls back to '
                    'fresh mode'
                ),
                'flag_word': (
                    'the effective flag (1 or 0) is stored into the '
                    'event record at +0x8 and into the rewritten order '
                    'at +0x10'
                ),
                'link_mode_sources': {
                    'order_+0x0': 'the qword at slab buffer[stack_2] + 0x0',
                    'order_+0x8': 'the qword at slab buffer[stack_2] + 0x8',
                    'order_+0x18': 'stack_2 itself',
                    'event_+0x10': 'the qword at slab buffer[stack_2] + 0xf0',
                },
                'fresh_mode_sources': {
                    'order_+0x0': 'the qword at level + 0x10',
                    'order_+0x8': 'the qword at level + 0x18',
                    'order_+0x18': ('a frame slot this routine writes '
                                    'only on the link path (recorded, '
                                    'not interpreted)'),
                    'event_+0x10': 'the qword at order + 0xe0',
                },
            },
            'event_record': {
                'collection': 'the rcx argument',
                'element_bytes': 'per twin (owners_detail)',
                'grow': ('when length equals the capacity field '
                         '[rcx+0x0], the per-twin grow slot runs on '
                         'the collection before the copy'),
                'fields': [
                    {'offset': 0, 'bytes': 8, 'source': 'constant 2'},
                    {'offset': 8, 'bytes': 8,
                     'source': 'the effective mode flag (0 or 1)'},
                    {'offset': 16, 'bytes': 8,
                     'source': ('link mode: the qword at slab '
                                'buffer[stack_2] + 0xf0; fresh mode: '
                                'the qword at order + 0xe0')},
                    {'offset': 24, 'bytes': 8,
                     'source': 'the qword at order + 0xe0'},
                    {'offset': 32, 'bytes': 8,
                     'source': 'the qword at order + 0xb0'},
                    {'offset': 40, 'bytes': 8, 'source': 'the rdx argument'},
                    {'offset': 48, 'bytes': 8,
                     'source': 'the qword at order + 0xf0'},
                    {'offset': 56, 'bytes': 16,
                     'source': 'the 16 bytes at order + 0xf8'},
                    {'offset': 72, 'bytes': 4,
                     'source': 'the dword at order + 0x108'},
                    {'offset': 76, 'bytes': 1,
                     'source': 'the byte at order + 0xd2'},
                ],
                'written_span_bytes': 77,
                'tail': ('the remaining element bytes past offset 77 '
                         'are not written by this routine'),
            },
            'order_rewrite': {
                'fields': [
                    {'offset': 0, 'bytes': 8,
                     'source': 'mode-dependent first qword (mode_selection)'},
                    {'offset': 8, 'bytes': 8,
                     'source': 'mode-dependent second qword (mode_selection)'},
                    {'offset': 16, 'bytes': 8,
                     'source': 'the effective mode flag (0 or 1)'},
                    {'offset': 24, 'bytes': 8,
                     'source': ('link mode: stack_2; fresh mode: a '
                                'frame slot written only on the link '
                                'path')},
                ],
                'scratch_copies': (
                    'the rewritten order is copied to two frame '
                    'scratch areas (the event record area after its '
                    'append, and a second area past the record); '
                    'neither copy is read on the return path'
                ),
            },
            'return_contract': {
                'register': 'rax',
                'value': (
                    'the slab head field [rdi+0x20], loaded after the '
                    'event append and the order rewrite; it is the '
                    'index of the 0x110-byte slab slot that receives '
                    'the order copy'
                ),
                'counter_before_decision': (
                    '[rdi+0x18] is saturating-incremented before the '
                    'head/length comparison'
                ),
                'cases': [
                    {
                        'case': 'append',
                        'condition': 'head == length',
                        'action': (
                            'when head also equals the capacity field '
                            '[rdi+0x0], the per-twin slab grow slot '
                            'runs first; the order copy lands in '
                            'buffer[head]; length and head both become '
                            'head + 1'
                        ),
                        'returns': 'head (the pre-insert length)',
                    },
                    {
                        'case': 'reuse',
                        'condition': (
                            'head < length and the first dword of '
                            'buffer[head] equals 2 (vacant)'
                        ),
                        'action': (
                            'head becomes the qword at buffer[head] '
                            '+ 0x8 (the vacant slot link) and the '
                            'order copy overwrites buffer[head]'
                        ),
                        'returns': 'head (the vacant slot index)',
                    },
                    {
                        'case': 'panic',
                        'condition': (
                            'head > length, or head < length with a '
                            'first dword other than 2 at buffer[head]'
                        ),
                        'action': (
                            'the vacant-entry panic block runs and '
                            'traps with ud2'
                        ),
                        'returns': 'never returns',
                    },
                ],
                'mode_independence': (
                    'the stack arguments change only the order rewrite '
                    'sources and the link writes; the returned index '
                    'and the slot choice never depend on them'
                ),
            },
            'link_writes': {
                'flag_set': [
                    ('the element at the link index is checked '
                     '(index below the current length and its first '
                     'dword not equal to 2, assertion location '
                     'l1/src/book/book_orders.rs:81:40) and receives '
                     '1 at +0x0 and the returned index at +0x8'),
                    ('then, when the rewritten order first dword '
                     'equals 1, the element at the index taken from '
                     '[rsp+0x10] receives 1 at +0x10 and the returned '
                     'index at +0x18 under assertion location '
                     'l1/src/book/book_orders.rs:89:40; otherwise '
                     'the level record receives 1 at +0x0 and the '
                     'returned index at +0x8'),
                ],
                'flag_clear': [
                    ('the level record receives 1 at +0x10 and the '
                     'returned index at +0x18'),
                    ('then the same first-dword split applies: the '
                     'second element link write, or 1 at level +0x0 '
                     'and the returned index at level +0x8'),
                ],
            },
            'level_totals': {
                'quantity': (
                    '[level+0x70] += [order+0xe0] with the same '
                    'checked-add shape; its overflow arm uses the '
                    'second location record (also '
                    'l1/src/qtys/mod.rs:831:1) and the same slot'
                ),
                'count': '[level+0x78] is saturating-incremented',
                'timing': 'after the link writes, before the return',
            },
            'panics_and_assertions': {
                'vacant_entry': {
                    'message': ('length byte 0x16 plus the 22-byte '
                                'text "expected vacant entry " at the '
                                'lea target 0x4339b2'),
                    'location': 'l1/src/slab/slab.rs:78:21',
                    'helper_slot': hx(PANIC_SLOT),
                    'helper_target': hx(PANIC_TARGET),
                    'argument_record': (
                        'two frame words: a pointer to the frame '
                        'slot holding the head value, and the word '
                        'loaded through slot 0x64df6c8'
                    ),
                    'trap': 'ud2',
                },
                'overflow': {
                    'helper_slot': hx(OVERFLOW_SLOT),
                    'helper_target': hx(OVERFLOW_TARGET),
                    'locations': [
                        'l1/src/qtys/mod.rs:831:1',
                        'l1/src/qtys/mod.rs:831:1',
                    ],
                },
                'link_assertions': {
                    'helper_slot': hx(ASSERT_SLOT),
                    'helper_target': hx(ASSERT_TARGET),
                    'locations': [
                        'l1/src/book/book_orders.rs:81:40',
                        'l1/src/book/book_orders.rs:89:40',
                    ],
                },
            },
            'owners_detail': traces,
        },
    }


def twin_difference(data, binary):
    section_list = sections(data)
    decoded = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        _, body = read(data, section_list, start, end - start)
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}', f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        decoded[name] = (decode_export(asm, start, end, body), body)
    rows_a, body_a = decoded['shared_a']
    rows_b, body_b = decoded['shared_b']
    base_a = OWNERS['shared_a']['range'][0]
    base_b = OWNERS['shared_b']['range'][0]
    offsets_a = sorted(va - base_a for va in rows_a)
    offsets_b = sorted(va - base_b for va in rows_b)
    require(offsets_a == offsets_b, 'Twin instruction layout changed')
    differing = [
        offset for offset in offsets_a
        if rows_a[base_a + offset] != rows_b[base_b + offset]
    ]
    differing_bytes = sum(
        1 for i in range(len(body_a)) if body_a[i] != body_b[i]
    )
    require(len(differing) == len(DIFF_SITES), 'Twin difference set changed')
    require(sorted(entry[0] for entry in DIFF_SITES) == differing,
            'Twin difference set changed')
    return {
        'instructions_per_routine': len(offsets_a),
        'identical_instructions': len(offsets_a) - len(differing),
        'differing_instructions': len(differing),
        'differing_bytes': differing_bytes,
        'classes': {
            'frame_and_stack_displacements': (
                'frame size (0x408 / 0x418), the two stack-argument '
                'load displacements, and the two frame scratch '
                'offsets shift by 0x10 in shared_b'
            ),
            'event_element_size': (
                'the event record element size immediate is 0x2b8 '
                'in shared_a and 0x2c8 in shared_b (two sites)'
            ),
            'rip_relative_same_target': (
                'displacements differ but resolve to the same slot, '
                'record, message, or callee in both routines'
            ),
            'per_twin_targets': (
                'the event grow slots bind to different functions '
                '(0x59630a0 / 0x5962310); the slab grow slots differ '
                'but bind to the same function (0x43bbd40); the '
                'unwind destructor glue differs (0x5947550 / '
                '0x5948db0)'
            ),
        },
        'verdict': (
            'the return path -- head load, counter increment, '
            'head/length decision, both slot cases, the link writes, '
            'the totals, and the rax = r13 return move -- is '
            'byte-identical in both routines; the routines are the '
            'same contract instantiated over two event record types'
        ),
    }


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    report = analyze(data)
    report['twin_difference'] = twin_difference(data, binary)
    output.mkdir(parents=True, exist_ok=True)
    raw = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    ranges = [
        (spec['range'][0], spec['range'][1])
        for spec in list(OWNERS.values()) + list(CALLERS.values())
    ]
    lines = [
        line.replace(str(binary), '<authenticated-node115>')
        for line in raw.splitlines()
        if any(f'pc={start:016x}..{end:016x}' in line for start, end in ranges)
    ]
    require(len(lines) == len(report['frames']), 'Retained readelf frame changed')
    (output / 'frames.txt').write_text('\n'.join(lines) + '\n')
    exports = {}
    specs = dict(OWNERS)
    specs.update(CALLERS)
    required = {
        name: (
            [spec['range'][0] + offset for offset, _ in EXACT_SITES]
            + [spec['range'][0] + entry[0] for entry in DIFF_SITES]
            + [spec['range'][0] + branch[0] for branch in BRANCH_SITES]
        ) if name in OWNERS else list(spec['sites'].values())
        for name, spec in specs.items()
    }
    section_list = sections(data)
    for name, spec in specs.items():
        start, end = spec['range']
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}', f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        _, body = read(data, section_list, start, end - start)
        rows = decode_export(asm, start, end, body)
        for site in required[name]:
            require(site in rows,
                    f'{name} required site is not native instruction start: {hx(site)}')
        safe_name = f'{name}_{start:x}_{end:x}_objdump.txt'
        rendered = asm.replace(str(binary), '<authenticated-node115>')
        (output / safe_name).write_text(rendered)
        exports[name] = {'file': safe_name, 'sha256': sha(rendered.encode())}
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
