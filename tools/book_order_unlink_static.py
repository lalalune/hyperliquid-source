#!/usr/bin/env python3
"""Static contract of the node #115 book-order slab unlink twins.

The two 860-byte FDE bodies at 0x58dfbc0 and 0x58dff20 sit immediately
after the RE-006 shared insert-return twins. Each one removes one
0x110-byte slab element: a qword tag of 2, or an index at or past the
slab length, writes tag 2 to the output and returns; every other tag
pushes the slot onto the slab free list, appends one event record, and
subtracts the element qword at +0xe0 from the u64 behind r9. A null
level pointer skips the level updates. A negative qword at element
+0xb0 panics through l1/src/book/level.rs:32:54. Otherwise the body
rewires the level's link words under the book_orders.rs:137 and :145
Option unwrap sites, unless element byte +0xd8 is nonzero, in which
case it calls 0x4de02d0 first and this packet stops before interpreting
that callee's writes.

The twins differ in frame size, event-element size, the event grow
slot, and the unwind destructor. This tool authenticates the capture,
pins those facts, and regenerates the packet. It does not execute the
node.
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
PACKET = ROOT / 'research/work-items/RE-006-node115-book-order-unlink'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ELEMENT_STRIDE = 0x110
VACANT_TAG = 2

OWNERS = {
    'unlink_a': {
        'range': (0x58DFBC0, 0x58DFF1C),
        'sha256': '17ab611392e3211229944efe4c965d336f193010a8682d19934ece069e26007e',
        'frame_bytes': 0x418,
        'stack_argument_displacement': 0x450,
        'event_element_bytes': 0x2C8,
        'event_grow_slot': 0x64E4F88,
        'event_grow_target': 0x5962310,
        'unwind_destructor': 0x5948DB0,
    },
    'unlink_b': {
        'range': (0x58DFF20, 0x58E027C),
        'sha256': 'b23cb9f94a4440655d0649d0f7b9ccbdbfd1b16594a9e7f2fe83e675e98a3d86',
        'frame_bytes': 0x408,
        'stack_argument_displacement': 0x440,
        'event_element_bytes': 0x2B8,
        'event_grow_slot': 0x64E5A28,
        'event_grow_target': 0x59630A0,
        'unwind_destructor': 0x5947550,
    },
}
CALLERS = {
    'caller_a1': {
        'range': (0x58E1400, 0x58E1F34),
        'sha256': 'e978a87b5223ae9319a66a1b651849d36df81823cda84d9e0a688bffc74e9827',
        'owner': 'unlink_a',
        'site': 0x58E1A8C,
        'setup': bytes.fromhex(
            'eb034531e4498b8f100100004d8d8f180100004c892424'
            '488dbc24d0000000498db7800000004889ea4c8b442418'),
    },
    'caller_a2': {
        'range': (0x58E1F40, 0x58E2A74),
        'sha256': '34c675f2dda0a756f173c72ca26313f16e6d15d5055fd03dc712484d806e5137',
        'owner': 'unlink_a',
        'site': 0x58E25CC,
        'setup': bytes.fromhex(
            'eb034531e4498b8f100100004d8d8f180100004c892424'
            '488dbc24d0000000498db7800000004889ea4c8b442418'),
    },
    'caller_b1': {
        'range': (0x58E2A80, 0x58E36C0),
        'sha256': 'ae7e16c8b741bb8b3bb7931c82d271e359164e42fd9a40c0c96bbe7f56875954',
        'owner': 'unlink_b',
        'site': 0x58E3174,
        'setup': bytes.fromhex(
            'eb0231ed498b8e100100004d8d8e1801000048892c24'
            '488dbc24e0010000498db6800000004c89fa4c8b442408'),
    },
    'caller_b2': {
        'range': (0x58E36C0, 0x58E4300),
        'sha256': '1fbc74ef092d6469a9dc7985286fb9c62e682b6c8ceca081fdf2f3181c738e73',
        'owner': 'unlink_b',
        'site': 0x58E3DB4,
        'setup': bytes.fromhex(
            'eb0231ed498b8e100100004d8d8e1801000048892c24'
            '488dbc24e0010000498db6800000004c89fa4c8b442408'),
    },
}

COPY_SLOT = 0x64DF508
ASSERT_SLOT = 0x64DF830
ASSERT_TARGET = 0x1680C10
OVERFLOW_SLOT = 0x64E4EA8
OVERFLOW_TARGET = 0x4524E40
PANIC_SLOT = 0x64DF6A0
PANIC_TARGET = 0x1680C30
PAD_SLOT = 0x64DF4C0
PAD_TARGET = 0x1680CAB
SIDE_CALL = 0x4DE02D0
ORDER_DROP_GLUE = 0x5957F70
UNWIND_RESUME = 0x63F0A50
UNWRAP_MESSAGE_VA = 0x91F9EB
UNWRAP_MESSAGE = b'called `Result::unwrap()` on an `Err` value'
PANIC_ARGUMENT_VA = 0x64A35E0
LEVEL_LOCATION_VA = 0x64A3508
LEVEL_LOCATION = {'file': 'l1/src/book/level.rs', 'line': 32, 'column': 54}
QUANTITY_LOCATION_VA = 0x64B64F8
QUANTITY_LOCATION = {'file': 'l1/src/qtys/impl_sz.rs', 'line': 9, 'column': 1}
LINK_LOCATION_1_VA = 0x64B6510
LINK_LOCATION_1 = {'file': 'l1/src/book/book_orders.rs', 'line': 137, 'column': 44}
LINK_LOCATION_2_VA = 0x64B6528
LINK_LOCATION_2 = {'file': 'l1/src/book/book_orders.rs', 'line': 145, 'column': 44}

# Instruction bytes present at the same owner-relative offset in both
# bodies. Diff sites are checked separately.
SHARED_SITES = (
    (0x11, '4989d6'),
    (0x14, '488b5610'),
    (0x18, '4939d6'),
    (0x1b, '7315'),
    (0x1d, '488b4608'),
    (0x21, '4d69ee10010000'),
    (0x28, '4a8b2c28'),
    (0x2c, '4883fd02'),
    (0x30, '750c'),
    (0x32, '48c70702000000'),
    (0x39, 'e9b0020000'),
    (0x3e, '4d89c7'),
    (0x58, '4c8b6620'),
    (0x65, 'ba08010000'),
    (0x7b, '49c7450002000000'),
    (0x83, '4d896508'),
    (0x87, '488b4318'),
    (0x8b, '4883f801'),
    (0x8f, '4883d0ff'),
    (0x93, '48894318'),
    (0x97, '4c897320'),
    (0xa5, '418b8508010000'),
    (0xb3, '410f1085f8000000'),
    (0xbb, '0f11842488010000'),
    (0xdb, '48c784245801000003000000'),
    (0x10e, '48c784245001000002000000'),
    (0x11a, '4d8b6f10'),
    (0x11e, '4d3b2f'),
    (0x161, '4d29fd'),
    (0x16b, '4531ed'),
    (0x175, '31ff'),
    (0x1b1, '4d85e4'),
    (0x1b4, '0f884e010000'),
    (0x1ba, '837d2001'),
    (0x1c0, '4c397528'),
    (0x1c6, '0f10442450'),
    (0x1cb, '0f114520'),
    (0x1cf, '80bc241801000000'),
    (0x1d9, '8b84241c010000'),
    (0x1e0, '488d7d50'),
    (0x200, '488b4570'),
    (0x204, '488b4d78'),
    (0x208, '31d2'),
    (0x20a, '4c29f8'),
    (0x20d, '480f43d0'),
    (0x211, '48895570'),
    (0x215, '4883f901'),
    (0x219, '4883d1ff'),
    (0x21d, '48894d78'),
    (0x226, '41f6c001'),
    (0x243, '4869f010010000'),
    (0x24a, '833c3302'),
    (0x261, '48895610'),
    (0x265, '48894e18'),
    (0x26e, '4c894510'),
    (0x272, '48894518'),
    (0x27c, '31ed'),
    (0x28a, '48895500'),
    (0x28e, '48894d08'),
    (0x2aa, '4869c910010000'),
    (0x2b1, '833c0b02'),
    (0x2ba, '4c8903'),
    (0x2bd, '48894308'),
    (0x2c7, '0fb66d10'),
    (0x2cb, '4080f501'),
    (0x2d4, 'ba10010000'),
    (0x2e7, '4088ab10010000'),
    (0x2ff, 'c3'),
    (0x306, 'eb25'),
    (0x322, 'be2b000000'),
    (0x32d, '0f0b'),
)

# (offset, length, kind). kind is frame, stack, event, or an absolute
# target shared by both twins. A two-item tuple kind is (target_a, target_b).
DIFF_SITES = (
    (0x0A, 7, 'frame'),
    (0x75, 6, COPY_SLOT),
    (0x126, 6, 'grow'),
    (0x12C, 7, 'event'),
    (0x13F, 5, 'event'),
    (0x144, 6, COPY_SLOT),
    (0x16E, 7, QUANTITY_LOCATION_VA),
    (0x177, 6, OVERFLOW_SLOT),
    (0x185, 8, 'stack'),
    (0x19D, 8, 'stack'),
    (0x1FB, 5, SIDE_CALL),
    (0x231, 7, LINK_LOCATION_1_VA),
    (0x29C, 7, LINK_LOCATION_2_VA),
    (0x2E1, 6, COPY_SLOT),
    (0x2EE, 7, 'frame'),
    (0x300, 6, ASSERT_SLOT),
    (0x308, 7, UNWRAP_MESSAGE_VA),
    (0x30F, 7, PANIC_ARGUMENT_VA),
    (0x316, 7, LEVEL_LOCATION_VA),
    (0x327, 6, PANIC_SLOT),
    (0x33A, 5, 'unwind'),
    (0x341, 6, PAD_SLOT),
    (0x34F, 5, ORDER_DROP_GLUE),
    (0x357, 5, UNWIND_RESUME),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hx(value):
    return hex(value)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def relative_relocations(data):
    result = {}
    for section in sections(data):
        if section['name'] == '.rela.dyn':
            blob = data[section['offset']:section['offset'] + section['size']]
            for cursor in range(0, len(blob), 24):
                offset, info, addend = struct.unpack_from('<QQq', blob, cursor)
                if info & 0xFFFFFFFF == 8:
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


def resolve(body, base, offset, length):
    disp = struct.unpack_from('<i', body, offset + length - 4)[0]
    return base + offset + length + disp


def authenticate(data):
    require(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
            'Node 115 artifact authentication failed')


def check_locations(data, section_list, relas):
    found = {
        'level': location(data, section_list, relas, LEVEL_LOCATION_VA),
        'quantity': location(data, section_list, relas, QUANTITY_LOCATION_VA),
        'link_137': location(data, section_list, relas, LINK_LOCATION_1_VA),
        'link_145': location(data, section_list, relas, LINK_LOCATION_2_VA),
    }
    expect = {
        'level': LEVEL_LOCATION,
        'quantity': QUANTITY_LOCATION,
        'link_137': LINK_LOCATION_1,
        'link_145': LINK_LOCATION_2,
    }
    for name, wanted in expect.items():
        got = {key: found[name][key] for key in ('file', 'line', 'column')}
        require(got == wanted, f'{name} location changed: {got}')
    _, message = read(data, section_list, UNWRAP_MESSAGE_VA, len(UNWRAP_MESSAGE))
    require(message == UNWRAP_MESSAGE, 'Result unwrap message changed')
    return found


def check_owner(body, base, spec):
    for offset, text in SHARED_SITES:
        raw = bytes.fromhex(text)
        require(body[offset:offset + len(raw)] == raw,
                f'Shared site changed at {hx(base + offset)}')
    for offset, length, kind in DIFF_SITES:
        target = resolve(body, base, offset, length)
        if kind == 'frame':
            imm = struct.unpack_from('<I', body, offset + 3)[0]
            require(imm == spec['frame_bytes'],
                    f'Frame immediate changed at {hx(base + offset)}')
        elif kind == 'stack':
            disp = struct.unpack_from('<I', body, offset + 4)[0]
            require(disp == spec['stack_argument_displacement'],
                    f'Stack argument displacement changed at {hx(base + offset)}')
        elif kind == 'event':
            imm = struct.unpack_from('<I', body, offset + length - 4)[0]
            require(imm == spec['event_element_bytes'],
                    f'Event size changed at {hx(base + offset)}')
        elif kind == 'grow':
            require(target == spec['event_grow_slot'],
                    f'Grow slot changed at {hx(base + offset)}')
        elif kind == 'unwind':
            require(target == spec['unwind_destructor'],
                    f'Unwind destructor changed at {hx(base + offset)}')
        else:
            require(target == kind,
                    f'Resolved target changed at {hx(base + offset)}')


def analyze(data):
    section_list = sections(data)
    _frames, fdes, _extents = fde_extents(data)
    by_range = {(item['start'], item['end']): item for item in fdes}
    relas = relative_relocations(data)
    specs = dict(OWNERS)
    specs.update(CALLERS)
    for name, spec in specs.items():
        require(tuple(spec['range']) in by_range, f'{name} is not an exact FDE body')
    bodies = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        _, body = read(data, section_list, start, end - start)
        require(len(body) == 860, f'{name} extent changed')
        require(sha(body) == spec['sha256'], f'{name} body hash changed')
        check_owner(body, start, spec)
        bodies[name] = body
    left, right = bodies['unlink_a'], bodies['unlink_b']
    covered = set()
    for offset, length, _kind in DIFF_SITES:
        span = set(range(offset, offset + length))
        require(not covered & span, f'Overlapping diff site at {hx(offset)}')
        require(left[offset:offset + length] != right[offset:offset + length],
                f'Classified site is identical at {hx(offset)}')
        covered |= span
    actual = {index for index, (a, b) in enumerate(zip(left, right)) if a != b}
    require(actual <= covered, 'Twin byte differences escaped the classified instructions')
    require(len(DIFF_SITES) == 24, 'Diff site count changed')
    text = next(section for section in section_list if section['name'] == '.text')
    text_body = data[text['offset']:text['offset'] + text['size']]
    census = {spec['range'][0]: [] for spec in OWNERS.values()}
    cursor = text_body.find(b'\xe8')
    while cursor != -1:
        site = text['address'] + cursor
        if cursor + 5 <= len(text_body):
            target = site + 5 + struct.unpack_from('<i', text_body, cursor + 1)[0]
            if target in census:
                census[target].append(site)
        cursor = text_body.find(b'\xe8', cursor + 1)
    for name, spec in OWNERS.items():
        want = sorted(
            caller['site'] for caller in CALLERS.values()
            if caller['owner'] == name)
        require(sorted(census[spec['range'][0]]) == want,
                f'{name} direct caller census changed')
    for name, spec in CALLERS.items():
        start, end = spec['range']
        _, body = read(data, section_list, start, end - start)
        require(sha(body) == spec['sha256'], f'{name} body hash changed')
        site = spec['site']
        require(start <= site < end, f'{name} call site outside its FDE')
        _, ins = read(data, section_list, site, 5)
        require(ins[0] == 0xE8, f'{name} call site is not a direct E8')
        target = site + 5 + struct.unpack_from('<i', ins, 1)[0]
        require(target == OWNERS[spec['owner']]['range'][0],
                f'{name} call target changed')
        setup = spec['setup']
        _, window = read(data, section_list, site - len(setup), len(setup))
        require(window == setup, f'{name} argument setup changed')
    body_refs = [
        hx(offset) for offset in relas
        if any(spec['range'][0] <= offset < spec['range'][1]
               for spec in specs.values())
    ]
    addend_refs = [
        hx(value) for value in set(relas.values())
        if any(value == spec['range'][0] for spec in OWNERS.values())
    ]
    require(not body_refs, 'A selected body holds a relocation slot')
    require(not addend_refs, 'An owner entry is reached through a relocation')
    bindings = {
        hx(slot): (hx(relas[slot]) if slot in relas else None)
        for slot in (COPY_SLOT, ASSERT_SLOT, OVERFLOW_SLOT, PANIC_SLOT,
                     PAD_SLOT, OWNERS['unlink_a']['event_grow_slot'],
                     OWNERS['unlink_b']['event_grow_slot'])
    }
    require(bindings[hx(COPY_SLOT)] is None, 'Copy slot gained a relocation')
    require(bindings[hx(ASSERT_SLOT)] == hx(ASSERT_TARGET),
            'Assertion helper binding changed')
    require(bindings[hx(OVERFLOW_SLOT)] == hx(OVERFLOW_TARGET),
            'Quantity helper binding changed')
    require(bindings[hx(PANIC_SLOT)] == hx(PANIC_TARGET),
            'Panic helper binding changed')
    require(bindings[hx(PAD_SLOT)] == hx(PAD_TARGET),
            'Unwind pad binding changed')
    require(bindings[hx(OWNERS['unlink_a']['event_grow_slot'])]
            == hx(OWNERS['unlink_a']['event_grow_target']),
            'unlink_a grow binding changed')
    require(bindings[hx(OWNERS['unlink_b']['event_grow_slot'])]
            == hx(OWNERS['unlink_b']['event_grow_target']),
            'unlink_b grow binding changed')
    locations = check_locations(data, section_list, relas)
    frames = {}
    for name, spec in specs.items():
        start, end = spec['range']
        frames[name] = {
            'start': hx(start),
            'end': hx(end),
            'bytes': end - start,
            'sha256': spec['sha256'],
        }
        if name in OWNERS:
            frames[name].update({
                'frame_bytes': spec['frame_bytes'],
                'event_element_bytes': spec['event_element_bytes'],
                'event_grow_slot': hx(spec['event_grow_slot']),
                'event_grow_target': hx(spec['event_grow_target']),
                'unwind_destructor': hx(spec['unwind_destructor']),
            })
        else:
            frames[name].update({
                'owner': spec['owner'],
                'call_site': hx(spec['site']),
            })
    return {
        'target': {
            'path': 'artifacts/node/115/hl-node',
            'size': TARGET_SIZE,
            'sha256': TARGET_SHA256,
        },
        'component': 'orderbook',
        'task': 'RE-006',
        'question': (
            'What does the slab helper immediately after the shared '
            'insert-return twins do with one 0x110-byte element?'
        ),
        'scope': {
            'measured_denominator_bytes': 1720,
            'owner_fdes': 2,
            'caller_fdes_retained_as_boundary': 4,
            'caller_boundary_bytes': 12008,
            'claim': (
                'The 1,720 owner bytes are the interpreted contract. '
                'The four caller FDEs establish the direct-call '
                'boundary and the argument setup only.'
            ),
        },
        'frames': frames,
        'twin_difference': {
            'instructions_checked_as_shared_sites': len(SHARED_SITES),
            'classified_difference_instructions': len(DIFF_SITES),
            'differing_bytes': sum(1 for a, b in zip(left, right) if a != b),
            'frame_bytes': ['0x418', '0x408'],
            'event_element_bytes': ['0x2c8', '0x2b8'],
            'same_resolved_targets': [
                hx(kind) for _offset, _length, kind in DIFF_SITES
                if isinstance(kind, int)
            ],
        },
        'slots': bindings,
        'locations': locations,
        'unwrap_message': UNWRAP_MESSAGE.decode(),
        'contract': {
            'element_stride': ELEMENT_STRIDE,
            'vacant_tag': VACANT_TAG,
            'early_return': (
                'index >= slab length, or the element qword at +0x0 '
                'equals 2: store qword 2 at the output and return'
            ),
            'free_list': (
                'store qword 2 at element +0x0, store the previous '
                'head at element +0x8, saturating-decrement the qword '
                'at slab +0x18, and store the removed index at slab +0x20'
            ),
            'event': (
                'append one record whose defined stores are qword 2 at '
                '+0x0, qword 3 at +0x8, element +0xb0 at +0x20, the rcx '
                'argument at +0x28, element +0xf0 at +0x30, the 16 bytes '
                'at element +0xf8 at +0x38, the dword at element +0x108 '
                'at +0x48, and the byte at element +0xd2 at +0x4c; the '
                'copy length is the per-twin event size and the other '
                'copied bytes are not stored by this body'
            ),
            'quantity': (
                'subtract element +0xe0 from the u64 behind r9; a '
                'borrow calls the helper at the impl_sz.rs:9:1 '
                'location and, when that helper returns, stores 0'
            ),
            'null_level': (
                'a null stack argument copies the pre-removal element '
                'and writes flag byte 0 at output +0x110'
            ),
            'negative_field': (
                'a negative element qword at +0xb0, reached only when '
                'the level pointer is non-null, calls the panic '
                'formatter with the 43-byte Result unwrap message and '
                'traps with ud2'
            ),
            'cached_link': (
                'when the level dword at +0x20 equals 1 and the qword '
                'at +0x28 equals the removed index, copy 16 bytes from '
                'element +0x10 onto level +0x20'
            ),
            'side_call_boundary': (
                'a nonzero byte at element +0xd8 calls 0x4de02d0 with '
                'rdi = level + 0x50 and an argument pair (element '
                '+0xf0, element dword +0xdc); later level stores are '
                'not interpreted across that call'
            ),
            'level_totals': (
                'on the zero +0xd8 path, level +0x70 is a saturating '
                'subtract of element +0xe0 and level +0x78 is a '
                'saturating decrement'
            ),
            'relink': (
                'the low bit of the saved element tag selects which '
                'saved link index is checked against the original '
                'length and against a live low dword of 2; failure '
                'calls the Option unwrap helper and jumps to ud2. The '
                'zero link-word arm writes the saved tag and the other '
                'index into the level; the nonzero arm writes them '
                'into the checked element. The output flag is 0 when '
                'the level byte at +0x0 is nonzero, otherwise that '
                "byte's counterpart at +0x10 xor 1"
            ),
        },
        'limitations': [
            'An FDE extent is not a source-function boundary.',
            'The four caller bodies are not interpreted beyond the direct call and its immediate argument setup.',
            'Event bytes other than the listed stores are not defined by this body.',
            'The callee at 0x4de02d0 is a boundary: its writes are not modeled.',
            'The quantity helper is the same returning slot used by the insert twins; a path that does not return would skip the following store of 0.',
            'No whole-book match, cancel API, or component gate is claimed.',
        ],
    }


def saturating_dec(value):
    return value - 1 if value >= 1 else 0


def saturating_sub(value, amount):
    return value - amount if value >= amount else 0


def _u64(blob, offset):
    return int.from_bytes(blob[offset:offset + 8], 'little')


def _set_u64(blob, offset, value):
    blob[offset:offset + 8] = (value & ((1 << 64) - 1)).to_bytes(8, 'little')


def _u32(blob, offset):
    return int.from_bytes(blob[offset:offset + 4], 'little')


def unlink_order(elements, counter, head, index, argument, quantity, level,
                 event_len, event_cap):
    """Executable reading of the pinned removal contract.

    `elements` is a list of 0x110-byte buffers. `quantity` is a
    one-element list. `level` is None or a mutable byte buffer of at
    least 0x80 bytes. Returns a stop tag and a detail dict. Mutates
    the inputs only as far as the selected stop.
    """
    length = len(elements)
    if index >= length or _u64(elements[index], 0) == VACANT_TAG:
        return 'vacant', {}
    saved = bytearray(elements[index])
    _set_u64(elements[index], 0, VACANT_TAG)
    _set_u64(elements[index], 8, head[0])
    counter[0] = saturating_dec(counter[0])
    head[0] = index
    if event_len == event_cap:
        return 'event_full', {}
    event = {
        'discriminant': 2,
        'kind': 3,
        'field_b0': _u64(saved, 0xb0),
        'argument': argument,
        'field_f0': _u64(saved, 0xf0),
        'field_f8': bytes(saved[0xf8:0x108]),
        'field_108': _u32(saved, 0x108),
        'field_d2': saved[0xd2],
    }
    amount = _u64(saved, 0xe0)
    underflow = quantity[0] < amount
    quantity[0] = saturating_sub(quantity[0], amount)
    detail = {'event': event, 'underflow_helper': underflow}
    if level is None:
        detail['output'] = bytes(saved) + b'\x00'
        return 'returned', detail
    if _u64(saved, 0xb0) >> 63:
        return 'negative_field', detail
    if _u32(level, 0x20) == 1 and _u64(level, 0x28) == index:
        level[0x20:0x30] = saved[0x10:0x20]
    if saved[0xd8] != 0:
        detail['side_call'] = {
            'level_offset': 0x50,
            'field_f0': _u64(saved, 0xf0),
            'field_dc': _u32(saved, 0xdc),
        }
        return 'side_call', detail
    _set_u64(level, 0x70, saturating_sub(_u64(level, 0x70), amount))
    _set_u64(level, 0x78, saturating_dec(_u64(level, 0x78)))
    link_a = _u64(saved, 8)
    link_word = _u64(saved, 0x10)
    link_b = _u64(saved, 0x18)
    tag = _u64(saved, 0)

    def absent(link_index):
        return (link_index >= length
                or _u32(elements[link_index], 0) == VACANT_TAG)

    if tag & 1:
        if absent(link_a):
            return 'link_absent', detail
        _set_u64(elements[link_a], 0x10, link_word)
        _set_u64(elements[link_a], 0x18, link_b)
        if link_word != 0:
            if absent(link_b):
                return 'link_absent', detail
            _set_u64(elements[link_b], 0, tag)
            _set_u64(elements[link_b], 8, link_a)
        else:
            _set_u64(level, 0x10, tag)
            _set_u64(level, 0x18, link_a)
    else:
        _set_u64(level, 0, link_word)
        _set_u64(level, 8, link_b)
        if link_word != 0:
            if absent(link_b):
                return 'link_absent', detail
            _set_u64(elements[link_b], 0, tag)
            _set_u64(elements[link_b], 8, link_a)
        else:
            _set_u64(level, 0x10, tag)
            _set_u64(level, 0x18, link_a)
    flag = 0 if level[0] != 0 else (level[0x10] ^ 1)
    detail['output'] = bytes(saved) + bytes([flag])
    return 'returned', detail


def generate(binary, output):
    binary = Path(binary)
    data = binary.read_bytes()
    authenticate(data)
    report = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    raw = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    ranges = [tuple(spec['range']) for spec in list(OWNERS.values()) + list(CALLERS.values())]
    lines = [
        line.replace(str(binary), '<authenticated-node115>')
        for line in raw.splitlines()
        if any(f'pc={start:016x}..{end:016x}' in line for start, end in ranges)
    ]
    require(len(lines) == len(report['frames']), 'Retained readelf frame changed')
    (output / 'frames.txt').write_text('\n'.join(lines) + '\n')
    section_list = sections(data)
    exports = {}
    specs = dict(OWNERS)
    specs.update(CALLERS)
    for name, spec in specs.items():
        start, end = spec['range']
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}', f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        _, body = read(data, section_list, start, end - start)
        rows = decode_export(asm, start, end, body)
        if name in OWNERS:
            for offset, text in SHARED_SITES:
                require(start + offset in rows,
                        f'{name} shared site is not an instruction start')
            for offset, _length, _kind in DIFF_SITES:
                require(start + offset in rows,
                        f'{name} diff site is not an instruction start')
        else:
            require(spec['site'] in rows,
                    f'{name} call site is not an instruction start')
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
