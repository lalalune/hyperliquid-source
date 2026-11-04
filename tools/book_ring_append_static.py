#!/usr/bin/env python3
"""Static trace of the two node-115 book insert-path ring appends.

Both 663-byte FDE bodies (0x5911890 and 0x5911b30) are reached only from
the four large insert-order functions.  Either body loads the order's
qword at +0xb0 and panics when its sign bit is set, derives a signed key
from that qword and the side byte at +0xd2, then splits on the dword at
+0xd8.  The == 1 arm appends one 32-byte record to the level ring
{capacity +0x30, buffer +0x38, head +0x40, length +0x48}; the other arm
only calls the shared insert routine and conditionally caches its
result in the level's +0x20/+0x28 slots.  This tool authenticates the
whole capture, pins those facts in bytes, and regenerates the packet.
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
PACKET = ROOT / 'research/work-items/RE-006-node115-book-ring-append'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

OWNERS = {
    'ring_append_a': {
        'range': (0x5911890, 0x5911B27),
        'sha256': '08e8b4239e731ee50d74c945e5fe6ae3f8e18d12a5ee8c6ab8725363260558b6',
        'key_construction': 0x4DC42F0,
        'level_lookup': 0x4DA5F90,
        'shared_routine': 0x58DF360,
    },
    'ring_append_b': {
        'range': (0x5911B30, 0x5911DC7),
        'sha256': 'cecc9282e700d4433aa077e63b65b50eaa287b16d6de32964b7bbb743f5b3223',
        'key_construction': 0x4DC52B0,
        'level_lookup': 0x4DA7010,
        'shared_routine': 0x58DF790,
    },
}
CALLERS = {
    'insert_caller_1': {
        'range': (0x5901DD0, 0x5905CE9),
        'sha256': '69712a6423044cdfd8b9a5ddf17ffa1a7c6346381471234df8aa587d04e4b2c6',
        'site': 0x5903FAB,
        'owner': 'ring_append_a',
    },
    'insert_caller_2': {
        'range': (0x5905CF0, 0x5909B21),
        'sha256': '41b6ea3b11ca2a035f22bfa7703cb11ca5a623eb0a3970740b0193580a649e84',
        'site': 0x5908216,
        'owner': 'ring_append_b',
    },
    'insert_caller_3': {
        'range': (0x5909B30, 0x590DA49),
        'sha256': '368701b152fa985ad4852bfa862db2edefb73b7c15f5c425be49a1e259f6ecc4',
        'site': 0x590BD0B,
        'owner': 'ring_append_a',
    },
    'insert_caller_4': {
        'range': (0x590DA50, 0x5911881),
        'sha256': '17d3fe719c2fc2a12be204c26a182231920e632f81aabf26844f48acf6374bd2',
        'site': 0x590FF76,
        'owner': 'ring_append_b',
    },
}
PANIC_MESSAGE_VA = 0x91F9EB
PANIC_MESSAGE = b"called `Result::unwrap()` on an `Err` value"
PANIC_LOCATION_VA = 0x64A3508
PANIC_LOCATION = {'file': 'l1/src/book/level.rs', 'line': 32, 'column': 54}
PANIC_ARGUMENT_VA = 0x64A35E0
PANIC_SLOT = 0x64DF6A0
TRACK_LOCATION_VA = 0x64B6558
TRACK_LOCATION = {
    'file': 'l1/src/book/book/impl_insert_order.rs',
    'line': 537,
    'column': 45,
}
TRACK_CALLEE = 0x4DBE910
MEMCPY_SLOT = 0x64DF508
GROW_SLOT = 0x64E27A8
LEVEL_OP_CALLEE = 0x518E690
DERIVATION_CALLEES = (0x4DCE580, 0x4E188F0)

# Exact instruction bytes, identical at these owner-relative offsets in
# both twin bodies.  Only rip-relative displacements and the targets of
# the per-owner callees differ between the twins.
EXACT_SITES = (
    (0x000, '55415741564155415453'), (0x011, 'f20f11442408'),
    (0x017, '4989f4'), (0x041, '498b9c24f0000000'),
    (0x01A, '488b86b0000000'), (0x021, '4885c0'),
    (0x049, '410fb68c24d2000000'), (0x052, '4889c2'), (0x055, '48f7da'),
    (0x058, '85c9'), (0x05A, '480f45d0'), (0x05E, 'c1e105'),
    (0x061, '488d3439'), (0x065, '4881c6a8000000'),
    (0x09E, '4183bc24d800000001'), (0x0A9, '418b8424dc000000'),
    (0x0B5, '48c744243801000000'), (0x0BE, '48895c2440'),
    (0x0C3, '89442408'), (0x0C7, '89442448'),
    (0x0CB, '48c744245002000000'), (0x0ED, '4885c0'),
    (0x0F0, '48895c2430'),
    (0x0FC, 'b801000000'), (0x108, '488d5c2468'),
    (0x10D, 'ba10010000'), (0x13F, '6a00'), (0x14A, '41807e2000'),
    (0x155, '49c7462001000000'), (0x15D, '49894628'),
    (0x166, '498b4620'), (0x16A, '4889442410'), (0x16F, '498d5628'),
    (0x173, '4c8b3a'), (0x176, '488d5c2468'), (0x17B, 'ba10010000'),
    (0x1A9, '4157'), (0x1AB, 'ff742418'), (0x1BF, '498d7e50'),
    (0x1C3, '4c8b7c2430'), (0x1CB, '8b6c2408'), (0x1DC, '488b4c2428'),
    (0x1E1, '8b4108'), (0x1E4, '89442474'), (0x1E8, '488b01'),
    (0x1EB, '488944246c'), (0x1F0, '498b4e30'), (0x1F4, '498b4648'),
    (0x1F8, '4839c8'), (0x212, '488d5001'), (0x216, '49895648'),
    (0x21A, '49034640'), (0x21E, '31d2'), (0x220, '4839c8'),
    (0x223, '480f43d1'), (0x227, '4829d0'), (0x22A, '498b4e38'),
    (0x22E, '48c1e005'), (0x232, '4c893c01'), (0x236, '896c0108'),
    (0x23A, '0f10442468'), (0x23F, '0f1144010c'), (0x244, '4889d8'),
    (0x26E, '488d542407'), (0x273, 'be2b000000'), (0x27E, '0f0b'),
)
REQUIRED_SITES = tuple(
    [spec['range'][0] + offset for spec in OWNERS.values()
     for offset, _ in EXACT_SITES]
    + [0x5911890 + offset for offset in
       (0x24, 0x71, 0x7B, 0x99, 0xA7, 0xDE, 0xE8, 0xFA, 0x106, 0x118,
        0x141, 0x14F, 0x186, 0x1AF, 0x1B8, 0x1D7, 0x1FB, 0x204, 0x259,
        0x260, 0x267, 0x278)]
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


def signed_key(value, side_byte):
    """The pinned key rule: +[order+0xb0] for a nonzero side byte at
    +0xd2, its two's-complement negation for a zero side byte."""
    value &= 0xFFFFFFFFFFFFFFFF
    if side_byte:
        return value - (1 << 64) if value >> 63 else value
    negated = (-value) & 0xFFFFFFFFFFFFFFFF
    return negated - (1 << 64) if negated >> 63 else negated


def append_index(head, length, capacity):
    """The pinned slot rule: (head + length) reduced by one conditional
    subtraction of capacity.  Valid because the grow step guarantees
    length < capacity and head < capacity at the store."""
    total = head + length
    return total - capacity if total >= capacity else total


def call_target(body, base, offset):
    return base + offset + 5 + struct.unpack_from('<i', body, offset + 1)[0]


def slot_target(body, base, offset):
    return base + offset + 6 + struct.unpack_from('<i', body, offset + 2)[0]


def lea_target(body, base, offset):
    return base + offset + 7 + struct.unpack_from('<i', body, offset + 3)[0]


def element0_origin(body, base):
    """Bind the saved order word, including the reload overwriting cached R15.

    This is caller-local def/use evidence under ordinary ABI/stack premises,
    not execution or a proof of arbitrary opaque callee effects.
    """
    sites = (
        ('bind_order', 0x017, '4989f4'),
        ('load_order_word', 0x041, '498b9c24f0000000'),
        ('save_order_word', 0x0F0, '48895c2430'),
        ('reload_saved_word', 0x1C3, '4c8b7c2430'),
        ('store_element0', 0x232, '4c893c01'),
    )
    for name, offset, encoded in sites:
        require(body[offset:offset + len(encoded) // 2] == bytes.fromhex(encoded),
                f'Element0 source flow changed at {hx(base + offset)} ({name})')
    source_offset = struct.unpack_from('<I', body, 0x045)[0]
    saved_offset = body[0x0F4]
    require(saved_offset == body[0x1C7], 'Element0 reload uses a different spill')
    return {
        'object': 'order', 'offset': hx(source_offset),
        'saved_stack_offset': hx(saved_offset), 'carrier': 'r15',
        'sites': {name: hx(base + offset) for name, offset, _ in sites},
        'premise': 'ordinary callee-saved registers and caller-owned stack storage',
    }


def owner_trace(body, base, spec):
    for offset, expected in EXACT_SITES:
        want = bytes.fromhex(expected)
        require(body[offset:offset + len(want)] == want,
                f'Pinned instruction changed at {hx(base + offset)}')
    require(body[0x24:0x26] == b'\x0f\x88', 'Entry guard branch opcode changed')
    require(base + 0x2A + struct.unpack_from('<i', body, 0x26)[0] == base + 0x259,
            'Entry guard no longer reaches the panic block')
    require(body[0xA7] == 0x75, 'Arm split branch opcode changed')
    require(base + 0xA9 + struct.unpack_from('<b', body, 0xA8)[0] == base + 0x108,
            'Arm split no longer reaches the registration arm')
    require(body[0xFA] == 0x74, 'Derivation result branch opcode changed')
    require(base + 0xFC + struct.unpack_from('<b', body, 0xFB)[0] == base + 0x166,
            'Derivation zero path changed')
    require(body[0x106] == 0xEB, 'Append path jump opcode changed')
    require(base + 0x108 + struct.unpack_from('<b', body, 0x107)[0] == base + 0x173,
            'Append path entry changed')
    require(body[0x14F:0x151] == b'\x0f\x85', 'Registration flag branch opcode changed')
    require(base + 0x155 + struct.unpack_from('<i', body, 0x151)[0] == base + 0x247,
            'Registration arm no longer returns early when the flag is set')
    require(body[0x1FB] == 0x75, 'Grow branch opcode changed')
    require(base + 0x1FD + struct.unpack_from('<b', body, 0x1FC)[0] == base + 0x212,
            'Grow branch no longer skips to the append')
    calls = {
        'key_construction': call_target(body, base, 0x71),
        'level_lookup': call_target(body, base, 0x7B),
        'level_op': call_target(body, base, 0x99),
        'derivation_first': call_target(body, base, 0xDE),
        'derivation_second': call_target(body, base, 0xE8),
        'shared_in_registration_arm': call_target(body, base, 0x141),
        'shared_in_append_arm': call_target(body, base, 0x1AF),
        'track_caller': call_target(body, base, 0x1D7),
    }
    require(calls['key_construction'] == spec['key_construction'],
            'Key construction callee changed')
    require(calls['level_lookup'] == spec['level_lookup'],
            'Level lookup callee changed')
    require(calls['level_op'] == LEVEL_OP_CALLEE, 'Level operation callee changed')
    require((calls['derivation_first'], calls['derivation_second'])
            == DERIVATION_CALLEES, 'Arm derivation callees changed')
    require(calls['shared_in_registration_arm'] == spec['shared_routine']
            and calls['shared_in_append_arm'] == spec['shared_routine'],
            'Shared insert routine callee changed')
    require(calls['track_caller'] == TRACK_CALLEE, 'Track-caller callee changed')
    slots = {
        'memcpy_in_registration_arm': slot_target(body, base, 0x118),
        'memcpy_in_append_arm': slot_target(body, base, 0x186),
        'grow': slot_target(body, base, 0x204),
        'panic_format': slot_target(body, base, 0x278),
    }
    require(slots['memcpy_in_registration_arm'] == MEMCPY_SLOT
            and slots['memcpy_in_append_arm'] == MEMCPY_SLOT,
            'Order copy slot changed')
    require(slots['grow'] == GROW_SLOT, 'Ring grow slot changed')
    require(slots['panic_format'] == PANIC_SLOT, 'Panic format slot changed')
    require(lea_target(body, base, 0x259) == PANIC_MESSAGE_VA,
            'Panic message address changed')
    require(lea_target(body, base, 0x260) == PANIC_ARGUMENT_VA,
            'Panic argument address changed')
    require(lea_target(body, base, 0x267) == PANIC_LOCATION_VA,
            'Panic location record changed')
    require(lea_target(body, base, 0x1B8) == TRACK_LOCATION_VA,
            'Track-caller location record changed')
    return calls, slots


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
    owner_refs = [
        hx(offset) for offset in sorted(relas)
        if any(spec['range'][0] <= offset < spec['range'][1]
               for spec in OWNERS.values())
    ]
    frame_refs = [
        hx(offset) for offset in sorted(relas)
        if any(item['range'][0] <= offset < item['range'][1]
               for item in specs.values())
    ]
    require(not owner_refs and not frame_refs,
            'An append or caller body is reached through a relocation')
    text = next(section for section in section_list if section['name'] == '.text')
    text_body = data[text['offset']:text['offset'] + text['size']]
    census = {spec['range'][0]: [] for spec in OWNERS.values()}
    for cursor in range(text['size'] - 5):
        if text_body[cursor] != 0xE8:
            continue
        site = text['address'] + cursor
        target = site + 5 + struct.unpack_from('<i', text_body, cursor + 1)[0]
        if target in census:
            census[target].append(site)
    for name, spec in OWNERS.items():
        want = sorted(
            caller['site'] for caller in CALLERS.values()
            if caller['owner'] == name
        )
        require(sorted(census[spec['range'][0]]) == want,
                f'{name} direct caller census changed')
    message_offset, message = read(data, section_list, PANIC_MESSAGE_VA,
                                   len(PANIC_MESSAGE))
    require(message == PANIC_MESSAGE, 'Panic message changed')
    panic_location = location(data, section_list, relas, PANIC_LOCATION_VA)
    require({key: panic_location[key] for key in ('file', 'line', 'column')}
            == PANIC_LOCATION, 'Entry guard panic location changed')
    track_location = location(data, section_list, relas, TRACK_LOCATION_VA)
    require({key: track_location[key] for key in ('file', 'line', 'column')}
            == TRACK_LOCATION, 'Track-caller location changed')
    traces = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        _, body = read(data, section_list, start, end - start)
        calls, slots = owner_trace(body, start, spec)
        traces[name] = {
            'callees': {key: hx(value) for key, value in calls.items()},
            'slots': {key: hx(value) for key, value in slots.items()},
            'instruction_sites_checked': len(EXACT_SITES) + 22,
            'element0_origin': element0_origin(body, start),
        }
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
                hx(caller['site']) for caller in CALLERS.values()
                if caller['owner'] == name
            ],
        }
    callers = {
        name: {
            'range': [hx(spec['range'][0]), hx(spec['range'][1])],
            'bytes': spec['range'][1] - spec['range'][0],
            'sha256': spec['sha256'],
            'calls': spec['owner'],
            'call_site': hx(spec['site']),
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
            'owner_body_references': owner_refs,
            'frame_references': frame_refs,
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
                'Trace the two insert-path ring appends, their signed key '
                'rule, and the +0xd8 arm split, with the four insert '
                'callers as the boundary.'
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
        'source_locations': {
            'entry_guard_panic': panic_location,
            'track_caller_call': track_location,
            'panic_message': {
                'va': hx(PANIC_MESSAGE_VA),
                'file_offset': hx(message_offset),
                'bytes': len(PANIC_MESSAGE),
                'text': PANIC_MESSAGE.decode(),
            },
            'panic_argument_va': hx(PANIC_ARGUMENT_VA),
        },
        'trace': {
            'entry_guard': {
                'field_offset': '0xb0',
                'test': 'the qword at order +0xb0 is sign-tested (test/js)',
                'panic_block_offset': '0x259',
                'panic': 'Result::unwrap() on an Err value',
                'panic_location': 'l1/src/book/level.rs:32:54',
            },
            'signed_key_rule': {
                'value_field_offset': '0xb0',
                'side_byte_offset': '0xd2',
                'half_base_offset': '0xa8',
                'half_stride_bytes': 32,
                'cases': [
                    {'side_byte': 0, 'key': 'negated value'},
                    {'side_byte': 'nonzero', 'key': 'value unchanged'},
                ],
            },
            'arm_split': {
                'field_offset': '0xd8',
                'append_arm_value': 1,
                'append_arm': 'the dword at order +0xd8 equals 1',
                'other_arm': 'any other value',
                'order_copy_bytes': 0x110,
            },
            'registration_arm': {
                'shared_routine_stack_extra': 'one pushed zero qword',
                'flag_offset': '0x20',
                'cached_value_offset': '0x28',
                'rule': (
                    'if the level byte at +0x20 is nonzero the arm returns '
                    'the shared routine result unchanged; otherwise it sets '
                    '+0x20 to 1 and stores the result at +0x28, then returns '
                    'it; it never appends'
                ),
            },
            'append_arm': {
                'shared_routine_stack_arguments': (
                    'the selected qword (through post-derivation RDX on the '
                    'nonzero path, level +0x28 on the zero path) and the arm flag qword '
                    '(1 when the derivation lookup returned nonzero, else '
                    'the qword at level +0x20)'
                ),
                'shared_word_sources': {
                    'zero_derivation': {'base': 'level', 'offset': '0x28'},
                    'nonzero_derivation': {
                        'base': 'post_derivation_rdx', 'pointee_identity': 'unclosed',
                    },
                },
                'track_caller_call': (
                    'level +0x50 with the qword at order +0xf0, the dword '
                    'at order +0xdc, and the shared routine result; its '
                    'own result is discarded'
                ),
                'element_patch': (
                    'the copied order bytes at stack +0x68 are patched at '
                    '+4 with the third argument qword and at +12 with its '
                    'dword at +8 before the tail copy'
                ),
            },
            'append': {
                'object_offsets': {
                    'capacity': '0x30',
                    'buffer': '0x38',
                    'head': '0x40',
                    'length': '0x48',
                },
                'element_bytes': 32,
                'grow_rule': (
                    'when length equals capacity the grow helper behind '
                    'slot 0x64e27a8 runs on the ring fields at +0x30 before '
                    'the store'
                ),
                'index_rule': (
                    '(head + length) mod capacity by one conditional '
                    'subtraction of capacity'
                ),
                'length_increment': 1,
                'element0_origin': {
                    'object': 'order', 'offset': '0xf0',
                    'saved_stack_offset': '0x30', 'carrier': 'r15',
                },
                'element_fields': [
                    {'offset': 0, 'bytes': 8,
                     'source': 'the saved order +0xf0 qword, reloaded from stack +0x30'},
                    {'offset': 8, 'bytes': 4,
                     'source': 'the dword at order +0xdc'},
                    {'offset': 12, 'bytes': 16,
                     'source': 'the patched order copy at stack +0x68'},
                ],
            },
            'returns': (
                'both arms return the shared insert routine result; the '
                'append arm forwards it in rbx and the registration arm '
                'returns it in rax'
            ),
            'owners_detail': traces,
        },
    }


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    report = analyze(data)
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
            + [spec['range'][0] + offset for offset in
               (0x24, 0x71, 0x7B, 0x99, 0xA7, 0xDE, 0xE8, 0xFA, 0x106,
                0x118, 0x141, 0x14F, 0x186, 0x1AF, 0x1B8, 0x1D7, 0x1FB,
                0x204, 0x259, 0x260, 0x267, 0x278)]
        ) if name in OWNERS else [spec['site']]
        for name, spec in specs.items()
    }
    for name, spec in specs.items():
        start, end = spec['range']
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}', f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        section_list = sections(data)
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
