#!/usr/bin/env python3
"""Bind the node #115 Clearinghouse.user_states struct and its per-user entries (stage 105).

Continues #6218 and #6219. The Clearinghouse serializer 0x4482170 passes
`lea rdi,[rbx+0x60]` (user_states) to 0x446b620. That serializer writes six
named fields of a 0xe8-byte struct, each value taken from rbx (user_states)
plus a fixed displacement; two fields go through one-field helpers that load
their own name. Field user_to_state (+0x0) is written by 0x4663f30 as a JSON
array of [key, value] pairs over 0x98-byte entries: the key is the 20 bytes
at entry +0x80 (hex-encoded into a 0x2a-byte buffer by 0x3ee7590) and the
value is entry +0x0 written by 0x3beac00, which emits six one-letter fields.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from freeze_snapshot_115 import SHA256, read_va

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-clearinghouse-user-states-115'

US_SERIALIZER = 0x446b620
ENTRY_SERIALIZER = 0x4663f30
VALUE_SERIALIZER = 0x3beac00
CALLER = (0x4482244, '488d7b60', 0x4482279)   # Clearinghouse: lea rdi,[rbx+0x60]; call 0x446b620

# name, name-lea VA, length, offset-insn VA, offset-insn bytes, offset, value-call VA, callee
USER_STATES = (
    ('user_to_state', 0x446b671, 13, 0x446b680, '4889d9', 0x0, 0x446b683, ENTRY_SERIALIZER),
    ('users_with_positions', 0x446b69b, 20, 0x446b6b9, '488db3b0000000', 0xb0, 0x446b6f1, 0x4614d00),
    ('check_all_users_for_liquidatables', 0x446b715, 33, 0x446b70e, '488d8be0000000', 0xe0, 0x446b724,
     0x4649840),
    ('asset_to_oi_szi', 0x446b73b, 15, 0x446b734, '488d8b90000000', 0x90, 0x446b74a, 0x4664840),
)
# fields written by helpers that load their own name: helper, name-lea VA, length, arg insn, bytes, offset, call
HELPER_FIELDS = (
    ('open_order_tracker', 0x44f4610, 0x44f4624, 18, 0x446b754, '488d7348', 0x48, 0x446b75b),
    ('ar', 0x44f4ad0, 0x44f4ae4, 2, 0x446b765, '4881c3c8000000', 0xc8, 0x446b772),
)

# user_to_state entries: stride, key offset, key length, hex buffer, key call, value call
ENTRY_FIXED = {
    0x4663fd1: '4869c398000000',   # imul rax,rbx,0x98   (entry stride)
    0x4664112: '480580000000',     # add rax,0x80        (key at entry +0x80)
    0x4664192: 'be2a000000',       # mov esi,0x2a        (hex buffer: '0x' + 40 digits)
    0x4664197: 'b914000000',       # mov ecx,0x14        (key length 20)
}
ENTRY_CALLS = {0x46641ae: 0x3ee7590, 0x466425d: VALUE_SERIALIZER}

# per-user value: name, name-lea VA, offset-insn VA, bytes, offset, value-call VA, callee
VALUE_FIELDS = (
    ('u', 0x3bead84, 0x3beac14, '488b4748', 0x48, 0x3beaddf, 0x41d5380),
    ('p', 0x3beae25, 0x3beae78, '4c89ef', 0x0, 0x3beae7e, 0x4206910),
    ('D', 0x3beaec0, 0x3beac5b, '498d7d28', 0x28, 0x3beaed4, 0x464d090),
    ('l', 0x3beaf05, 0x3beaf26, '498d5d68', 0x68, 0x3beaf6f, 0x4592eb0),
    ('S', 0x3beaf93, 0x3beafb4, '498d7d50', 0x50, 0x3beafe9, 0x36752b0),
    ('r', 0x3beb013, 0x3beb00f, '4983c560', 0x60, 0x3beb027, 0x465f980),
)
VALUE_FIXED = {
    0x3bead78: '4c8b6c2460',   # mov r13,[rsp+0x60]  (entry base reloaded)
    0x3bead7d: '4c8b742468',   # mov r14,[rsp+0x68]  (entry +0x28)
    0x3beadda: '488b742448',   # mov rsi,[rsp+0x48]  (u value = entry +0x48)
    0x3beaed1: '4c89f1',       # mov rcx,r14         (D value)
    0x3beb024: '4c89e9',       # mov rcx,r13         (r value = entry +0x60)
}


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def name_at(data, lea_va, length):
    raw = read_va(data, lea_va, 7)
    if raw[:3] != b'\x48\x8d\x35':
        raise ValueError(f'name load at {lea_va:#x} changed')
    target = lea_va + 7 + struct.unpack_from('<i', raw, 3)[0]
    if bytes([0xba]) + struct.pack('<I', length) not in read_va(data, lea_va + 7, 14):
        raise ValueError(f'name length near {lea_va:#x} changed')
    return target, read_va(data, target, length).decode()


def bind(data, fdes=None):
    fixed(data, CALLER[0], CALLER[1])
    if call_target(data, CALLER[2]) != US_SERIALIZER:
        raise ValueError('user_states serializer call changed')
    fields = []
    for (name, lea_va, length, off_va, off_bytes, offset, call_va, callee) in USER_STATES:
        target, text = name_at(data, lea_va, length)
        if text != name:
            raise ValueError(f'field name at {target:#x} changed')
        fixed(data, off_va, off_bytes)
        if call_target(data, call_va) != callee:
            raise ValueError(f'value call at {call_va:#x} changed')
        fields.append({'name': name, 'name_va': hex(target), 'offset': hex(offset), 'offset_insn': hex(off_va),
                       'value_fn': hex(callee)})
    for (name, helper, lea_va, length, off_va, off_bytes, offset, call_va) in HELPER_FIELDS:
        target, text = name_at(data, lea_va, length)
        if text != name:
            raise ValueError(f'helper field name at {target:#x} changed')
        fixed(data, off_va, off_bytes)
        if call_target(data, call_va) != helper:
            raise ValueError(f'helper call at {call_va:#x} changed')
        fields.append({'name': name, 'name_va': hex(target), 'offset': hex(offset), 'offset_insn': hex(off_va),
                       'value_fn': hex(helper) + ' (helper writes name)'})
    for va, expect in ENTRY_FIXED.items():
        fixed(data, va, expect)
    for va, callee in ENTRY_CALLS.items():
        if call_target(data, va) != callee:
            raise ValueError(f'entry call at {va:#x} changed')
    for va, expect in VALUE_FIXED.items():
        fixed(data, va, expect)
    values = []
    for (name, lea_va, off_va, off_bytes, offset, call_va, callee) in VALUE_FIELDS:
        target, text = name_at(data, lea_va, 1)
        if text != name:
            raise ValueError(f'value field name at {target:#x} changed')
        fixed(data, off_va, off_bytes)
        if call_target(data, call_va) != callee:
            raise ValueError(f'value field call at {call_va:#x} changed')
        values.append({'name': name, 'name_va': hex(target), 'offset': hex(offset), 'offset_insn': hex(off_va),
                       'value_fn': hex(callee)})
    offsets = sorted(int(f['offset'], 16) for f in fields)
    if offsets != [0x0, 0x48, 0x90, 0xb0, 0xc8, 0xe0]:
        raise ValueError('user_states offsets changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'caller': {'site': hex(CALLER[0]), 'insn': 'lea rdi,[rbx+0x60]', 'call': hex(CALLER[2]),
                   'serializer': hex(US_SERIALIZER)},
        'user_states_size': hex(0x148 - 0x60),
        'user_states_fields': sorted(fields, key=lambda f: int(f['offset'], 16)),
        'user_to_state': {
            'writer': hex(ENTRY_SERIALIZER), 'entry_stride': '0x98', 'key_offset': '0x80', 'key_len': 20,
            'key_encoder': '0x3ee7590 (hex into 0x2a-byte buffer)', 'value_offset': '0x0',
            'value_serializer': hex(VALUE_SERIALIZER), 'form': 'JSON array of [key, value] pairs',
        },
        'per_user_value_fields': values,
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    result = bind(binary.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(f"user_states_fields={len(result['user_states_fields'])} value_fields={len(result['per_user_value_fields'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
