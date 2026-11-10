#!/usr/bin/env python3
"""Bind node #115 hash_signature_tracker per-height records, sender replace and tag recorder (67th stage).

Continues #6053 (vote item) and #6054 (per-signer cap). This tool binds:

1. the default per-height value: the insert 0x537b870 gets or creates the
   height's value through 0x4da61f0 (twin insert 0x537aa60 through
   0x4da4b90). Both build the same default on the stack: words {0, 8, 0, 0}
   (an empty collection) and byte +0x20 = 1, so a new height starts
   unresolved;
2. the sender insert 0x4dd4f80: keys are 20 bytes (memcmp length 0x14). On a
   hit it copies the old 0x48-byte value out, writes the new one over it and
   returns tag 1. A repeated sender replaces its value, like the key insert
   0x4dd26f0 (#6054);
3. the recorder behind slot 0x64e4ea8 (0x4524e40): under the lock word
   0x64fdb00 it inserts (tag byte, the first 0x14 bytes of a Location record)
   into the global map 0x64fdb08 through 0x3cded00. The only other code that
   addresses the map is 0x4524c20 (slot 0x64e6b50), which empties it. Tags 10
   and 11 come from the two updates with Locations
   hash_signature_tracker.rs:107:28 and :123:32.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from freeze_snapshot_115 import (RELATIVE, SHA256, TARGET, direct_calls, fixed, read_va,
                                 relative_relocations, rip_target, text)

PACKET = ROOT / 'research/work-items/RE-008-hash-signature-tracker-record-115'

INSERT, TWIN = 0x537b870, 0x537aa60
OR_INSERT, TWIN_OR_INSERT = 0x4da61f0, 0x4da4b90
SENDER_INSERT, KEY_INSERT = 0x4dd4f80, 0x4dd26f0
RECORDER, RECORDER_SLOT = 0x4524e40, 0x64e4ea8
CLEAR, CLEAR_SLOT = 0x4524c20, 0x64e6b50
MAP_INSERT = 0x3cded00
LOCK, MAP, ONCE = 0x64fdb00, 0x64fdb08, 0x64fdb28
LOCATIONS = {0x64bc860: (107, 28), 0x64bc878: (123, 32)}
FILE = (0x44d8e1, b'l1/src/abci/hash_signature_tracker.rs')

FIXED = {
    # default per-height value (or-insert 0x4da61f0)
    0x4da621d: 'c644242801',              # mov byte [rsp+0x28], 1    (value +0x20)
    0x4da6222: '48c744240800000000',      # mov qword [rsp+0x8], 0    (value +0x0)
    0x4da622b: '48c744241008000000',      # mov qword [rsp+0x10], 8   (value +0x8)
    0x4da6234: '0f57c9',                  # xorps xmm1, xmm1
    0x4da6237: '0f114c2418',              # movups [rsp+0x18], xmm1   (value +0x10..+0x20)
    # same default in the twin's or-insert 0x4da4b90
    0x4da4bbd: 'c644242801',
    0x4da4bc2: '48c744240800000000',
    0x4da4bcb: '48c744241008000000',
    0x4da4bd4: '0f57c9',
    # insert: resolved test, sender/key inserts, resolve store
    0x537c09f: '807b2000',                # cmp byte [rbx+0x20], 0
    0x537c192: 'c6432000',                # mov byte [rbx+0x20], 0
    # sender insert: 20-byte keys, replace on hit, tag 1
    0x4dd5372: 'ba14000000',              # mov edx, 0x14             (memcmp length)
    0x4dd53f4: '498b4d40',                # mov rcx, [r13+0x40]       (old value tail)
    0x4dd53f8: '48894848',                # mov [rax+0x48], rcx       (old value out)
    0x4dd5443: '488b4a40',                # mov rcx, [rdx+0x40]       (new value tail)
    0x4dd5447: '49894d40',                # mov [r13+0x40], rcx       (overwrite)
    0x4dd544b: 'b901000000',              # mov ecx, 1                (Some(old))
    # recorder: copy 0x14 Location bytes, tag byte, map insert
    0x4524e7e: '0f1006',                  # movups xmm0, [rsi]
    0x4524e81: '8b4610',                  # mov eax, [rsi+0x10]
    0x4524e8d: '400fb6d7',                # movzx edx, dil            (tag)
    # update tags passed in edi to the recorder slot
    0x5afaa83: 'bf0a000000',              # mov edi, 10
    0x5afac32: 'bf0a000000',
    0x5afb063: 'bf0b000000',              # mov edi, 11
    0x5afb212: 'bf0b000000',
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x537bf60, b'\xe8', 5, OR_INSERT),
    (0x537b150, b'\xe8', 5, TWIN_OR_INSERT),
    (0x537c106, b'\xe8', 5, SENDER_INSERT),
    (0x537c152, b'\xe8', 5, KEY_INSERT),
    (0x4524e91, b'\x48\x8d\x35', 7, MAP),
    (0x4524ea2, b'\xe8', 5, MAP_INSERT),
    (0x4524e58, b'\xf0\x48\x0f\xb1\x0d', 9, LOCK),
    (0x4524d03, b'\x48\xc7\x05', 11, MAP),
    (0x5afaa7c, b'\x48\x8d\x35', 7, 0x64bc860),
    (0x5afaa88, b'\xff\x15', 6, RECORDER_SLOT),
    (0x5afac2b, b'\x48\x8d\x35', 7, 0x64bc878),
    (0x5afac37, b'\xff\x15', 6, RECORDER_SLOT),
    (0x5afb05c, b'\x48\x8d\x35', 7, 0x64bc860),
    (0x5afb068, b'\xff\x15', 6, RECORDER_SLOT),
    (0x5afb20b, b'\x48\x8d\x35', 7, 0x64bc878),
    (0x5afb217, b'\xff\x15', 6, RECORDER_SLOT),
)

CLEAR_FIXED = {
    0x4524d03: '48c705fa8dfd0100000000',  # mov qword [MAP], 0
    0x4524d0e: '48c705f78dfd0108000000',  # mov qword [MAP+8], 8
}


def slot_calls(data, slot):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot:
            out.append(base + i)
    return out


def map_references(data):
    """Every RIP-relative mov/lea or lock cmpxchg whose target is the lock, map or Once word."""
    base, code = text(data)
    targets = {LOCK: 'lock', MAP: 'map', MAP + 8: 'map', ONCE: 'once'}
    hits = []
    for m in re.finditer(rb'[\x48\x4c][\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if base + i + 7 + struct.unpack_from('<i', code, i + 3)[0] in targets:
            hits.append(base + i)
    for m in re.finditer(rb'\xf0\x48\x0f\xb1[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if base + i + 9 + struct.unpack_from('<i', code, i + 5)[0] in targets:
            hits.append(base + i)
    for m in re.finditer(rb'\x48\xc7\x05', code):
        i = m.start()
        if base + i + 11 + struct.unpack_from('<i', code, i + 3)[0] in targets:
            hits.append(base + i)
    return sorted(hits)


def bind(data):
    for va, expect in {**FIXED, **CLEAR_FIXED}.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in ((RECORDER_SLOT, RECORDER), (CLEAR_SLOT, CLEAR)):
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    if read_va(data, FILE[0], len(FILE[1])) != FILE[1]:
        raise ValueError('source path changed')
    locations = {}
    for va, (line, col) in LOCATIONS.items():
        if rel.get(va) != FILE[0]:
            raise ValueError(f'Location {va:#x} file changed')
        _, length, got_line, got_col = struct.unpack('<QQII', read_va(data, va, 0x18))
        if (length, got_line, got_col) != (len(FILE[1]), line, col):
            raise ValueError(f'Location {va:#x} changed')
        locations[hex(va)] = f'{FILE[1].decode()}:{line}:{col}'

    refs = map_references(data)
    if not refs or refs[0] < CLEAR or refs[-1] >= RECORDER + 0x170:
        raise ValueError('global map referenced outside the recorder and clear')
    recorder_calls = slot_calls(data, RECORDER_SLOT)
    clear_calls = slot_calls(data, CLEAR_SLOT)
    if direct_calls(data, RECORDER) or direct_calls(data, CLEAR):
        raise ValueError('recorder or clear gained a direct call')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'default_height_value': {
            'or_insert': {'insert': hex(INSERT) + ' -> ' + hex(OR_INSERT),
                          'twin': hex(TWIN) + ' -> ' + hex(TWIN_OR_INSERT)},
            'words': '+0x0 = 0, +0x8 = 8, +0x10..+0x20 = 0 (empty collection)',
            'flag_plus_0x20': 1,
            'meaning': 'a new height starts unresolved; the insert writes 0 at 0x537c192 when the quorum check passes',
        },
        'sender_insert': {
            'fn': hex(SENDER_INSERT),
            'key_bytes': 0x14,
            'on_hit': 'old 0x48-byte value copied to out +0x8..+0x50, new value written, tag 1',
            'called_at': hex(0x537c106) + ' (collection +0x20); key insert ' + hex(KEY_INSERT)
                         + ' at ' + hex(0x537c152) + ' (collection +0x0)',
        },
        'recorder': {
            'slot': hex(RECORDER_SLOT) + ' -> ' + hex(RECORDER),
            'slot_calls': len(recorder_calls),
            'action': 'lock word %s; insert (tag byte, first 0x14 bytes of the Location) into map %s via %s'
                      % (hex(LOCK), hex(MAP), hex(MAP_INSERT)),
            'clear': 'slot %s -> %s resets the map to {0, 8, 0, 0}; slot calls %d'
                     % (hex(CLEAR_SLOT), hex(CLEAR), len(clear_calls)),
            'map_references': len(refs),
            'tag_sites': {'10': ['0x5afaa83', '0x5afac32'], '11': ['0x5afb063', '0x5afb212']},
            'locations': locations,
        },
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
    r = result['recorder']
    print(f"recorder_calls={r['slot_calls']} map_refs={r['map_references']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
