#!/usr/bin/env python3
"""RE-001: verify node94's non-production context initializer, without execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x143f520, 0x143f670
BODY_SHA256 = '77c2e3d7ef4fea21b9c49db48437215f2fc7d3f657e4fc9418bd9b2f706d3e1f'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_va(data, secs, va, size):
    mappings = [s for s in secs if s['type'] != 8 and s['address'] <= va
                and va + size <= s['address'] + s['size']]
    require(len(mappings) == 1, 'Expected one file-backed mapping')
    s = mappings[0]
    offset = s['offset'] + va - s['address']
    require(offset + size <= len(data), 'Truncated mapped bytes')
    return data[offset:offset + size]


def observe(data):
    """Structural controls remain reachable independently of the identity gate."""
    secs = sections(data)
    read = lambda va, size: read_va(data, secs, va, size)
    _, frames = eh_frame_records(data, secs)
    matches = [f for f in frames if f['start'] == START]
    require(len(matches) == 1 and matches[0]['end'] == END, 'Initializer FDE changed')
    frame = matches[0]
    reloc_section = next(s for s in secs if s['name'] == '.rela.dyn')
    raw = read(reloc_section['address'], reloc_section['size'])
    require(len(raw) % 24 == 0, 'Truncated RELA table')
    relocs = {}
    for slot, info, addend in struct.iter_unpack('<QQq', raw):
        if info == 8:
            require(slot not in relocs, 'Duplicate RELATIVE relocation')
            relocs[slot] = addend

    def encoding(va, prefix, size):
        block = read(va, size)
        require(block.startswith(bytes.fromhex(prefix)), f'Instruction changed at {va:#x}')
        return block

    # Decode the actual immediate and displacements rather than assuming zeroed padding.
    flags = encoding(0x143f563, '66c783', 9)
    flag_offset, flag_value = struct.unpack_from('<IH', flags, 3)
    require((flag_offset, flag_value) == (0x110, 0), 'Flag word changed')
    sentinel = struct.unpack_from('<Q', encoding(0x143f57f, '48b8', 10), 2)[0]
    require(sentinel == 1 << 63, 'Sentinel value changed')
    sentinel_offsets = [struct.unpack_from('<I', encoding(va, '488983', 7), 3)[0]
                        for va in (0x143f589, 0x143f590)]
    require(sentinel_offsets == [0x90, 0xa8], 'Sentinel destinations changed')
    label_load = encoding(0x143f543, '0f1005', 7)
    label_va = 0x143f54a + struct.unpack_from('<i', label_load, 3)[0]
    tail = encoding(0x143f54d, 'c74010', 7)[3:]
    label = read(label_va, 16) + tail
    require(label == b'N/A (non-production)', 'Label copy changed')
    require(read(label_va, 20) == label, 'Label data changed')
    static_va = 0x143f5a8 + struct.unpack_from('<i', encoding(0x143f5a1, '0f1005', 7), 3)[0]
    static_second = 0x143f5b6 + struct.unpack_from('<i', encoding(0x143f5af, '0f100d', 7), 3)[0]
    require((static_va, static_second) == (0x566a228, 0x566a238), 'Static copy source changed')
    static_data = read(static_va, 32)
    static_relocs = {s: v for s, v in relocs.items() if static_va <= s < static_va + 32}
    require(static_relocs == {0x566a228: 0x202e90}, 'Static initializer relocation changed')
    require(static_data == bytes(32), 'Static file bytes changed')
    source_slot = 0x143f55b + struct.unpack_from('<i', encoding(0x143f554, '488d35', 7), 3)[0]
    require(source_slot == 0x566a248 and source_slot in relocs, 'Source Location binding changed')
    path_size, line, column = struct.unpack('<QII', read(source_slot + 8, 16))
    path = read(relocs[source_slot], path_size).decode('utf-8')
    require(path == '/home/ubuntu/hl/code_Mainnet/base/src/crit_msg.rs', 'Location source path changed')
    require(relocs.get(0x577acf0) == START, 'Initializer function-pointer binding changed')
    expected_slots = {0x576dfd8: 0x54c06b0, 0x576dfb8: 0x1346068,
                      0x576e010: 0x54c8cb0, 0x576e128: 0x157b63b}
    require(all(relocs.get(s) == v for s, v in expected_slots.items()), 'Call relocation changed')
    calls = []
    for va, indirect in [(0x143f531, True), (0x143f55e, False), (0x143f632, True),
                         (0x143f645, False), (0x143f64d, False), (0x143f65c, True),
                         (0x143f665, False), (0x143f66a, True)]:
        if indirect:
            code = encoding(va, 'ff15', 6)
            slot = va + 6 + struct.unpack_from('<i', code, 2)[0]
            require(slot in relocs, 'Call slot missing RELATIVE relocation')
            calls.append({'site_va': hex(va), 'slot_va': hex(slot), 'target_va': hex(relocs[slot])})
        else:
            code = encoding(va, 'e8', 5)
            calls.append({'site_va': hex(va), 'target_va': hex(va + 5 + struct.unpack_from('<i', code, 1)[0])})
    body = read(START, END - START)
    require(hashlib.sha256(body).hexdigest() == BODY_SHA256, 'Enclosing initializer body changed')
    return {
        'target_sha256': SHA256,
        'range': {'start_va': hex(START), 'end_va_exclusive': hex(END), 'bytes': len(body),
                  'body_sha256': BODY_SHA256, 'fde_va': hex(frame['fde']), 'cie_va': hex(frame['cie'])},
        'label': {'va': hex(label_va), 'copied_bytes': len(label), 'text': label.decode()},
        'zero_flag_word': {'offset': hex(flag_offset), 'width': 2},
        'sentinel_stores': [{'offset': hex(o), 'width': 8, 'value': hex(sentinel)} for o in sentinel_offsets],
        'static_copy': {'source_va': hex(static_va), 'file_bytes': static_data.hex(),
                        'destination_offsets': ['0xc0', '0xe0'], 'width_each': 32,
                        'relocated_first_qword': 'load_bias + 0x202e90'},
        'helper_location': {'slot_va': hex(source_slot), 'path_va': hex(relocs[source_slot]),
                            'path': path, 'line': line, 'column': column},
        'initializer_function_pointer': {'slot_va': '0x577acf0', 'addend_va': hex(START)},
        'calls': calls,
        'minimum_written_output_bytes': flag_offset + 2,
        'captured_binaries_executed': False,
        'limits': 'Opaque regions are not all-zero. Their Rust types, inactive bytes, allocation/helper '
                  'semantics, full caller closure and complete output layout remain unresolved. No progress gate.',
    }


def build(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Wrong node94 SHA-256')
    return observe(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--out', type=Path, default=ROOT / 'work/production-default-94.json')
    args = parser.parse_args()
    result = build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('Verified node94 initializer stores, FDE, static relocation and call bindings; no execution.')


if __name__ == '__main__':
    main()
