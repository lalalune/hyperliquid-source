#!/usr/bin/env python3
"""Read the two constant-template anchors and formatter Location; no execution."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA:
    raise ValueError('expected pinned node94')
secs = sections(data)


def read(va, size):
    offsets = [s['offset'] + va - s['address'] for s in secs if s['type'] != 8
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(offsets) != 1:
        raise ValueError('expected one file-backed mapping')
    return offsets[0], data[offsets[0]:offsets[0] + size]


anchors = []
for va, text, site in [(0x1ef5f5, '/static_config', 0x164fbae), (0x1fc0ec, '/cham', 0x164f840)]:
    expected = b'\xc0' + bytes([len(text)]) + text.encode() + b'\0'
    offset, raw = read(va, len(expected))
    instruction = read(site, 7)[1]
    if raw != expected or instruction[:3] != b'\x48\x8d\x35' or site + 7 + struct.unpack_from('<i', instruction, 3)[0] != va:
        raise ValueError('template anchor or source xref changed')
    anchors.append({'template_va': hex(va), 'file_offset': hex(offset), 'bytes_hex': raw.hex(),
                    'literal_va': hex(va + 2), 'literal': text,
                    'xref_site': hex(site), 'xref_bytes_hex': instruction.hex()})

rela = next(s for s in secs if s['name'] == '.rela.dyn')
rels = {a: (i, v) for a, i, v in struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']])}
slot, site = 0x5663328, 0x13448ba
info, path_va = rels[slot]
length, line, column = struct.unpack('<QII', read(slot + 8, 16)[1])
path = read(path_va, length)[1].decode()
instruction = read(site, 7)[1]
if info != 8 or (length, line, column) != (72, 650, 14) or path != '/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/alloc/src/fmt.rs':
    raise ValueError('formatter Location changed')
if instruction[:3] != b'\x4c\x8d\x05' or site + 7 + struct.unpack_from('<i', instruction, 3)[0] != slot:
    raise ValueError('formatter Location xref changed')
_, frames, _ = fde_extents(data)
frame = next(f for f in frames if f['start'] == 0x1344760)
if frame['end'] != 0x13448f2:
    raise ValueError('formatter containing range changed')
print(json.dumps({'target_sha256': SHA, 'anchors': anchors,
                  'formatter_location': {'site': hex(site), 'instruction_hex': instruction.hex(),
                                         'slot': hex(slot), 'slot_file_offset': hex(read(slot, 24)[0]),
                                         'path_va': hex(path_va), 'path': path,
                                         'length': length, 'line': line, 'column': column},
                  'formatter_fde': {'start': hex(frame['start']), 'end': hex(frame['end']),
                                    'fde_va': hex(frame['fde']), 'cie_va': hex(frame['cie'])},
                  'captured_binary_executed': False}, indent=2) + '\n', end='')
