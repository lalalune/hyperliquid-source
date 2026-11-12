#!/usr/bin/env python3
"""Replay one bounded static node115 entry question; never execute the target."""
from pathlib import Path
import hashlib
import json
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections

PACKET = Path(__file__).resolve().parent
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = 'a8616af9432b8d8517b2af677880e117b7c28ef3'


def excerpt_bytes():
    rows = []
    for line in (PACKET / 'entry.asm').read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)', line)
        if match:
            rows.append((int(match[1], 16), bytes.fromhex(match[2])))
    pos = 0x32b03e0
    output = bytearray()
    for va, raw in rows:
        if va != pos:
            raise ValueError('Noncontiguous retained excerpt')
        output.extend(raw)
        pos += len(raw)
    if pos != 0x32b05df:
        raise ValueError('Wrong retained excerpt end')
    return bytes(output)


def inspect(data):
    """Structural/data replay. Caller separately authenticates the full image."""
    secs = sections(data)

    def offset(va, size=1):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('Expected unique file-backed VA mapping')
        s = matches[0]
        return s['offset'] + va - s['address']

    raw_excerpt = excerpt_bytes()
    start = offset(0x32b03e0, len(raw_excerpt))
    if data[start:start + len(raw_excerpt)] != raw_excerpt:
        raise ValueError('Retained excerpt differs from target')
    headers = [s for s in secs if s['name'] == '.eh_frame_hdr']
    if len(headers) != 1:
        raise ValueError('Ambiguous unwind header')
    hdr = headers[0]
    h = hdr['offset']
    if data[h:h + 4] != bytes([1, 27, 3, 59]):
        raise ValueError('Unsupported unwind header encodings')
    count = struct.unpack_from('<I', data, h + 8)[0]
    if 12 + count * 8 > hdr['size']:
        raise ValueError('Truncated unwind index')
    rows = []
    for i in range(count):
        a, b = struct.unpack_from('<ii', data, h + 12 + i * 8)
        if hdr['address'] + a == 0x32b03e0:
            rows.append(dict(index=i, header_entry_file_offset=h + 12 + i * 8,
                             start=hex(hdr['address'] + a), fde=hex(hdr['address'] + b)))
    if len(rows) != 1:
        raise ValueError('Expected one indexed FDE')
    fv = int(rows[0]['fde'], 16)
    fo = offset(fv, 24)
    raw = data[fo:fo + 24]
    length, cie_delta, pc_delta, extent = struct.unpack_from('<IIiI', raw)
    if length != 80 or fv + 8 + pc_delta != 0x32b03e0 or extent != 5194:
        raise ValueError('Selected FDE differs from GNU readelf evidence')
    cie = fv + 4 - cie_delta
    cp = offset(cie, 24)
    cie_length = struct.unpack_from('<I', data, cp)[0]
    cie_bytes = data[cp:cp + 4 + cie_length]
    if cie_bytes.hex() != '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000':
        raise ValueError('Selected CIE encoding bytes differ')
    base = 0x718010
    values = struct.unpack_from('<225i', data, offset(base, 900))
    relocations = []
    for s in secs:
        if s['type'] == 4:
            if s['size'] % 24:
                raise ValueError('Partial RELA record')
            for i in range(0, s['size'], 24):
                loc, info, add = struct.unpack_from('<QQq', data, s['offset'] + i)
                if loc in (0x64e3770, 0x64e3778):
                    slot = offset(loc, 8)
                    relocations.append(dict(section=s['name'], record_file_offset=s['offset'] + i,
                        slot=hex(loc), type=info & 0xffffffff, symbol_index=info >> 32,
                        addend=hex(add), slot_file_offset=slot, slot_raw=data[slot:slot + 8].hex()))
    return dict(source_revision=BASE, coordinate_system='linked ELF VA, exclusive end',
        mappings={hex(v):hex(offset(v)) for v in (0x32b03e0, 0x32b05df, base, 0x64e3770)},
        unwind_header=rows[0], fde=dict(file_offset=hex(fo), raw_prefix=raw.hex(), length=length,
            cie_va=hex(cie), start=hex(fv + 8 + pc_delta), end=hex(fv + 8 + pc_delta + extent), extent=extent),
        table=dict(base=hex(base), file_offset=hex(offset(base)), bounded_data_entries=225,
            table_extent_inferred=False, groups=[dict(target=hex(base + x),
                indices=[i for i,v in enumerate(values) if v == x]) for x in sorted(set(values))]),
        relocations=relocations)


def replay(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('Wrong target SHA-256')
    observed = inspect(data)
    if observed != json.loads((PACKET / 'joins.json').read_text()):
        raise ValueError('Static joins differ from retained observations')
    return observed


if __name__ == '__main__':
    result = replay(TARGET.read_bytes())
    print(json.dumps({'target_sha256': SHA256, 'fde': result['fde'],
        'excerpt_bytes_matched': len(excerpt_bytes()), 'data_entries_compared': 225,
        'helper_relocations_compared': len(result['relocations']),
        'captured_binary_executed': False}, indent=2))
