#!/usr/bin/env python3
"""Index captured ELF64-LE unwind starts without executing or disassembling code."""
import argparse
import bisect
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]


def sections(data):
    if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64:
        raise ValueError('Expected ELF64 little-endian input')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, names_index = struct.unpack_from('<HHH', data, 58)
    if entsize < 64 or not count or names_index >= count or shoff + entsize * count > len(data):
        raise ValueError('Invalid or unsupported ELF section table')
    rows = []
    for index in range(count):
        name, typ, flags, addr, off, size, link, info, align, entry = struct.unpack_from('<IIQQQQIIQQ', data, shoff + index * entsize)
        if typ != 8 and off + size > len(data):
            raise ValueError('Section outside file')
        rows.append(dict(name_offset=name, type=typ, flags=flags, address=addr, offset=off, size=size))
    names = rows[names_index]
    table = data[names['offset']:names['offset'] + names['size']]
    for row in rows:
        off = row.pop('name_offset')
        if off >= len(table):
            raise ValueError('Invalid section name offset')
        end = table.find(b'\0', off)
        if end < 0:
            raise ValueError('Unterminated section name')
        row['name'] = table[off:end].decode('utf-8')
    return rows


def entry_file_offset(data):
    """Resolve the linked entry VA to source bytes, independently of loader rebasing."""
    secs = sections(data)
    entry = struct.unpack_from('<Q', data, 24)[0]
    offsets = {s['offset'] + entry - s['address'] for s in secs
               if s['type'] != 8 and s['address'] <= entry < s['address'] + s['size']}
    if len(offsets) != 1:
        raise ValueError('ELF entry does not have one unambiguous file mapping')
    return offsets.pop()


def unwind_index(data):
    secs = sections(data)
    header = next((s for s in secs if s['name'] == '.eh_frame_hdr'), None)
    if header is None:
        raise ValueError('No .eh_frame_hdr')
    off, base = header['offset'], header['address']
    if header['size'] < 12 or data[off:off + 4] != bytes([1, 0x1b, 0x03, 0x3b]):
        raise ValueError('Unsupported .eh_frame_hdr encodings; do not guess')
    count = struct.unpack_from('<I', data, off + 8)[0]
    if 12 + count * 8 > header['size']:
        raise ValueError('Unwind table is truncated')
    executable = [s for s in secs if s['flags'] & 4 and s['size']]
    entries = []
    for i in range(count):
        start_delta, fde_delta = struct.unpack_from('<ii', data, off + 12 + i * 8)
        start, fde = base + start_delta, base + fde_delta
        section = next((s for s in executable if s['address'] <= start < s['address'] + s['size']), None)
        if section is None:
            raise ValueError(f'Unwind start outside executable sections: {start:#x}')
        fde_section = next((s for s in secs if s['name'] == '.eh_frame'), None)
        if fde_section is None or not fde_section['address'] <= fde < fde_section['address'] + fde_section['size']:
            raise ValueError('FDE pointer outside .eh_frame')
        entries.append({'index': i, 'start': start, 'fde': fde, 'section': section['name']})
    starts = [e['start'] for e in entries]
    if starts != sorted(starts):
        raise ValueError('Unwind index is not ordered')
    for row in entries:
        sec = next(s for s in executable if s['name'] == row['section'])
        following = bisect.bisect_right(starts, row['start'])
        upper = sec['address'] + sec['size']
        if following < len(starts):
            upper = min(upper, starts[following])
        row['next_index_upper_bound'] = upper
    return secs, entries


def generate(binary, prefix):
    data = binary.read_bytes()
    secs, entries = unwind_index(data)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with prefix.with_suffix('.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['index', 'start_va', 'fde_va', 'section', 'next_index_upper_bound_va'])
        for row in entries:
            writer.writerow([row['index'], hex(row['start']), hex(row['fde']), row['section'], hex(row['next_index_upper_bound'])])
    summary = {'binary_sha256': hashlib.sha256(data).hexdigest(), 'unwind_entries': len(entries),
               'unique_starts': len({e['start'] for e in entries}), 'executable_sections': [s for s in secs if s['flags'] & 4],
               'limitations': 'Unwind index entries are not a complete function census. The next-index upper bound is not a decoded FDE function extent. No component ownership or equivalence is established.'}
    prefix.with_suffix('.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


def target_for(release):
    """Map a release label to its artifact path, inventory path and unwind prefix."""
    if release == 'visor':
        return ('artifacts/visor/captured/hl-visor',
                'research/imported/hl-visor.inventory.json',
                'visor-unwind')
    return (f'artifacts/node/{release}/hl-node',
            f'research/imported/hl-node-{release}.inventory.json',
            f'node-{release}-unwind')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release', choices=['94', '115', 'visor'], required=True)
    p.add_argument('--output-dir', type=Path, default=ROOT / 'work/index')
    args = p.parse_args()
    try:
        from artifacts import check
        rel, inventory, prefix = target_for(args.release)
        item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == rel)
        check(ROOT / rel, item)
        summary = generate(ROOT / rel, args.output_dir / prefix)
        expected = json.loads((ROOT / inventory).read_text())['fde_count_eh_frame_hdr']
        if summary['unwind_entries'] != expected:
            raise ValueError('Parsed unwind count differs from retained inventory')
    except (ValueError, OSError) as e:
        print(f'elf_index: {e}', file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
