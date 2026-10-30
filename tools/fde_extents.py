#!/usr/bin/env python3
"""Decode captured ELF64-LE .eh_frame FDE extents without executing or disassembling code."""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index

ROOT = Path(__file__).resolve().parents[1]

# Only the encodings observed in the captured nodes are accepted; anything else fails closed.
PCREL_SDATA4 = 0x1b
INDIRECT_PCREL_SDATA4 = 0x9b
AUGMENTATION_CHARS = set('zRPLS')
INT3 = 0xcc
LIMITATIONS = ('An FDE extent is the unwind-described address range, not a validated function boundary. '
               'Split hot/cold parts get separate FDEs and code without unwind data has none. Gap classes are '
               'byte patterns only: other-byte gaps may hold NOP fill, data or code without FDEs. '
               'No component ownership or equivalence is established.')


def uleb(data, pos, end):
    result = shift = 0
    while True:
        if pos >= end or shift > 63:
            raise ValueError('Truncated or oversized ULEB128')
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7f) << shift
        shift += 7
        if byte < 0x80:
            return result, pos


def sleb(data, pos, end):
    result = shift = 0
    while True:
        if pos >= end or shift > 63:
            raise ValueError('Truncated or oversized SLEB128')
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7f) << shift
        shift += 7
        if byte < 0x80:
            return result - (1 << shift) if byte & 0x40 else result, pos


def sdata4(data, pos, end):
    if pos + 4 > end:
        raise ValueError('Truncated encoded pointer')
    return struct.unpack_from('<i', data, pos)[0], pos + 4


def pcrel(data, pos, end, base_va, offset_base):
    """Apply a DW_EH_PE_pcrel|sdata4 value; a raw zero is a null pointer, as in libgcc."""
    raw, after = sdata4(data, pos, end)
    return (None if raw == 0 else base_va + pos - offset_base + raw), after


def parse_cie(data, start, body, end, va, base):
    version = data[body]
    if version != 1:
        raise ValueError(f'Unsupported CIE version {version} at {va + start - base:#x}')
    terminator = data.find(b'\0', body + 1, end)
    if terminator < 0:
        raise ValueError('Unterminated CIE augmentation')
    augmentation = data[body + 1:terminator].decode('ascii')
    if not augmentation.startswith('z') or set(augmentation) - AUGMENTATION_CHARS or augmentation.count('z') != 1:
        raise ValueError(f'Unsupported CIE augmentation {augmentation!r}; do not guess')
    pos = terminator + 1
    code_align, pos = uleb(data, pos, end)
    data_align, pos = sleb(data, pos, end)
    if pos >= end:
        raise ValueError('Truncated CIE')
    pos += 1  # Version 1 return-address register is one byte.
    aug_length, pos = uleb(data, pos, end)
    aug_end = pos + aug_length
    if aug_end > end:
        raise ValueError('CIE augmentation data outside record')
    cie = {'va': va + start - base, 'augmentation': augmentation, 'code_align': code_align,
           'data_align': data_align, 'fde_encoding': None, 'lsda_encoding': None, 'personality_slot': None}
    for char in augmentation[1:]:
        if char == 'S':
            continue
        if pos >= aug_end:
            raise ValueError('Truncated CIE augmentation data')
        encoding = data[pos]
        pos += 1
        if char == 'R':
            if encoding != PCREL_SDATA4:
                raise ValueError(f'Unsupported FDE pointer encoding {encoding:#x}')
            cie['fde_encoding'] = encoding
        elif char == 'L':
            if encoding != PCREL_SDATA4:
                raise ValueError(f'Unsupported LSDA encoding {encoding:#x}')
            cie['lsda_encoding'] = encoding
        else:  # 'P': record the indirect slot address; never dereference it.
            if encoding != INDIRECT_PCREL_SDATA4:
                raise ValueError(f'Unsupported personality encoding {encoding:#x}')
            cie['personality_slot'], pos = pcrel(data, pos, aug_end, va, base)
    if pos != aug_end:
        raise ValueError('CIE augmentation length mismatch')
    if cie['fde_encoding'] is None:
        raise ValueError('CIE lacks an R pointer encoding; do not guess')
    return cie


def eh_frame_records(data, secs=None):
    """Return CIEs keyed by VA and FDEs in section order from a captured .eh_frame."""
    secs = secs or sections(data)
    frame = next((s for s in secs if s['name'] == '.eh_frame'), None)
    if frame is None or frame['type'] == 8:
        raise ValueError('No .eh_frame contents')
    base, limit, va = frame['offset'], frame['offset'] + frame['size'], frame['address']
    cies, fdes, pos, terminated = {}, [], base, False
    while pos < limit:
        if pos + 4 > limit:
            raise ValueError('Truncated .eh_frame length')
        length = struct.unpack_from('<I', data, pos)[0]
        if length == 0:
            terminated = True
            if any(data[pos + 4:limit]):
                raise ValueError('Non-zero bytes after .eh_frame terminator')
            break
        if length == 0xffffffff:
            raise ValueError('64-bit DWARF .eh_frame records are unsupported; do not guess')
        body, end = pos + 8, pos + 4 + length
        if length < 4 or end > limit:
            raise ValueError(f'.eh_frame record outside section at {va + pos - base:#x}')
        cie_delta = struct.unpack_from('<I', data, pos + 4)[0]
        if cie_delta == 0:
            cie = parse_cie(data, pos, body, end, va, base)
            cies[cie['va']] = cie
        else:
            cie_va = va + pos + 4 - base - cie_delta
            cie = cies.get(cie_va)
            if cie is None:
                raise ValueError(f'FDE at {va + pos - base:#x} names no preceding CIE')
            begin, after = pcrel(data, body, end, va, base)
            if begin is None:
                raise ValueError(f'FDE at {va + pos - base:#x} has a null start')
            pc_range, after = sdata4(data, after, end)
            if pc_range < 0:
                raise ValueError('Negative FDE range')
            lsda = None
            aug_length, after = uleb(data, after, end)
            aug_end = after + aug_length
            if aug_end > end:
                raise ValueError('FDE augmentation data outside record')
            if cie['lsda_encoding'] is not None:
                lsda, after = pcrel(data, after, aug_end, va, base)
            if after != aug_end:
                raise ValueError('FDE augmentation length mismatch')
            fdes.append({'fde': va + pos - base, 'cie': cie_va, 'start': begin, 'end': begin + pc_range, 'lsda': lsda})
        pos = end
    if not terminated:
        raise ValueError('.eh_frame lacks a zero terminator')
    return cies, fdes


def is_int3_fill(data, section, start, end):
    offset = section['offset'] + start - section['address']
    return data[offset:offset + end - start].count(INT3) == end - start


def fde_extents(data):
    secs, table = unwind_index(data)
    cies, fdes = eh_frame_records(data, secs)
    frame = next(s for s in secs if s['name'] == '.eh_frame')
    header = next(s for s in secs if s['name'] == '.eh_frame_hdr')
    frame_ptr = header['address'] + 4 + struct.unpack_from('<i', data, header['offset'] + 4)[0]
    if frame_ptr != frame['address']:
        raise ValueError('.eh_frame_hdr eh_frame_ptr does not name .eh_frame')
    executable = [s for s in secs if s['flags'] & 4 and s['size']]
    except_table = next((s for s in secs if s['name'] == '.gcc_except_table'), None)
    by_va = {f['fde']: f for f in fdes}
    if len(by_va) != len(fdes):
        raise ValueError('Duplicate FDE record addresses')
    referenced, start_mismatch = set(), 0
    for row in table:
        fde = by_va.get(row['fde'])
        if fde is None:
            raise ValueError(f"Unwind table entry {row['index']} does not name an FDE record")
        if row['fde'] in referenced:
            raise ValueError(f"FDE {row['fde']:#x} is indexed more than once")
        referenced.add(row['fde'])
        start_mismatch += row['start'] != fde['start']
        fde['index'], fde['next_index_upper_bound'] = row['index'], row['next_index_upper_bound']
    counts = collections.Counter()
    for fde in fdes:
        section = next((s for s in executable if s['address'] <= fde['start'] < s['address'] + s['size']), None)
        if section is None:
            raise ValueError(f"FDE start outside executable sections: {fde['start']:#x}")
        fde['section'] = section['name']
        counts['extent_crosses_section_end'] += fde['end'] > section['address'] + section['size']
        counts['zero_length'] += fde['end'] == fde['start']
        if fde['lsda'] is not None:
            counts['with_lsda'] += 1
            if except_table is None or not except_table['address'] <= fde['lsda'] < except_table['address'] + except_table['size']:
                counts['lsda_outside_gcc_except_table'] += 1
        if 'index' in fde:
            counts['end_equals_next_index_upper_bound'] += fde['end'] == fde['next_index_upper_bound']
            counts['end_exceeds_next_index_upper_bound'] += fde['end'] > fde['next_index_upper_bound']
    ordered = sorted(fdes, key=lambda f: (f['start'], f['end'], f['fde']))
    for previous, current in zip(ordered, ordered[1:]):
        counts['duplicate_start'] += current['start'] == previous['start']
    # Sweep each section with the running covered end, so nested or overlapping
    # extents never produce a false gap or double-counted coverage.
    gaps, gap_counts, covered = [], collections.Counter(), collections.Counter()
    edges = {}
    for section in executable:
        name, lower, upper = section['name'], section['address'], section['address'] + section['size']
        inside = [f for f in ordered if f['section'] == name]
        reach = None  # Running maximum covered end within this section.
        for fde in inside:
            if reach is None:
                reach = fde['start']
            elif fde['start'] < reach:
                counts['starts_inside_earlier_extent'] += 1
            elif fde['start'] > reach:
                int3 = is_int3_fill(data, section, reach, fde['start'])
                gaps.append({'start': reach, 'end': fde['start'], 'section': name, 'int3_only': int3})
                kind = 'int3_only' if int3 else 'other_bytes'
                gap_counts[f'{kind}_gaps'] += 1
                gap_counts[f'{kind}_bytes'] += fde['start'] - reach
            end = min(fde['end'], upper)
            covered[name] += max(0, end - max(fde['start'], reach))
            reach = max(reach, end)
        edges[name] = ((inside[0]['start'] - lower, upper - reach) if inside else (section['size'], 0))
    summary = {
        'binary_sha256': hashlib.sha256(data).hexdigest(),
        'cie_records': len(cies),
        'cie_augmentations': dict(sorted(collections.Counter(c['augmentation'] for c in cies.values()).items())),
        'fde_records': len(fdes),
        'unwind_table_entries': len(table),
        'fde_records_not_in_unwind_table': len(fdes) - len(referenced),
        'unwind_start_differs_from_fde_start': start_mismatch,
        'unique_fde_starts': len({f['start'] for f in fdes}),
        **{k: counts[k] for k in ['duplicate_start', 'zero_length', 'starts_inside_earlier_extent', 'extent_crosses_section_end',
                                  'end_equals_next_index_upper_bound', 'end_exceeds_next_index_upper_bound',
                                  'with_lsda', 'lsda_outside_gcc_except_table']},
        'same_section_gaps': {k: gap_counts[k] for k in ['int3_only_gaps', 'int3_only_bytes', 'other_bytes_gaps', 'other_bytes_bytes']},
        'executable_sections': {s['name']: {'section_bytes': s['size'], 'fde_covered_bytes': covered[s['name']],
                                            'bytes_before_first_fde': edges[s['name']][0],
                                            'bytes_after_last_fde': edges[s['name']][1]}
                                for s in executable},
        'limitations': LIMITATIONS,
    }
    return summary, ordered, gaps


def generate(binary, prefix):
    summary, ordered, gaps = fde_extents(binary.read_bytes())
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with prefix.with_suffix('.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['start_va', 'end_va', 'size', 'section', 'fde_va', 'cie_va', 'lsda_va', 'unwind_index'])
        for f in ordered:
            writer.writerow([hex(f['start']), hex(f['end']), f['end'] - f['start'], f['section'], hex(f['fde']),
                             hex(f['cie']), '' if f['lsda'] is None else hex(f['lsda']), f.get('index', '')])
    with prefix.with_name(prefix.name + '-gaps.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['start_va', 'end_va', 'size', 'section', 'int3_only'])
        for g in gaps:
            writer.writerow([hex(g['start']), hex(g['end']), g['end'] - g['start'], g['section'], str(g['int3_only']).lower()])
    prefix.with_suffix('.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release', choices=['94', '115'], required=True)
    p.add_argument('--output-dir', type=Path, default=ROOT / 'work/index')
    args = p.parse_args()
    from artifacts import check, manifest_item
    rel = f'artifacts/node/{args.release}/hl-node'
    item = manifest_item(ROOT, rel)
    check(ROOT / rel, item)
    summary = generate(ROOT / rel, args.output_dir / f'node-{args.release}-fde')
    expected = json.loads((ROOT / f'research/imported/hl-node-{args.release}.inventory.json').read_text())['fde_count_eh_frame_hdr']
    if summary['unwind_table_entries'] != expected:
        raise ValueError('Parsed unwind count differs from retained inventory')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
