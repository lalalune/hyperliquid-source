#!/usr/bin/env python3
"""Inventory node #94 CFI frame bases, without executing captured code."""
import argparse
from collections import Counter
import csv
import hashlib
from importlib.metadata import version
import io
import json
from pathlib import Path

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[3]
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280


def survey(path):
    data = path.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('Expected exact node #94 size and SHA-256')
    if version('pyelftools') != '0.32':
        raise ValueError('Reproduce with pyelftools 0.32')
    classes, prefixes, cross, samples = Counter(), Counter(), Counter(), {}
    raw = io.StringIO(newline='')
    writer = csv.writer(raw, delimiter='\t', lineterminator='\n')
    writer.writerow(['fde_offset', 'start_va', 'end_va', 'cfa_registers',
                     'cfa_expression', 'rbp_stack_recovery_rule', 'entry_prefix'])
    total = outside = 0
    elf = ELFFile(io.BytesIO(data))
    if elf['e_machine'] != 'EM_X86_64' or not elf.little_endian or elf.elfclass != 64:
        raise ValueError('Expected ELF64-LE x86-64')
    text = elf.get_section_by_name('.text')
    code = text.data()
    text_start, text_end = text['sh_addr'], text['sh_addr'] + len(code)
    frames = elf.get_section_by_name('.eh_frame').data()
    entries = elf.get_dwarf_info().EH_CFI_entries()
    for index in range(len(entries)):
        entry = entries[index]
        if not isinstance(entry, FDE):
            continue
        start, size = entry['initial_location'], entry['address_range']
        end = start + size
        if not text_start <= start < text_end:
            outside += 1
            entries[index] = None
            continue
        if end > text_end:
            raise ValueError('FDE extends beyond .text')
        total += 1
        rows = entry.get_decoded().table
        if any(not start <= row['pc'] <= end for row in rows):
            raise ValueError('Decoded CFI row outside FDE extent')
        registers = sorted({row['cfa'].reg for row in rows if row['cfa'].reg is not None})
        expression = any(row['cfa'].expr is not None for row in rows)
        rbp_stack = any(6 in row and row[6].type == 'OFFSET' for row in rows)
        key = ','.join(map(str, registers)) + ('+expression' if expression else '')
        prefix = code[start - text_start:start - text_start + min(size, 16)]
        prefix_kind = ('55-4889e5' if prefix.startswith(bytes.fromhex('554889e5'))
                       else '55-other' if prefix.startswith(b'\x55') else 'other')
        classes[key] += 1
        prefixes[prefix_kind] += 1
        cross[(key, prefix_kind, rbp_stack)] += 1
        writer.writerow([hex(entry.offset), hex(start), hex(end), key,
                         str(expression).lower(), str(rbp_stack).lower(), prefix_kind])
        sample_key = f'{key}/{prefix_kind}/rbp-stack-{str(rbp_stack).lower()}'
        if len(samples.setdefault(sample_key, [])) < 3:
            record_length = int.from_bytes(frames[entry.offset:entry.offset + 4], 'little')
            if record_length == 0xffffffff:
                raise ValueError('Unexpected extended record length')
            samples[sample_key].append({
                'start_va': hex(start), 'end_va': hex(end),
                'fde_section_offset': hex(entry.offset),
                'fde_hex': frames[entry.offset:entry.offset + 4 + record_length].hex(),
                'prefix_hex': prefix.hex(),
                'rows': [{'pc': hex(row['pc']), 'cfa_register': row['cfa'].reg,
                          'cfa_offset': row['cfa'].offset, 'cfa_expression': row['cfa'].expr,
                          'rbp_recovery': None if 6 not in row else {
                              'type': row[6].type, 'argument': row[6].arg}}
                         for row in rows],
            })
        entries[index] = None
    raw_bytes = raw.getvalue().encode('utf-8')
    result = {
        'schema': 'node94-cfi-frame-bases/v1', 'target_sha256': SHA256,
        'target_bytes': len(data), 'parser': 'pyelftools 0.32',
        'text_start_va': hex(text_start), 'text_end_va': hex(text_end),
        'text_fde_records': total, 'fdes_outside_text': outside,
        'cfa_register_sets': dict(sorted(classes.items())),
        'entry_prefixes': dict(sorted(prefixes.items())),
        'cross_counts': [{'cfa_register_set': key, 'entry_prefix': prefix,
                          'rbp_stack_recovery_rule': saved, 'records': count}
                         for (key, prefix, saved), count in sorted(cross.items())],
        'raw_tsv_sha256': hashlib.sha256(raw_bytes).hexdigest(),
        'samples': dict(sorted(samples.items())),
        'captured_binary_executed': False, 'progress_gate_requested': False,
    }
    return result, raw_bytes


def save_or_check(path, data):
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError(f'Refusing to overwrite different evidence: {path}')
    else:
        path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'work/frame-pointers-94')
    parser.add_argument('--check', type=Path)
    args = parser.parse_args()
    result, raw = survey(args.input)
    if args.check and result != json.loads(args.check.read_text(encoding='utf-8')):
        raise ValueError('Retained survey differs')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    save_or_check(args.output_dir / 'frames.tsv', raw)
    save_or_check(args.output_dir / 'summary.json',
                  (json.dumps(result, indent=2) + '\n').encode('utf-8'))
    print(json.dumps({key: value for key, value in result.items() if key != 'samples'}, indent=2))


if __name__ == '__main__':
    main()
