#!/usr/bin/env python3
"""Statically map two entry candidates in node #94's unwindless 0x5631543 gap.

This is a digest-specific boundary observation, not a recovered source-function
or behavior claim. GNU objdump reads a 2,418-byte scratch slice; no target runs.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
LOWER, UPPER = 0x5631580, 0x5631ef2
ENTRY_MARKER = bytes.fromhex('f30f1efa')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def span(data, secs, start, end):
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 4
               and s['address'] <= start < end <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('Window lacks one file-backed executable mapping')
    section = matches[0]
    offset = section['offset'] + start - section['address']
    return bytes(data[offset:offset + end - start]), offset


def parse_disassembly(text, code, base):
    """Require a complete, byte-exact native decode of the selected slice."""
    rows, cursor = [], base
    for line in text.splitlines():
        parts = line.split('\t', 2)
        if len(parts) != 3 or not re.fullmatch(r'\s*[0-9a-f]+:', parts[0]):
            continue
        address = int(parts[0].strip()[:-1], 16)
        encoded = bytes.fromhex(parts[1])
        assembly = parts[2].strip()
        if address != cursor or not 1 <= len(encoded) <= 15:
            raise ValueError('Native decode is not contiguous')
        if encoded != code[address - base:address - base + len(encoded)]:
            raise ValueError('Native decode bytes differ from input')
        if '(bad)' in assembly or assembly.startswith('.byte'):
            raise ValueError('Native decoder did not accept an instruction')
        rows.append({'va': address, 'bytes': encoded.hex(), 'size': len(encoded),
                     'assembly': assembly})
        cursor += len(encoded)
    if cursor != base + len(code):
        raise ValueError('Native decode does not cover the complete slice')
    return rows


def decode(code, base, objdump='objdump'):
    # A fixed relative name keeps the retained native output free of temp paths.
    with tempfile.TemporaryDirectory(prefix='hl-gap-decode-') as temporary:
        directory = Path(temporary)
        (directory / 'slice.bin').write_bytes(code)
        argv = [objdump, '-D', '-b', 'binary', '-m', 'i386:x86-64', '-w', '-Mintel',
                '--adjust-vma=' + hex(base), 'slice.bin']
        result = subprocess.run(argv, cwd=directory, capture_output=True,
                                text=True, encoding='utf-8', check=True)
    return parse_disassembly(result.stdout, code, base), result.stdout, argv


def branch_target(row):
    """Resolve the direct branch from its bytes, independently of printed labels."""
    raw = bytes.fromhex(row['bytes'])
    if raw[0] in (0xe9, 0xeb):
        width, displacement = (5, struct.unpack_from('<i', raw, 1)[0]) if raw[0] == 0xe9 else (2, struct.unpack_from('<b', raw, 1)[0])
    elif 0x70 <= raw[0] <= 0x7f:
        width, displacement = 2, struct.unpack_from('<b', raw, 1)[0]
    elif raw[0] == 0x0f and len(raw) >= 2 and 0x80 <= raw[1] <= 0x8f:
        width, displacement = 6, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('Unexpected direct-branch encoding')
    if len(raw) != width:
        raise ValueError('Unexpected direct-branch width')
    target = row['va'] + width + displacement
    printed = row['assembly'].split()[1]
    if int(printed, 16) != target:
        raise ValueError('Native branch target disagrees with encoded displacement')
    return target


def candidate_graphs(rows, lower, upper):
    starts = {r['va']: r for r in rows}
    entries = [r['va'] for r in rows if r['bytes'] == ENTRY_MARKER.hex()]
    if entries != [LOWER, 0x56319fd] or (lower, upper) != (LOWER, UPPER):
        raise ValueError('Observed entry-marker partition changed')
    graphs = []
    for entry, end in zip(entries, entries[1:] + [upper]):
        local = [r for r in rows if entry <= r['va'] < end]
        successors, branches, returns = {}, [], []
        for row in local:
            at, following = row['va'], row['va'] + row['size']
            mnemonic = row['assembly'].split()[0]
            if mnemonic == 'ret':
                if row['bytes'] != 'c3':
                    raise ValueError('Unexpected return encoding')
                returns.append(at)
                targets = []
            elif mnemonic.startswith('j'):
                target = branch_target(row)
                targets = [target] if mnemonic == 'jmp' else [target, following]
                branches.append({'va': at, 'target': target,
                                 'conditional': mnemonic != 'jmp'})
            elif mnemonic.startswith(('call', 'loop')) or mnemonic in ('ud2', 'hlt', 'int3'):
                raise ValueError('Unresolved control transfer in candidate span')
            else:
                targets = [following]
            if any(target not in starts or not entry <= target < end for target in targets):
                raise ValueError('Branch/fallthrough target is not a local instruction start')
            successors[at] = targets
        reached, pending = set(), [entry]
        while pending:
            at = pending.pop()
            if at not in reached:
                reached.add(at)
                pending.extend(successors[at])
        if reached != set(successors):
            raise ValueError('Candidate contains instructions unreachable in its static CFG')
        if returns != [end - 1]:
            raise ValueError('Candidate return does not close the observed partition')
        leaders = {entry}
        for branch in branches:
            leaders.add(branch['target'])
            if branch['conditional']:
                row = starts[branch['va']]
                leaders.add(row['va'] + row['size'])
        blocks = []
        for begin, finish in zip(sorted(leaders), sorted(leaders)[1:] + [end]):
            members = [r for r in local if begin <= r['va'] < finish]
            blocks.append({'start': begin, 'end': finish, 'instructions': len(members),
                           'successors': successors[members[-1]['va']]})
        graphs.append({'entry': entry, 'end': end, 'bytes': end - entry,
                       'instructions': len(local), 'statically_reachable_instructions': len(reached),
                       'sha256': sha(b''.join(bytes.fromhex(r['bytes']) for r in local)),
                       'returns': returns, 'branches': branches, 'basic_blocks': blocks})
    return graphs


def inspect_target(binary, objdump='objdump'):
    with binary.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if sha(data) != DIGEST:
            raise ValueError('Node #94 SHA-256 mismatch')
        secs = sections(data)
        _, fdes = eh_frame_records(data, secs)
        if any(f['start'] < UPPER and LOWER < f['end'] for f in fdes):
            raise ValueError('An FDE overlaps the selected window')
        previous = max((f for f in fdes if f['end'] <= LOWER), key=lambda f: f['end'])
        following = min((f for f in fdes if f['start'] >= UPPER), key=lambda f: f['start'])
        frame = next(s for s in secs if s['name'] == '.eh_frame')
        records = []
        for address in sorted({previous['fde'], following['fde'], previous['cie'], following['cie']}):
            offset = frame['offset'] + address - frame['address']
            length = struct.unpack_from('<I', data, offset)[0] + 4
            encoded = bytes(data[offset:offset + length])
            records.append({'va': address, 'file_offset': offset, 'bytes': length,
                            'sha256': sha(encoded), 'hex': encoded.hex()})
        gap, gap_offset = span(data, secs, previous['end'], following['start'])
        code, code_offset = span(data, secs, LOWER, UPPER)
        prefix, suffix = gap[:LOWER - previous['end']], gap[UPPER - previous['end']:]
        if not prefix or not suffix or any(x != 0xcc for x in prefix + suffix):
            raise ValueError('Observed surrounding int3 fill changed')
        rows, raw, argv = decode(code, LOWER, objdump)
        graphs = candidate_graphs(rows, LOWER, UPPER)
        relocations, relocation_count = [], 0
        for section in secs:
            if section['type'] != 4:
                continue
            if section['size'] % 24:
                raise ValueError('Unexpected ELF64 RELA table width')
            for offset in range(section['offset'], section['offset'] + section['size'], 24):
                place, info, addend = struct.unpack_from('<QQq', data, offset)
                relocation_count += 1
                if LOWER <= place < UPPER or info & 0xffffffff == 8 and LOWER <= addend < UPPER:
                    relocations.append({'table': section['name'], 'place': place,
                                        'type': info & 0xffffffff, 'symbol': info >> 32,
                                        'addend': addend})
        references, scanned = [], 0
        pattern = re.compile(b'[\xe8\xe9]')
        entries = {graph['entry'] for graph in graphs}
        for section in secs:
            if section['type'] == 8 or not section['flags'] & 4:
                continue
            for match in pattern.finditer(data, section['offset'], section['offset'] + section['size'] - 4):
                offset = match.start()
                at = section['address'] + offset - section['offset']
                target = at + 5 + struct.unpack_from('<i', data, offset + 1)[0]
                scanned += 1
                if target in entries:
                    references.append({'va': at, 'target': target, 'instruction_validated': False})
        version = subprocess.run([objdump, '--version'], check=True, capture_output=True,
                                 text=True, encoding='utf-8').stdout.splitlines()[0]
        report = {'target_sha256': DIGEST, 'target_bytes': len(data),
                  'coordinates': 'linked ELF virtual addresses; file offsets recorded separately',
                  'window': {'start': LOWER, 'end': UPPER, 'file_offset': code_offset,
                             'bytes': len(code), 'sha256': sha(code)},
                  'gap': {'start': previous['end'], 'end': following['start'],
                          'file_offset': gap_offset, 'bytes': len(gap), 'sha256': sha(gap),
                          'leading_int3_bytes': len(prefix), 'trailing_int3_bytes': len(suffix)},
                  'fde_records_examined': len(fdes), 'overlapping_fdes': 0,
                  'previous_fde': previous, 'following_fde': following,
                  'neighbor_fde_cie_records': records,
                  'analysis_source_sha256': sha(Path(__file__).read_bytes()),
                  'parser_source_sha256': {name: sha((ROOT / 'tools' / name).read_bytes())
                                           for name in ('elf_index.py', 'fde_extents.py')},
                  'native_decoder': version, 'decoder_argv': argv,
                  'decoded_instructions': len(rows), 'candidates': graphs,
                  'decoded_calls': [], 'decoded_rip_relative_operands': [r['va'] for r in rows if 'rip' in r['assembly']],
                  'elf_rela_records_examined': relocation_count, 'selected_relocations': relocations,
                  'entry_rel32_byte_candidates_examined': scanned,
                  'entry_rel32_byte_candidates': references,
                  'limitations': [
                      'ENDBR64, RET, local CFG reachability and FDE absence identify boundary candidates, not original Rust source functions.',
                      'Static reachability overapproximates feasible paths; arithmetic, memory safety, ABI and behavior are unresolved.',
                      'Raw E8/E9 matches are byte candidates, not decoded incoming calls; zero matches do not prove absence of indirect callers.',
                      'No whole-node instruction decode, indirect reference closure, source ownership, Rust implementation or acceptance gate is claimed.',
                      'Only RELA records and relative addends into this window are classified; arbitrary data words and register-derived references remain unresolved.',
                  ]}
    return report, rows, raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'work/node94-gap-boundaries')
    parser.add_argument('--objdump', default='objdump')
    args = parser.parse_args()
    report, rows, raw = inspect_target(ROOT / 'artifacts/node/94/hl-node', args.objdump)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    (args.output_dir / 'instructions.json').write_text(json.dumps(rows, indent=2) + '\n', encoding='utf-8', newline='\n')
    (args.output_dir / 'native.objdump').write_text(raw, encoding='utf-8', newline='\n')
    print(json.dumps({'output': str(args.output_dir), 'target_sha256': DIGEST,
                      'boundary_candidates': len(report['candidates']), 'decoded_instructions': len(rows)}))


if __name__ == '__main__':
    main()
