#!/usr/bin/env python3
"""Static node94 leaf boundary and one caller/RELA/data binding; no target execution."""
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
START, END = 0x54aa940, 0x54aaaf9
CALL, SLOT = 0x14f92e3, 0x5770088


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mapped(data, secs, address, size, *, executable=False, readonly=False):
    choices = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and s['address'] <= address < address + size <= s['address'] + s['size']]
    if len(choices) != 1:
        raise ValueError('Reference lacks one allocated file-backed mapping')
    section = choices[0]
    if executable and not section['flags'] & 4:
        raise ValueError('Selected code mapping is not executable')
    if readonly and section['flags'] & (1 | 4):
        raise ValueError('Constant reference is not readonly non-code data')
    offset = section['offset'] + address - section['address']
    raw = bytes(data[offset:offset + size])
    return {'va': address, 'file_offset': offset, 'section': section['name'],
            'bytes': size, 'hex': raw.hex(), 'sha256': sha(raw)}


def parse_native(text, code, base):
    rows, cursor = [], base
    for line in text.splitlines():
        parts = line.split('\t', 2)
        if len(parts) != 3 or not re.fullmatch(r'\s*[0-9a-f]+:', parts[0]):
            continue
        address, encoded = int(parts[0].strip()[:-1], 16), bytes.fromhex(parts[1])
        assembly = parts[2].strip()
        if address != cursor or not 1 <= len(encoded) <= 15:
            raise ValueError('Native decode is not contiguous')
        if encoded != code[address - base:address - base + len(encoded)]:
            raise ValueError('Native bytes do not match selected input')
        if '(bad)' in assembly or assembly.startswith('.byte'):
            raise ValueError('Native decoder rejected an instruction')
        rows.append({'va': address, 'size': len(encoded), 'hex': encoded.hex(), 'assembly': assembly})
        cursor += len(encoded)
    if cursor != base + len(code):
        raise ValueError('Native decode is incomplete')
    return rows


def native(code, base, objdump='objdump'):
    with tempfile.TemporaryDirectory(prefix='hl-relocated-leaf-') as temporary:
        directory = Path(temporary)
        (directory / 'selected.bin').write_bytes(code)
        argv = [objdump, '-D', '-b', 'binary', '-m', 'i386:x86-64', '-w', '-Mintel',
                '--adjust-vma=' + hex(base), 'selected.bin']
        result = subprocess.run(argv, cwd=directory, capture_output=True,
                                text=True, encoding='utf-8', check=True)
    return parse_native(result.stdout, code, base), result.stdout


def leaf_graph(rows):
    if rows[0]['va'] != START or rows[0]['hex'] != 'f30f1efa':
        raise ValueError('Selected candidate lacks its observed entry marker')
    starts = {r['va'] for r in rows}
    edges, branches, returns = {}, [], []
    for row in rows:
        at, after, raw = row['va'], row['va'] + row['size'], bytes.fromhex(row['hex'])
        mnemonic = row['assembly'].split()[0]
        if mnemonic == 'ret':
            if raw != b'\xc3':
                raise ValueError('Unexpected return encoding')
            targets = []
            returns.append(at)
        elif mnemonic in ('je', 'jmp'):
            if raw[0] == 0x74 and len(raw) == 2:
                target = after + struct.unpack_from('<b', raw, 1)[0]
            elif raw[0] == 0xe9 and len(raw) == 5:
                target = after + struct.unpack_from('<i', raw, 1)[0]
            else:
                raise ValueError('Unexpected selected direct-branch encoding')
            if int(row['assembly'].split()[1], 16) != target:
                raise ValueError('Native branch text disagrees with its encoded displacement')
            targets = [target] if mnemonic == 'jmp' else [target, after]
            branches.append({'va': at, 'target': target, 'conditional': mnemonic != 'jmp'})
        elif mnemonic.startswith(('j', 'call', 'loop')) or mnemonic in ('ud2', 'hlt', 'int3'):
            raise ValueError('Unresolved control transfer in selected candidate')
        else:
            targets = [after]
        if any(t not in starts or not START <= t < END for t in targets):
            raise ValueError('Local edge does not land on an instruction start')
        edges[at] = targets
    reached, pending = set(), [START]
    while pending:
        at = pending.pop()
        if at not in reached:
            reached.add(at)
            pending.extend(edges[at])
    if reached != starts or returns != [END - 1]:
        raise ValueError('Candidate CFG does not close at its observed return')
    leaders = {START}
    for branch in branches:
        leaders.add(branch['target'])
        if branch['conditional']:
            row = next(r for r in rows if r['va'] == branch['va'])
            leaders.add(row['va'] + row['size'])
    blocks = []
    for first, last in zip(sorted(leaders), sorted(leaders)[1:] + [END]):
        members = [r for r in rows if first <= r['va'] < last]
        blocks.append({'start': first, 'end': last, 'instructions': len(members),
                       'successors': edges[members[-1]['va']]})
    return {'start': START, 'end': END, 'native_instructions': len(rows),
            'statically_reachable_instructions': len(reached), 'branches': branches,
            'returns': returns, 'blocks': blocks}


def native_comment_target(row):
    match = re.search(r'#\s*(?:0x)?([0-9a-fA-F]+)(?:\s|$)', row['assembly'])
    if not match:
        raise ValueError('Missing native RIP target annotation')
    return int(match.group(1), 16)


def incoming_call(rows):
    selected = [r for r in rows if r['va'] == CALL]
    if len(selected) != 1:
        raise ValueError('Selected call is not a native instruction start')
    row = selected[0]
    raw = bytes.fromhex(row['hex'])
    if len(raw) != 6 or raw[:2] != b'\xff\x15' or not row['assembly'].startswith('call '):
        raise ValueError('Selected incoming instruction is not the observed RIP-indirect call')
    target = CALL + 6 + struct.unpack_from('<i', raw, 2)[0]
    if target != SLOT or native_comment_target(row) != target:
        raise ValueError('Selected encoded call does not name the selected slot')
    return {'call_va': CALL, 'instruction_hex': raw.hex(), 'slot_va': target}


def relative_binding(raw):
    if len(raw) != 24:
        raise ValueError('Selected RELA record has the wrong width')
    place, info, addend = struct.unpack('<QQq', raw)
    if place != SLOT or info != 8 or addend != START:
        raise ValueError('Selected RELATIVE relocation does not bind slot to entry')
    return {'place': place, 'type': info & 0xffffffff, 'symbol_index': info >> 32,
            'addend': addend, 'hex': raw.hex(), 'sha256': sha(raw)}


def constants(rows, data, secs):
    result = []
    for row in rows:
        if 'rip' not in row['assembly']:
            continue
        raw = bytes.fromhex(row['hex'])
        start = 1 if 0x40 <= raw[0] <= 0x4f else 0
        if raw[start:start + 2] != b'\x0f\x28' or raw[start + 2] & 0xc7 != 5 or len(raw) != start + 7:
            raise ValueError('Unexpected selected RIP-relative data encoding')
        target = row['va'] + row['size'] + struct.unpack_from('<i', raw, len(raw) - 4)[0]
        if native_comment_target(row) != target:
            raise ValueError('Native data target disagrees with encoded displacement')
        result.append({'instruction_va': row['va'], **mapped(data, secs, target, 16, readonly=True)})
    if len(result) != 3 or len({r['va'] for r in result}) != 3:
        raise ValueError('Selected candidate does not have three distinct constant references')
    return result


def inspect(binary, objdump='objdump'):
    with binary.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if sha(data) != DIGEST:
            raise ValueError('Node94 digest mismatch')
        secs = sections(data)
        _, fdes = eh_frame_records(data, secs)
        if any(f['start'] < END and START < f['end'] for f in fdes):
            raise ValueError('An FDE intersects the selected unwindless candidate')
        owners = [f for f in fdes if f['start'] <= CALL < f['end']]
        if len(owners) != 1 or not CALL + 6 <= owners[0]['end']:
            raise ValueError('Selected call lacks one containing FDE')
        owner = owners[0]
        frame = next(s for s in secs if s['name'] == '.eh_frame')
        frame_records = []
        for address in sorted({owner['fde'], owner['cie']}):
            offset = frame['offset'] + address - frame['address']
            size = 4 + struct.unpack_from('<I', data, offset)[0]
            raw_record = bytes(data[offset:offset + size])
            frame_records.append({'va': address, 'file_offset': offset, 'bytes': size,
                                  'hex': raw_record.hex(), 'sha256': sha(raw_record)})
        leaf = mapped(data, secs, START, END - START, executable=True)
        prefix = mapped(data, secs, owner['start'], CALL + 6 - owner['start'], executable=True)
        leaf_rows, leaf_native = native(bytes.fromhex(leaf['hex']), START, objdump)
        prefix_rows, prefix_native = native(bytes.fromhex(prefix['hex']), owner['start'], objdump)
        graph, call = leaf_graph(leaf_rows), incoming_call(prefix_rows)
        selected = []
        for section in secs:
            if section['type'] != 4:
                continue
            if section['size'] % 24:
                raise ValueError('Unexpected RELA table width')
            for offset in range(section['offset'], section['offset'] + section['size'], 24):
                if struct.unpack_from('<Q', data, offset)[0] == SLOT:
                    selected.append({'table': section['name'], 'file_offset': offset,
                                     **relative_binding(bytes(data[offset:offset + 24]))})
        if len(selected) != 1:
            raise ValueError('Selected slot does not have exactly one RELATIVE record')
        refs = constants(leaf_rows, data, secs)
        # Only selected small spans/metadata are retained, not a full node snapshot.
        if sha(data) != DIGEST:
            raise ValueError('Node94 changed during selected evidence extraction')
        version = subprocess.run([objdump, '--version'], capture_output=True, text=True,
                                 encoding='utf-8', check=True).stdout.splitlines()[0]
        report = {'target_sha256': DIGEST, 'target_bytes': len(data),
                  'coordinates': 'linked ELF virtual addresses, not runtime ASLR addresses',
                  'candidate': leaf, 'candidate_cfg': graph, 'overlapping_fdes': 0,
                  'fde_records_examined': len(fdes), 'selected_incoming_edges': 1,
                  'selected_incoming_edge': call, 'caller_fde': owner,
                  'caller_fde_cie_records': frame_records,
                  'caller_decode_prefix': prefix, 'caller_prefix_instructions': len(prefix_rows),
                  'relocation': selected[0], 'slot_original_file_bytes': mapped(data, secs, SLOT, 8),
                  'constant_references': refs, 'constant_bytes': sum(r['bytes'] for r in refs),
                  'native_decoder': version,
                  'analysis_source_sha256': sha(Path(__file__).read_bytes()),
                  'parser_source_sha256': {p: sha((ROOT / 'tools' / p).read_bytes())
                                           for p in ('elf_index.py', 'fde_extents.py')},
                  'limitations': [
                      'This is one candidate CFG and one selected incoming instruction/relocation edge, not a source-function or complete-call-graph claim.',
                      'The containing caller is decoded only to establish instruction alignment; its selector, arguments, ABI and runtime path feasibility are not recovered.',
                      'ELF RELATIVE metadata associates the slot with load_bias+addend; runtime slot contents and actual dispatch are not observed.',
                      'Algorithm, original source names, Rust implementation, behavior, source ownership and progress gates remain unresolved.',
                  ]}
    return report, leaf_rows, prefix_rows, leaf_native, prefix_native


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'work/relocated-leaf-54aa940')
    parser.add_argument('--objdump', default='objdump')
    args = parser.parse_args()
    report, leaf, prefix, raw_leaf, raw_prefix = inspect(ROOT / 'artifacts/node/94/hl-node', args.objdump)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    for name, content in [('report.json', report), ('leaf-instructions.json', leaf), ('caller-prefix-instructions.json', prefix)]:
        (args.output_dir / name).write_text(json.dumps(content, indent=2) + '\n', encoding='utf-8', newline='\n')
    (args.output_dir / 'leaf.objdump').write_text(raw_leaf, encoding='utf-8', newline='\n')
    (args.output_dir / 'caller-prefix.objdump').write_text(raw_prefix, encoding='utf-8', newline='\n')
    print(json.dumps({'candidate_bytes': END - START, 'candidate_instructions': len(leaf),
                      'selected_incoming_edges': report['selected_incoming_edges'],
                      'constant_bytes': report['constant_bytes'], 'output': str(args.output_dir)}))


if __name__ == '__main__':
    main()
