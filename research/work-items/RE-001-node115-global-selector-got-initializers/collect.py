#!/usr/bin/env python3
"""Collect static #115 evidence for two fixed global-selector GOT slots."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SLOTS = (0x64dfff8, 0x64e0000)
OBJECTS = (0x64efc80, 0x64efcb0)
MEMCMP_SLOT = 0x64dfb50
CALLBACKS = (
    {'object': 0x64efc80, 'target': 0x14c4570, 'end': 0x14c4741,
     'call_register': 'rbp', 'expected_compares': 1, 'stride_register': 'r13'},
    {'object': 0x64efcb0, 'target': 0x14c4020, 'end': 0x14c4567,
     'call_register': 'r15', 'expected_compares': 4, 'stride_register': 'r12'},
)
TARGET = ROOT / 'artifacts/node/115/hl-node'


def require(value, message):
    if not value:
        raise ValueError(message)


def file_bytes(data, secs, address, size):
    matches = [s for s in secs if s['type'] != 8 and
               s['address'] <= address <= address + size <= s['address'] + s['size']]
    require(len(matches) == 1, f'ambiguous or absent file mapping at {address:#x}')
    section = matches[0]
    offset = section['offset'] + address - section['address']
    return bytes(data[offset:offset + size])


def parse_relocations(data, secs):
    relasec = next((s for s in secs if s['name'] == '.rela.dyn'), None)
    require(relasec is not None and relasec['size'] % 24 == 0, 'invalid .rela.dyn')
    rows = {}
    raw = data[relasec['offset']:relasec['offset'] + relasec['size']]
    for offset, info, addend in struct.iter_unpack('<QQq', raw):
        require(offset not in rows, f'duplicate relocation at {offset:#x}')
        rows[offset] = (info, addend)
    return rows


def parse_xrefs(text, fdes, slots=SLOTS, scope=None):
    by_site = {}
    for line in text.splitlines():
        if not any(f'# {slot:x} ' in line for slot in slots):
            continue
        match = re.match(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.+)$', line)
        require(match is not None, 'unparsed direct reference instruction')
        site = int(match.group(1), 16)
        if scope is not None and not any(start <= site < end for start, end in scope):
            continue
        code = bytes.fromhex(match.group(2))
        instruction = match.group(3).strip()
        require(len(code) == 7 and code[:2] == b'\x48\x8b' or
                len(code) == 7 and code[:2] == b'\x4c\x8b', 'reference is not a 64-bit RIP-relative load')
        slot = site + len(code) + struct.unpack('<i', code[-4:])[0]
        require(slot in slots, 'disassembly target disagrees with encoded displacement')
        require(re.match(r'mov\s+\w+,QWORD PTR \[rip\+', instruction) is not None,
                'reference is not a direct load')
        owners = [f for f in fdes if f['start'] <= site < f['end']]
        require(len(owners) == 1, f'expected one FDE for {site:#x}')
        row = {'site': hex(site), 'slot': hex(slot), 'instruction_bytes': code.hex(),
               'instruction': instruction.split('  #', 1)[0].strip(),
               'fde_start': hex(owners[0]['start']), 'fde_end': hex(owners[0]['end'])}
        require(site not in by_site, f'duplicate xref at {site:#x}')
        by_site[site] = row
    return [by_site[site] for site in sorted(by_site)]


def collect(image, output):
    digest = hashlib.sha256(image).hexdigest()
    require(digest == SHA, 'node115 identity mismatch')
    secs = sections(image)
    by_name = {s['name']: s for s in secs}
    require(by_name['.got']['address'] <= min(SLOTS) and
            max(SLOTS) + 8 <= by_name['.got']['address'] + by_name['.got']['size'],
            'selector slots are not both in .got')
    require(all(by_name['.data']['address'] <= va < by_name['.data']['address'] + by_name['.data']['size']
                for va in OBJECTS), 'referenced objects are not in .data')

    relocations = parse_relocations(image, secs)
    bindings = []
    for slot, object_va in zip(SLOTS, OBJECTS):
        info, addend = relocations.get(slot, (None, None))
        require(info == 8 and addend == object_va, f'GOT relocation mismatch at {slot:#x}')
        bindings.append({'slot': hex(slot), 'relocation_type': 'R_X86_64_RELATIVE',
                         'addend': hex(addend), 'target_object': hex(object_va),
                         'object_file_bytes': file_bytes(image, secs, object_va, 48).hex()})
    object_relocations = []
    for va, code_target in zip(OBJECTS, (0x14c4570, 0x14c4020)):
        info, addend = relocations.get(va, (None, None))
        require(info == 8 and addend == code_target, f'object first-word relocation mismatch at {va:#x}')
        object_relocations.append({'slot': hex(va), 'relocation_type': 'R_X86_64_RELATIVE',
                                   'addend': hex(addend)})

    objdump, readelf = shutil.which('objdump'), shutil.which('readelf')
    require(objdump is not None and readelf is not None, 'GNU objdump and readelf are required')
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C'}
    version = subprocess.check_output([objdump, '--version'], text=True, env=env).splitlines()[0]
    readelf_version = subprocess.check_output([readelf, '--version'], text=True, env=env).splitlines()[0]
    require('GNU' in version, 'GNU objdump is required')
    require('GNU' in readelf_version, 'GNU readelf is required')
    _, fdes, _ = fde_extents(image)
    indexed_fdes = {}
    for frame in fdes:
        key = frame['start'], frame['end']
        require(key not in indexed_fdes, 'duplicate FDE extent')
        indexed_fdes[key] = frame
    callback_ranges = []
    callback_bodies = []
    for callback in CALLBACKS:
        frames = [f for f in fdes if f['start'] == callback['target']]
        require(len(frames) == 1 and frames[0]['end'] == callback['end'],
                f"callback FDE changed at {callback['target']:#x}")
        frame = frames[0]
        callback_ranges.append((frame['start'], frame['end']))
        body = file_bytes(image, secs, frame['start'], frame['end'] - frame['start'])
        callback_bodies.append((callback, frame, body))
    with __import__('tempfile').TemporaryDirectory(prefix='node115-selector-static-') as tmp:
        binary = Path(tmp) / 'node115.elf'
        binary.write_bytes(image)
        binary.chmod(0o400)
        disassembly = subprocess.check_output([objdump, '-d', '-w', '-Mintel', str(binary)], text=True, env=env)
        callback_exports = {}
        for callback, frame, body in callback_bodies:
            raw = subprocess.check_output([objdump, '-d', '-w', '-Mintel',
                f"--start-address={frame['start']}", f"--stop-address={frame['end']}", str(binary)],
                text=True, env=env).replace(str(binary), 'artifacts/node/115/hl-node')
            raw = '\n'.join(line.rstrip() for line in raw.splitlines()) + '\n'
            decoded = decode_export(raw, frame['start'], frame['end'], body)
            rows = []
            for line in raw.splitlines():
                match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)(.*)$', line)
                if match and match[3].strip():
                    rows.append((int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()))
            calls = [(va, code) for va, code, text in rows
                     if re.search(rf'\bcall\s+{callback["call_register"]}\b', text)]
            lengths = [(va, code) for va, code, text in rows
                       if re.search(r'\bmov\s+edx,0x14\b', text)]
            strides = [(va, code) for va, code, text in rows
                       if re.search(rf'\badd\s+{callback["stride_register"]},0x14\b', text)]
            signs = [(va, code) for va, code, text in rows
                     if re.search(r'\bsets\s+cl\b|\bsetg\s+al\b|\bsub\s+al,cl\b', text)]
            require(len(calls) == callback['expected_compares'], 'comparison call count changed')
            require(len(lengths) == callback['expected_compares'], '20-byte compare length count changed')
            require(len(strides) == callback['expected_compares'], '20-byte loop stride count changed')
            require(len(signs) == callback['expected_compares'] * 3, 'comparison sign conversion changed')
            callback_exports[frame['start']] = (raw, decoded, rows, calls, lengths, strides, signs)
        native_relocations = subprocess.check_output([readelf, '-rW', str(binary)], text=True, env=env)

    xrefs = parse_xrefs(disassembly, fdes)
    require(len(xrefs) == 36, 'selector xref census changed')
    counts = {hex(slot): sum(row['slot'] == hex(slot) for row in xrefs) for slot in SLOTS}
    require(counts == {'0x64dfff8': 18, '0x64e0000': 18}, 'selector xref counts changed')
    memcmp_rows = parse_xrefs(disassembly, fdes, (MEMCMP_SLOT,), callback_ranges)
    require(len(memcmp_rows) == 5, 'callback memcmp GOT load count changed')
    memcmp_relocs = [line.split() for line in native_relocations.splitlines()
                     if re.match(r'^[0-9a-f]+\s', line) and int(line.split()[0], 16) == MEMCMP_SLOT]
    require(len(memcmp_relocs) == 1 and len(memcmp_relocs[0]) >= 5 and
            memcmp_relocs[0][2] == 'R_X86_64_GLOB_DAT' and
            memcmp_relocs[0][4] == 'memcmp@GLIBC_2.2.5', 'memcmp import relocation changed')
    output.mkdir(parents=True, exist_ok=True)
    callback_records = []
    for callback, frame, body in callback_bodies:
        raw, decoded, rows, calls, lengths, strides, signs = callback_exports[frame['start']]
        selected_refs = [row for row in memcmp_rows if row['fde_start'] == hex(frame['start'])]
        require(len(selected_refs) == callback['expected_compares'], 'callback memcmp load count mismatch')
        output_name = f'{frame["start"]:x}.objdump.txt'
        callback_records.append({
            'data_object': hex(callback['object']), 'target': hex(callback['target']),
            'fde': {'start': hex(frame['start']), 'end': hex(frame['end']),
                    'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                    'lsda': None if frame['lsda'] is None else hex(frame['lsda'])},
            'memcmp_slot': hex(MEMCMP_SLOT), 'memcmp_import': 'memcmp@GLIBC_2.2.5',
            'direct_memcmp_loads': [row['site'] for row in selected_refs],
            'indirect_compare_calls': [hex(va) for va, _ in calls],
            'length_20_setup_sites': [hex(va) for va, _ in lengths],
            'stride_20_sites': [hex(va) for va, _ in strides],
            'sign_zero_conversion_sites': [hex(va) for va, _ in signs],
            'decoded_instruction_count': len(decoded), 'disassembly_file': output_name,
        })
        (output / output_name).write_text(raw)
    (output / 'memcmp-relocation.txt').write_text('\n'.join(' '.join(row) for row in memcmp_relocs) + '\n')
    record = {
        'target': 'Linux x86-64 node #115', 'target_sha256': digest,
        'scope': 'Two fixed selector GOT slots: RELA initialization, pointed-to objects, the two code targets, and direct references.',
        'method': 'Independent ELF section/RELA parsing, FDE extent decoding, GNU objdump byte exports, and GNU readelf import cross-check; static only.',
        'got_bindings': bindings, 'object_first_word_relocations': object_relocations,
        'callback_targets': callback_records,
        'direct_reference_counts': counts, 'direct_references': xrefs,
        'unique_fde_extents': [list(extent) for extent in
                               sorted({(row['fde_start'], row['fde_end']) for row in xrefs})],
        'limitations': [
            'FDE ranges are unwind extents, not proven function boundaries.',
            'The inventory is limited to directly encoded RIP-relative references visible in disassembly.',
            'No source-level names, runtime selection policy, dynamic pointer writes, or object semantics are inferred.',
            'The two relocated code targets make 20-byte memcmp calls in 0x14-stride loops; no source-level type, comparator owner, or object meaning is assigned.',
            'No target code is executed or emulated.'
        ]
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / 'records.json').write_text(json.dumps(record, indent=2) + '\n')
    (output / 'xref-instructions.txt').write_text('\n'.join(
        f"{row['site']} {row['instruction_bytes']} {row['instruction']} -> {row['slot']} FDE {row['fde_start']}..{row['fde_end']}"
        for row in xrefs) + '\n')
    (output / 'tool-versions.json').write_text(json.dumps({'objdump': version, 'readelf': readelf_version}, indent=2) + '\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', type=Path, default=TARGET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = collect(args.image.read_bytes(), args.output)
    if args.check:
        require(result == json.loads((PACKET / 'records.json').read_text()), 'retained record changed')
    print(json.dumps({'target_sha256': result['target_sha256'],
                      'direct_references': len(result['direct_references']),
                      'callback_targets': len(result['callback_targets']),
                      'unique_fde_extents': len(result['unique_fde_extents']),
                      'target_executed': False, 'record_check': args.check}))
