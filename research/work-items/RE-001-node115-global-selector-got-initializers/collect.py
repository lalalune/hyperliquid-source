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

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SLOTS = (0x64dfff8, 0x64e0000)
OBJECTS = (0x64efc80, 0x64efcb0)
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


def parse_xrefs(text, fdes):
    by_site = {}
    for line in text.splitlines():
        if not any(f'# {slot:x} ' in line for slot in SLOTS):
            continue
        match = re.match(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.+)$', line)
        require(match is not None, 'unparsed direct reference instruction')
        site = int(match.group(1), 16)
        code = bytes.fromhex(match.group(2))
        instruction = match.group(3).strip()
        require(len(code) == 7 and code[:2] == b'\x48\x8b' or
                len(code) == 7 and code[:2] == b'\x4c\x8b', 'reference is not a 64-bit RIP-relative load')
        slot = site + len(code) + struct.unpack('<i', code[-4:])[0]
        require(slot in SLOTS, 'disassembly target disagrees with encoded displacement')
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

    objdump = shutil.which('objdump')
    require(objdump is not None, 'objdump is required')
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C'}
    version = subprocess.check_output([objdump, '--version'], text=True, env=env).splitlines()[0]
    require('GNU' in version, 'GNU objdump is required')
    with __import__('tempfile').TemporaryDirectory(prefix='node115-selector-static-') as tmp:
        binary = Path(tmp) / 'node115.elf'
        binary.write_bytes(image)
        binary.chmod(0o400)
        disassembly = subprocess.check_output([objdump, '-d', '-w', '-Mintel', str(binary)], text=True, env=env)
    _, fdes, _ = fde_extents(image)
    xrefs = parse_xrefs(disassembly, fdes)
    require(len(xrefs) == 36, 'selector xref census changed')
    counts = {hex(slot): sum(row['slot'] == hex(slot) for row in xrefs) for slot in SLOTS}
    require(counts == {'0x64dfff8': 18, '0x64e0000': 18}, 'selector xref counts changed')
    record = {
        'target': 'Linux x86-64 node #115', 'target_sha256': digest,
        'scope': 'Two fixed selector GOT slots: RELA initialization, pointed-to file-backed objects, and all direct code references.',
        'method': 'Independent ELF section/RELA parsing, FDE extent decoding, and GNU objdump cross-check; static only.',
        'got_bindings': bindings, 'object_first_word_relocations': object_relocations,
        'direct_reference_counts': counts, 'direct_references': xrefs,
        'unique_fde_extents': [list(extent) for extent in
                               sorted({(row['fde_start'], row['fde_end']) for row in xrefs})],
        'limitations': [
            'FDE ranges are unwind extents, not proven function boundaries.',
            'The inventory is limited to directly encoded RIP-relative references visible in disassembly.',
            'No source-level names, runtime selection policy, dynamic pointer writes, or object semantics are inferred.',
            'The relocated code targets are address observations; no function meaning or ABI is assigned.',
            'No target code is executed or emulated.'
        ]
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / 'records.json').write_text(json.dumps(record, indent=2) + '\n')
    (output / 'xref-instructions.txt').write_text('\n'.join(
        f"{row['site']} {row['instruction_bytes']} {row['instruction']} -> {row['slot']} FDE {row['fde_start']}..{row['fde_end']}"
        for row in xrefs) + '\n')
    (output / 'tool-versions.json').write_text(json.dumps({'objdump': version}, indent=2) + '\n')
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
                      'unique_fde_extents': len(result['unique_fde_extents']),
                      'target_executed': False, 'record_check': args.check}))
