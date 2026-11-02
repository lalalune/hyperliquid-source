#!/usr/bin/env python3
"""Authenticate and export one node94 static bootstrap record-consumption slice.

Only the repository's reviewed ELF/FDE parsers are imported. No captured code
is executed. LLVM objdump is a static, second-method instruction decoder.
"""
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x4389070, 0x438a38c
OBJDUMP = '/Library/Developer/CommandLineTools/usr/bin/llvm-objdump'
DWARFDUMP = '/Library/Developer/CommandLineTools/usr/bin/llvm-dwarfdump'
# Exact instruction probes document the operands supporting the claims below.
PINS = {
    'record_stride_shift': (0x438994e, '49c1e705'),
    'record_end_add': (0x4389952, '4d01ef'),
    'cursor_increment': (0x4389988, '498d4d20'),
    'cursor_store': (0x438998c, '48898b28010000'),
    'record_zero_test': (0x43899a4, '4883bb4001000000'),
    'callback_call': (0x43899e1, 'ff1581cc3e01'),
    'callback_tag_base': (0x4389944, '48bd0000000000000080'),
    'callback_tag_add': (0x43899eb, '488d4540'),
    'callback_tag_compare': (0x43899ef, '4939c6'),
    'callback_nonmatch_branch': (0x43899f2, '0f8555050000'),
    'resume_cursor_reload': (0x4389ab5, '4c8bab28010000'),
    'resume_end_reload': (0x4389abc, '4c8bbb38010000'),
    'cursor_end_compare': (0x4389ad1, '4d39fd'),
    'record_cleanup_call': (0x4389ae1, 'e88ad31300'),
    'current_height_reload': (0x4389c22, '488bb008010000'),
    'target_height_compare': (0x4389c29, '4839ce'),
    'height_mismatch_branch': (0x4389c2c, '0f857df6ffff'),
    'completion_byte_store': (0x4389c32, 'c6801801000001'),
}
WINDOWS = [(0x43892a6, 0x43892b5), (0x4389944, 0x4389a0a), (0x4389aae, 0x4389ae6),
           (0x4389c14, 0x4389c39), (0x4389f4d, 0x4389f8b)]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_pins(reader):
    for name, (va, hx) in PINS.items():
        require(reader(va, len(bytes.fromhex(hx))).hex() == hx,
                'instruction mismatch: ' + name)


def main():
    binary = ROOT / 'artifacts/node/94/hl-node'
    data = binary.read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == DIGEST,
            'node94 artifact size/SHA-256 mismatch')
    secs = sections(data)

    def off(va, size=1):
        matches = [s for s in secs if s['type'] != 8 and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'ambiguous or missing VA mapping')
        return matches[0]['offset'] + va - matches[0]['address']

    def raw(va, size):
        offset = off(va, size)
        return data[offset:offset + size]

    cies, fdes = eh_frame_records(data, secs)
    matches = [f for f in fdes if f['start'] == START]
    require(len(matches) == 1 and matches[0]['end'] == END, 'owner FDE mismatch')
    fde = matches[0]
    _, index = unwind_index(data)
    indexed = [i for i in index if i['start'] == START]
    require(len(indexed) == 1 and indexed[0]['fde'] == fde['fde'], 'unwind index mismatch')
    frame = next(s for s in secs if s['name'] == '.eh_frame')
    dwarf_command = [DWARFDUMP, '--eh-frame=' + hex(fde['fde'] - frame['address']),
                     'artifacts/node/94/hl-node']
    dwarf = subprocess.check_output(dwarf_command, cwd=str(ROOT), text=True)
    require('pc=04389070...0438a38c' in dwarf, 'independent LLVM FDE mismatch')
    validate_pins(raw)

    command = [OBJDUMP, '--disassemble', '--x86-asm-syntax=intel',
               '--start-address=' + hex(START), '--stop-address=' + hex(END),
               'artifacts/node/94/hl-node']
    result = subprocess.run(command, cwd=str(ROOT), check=True, capture_output=True, text=True)
    # Decode from the FDE entry, never resynchronize at a selected address.
    rows = []
    for line in result.stdout.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$', line)
        if match:
            rows.append((int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()))
    require(rows and rows[0][0] == START, 'LLVM output missing owner entry')
    cursor = START
    for va, bs, text in rows:
        require(va == cursor and raw(va, len(bs)) == bs, 'LLVM bytes/gap mismatch')
        require('<unknown>' not in text, 'LLVM unknown instruction')
        cursor += len(bs)
    require(cursor == END, 'LLVM did not consume exact owner range')
    boundaries = {r[0] for r in rows}
    require(all(va in boundaries for va, _ in PINS.values()), 'probe not on instruction boundary')

    slot = 0x43899e1 + 6 + struct.unpack('<i', raw(0x43899e1 + 2, 4))[0]
    rela = [s for s in secs if s['name'] == '.rela.dyn']
    require(len(rela) == 1 and rela[0]['size'] % 24 == 0, 'bad relocation section')
    relocations = []
    sec = rela[0]
    for offset in range(sec['offset'], sec['offset'] + sec['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', data, offset)
        if target == slot:
            relocations.append({'file_offset': hex(offset), 'slot_va': hex(target),
                                'info': hex(info), 'addend_va': hex(addend),
                                'raw_hex': data[offset:offset + 24].hex()})
    require(len(relocations) == 1 and relocations[0]['info'] == '0x8', 'callback RELATIVE relocation mismatch')
    require(raw(slot, 8) == bytes(8), 'callback slot pre-relocation value changed')

    def record_bytes(va):
        size = struct.unpack('<I', raw(va, 4))[0] + 4
        return raw(va, size).hex()

    controls = []
    # Corruption controls are evidence-validation tests, not target behavior.
    for name in ('cursor_increment', 'record_zero_test', 'callback_call',
                 'callback_tag_add', 'height_mismatch_branch', 'completion_byte_store'):
        va, hx = PINS[name]
        original = bytes.fromhex(hx)
        altered = bytearray(original)
        altered[-1] ^= 1
        def altered_reader(at, size):
            block = bytearray(raw(at, size))
            for i in range(size):
                if va <= at + i < va + len(altered):
                    block[i] = altered[at + i - va]
            return bytes(block)
        try:
            validate_pins(altered_reader)
        except ValueError as error:
            require(str(error) == 'instruction mismatch: ' + name, 'unexpected control failure')
        else:
            raise ValueError('corruption escaped operand checker: ' + name)
        controls.append({'probe': name, 'va': hex(va), 'original': hx,
                         'mutant': bytes(altered).hex(),
                         'exact_operand_validator_rejects': True})
    selected = [r for r in rows if any(lo <= r[0] < hi for lo, hi in WINDOWS)]
    records = {
        'task': 'RE-012', 'component': 'node-runtime', 'target_sha256': DIGEST,
        'source_base': 'e5c9b6436876b2a4a39daef813171f9879317699',
        'reference_gitlink': '999556f6e0a474b8312db96ec3149e1c44e97c23',
        'coordinate_system': 'linked ELF VA; file offsets derived from section mapping',
        'target_size': len(data), 'owner': {**{k: hex(v) if isinstance(v, int) else v for k, v in fde.items()},
        'sha256': hashlib.sha256(raw(START, END-START)).hexdigest(),
        'fde_raw_hex': record_bytes(fde['fde']), 'cie_raw_hex': record_bytes(fde['cie']),
        'instruction_count': len(rows), 'bytes': END-START, 'unwind_index': indexed[0]},
        'windows': [{'start_va': hex(lo), 'end_exclusive': hex(hi),
                     'file_offset': hex(off(lo)), 'raw_hex': raw(lo, hi-lo).hex()} for lo, hi in WINDOWS],
        'callback_relocation': relocations[0],
        'callee_fde_extents': [{k: hex(v) if isinstance(v, int) else v for k, v in f.items()}
                               for f in fdes if f['start'] in (0x4360000, 0x44c6e70)],
        'probes': [{'name': name, 'va': hex(va), 'file_offset': hex(off(va)), 'raw_hex': hx}
                   for name, (va, hx) in PINS.items()],
        'static_decoder': {'command': command, 'version': subprocess.check_output([OBJDUMP, '--version'], text=True).splitlines()[0],
                           'coverage': 'whole owner decoded linearly; selected windows interpreted',
                           'selected_instruction_count': len(selected)},
        'independent_unwind_command': dwarf_command,
        'tool_versions': {'python': platform.python_version(), 'system': platform.system(),
                          'machine': platform.machine()},
        'parser_sha256': {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
                           for p in ('tools/elf_index.py', 'tools/fde_extents.py')},
        'negative_controls': controls,
        'nonclaims': ['No target execution or behavior comparison', 'No Rust implementation',
                      'No full bootstrap/CFG/helper closure', 'No acceptance gate change'],
    }
    # Prefix static transcript with the exact relative command and target identity.
    transcript = ' '.join(command) + '\nTarget SHA256: ' + DIGEST + '\n'
    transcript += '\n'.join(hex(va) + ' ' + bs.hex() + ' ' + text for va, bs, text in selected) + '\n'
    (HERE / 'instructions.llvm.txt').write_text(transcript)
    (HERE / 'owner-fde.llvm.txt').write_text(' '.join(dwarf_command) + '\n' + dwarf.rstrip('\n') + '\n')
    (HERE / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
    print('PASS: authenticated target, FDE/index, whole-owner LLVM boundaries, 18 operand probes, callback relocation, 6 operand-corruption controls')


if __name__ == '__main__':
    main()
