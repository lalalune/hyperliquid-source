#!/usr/bin/env python3
"""Static node94 block-reader range admission; never execute captured code."""
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x27abee0, 0x27ac599
OBJDUMP = '/Library/Developer/CommandLineTools/usr/bin/llvm-objdump'
DWARF = '/Library/Developer/CommandLineTools/usr/bin/llvm-dwarfdump'
PINS = {
    'outer-state-load': (0x27abef4, '0fb686f0000000'),
    'outer-dispatch': (0x27abefb, '488d0d1a2dc4fd486304814801c8ffe0'),
    'range-low': (0x27abf12, '488babd0000000'),
    'range-high': (0x27abf19, '4c8bb3d8000000'),
    'subtract': (0x27abf37, '4c89f04829e8'),
    'unsigned-no-borrow': (0x27abf3d, '0f93c1'),
    'exclude-max-delta': (0x27abf40, '4883f8ff400f95c6'),
    'and-predicates': (0x27abf48, '4020ce4080fe01'),
    'reject-branch': (0x27abf4f, '757f'),
    'inclusive-increment': (0x27abf5b, '48ffc0'),
    'save-count': (0x27abf5e, '488983e0000000'),
    'invalid-tag': (0x27abfd0, '40b508e910040000'),
    'output-tag-store': (0x27ac3e8, '40882f'),
    'outer-complete-state': (0x27ac3f7, 'b0018883f0000000'),
    'source-location-reference': (0x27ac42b, '488d3d666cf102'),
}
TABLES = {
    0x3eec1c: [0x27abf0b, 0x27ac41e, 0x27ac411, 0x27abf9b],
    0x3eec2c: [0x27abfbe, 0x27ac43a, 0x27ac42b, 0x27abfd8],
    0x3eec3c: [0x27abffa, 0x27ac45d, 0x27ac449, 0x27ac201],
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def validate(read):
    for name, (va, hx) in PINS.items():
        need(read(va, len(bytes.fromhex(hx))).hex() == hx, name)
    for va, targets in TABLES.items():
        need([va + n for n in struct.unpack('<4i', read(va, 16))] == targets,
             f'dispatch table {va:#x}')


def main():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    need(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA, 'whole target identity')
    ss = sections(data)
    def off(va, size):
        found = [s for s in ss if s['type'] != 8 and s['address'] <= va and
                 va + size <= s['address'] + s['size']]
        need(len(found) == 1, 'unique VA mapping')
        return found[0]['offset'] + va - found[0]['address']
    def read(va, size):
        o = off(va, size)
        return data[o:o + size]
    validate(read)
    _, fdes = eh_frame_records(data, ss)
    ff = [f for f in fdes if f['start'] == START]
    need(len(ff) == 1 and ff[0]['end'] == END and ff[0]['fde'] == 0x10f8420, 'owner FDE')
    _, index = unwind_index(data)
    ii = [r for r in index if r['start'] == START]
    need(len(ii) == 1 and ii[0]['fde'] == ff[0]['fde'], 'unwind index')
    frame_sec = next(s for s in ss if s['name'] == '.eh_frame')
    dwarf_cmd = [DWARF, f"--eh-frame={ff[0]['fde'] - frame_sec['address']:#x}", 'artifacts/node/94/hl-node']
    dwarf = subprocess.check_output(dwarf_cmd, cwd=ROOT, text=True)
    need('pc=027abee0...027ac599' in dwarf, 'independent LLVM FDE')
    command = [OBJDUMP, '-d', '--x86-asm-syntax=intel', f'--start-address={START:#x}',
               f'--stop-address={END:#x}', 'artifacts/node/94/hl-node']
    output = subprocess.check_output(command, cwd=ROOT, text=True)
    rows = []
    for line in output.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$', line)
        if m:
            rows.append((int(m[1], 16), bytes.fromhex(m[2]), m[3].strip()))
    cursor = START
    for va, bs, text in rows:
        need(va == cursor and read(va, len(bs)) == bs and '<unknown>' not in text,
             'complete entry-based LLVM decode')
        cursor += len(bs)
    need(cursor == END, 'exact owner end')
    boundaries = {r[0] for r in rows}
    need(all(va in boundaries for va, _ in PINS.values()), 'pin instruction boundaries')
    need(all(t in boundaries for ts in TABLES.values() for t in ts), 'selected dispatch destinations')
    # Independently bind the embedded Location to a relocation and original path.
    slot = 0x56c3098
    rela = [s for s in ss if s['name'] == '.rela.dyn']
    need(len(rela) == 1 and rela[0]['size'] % 24 == 0, 'RELA identity')
    bindings = []
    for o in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', data, o)
        if target == slot:
            bindings.append({'slot': hex(target), 'info': hex(info), 'target': hex(addend),
                             'raw': data[o:o + 24].hex()})
    need(len(bindings) == 1 and bindings[0]['info'] == '0x8', 'unique source Location RELATIVE binding')
    ptr, length, line, column = struct.unpack('<QQII', read(slot, 24))
    path = read(int(bindings[0]['target'], 16), length).decode()
    need(ptr == 0 and path == '/home/ubuntu/hl/code_Mainnet/db/src/block_reader.rs' and
         line == 45 and column == 114, 'source Location payload')
    # Two independently phrased arithmetic forms, with no native target run.
    mask = (1 << 64) - 1
    domain = [0, 1, 2, 4, 5, 6, (1 << 63)-1, 1 << 63, mask-2, mask-1, mask]
    probes = []
    for low in domain:
        for high in domain:
            delta = (high - low) & mask
            accept = high >= low and delta != mask
            result = ((delta + 1) & mask) if accept else None
            full = high - low + 1
            expected = full if 1 <= full <= mask else None
            need(result == expected, 'independent inclusive arithmetic form')
            probes.append({'low': str(low), 'high': str(high), 'selected_count': None if result is None else str(result)})
    controls = []
    for name, va in [(name, va) for name, (va, _) in PINS.items()] + [
            (f'table-{va:#x}', va) for va in TABLES]:
        def mutated(at, size):
            block = bytearray(read(at, size))
            if at <= va < at + size:
                block[va - at] ^= 1
            return bytes(block)
        try:
            validate(mutated)
        except ValueError as error:
            controls.append({'name': name, 'mutated_va': hex(va), 'rejected_without_hash_gates': str(error)})
        else:
            raise ValueError('mutation escaped: ' + name)
    record = {
        'task': 'RE-009', 'target_sha256': SHA, 'target_size': len(data),
        'source_base': 'e5c9b6436876b2a4a39daef813171f9879317699',
        'coordinate_system': 'ELF VA, end exclusive',
        'owner': {**{k: hex(v) if isinstance(v, int) else v for k, v in ff[0].items()},
                  'bytes': END-START, 'instruction_count': len(rows),
                  'sha256': hashlib.sha256(read(START, END-START)).hexdigest(),
                  'fde_raw': read(ff[0]['fde'], struct.unpack('<I', read(ff[0]['fde'], 4))[0] + 4).hex(),
                  'cie_raw': read(ff[0]['cie'], struct.unpack('<I', read(ff[0]['cie'], 4))[0] + 4).hex()},
        'unwind_index': ii[0],
        'source_location': {'va': hex(slot), 'raw': read(slot, 24).hex(), 'path': path,
                            'line': line, 'column': column, 'binding': bindings[0]},
        'probes': {name: {'va': hex(va), 'raw': hx} for name, (va, hx) in PINS.items()},
        'selected_dispatch_entries': {hex(va): {'raw': read(va, 16).hex(), 'targets': [hex(t) for t in targets]}
                                      for va, targets in TABLES.items()},
        'dispatch_limits': 'Only indices 0..3 qualified; no bounds check precedes indexed jumps; valid state domain/initialization not established',
        'tool_commands': [command, dwarf_cmd],
        'decoder': subprocess.check_output([OBJDUMP, '--version'], text=True).splitlines()[0],
        'host': platform.system() + ' ' + platform.machine(), 'python': platform.python_version(),
        'parser_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                          for p in ['tools/elf_index.py', 'tools/fde_extents.py']},
        'arithmetic_domain': [str(n) for n in domain], 'arithmetic_probes': probes,
        'negative_controls': controls,
        'counts': {'owner_bytes': END-START, 'owner_instructions': len(rows), 'instruction_pins': len(PINS),
                   'dispatch_entries': sum(len(v) for v in TABLES.values()),
                   'arithmetic_probes': len(probes), 'rejected_mutations': len(controls)},
        'nonclaims': ['No execution or emulation of captured program', 'No Rust implementation',
                      'No complete async state machine, backend/helper or CFG closure', 'No acceptance-gate change'],
    }
    (HERE / 'owner.llvm.txt').write_text((' '.join(command) + '\n' + output).rstrip('\n') + '\n')
    (HERE / 'owner-fde.llvm.txt').write_text((' '.join(dwarf_cmd) + '\n' + dwarf).rstrip('\n') + '\n')
    (HERE / 'records.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
