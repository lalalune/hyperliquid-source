#!/usr/bin/env python3
"""Authenticate and export node #94 receiver poll/terminal-path static evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from artifacts import ROOT, check
from elf_index import sections

RANGES = {
    'receiver-poll': (0x145D5E0, 0x145D97C),
    'wait-poll': (0x145D250, 0x145D5DA),
    'channel-poll': (0x1499120, 0x14993C4),
    'terminal-call': (0x14C4DE0, 0x14C4E17),
    'exit-wrapper': (0x4EEE1B0, 0x4EEE1C4),
    'exit-import-caller': (0x4EE3710, 0x4EE3725),
}
TABLES = {
    0x21A0F8: [0x145D60A, 0x145D8C9, 0x145D882, 0x145D61C, 0x145D7F0],
    0x21A10C: [0x145D634, 0x145D89E, 0x145D88F, 0x145D697],
    0x21A11C: [0x145D6AF, 0x145D8BC, 0x145D8AD, 0x145D816],
    0x21A0D8: [0x145D27C, 0x145D52F, 0x145D522, 0x145D29B],
    0x21A0E8: [0x145D2B9, 0x145D54B, 0x145D53C, 0x145D4E1],
}
RELATIVE = {0x566B328: 0x1DE97C, 0x566B298: 0x1E4DCC,
            0x576F530: 0x14C4DE0, 0x576FE08: 0x4EEE1B0,
            0x576F728: 0x4F65D40, 0x576F088: 0x4F68F00}
CONTROLS = {
    0x145D5F6: '0fb64748',
    0x145D650: 'e8cbba0300',
    0x145D65A: '49bc0000000000000080',
    0x145D664: '498d4424014839c10f94c200d2fec241885500',
    0x145D677: '4839c1750641c60703eb0e',
    0x145D690: 'b103e96b010000',
    0x145D7DB: '48b8000000000000344048894350',
    0x145D7F7: 'e854faffffb10484c0745d',
    0x145D802: '884b48',
    0x145D85F: '80bbe800000003751280bbe0000000037509488d7b68e876820000',
    0x145D87A: 'ff15b01c3104',
    0x145D96A: 'c6434802',
    0x145D285: '660f57c9660f2ec175407a3e',
    0x145D4EB: 'ff15971b310489c541b60384c0750b41b601',
    0x145D505: '458834244488b39800000089e8',
    0x14C4E0C: 'bf01000000ff15f1af2a04',
    0x4EEE1BD: '89dfe84c55ffff',
    0x4EE371D: '89dfff15533c8900',
}

def read_va(data, address, length):
    candidates = [s for s in sections(data) if s['type'] != 8 and
                  s['address'] <= address and address + length <= s['address'] + s['size']]
    if len(candidates) != 1:
        raise ValueError('Expected one file-backed section')
    offset = candidates[0]['offset'] + address - candidates[0]['address']
    return offset, data[offset:offset + length]

def instruction_controls(data):
    for address, expected in CONTROLS.items():
        if read_va(data, address, len(bytes.fromhex(expected)))[1] != bytes.fromhex(expected):
            raise ValueError(f'Receiver instruction changed at {address:#x}')
    path = b'/home/ubuntu/hl/code_Mainnet/base/src/recver.rs'
    if read_va(data, 0x1DE97C, len(path))[1] != path:
        raise ValueError('Receiver source path changed')

def tables(data):
    rows = []
    for address, expected in TABLES.items():
        offset, raw = read_va(data, address, 4 * len(expected))
        actual = [address + displacement for displacement in struct.unpack('<' + 'i' * len(expected), raw)]
        if actual != expected:
            raise ValueError(f'Receiver jump table changed at {address:#x}')
        rows.append({'va': hex(address), 'file_offset': hex(offset), 'bytes': raw.hex(),
                     'targets': [hex(target) for target in actual]})
    return rows

def relocations(data):
    rows = {}
    exit_symbol = False
    section_rows = sections(data)
    shoff = struct.unpack_from('<Q', data, 40)[0]
    shsize = struct.unpack_from('<H', data, 58)[0]
    for section_index, section in enumerate(section_rows):
        if section['type'] != 4:
            continue
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot in RELATIVE:
                if info != 8 or addend != RELATIVE[slot]:
                    raise ValueError(f'Receiver relocation changed at {slot:#x}')
                rows[slot] = {'slot_va': hex(slot), 'info': hex(info), 'addend': hex(addend)}
            if slot == 0x5777378:
                # Resolve this actual linked symbol table entry; do not infer exit
                # from an address annotation or a reference source function name.
                symbol_index = struct.unpack_from('<I', data, shoff + section_index * shsize + 40)[0]
                symbol_section = section_rows[symbol_index]
                string_index = struct.unpack_from('<I', data, shoff + symbol_index * shsize + 40)[0]
                string_section = section_rows[string_index]
                entry_size = struct.unpack_from('<Q', data, shoff + symbol_index * shsize + 56)[0]
                if symbol_section['type'] != 11 or entry_size != 24:
                    raise ValueError('Unexpected dynamic symbol table')
                symbol = symbol_section['offset'] + (info >> 32) * entry_size
                name_offset = struct.unpack_from('<I', data, symbol)[0]
                if name_offset >= string_section['size']:
                    raise ValueError('Receiver dynamic symbol name offset outside string table')
                string_table = data[string_section['offset']:string_section['offset'] + string_section['size']]
                end = string_table.find(b'\0', name_offset)
                if end < 0:
                    raise ValueError('Receiver dynamic symbol name not terminated inside string table')
                name = string_table[name_offset:end].decode('ascii')
                if info & 0xFFFFFFFF != 6 or name != 'exit' or addend != 0:
                    raise ValueError('Exit import binding changed')
                exit_symbol = True
                rows[slot] = {'slot_va': hex(slot), 'info': hex(info), 'symbol': name, 'addend': '0x0'}
    if set(rows) != {*RELATIVE, 0x5777378} or not exit_symbol:
        raise ValueError('Missing receiver/exit binding')
    return [rows[slot] for slot in sorted(rows)]

def generate(binary, output):
    identity = next(item for item in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if item['path'] == 'artifacts/node/94/hl-node')
    check(binary, identity)
    data = binary.read_bytes()
    instruction_controls(data)
    jump_tables, relocation_rows = tables(data), relocations(data)
    frames = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    extents = [(int(a, 16), int(b, 16)) for a, b in
               re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)', frames)]
    output.mkdir(parents=True, exist_ok=True)
    ranges = {}
    for name, pair in RANGES.items():
        if extents.count(pair) != 1:
            raise ValueError(f'Expected one exact receiver FDE: {pair}')
        begin, end = pair
        offset, body = read_va(data, begin, end - begin)
        ranges[name] = {'start_va': hex(begin), 'end_va': hex(end), 'file_offset': hex(offset),
                        'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        result = subprocess.check_output(['objdump', '-d', f'--start-address={begin:#x}',
                                          f'--stop-address={end:#x}', str(binary)], text=True)
        (output / (name + '.objdump.txt')).write_text(result.replace(str(binary), '<authenticated-node94>'))
    (output / 'frames.txt').write_text('\n'.join(line for line in frames.splitlines()
        if 'FDE' in line and any(f'pc={a:016x}..{b:016x}' in line for a, b in RANGES.values())) + '\n')
    raw_rela = subprocess.check_output(['readelf', '-rW', str(binary)], text=True)
    slots = {*RELATIVE, 0x5777378}
    (output / 'relocations.txt').write_text('\n'.join(line for line in raw_rela.splitlines()
        if re.match(r'^[0-9a-f]+\s', line) and int(line.split()[0], 16) in slots) + '\n')
    record = {'target_sha256': identity['sha256'], 'target_bytes': len(data), 'ranges': ranges,
              'jump_tables': jump_tables, 'relocations': relocation_rows,
              'instruction_controls': {hex(a): b for a, b in CONTROLS.items()},
              'fde_records_observed': len(extents), 'captured_binary_executed': False,
              'limits': 'Numeric poll states and terminal call path only. No full channel/API, scheduler, wait duration, runtime reachability, floating conversion equivalence, ownership or component gate claim.'}
    (output / 'records.json').write_text(json.dumps(record, indent=2) + '\n')
    return record

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT / 'work/receiver-poll-94')
    args = parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(), args.output), indent=2))
