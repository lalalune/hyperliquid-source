#!/usr/bin/env python3
"""Read-only node115 TCP prefix evidence. Does not run or emulate the node."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET = ROOT / 'artifacts/node/115/hl-node'
RANGES = [(0x2b780d0, 0x2b782d5), (0x2b788e0, 0x2b79e2e),
          (0x2b7a290, 0x2b7b523)]


def require(value, message):
    if not value:
        raise ValueError(message)


def read(data, address, size):
    matches = [s for s in sections(data) if s['type'] != 8
               and s['address'] <= address and address + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'ambiguous or missing file mapping')
    offset = matches[0]['offset'] + address - matches[0]['address']
    return offset, bytes(data[offset:offset + size])


def projection(data):
    """Extract bounded instruction facts, not a CPU or async-state emulator."""
    anchors = {
        0x2b780fc: '488d5350c7435000000000c6435400',
        0x2b78225: '8b4b500fc90fb6435431d2',
        0x2b78230: '41891641894e0449894608',
        0x2b79038: '4589f64c8973584c3973280f837d010000',
        0x2b791ca: '0f944350',
        0x2b7a702: '4d8d7505',
        0x2b7a72d: '410fcd448928',
        0x2b7a758: '44887804',
        0x2b7a75c: '48c7839000000005000000',
        0x2b7a767: '4c8b6b704c8b7378',
        0x2b7a776: '4883c0fb4939c60f875a01000041bc05000000',
        0x2b7a795: '4c01e74c89ee4c89f2',
    }
    for address, expected in anchors.items():
        raw = bytes.fromhex(expected)
        require(read(data, address, len(raw))[1] == raw,
                f'prefix instruction changed at {address:#x}')
    width = read(data, 0x2b78112, 8)[1]
    require(width[:4] == bytes.fromhex('48c74310'), 'header span store changed')
    guard = read(data, 0x2b7a6b5, 9)[1]
    require(guard[:6] == bytes.fromhex('4c89e848c1e8') and guard[7:] == b'\x74\x44',
            'sender upper-word guard changed')
    marker = read(data, 0x2b791c6, 4)[1]
    require(marker[:3] == bytes.fromhex('4080fd'), 'receiver marker compare changed')
    return {'prefix_bytes': struct.unpack('<I', width[4:])[0],
            'sender_length_bits': guard[6], 'marker_equal_to': marker[3],
            'length_byte_order': 'big', 'marker_raw_offset': 4,
            'receiver_accepts_equal_limit': True}


def validate_projection(value):
    require(value == {'prefix_bytes': 5, 'sender_length_bits': 32,
                      'marker_equal_to': 1, 'length_byte_order': 'big',
                      'marker_raw_offset': 4, 'receiver_accepts_equal_limit': True},
            'prefix relation changed')


def _collect_authenticated(data, output, native_target):
    facts = projection(data)
    validate_projection(facts)
    _, frames, _ = fde_extents(data)
    indexed = {(f['start'], f['end']): f for f in frames}
    output.mkdir(parents=True, exist_ok=True)
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C'}
    versions = {}
    for tool in ['objdump', 'readelf']:
        version = subprocess.check_output([tool, '--version'], text=True, env=environment).splitlines()[0]
        require('GNU' in version, f'{tool} must be GNU binutils')
        versions[tool] = version
    native_frames = subprocess.check_output(['readelf', '-wf', str(native_target)], text=True, env=environment)
    native_ranges = {tuple(int(v, 16) for v in m) for m in
                     re.findall(r'pc=([0-9a-f]+)\.\.([0-9a-f]+)', native_frames)}
    frame_blocks = [block for block in native_frames.split('\n\n') if any(
        f'pc={start:016x}..{end:016x}' in block for start, end in RANGES)]
    require(len(frame_blocks) == 3, 'native FDE export incomplete')
    (output / 'frames.txt').write_text('\n\n'.join(frame_blocks) + '\n')
    rows = []
    instruction_sets = {}
    for start, end in RANGES:
        require((start, end) in indexed and (start, end) in native_ranges,
                'Python/native FDE disagreement')
        frame = indexed[start, end]
        offset, body = read(data, start, end - start)
        raw = subprocess.check_output(['objdump', '-d', '-M', 'intel',
            f'--start-address={start}', f'--stop-address={end}', str(native_target)],
            text=True, env=environment).replace(str(native_target), 'artifacts/node/115/hl-node')
        instructions = decode_export(raw, start, end, body)
        instruction_sets[start] = instructions
        calls = []
        for pc, code in instructions.items():
            if len(code) == 5 and code[:1] == b'\xe8':
                calls.append({'pc': hex(pc), 'kind': 'direct',
                              'target': hex(pc + 5 + struct.unpack('<i', code[1:])[0])})
            elif len(code) == 6 and code[:2] == b'\xff\x15':
                calls.append({'pc': hex(pc), 'kind': 'rip-slot',
                              'slot': hex(pc + 6 + struct.unpack('<i', code[2:])[0])})
        (output / f'{start:x}.objdump.txt').write_text(raw)
        frame_bytes = {}
        for name in ['fde', 'cie']:
            address = frame[name]
            size = struct.unpack('<I', read(data, address, 4)[1])[0] + 4
            frame_bytes[name] = {'va': hex(address), 'raw': read(data, address, size)[1].hex()}
        rows.append({'start': hex(start), 'end': hex(end), 'file_offset': offset,
                     'bytes': len(body), 'instructions': len(instructions),
                     'sha256': hashlib.sha256(body).hexdigest(), 'unwind': frame_bytes,
                     'lsda': None if frame['lsda'] is None else hex(frame['lsda']), 'calls': calls})
    rela = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    rels = {slot: (info, addend) for slot, info, addend in
            struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']])}
    bindings = []
    dynsym = next(s for s in sections(data) if s['name'] == '.dynsym')
    dynstr = next(s for s in sections(data) if s['name'] == '.dynstr')
    for slot in sorted({int(call['slot'], 16) for row in rows
                        for call in row['calls'] if call['kind'] == 'rip-slot'}):
        require(slot in rels, 'measured RIP call slot lacks a dynamic relocation')
        info, addend = rels[slot]
        symbol = None
        if info >> 32:
            offset = dynsym['offset'] + (info >> 32) * 24
            require(offset + 24 <= dynsym['offset'] + dynsym['size'], 'invalid dynamic symbol')
            name_offset = struct.unpack_from('<I', data, offset)[0]
            require(name_offset < dynstr['size'], 'invalid dynamic symbol string')
            begin = dynstr['offset'] + name_offset
            end = data.index(0, begin, dynstr['offset'] + dynstr['size'])
            symbol = bytes(data[begin:end]).decode('ascii')
        bindings.append({'slot': hex(slot), 'info': info, 'addend': hex(addend), 'symbol': symbol})
    selected_slots = {int(row['slot'], 16) for row in bindings} | {0x644afc0, 0x644b020}
    native_relocations = subprocess.check_output(['readelf', '-rW', str(native_target)], text=True, env=environment)
    selected_lines = []
    for line in native_relocations.splitlines():
        match = re.match(r'^([0-9a-f]+)\s', line)
        if match and int(match[1], 16) in selected_slots:
            slot = int(match[1], 16)
            fields = line.split()
            info, addend = rels[slot]
            require(int(fields[1], 16) == info, 'native relocation info differs')
            if info == 8:
                require(fields[2] == 'R_X86_64_RELATIVE' and int(fields[3], 16) == addend,
                        'native relative addend differs')
            else:
                binding = next(row for row in bindings if int(row['slot'], 16) == slot)
                require(info & 0xffffffff == 6 and fields[2] == 'R_X86_64_GLOB_DAT'
                        and fields[4].split('@')[0] == binding['symbol']
                        and fields[-2] == '+' and int(fields[-1], 16) == addend,
                        'native import binding differs')
            selected_lines.append(line)
    require(len(selected_lines) == len(selected_slots), 'native relocation export incomplete')
    (output / 'relocations.txt').write_text('\n'.join(selected_lines) + '\n')
    locations = []
    for slot, path, line in [(0x644afc0, b'net_utils/src/tcp/read.rs', 35),
                             (0x644b020, b'net_utils/src/tcp/write.rs', 34)]:
        info, pointer = rels[slot]
        length, source_line, column = struct.unpack('<QII', read(data, slot + 8, 16)[1])
        require(info == 8 and length == len(path) and source_line == line
                and read(data, pointer, length)[1] == path, 'source Location changed')
        locations.append({'slot': hex(slot), 'relocation_info': info,
                          'path_va': hex(pointer), 'path': path.decode(),
                          'length': length, 'line': source_line, 'column': column})
    location_xrefs = []
    for owner, instructions in instruction_sets.items():
        for pc, code in instructions.items():
            if len(code) == 7 and code[0] in (0x48, 0x4c) and code[1] == 0x8d and code[2] & 0xc7 == 5:
                destination = pc + 7 + struct.unpack('<i', code[3:])[0]
                if destination in (0x644afc0, 0x644b020):
                    location_xrefs.append({'pc': hex(pc), 'owner': hex(owner), 'location': hex(destination)})
    require(len(location_xrefs) == 3, 'source Location instruction references changed')
    tables = []
    for address in [0x604bf0, 0x604c00]:
        raw = read(data, address, 16)[1]
        destinations = [address + delta for delta in struct.unpack('<4i', raw)]
        require(all(p in instruction_sets[RANGES[0][0]] for p in destinations),
                'header poll dispatch does not name a measured instruction')
        tables.append({'address': hex(address), 'raw': raw.hex(),
                       'targets': [hex(p) for p in destinations]})
    record = {'target': 'node115', 'target_sha256': SHA, 'projection': facts,
              'scope': 'three complete FDE exports; bounded prefix semantics only',
              'windows': rows, 'source_locations': locations, 'header_poll_tables': tables,
              'source_location_xrefs': location_xrefs,
              'rip_call_bindings': bindings,
              'eof_material': read(data, 0x94d48e, 9)[1].decode(),
              'total_bytes': sum(row['bytes'] for row in rows),
              'total_instructions': sum(row['instructions'] for row in rows)}
    (output / 'records.json').write_text(json.dumps(record, indent=2) + '\n')
    (output / 'tool-versions.json').write_text(json.dumps(versions, indent=2) + '\n')
    return record


def collect(data, output):
    require(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == SHA,
            'node115 identity mismatch')
    with tempfile.TemporaryDirectory(prefix='node115-prefix-static-') as directory:
        native_target = Path(directory) / 'node115.elf'
        native_target.write_bytes(data)
        native_target.chmod(0o400)
        return _collect_authenticated(data, output, native_target)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/node115-tcp-prefix')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    record = collect(TARGET.read_bytes(), args.output)
    if args.check:
        expected = json.loads((PACKET / 'records.json').read_text())
        require(record == expected, 'retained prefix record differs')
    print(json.dumps({'bytes': record['total_bytes'], 'instructions': record['total_instructions'],
                      'captured_node_executed': False, 'record_check': args.check}))
