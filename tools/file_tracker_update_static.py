#!/usr/bin/env python3
"""Digest-bound static observations of one node #94 file-tracker updater."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records

RANGES = {'updater': (0x13CC5D0, 0x13CC973), 'caller': (0x143D010, 0x143E888)}
CONTROLS = {
    'poll-sentinel': (0x13CC5F3, '8b453885c07469'),
    'interval-unordered-or-below': (0x13CC657, '660f2e4424100f861a010000'),
    'poll-store-before-predicate': (0x13CC663, '488d45388b4c2408894808488b0c24488908'),
    'regular-file-predicate': (0x13CC683, 'ff155f233a0484c00f84ec000000'),
    'metadata-error-tag': (0x13CC6A2, '837c2440010f844e020000'),
    'signed-unsigned-mtime-order': (0x13CC6B9, '3b5d500f9fc075123b4d540f97c0750a3b5558770de9aa00000084c00f84a2000000'),
    'load-discriminator': (0x13CC6F4, 'e8770d080031c0483b8424800000000f818a000000'),
    'replace-error': (0x13CC767, '488b1c24488b7d484885ff7405488b07ff1048895d48'),
    'return-zero': (0x13CC77D, '31db89d8'),
    'replace-value': (0x13CC862, '488b84249000000048894310660f10842480000000660f1103'),
    'replace-mtime': (0x13CC880, '8b4424348943508b44243c8943548b442438894358'),
    'clear-error': (0x13CC895, '488b7b484885ff7405488b07ff1048c7434800000000'),
    'return-one': (0x13CC8B1, 'b30185c00f84c4feffff'),
    'metadata-unwrap-and-ud2': (0x13CC905, '488d3d91a6e4fe488d0d45a62904488d542418be2b0000004d89f0ff1522173a040f0b'),
    'caller-arguments-and-call': (0x143DEEC, '488d3d4dce3304488d357ec32204e8d1e6f8ff'),
}
LITERALS = {0x216F9D: b'called `Result::unwrap()` on an `Err` value',
            0x1DF907: bytes.fromhex('264572726f72207570646174696e672046696c654d6f6454696d65547261636b657220666f7220c0023a20c000')}
RELATIVE = {0x5666F58: 0x13D2F20, 0x576E048: 0x157AA10,
            0x576E8A0: 0x151CBA0, 0x576E8C0: 0x1447130,
            0x576E978: 0x143D010, 0x576E9E8: 0x144A710,
            0x576E9F0: 0x144C930}
CALLS = {0x13CC5ED: ('slot', 0x576E8A0), 0x13CC651: ('slot', 0x576E8C0),
         0x13CC683: ('slot', 0x576E9E8), 0x13CC69C: ('slot', 0x576E9F0),
         0x13CC6F4: ('direct', 0x144D470), 0x13CC761: ('slot', 0x576E978),
         0x13CC920: ('slot', 0x576E048), 0x143DEFA: ('direct', 0x13CC5D0)}


def read_va(data, va, length):
    if length < 0:
        raise ValueError('Negative byte length')
    matches = [s for s in sections(data) if s['type'] != 8 and
               s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'Expected one file-backed mapping for {va:#x}')
    offset = matches[0]['offset'] + va - matches[0]['address']
    if offset + length > len(data):
        raise ValueError('Mapped bytes outside input')
    return offset, data[offset:offset + length]


def controls(data):
    # Call separately in corruption tests so the global digest does not hide
    # whether the local architectural obligations actually reject a mutation.
    for name, (va, expected) in CONTROLS.items():
        if read_va(data, va, len(bytes.fromhex(expected)))[1] != bytes.fromhex(expected):
            raise ValueError(f'Updater instruction changed: {name} at {va:#x}')
    for va, expected in LITERALS.items():
        if read_va(data, va, len(expected))[1] != expected:
            raise ValueError(f'Updater diagnostic changed at {va:#x}')


def relocations(data):
    found = {}
    for section in sections(data):
        if section['type'] != 4:
            continue
        if section['size'] % 24:
            raise ValueError('Non-integral ELF64 RELA section')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot in RELATIVE:
                if slot in found or info != 8 or addend != RELATIVE[slot]:
                    raise ValueError(f'Updater relocation changed or duplicated at {slot:#x}')
                found[slot] = {'slot_va': hex(slot), 'info': info, 'addend': hex(addend)}
    if set(found) != set(RELATIVE):
        raise ValueError('Missing updater relocation')
    return [found[slot] for slot in sorted(found)]


def frames(data):
    _, fdes = eh_frame_records(data)
    result = {}
    for name, (start, end) in RANGES.items():
        matches = [f for f in fdes if f['start'] == start]
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError(f'Expected exact updater/caller FDE extent: {name}')
        result[name] = matches[0]
    return result


def calls(data):
    result = []
    for va, (kind, target) in CALLS.items():
        raw = read_va(data, va, 6 if kind == 'slot' else 5)[1]
        prefix, size, delta_at = (b'\xff\x15', 6, 2) if kind == 'slot' else (b'\xe8', 5, 1)
        if not raw.startswith(prefix) or va + size + struct.unpack_from('<i', raw, delta_at)[0] != target:
            raise ValueError(f'Updater call target changed at {va:#x}')
        result.append({'site_va': hex(va), 'kind': kind, 'target_va': hex(target), 'bytes': raw.hex()})
    return result


def instructions(text):
    rows = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if match:
            rows.append((int(match[1], 16), bytes.fromhex(match[2])))
    return rows


def decoded_body(text, data, start, end):
    rows = instructions(text)
    cursor = start
    for va, raw in rows:
        if va != cursor or read_va(data, va, len(raw))[1] != raw:
            raise ValueError('Disassembler instruction coverage/bytes differ')
        cursor += len(raw)
    if cursor != end:
        raise ValueError('Disassembler did not cover the complete body')
    return rows


def tool_version(tool, gnu=False):
    value = subprocess.check_output([tool, '--version'], text=True).splitlines()[0]
    if gnu and 'GNU' not in value and 'Binutils' not in value:
        raise ValueError(f'GNU binutils required: {tool}')
    return value


def disassemble(tool, binary, start, end, gnu=True):
    args = [tool, '-d', f'--start-address={start:#x}', f'--stop-address={end:#x}']
    if gnu:
        args.append('--insn-width=16')
    return subprocess.check_output([*args, str(binary)], text=True).replace(str(binary), '<authenticated-node94>')


def generate(binary, output, objdump='objdump', readelf='readelf', second_objdump=None):
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == 'artifacts/node/94/hl-node')
    data = binary.read_bytes()
    # Authenticate the same byte snapshot that is analyzed below.
    if len(data) != identity['size'] or hashlib.sha256(data).hexdigest() != identity['sha256']:
        raise ValueError(f'Artifact size/SHA-256 mismatch: {binary}')
    controls(data)
    relocs, fdes, call_rows = relocations(data), frames(data), calls(data)
    versions = {'objdump': tool_version(objdump, True), 'readelf': tool_version(readelf, True)}
    raw_frames = subprocess.check_output([readelf, '-wf', str(binary)], text=True)
    frame_lines = []
    for name, (start, end) in RANGES.items():
        matches = [line for line in raw_frames.splitlines() if re.search(
            rf'FDE[^\n]*pc={start:016x}\.\.{end:016x}(?:\s|$)', line)]
        if len(matches) != 1:
            raise ValueError(f'Independent readelf FDE mismatch: {name}')
        frame_lines.extend(matches)
    start, end = RANGES['updater']
    text = disassemble(objdump, binary, start, end)
    decoded = decoded_body(text, data, start, end)
    # Decode the complete containing FDE before retaining only a short context.
    a, b = RANGES['caller']
    caller_text = disassemble(objdump, binary, a, b)
    caller_rows = decoded_body(caller_text, data, a, b)
    if (0x143DEFA, bytes.fromhex('e8d1e6f8ff')) not in caller_rows:
        raise ValueError('Caller site is not an instruction boundary')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'update.objdump.txt').write_text(text)
    (output / 'caller-context.txt').write_text('\n'.join(line for line in caller_text.splitlines()
        if (m := re.match(r'\s*([0-9a-f]+):', line)) and 0x143DEEC <= int(m[1], 16) < 0x143DF0A) + '\n')
    offset, body = read_va(data, start, end - start)
    (output / 'update-body.hex').write_text(body.hex() + '\n')
    fde = fdes['updater']['fde']
    length = struct.unpack('<I', read_va(data, fde, 4)[1])[0] + 4
    (output / 'update-fde.hex').write_text(read_va(data, fde, length)[1].hex() + '\n')
    (output / 'frames.txt').write_text('\n'.join(frame_lines) + '\n')
    second = None
    if second_objdump:
        versions['second_objdump'] = tool_version(second_objdump)
        second_text = disassemble(second_objdump, binary, start, end, False)
        if decoded_body(second_text, data, start, end) != decoded:
            raise ValueError('Independent decoder boundaries/bytes differ')
        (output / 'update.second-objdump.txt').write_text(second_text)
        second = {'instructions': len(decoded), 'bytes': len(body), 'equal': True}
    result = {'target_sha256': identity['sha256'], 'target_bytes': len(data),
              'range': {'start_va': hex(start), 'end_va': hex(end), 'file_offset': hex(offset),
                        'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()},
              'frames': {name: {key: hex(value) if value is not None else None for key, value in row.items()}
                         for name, row in fdes.items()},
              'instruction_count': len(decoded), 'second_decoder': second, 'tools': versions,
              'controls': {name: {'va': hex(va), 'bytes': raw} for name, (va, raw) in CONTROLS.items()},
              'diagnostic_bytes': {hex(va): value.hex() for va, value in LITERALS.items()},
              'metadata_error_vtable': {'va': '0x5666f58',
                                        'raw_bytes': read_va(data, 0x5666F58, 24)[1].hex()},
              'relocations': relocs, 'selected_calls': call_rows,
              'captured_binaries_executed': False,
              'limits': 'One updater and one validated direct caller; no exhaustive caller census, indirect/helper closure, Rust implementation, runtime equivalence or progress gate.'}
    (output / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT / 'work/file-tracker-update-94')
    parser.add_argument('--objdump', default='objdump')
    parser.add_argument('--readelf', default='readelf')
    parser.add_argument('--second-objdump')
    args = parser.parse_args()
    try:
        print(json.dumps(generate(args.binary.resolve(), args.output, args.objdump, args.readelf, args.second_objdump), indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'file-tracker update: {error}\n')
