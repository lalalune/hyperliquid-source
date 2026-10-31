#!/usr/bin/env python3
"""Bind one node94 diagnostic's raw fields to observed formatter name slices.

Static only. Native tools receive small copied spans, never the captured ELF
pathname. This is not a Rust enum, reader implementation or runtime renderer.
"""
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

import bincode_varint as bv

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = bv.SHA256
SIZE = 91774280
RANGES = {
    'diagnostic-parent': (0x14F68E0, 0x14F722D),
    'name-reference': (0x14F7310, 0x14F733F),
    'name-value': (0x14F7910, 0x14F793C),
    'raw-builder': (0x466DAC0, 0x466DACE),
}
ANCHORS = {
    0x14F68ED: '4889f34c8b27410fb60424488d0dd969d2fe486304814801c8ffe0',
    0x14F6BFA: ('4d8d7424014983c4024c89642420488b3b488b4308488d354067d2feba12000000ff5018'
                '48895c240888442410c644241100488d352542d1fe4c8d05e68d17044c8b3d87762704'
                '488d5c2408ba080000004889df4c89f141ffd7488d350d67d2fe4c8d05de8d1704'
                '488d4c2420ba050000004889df41ffd7e92c020000'),
    0x14F7310: '488b070fb600c1e003488d0d8061d2fe488b1408488d0d55881704488b0408488b3e488b4e08488b49184889c6ffe1',
    0x14F7910: '0fb607c1e003488d0d835bd2fe488b1408488d0d58821704488b0408488b3e488b4e08488b49184889c6ffe1',
    0x466DAC0: '4889f8c6070340887701885702c3',
}
LABELS = ('U8', 'U16', 'U32', 'U64', 'U128', 'Usize', 'I8', 'I16', 'I32', 'I64', 'I128', 'Isize', 'Reserved')
LITERAL_VAS = (0x21D44A, 0x21D44C, 0x21D44F, 0x21D452, 0x209ED0, 0x21D455,
               0x21D45A, 0x21D45C, 0x21D45F, 0x21D462, 0x20A110, 0x21D465, 0x20B0A0)
POINTERS = 0x566FB80
LENGTHS = 0x21D4A0


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def derive(data):
    """Local byte obligations; production admission is separately mandatory."""
    secs = bv.sections(data)

    def off(va, size=1):
        rows = [s for s in secs.values() if s['addr'] and s['addr'] <= va
                and va + size <= s['addr'] + s['size']]
        require(len(rows) == 1, f'VA range {va:#x}+{size} is not uniquely section-bound')
        result = rows[0]['offset'] + va - rows[0]['addr']
        require(result + size <= len(data), 'Selected file range is truncated')
        return result

    fdes = bv.fde_extents(data, secs)
    for name, (start, end) in RANGES.items():
        require(fdes.get(start) == end, f'{name}: FDE extent changed')
    for va, expected in ANCHORS.items():
        want = bytes.fromhex(expected)
        require(data[off(va, len(want)):off(va, len(want)) + len(want)] == want,
                f'Instruction obligation at {va:#x} changed')
    table = 0x21D2D8
    displacement = struct.unpack_from('<i', data, off(table + 12, 4))[0]
    require(table + displacement == 0x14F6BFA, 'Diagnostic dispatch entry3 changed')

    rela = secs['.rela.dyn']
    wanted = {POINTERS + 8 * i for i in range(13)} | {0x566FA38, 0x566FA58, 0x576E2C8}
    entries = {va: [] for va in wanted}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, pos)
        if where in entries:
            entries[where].append((info, addend, pos))

    def binding(slot, expected):
        matches = entries[slot]
        require(len(matches) == 1, f'RELA slot {slot:#x} is not unique')
        info, addend, pos = matches[0]
        require(info == 8 and addend == expected, f'RELA binding {slot:#x} changed')
        require(struct.unpack_from('<Q', data, off(slot, 8))[0] == 0,
                f'Original pointer-slot bytes {slot:#x} changed')
        return {'slot_va': hex(slot), 'record_file_offset': hex(pos), 'type': 8,
                'symbol_index': 0, 'addend_va': hex(addend), 'original_word': 0}

    rows = []
    for i, (label, va) in enumerate(zip(LABELS, LITERAL_VAS)):
        link = binding(POINTERS + i * 8, va)
        size = struct.unpack_from('<Q', data, off(LENGTHS + i * 8, 8))[0]
        require(size == len(label), f'Name length at index{i} changed')
        literal = data[off(va, size):off(va, size) + size]
        try:
            text = literal.decode('utf-8')
        except UnicodeDecodeError as error:
            raise EvidenceError(f'Name UTF-8 at index{i} changed') from error
        require(text == label, f'Name literal at index{i} changed')
        rows.append({'raw_index': i, 'length_slot_va': hex(LENGTHS + i * 8),
                     'length': size, 'literal_va': hex(va), 'literal_file_offset': hex(off(va, size)),
                     'literal': text, 'literal_sha256': digest(literal), 'relocation': link})
    descriptors = []
    for va, words, target, indirection in [(0x566FA20, (0, 1, 1, 0), 0x14F7910, 'byte at supplied address'),
                                           (0x566FA40, (0, 8, 8, 0), 0x14F7310, 'byte through supplied pointer')]:
        require(struct.unpack_from('<QQQQ', data, off(va, 32)) == words, f'Descriptor words {va:#x} changed')
        descriptors.append({'va': hex(va), 'raw_words': list(words),
                            'format_slot': binding(va + 24, target), 'observed_read': indirection})
    helper = binding(0x576E2C8, 0x1571F50)
    for va, literal in [(0x21D356, b'InvalidIntegerType'), (0x20AE58, b'expected'), (0x21D368, b'found')]:
        require(data[off(va, len(literal)):off(va, len(literal)) + len(literal)] == literal,
                f'Diagnostic literal {va:#x} changed')

    hdr = secs['.eh_frame_hdr']
    count = struct.unpack_from('<I', data, hdr['offset'] + 8)[0]
    selected = {}
    by_start = {start: (name, end) for name, (start, end) in RANGES.items()}
    for i in range(count):
        start_rel, fde_rel = struct.unpack_from('<ii', data, hdr['offset'] + 12 + i * 8)
        start, fde_va = hdr['addr'] + start_rel, hdr['addr'] + fde_rel
        if start not in by_start:
            continue
        name, end = by_start[start]
        pos = off(fde_va, 16)
        length, cie_pointer = struct.unpack_from('<II', data, pos)
        require(length == (0x58 if name == 'diagnostic-parent' else 0x10),
                f'{name}: FDE record length changed')
        cie_va = fde_va + 4 - cie_pointer
        require(cie_va == 0xCE1518, f'{name}: CIE reference changed')
        cie_pos = off(cie_va, 8)
        cie_size = struct.unpack_from('<I', data, cie_pos)[0] + 4
        cie = data[cie_pos:cie_pos + cie_size]
        require(cie.hex() == '1400000000000000017a5200017810011b0c070890010000', f'{name}: CIE bytes changed')
        body = data[off(start, end - start):off(start, end - start) + end - start]
        selected[name] = {'start_va': hex(start), 'end_va': hex(end), 'file_offset': hex(off(start)),
                          'bytes': len(body), 'body_sha256': digest(body), 'fde_va': hex(fde_va),
                          'fde_file_offset': hex(pos), 'fde_bytes': data[pos:pos + 4 + length].hex(),
                          'cie_va': hex(cie_va), 'cie_bytes': cie.hex()}
    return {'schema': 're005-integer-error-names/1', 'target_sha256': digest(data), 'target_bytes': len(data),
            'fde_index_entries': count, 'selected_fdes': selected,
            'builder': {'tag_offset': 0, 'tag': 3, 'sil_offset': 1, 'dl_offset': 2},
            'diagnostic_arm': {'dispatch_table': hex(table), 'tag3_target': '0x14f6bfa',
                               'selected_end': '0x14f6c77', 'label': 'InvalidIntegerType',
                               'expected_field': {'record_offset': 1, 'descriptor': '0x566fa20', 'call_va': '0x14f6c51'},
                               'found_field': {'record_offset': 2, 'pointer_on_stack': True,
                                               'descriptor': '0x566fa40', 'call_va': '0x14f6c6f'},
                               'opaque_field_helper': helper},
            'descriptors': descriptors, 'pointer_window': [hex(POINTERS), hex(POINTERS + 13 * 8)],
            'length_window': [hex(LENGTHS), hex(LENGTHS + 13 * 8)], 'observed_name_rows': rows,
            'local_index_guard': False, 'uninspected_indices': '13..255; no behavior claimed',
            'nominal_type_or_runtime_rendering_claimed': False, 'component_gates_requested': False}


def analyze(data):
    require(len(data) == SIZE and digest(data) == SHA256, 'Input is not authenticated node94')
    return derive(data)


def verify_listing(text, body, base, selected=()):
    cursor, starts = base, set()
    for line in text.splitlines():
        parts = line.split('\t')
        if len(parts) < 3 or not re.fullmatch(r'\s*[0-9a-f]+:', parts[0]):
            continue
        address = int(parts[0].strip()[:-1], 16)
        raw = bytes.fromhex(parts[1])
        require(raw and address == cursor and '(bad)' not in parts[2], 'Native instruction tiling changed')
        require(body[address - base:address - base + len(raw)] == raw, 'Native instruction bytes changed')
        starts.add(address)
        cursor += len(raw)
    require(cursor == base + len(body), 'Native listing does not cover complete selected span')
    require(set(selected) <= starts, 'Selected native instruction boundary is absent')
    return len(starts)


def native_evidence(data, records):
    version = subprocess.run(['objdump', '--version'], check=True, capture_output=True, text=True).stdout.splitlines()[0]
    require('GNU objdump' in version, 'GNU objdump is required for recorded native exports')
    output, counts, commands = {}, {}, {}
    with tempfile.TemporaryDirectory(prefix='integer-error-raw-') as folder:
        for name, (start, end) in RANGES.items():
            span = records['selected_fdes'][name]
            pos = int(span['file_offset'], 16)
            body = data[pos:pos + end - start]
            path = Path(folder) / (name + '.bin')
            with path.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(body)
            argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                    '--insn-width=16', '--adjust-vma=' + hex(start), str(path)]
            commands[name] = argv[:-1] + ['<owned-raw-span>']
            text = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
            require(path.read_bytes() == body, 'Owned raw span changed during native collection')
            selected = (0x14F6BFA, 0x14F6C51, 0x14F6C6F) if name == 'diagnostic-parent' else ()
            counts[name] = verify_listing(text, body, start, selected)
            output[name + '.objdump.txt'] = text.replace(str(path), '<node94-raw-' + name + '>')
    output['native.json'] = json.dumps({'tool': version, 'mode': 'owned small raw spans only',
                                      'commands': commands,
                                      'instruction_rows': counts,
                                      'whole_elf_path_reopened': False}, indent=2, sort_keys=True) + '\n'
    return output


def generate(binary, output):
    require(not output.exists(), 'Output already exists; retained evidence is preserved')
    data = binary.read_bytes()
    records = analyze(data)
    exports = native_evidence(data, records)
    exports['records.json'] = json.dumps(records, indent=2, sort_keys=True) + '\n'
    output.mkdir(parents=True, exist_ok=False)
    for name, value in exports.items():
        with (output / name).open('x') as stream:
            stream.write(value)
    return records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        records = generate(args.input, args.output)
    except (EvidenceError, bv.EvidenceError, OSError, struct.error, subprocess.SubprocessError) as error:
        print(f'bincode_integer_error_static: {error}', file=sys.stderr)
        return 1
    print(json.dumps({'target_sha256': SHA256, 'observed_name_rows': len(records['observed_name_rows']),
                      'component_gates_requested': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
