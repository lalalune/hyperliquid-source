#!/usr/bin/env python3
"""Authenticate and export the node #115 clearinghouse notional-ratio body.

No target execution, instruction evaluation or emulation is performed.
The division proof is integer arithmetic over the decoded multiplier.
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

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODY = 0x44dcf80
CALLER = 0x3db8470
CALL = 0x3db8525
MAGIC = 0x346dc5d63886594b
CONFIG = {
    'ranges': [['0x44dcf80', '0x44dd1a4'], ['0x3db8470', '0x3db8983']],
    'locations': [
        ['0x648bb28', 'l1/src/clearinghouse/clearinghouse.rs', 179, 98],
        ['0x648ba20', 'l1/src/clearinghouse/oracle/oracle.rs', 433, 18],
        ['0x648ba50', 'l1/src/qtys/impl_ntl.rs', 70, 1],
    ],
    'constants': {
        '0x451210': '0000304300003045',
        '0x450170': '00000000000030430000000000003045',
        '0x459808': '000000000000e0c3',
        '0x459360': '000000000000e043',
        '0x458e50': 'ffffffffffffdf43',
    },
    'scope': ('Clearinghouse notional ratio at 0x44dcf80 and its one direct call; '
              'caller loop, panic ABI and MXCSR image are outside the arithmetic claim'),
    'facts': {
        'record_stride': 96,
        'field_offset': '0x20',
        'divisor': 10000,
        'magic': '0x346dc5d63886594b',
        'magic_shift': 75,
        'output_tag_absent': 0,
        'output_tag_applied': 1,
        'low_clamp_bits': '0xc3e0000000000000',
        'high_clamp_bits': '0x43e0000000000000',
        'cvtt_threshold_bits': '0x43dfffffffffffff',
        'nonfinite_limit_bits': '0x7fefffffffffffff',
        'direct_calls': ['0x3db8525'],
    },
    'anchors': {
        '0x44dcf91': '48ba4b598638d6c56d344889d848f7e24d8b042448c1ea0b4869d2102700004889d84829d0',
        '0x44dcfc7': '488d044048c1e0054c8b7402204d85f60f8839010000',
        '0x44dcfdd': '488b51104c0faff20f802b010000',
        '0x44dcff3': '4885c00f84a4000000',
        '0x44dd048': '498b4424180f57c0f2480f2a00f20f5ed9f20f59c366480f7ec0',
        '0x44dd062': '48beffffffffffffff7f4821f0660f57c948b9ffffffffffffef7f4839c87f32',
        '0x44dd082': 'f20f10157ec7f7fb660f2ed07714660f2e05c8c2f7fb770a660f28c8eb14',
        '0x44dd0a0': '31c0eb5d',
        '0x44dd0a4': 'f20f5fd0f20f100db0c2f7fbf20f5dca',
        '0x44dd0b4': 'f2480f2cc1660f2e0d8fbdf7fb480f47c631ed660f2ec9480f4be84989ed',
        '0x44dd0d2': '4d29f5704c',
        '0x44dd0d7': '4d8b6424204d8b3c244c89f84829e8706d4989042448895f08488957104c896f184c897720b801000000',
        '0x44dd101': '488907',
        '0x3db8487': '488d4648',
        '0x3db848f': '4c8d742408',
        '0x3db8494': '4889442408',
        '0x3db8510': '4883791000',
        '0x3db851c': '488b104c89e74c89f6e8564a7200807c244000',
    },
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def prove_divisor():
    """floor(x * MAGIC / 2**75) == x // 10000 for every x in 0..2**64."""
    require(MAGIC == ((1 << 75) + 9999) // 10000, 'magic is not ceil(2^75/10000)')
    require(10000 * MAGIC - (1 << 75) == 432, 'magic excess changed')
    # (x * 432) / 2**75 < 1/10000 for x < 2**64, so the positive error cannot
    # cross a multiple of 10000. The largest remainder is 9999.
    require((1 << 64) * 432 < (1 << 75), 'error bound exceeds one divisor')
    left = 9999 * (1 << 75) + ((1 << 64) - 1) * 432
    require(left < 10000 * (1 << 75), 'remainder can round across a boundary')


def read(data, address, size):
    matches = [s for s in sections(data) if s['type'] != 8
               and s['address'] <= address <= address + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'ambiguous or absent file mapping')
    offset = matches[0]['offset'] + address - matches[0]['address']
    return offset, bytes(data[offset:offset + size])


def anchors(data):
    prove_divisor()
    for address, raw in CONFIG['anchors'].items():
        wanted = bytes.fromhex(raw)
        require(read(data, int(address, 16), len(wanted))[1] == wanted,
                'changed arithmetic anchor at ' + address)
    for address, raw in CONFIG['constants'].items():
        wanted = bytes.fromhex(raw)
        require(read(data, int(address, 16), len(wanted))[1] == wanted,
                'changed constant pool at ' + address)
    return dict(CONFIG['facts'])


def direct_calls(data, target):
    text = next(s for s in sections(data) if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    found = []
    for pos in range(len(blob) - 5):
        if blob[pos] != 0xe8:
            continue
        dest = base + pos + 5 + struct.unpack_from('<i', blob, pos + 1)[0]
        if dest == target:
            found.append(base + pos)
    return found


def collect(data, output):
    require(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == SHA,
            'node115 identity mismatch')
    facts = anchors(data)
    calls = direct_calls(data, BODY)
    require([hex(pc) for pc in calls] == facts['direct_calls'], 'direct-call census changed')
    _, frames, _ = fde_extents(data)
    index = {}
    for frame in frames:
        key = frame['start'], frame['end']
        require(key not in index, 'duplicate unwind extent')
        index[key] = frame
    secs = sections(data)
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    rels = {}
    for slot, info, addend in struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']]):
        require(slot not in rels, 'duplicate relocation slot')
        rels[slot] = info, addend
    require(all(addend != BODY for _info, addend in rels.values()),
            'body address is present as a relocation addend')
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C'}
    output.mkdir(parents=True, exist_ok=True)
    versions = {}
    for tool in ['objdump', 'readelf']:
        versions[tool] = subprocess.check_output([tool, '--version'], text=True, env=env).splitlines()[0]
        require('GNU' in versions[tool], 'GNU binutils required')
    with tempfile.TemporaryDirectory(prefix='node115-ntl-ratio-') as directory:
        native = Path(directory) / 'node115.elf'
        native.write_bytes(data)
        native.chmod(0o400)
        native_frames = subprocess.check_output(['readelf', '-wf', str(native)], text=True, env=env)
        native_rels = subprocess.check_output(['readelf', '-rW', str(native)], text=True, env=env)
        rows, slots, sources, blocks = [], set(), [], []
        decoded = {}
        for start, end in CONFIG['ranges']:
            start, end = int(start, 16), int(end, 16)
            require((start, end) in index, 'Python FDE extent mismatch')
            block = [b for b in native_frames.split('\n\n') if f'pc={start:016x}..{end:016x}' in b]
            require(len(block) == 1, 'GNU FDE extent mismatch')
            blocks.extend(block)
            offset, body = read(data, start, end - start)
            raw = subprocess.check_output(['objdump', '-d', '-M', 'intel',
                f'--start-address={start}', f'--stop-address={end}', str(native)],
                text=True, env=env).replace(str(native), 'artifacts/node/115/hl-node')
            ins = decode_export(raw, start, end, body)
            raw = '\n'.join(line.rstrip() for line in raw.splitlines()) + '\n'
            decoded.update(ins)
            exported_calls = []
            for pc, code in ins.items():
                if len(code) == 5 and code[0] == 0xe8:
                    exported_calls.append({'pc': hex(pc), 'kind': 'direct',
                                           'target': hex(pc + 5 + struct.unpack('<i', code[1:])[0])})
                elif len(code) == 6 and code[:2] == b'\xff\x15':
                    slot = pc + 6 + struct.unpack('<i', code[2:])[0]
                    slots.add(slot)
                    exported_calls.append({'pc': hex(pc), 'kind': 'rip-slot', 'slot': hex(slot)})
            frame = index[start, end]
            unwind = {}
            for name in ['fde', 'cie']:
                addr = frame[name]
                length = struct.unpack('<I', read(data, addr, 4)[1])[0] + 4
                unwind[name] = {'va': hex(addr), 'raw': read(data, addr, length)[1].hex()}
            (output / f'{start:x}.objdump.txt').write_text(raw)
            rows.append({'start': hex(start), 'end': hex(end), 'file_offset': offset,
                         'bytes': len(body), 'instructions': len(ins),
                         'sha256': hashlib.sha256(body).hexdigest(),
                         'unwind': unwind,
                         'lsda': None if frame['lsda'] is None else hex(frame['lsda']),
                         'calls': exported_calls})
        body_row = next(row for row in rows if row['start'] == hex(BODY))
        require(all(call['target'] != hex(BODY) for call in body_row['calls'] if call['kind'] == 'direct'),
                'arithmetic body calls itself')
        caller_row = next(row for row in rows if row['start'] == hex(CALLER))
        require(any(call['kind'] == 'direct' and call['pc'] == hex(CALL) and call['target'] == hex(BODY)
                    for call in caller_row['calls']),
                'retained caller is missing the direct call')
        for loc in CONFIG['locations']:
            slot, path, line, column = int(loc[0], 16), loc[1], loc[2], loc[3]
            info, address = rels[slot]
            length, actual_line, actual_column = struct.unpack('<QII', read(data, slot + 8, 16)[1])
            require(info == 8 and length == len(path) and actual_line == line and actual_column == column
                    and read(data, address, length)[1] == path.encode(), 'Location binding mismatch')
            xrefs = []
            for pc, code in decoded.items():
                if len(code) == 7 and code[0] in (0x48, 0x4c) and code[1] == 0x8d and code[2] & 0xc7 == 5:
                    if pc + 7 + struct.unpack('<i', code[3:])[0] == slot:
                        xrefs.append(hex(pc))
            require(xrefs, 'no native instruction Location xref')
            slots.add(slot)
            sources.append({'slot': hex(slot), 'path': path, 'path_va': hex(address), 'line': line,
                            'column': column, 'raw_tail': read(data, slot + 8, 16)[1].hex(), 'xrefs': xrefs})
        bindings, native_lines = [], []
        for slot in sorted(slots):
            require(slot in rels, 'call slot missing relocation')
            info, addend = rels[slot]
            symbol = None
            if info >> 32:
                o = dynsym['offset'] + (info >> 32) * 24
                require(o + 24 <= dynsym['offset'] + dynsym['size'], 'symbol out of range')
                name = struct.unpack_from('<I', data, o)[0]
                require(name < dynstr['size'], 'symbol string out of range')
                begin = dynstr['offset'] + name
                stop = data.index(0, begin, dynstr['offset'] + dynstr['size'])
                symbol = bytes(data[begin:stop]).decode('ascii')
            lines = [line for line in native_rels.splitlines()
                     if re.match(r'^[0-9a-f]+\s', line) and int(line.split()[0], 16) == slot]
            require(len(lines) == 1, 'GNU relocation evidence missing')
            fields = lines[0].split()
            require(int(fields[1], 16) == info, 'GNU relocation info mismatch')
            if info == 8:
                require(fields[2] == 'R_X86_64_RELATIVE' and int(fields[3], 16) == addend,
                        'GNU relative addend mismatch')
            else:
                require(info & 0xffffffff == 6 and fields[2] == 'R_X86_64_GLOB_DAT'
                        and fields[4].split('@')[0] == symbol and fields[-2] == '+'
                        and int(fields[-1], 16) == addend, 'GNU import mismatch')
            native_lines.extend(lines)
            bindings.append({'slot': hex(slot), 'info': info, 'addend': hex(addend), 'symbol': symbol})
        for pc in CONFIG['anchors']:
            require(int(pc, 16) in decoded, 'anchor not an exported instruction boundary')
        (output / 'frames.txt').write_text('\n\n'.join(blocks) + '\n')
        (output / 'relocations.txt').write_text('\n'.join(native_lines) + '\n')
    record = {'target': 'node115', 'target_sha256': SHA,
              'base': '05bc2de303c05525b71e7e257426e741bc66a390',
              'method': 'GNU static exports plus independent ELF/FDE/relocation parsing; no target execution or emulation',
              'scope': CONFIG['scope'], 'facts': facts, 'windows': rows, 'source_locations': sources,
              'bindings': bindings, 'exported_bytes': sum(row['bytes'] for row in rows),
              'exported_instructions': sum(row['instructions'] for row in rows),
              'implementation_bytes': 0, 'requested_gates': []}
    (output / 'records.json').write_text(json.dumps(record, indent=2) + '\n')
    (output / 'tool-versions.json').write_text(json.dumps(versions, indent=2) + '\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    record = collect((ROOT / 'artifacts/node/115/hl-node').read_bytes(), args.output)
    if args.check:
        require(record == json.loads((PACKET / 'records.json').read_text()), 'retained record changed')
    print(json.dumps({'exported_bytes': record['exported_bytes'],
                      'exported_instructions': record['exported_instructions'],
                      'captured_target_executed': False, 'record_check': args.check}))
