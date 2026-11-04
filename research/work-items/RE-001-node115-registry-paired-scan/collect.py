#!/usr/bin/env python3
"""Authenticate and export one bounded node115 static node115 research packet.

No target execution, instruction evaluation or emulation is performed.
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
CONFIG = {'ranges': [['0x560f890', '0x560fa10'], ['0x560eb10', '0x560f890']],
 'locations': [['0x648b978', 'l1/src/dex_registry/dex_registry.rs', 37, 48]],
 'scope': 'Paired registry row counts, scan order, short-circuit result and actual caller branches; helper '
          'predicates and original policy names unclosed',
 'facts': {'first_stride': 1296,
           'second_stride': 512,
           'first_field_offset': 96,
           'second_field_offset': 392,
           'mismatch_bound': 'min of reloaded lengths after diagnostic returns',
           'argument_bytes': 20,
           'first_helper': '0x4716be0',
           'second_helper': '0x5a1d500',
           'tail_helper': '0x5a1d230'},
 'anchors': {'0x560f8a1': '4c8b3f4c8b7708498b5e10493b5f107421488d35bfc0e700',
             '0x560f8b2': '488d35bfc0e700bf05000000ff15e455ed00498b5e10498b47104839d8480f42d84c896424204d8b642418',
             '0x560f8d3': '4c896424204d8b6424184885db0f84db000000',
             '0x560f8e6': '4d8b76084d8b7f084981c6880100004983c7604889e541b50190',
             '0x560f900': '418b44241089442410410f1004240f2904244c89ff4889eee8c37210ff',
             '0x560f920': '8b05d2e1ee0085c075574885ed488d054ce1ee00480f44e848837d20000f85bb000000418b442410',
             '0x560f938': '48837d20000f85bb000000',
             '0x560f943': '418b44241089442410410f1004240f2904244c89f74889e54889eee89ddb4000',
             '0x560f963': '4885c00f85920000004981c6000200004981c71005000048ffcb7581',
             '0x560f9c1': '488b442420488b7810418b44241089442410410f1004240f2904244889e6e84cd84000',
             '0x560f9e4': '41b5014885c07512488b442420488b40204883782000410f95c5',
             '0x560f550': 'e83b03000066bb820184c08b4424287406',
             '0x560f581': '488d7c2440e80503000066bb830184c074096641891e'},
 'tables': []}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(data, address, size):
    matches = [s for s in sections(data) if s['type'] != 8
               and s['address'] <= address <= address + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'ambiguous or absent file mapping')
    offset = matches[0]['offset'] + address - matches[0]['address']
    return offset, bytes(data[offset:offset + size])


def anchors(data):
    for address, raw in CONFIG['anchors'].items():
        wanted = bytes.fromhex(raw)
        require(read(data, int(address, 16), len(wanted))[1] == wanted,
                'changed native anchor at ' + address)
    for table in CONFIG['tables']:
        base = int(table['va'], 16)
        raw = read(data, base, len(bytes.fromhex(table['raw'])))[1]
        require(raw.hex() == table['raw'], 'changed dispatch data')
        targets = [hex(base + offset) for (offset,) in struct.iter_unpack('<i', raw)]
        require(targets == table['targets'], 'inconsistent relative dispatch targets')
    return dict(CONFIG['facts'])


def collect(data, output):
    require(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == SHA,
            'node115 identity mismatch')
    facts = anchors(data)
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
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C'}
    output.mkdir(parents=True, exist_ok=True)
    versions = {}
    for tool in ['objdump', 'readelf']:
        versions[tool] = subprocess.check_output([tool, '--version'], text=True, env=env).splitlines()[0]
        require('GNU' in versions[tool], 'GNU binutils required')
    with tempfile.TemporaryDirectory(prefix='node115-arithmetic-static-') as directory:
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
            calls = []
            for pc, code in ins.items():
                if len(code) == 5 and code[0] == 0xe8:
                    calls.append({'pc': hex(pc), 'kind': 'direct', 'target': hex(pc + 5 + struct.unpack('<i', code[1:])[0])})
                elif len(code) == 6 and code[:2] == b'\xff\x15':
                    slot = pc + 6 + struct.unpack('<i', code[2:])[0]
                    slots.add(slot)
                    calls.append({'pc': hex(pc), 'kind': 'rip-slot', 'slot': hex(slot)})
            frame = index[start, end]
            unwind = {}
            for name in ['fde', 'cie']:
                addr = frame[name]
                length = struct.unpack('<I', read(data, addr, 4)[1])[0] + 4
                unwind[name] = {'va': hex(addr), 'raw': read(data, addr, length)[1].hex()}
            (output / f'{start:x}.objdump.txt').write_text(raw)
            rows.append({'start': hex(start), 'end': hex(end), 'file_offset': offset,
                         'bytes': len(body), 'instructions': len(ins), 'sha256': hashlib.sha256(body).hexdigest(),
                         'unwind': unwind, 'lsda': None if frame['lsda'] is None else hex(frame['lsda']), 'calls': calls})
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
            lines = [line for line in native_rels.splitlines() if re.match(r'^[0-9a-f]+\s', line) and int(line.split()[0], 16) == slot]
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
    for table in CONFIG['tables']:
        require(all(int(pc, 16) in decoded for pc in table['targets']), 'dispatch target outside measured instructions')
    record = {'dispatch_tables': CONFIG['tables'], 'target': 'node115', 'target_sha256': SHA, 'base': '8fd8db680ec4bfef40996e5616bce3d5156d0b86',
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
