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
CONFIG = {'extra_slots': [],
 'data_anchors': {'0x451210': '00003043000030450000000000000000',
                  '0x450170': '00000000000030430000000000003045',
                  '0x5ed748': '000000000000f03f000000000000244000000000000059400000000000408f40000000000088c34000000000006af8400000000080842e41',
                  '0x4553c4': '000000000000000000000000'},
 'ranges': [['0x2774760', '0x277498f'], ['0x2357a10', '0x2357cfd']],
 'locations': [['0x643b3f8', 'l1/src/clearinghouse/oracle/oracle.rs', 438, 18],
               ['0x64768a8', 'l1/src/perp_meta.rs', 163, 38],
               ['0x6478258', 'l1/src/perp_meta.rs', 287, 28]],
 'scope': 'Quotient/remainder metadata guards, conversion result flag and native output projection; '
          'floating/decimal units and helper closure unmeasured',
 'facts': {'index_divisor': 10000,
           'metadata_byte_limit': 7,
           'result_present_tag': 1,
           'result_absent_tag': 0,
           'conversion_helper': '0x5c43c60'},
 'anchors': {'0x2774770': '488b0e48ba4b598638d6c56d344c89f048f7e2488b0148c1ea0b4869f2102700004c89f74829f7488b70104839f70f83d1010000',
             '0x277479b': '4839f70f83d1010000488b4908483b51500f85b6010000483b79100f83ac010000488b49084889fa',
             '0x27747c0': '4889fa48c1e2050fb64c111d4883f9070f83ac010000',
             '0x27747d6': '488b4008488d147f48c1e205be0600000029cef20f100410',
             '0x2774818': '66480f7ec848b9ffffffffffffff7f4821c148ba000000000000f07f4839d10f8d8d0000004889c248c1ea34',
             '0x277483d': '4889c248c1ea3448b9ffffffffffff0f004821c181e2ff070000742248c1e92089442430',
             '0x2774859': '48c1e92089442430c74424380000000081c900001000894c243481c2cdfbffffeb1e4885c97465',
             '0x2774899': '31c94885c00f99c1488d7c2408488d74243041b80100000041b901000000e8a4f34c03807c240800',
             '0x27748bc': '807c24080066c7442430b000754366c78424c0000000b000488dbc24c0000000e8af9a000031c0eb72',
             '0x277490d': '8b44240c89442420488b44241048894424248b4424188944242c488d7c2430e89fd7ab01660f10442420660f118424b0000000660f118424c4000000660f1143104c897308b801000000488903',
             '0x2774968': '488d3d391fd003ff15bbaed603488d157c6acc03ff159eacd603488d3dcf38d003ff15b9aed603',
             '0x2357a7e': 'e8ddcc4100807c242000'},
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
    for address, raw in CONFIG.get('data_anchors', {}).items():
        require(read(data, int(address, 16), len(bytes.fromhex(raw)))[1].hex() == raw, 'changed native data')
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
        slots.update(CONFIG.get('extra_slots', []))
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
                else:
                    op = code[1:] if code and 0x40 <= code[0] <= 0x4f else code
                    if len(op) >= 2 and op[0] == 0xff and (op[1] >> 3) & 7 == 2:
                        calls.append({'pc': hex(pc), 'kind': 'unresolved-indirect', 'raw': code.hex()})
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
    record = {'data_anchors': CONFIG.get('data_anchors', {}), 'dispatch_tables': CONFIG['tables'], 'target': 'node115', 'target_sha256': SHA, 'base': '8fd8db680ec4bfef40996e5616bce3d5156d0b86',
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
