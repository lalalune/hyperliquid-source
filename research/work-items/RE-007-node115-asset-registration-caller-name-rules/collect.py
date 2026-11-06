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
CONFIG = {'ranges': [['0x38b3f90', '0x38b4546'],
            ['0x447d760', '0x447db37'],
            ['0x3f10940', '0x3f109b2'],
            ['0x44e59d0', '0x44e5a9c']],
 'locations': [['0x648b990', 'l1/src/dex_registry/clearinghouses.rs', 11, 29],
               ['0x648b9a8', 'l1/src/dex_registry/clearinghouses.rs', 17, 33],
               ['0x6483e20', 'l1/src/dex_registry/perp_dex.rs', 34, 33],
               ['0x63fe278',
                '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sync/once.rs',
                219,
                20]],
 'data_slots': ['0x64df9f0',
                '0x64df6a0',
                '0x64e6bc8',
                '0x64df4c0',
                '0x64df4a0',
                '0x64df480',
                '0x64df498',
                '0x64e69b8',
                '0x64df6e8',
                '0x64df6c8',
                '0x64e6010',
                '0x64df508',
                '0x64df9f8',
                '0x648c5f8',
                '0x6484140',
                '0x64f01c0'],
 'scope': 'Caller of the registration entry, its pre-registration rule check, the 0x120-byte element push '
          'and the name character scan; no value semantics of calls outside the four extents',
 'facts': {'ok_tag': 418,
           'tag_err_unwrap_value': 342,
           'tag_count_limit': 341,
           'tag_name_too_long': 344,
           'tag_name_prefix_mismatch': 342,
           'tag_message': 240,
           'element_stride_state': 1296,
           'element_stride_front': 512,
           'boxed_direct_object_bytes': 1808,
           'sub_record_stride': 288,
           'count_hard_limit': 9999,
           'kind_limit_table': [15, 100, 100, 150],
           'name_length_rejected_above': 100,
           'suffix_length_accepted': [1, 9],
           'suffix_alphabet': 'A-Z0-9',
           'messages': ['cross margin not supported',
                        'Too many assets in perp dex',
                        'asset name only accepts upper case characters and digits',
                        'asset name must be between 1 and 9 characters'],
           'once_guard_initial_dword': 3},
 'anchors': {'0x434aac': 'c0013a00',
             '0x43e2f6': '216173736574206e616d65206d757374206265206265747765656e203120616e6420c00b',
             '0x4575a0': '0f00000000000000640000000000000064000000000000009600000000000000',
             '0x7d24a5': '63726f7373206d617267696e206e6f7420737570706f72746564',
             '0x7d24bf': '546f6f206d616e792061737365747320696e207065727020646578',
             '0x7d24da': '6173736574206e616d65206f6e6c7920616363657074732075707065722063617365206368617261637465727320616e6420646967697473',
             '0x38b3fb7': '8b051bc2c30285c04889742410',
             '0x38b3fe2': '66c74424205601',
             '0x38b3ff3': '488b4c2410488b1148895424084883fa017539',
             '0x38b4032': '48690424100500004801c3',
             '0x38b4047': '488d9800020000',
             '0x38b4053': '4889de4c89fa4889e94d89e8e8fc96bc00',
             '0x38b4064': '0fb74424203da2010000',
             '0x38b4074': '4c8b4424284c8b4c2430807c240800',
             '0x38b40ac': '4869e91005000048036808',
             '0x38b40f3': '4889d848c1e009',
             '0x38b41b2': '488dab000200004989dd',
             '0x38b41bc': '498b473048898424e0000000410f1007410f104f10410f1057200f299424d00000000f298c24c00000000f298424b0000000488d7c2420488d8c24b00000004889ee488b9424a0000000e8557dbb00',
             '0x38b422d': '4c89efe80bc76500',
             '0x38b4235': '807c241c00746b',
             '0x38b4285': 'e8367431004881c5a0010000488d742420488d9424b00000004889efff152129c302',
             '0x38b42a7': '488b4c2410488b4110498946180f1001410f1146086641c706a201e98a000000',
             '0x38b432d': '4889dfe80b5a0400488dbb00020000e8df740400be100700004889df31d2ff154fb1c202',
             '0x38b4366': '488d0553bec30248898424b0000000488d8424b00000004889442420488d3d4fbec302488d0dc09eb4024c8d05e19eb402488d542420be01000000',
             '0x38b43c0': '66c74424205601488d3d44eef1fc488d0d2382bd024c8d05b475bd02488d542420be2b000000ff15b4b2c202',
             '0x38b4454': '488d3d9f51f1fc488d0ddefcbc024c8d05b7f9bc02488d542420be2b000000ff1527b2c202',
             '0x3f10957': '4c8b73104c3b3375094889dfff15a7565d02',
             '0x3f10969': '4b8d3cf648c1e70548037b08488d742408ba20010000ff1583eb5c02',
             '0x43cd590': '4889f0488b7708488b57104889c7',
             '0x447d778': '31ff483bbe780300007112483d0f270000767566c7035501e95f010000',
             '0x447d795': '0fb679014c8d0d009efdfb493b04f9736f',
             '0x447d7a6': '8039000f84ad000000807a34000f85a3000000bf1a000000',
             '0x447d7e2': '66c703f000',
             '0x447d800': '4531f64c8973084c897b1066c703a201e9df000000',
             '0x447d815': 'bf1b000000',
             '0x447d864': '488b86a00400004889442408488d0519fdf4ff4889442410488d352972fbfb488d7c2430488d4424084989d44889c2',
             '0x447d89c': '4d8b6c24104983fd64760b66c703580148894308eb2b',
             '0x447d8b7': '4d39e5721c488b68084c8b7c24384c89ff4889ee4c89e2ff152421060285c07431',
             '0x447d8d8': '66c7035601',
             '0x447d90e': '4d89ef4d29e748c7442450090000000f94c04983ff0a0f93c108c17466',
             '0x447d991': '4901ec4901ed4c896424084c896c2410488d7c2408e825800600',
             '0x447d9af': 'bf38000000',
             '0x447da0f': '48b8000000000000008048ffc0493986080400004c8b6c242875054531f6eb2d',
             '0x447da2f': '488d7c24704c89e64c89fa488b4c2448ff15738f06020fb74424703da20100007529',
             '0x447da51': '41be010000004c8b7c2478',
             '0x44e59f0': '8d72a583fee6400f92c683c2c683faf60f92c24020f24989c880fa01',
             '0x44e5a96': '31c0c3b001c3'},
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
    with tempfile.TemporaryDirectory(prefix='node115-registration-static-') as directory:
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
        for slot in CONFIG.get('data_slots', []):
            slots.add(int(slot, 16))
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
        windows = [(int(a, 16), int(b, 16)) for a, b in CONFIG['ranges']]
        for pc in CONFIG['anchors']:
            # Anchors inside an exported extent must start an exported instruction;
            # the remaining anchors are bytes of read-only data outside every extent.
            inside = any(a <= int(pc, 16) < b for a, b in windows)
            require((int(pc, 16) in decoded) if inside else True,
                    'anchor not an exported instruction boundary')
        (output / 'frames.txt').write_text('\n\n'.join(blocks) + '\n')
        (output / 'relocations.txt').write_text('\n'.join(native_lines) + '\n')
    for table in CONFIG['tables']:
        require(all(int(pc, 16) in decoded for pc in table['targets']), 'dispatch target outside measured instructions')
    record = {'dispatch_tables': CONFIG['tables'], 'target': 'node115', 'target_sha256': SHA, 'base': '05bc2de303c05525b71e7e257426e741bc66a390',
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
