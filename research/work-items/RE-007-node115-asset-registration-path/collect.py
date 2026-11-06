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
CONFIG = {'ranges': [['0x446bf60', '0x446c1fa'],
            ['0x3c42130', '0x3c4265d'],
            ['0x3c42660', '0x3c4287e'],
            ['0x3d16b20', '0x3d16b84']],
 'locations': [['0x646e428', 'l1/src/clearinghouse/oracle/oracle.rs', 110, 13],
               ['0x64768a8', 'l1/src/perp_meta.rs', 163, 38],
               ['0x6478258', 'l1/src/perp_meta.rs', 287, 28]],
 'scope': 'Registration of one indexed entry: parameter checks, name-record push, id composition, and the '
          '96-byte per-index state append; no value semantics of the helper calls, no caller closure',
 'facts': {'ok_tag': 418,
           'first_string_length_rejected_from': 101,
           'index_count_rejected_above': 9999,
           'id_modulus': 10000,
           'byte_param_rejected_above': 6,
           'u32_param_membership_checked_from': 50,
           'second_string_length_rejected_from': 101,
           'name_record_bytes': 32,
           'state_record_bytes': 96,
           'state_record_qword_fields_equal_to_value': ['+0x00', '+0x08', '+0x20', '+0x28', '+0x40', '+0x48'],
           'state_record_copy_fields': ['+0x10 qword,+0x18 dword', '+0x30 qword,+0x38 dword'],
           'state_record_constant_fields': '+0x50 qword and +0x58 dword read from rodata 0x7bd538/0x7bd540',
           'error_tags': {'0x158': 'a string length is not below 101',
                          '0x64': 'index count above 9999 or composed id fails the quotient/remainder check',
                          '0x3e': 'new name equals an existing name record',
                          '0x41': 'byte parameter above 6',
                          '0x16a': 'u32 parameter at or above 50 and the membership test fails (tree variant: no equal key; hash-helper variant: helper 0x4556c50 returns nonzero)',
                          '0x152': 'push rolled back after the id step failed'},
           'rollback_pops_name_record': True,
           'append_requires_index_equals_length': True,
           'map_update_flag_argument_value': 1},
 'anchors': {'0x3c42157': '4883fd6572244885c07410488b7c24184889c631d2ff152ed3890249896e186641c7065801',
             '0x3c42181': '488b4e104881f90f27000076186641c706640049894e08',
             '0x3c421b5': '0fb643358844240e8b43308944242c0fb643348844240f48894c2430',
             '0x3c421eb': '4c8b2d06d88902',
             '0x3c42209': '4b3b6c271075f04b8b742708488b7c24184889ea41ffd585c075dc',
             '0x3c42229': '6641c7063e00488b44241049894608488b4424184989461049896e18',
             '0x3c4224a': '807c240e0676104c8b7424206641c7064100',
             '0x3c42261': '448b6c242c44896c24404183fd324c8b7424204c8b7c24380f8332010000',
             '0x3c4227f': '488b53284883fa650f83960100004c8b6320',
             '0x3c4229f': '0fb74424403da20100000f85a2010000',
             '0x3c422bc': '488b4424104889442440488b442418488944244848896c24500fb644240e8844245d44896c24580fb644240f8844245c488d7424404c89ffe827480d00',
             '0x3c422f9': '498b7750b9102700004889f048f7e10f8004030000480344243048c7c1ffffffff480f43c8480f43c8',
             '0x3c42322': '498b7f1048ba4b598638d6c56d344889c848f7e248c1ea0b4c89bc24300100000f288424200100000f118424380100004839f20f85b70100004869c2102700004889ca4829c24839fa0f83a1010000',
             '0x3c42371': '488dbc24b0000000488db424300100004889cae8d70200006681bc24b0000000a201',
             '0x3c42399': '0f108424b8000000410f1146086641c706a201',
             '0x3c423b1': '31c0493b47307175',
             '0x3c423e5': '443bac90cc020000410f97c04180d800',
             '0x3c42423': '6641c7065801e9a0000000',
             '0x3c4242e': '498d7f30488d742440e8144891004885c00f843afeffff',
             '0x3c42445': '6641c7066a0145896e04',
             '0x3c42512': '66c78424b0000000640048898c24b8000000eb04',
             '0x3c425b3': '4885ff743548ffcf49897f10498b470848c1e705488b3438488b7c38086641c7065201',
             '0x3c42688': '4c89f048f7e248c1ea0b483b51500f85c80100004869d2102700004c89f04829d0483b41100f83b1010000',
             '0x3c426b3': '488b490848c1e0050fb644011d3c070f83a9010000',
             '0x3c426c8': '4889fbb10628c10fb6c9488d7c2410488db424e0000000ba02000000ff157e3d8a02',
             '0x3c426ea': '66817c2410a20175324c8b7c2418',
             '0x3d16b2b': '4c8b7f104c3b3f7509',
             '0x3d16b3d': '498b46084c89f948c1e1050f10030f104b100f114c08100f11040849ffc74d897e10',
             '0x446bf88': 'e8a3617dff',
             '0x446bf92': '3da20100000f8590000000',
             '0x446bf9d': '4c8934244c8b6c24184c8b742420',
             '0x446bfad': '493b87780300000f8002010000',
             '0x446bff5': '4c3b6cd010410f97c04180d800',
             '0x446c0c1': '48b94b598638d6c56d344c89e848f7e148c1ea0b4869c2102700004d89ec4929c4',
             '0x446c0ea': '498b875801000048894424104939c40f85dd000000',
             '0x446c0ff': '498dbf480100004c3b277506ff154fa00702',
             '0x446c111': '498b87500100004b8d0c6448c1e1054c8934084c89740808488b550048895408108b5508895408184c897408204c89740828488b550048895408308b5508895408384c897408404c89740848488b15d41335fc48895408508b15d11335fc8954085849ffc44d89a758010000',
             '0x446c17d': '48837c240801753548b8000000000000008049398778030000742248ffc04939870804000074164981c7280400004c89ff4c89ee488b1424e8e63887ff',
             '0x446c1ba': '4c896b084c89731066c703a201',
             '0x446c1dc': '4c8d0d45220002488db42488000000488d54241031ff31c9ff151e380702'},
 'data_slots': ['0x64df9f8'],
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
        for pc in CONFIG['anchors']:
            require(int(pc, 16) in decoded, 'anchor not an exported instruction boundary')
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
