#!/usr/bin/env python3
"""Authenticate and export one bounded node115 static signed-split packet.

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
CONFIG = {'ranges': [['0x3f10c10', '0x3f10ecf']], 'locations': [['0x6487460', 'l1/src/qtys/mod.rs', 835, 1]], 'scope': 'Private consumed-collection signed split: negative capped negation, positive checked100scale and saved-value u64 saturation; helper/map policies remain opaque', 'facts': {'positive_multiplier': 100, 'signed_negative_min_clamp': 9223372036854775807, 'zero_skips_entry_helpers': True, 'positive_overflow_skips_entry_helpers': True, 'positive_addition': 'saved old u64 plus scaled positive, unsigned saturation after diagnostic normal return', 'output_descriptor_bytes': 64, 'input_consumed_on_normal_path': True, 'whole_transform_implemented': False}, 'anchors': {'0x3f10c25': '48c74424680000000048c7442470080000000f57c00f11442478488b064889c148f7d9488974240848897c24587122', '0x3f10c54': '488b460831c94989c04885c00f95c274044c8b4618488b761088d131d24889cfeb55', '0x3f10c76': '4c8b46184d85c07428488b561031c94839c2480f43c84829ca4989c14929d14c89c14c29c977104901d031c94c89c0eb0631d231c031c9488b760848c1e2044801f248c1e0044801f048c1e1044801f1bf02000000', '0x3f10ccb': '48897c241048895424184889442420488974242848894c243048c744243800000000488944244048897424484c8944245048b8000000000000008048ffc8488944246041bf640000004c8dac2488000000488d6c2410', '0x3f10d30': '4889f248f7da48b800000000000000804839c6480f44542460488d7c24684889cee8aad5dcff', '0x3f10d5b': '4883ff02754f488b442418488b4c24204839c87522488d5424180f1042100f1102488944242848894c2430488b442418483b4424207474488d481048894c2418488d5008eb17', '0x3f10db0': '4889efe898298bff4885c0746f488b324885f67491488b080f8862ffffff', '0x3f10dce': '4889f049f7e770804989c6', '0x3f10dd9': '4c89ef488b34244889cae8b8ffdbff4c89efe830410000', '0x3f10df0': '4889c34c8b204c89e04c01f0720c488903e950ffffff', '0x3f10e0a': '31ff488d354d665702ff158f405d024d01f448c7c0ffffffff4c0f42e04c89e0ebd2', '0x3f10e2c': '0f104424680f104c2478488b5c24580f114b100f1103488b04240f10000f1048100f1143200f114b30', '0x3f10e55': '488b7c2408488b3748b800000000000000804839c6750b4883c708e84b32a2ffeb154885f67410488b7f0848c1e60431d2ff1514e65c02'}}
DATA = {}

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
                'changed arithmetic anchor at ' + address)
    facts=dict(CONFIG['facts'])
    facts['positive_multiplier']=struct.unpack('<I',read(data,0x3f10d10,4)[1])[0]
    facts['negative_min_word']=hex(struct.unpack('<Q',read(data,0x3f10d38,8)[1])[0])
    return facts


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

            import capstone
            cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
            cseq=list(cs.disasm(body,start))
            require([(i.address,bytes(i.bytes)) for i in cseq]==list(ins.items()),'Capstone/GNU full partition mismatch')
            branches=[]
            for i in cseq:
                if i.mnemonic.startswith('j'):
                    try:target=int(i.op_str,0)
                    except ValueError:branches.append({'site':hex(i.address),'target':'unresolved '+i.op_str});continue
                    require(start!=0x3f10c10 or target in ins,'new helper direct branch escape')
                    branches.append({'site':hex(i.address),'target':hex(target),'bytes':bytes(i.bytes).hex()})
            versions['capstone']=capstone.__version__
            versions['python']=sys.version
            decoded.update(ins)
            calls = []
            for pc, code in ins.items():
                if len(code) == 5 and code[0] == 0xe8:
                    calls.append({'pc': hex(pc), 'kind': 'direct', 'target': hex(pc + 5 + struct.unpack('<i', code[1:])[0])})
                elif len(code) == 6 and code[:2] == b'\xff\x15':
                    slot = pc + 6 + struct.unpack('<i', code[2:])[0]
                    slots.add(slot)
                    calls.append({'pc': hex(pc), 'kind': 'rip-slot', 'slot': hex(slot)})
            for pc, code in ins.items():
                if code in [bytes.fromhex('41ffd4'), bytes.fromhex('ffd0')]:
                    calls.append({'pc': hex(pc), 'kind': 'register-indirect', 'raw': code.hex(), 'target': 'unresolved runtime pointer'})
            calls.sort(key=lambda row: int(row['pc'], 16))
            frame = index[start, end]
            unwind = {}
            for name in ['fde', 'cie']:
                addr = frame[name]
                length = struct.unpack('<I', read(data, addr, 4)[1])[0] + 4
                unwind[name] = {'va': hex(addr), 'raw': read(data, addr, length)[1].hex()}
            (output / f'{start:x}.objdump.txt').write_text(raw)
            rows.append({'start': hex(start), 'end': hex(end), 'file_offset': offset,
                         'bytes': len(body), 'instructions': len(ins), 'sha256': hashlib.sha256(body).hexdigest(),
                         'unwind': unwind, 'lsda': None if frame['lsda'] is None else hex(frame['lsda']), 'calls': calls, 'branches': branches, 'role': 'new-private-split-question'})
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
    record = {'target': 'node115', 'target_sha256': SHA, 'base': '05bc2de303c05525b71e7e257426e741bc66a390',
              'method': 'GNU static exports plus independent ELF/FDE/relocation parsing; no target execution or emulation',
              'scope': CONFIG['scope'], 'facts': facts, 'windows': rows, 'source_locations': sources,
              'bindings': bindings, 'exported_bytes': sum(row['bytes'] for row in rows),
              'exported_instructions': sum(row['instructions'] for row in rows),
              'implementation_bytes': 0, 'requested_gates': [], 'new_helper_bytes':sum(row['bytes'] for row in rows), 'credited_context_bytes':0, 'readonly_context_data':[{'va':hex(a),'raw':raw} for a,raw in DATA.items()]}
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
