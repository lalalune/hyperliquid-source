#!/usr/bin/env python3
"""Authenticate and export one bounded node115 static subaccount-label packet.

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
CONFIG = {'ranges': [['0x366b350', '0x366b4f9'], ['0x366a620', '0x366ac91']], 'locations': [['0x6468aa8', 'l1/src/sub_account.rs', 75, 13]], 'scope': 'Subaccount label admission: original-byte length1..16, transformed-length-first duplicate comparison, rawtags and store-before-free ordering; transformation/lookup contracts open', 'facts': {'admitted_input_byte_lengths': [1, 16], 'invalid_tag': 232, 'duplicate_tag': 230, 'success_tag': 418, 'existing_record_stride': 64, 'byte_equality_import': 'bcmp', 'transformation_slot': '0x64df650', 'transformation_target': '0x141cc40', 'whole_subaccount_implemented': False}, 'anchors': {'0x366b35e': '4989fc498d40ef4883f8ef770c6641c70424e800e936010000', '0x366b377': '4989d64989f7488d7c24084889ce4c89c2ff15c242e702', '0x366b38e': '4c89ff4c89f6e8e7b40a0166b9a2014885c00f84eb000000488b58104885db0f84de000000', '0x366b3b3': '4c8924244c8b780848c1e306488b4424104889442428488b6c24184531f64c8d6c24304c8b257342e7024c897c2420eb32', '0x366b3f0': '85ed4989dd4c89fb4c89e54c8b7c24204c8b254942e7020f84af0000004983c6404c39f37473', '0x366b416': '4b8b7437084b8b5437104c89ef41ffd448396c24407543', '0x366b42d': '4989df4c89eb4c8b6c24384c89ef488b7424284989ec4889eaff15ac45e70289c5', '0x366b44e': '488b7424304885f674984c89ef31d2ff153d40e702eb8b', '0x366b470': '488b7424304885f67493488b7c243831d2ff151940e702eb84', '0x366b489': '4c8b242466b9a2016641890c24488b7424084885f6740d488b7c241031d2ff15f33fe702', '0x366b4ad': '4883c4485b415c415d415e415f5dc3', '0x366b4bc': '66b9e6004c8b24246641890c24488b7424084885f675cdebd8', '0x366b4d7': '4889c3488b7424084885f6740d488b7c241031d2ff15af3fe7024889dfe85755d802'}}
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

            import capstone
            cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
            cseq=list(cs.disasm(body,start))
            require([(i.address,bytes(i.bytes)) for i in cseq]==list(ins.items()),'Capstone/GNU full partition mismatch')
            branches=[]
            for i in cseq:
                if i.mnemonic.startswith('j'):
                    try:target=int(i.op_str,0)
                    except ValueError:branches.append({'site':hex(i.address),'target':'unresolved '+i.op_str});continue
                    require(start!=0x366b350 or target in ins,'new helper direct branch escape')
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
            known={int(c['pc'],16) for c in calls}
            for i in cseq:
                if i.mnemonic=='call' and i.address not in known:
                    calls.append({'pc':hex(i.address),'kind':'runtime-indirect','raw':bytes(i.bytes).hex(),'operand':i.op_str,'target':'unresolved runtime pointer'})
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
                         'unwind': unwind, 'lsda': None if frame['lsda'] is None else hex(frame['lsda']), 'calls': calls, 'branches': branches, 'role': 'new-private-label-guard' if start==0x366b350 else 'credited-caller-context'})
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
              'implementation_bytes': 0, 'requested_gates': [], 'new_helper_bytes':sum(row['bytes'] for row in rows if row['role']=='new-private-label-guard'), 'credited_context_bytes':sum(row['bytes'] for row in rows if row['role']=='credited-caller-context'), 'readonly_context_data':[{'va':hex(a),'raw':raw} for a,raw in DATA.items()]}
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
