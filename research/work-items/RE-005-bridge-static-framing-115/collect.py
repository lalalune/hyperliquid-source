#!/usr/bin/env python3
"""Authenticate and export one bounded node115 bridge static framing packet.

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
CONFIG = {'ranges': [['0x4302cd0', '0x4302e41'], ['0x4526e40', '0x45270f8'], ['0x169e350', '0x169e59b'], ['0x169c190', '0x169c2ad'], ['0x169dcc0', '0x169de5b'], ['0x169e650', '0x169e6ca'], ['0x169e6d0', '0x169e7c0'], ['0x169e1d0', '0x169e342'], ['0x169e5a0', '0x169e649'], ['0x169df80', '0x169e1c4'], ['0x169bf30', '0x169c18a']], 'locations': [['0x648f278', 'l1/src/bridge_request.rs', 83, 78]], 'scope': 'Private bridge two-token construction and conditional static-word framing, with explicit generic codec/copy/allocation gaps', 'facts': {'token_count': 2, 'token_stride': 40, 'first_raw_tag': 0, 'first_payload_bytes': 20, 'second_raw_tag': 1, 'second_payload_bytes': 32, 'mediate_stride': 32, 'head_each': 32, 'tail_each': 0, 'conditional_static_bytes': 64, 'word_scratch_allocation_request': 2048, 'whole_encoding_executed': False, 'whole_bridge_implemented': False}, 'anchors': {'0x4302cdf': 'bf50000000ff1596c71d02', '0x4302cf6': '418b471089442419410f10070f11442409c644240800', '0x4302d0c': 'bf20000000ff1569c71d024885c00f84b2000000410f104714410f104f240f1148100f1100', '0x4302d31': '488b4c242848894b200f104424080f104c24180f114b100f1103c643280148c74330200000004889433848c7434020000000', '0x4302d63': '48c74424080200000048895c241048c744241802000000ba020000004c89f74889deff15b5d31d02', '0x4302d90': '4983ff50740f4a8d3c3b4983c728e83dcda8ffebebbe500000004889df31d2ff15ebc61d024c89f04883c4305b415e415fc3', '0x169dccc': '4889fb440fb626488d0552daddfe4a630ca04801c1ffe1', '0x169dce3': '4889730848b80000000001000000488903e92b010000', '0x169ddb9': '488b46184883f8e00f87870000004883c01f48c1e80589430448897308c70300000000eb46', '0x169e654': '8b0fb8200000008d51fe83fa0373055b415e5dc385c975128b47043dffffff077747c1e0055b415e5dc3', '0x169e6d7': '8b0731db488d0da2d0ddfe486304814801c8ffe0', '0x169e78c': '89d84883c4085b415e415f5dc348', '0x169e3b0': '4c89efe8980200004101c40f82460100004c89efe80703000001c50f822a0100004983c52049ffcf75d64401e50f8231010000', '0x169e3e5': '4189ef4d89fc49c1e4054c89e7ff158810e404', '0x169e1f0': '4989d549c1e50531c04989f40f1f400089c54c89e7e84604000001e872594983c42049ffcf75e9', '0x169e220': '89c54c89ff4c89f689c2e8710300004c89ffe89904000001e872394983c7204983c4e075db', '0x169e5f9': '85c07516488b77084889df4883c4085b415e415f5de96df9ffff', '0x169e02c': 'c74424180000000048c7442410000000008b46118944242c0f1046010f1144241c4c8b73104c3b3375094889dfff150141e404488b43084c89f148c1e1050f104424100f104c24200f114c08100f110408', '0x169e082': '488b4618488904244c8d681f49c1ed050f84da000000488b6e104c8b34244183e61fb8200000004c0f44f04531ffeb40', '0x169e0c0': '488b43084c89e148c1e1050f284424400f284c24500f114c08100f11040849ffc44c8963104983c72049ffcd0f8480000000', '0x169e0f2': '0f57c00f294424500f294424404983fd01ba20000000490f44d64a8d343a483b3424776b498d342f488d7c2440ff15e313e404', '0x169c1a7': '4c29fe48bacdcccccccccccccc4889f048f7e248b8d8ffffffffffff9f4839c6760b31ff4c89eeff15c432e4044889fb4c39f974664989d64989d54983e5e04c89efff159132e404'}}
DATA = {4699948: 'b72522018d26220136262201b7252201b7252201b725220136262201cd25220169262201cd252201', 4700036: '0830220108302201672f2201c32f22017e2f2201', 4700016: '202b2201202b22013b2b2201ac2b22014a2b2201', 4699988: 'd82822012e2922015f2822018028220180282201e52922015f282201'}

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
    for address, raw in DATA.items():
        require(read(data,address,len(bytes.fromhex(raw)))[1].hex()==raw,'changed selected scalar '+hex(address))
    facts=dict(CONFIG['facts'])
    facts['token_count']=struct.unpack('<I',read(data,0x4302d7b,4)[1])[0]
    facts['first_raw_tag']=read(data,0x4302d0b,1)[1][0]
    facts['second_raw_tag']=read(data,0x4302d4e,1)[1][0]
    facts['second_payload_bytes']=struct.unpack('<I',read(data,0x4302d0d,4)[1])[0]
    facts['dispatch_targets']={hex(a):[hex(a+x) for x in struct.unpack('<'+'i'*(len(bytes.fromhex(raw))//4),bytes.fromhex(raw))] for a,raw in DATA.items()}
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
                    require(start!=0x4302cd0 or target in ins,'new helper direct branch escape')
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
                if code in [bytes.fromhex('41ffd6'), bytes.fromhex('ffd0')]:
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
                         'unwind': unwind, 'lsda': None if frame['lsda'] is None else hex(frame['lsda']), 'calls': calls, 'branches': branches, 'role': 'new-private-builder-question' if start==0x4302cd0 else 'credited-caller-or-conditional-codec-context'})
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
              'implementation_bytes': 0, 'requested_gates': [], 'new_helper_bytes':next(row['bytes'] for row in rows if row['start']=='0x4302cd0'), 'conditional_framing_context_bytes':sum(row['bytes'] for row in rows if row['start']!='0x4302cd0'), 'readonly_context_data':[{'va':hex(a),'raw':raw} for a,raw in DATA.items()]}
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
