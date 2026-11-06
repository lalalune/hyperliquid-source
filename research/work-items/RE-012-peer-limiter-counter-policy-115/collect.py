#!/usr/bin/env python3
"""Authenticate and export one bounded node115 static limiter packet.

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
CONFIG = {'ranges': [['0x595ec00', '0x595f2d7'], ['0x2af8be0', '0x2af9c09']], 'locations': [], 'scope': 'Complete caller-bound limiter FDE static counter/callback/return ordering, with all helpers opaque; no runtime rate/clock guarantee', 'facts': {'raw_charge_minimum': 1, 'budget_wrapping_factor': 10, 'key_bytes': 20, 'entry_cumulative': {'offset_before_cursor': -16, 'arithmetic': 'unsigned saturating addition'}, 'entry_count': {'offset_before_cursor': -8, 'arithmetic': 'unsigned saturating increment'}, 'strict_final_comparison': 'entry cumulative > wrapping10x budget', 'opaque_return_gate': 'AL !=0 from callback atstate+0x170 bypasses counters and yields0', 'overbudget_outcome': 'AL=1 regardless later callbackAL, conditional normal returns; separate source effects remain opaque'}, 'anchors': {'0x595ec2a': '488b6f104885ed0f84980000004c8b6f184c8b250e0fb800', '0x595ec46': '0fb785e600000048894424588d0485000000004c8d348048c7c3ffffffff', '0x595ec79': 'ba14000000488b7c240841ffd448984885c00f98c10f9fc028c848ffc34983c6ec4c89fe3c0174cf0fb6c085c0750d', '0x595ecb5': '4983ed017214488bacdde8000000e97affffff31ede93a050000', '0x595eccf': '4c8b7424504983fe014983d600', '0x595ecde': 'b10131c04c8b642438f0410fb00c240f852a050000', '0x595ed91': '31c04885c9480f4fc1', '0x595ed9a': '498d8c2460010000488b094889c24809ca48c1ea200f846201000031d248f7f1498d5c2408498b8c24680100004839c876084989842468010000', '0x595ee0c': '498b842470010000488b5424088b4a10894c2420f30f6f02660f7f442410488d7c2410ffd084c00f85c2030000', '0x595ee39': '488b4424404801c04c8d2c80', '0x595ee45': '498dbc2450010000488b742408e8e93a4fff4989c74889c548c1ed39', '0x595eff7': '4d0377f048c7c3ffffffff4c89f0480f42c3490f43c6498947f0', '0x595f011': '41833a01756166480f6ec0660f6205ec21affa660f5c054411affa660f28c8660f15c8f20f58c80f57c0f2490f2ac5f2410f59442410660f2ec8762b', '0x595f04d': '498dbc24d8010000488b4c24088b411089442420f30f6f01660f7f442410488d7424104c89eae8c89359ff', '0x595f078': '498b47f848ffc0480f44c3498947f831c0493b4424300f80d8000000', '0x595f132': '4c89e849f764244870304839c3762b', '0x595f141': '498dbc2478010000488b4c24088b411089442420f30f6f01660f7f442410488d7424104c89eae8d49259ff', '0x595f16c': '4d396ff00f8685000000498dbc24a8010000488b4c24088b411089442420f30f6f01660f7f442410488d742410e8729859ff40b50184c07558', '0x595f1a5': '48b8000000000000008049398424800000007444488d7c2410498db42460010000ff151c0eb800498db42480000000488b4c24088b41108944242cf30f6f01f30f7f44241c488d7c2468488d542410e847f24dff', '0x595f1fb': '31ed31c9b001f0410fb00c24752789e84881c4980000005b415c415d415e415f5dc3', '0x595f21d': '4c89e7ba00ca9a3bff15cd0fb800e9c3faffff4c89e731f6ff15fd1cb800ebcc', '0x2af8f0e': '488b842458040000488b4820488bbbb8000000488bb3c00000004883c610488d9424c00200004c8d8c24c000000041b810270000e8b95ce602e993000000', '0x2af8fba': '488bbbb8000000488d9424c00200004c8d8c24c000000041b840420f004889e9e8215ce60284c00f84b0000000'}}
DATA = {4526608: '00003043000030450000000000000000', 4522352: '00000000000030430000000000003045', 4535600: '7b14ae47e17a843f9a9999999999a93f'}

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
    # These are decoded immediate values; fixed instruction groups also bind
    # the surrounding arithmetic, flags, widths and control-flow destinations.
    for address, raw in DATA.items():
        require(read(data,address,16)[1].hex()==raw,'changed selected readonly data '+hex(address))
    facts = dict(CONFIG['facts'])
    facts['raw_charge_minimum'] = read(data, 0x595ecd7, 1)[1][0]
    require(facts['raw_charge_minimum'] == 1, 'changed charge minimum')
    sib = read(data, 0x595ee44, 1)[1][0]
    require(sib & 0x3f == 0, 'budget LEA must use RAX for index and base')
    facts['budget_wrapping_factor'] = 2 * (1 + (1 << (sib >> 6)))
    require(facts['budget_wrapping_factor'] == 10, 'changed double plus scale-four budget')
    facts['key_bytes'] = int.from_bytes(read(data, 0x595ec7a, 4)[1], 'little')
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
        rows, slots, sources, blocks = [], {0x64dfb50}, [], []
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
                    require(start!=0x595ec00 or target in ins,'new helper direct branch escape')
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
                         'unwind': unwind, 'lsda': None if frame['lsda'] is None else hex(frame['lsda']), 'calls': calls, 'branches': branches, 'role': 'new-helper-question' if start==0x595ec00 else 'credited-caller-context-2628'})
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
              'implementation_bytes': 0, 'requested_gates': [], 'new_helper_bytes':1751, 'credited_caller_bytes':4137, 'readonly_context_data':[{'va':hex(a),'raw':raw} for a,raw in DATA.items()]}
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
