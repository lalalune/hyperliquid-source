#!/usr/bin/env python3
"""Authenticate and export one bounded node115 private fee-floor packet.

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
CONFIG = {'ranges': [['0x36a58d0', '0x36a5d40'], ['0x63f0210', '0x63f0221'], ['0x63f0230', '0x63f0679'], ['0x63f0680', '0x63f0686'], ['0x63f0690', '0x63f0697'], ['0x63f06a0', '0x63f0711']], 'locations': [], 'scope': 'Private fee floor helper local input selection, two staged bounds, ternary floating dispatch and late result gate; math/validator/runtime environment remain conditional', 'facts': {'floor_epsilon': 5e-06, 'math_calls': 10, 'hardware_context': 'FMA3/FMA4 instruction forms only; software fallback not proved equivalent', 'unordered': 'JA lower-bound failures do not take unordered; no floating trap/MXCSR guarantee', 'late_success_head': 2, 'whole_gate_implemented': False, 'helper_results_supplied': False}, 'anchors': {'0x36a58dd': '488b17488b4f08488b4710f20f106718f20f104f20f20f105728f20f11542470f20f104730f20f105f38f20f115c2408f20f115c2478488b7210660f28ec4885f6740a488b5208f20f106cf2f8488b51104885d2740a488b4908f20f1064d1f8f20f105b40', '0x36a5942': '660f28fdf20fc2fd03660f28f7660f54f4f20f5de5660f55fc660f56fe', '0x36a5968': '488b48104885c97416488b4008f20f104cc8f8f20f114c2448f20f1020eb0af20f114c2448660f28e1f20f11a42488000000', '0x36a599a': 'f20f10250e39dbfc660f28ecf20f5ceaf20f59e9660f28ccf20f5cc8f20f116c2428f20f59cdf20f5ce3f20f59e1660f28c7f20f58c4f20f100db039dbfc660f2ec80f87f0000000', '0x36a59e2': 'f20f100dee38dbfc660f28d7f20f59d1660f28c4f20f11542420660f297c2430f20f11642410ff15c2b5e302', '0x36a5a0e': 'f20f105c2410660f28542430f20f100d6639dbfc660f2ec80f87a6000000f20f100dd433dbfcf20f59d1660f28c3f20f11542418ff1588b5e302', '0x36a5a48': 'f20f105c2410660f28542430f20f100d2c39dbfc660f2ec87770f20f100d7639dbfcf20f59d1660f28c3f20f11542468ff1552b5e302', '0x36a5a7e': 'f20f105c2410660f284c2430f20f1015f638dbfc660f2ed0773a660f28d1f20f58d1f20f100d0834dbfc660f28c3f20f11542460ff1518b5e302f20f105c2410660f28642430f20f1015bc38dbfc660f2ed0761b', '0x36a5ad2': '8b0500a7e40285c00f851402000031c04881c4180100005b415ec3', '0x36a5aed': 'f20f1005bb37dbfcf20f5c442408f20f59442428f20f11442408f20f100d993cdbfc660f28d4f20f59d1f20f115424284c8b35acb4e302660f28c341ffd6f20f11442450', '0x36a5b31': 'f20f100d9f37dbfcf20f10442408f20f1054242041ffd6f20f11442458f20f100db232dbfcf20f10442408f20f1054241841ffd6f20f11442418f20f100d6d38dbfcf20f10442408f20f1054246841ffd6f20f11442420f20f100d2033dbfcf20f10442408f20f1054246041ffd6f20f11442410f20f10442408f20f100df53bdbfcf20f1054242841ffd6f20f1015c437dbfc', '0x36a5bc4': '660f284c2430660f2ed00f87fefeffff660f2e5424100f87f2feffff660f2e5424200f87e6feffff660f2e5424180f87dafeffff660f2e5424580f87cefefffff20f10442408f20f58c1660f2ed00f87bafeffff660f2e5424500f87aefeffff', '0x36a5c24': '0f1005c5780ffd0f118424080100000f1005a6780ffd0f118424f8000000660f100586780ffd660f118424e8000000488d44244848898424b8000000488d44247048898424c0000000488d44247848898424c800000048899c24d0000000488d84248000000048898424d8000000488d84248800000048898424e0000000488dbc2498000000488db424b8000000e8396fed00488b8c2498000000b0014883f9020f8417feffff488bb424a000000083f9014885f60f8401feffff488bbc24a800000031d2ff15b197e302e9ecfdffff', '0x36a5cf4': '488d05c5a4e4024889842490000000488d84249000000048898424b8000000488d3dbea4e402488d0d2f85d5024c8d055085d502488d9424b8000000be01000000ff15b59ce302e9a0fdffff', '0x63f0210': '554889e5488b05e5fb1000ffd05dc30f0b', '0x63f0680': 'c4e2f1a9c2c3', '0x63f0690': 'c4e3f96bc210c3', '0x63f06a0': '8b057a82330085c0792a84c0488d0d7dfbffff488d15d6ffffff480f49d1a840488d05b9ffffff480f44c24889052ef71000ffe0554889e54883ec20f20f1155e8f20f114df0f20f1145f8e840000000f20f1045f8f20f104df0f20f1055e80d000000808905168233004883c4205deb99'}}
DATA = {4559536: '000000000000f03f', 4559752: 'f168e388b5f8d43e', 4559576: '9a9999999999c93f', 4558344: '0000000000001840', 4559840: '9a9999999999b93f', 4558512: '0000000000000040', 4560808: '0000000000004440', 7984336: '000000000000f03f9a9999999999c93f00000000000018409a9999999999b93f00000000000000400000000000004440'}

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
    facts['epsilon_bits']=hex(struct.unpack('<Q',read(data,0x459388,8)[1])[0])
    facts['floor_epsilon']=struct.unpack('<d',read(data,0x459388,8)[1])[0]
    facts['late_success_head']=read(data,0x36a5cc4,1)[1][0]
    facts['coefficients']=[struct.unpack('<d',read(data,a,8)[1])[0] for a in [0x4592d8,0x458e08,0x4593e0,0x458eb0,0x4597a8]]
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
        rows, slots, sources, blocks = [], {0x64ffe00}, [], []
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
                    require(start!=0x36a58d0 or target in ins,'new helper direct branch escape')
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
                         'unwind': unwind, 'lsda': None if frame['lsda'] is None else hex(frame['lsda']), 'calls': calls, 'branches': branches, 'role': 'new-private-floor-question' if start==0x36a58d0 else 'conditional-floating-helper-context'})
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
              'implementation_bytes': 0, 'requested_gates': [], 'new_helper_bytes':1136, 'conditional_math_context_bytes':1240, 'readonly_context_data':[{'va':hex(a),'raw':raw} for a,raw in DATA.items()]}
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
