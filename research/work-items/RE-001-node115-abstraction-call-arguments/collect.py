#!/usr/bin/env python3
"""Record static register setup at direct abstraction visitor calls."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BINARY = ROOT / 'artifacts/node/115/hl-node'
SITES = [
    {'site': 0x1c0ef86, 'target': 0x23c65f0, 'fde': (0x1c0eab0, 0x1c0f199),
     'args': [('rdi', 0x1c0ef83, '4c89ff', 'r15'),
              ('rsi', 0x1c0ef79, '488b742408', 'mem[rsp+0x08]'),
              ('rdx', 0x1c0ef7e, '488b542410', 'mem[rsp+0x10]')]},
    {'site': 0x3164176, 'target': 0x3bdd720, 'fde': (0x3163ca0, 0x3164389),
     'args': [('rdi', 0x3164173, '4c89ff', 'r15'),
              ('rsi', 0x3164169, '488b742408', 'mem[rsp+0x08]'),
              ('rdx', 0x316416e, '488b542410', 'mem[rsp+0x10]')]},
    {'site': 0x48d2956, 'target': 0x4d6b5d0, 'fde': (0x48d2480, 0x48d2b69),
     'args': [('rdi', 0x48d2953, '4c89ff', 'r15'),
              ('rsi', 0x48d2949, '488b742408', 'mem[rsp+0x08]'),
              ('rdx', 0x48d294e, '488b542410', 'mem[rsp+0x10]')]},
    {'site': 0x1debabf, 'target': 0x23c6720, 'fde': (0x1deba10, 0x1debb91),
     'args': [('rdi', 0x1debaba, '488d7c2418', 'rsp+0x18'),
              ('rsi', 0x1debaaa, '488b742408', 'mem[rsp+0x08]'),
              ('rdx', 0x1debab5, '488b542410', 'mem[rsp+0x10]')],
     'branch': (0x1debaaf, '0f84cf000000', 'fallthrough')},
    {'site': 0x1e22089, 'target': 0x23c6720, 'fde': (0x1e21fc0, 0x1e220e3),
     'args': [('rdi', 0x1e22084, '488d7c2410', 'rsp+0x10'),
              ('rsi', 0x1e2206f, '488b742428', 'mem[rsp+0x28]'),
              ('rdx', 0x1e2207f, '488b542430', 'mem[rsp+0x30]')],
     'branch': (0x1e22074, '7509', 'taken')},
    {'site': 0x3f7f8cf, 'target': 0x3bdd5e0, 'fde': (0x3f7f820, 0x3f7f9a1),
     'args': [('rdi', 0x3f7f8ca, '488d7c2418', 'rsp+0x18'),
              ('rsi', 0x3f7f8ba, '488b742408', 'mem[rsp+0x08]'),
              ('rdx', 0x3f7f8c5, '488b542410', 'mem[rsp+0x10]')],
     'branch': (0x3f7f8bf, '0f84cf000000', 'fallthrough')},
    {'site': 0x3fbb239, 'target': 0x3bdd5e0, 'fde': (0x3fbb170, 0x3fbb293),
     'args': [('rdi', 0x3fbb234, '488d7c2410', 'rsp+0x10'),
              ('rsi', 0x3fbb21f, '488b742428', 'mem[rsp+0x28]'),
              ('rdx', 0x3fbb22f, '488b542430', 'mem[rsp+0x30]')],
     'branch': (0x3fbb224, '7509', 'taken')},
]


def instructions(output):
    found = {}
    for line in output.splitlines():
        if ':' not in line:
            continue
        address, rest = line.split(':', 1)
        if not re.fullmatch(r'\s*[0-9a-fA-F]+\s*', address):
            continue
        fields = rest.split('\t')
        if len(fields) < 3:
            continue
        raw = bytes.fromhex(fields[1].strip().replace(' ', ''))
        found[int(address, 16)] = {'bytes': raw, 'text': fields[2].strip()}
    return found


def extract(binary=BINARY, objdump='objdump'):
    data = Path(binary).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET_SHA256:
        raise ValueError(f'target digest mismatch: {digest}')
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    rows = []
    for item in SITES:
        site, target = item['site'], item['target']
        start, end = item['fde']
        owners = [f for f in fdes if f['start'] == start and f['end'] == end and start <= site < end]
        if len(owners) != 1:
            raise ValueError(f'{site:#x}: expected the recorded unique FDE')
        out = subprocess.check_output([objdump, '-d', '-w', f'--start-address={start:#x}',
                                       f'--stop-address={site + 5:#x}', str(binary)], text=True)
        decoded = instructions(out)
        call = decoded.get(site)
        if call is None or call['bytes'][0] != 0xe8 or len(call['bytes']) != 5:
            raise ValueError(f'{site:#x}: expected decoded E8 rel32 call')
        destination = site + 5 + struct.unpack('<i', call['bytes'][1:])[0]
        if destination != target or not call['text'].startswith('call'):
            raise ValueError(f'{site:#x}: call target/decode mismatch')
        args = []
        for register, address, expected_bytes, source in item['args']:
            instruction = decoded.get(address)
            if instruction is None or instruction['bytes'].hex() != expected_bytes:
                raise ValueError(f'{site:#x}: {register} producer mismatch at {address:#x}')
            aliases = {'rdi': r'(?:rdi|edi|di|dil)',
                       'rsi': r'(?:rsi|esi|si|sil)',
                       'rdx': r'(?:rdx|edx|dx|dl)'}[register]
            for other_address, other in decoded.items():
                if address < other_address < site and re.search(r',\s*%'+aliases+r'\s*$', other['text']):
                    raise ValueError(f'{site:#x}: {register} is overwritten at {other_address:#x}')
            args.append({'register': register, 'producer': address,
                         'bytes': expected_bytes, 'source': source})
        row = {'site': site, 'visitor_entry': target, 'fde_start': start, 'fde_end': end,
               'call_bytes': call['bytes'].hex(), 'arguments': args}
        if 'branch' in item:
            address, expected_bytes, relation = item['branch']
            instruction = decoded.get(address)
            if instruction is None or instruction['bytes'].hex() != expected_bytes:
                raise ValueError(f'{site:#x}: branch bytes mismatch at {address:#x}')
            raw = instruction['bytes']
            mnemonic = 'je' if raw[:2] == b'\x0f\x84' else 'jne'
            if not instruction['text'].startswith(mnemonic):
                raise ValueError(f'{site:#x}: unexpected conditional branch at {address:#x}')
            if raw[:2] == b'\x0f\x84':
                target_address = address + 6 + struct.unpack('<i', raw[2:])[0]
            else:
                target_address = address + len(raw) + struct.unpack('<b', raw[1:])[0]
            row['branch'] = {'address': address, 'bytes': expected_bytes,
                             'target': target_address,
                             'call_path': relation}
        rows.append(row)
    return {'target_sha256': digest, 'coordinate': 'ELF virtual address',
            'scope': 'seven direct call boundaries and their explicit register producers',
            'calls': rows,
            'limitations': ['Register sources are machine-level observations, not Rust parameter types.',
                            'Stack slots are not assigned source-level names or layouts.',
                            'No indirect call, tail jump, or non-visited control-flow path is analyzed.',
                            'Captured code is disassembled but never executed.']}


if __name__ == '__main__':
    out = extract(objdump=os.environ.get('OBJDUMP', 'objdump'))
    target = Path(__file__).resolve().parent / 'records.json'
    target.write_text(json.dumps(out, indent=2) + '\n')
    print(f"verified calls={len(out['calls'])} visitors={len({row['visitor_entry'] for row in out['calls']})}")
