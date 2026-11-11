#!/usr/bin/env python3
"""Bind the node #115 action-error display table and its staking arms.

No captured code is executed or emulated. GNU objdump is used only as a
disassembler.
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

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
ENTRY = 0x46ef710
END = 0x46f312f
TABLE = 0x7d8c1c
ARM_COUNT = 418
GOT = 0x64e28a0
FLOAT_FMT = 0x1688740
PROLOGUE = bytes.fromhex('4883ec380fb707488d0dfe940efc486304814801c8ffe0')
FLOAT_HEAD = bytes.fromhex('4889f0f20f10078b7610f7c600000010')
INTERVAL_BITS = 0x4072c00000000000
KEYWORDS = ('jail', 'delegat', 'stake', 'unjail', 'commission', 'staker', 'undelegate')
RUST = ROOT / 'src/node115-staking-error-text/src/lib.rs'
CALLS = {
    0x18bdbff: 'call', 0x25f7809: 'call', 0x25f787c: 'call', 0x2e325f9: 'call',
    0x304623f: 'call', 0x46de499: 'call', 0x46de50c: 'call', 0x46f35b9: 'call',
    0x4891d3f: 'call', 0x4e4c6f9: 'call', 0x4e4c76c: 'call', 0x56549a8: 'call',
    0x46dd813: 'tail', 0x2a845f9: 'load', 0x2a846d0: 'load', 0x5580b02: 'load',
    0x5580bd0: 'load', 0x5581446: 'load', 0x558151b: 'load',
}
STATIC = {
    51: 'Delegate amount cannot be zero.',
    184: 'Insufficient delegatable balance for priority order',
    267: 'Insufficient balance to delegate',
    268: 'Validator has delegations disabled',
    269: 'Insufficient balance to undelegate',
    270: 'Cannot undelegate during lockup period after delegating or voting.',
    273: 'Insufficient delegations to propose',
    278: 'Insufficient delegations to vote',
    282: 'Insufficient stake',
    306: 'Validator commission must be between 0 and 100%. If commission increases, it cannot exceed 1%.',
    324: 'Cannot unregister validator with delegations',
    325: 'Self delegation insufficient',
    358: 'Invalid staker',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_va(data, secs, address, size):
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= address
               and address + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'ambiguous or absent file mapping')
    offset = matches[0]['offset'] + address - matches[0]['address']
    return offset, bytes(data[offset:offset + size])


def decode_template(raw):
    parts = []
    index = 0
    while index < len(raw):
        marker = raw[index]
        if marker == 0:
            return parts, raw[:index + 1]
        if marker >= 0x80:
            parts.append(('arg', marker))
            index += 1
            continue
        literal = raw[index + 1:index + 1 + marker]
        if len(literal) != marker or any(byte < 32 or byte > 126 for byte in literal):
            raise ValueError('changed native anchor')
        parts.append(('lit', literal.decode('ascii')))
        index += 1 + marker
    raise ValueError('changed native anchor')


def instructions(objdump):
    rows = []
    for line in objdump.splitlines():
        match = re.match(r'\s*([0-9a-f]+):\t[0-9a-f ]+\t(.+)$', line)
        if match:
            rows.append((int(match.group(1), 16), re.sub(r'\s+', ' ', match.group(2).strip())))
    require(rows and rows[0][0] == ENTRY, 'objdump missed the display entry')
    return rows


def classify(rows, targets, read):
    by_addr = {addr: index for index, (addr, _) in enumerate(rows)}
    arms = []
    for index, target in enumerate(targets):
        cursor = by_addr[target]
        window = []
        for addr, text in rows[cursor:]:
            if window and addr in targets:
                break
            window.append((addr, text))
        lea_rsi = lea_rdx = edx = immediate = None
        for _, text in window:
            if text.startswith('lea ') and '#' in text:
                match = re.search(r'lea (\w+),.*# ([0-9a-f]+)', text)
                require(match, 'unparsed lea')
                if match.group(1) == 'rsi':
                    lea_rsi = int(match.group(2), 16)
                elif match.group(1) == 'rdx':
                    lea_rdx = int(match.group(2), 16)
            if text.startswith('mov edx,0x'):
                edx = int(text.split('0x', 1)[1], 16)
            if text.startswith('movabs rax,0x'):
                immediate = int(text.split('0x', 1)[1], 16)
        record = {'index': index, 'arm': hex(target)}
        if any(text == 'jmp rax' for _, text in window) and lea_rsi is not None and edx is not None:
            raw = read(lea_rsi, edx)
            require(all(32 <= byte < 127 for byte in raw), 'non-text static arm')
            record.update(kind='static', text=raw.decode('ascii'), string_va=hex(lea_rsi), length=edx)
        elif lea_rdx is not None:
            parts, raw = decode_template(read(lea_rdx, 240))
            record.update(kind='format', template_va=hex(lea_rdx), template=raw.hex(),
                          literals=[part[1] for part in parts if part[0] == 'lit'],
                          markers=[part[1] for part in parts if part[0] == 'arg'])
            if immediate is not None:
                record['immediate'] = hex(immediate)
                record['immediate_f64'] = struct.unpack('<d', struct.pack('<Q', immediate))[0]
        else:
            record['kind'] = 'other'
        arms.append(record)
    return arms


def selected(arms):
    chosen = []
    for arm in arms:
        if arm['kind'] == 'static':
            rendered = arm['text']
        elif arm['kind'] == 'format':
            rendered = ''.join(arm['literals'])
        else:
            continue
        if any(key in rendered.lower() for key in KEYWORDS):
            chosen.append(arm)
    return chosen


def call_sites(data, text):
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    found = {}
    for opcode, kind, length in ((b'\xff\x15', 'call', 6), (b'\xff\x25', 'tail', 6)):
        start = 0
        while True:
            index = blob.find(opcode, start)
            if index < 0 or index + length > len(blob):
                break
            start = index + 1
            disp = struct.unpack_from('<i', blob, index + 2)[0]
            pc = base + index
            if pc + length + disp == GOT:
                found[pc] = kind
    start = 0
    while True:
        index = blob.find(b'\x8b', start)
        if index < 0 or index + 6 > len(blob):
            break
        start = index + 1
        if index < 1 or (blob[index - 1] & 0xf8) != 0x48:
            continue
        if (blob[index + 1] & 0xc7) != 0x05:
            continue
        disp = struct.unpack_from('<i', blob, index + 2)[0]
        pc = base + index - 1
        if pc + 7 + disp == GOT:
            found[pc] = 'load'
    return found


def anchors(data):
    secs = sections(data)
    def read(address, size):
        return read_va(data, secs, address, size)[1]
    require(read(ENTRY, len(PROLOGUE)) == PROLOGUE, 'changed native anchor')
    require(read(FLOAT_FMT, len(FLOAT_HEAD)) == FLOAT_HEAD, 'changed native anchor')
    table = read(TABLE, ARM_COUNT * 4)
    targets = []
    for index in range(ARM_COUNT):
        rel = struct.unpack_from('<i', table, index * 4)[0]
        target = TABLE + rel
        require(ENTRY < target < END, 'jump table length')
        targets.append(target)
    require(len(set(targets)) == ARM_COUNT, 'jump table length')
    outside = TABLE + struct.unpack_from('<i', read(TABLE + ARM_COUNT * 4, 4), 0)[0]
    require(not (ENTRY <= outside < END), 'jump table length')
    return secs, read, targets, table, outside


def collect(data, output, *, identity=True):
    if identity:
        require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA, 'node115 identity mismatch')
    else:
        require(len(data) == SIZE, 'node115 identity mismatch')
    secs, read, targets, table, outside = anchors(data)
    _, frames, _ = fde_extents(data)
    frame = next(frame for frame in frames if frame['start'] == ENTRY)
    require(frame['end'] == END and frame['lsda'] is None and frame.get('index') is not None,
            'display FDE mismatch')
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C'}
    versions = {}
    for tool in ('objdump', 'readelf'):
        versions[tool] = subprocess.check_output([tool, '--version'], text=True, env=env).splitlines()[0]
        require('GNU' in versions[tool], 'GNU binutils required')
    objdump = subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', f'--start-address={ENTRY}', f'--stop-address={END}',
         str(ROOT / 'artifacts/node/115/hl-node')], text=True, env=env)
    objdump = objdump.replace(str(ROOT / 'artifacts/node/115/hl-node'), 'artifacts/node/115/hl-node')
    objdump = '\n'.join(line.rstrip() for line in objdump.splitlines()) + '\n'
    rows = instructions(objdump)
    starts = {addr for addr, _ in rows}
    require(all(target in starts for target in targets), 'table target is not an instruction boundary')
    require(outside not in starts, 'table continued past the display body')
    arms = classify(rows, targets, read)
    chosen = selected(arms)
    static = {arm['index']: arm['text'] for arm in chosen if arm['kind'] == 'static'}
    require(static == STATIC, 'staking arm text mismatch')
    formatted = [arm for arm in chosen if arm['kind'] == 'format']
    require([arm['index'] for arm in formatted] == [159, 160], 'staking arm text mismatch')
    unjail, jailed = formatted
    require(unjail['literals'] == ['Can only manually unjail once every ', ' seconds']
            and unjail['markers'] == [0xc0] and int(unjail['immediate'], 16) == INTERVAL_BITS
            and unjail['immediate_f64'] == 300.0, 'staking arm text mismatch')
    require(jailed['literals'] == ['Jailed until '] and jailed['markers'] == [0xc0]
            and 'immediate' not in jailed, 'staking arm text mismatch')
    jailed['argument_helper'] = '0x3d526f0'
    require(read(0x46efdd0, 10) == bytes.fromhex('48b80000000000c07240'), 'changed native anchor')
    require(read(0x46f1816, 4) == bytes.fromhex('4883c704'), 'changed native anchor')
    require(read(0x46f1826, 7) == bytes.fromhex('488d05c30e66ff'), 'changed native anchor')
    calls = call_sites(data, next(s for s in secs if s['name'] == '.text'))
    require(calls == CALLS, 'display caller set changed')
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    slot = None
    for off in range(0, rela['size'], 24):
        got, info, addend = struct.unpack_from('<QQq', data, rela['offset'] + off)
        if got == GOT:
            slot = (info, addend)
    require(slot == (8, ENTRY), 'display GOT relocation mismatch')
    direct = 0
    text = next(s for s in secs if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    for opcode in (b'\xe8', b'\xe9'):
        start = 0
        while True:
            index = blob.find(opcode, start)
            if index < 0 or index + 5 > len(blob):
                break
            start = index + 1
            disp = struct.unpack_from('<i', blob, index + 1)[0]
            if base + index + 5 + disp == ENTRY:
                direct += 1
    require(direct == 0, 'unexpected direct entry call')
    source = RUST.read_text(encoding='utf-8')
    for message in STATIC.values():
        require(f'"{message}"' in source, 'rust text drifted from the native arm')
    require('0x4072_c000_0000_0000' in source, 'rust text drifted from the native arm')
    for literal in unjail['literals'] + jailed['literals']:
        require(f'"{literal}"' in source, 'rust text drifted from the native arm')
    fde_off, _ = read_va(data, secs, frame['fde'], 4)
    fde_size = struct.unpack_from('<I', data, fde_off)[0] + 4
    cie_off, _ = read_va(data, secs, frame['cie'], 4)
    cie_size = struct.unpack_from('<I', data, cie_off)[0] + 4
    fde_raw = data[fde_off:fde_off + fde_size]
    cie_raw = data[cie_off:cie_off + cie_size]
    require(fde_size == 2536 and cie_size == 24, 'display FDE mismatch')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'display.objdump.txt').write_text(objdump)
    record = {
        'target': 'node115',
        'target_sha256': SHA,
        'base': '05bc2de303c05525b71e7e257426e741bc66a390',
        'component': 'staking',
        'method': 'GNU objdump plus independent ELF, FDE and relocation parsing; no target execution',
        'fde': {'start': hex(ENTRY), 'end': hex(END), 'bytes': END - ENTRY,
                'instructions': len(rows), 'fde_va': hex(frame['fde']), 'cie_va': hex(frame['cie']),
                'lsda': None, 'unwind_index': frame['index'],
                'fde_bytes': fde_size, 'fde_sha256': hashlib.sha256(fde_raw).hexdigest(),
                'cie_bytes': cie_size, 'cie_sha256': hashlib.sha256(cie_raw).hexdigest()},
        'dispatch': {
            'table_va': hex(TABLE), 'arm_count': ARM_COUNT, 'table_sha256': hashlib.sha256(table).hexdigest(),
            'entry0': hex(targets[0]), 'entry417': hex(targets[-1]),
            'next_slot_target': hex(outside), 'bounds_check_in_prologue': False,
            'got_slot': hex(GOT), 'got_relocation': 'R_X86_64_RELATIVE', 'direct_calls': 0,
        },
        'callers': [{'pc': hex(pc), 'kind': CALLS[pc]} for pc in sorted(CALLS)],
        'selection': {
            'rule': 'case-insensitive substring of static text or format literals against jail, delegat, stake, unjail, commission, staker, undelegate',
            'arms': chosen,
        },
        'float_formatter': {'va': hex(FLOAT_FMT), 'head': FLOAT_HEAD.hex()},
        'exported_bytes': END - ENTRY,
        'exported_instructions': len(rows),
        'implementation_bytes': 0,
        'requested_gates': [],
    }
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
        for name in ('display.objdump.txt', 'tool-versions.json'):
            require((args.output / name).read_bytes() == (PACKET / name).read_bytes(), 'retained export changed')
    print(json.dumps({'arms': record['dispatch']['arm_count'], 'selected': len(record['selection']['arms']),
                      'instructions': record['exported_instructions'], 'record_check': args.check}))
