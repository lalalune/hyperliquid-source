#!/usr/bin/env python3
"""Reproduce one digest-bound node #94 static heartbeat observation; never execute it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from artifacts import ROOT, check
from elf_index import sections

START, END = 0x4726A50, 0x4726D2C
CALLER_START, CALLER_END = 0x4876F90, 0x48774B0
HELPER_START, HELPER_END = 0x1447130, 0x14472A0
EXPECTED_CALLERS = [0x4876FD9, 0x487734C]


def mapped(data, va, size):
    matches = [s for s in sections(data) if s['type'] != 8 and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'No unique file-backed mapping: {va:#x}+{size}')
    offset = matches[0]['offset'] + va - matches[0]['address']
    return offset, data[offset:offset + size]


def expect(data, va, value):
    if mapped(data, va, len(value))[1] != value:
        raise ValueError(f'Instruction/data control changed at {va:#x}')


def static_controls(data):
    """Independent byte controls for the branches annotated in the packet."""
    controls = {
        0x4726AC9: 'ba14000000',  # memcmp key length
        0x4726AD1: 'ffd3',
        0x4726B38: 'f2410f104708',  # denominator
        0x4726B42: '660f2ec175027b13',  # zero/unordered distinction
        0x4726B4A: '660f2ec10f86bf010000',  # nonpositive/NaN -> panic
        0x4726B54: 'f2410f100ff20f5ec8',  # numerator / denominator
        0x4726BC3: '660f2e4b187666',  # ratio <= config threshold
        0x4726C26: '807b20000f84b2000000',  # flag-zero -> tag 2
        0x4726C81: 'ff15397c0401',
        0x4726C87: '660f2e054940aefb772d',  # elapsed > literal -> tag 1
        0x4726C95: '48c7401803000000',
        0x4726CB4: '48c7411800000000',
        0x4726CD3: '48c7411801000000',
        0x4726CF7: '48c7411802000000',
        0x1447181: '4869c640420f00',  # integer scale by 1,000,000
        0x14471C6: 'f20f5e05923cdcfe',  # floating scale by 1/1,000,000
        0x4876FE3: '4883f9037542',  # consumer skips tag 3
        0x4877359: '4883f9030f84fdfdffff',
    }
    for va, value in controls.items():
        expect(data, va, bytes.fromhex(value))
    expect(data, 0x20ACD8, struct.pack('<d', 180.0))
    expect(data, 0x20AE60, struct.pack('<d', 1000000.0))
    expect(data, 0x6FB82A, b'/home/ubuntu/hl/code_Mainnet/node/src/consensus/heartbeat_tracker.rs')
    expect(data, 0x21A843, b'assertion failed: self.denom > 0.')
    return [{'va': hex(va), 'bytes': value} for va, value in controls.items()]


def frame_ranges(text):
    return [(int(a, 16), int(b, 16)) for a, b in
            re.findall(r'FDE[^\n]*pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)', text)]


def direct_callers(lines):
    result = []
    for line in lines:
        m = re.match(r'\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+call\s+4726a50\b', line)
        if m:
            result.append(int(m[1], 16))
    return result


def relocations(data):
    # ELF64 RELA; retain both internal addends and the dynamic memcmp symbol.
    result = []
    wanted = {0x576E488, 0x576E978, 0x576E8C0, 0x576E108, 0x576EAA0}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        for offset in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot in wanted:
                result.append({'slot_va': hex(slot), 'type': info & 0xffffffff,
                               'symbol_index': info >> 32, 'addend': hex(addend)})
    expected = [(0x576E108, 8, 0x157B7F0), (0x576E8C0, 8, HELPER_START),
                (0x576E978, 8, 0x143D010), (0x576EAA0, 8, 0x151D1B0),
                (0x576E488, 6, 0)]
    actual = {(int(r['slot_va'], 16), r['type'], int(r['addend'], 16)) for r in result}
    if actual != set(expected):
        raise ValueError('Relevant relocation targets changed')
    return sorted(result, key=lambda r: int(r['slot_va'], 16))


def run(binary, output):
    item = next(x for x in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                if x['path'] == 'artifacts/node/94/hl-node')
    check(binary, item)
    data = binary.read_bytes()
    controls = static_controls(data)
    frames = subprocess.check_output(['readelf', '-wf', str(binary)], text=True, encoding='utf-8')
    ranges = frame_ranges(frames)
    for pair in [(START, END), (CALLER_START, CALLER_END), (HELPER_START, HELPER_END)]:
        if ranges.count(pair) != 1:
            raise ValueError(f'Expected one decoded FDE for {pair}')
    # Stream the complete .text decoder output rather than scanning raw E8 bytes.
    with subprocess.Popen(['objdump', '-d', '-j', '.text', str(binary)],
                          stdout=subprocess.PIPE, text=True, encoding='utf-8') as proc:
        callers = direct_callers(proc.stdout)
        if proc.wait() != 0:
            raise ValueError('Full .text disassembly failed')
    if callers != EXPECTED_CALLERS:
        raise ValueError(f'Decoded direct caller set changed: {callers}')
    output.mkdir(parents=True, exist_ok=True)
    relocation_text = subprocess.check_output(['readelf', '-rW', str(binary)], text=True, encoding='utf-8')
    relevant_slots = {int(r['slot_va'], 16) for r in relocations(data)}
    relocation_lines = [line for line in relocation_text.splitlines()
                        if re.match(r'^([0-9a-f]+)\s', line) and
                        int(line.split()[0], 16) in relevant_slots]
    if not any('memcmp@GLIBC_2.2.5' in line and line.startswith('000000000576e488 ')
               for line in relocation_lines):
        raise ValueError('Lookup comparator symbol changed')
    (output / 'relocations.txt').write_text('\n'.join(relocation_lines) + '\n')
    raw = {}
    for name, begin, end in [('status', START, END), ('consumer', CALLER_START, CALLER_END),
                             ('elapsed-helper', HELPER_START, HELPER_END)]:
        command = ['objdump', '-d', f'--start-address={begin:#x}', f'--stop-address={end:#x}', str(binary)]
        text = subprocess.check_output(command, text=True, encoding='utf-8')
        # Exclude the local absolute pathname from durable deterministic evidence.
        text = text.replace(str(binary), '<authenticated-node94>')
        (output / f'{name}.objdump.txt').write_text(text)
        offset, body = mapped(data, begin, end - begin)
        raw[name] = {'start_va': hex(begin), 'end_va': hex(end), 'file_offset': hex(offset),
                     'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    (output / 'frames.txt').write_text('\n'.join(line for line in frames.splitlines()
        if 'FDE' in line and any(f'pc={a:016x}..{b:016x}' in line for a, b in
                               [(START, END), (CALLER_START, CALLER_END), (HELPER_START, HELPER_END)])) + '\n')
    result = {'target_sha256': item['sha256'], 'target_bytes': len(data), 'ranges': raw,
              'fde_record_count': len(ranges), 'direct_callers_in_decoded_text': [hex(v) for v in callers],
              'instruction_controls': controls, 'relocations': relocations(data),
              'literal_180_va': '0x20acd8', 'source_path_va': '0x6fb82a',
              'captured_binary_executed': False,
              'limits': 'One static status function; no indirect-caller completeness, live behavior, EMA implementation, Rust build or component gate.'}
    (output / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT / 'work/heartbeat-status-94')
    args = parser.parse_args()
    print(json.dumps(run(args.binary.resolve(), args.output), indent=2))
