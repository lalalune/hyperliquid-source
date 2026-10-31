#!/usr/bin/env python3
"""Digest-bound static observations of node #94 compact-string construction."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from artifacts import ROOT, check
from elf_index import sections

RANGES = {'constructor': (0x1449A80, 0x144A009), 'packer': (0x144A010, 0x144A069),
          'alias-producer': (0x13C6060, 0x13C629E)}
CALLERS = [(0x13B604B, 0x13B5DF0, 0x13B6530), (0x13C64CB, 0x13C6430, 0x13C65E7),
           (0x14BCF6A, 0x14BCDB0, 0x14BD3ED), (0x358EAD1, 0x358EA60, 0x358ED18)]
SLOTS = {0x576E798: 0x1449A80, 0x576F5F0: 0x144A010}


def read_va(data, va, size):
    matches = [s for s in sections(data) if s['type'] != 8 and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'Expected one file mapping for {va:#x}')
    offset = matches[0]['offset'] + va - matches[0]['address']
    return offset, data[offset:offset + size]


def controls(data):
    # These are architectural byte controls, not execution of the target.
    expected = {
        0x1449A9B: '4883fe10763e',  # unsigned byte-length <=16 admission
        0x1449ADF: '31d2',  # initial packer index zero
        0x1449AF2: 'ff25f85a3204',  # inline tail call to packer GOT slot
        0x1449C99: '48b8000000000a000000',  # observed counter pair 0,10
        0x1449CB2: 'e8a9c3f7ff',  # call alias producer
        0x1449CCA: '4883fe100f87bb020000',  # produced byte-length bound
        0x1449CD7: '31d2ff1511593204',  # reuses same index-zero packer
        0x1449D8F: '4981fe9f8601000f87ab000000',  # insertion eligibility >99999 skip
        0x144A011: '31c0b900000000',  # empty suffix -> zero halves
        0x144A018: '4839f27427732a',  # index==length base, index>length panic
        0x144A01F: '0fb61c1748ffc2',  # current byte, then next index
        0x144A026: 'ff15c4553204',  # recursive packer GOT call
        0x144A02C: '4889d148c1ea387527',  # high byte lost by shift must be zero
        0x144A035: '0fb6d3480fa4c10848c1e0084809d0',  # 128-bit shift + OR byte
        0x13C60A0: '48b875657370656d6f73',
        0x13C60AF: '48b86172656e6567796c',
        0x13C60BE: '48b86d6f646e61726f64',
        0x13C60CD: '48b87365747962646574',  # four hash-state constants
        0x13C6105: 'c6442408ffba01000000',  # one ff byte feed
        0x13C611F: '896c2408ba04000000',  # four-byte counter feed
        0x13C6242: '438d0cbf8d0c894401f94129ce4180c641',  # 26*q subtraction + A
        0x13C6257: '4488340149ffc44c896310',  # emit one byte and increment length
        0x13C6262: '396c240c0f8534feffff',  # continue to requested endpoint
    }
    for va, value in expected.items():
        if read_va(data, va, len(bytes.fromhex(value)))[1] != bytes.fromhex(value):
            raise ValueError(f'Compact-string control changed at {va:#x}')
    path = b'/home/ubuntu/hl/code_Mainnet/base/src/short_string.rs'
    if read_va(data, 0x1EA56A, len(path))[1] != path:
        raise ValueError('Compact-string source-path bytes changed')
    return [{'va': hex(va), 'bytes': value} for va, value in expected.items()]


def relevant_relocations(data):
    wanted = {**SLOTS, 0x566A990: 0x1EA56A, 0x566A9A8: 0x1EA56A, 0x566A9C0: 0x1EA56A}
    rows = []
    for section in sections(data):
        if section['type'] != 4:
            continue
        if section['size'] % 24:
            raise ValueError('Truncated relocation section')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot in wanted:
                if info != 8 or addend != wanted[slot]:
                    raise ValueError(f'Compact-string relocation changed at {slot:#x}')
                rows.append({'slot_va': hex(slot), 'type': 'R_X86_64_RELATIVE', 'addend': hex(addend)})
    if len(rows) != len(wanted):
        raise ValueError('Missing compact-string relocation')
    return sorted(rows, key=lambda r: int(r['slot_va'], 16))


def decoded_reference(line):
    """Decode only call/jump bytes already delineated by objdump, not raw E8 scans."""
    match = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(?:call|jmp)\s', line)
    if not match:
        return None
    va, instruction = int(match[1], 16), bytes.fromhex(match[2])
    if len(instruction) == 6 and instruction[:2] in (b'\xff\x15', b'\xff\x25'):
        return va, 'GOT', va + 6 + struct.unpack_from('<i', instruction, 2)[0]
    if len(instruction) == 5 and instruction[0] in (0xe8, 0xe9):
        return va, 'direct', va + 5 + struct.unpack_from('<i', instruction, 1)[0]
    return None


def generate(binary, output):
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == 'artifacts/node/94/hl-node')
    check(binary, identity)
    data = binary.read_bytes()
    byte_controls, relocs = controls(data), relevant_relocations(data)
    frames_text = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    fdes = [(int(a, 16), int(b, 16)) for a, b in
            re.findall(r'FDE[^\n]*pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)', frames_text)]
    scope = list(RANGES.values()) + [(begin, end) for _, begin, end in CALLERS]
    for pair in scope:
        if fdes.count(pair) != 1:
            raise ValueError(f'Expected one exact FDE range: {pair}')
    references = []
    with subprocess.Popen(['objdump', '-d', '-j', '.text', str(binary)],
                          stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            ref = decoded_reference(line)
            if ref and ((ref[1] == 'GOT' and ref[2] in SLOTS) or
                        (ref[1] == 'direct' and ref[2] in {a for a, _ in RANGES.values()})):
                references.append({'site_va': hex(ref[0]), 'kind': ref[1], 'target_va': hex(ref[2])})
        if process.wait() != 0:
            raise ValueError('Complete .text disassembly failed')
    constructor_sites = [int(r['site_va'], 16) for r in references
                         if r['kind'] == 'GOT' and int(r['target_va'], 16) == 0x576E798]
    if constructor_sites != [site for site, _, _ in CALLERS]:
        raise ValueError('Constructor GOT caller set changed')
    output.mkdir(parents=True, exist_ok=True)
    rela_text = subprocess.check_output(['readelf', '-rW', str(binary)], text=True)
    slots = {int(row['slot_va'], 16) for row in relocs}
    rela_rows = [line for line in rela_text.splitlines()
                 if re.match(r'^[0-9a-f]+\s', line) and int(line.split()[0], 16) in slots]
    if len(rela_rows) != len(slots):
        raise ValueError('Independent readelf relocation row count differs')
    (output / 'relocations.txt').write_text('\n'.join(rela_rows) + '\n')
    ranges = {}
    for name, (begin, end) in RANGES.items():
        offset, body = read_va(data, begin, end - begin)
        ranges[name] = {'start_va': hex(begin), 'end_va': hex(end), 'file_offset': hex(offset),
                        'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        text = subprocess.check_output(['objdump', '-d', f'--start-address={begin:#x}',
                                        f'--stop-address={end:#x}', str(binary)], text=True)
        (output / f'{name}.objdump.txt').write_text(text.replace(str(binary), '<authenticated-node94>'))
    for site, begin, end in CALLERS:
        # Retain caller context without claiming its opaque calls are closed.
        text = subprocess.check_output(['objdump', '-d', f'--start-address={begin:#x}',
                                        f'--stop-address={end:#x}', str(binary)], text=True)
        (output / f'caller-{site:x}.objdump.txt').write_text(text.replace(str(binary), '<authenticated-node94>'))
    (output / 'frames.txt').write_text('\n'.join(line for line in frames_text.splitlines()
        if 'FDE' in line and any(f'pc={a:016x}..{b:016x}' in line for a, b in scope)) + '\n')
    records = {'target_sha256': identity['sha256'], 'target_bytes': len(data),
               'ranges': ranges, 'decoded_fde_count': len(fdes), 'instruction_controls': byte_controls,
               'relocations': relocs, 'decoded_references': references,
               'constructor_caller_fdes': [{'site_va': hex(a), 'start_va': hex(b), 'end_va': hex(c)}
                                           for a, b, c in CALLERS],
               'carrier_observation': 'P(i) = byte[i] OR (P(i+1) << 8); P(length)=0; checked 128-bit shift. Constructor starts at i=0.',
               'captured_binary_executed': False,
               'limits': 'Static constructor/packer/alias control flow; hash-feed, cache, allocation, panic and lock callees not closed. No full alias algorithm, struct/serialization ABI, runtime equivalence or gate.'}
    (output / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT / 'work/short-string-static-94')
    args = parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(), args.output), indent=2))
