#!/usr/bin/env python3
"""Verify one node #115 branch-conditioned direct-call path from pinned bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
SOURCE = 0x3aa8840
SOURCE_END = 0x3aa887f
CALLS = {0x3aa885d: 0x3b62630, 0x3aa8875: 0x3b676e0}
ERROR_CONTEXT_LEA = 0x3aa8869
ERROR_VALUE_LEA = 0x3aa8870
STATIC_CONTEXT = 0x646fb38
BYTE = re.compile(r'^[0-9a-fA-F]{2}$')
ROW = re.compile(r'^\s*([0-9a-fA-F]+):\s*(.*?)\s*$')

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def section_named(section_rows, name):
    matches = [row for row in section_rows if row['name'] == name and row['type'] != 8]
    if len(matches) != 1:
        raise AssertionError('expected one file-backed %s section' % name)
    return matches[0]


def get_fde(fdes, address):
    matches = [row for row in fdes if row['start'] == address]
    if len(matches) != 1:
        raise AssertionError('expected one FDE at %x, found %d' % (address, len(matches)))
    return matches[0]


def fde_evidence(data, text, fde):
    start, end = fde['start'], fde['end']
    if not text['address'] <= start < end <= text['address'] + text['size']:
        raise AssertionError('FDE outside .text: %x..%x' % (start, end))
    offset = text['offset'] + start - text['address']
    body = data[offset:offset + end - start]
    if len(body) != end - start:
        raise AssertionError('short FDE body at %x' % start)
    return {
        'start': hex(start), 'end': hex(end), 'length': len(body),
        'sha256': sha256(body), 'fde_offset': hex(fde['fde']),
        'cie_offset': hex(fde['cie']), 'raw_fde_sha256': sha256(
            data[fde['fde']:fde['fde'] + 4 + struct.unpack_from('<I', data, fde['fde'])[0]]),
    }, body


def disassembly(target, start, end):
    objdump = shutil.which('objdump')
    if not objdump:
        raise AssertionError('objdump is required for the bounded call-path listing')
    try:
        display = target.resolve().relative_to(ROOT.resolve())
        cwd = ROOT
    except ValueError:
        display, cwd = target.resolve(), None
    command = [objdump, '-d', '--start-address=0x%x' % start,
               '--stop-address=0x%x' % end, str(display)]
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise AssertionError('objdump failed: %s' % result.stderr.strip())
    instructions = []
    decoded = bytearray()
    for line in result.stdout.splitlines():
        match = ROW.match(line)
        if not match:
            continue
        fields = match.group(2).split()
        byte_count = 0
        while byte_count < len(fields) and BYTE.fullmatch(fields[byte_count]):
            byte_count += 1
        if not byte_count:
            continue
        raw = bytes.fromhex(''.join(fields[:byte_count]))
        decoded.extend(raw)
        if byte_count < len(fields):
            instructions.append({'address': int(match.group(1), 16),
                                 'bytes': raw.hex(), 'text': ' '.join(fields[byte_count:])})
    cursor = start
    for row in instructions:
        if row['address'] != cursor:
            raise AssertionError('disassembly instruction gap or overlap at %x' % cursor)
        cursor += len(bytes.fromhex(row['bytes']))
    if cursor != end:
        raise AssertionError('disassembly instruction rows do not reach FDE end')
    body_offset = file_offset_for_va(target, start)
    if bytes(decoded) != target.read_bytes()[body_offset:body_offset + end - start]:
        raise AssertionError('objdump bytes do not exactly cover source FDE')
    if not instructions or instructions[0]['address'] != start:
        raise AssertionError('source FDE disassembly does not begin at its entry')
    return result.stdout, instructions


def file_offset_for_va(target, address):
    data = Path(target).read_bytes()
    rows = sections(data)
    text = section_named(rows, '.text')
    if not text['address'] <= address < text['address'] + text['size']:
        raise AssertionError('address outside .text: %x' % address)
    return text['offset'] + address - text['address']


def rel32_target(site, encoding):
    if len(encoding) != 5 or encoding[0] != 0xe8:
        raise AssertionError('expected direct rel32 CALL at %x' % site)
    return site + 5 + struct.unpack('<i', encoding[1:])[0]


def relative_target(site, encoding, opcode):
    if len(encoding) != 2 or encoding[0] != opcode:
        raise AssertionError('unexpected short branch encoding at %x' % site)
    return site + 2 + struct.unpack('<b', encoding[1:])[0]


def derive(target=TARGET):
    target = Path(target)
    if target.stat().st_size != TARGET_SIZE:
        raise AssertionError('target size mismatch')
    data = target.read_bytes()
    if sha256(data) != TARGET_SHA256:
        raise AssertionError('target SHA-256 mismatch')
    section_rows = sections(data)
    text = section_named(section_rows, '.text')
    relro = section_named(section_rows, '.data.rel.ro')
    _, fdes = eh_frame_records(data, section_rows)
    source_fde = get_fde(fdes, SOURCE)
    source, body = fde_evidence(data, text, source_fde)
    if source['end'] != hex(SOURCE_END):
        raise AssertionError('source FDE end mismatch')

    listing, instructions = disassembly(target, SOURCE, SOURCE_END)
    by_address = {row['address']: row for row in instructions}
    if len(by_address) != len(instructions):
        raise AssertionError('duplicate disassembly instruction address')
    call_rows = [row for row in instructions if re.search(r'\bcallq?\b', row['text'])]
    if {row['address'] for row in call_rows} != set(CALLS):
        raise AssertionError('direct call-site set differs from the expected source path')

    edges = []
    for site, expected_target in CALLS.items():
        row = by_address[site]
        encoding = bytes.fromhex(row['bytes'])
        target_va = rel32_target(site, encoding)
        if target_va != expected_target:
            raise AssertionError('call target mismatch at %x: %x' % (site, target_va))
        target_fde = get_fde(fdes, target_va)
        callee, _ = fde_evidence(data, text, target_fde)
        edges.append({'site': hex(site), 'instruction_bytes': encoding.hex(),
                      'target': hex(target_va), 'target_fde': callee})

    # Check branch destinations and the error-helper argument address from bytes.
    branch_expectations = {
        0x3aa8846: (bytes.fromhex('7503'), 0x3aa884b),
        0x3aa884f: (bytes.fromhex('740c'), 0x3aa885d),
        0x3aa8854: (bytes.fromhex('7513'), 0x3aa8869),
        0x3aa885b: (bytes.fromhex('750c'), 0x3aa8869),
    }
    for site, (encoding, expected_target) in branch_expectations.items():
        offset = site - SOURCE
        actual = body[offset:offset + len(encoding)]
        if actual != encoding:
            raise AssertionError('conditional-branch bytes changed at %x' % site)
        opcode = encoding[0]
        if relative_target(site, actual, opcode) != expected_target:
            raise AssertionError('conditional-branch target mismatch at %x' % site)
    context_bytes = body[ERROR_CONTEXT_LEA - SOURCE:ERROR_CONTEXT_LEA - SOURCE + 7]
    value_bytes = body[ERROR_VALUE_LEA - SOURCE:ERROR_VALUE_LEA - SOURCE + 5]
    if context_bytes[:3] != bytes.fromhex('488d15') or len(context_bytes) != 7:
        raise AssertionError('unexpected error-context LEA at %x' % ERROR_CONTEXT_LEA)
    context_target = ERROR_CONTEXT_LEA + 7 + struct.unpack('<i', context_bytes[3:])[0]
    if context_target != STATIC_CONTEXT:
        raise AssertionError('error-context address mismatch')
    if value_bytes != bytes.fromhex('488d742407'):
        raise AssertionError('unexpected error-value LEA at %x' % ERROR_VALUE_LEA)
    if not relro['address'] <= context_target < relro['address'] + relro['size']:
        raise AssertionError('error-context reference outside .data.rel.ro')
    data_offset = relro['offset'] + context_target - relro['address']
    context = data[data_offset:data_offset + 32]

    evidence = {
        'target': {'sha256': TARGET_SHA256, 'size': TARGET_SIZE,
                   'release': 'node #115 Linux x86-64'},
        'source_fde': source,
        'observed_dispatch': {
            'input_read': {'address': '0x3aa8840', 'bytes': '0fb607',
                           'statement': 'zero-extend one byte from the initial RDI address'},
            'branches': [
                {'site': '0x3aa8846', 'bytes': '7503', 'predicate': 'input byte is not 0x16',
                 'taken_to': '0x3aa884b', 'fallthrough_to': '0x3aa8848'},
                {'site': '0x3aa884f', 'bytes': '740c', 'predicate': 'input byte is 0x12',
                 'taken_to': '0x3aa885d'},
                {'site': '0x3aa8854', 'bytes': '7513', 'predicate': 'input byte is not 0x15',
                 'taken_to': '0x3aa8869'},
                {'site': '0x3aa885b', 'bytes': '750c', 'predicate': 'qword at initial RDI + 0x18 is nonzero',
                 'taken_to': '0x3aa8869'},
            ],
            'direct_calls': edges,
            'error_helper_arguments': {
                'rdi': 'initial RDI value is not overwritten before the call',
                'rsi': {'site': hex(ERROR_VALUE_LEA), 'bytes': value_bytes.hex(),
                        'addressing': 'current RSP + 7'},
                'rdx': {'site': hex(ERROR_CONTEXT_LEA), 'bytes': context_bytes.hex(),
                        'target': hex(context_target), 'section': '.data.rel.ro',
                        'window_hex': context.hex(), 'window_sha256': sha256(context)},
            },
            'excluded_cases': ['input byte 0x16 reaches the zero-return branch before either call'],
        },
    }
    version_result = subprocess.run([shutil.which('objdump') or 'objdump', '--version'],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    tool = {'objdump': version_result.stdout.splitlines()[0] if version_result.stdout else 'unknown',
            'parser': 'tools/elf_index.py + tools/fde_extents.py + relative-branch byte checks'}
    return evidence, listing, tool


def manifest(packet):
    files = sorted(path for path in packet.iterdir() if path.is_file() and path.name != 'MANIFEST.sha256')
    lines = ['%s  %s' % (sha256(path.read_bytes()), path.name) for path in files]
    return '\n'.join(lines) + '\n'


def verify(packet=PACKET, target=TARGET):
    packet, target = Path(packet), Path(target)
    evidence, listing, tool = derive(target)
    saved_evidence = json.loads((packet / 'edges.json').read_text(encoding='utf-8'))
    if saved_evidence != evidence:
        raise AssertionError('saved edge evidence differs from target-derived records')
    if (packet / 'window.txt').read_text(encoding='utf-8') != listing:
        raise AssertionError('saved disassembly differs from target')
    if json.loads((packet / 'tools.json').read_text(encoding='utf-8')) != tool:
        raise AssertionError('saved tool identity differs from current tool')
    if (packet / 'MANIFEST.sha256').read_text(encoding='utf-8') != manifest(packet):
        raise AssertionError('packet manifest differs from packet contents')
    return evidence


def write_packet(packet=PACKET, target=TARGET):
    packet = Path(packet)
    packet.mkdir(parents=True, exist_ok=True)
    evidence, listing, tool = derive(target)
    (packet / 'edges.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    (packet / 'window.txt').write_text(listing, encoding='utf-8')
    (packet / 'tools.json').write_text(json.dumps(tool, indent=2) + '\n', encoding='utf-8')
    (packet / 'MANIFEST.sha256').write_text(manifest(packet), encoding='utf-8')
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    evidence = write_packet() if args.write else verify()
    print('verified source=%s..%s direct_calls=%d' %
          (evidence['source_fde']['start'], evidence['source_fde']['end'],
           len(evidence['observed_dispatch']['direct_calls'])))


if __name__ == '__main__':
    main()
