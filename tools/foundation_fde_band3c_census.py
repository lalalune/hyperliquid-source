#!/usr/bin/env python3
"""Re-derive the node #115 FDE census for .text starts in band 3c."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-fde-band3c-census'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
PACKET_NAME = 'RE-001-node115-fde-band3c-census'
BAND_START = 0x3A80000
BAND_END = 0x3AC0000
REQUIRED = ('README.md', 'evidence.json', 'frames.txt', 'window.txt', 'tools.json', 'MANIFEST.sha256')
ADDRESS_LINE = re.compile(r'^\s*([0-9a-fA-F]+):\s*(.*?)\s*$')
BYTE_TOKEN = re.compile(r'^[0-9a-fA-F]{2}$')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def run(command, cwd=None):
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise AssertionError('command failed: %s: %s' % (' '.join(command), result.stderr.strip()))
    return result.stdout


def target_sections(data):
    found = sections(data)
    text = [section for section in found if section['name'] == '.text' and section['type'] != 8]
    frames = [section for section in found if section['name'] == '.eh_frame' and section['type'] != 8]
    if len(text) != 1 or len(frames) != 1:
        raise AssertionError('expected unique file-backed .text and .eh_frame sections')
    return found, text[0], frames[0]


def checked_rows(data, found, text):
    _, fdes = eh_frame_records(data, found)
    rows = sorted((fde for fde in fdes if BAND_START <= fde['start'] < BAND_END),
                  key=lambda fde: (fde['start'], fde['end'], fde['fde']))
    if not rows:
        raise AssertionError('no FDE starts in band 3c')
    previous = None
    for fde in rows:
        start, end = fde['start'], fde['end']
        if end <= start:
            raise AssertionError('empty FDE: %x..%x' % (start, end))
        if not text['address'] <= start < end <= text['address'] + text['size']:
            raise AssertionError('FDE outside .text: %x..%x' % (start, end))
        if previous is not None:
            if start == previous['start']:
                raise AssertionError('duplicate FDE start: %x' % start)
            if start < previous['end']:
                raise AssertionError('overlapping FDE ranges: %x < %x' % (start, previous['end']))
        previous = fde
    return rows


def record_bytes(data, section, address):
    offset = section['offset'] + address - section['address']
    if offset < section['offset'] or offset + 4 > section['offset'] + section['size']:
        raise AssertionError('DWARF record header outside section: %x' % address)
    length = struct.unpack_from('<I', data, offset)[0]
    if length in (0, 0xFFFFFFFF) or offset + 4 + length > section['offset'] + section['size']:
        raise AssertionError('unsupported or truncated DWARF record: %x' % address)
    return data[offset:offset + 4 + length]


def objdump_rows(text):
    """Yield address, bytes, and whether a row contains decoded instruction text."""
    for line in text.splitlines():
        match = ADDRESS_LINE.match(line)
        if not match:
            continue
        fields = match.group(2).split()
        byte_count = 0
        while byte_count < len(fields) and BYTE_TOKEN.fullmatch(fields[byte_count]):
            byte_count += 1
        if byte_count == 0:
            continue
        yield (int(match.group(1), 16), bytes.fromhex(''.join(fields[:byte_count])),
               byte_count < len(fields))


def parse_objdump(text):
    """Count mnemonic-bearing address rows; byte-only continuation rows are not instructions."""
    instruction_addresses = []
    decoded_bytes = 0
    for address, raw, has_instruction in objdump_rows(text):
        decoded_bytes += len(raw)
        if has_instruction:
            instruction_addresses.append(address)
    return instruction_addresses, decoded_bytes


def disassemble(target, start, end):
    objdump = shutil.which('objdump')
    if not objdump:
        raise AssertionError('objdump is required to derive instruction counts')
    resolved = Path(target).resolve()
    try:
        display_path = str(resolved.relative_to(ROOT.resolve()))
        cwd = ROOT
    except ValueError:
        display_path = str(resolved)
        cwd = None
    output = run([objdump, '-d', '--start-address=0x%x' % start,
                  '--stop-address=0x%x' % end, display_path], cwd=cwd)
    addresses, decoded_bytes = parse_objdump(output)
    if decoded_bytes != end - start:
        raise AssertionError('objdump decoded %d bytes for %x..%x (%d expected)' %
                             (decoded_bytes, start, end, end - start))
    if not addresses:
        raise AssertionError('objdump decoded no instructions for %x..%x' % (start, end))
    if addresses[0] != start or any(not start <= address < end for address in addresses):
        raise AssertionError('instruction addresses escape FDE %x..%x' % (start, end))
    return output, len(addresses), decoded_bytes


def derive(target):
    target = Path(target)
    if target.stat().st_size != TARGET_SIZE:
        raise AssertionError('target size mismatch')
    data = target.read_bytes()
    target_sha = sha256(data)
    if target_sha != TARGET_SHA256:
        raise AssertionError('target SHA-256 mismatch: %s' % target_sha)
    found, text, frame_section = target_sections(data)
    rows = checked_rows(data, found, text)
    evidence_rows = []
    raw_frame_lines = []
    for fde in rows:
        start, end = fde['start'], fde['end']
        offset = text['offset'] + start - text['address']
        body = data[offset:offset + end - start]
        if len(body) != end - start:
            raise AssertionError('short body for FDE %x..%x' % (start, end))
        _, instruction_count, decoded_bytes = disassemble(target, start, end)
        fde_raw = record_bytes(data, frame_section, fde['fde'])
        cie_raw = record_bytes(data, frame_section, fde['cie'])
        evidence_rows.append({
            'fde_va': hex(fde['fde']), 'cie_va': hex(fde['cie']),
            'start': hex(start), 'end': hex(end), 'body_size': len(body),
            'body_sha256': sha256(body), 'instruction_count': instruction_count,
            'decoded_bytes': decoded_bytes, 'fde_sha256': sha256(fde_raw),
            'cie_sha256': sha256(cie_raw),
        })
        raw_frame_lines.append('fde=%s cie=%s range=%s..%s bytes=%d fde_raw=%s' %
                               (hex(fde['fde']), hex(fde['cie']), hex(start), hex(end),
                                len(fde_raw), fde_raw.hex()))
    smallest = min(evidence_rows, key=lambda row: (row['body_size'], int(row['start'], 16)))
    start, end = int(smallest['start'], 16), int(smallest['end'], 16)
    window_bytes = min(16, end - start)
    offset = text['offset'] + start - text['address']
    prologue = data[offset:offset + window_bytes]
    window_output, _, _ = disassemble(target, start, min(end, start + 64))
    version_line = run([shutil.which('objdump') or 'objdump', '--version']).splitlines()[0]
    evidence = {
        'packet': PACKET_NAME, 'target': 'node115', 'target_size': TARGET_SIZE,
        'target_sha256': target_sha, 'component_allocation': 'foundation',
        'band': {'start': hex(BAND_START), 'end': hex(BAND_END), 'rule': 'FDE start in half-open band'},
        'text': {'address': hex(text['address']), 'offset': hex(text['offset']), 'size': hex(text['size'])},
        'fde_count': len(evidence_rows), 'fdes': evidence_rows,
        'smallest': {'start': smallest['start'], 'end': smallest['end'],
                     'body_size': smallest['body_size'], 'body_sha256': smallest['body_sha256'],
                     'instruction_count': smallest['instruction_count'], 'prologue_hex': prologue.hex()},
        'limitations': ['FDE extents are unwind descriptions, not validated function boundaries.',
                        'No behavior, source name, component ownership, or whole-module denominator is claimed.',
                        'The target was read as data and never executed or copied.'],
    }
    frames = '\n'.join(['# Raw .eh_frame FDE records for starts in band 3c'] + raw_frame_lines) + '\n'
    window = ('smallest_fde=%s..%s\nprologue_hex=%s\nobjdump_output:\n%s' %
              (smallest['start'], smallest['end'], prologue.hex(), window_output))
    tools = {'python': sys.version.split()[0], 'objdump_version': version_line,
             'objdump_invocation': 'objdump -d --start-address=<FDE start> --stop-address=<FDE end>',
             'parser': 'tools/elf_index.py + tools/fde_extents.py'}
    return evidence, frames, window, tools


def manifest_entries(packet):
    names = sorted(path.name for path in packet.iterdir() if path.is_file() and path.name != 'MANIFEST.sha256')
    return {name: file_sha256(packet / name) for name in names}


def write_packet(packet, evidence, frames, window, tools):
    packet.mkdir(parents=True, exist_ok=True)
    (packet / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    (packet / 'frames.txt').write_text(frames, encoding='utf-8')
    (packet / 'window.txt').write_text(window, encoding='utf-8')
    (packet / 'tools.json').write_text(json.dumps(tools, indent=2) + '\n', encoding='utf-8')
    entries = manifest_entries(packet)
    (packet / 'MANIFEST.sha256').write_text(''.join('%s  %s\n' % (value, name)
                                                     for name, value in entries.items()), encoding='utf-8')


def verify_window(packet, evidence):
    text = (packet / 'window.txt').read_text(encoding='utf-8')
    if 'smallest_fde=%s..%s\n' % (evidence['smallest']['start'], evidence['smallest']['end']) not in text:
        raise AssertionError('window FDE does not match evidence')
    if 'prologue_hex=%s\n' % evidence['smallest']['prologue_hex'] not in text:
        raise AssertionError('window prologue does not match evidence')
    if 'objdump_output:\n' not in text:
        raise AssertionError('missing saved objdump output')
    output = text.split('objdump_output:\n', 1)[1]
    start = int(evidence['smallest']['start'], 16)
    expected = bytes.fromhex(evidence['smallest']['prologue_hex'])
    cursor = start
    actual = bytearray()
    saw_instruction = False
    for address, raw, has_instruction in objdump_rows(output):
        if not actual and address != start:
            continue
        if address != cursor:
            break
        actual.extend(raw)
        cursor += len(raw)
        saw_instruction |= has_instruction
        if len(actual) >= len(expected):
            break
    if bytes(actual[:len(expected)]) != expected or not saw_instruction:
        raise AssertionError('saved objdump prologue does not match target bytes')


def verify_manifest(packet):
    listed = {}
    for line in (packet / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines():
        digest, separator, name = line.partition('  ')
        if not separator or not re.fullmatch(r'[0-9a-f]{64}', digest) or not name:
            raise AssertionError('malformed manifest line: %r' % line)
        if name in listed:
            raise AssertionError('duplicate manifest path: %s' % name)
        listed[name] = digest
    present = sorted(path.name for path in packet.iterdir() if path.is_file() and path.name != 'MANIFEST.sha256')
    if present != sorted(listed):
        raise AssertionError('manifest file set differs from packet')
    for name, digest in listed.items():
        actual = file_sha256(packet / name)
        if actual != digest:
            raise AssertionError('manifest mismatch: %s' % name)


def verify(packet=None, target=None):
    packet = Path(packet) if packet else PACKET
    target = Path(target) if target else TARGET
    evidence, frames, _, _ = derive(target)
    if json.loads((packet / 'evidence.json').read_text(encoding='utf-8')) != evidence:
        raise AssertionError('saved evidence differs from target-derived records')
    if (packet / 'frames.txt').read_text(encoding='utf-8') != frames:
        raise AssertionError('saved raw FDE records differ from target')
    tools = json.loads((packet / 'tools.json').read_text(encoding='utf-8'))
    if not tools.get('objdump_version') or tools.get('parser') != 'tools/elf_index.py + tools/fde_extents.py':
        raise AssertionError('missing or invalid analysis tool identity')
    verify_window(packet, evidence)
    verify_manifest(packet)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', default=str(TARGET))
    parser.add_argument('--packet', default=str(PACKET))
    parser.add_argument('--write', action='store_true', help='derive and write the packet')
    args = parser.parse_args()
    if args.write:
        evidence, frames, window, tools = derive(args.target)
        write_packet(Path(args.packet), evidence, frames, window, tools)
        print('wrote fdes=%d band=%s..%s smallest=%s..%s' %
              (evidence['fde_count'], hex(BAND_START), hex(BAND_END),
               evidence['smallest']['start'], evidence['smallest']['end']))
    else:
        evidence = verify(args.packet, args.target)
        print('verified fdes=%d band=%s..%s smallest=%s..%s' %
              (evidence['fde_count'], hex(BAND_START), hex(BAND_END),
               evidence['smallest']['start'], evidence['smallest']['end']))


if __name__ == '__main__':
    main()
