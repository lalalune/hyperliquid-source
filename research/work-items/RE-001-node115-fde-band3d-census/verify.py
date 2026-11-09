#!/usr/bin/env python3
"""Re-derive node #115 FDEs and direct control-transfer references in band 3d."""
import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
PACKET_NAME = 'RE-001-node115-fde-band3d-census'
BAND_START = 0x3ac0000
BAND_END = 0x3b00000
ADDRESS_LINE = re.compile(r'^\s*([0-9a-fA-F]+):\s*(.*?)\s*$')
HEX_BYTE = re.compile(r'^[0-9a-fA-F]{2}$')
HEX_ADDRESS = re.compile(r'^(?:0x)?([0-9a-fA-F]+)(?:\s|$)')

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def digest_file(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            value.update(chunk)
    return value.hexdigest()


def tool_prefix():
    found = shutil.which('llvm-objdump')
    if found:
        return [found]
    found = shutil.which('xcrun')
    if found:
        return [found, 'llvm-objdump']
    found = shutil.which('objdump')
    if found:
        return [found]
    raise AssertionError('llvm-objdump or objdump is required for static decoding')


def run(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=False)
    if result.returncode:
        raise AssertionError('command failed: %s: %s' %
                             (' '.join(command), result.stderr.strip()))
    return result.stdout


def parse_disassembly(output):
    rows = []
    for line in output.splitlines():
        match = ADDRESS_LINE.match(line)
        if not match:
            continue
        fields = match.group(2).split()
        width = 0
        while width < len(fields) and HEX_BYTE.fullmatch(fields[width]):
            width += 1
        if width == 0:
            continue
        raw = bytes.fromhex(''.join(fields[:width]))
        assembly = ' '.join(fields[width:])
        rows.append({'address': int(match.group(1), 16), 'bytes': raw,
                     'assembly': assembly, 'instruction': bool(assembly)})
    return rows


def transfer(row):
    """Return a conservative direct target or the visible indirect reference."""
    assembly = row['assembly']
    if not assembly:
        return None
    mnemonic, _, operands = assembly.partition(' ')
    mnemonic = mnemonic.lower()
    if not (mnemonic.startswith('call') or mnemonic.startswith('j')):
        return None
    operand = operands.strip()
    if not operand:
        return {'mnemonic': mnemonic, 'kind': 'unresolved-control-transfer', 'operand': ''}
    if not operand.startswith('*'):
        match = HEX_ADDRESS.match(operand)
        if match:
            return {'mnemonic': mnemonic, 'kind': 'direct', 'operand': operand,
                    'target': int(match.group(1), 16)}
    comment = re.search(r'#\s*(?:0x)?([0-9a-fA-F]+)', operand)
    if comment:
        return {'mnemonic': mnemonic, 'kind': 'indirect-slot', 'operand': operand,
                'target': int(comment.group(1), 16)}
    return {'mnemonic': mnemonic, 'kind': 'indirect-register-or-unresolved', 'operand': operand}


def record_bytes(data, frame_section, address):
    offset = frame_section['offset'] + address - frame_section['address']
    if offset < frame_section['offset'] or offset + 4 > frame_section['offset'] + frame_section['size']:
        raise AssertionError('frame record address outside .eh_frame')
    length = struct.unpack_from('<I', data, offset)[0]
    if length in (0, 0xffffffff) or offset + 4 + length > frame_section['offset'] + frame_section['size']:
        raise AssertionError('unsupported or truncated frame record at %x' % address)
    return data[offset:offset + 4 + length]


def derive(target=TARGET):
    target = Path(target)
    if target.stat().st_size != TARGET_SIZE:
        raise AssertionError('target size mismatch')
    data = target.read_bytes()
    if sha256(data) != TARGET_SHA256:
        raise AssertionError('target SHA-256 mismatch')

    found = sections(data)
    text_rows = [row for row in found if row['name'] == '.text' and row['type'] != 8]
    frame_rows = [row for row in found if row['name'] == '.eh_frame' and row['type'] != 8]
    if len(text_rows) != 1 or len(frame_rows) != 1:
        raise AssertionError('expected one file-backed .text and .eh_frame')
    text, frame = text_rows[0], frame_rows[0]

    indexed_sections, index_rows = unwind_index(data)
    _, fdes = eh_frame_records(data, indexed_sections)
    rows = sorted((row for row in fdes if BAND_START <= row['start'] < BAND_END),
                  key=lambda row: (row['start'], row['end'], row['fde']))
    if not rows:
        raise AssertionError('no FDE starts in selected band')
    indexed = {(row['start'], row['fde']) for row in index_rows}
    prior_end = None
    prior_start = None
    for row in rows:
        start, end = row['start'], row['end']
        if (start, row['fde']) not in indexed:
            raise AssertionError('FDE not represented in unwind header: %x' % start)
        if start < text['address'] or end > text['address'] + text['size'] or end <= start:
            raise AssertionError('FDE outside .text or empty: %x..%x' % (start, end))
        if prior_start is not None and start <= prior_start:
            raise AssertionError('duplicate or unordered FDE start: %x' % start)
        if prior_end is not None and start < prior_end:
            raise AssertionError('overlapping FDE ranges at %x' % start)
        prior_start, prior_end = start, end

    low = min(row['start'] for row in rows)
    high = max(row['end'] for row in rows)
    prefix = tool_prefix()
    version = run(prefix + ['--version']).splitlines()[0]
    disassembly = run(prefix + ['--disassemble', '--start-address=0x%x' % low,
                                '--stop-address=0x%x' % high, str(target)])
    decoded = parse_disassembly(disassembly)
    records = []
    edge_rows = []
    frame_lines = []
    for fde in rows:
        start, end = fde['start'], fde['end']
        body_offset = text['offset'] + start - text['address']
        body = data[body_offset:body_offset + end - start]
        if len(body) != end - start:
            raise AssertionError('short target bytes for FDE %x..%x' % (start, end))
        selected = [item for item in decoded if start <= item['address'] < end]
        cursor = start
        instruction_count = 0
        local_edges = []
        for item in selected:
            if item['address'] != cursor or item['address'] + len(item['bytes']) > end:
                raise AssertionError('decoded byte gap/overrun in FDE %x..%x at %x' %
                                     (start, end, item['address']))
            offset = text['offset'] + item['address'] - text['address']
            if data[offset:offset + len(item['bytes'])] != item['bytes']:
                raise AssertionError('disassembler bytes differ from target at %x' % item['address'])
            cursor += len(item['bytes'])
            instruction_count += int(item['instruction'])
            edge = transfer(item) if item['instruction'] else None
            if edge:
                edge.update({'source_fde': start, 'instruction_va': item['address']})
                local_edges.append(edge)
        if cursor != end or instruction_count == 0:
            raise AssertionError('decoded %x bytes and %d instructions for FDE %x..%x' %
                                 (cursor - start, instruction_count, start, end))
        fde_raw = record_bytes(data, frame, fde['fde'])
        cie_raw = record_bytes(data, frame, fde['cie'])
        record = {
            'fde_va': hex(fde['fde']), 'cie_va': hex(fde['cie']),
            'start': hex(start), 'end': hex(end), 'body_size': len(body),
            'body_sha256': sha256(body), 'instruction_count': instruction_count,
            'decoded_bytes': cursor - start, 'fde_sha256': sha256(fde_raw),
            'cie_sha256': sha256(cie_raw), 'control_transfer_count': len(local_edges),
        }
        records.append(record)
        frame_lines.append('fde=%s cie=%s range=%s..%s bytes=%d raw=%s' %
                           (hex(fde['fde']), hex(fde['cie']), hex(start), hex(end),
                            len(fde_raw), fde_raw.hex()))
        for edge in local_edges:
            target_va = edge.get('target')
            in_band = (BAND_START <= target_va < BAND_END) if edge['kind'] == 'direct' and target_va is not None else None
            edge_rows.append((start, edge['instruction_va'], edge['mnemonic'], edge['kind'],
                              edge['operand'], target_va, in_band))

    smallest = min(records, key=lambda item: (item['body_size'], int(item['start'], 16)))
    start, end = int(smallest['start'], 16), int(smallest['end'], 16)
    snippet = []
    cursor = start
    stop = min(end, start + 64)
    for item in decoded:
        if start <= item['address'] < stop:
            snippet.append('0x%x: %s %s' % (item['address'], item['bytes'].hex(), item['assembly']))
    if not snippet or not snippet[0].startswith('0x%x:' % start):
        raise AssertionError('smallest FDE has no decoded prologue at its start')
    selection = json.loads((PACKET / 'selection.json').read_text(encoding='utf-8'))
    source_commit = selection.get('base_commit')
    if not isinstance(source_commit, str) or not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise AssertionError('selection record has no pinned source commit')
    evidence = {
        'packet': PACKET_NAME, 'target_release': 'node #115',
        'target_size': TARGET_SIZE, 'target_sha256': TARGET_SHA256,
        'source_commit': source_commit,
        'component_allocation': 'foundation',
        'band': {'start': hex(BAND_START), 'end': hex(BAND_END),
                 'rule': 'select FDEs whose start lies in this half-open VA interval'},
        'text': {'address': hex(text['address']), 'file_offset': hex(text['offset']),
                 'size': hex(text['size'])},
        'fde_count': len(records), 'fdes': records,
        'control_transfer_count': len(edge_rows),
        'control_transfer_kinds': {
            kind: sum(1 for row in edge_rows if row[3] == kind)
            for kind in sorted({row[3] for row in edge_rows})
        },
        'control_transfer_mnemonics': {
            mnemonic: sum(1 for row in edge_rows if row[2] == mnemonic)
            for mnemonic in sorted({row[2] for row in edge_rows})
        },
        'smallest': {'start': smallest['start'], 'end': smallest['end'],
                     'body_size': smallest['body_size'],
                     'body_sha256': smallest['body_sha256'],
                     'instruction_count': smallest['instruction_count']},
        'limits': [
            'FDE extents are unwind descriptions, not validated logical function boundaries.',
            'Direct control-transfer operands are statically decoded; indirect call slots are not loader-resolved here.',
            'No source names, behavior, component ownership, or whole-module denominator are claimed.',
            'The target was read as data and never executed or copied.'
        ],
    }
    frames = '# Raw FDE records for starts in [0x3ac0000, 0x3b00000)\n' + '\n'.join(frame_lines) + '\n'
    edges = ('source_fde_va\tinstruction_va\tmnemonic\tkind\toperand\ttarget_or_slot_va\tdirect_target_va_in_band\n' +
             ''.join('%s\t%s\t%s\t%s\t%s\t%s\t%s\n' %
                     (hex(a), hex(b), mnemonic, kind, operand.replace('\t', ' '),
                      hex(target) if target is not None else '-',
                      str(in_band).lower() if in_band is not None else '-')
                     for a, b, mnemonic, kind, operand, target, in_band in edge_rows))
    window = 'smallest_fde=%s..%s\n' % (smallest['start'], smallest['end']) + '\n'.join(snippet) + '\n'
    tools = {
        'python': sys.version.split()[0], 'disassembler_version': version,
        'disassembler_command': 'llvm-objdump --disassemble --start-address=<first FDE> --stop-address=<last FDE end> <target>',
        'fde_parser': 'tools/elf_index.py and tools/fde_extents.py from the source commit',
        'platform': sys.platform,
    }
    return evidence, frames, edges, window, tools


def manifest(packet):
    files = sorted(p for p in Path(packet).iterdir() if p.is_file() and p.name != 'MANIFEST.sha256')
    return ''.join('%s  %s\n' % (digest_file(p), p.name) for p in files)


def write(packet, outputs):
    packet = Path(packet)
    packet.mkdir(parents=True, exist_ok=True)
    evidence, frames, edges, window, tools = outputs
    (packet / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    (packet / 'frames.txt').write_text(frames, encoding='utf-8')
    (packet / 'edges.tsv').write_text(edges, encoding='utf-8')
    (packet / 'window.txt').write_text(window, encoding='utf-8')
    (packet / 'tools.json').write_text(json.dumps(tools, indent=2) + '\n', encoding='utf-8')
    (packet / 'MANIFEST.sha256').write_text(manifest(packet), encoding='utf-8')


def check_manifest(packet):
    packet = Path(packet)
    listed = {}
    for line in (packet / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines():
        value, separator, name = line.partition('  ')
        if not separator or not re.fullmatch(r'[0-9a-f]{64}', value) or name in listed:
            raise AssertionError('malformed or duplicate manifest entry')
        listed[name] = value
    present = sorted(p.name for p in packet.iterdir()
                     if p.is_file() and p.name != 'MANIFEST.sha256')
    if present != sorted(listed):
        raise AssertionError('manifest file list differs from packet')
    for name, value in listed.items():
        if digest_file(packet / name) != value:
            raise AssertionError('manifest digest mismatch: %s' % name)


def verify(packet=PACKET, target=TARGET):
    packet = Path(packet)
    evidence, frames, edges, window, tools = derive(target)
    if json.loads((packet / 'evidence.json').read_text(encoding='utf-8')) != evidence:
        raise AssertionError('saved evidence differs from target-derived values')
    for name, expected in (('frames.txt', frames), ('edges.tsv', edges), ('window.txt', window)):
        if (packet / name).read_text(encoding='utf-8') != expected:
            raise AssertionError('%s differs from target-derived values' % name)
    saved_tools = json.loads((packet / 'tools.json').read_text(encoding='utf-8'))
    if not saved_tools.get('disassembler_version') or saved_tools.get('fde_parser') != tools['fde_parser']:
        raise AssertionError('tool identity is incomplete')
    check_manifest(packet)
    return evidence


def self_test():
    verify()
    with tempfile.TemporaryDirectory(prefix='fde-band3d-check-') as temp:
        clone = Path(temp) / PACKET_NAME
        shutil.copytree(PACKET, clone)
        saved = json.loads((clone / 'evidence.json').read_text(encoding='utf-8'))
        saved['fdes'][0]['body_sha256'] = '0' * 64
        (clone / 'evidence.json').write_text(json.dumps(saved, indent=2) + '\n', encoding='utf-8')
        (clone / 'MANIFEST.sha256').write_text(manifest(clone), encoding='utf-8')
        try:
            verify(clone)
        except AssertionError:
            pass
        else:
            raise AssertionError('tampered evidence passed the corruption control')
    print('verified clean packet and rejected a re-manifested evidence mutation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='derive and write this packet from the pinned target')
    parser.add_argument('--self-test', action='store_true', help='run verifier plus a tamper rejection control')
    args = parser.parse_args()
    if args.write:
        outputs = derive()
        write(PACKET, outputs)
    if args.self_test:
        self_test()
    else:
        evidence = verify()
        print('verified target, %d complete FDE extents, and %d control-transfer references' %
              (evidence['fde_count'], evidence['control_transfer_count']))


if __name__ == '__main__':
    main()
