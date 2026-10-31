#!/usr/bin/env python3
"""Compare two selected unwindless code spans across authenticated captures.

This is a bounded static correspondence, not a function or runtime identity.
Only GNU objdump is executed, on tiny private raw views of admitted input bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    '94': (91774280, '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f', 121299),
    '115': (105896032, 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301', 135313),
}
CANDIDATES = [('A', 0x5631580, 0x56319fd, 285), ('B', 0x56319fd, 0x5631ef2, 324)]
CONDITIONS = ['jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja',
              'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def admit_image(path, size, sha256):
    """Authenticate the exact immutable object used by every later reader.

    Filesystem reads need not be atomic: only an immutable bytes result with the
    complete expected digest is admitted. No later path/descriptor reads supply
    metadata, search, or native-input facts.
    """
    with Path(path).open('rb') as handle:
        if os.fstat(handle.fileno()).st_size != size:
            raise ValueError('Wrong captured target size')
        image = handle.read(size + 1)
    if len(image) != size or digest(image) != sha256:
        raise ValueError('Wrong captured target digest or size')
    return image


def layout(data):
    """Retain section and PT_LOAD coordinates separately, refusing ambiguity."""
    secs = sections(data)
    for name in ('.text', '.eh_frame', '.eh_frame_hdr'):
        if len([s for s in secs if s['name'] == name]) != 1:
            raise ValueError('Expected one ' + name + ' section')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    width, count = struct.unpack_from('<HH', data, 54)
    if width != 56 or not count or phoff + width * count > len(data):
        raise ValueError('Unsupported or truncated program header table')
    loads = []
    for i in range(count):
        typ, flags, off, va, _, size, memory_size, align = struct.unpack_from(
            '<IIQQQQQQ', data, phoff + i * width)
        if typ != 1:
            continue
        if size > memory_size or off + size > len(data):
            raise ValueError('Invalid file-backed PT_LOAD')
        loads.append({'flags': flags, 'offset': off, 'address': va,
                      'size': size, 'memory_size': memory_size, 'alignment': align})
    return secs, loads


def coordinate(secs, loads, offset, size, expected_va=None):
    if offset < 0 or size <= 0:
        raise ValueError('Invalid selected file interval')
    ss = [s for s in secs if s['type'] != 8 and s['offset'] <= offset
          and offset + size <= s['offset'] + s['size']]
    ps = [p for p in loads if p['offset'] <= offset
          and offset + size <= p['offset'] + p['size']]
    if len(ss) != 1 or len(ps) != 1:
        raise ValueError('Selected interval has ambiguous section or PT_LOAD mapping')
    sec, load = ss[0], ps[0]
    sva = sec['address'] + offset - sec['offset']
    pva = load['address'] + offset - load['offset']
    if sec['name'] != '.text' or not sec['flags'] & 4 or not load['flags'] & 1:
        raise ValueError('Selected interval is not executable text in PT_LOAD')
    if sva != pva or expected_va is not None and sva != expected_va:
        raise ValueError('File, section and PT_LOAD coordinates disagree')
    return {'start': sva, 'end': sva + size, 'offset': offset,
            'section': sec, 'load_segment': load}


def source_coordinate(secs, loads, start, end):
    ss = [s for s in secs if s['type'] != 8 and s['address'] <= start
          and end <= s['address'] + s['size']]
    if len(ss) != 1:
        raise ValueError('Source VA has ambiguous section mapping')
    off = ss[0]['offset'] + start - ss[0]['address']
    return coordinate(secs, loads, off, end - start, start)


def unique_match(data, needle):
    if not needle:
        raise ValueError('Empty comparison body')
    first = data.find(needle)
    if first < 0 or data.find(needle, first + 1) >= 0:
        raise ValueError('Comparison body must occur exactly once in complete target')
    return first


def frame_record(data, frame, va):
    off = frame['offset'] + va - frame['address']
    if not frame['offset'] <= off <= frame['offset'] + frame['size'] - 4:
        raise ValueError('Unwind record outside .eh_frame')
    size = 4 + struct.unpack_from('<I', data, off)[0]
    if size < 8 or off + size > frame['offset'] + frame['size']:
        raise ValueError('Invalid selected unwind record')
    raw = data[off:off + size]
    return {'address': va, 'offset': off, 'bytes': size,
            'sha256': digest(raw), 'hex': raw.hex()}


def unwind_context(data, secs, fdes, start, end):
    intersections = [f for f in fdes if f['start'] < end and start < f['end']]
    if intersections:
        raise ValueError('Selected candidate intersects an FDE')
    previous = max((f for f in fdes if f['end'] <= start), key=lambda f: f['end'])
    following = min((f for f in fdes if f['start'] >= end), key=lambda f: f['start'])
    frame = next(s for s in secs if s['name'] == '.eh_frame')

    def bound(fde):
        return {**fde, 'raw_fde': frame_record(data, frame, fde['fde']),
                'raw_cie': frame_record(data, frame, fde['cie'])}

    return {'intersecting_fdes': [], 'previous': bound(previous),
            'following': bound(following)}


def native_version():
    version = subprocess.check_output(['objdump', '--version'], text=True).splitlines()[0]
    if 'GNU objdump' not in version:
        raise ValueError('GNU objdump is required; no native result was produced')
    return version


def native_listing(raw, start):
    with tempfile.TemporaryDirectory(prefix='gapmap-') as temp:
        folder = Path(temp)
        (folder / 'view.bin').write_bytes(raw)
        argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-Mintel',
                '--insn-width=16', '--adjust-vma=' + str(start), 'view.bin']
        return subprocess.check_output(argv, cwd=folder,
                                       env={**os.environ, 'LC_ALL': 'C'}).decode('ascii')


def encoded_branch(raw, address):
    """Derive Jcc/JMP destinations from their actual signed encodings."""
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        return CONDITIONS[raw[0] - 0x70], address + 2 + struct.unpack('<b', raw[1:])[0]
    if len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return CONDITIONS[raw[1] - 0x80], address + 6 + struct.unpack('<i', raw[2:])[0]
    if len(raw) == 2 and raw[0] == 0xeb:
        return 'jmp', address + 2 + struct.unpack('<b', raw[1:])[0]
    if len(raw) == 5 and raw[0] == 0xe9:
        return 'jmp', address + 5 + struct.unpack('<i', raw[1:])[0]
    return None


def decode(raw, start, expected_rows, provider=native_listing):
    text = provider(raw, start)
    rows, normalized, branches = [], [], []
    cursor = start
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if not match:
            continue
        address, encoding, asm = int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()
        if address != cursor or not encoding or raw[cursor - start:cursor - start + len(encoding)] != encoding:
            raise ValueError('Native row address/bytes do not bind the admitted view')
        if len(encoding) > 15 or cursor + len(encoding) > start + len(raw):
            raise ValueError('Native row extends outside selected bytes')
        cursor += len(encoding)
        fields = asm.split(None, 1)
        mnemonic, operand = fields[0], fields[1] if len(fields) == 2 else ''
        if '(bad)' in asm or mnemonic.startswith('call') or re.search(r'\b(?:rip|eip)\b', operand):
            raise ValueError('Unknown instruction or unqualified external dependency')
        branch = encoded_branch(encoding, address)
        normalized_operand = operand
        if branch is not None:
            wanted_mnemonic, destination = branch
            if mnemonic != wanted_mnemonic or not re.fullmatch(r'(?:0x)?[0-9a-f]+', operand):
                raise ValueError('Native branch form does not bind its opcode')
            if int(operand, 16) != destination:
                raise ValueError('Native branch display disagrees with encoded destination')
            normalized_operand = {'candidate_relative_destination': destination - start}
            branches.append({'source_offset': address - start, 'mnemonic': mnemonic,
                             'target_offset': destination - start})
        elif mnemonic.startswith('j'):
            raise ValueError('Unqualified native branch form')
        rows.append({'address': address, 'offset': address - start,
                     'encoding': encoding.hex(), 'mnemonic': mnemonic, 'operand': operand})
        normalized.append({'offset': address - start, 'encoding': encoding.hex(),
                           'mnemonic': mnemonic, 'operand': normalized_operand})
    if cursor != start + len(raw) or len(rows) != expected_rows:
        raise ValueError('Native rows do not cover the complete selected body')
    if rows[-1]['mnemonic'] != 'ret' or rows[-1]['encoding'] != 'c3':
        raise ValueError('Expected terminal RET boundary')
    by_offset = {r['offset']: r for r in rows}
    edges = {b['source_offset']: b for b in branches}
    leaders = {0}
    for branch in branches:
        target = branch['target_offset']
        if target not in by_offset:
            raise ValueError('Encoded branch target is not a selected instruction boundary')
        leaders.add(target)
        following = branch['source_offset'] + len(bytes.fromhex(by_offset[branch['source_offset']]['encoding']))
        if following < len(raw):
            leaders.add(following)
    reached, todo = set(), [0]
    returns = []
    while todo:
        off = todo.pop()
        if off in reached:
            continue
        if off not in by_offset:
            raise ValueError('CFG falls outside selected instruction boundaries')
        reached.add(off)
        row = by_offset[off]
        if row['mnemonic'] == 'ret':
            if row['encoding'] != 'c3':
                raise ValueError('Unqualified return form')
            returns.append(off)
            continue
        if off in edges:
            todo.append(edges[off]['target_offset'])
            if row['mnemonic'] == 'jmp':
                continue
        todo.append(off + len(bytes.fromhex(row['encoding'])))
    if len(reached) != len(rows) or returns != [len(raw) - 1]:
        raise ValueError('Selected complete CFG or unique RET boundary changed')
    return {'rows': rows, 'normalized_rows': normalized, 'branches': branches,
            'block_leaders': sorted(leaders), 'reachable_rows': len(reached),
            'native_text': text}


def compare_bodies(raw94, start94, raw115, start115, count, provider=native_listing):
    if raw94 != raw115:
        raise ValueError('Raw selected code differs; no byte masks are permitted')
    left = decode(raw94, start94, count, provider)
    right = decode(raw115, start115, count, provider)
    if left['normalized_rows'] != right['normalized_rows']:
        raise ValueError('Complete native scalar/memory/CFG operands differ')
    if left['branches'] != right['branches'] or left['block_leaders'] != right['block_leaders']:
        raise ValueError('Selected local control-flow mapping differs')
    return left, right


def analyze(images, provider=native_listing):
    if set(images) != set(TARGETS) or any(type(image) is not bytes for image in images.values()):
        raise ValueError('Analysis requires one immutable admitted bytes object per target')
    layouts, fde_tables, report_targets = {}, {}, {}
    for release, data in images.items():
        secs, loads = layout(data)
        _, fdes = eh_frame_records(data, secs)
        if len(fdes) != TARGETS[release][2]:
            raise ValueError('Incomplete raw unwind metadata parse')
        layouts[release], fde_tables[release] = (secs, loads), fdes
        report_targets[release] = {'sha256': TARGETS[release][1], 'bytes': len(data),
                                   'raw_fde_records_parsed': len(fdes), 'candidates': []}
    instruction_records, native_outputs, pairs = {}, {}, []
    for label, start94, end94, row_count in CANDIDATES:
        source = source_coordinate(*layouts['94'], start94, end94)
        raw94 = images['94'][source['offset']:source['offset'] + end94 - start94]
        offset115 = unique_match(images['115'], raw94)
        target = coordinate(*layouts['115'], offset115, len(raw94))
        raw115 = images['115'][offset115:offset115 + len(raw94)]
        decoded = compare_bodies(raw94, start94, raw115, target['start'], row_count, provider)
        for release, coord, raw, native in zip(('94', '115'), (source, target), (raw94, raw115), decoded):
            secs, _ = layouts[release]
            context = unwind_context(images[release], secs, fde_tables[release], coord['start'], coord['end'])
            name = 'node' + release + '-' + label + '.objdump'
            native_outputs[name] = native['native_text'].encode('ascii')
            instruction_records[release + '-' + label] = {k: v for k, v in native.items() if k != 'native_text'}
            report_targets[release]['candidates'].append({
                'label': label, **coord, 'bytes': len(raw), 'sha256': digest(raw),
                'native_rows': len(native['rows']), 'reachable_rows': native['reachable_rows'],
                'local_branches': native['branches'], 'block_leaders': native['block_leaders'],
                'native_export': name, 'native_export_sha256': digest(native_outputs[name]),
                'unwind_context': context})
        pairs.append({'label': label, 'code_byte_pairs': len(raw94), 'instruction_pairs': row_count,
                      'local_branch_pairs': len(decoded[0]['branches']), 'code_bytes_equal': True,
                      'normalized_complete_native_rows_equal': True, 'byte_masks': [],
                      'whole115file_exact_occurrences': 1, 'linked_address_delta': target['start'] - start94})
    following_sizes = {release: target['candidates'][0]['unwind_context']['following']['end']
                       - target['candidates'][0]['unwind_context']['following']['start']
                       for release, target in report_targets.items()}
    report = {'schema_version': 1, 'task': 'RE-014', 'targets': report_targets,
              'pairs': pairs, 'denominator': {'code_byte_pairs': sum(p['code_byte_pairs'] for p in pairs),
              'instruction_pairs': sum(p['instruction_pairs'] for p in pairs),
              'local_branch_pairs': sum(p['local_branch_pairs'] for p in pairs)},
              'comparison_rule': 'Raw bytes are equal without masks. Only displayed direct-branch linked coordinates are made candidate-relative after checking the encoded signed destination. All other mnemonic/scalar/memory operands compare exactly.',
              'following_fde_sizes': following_sizes,
              'context_limit': 'Neighboring FDE/CIE records are bound separately per target. The following FDE-sized regions are not part of this correspondence; their observed sizes are recorded separately.',
              'credit': {'373': 'Previously reported gap census/bounds; credited context only, no new global gap counts.',
                         '37': 'Held FDE-based release drift explicitly excludes code without FDEs.',
                         '875': 'Held FDE-bounded ISA census is neither edited nor relied on.',
                         '981_1022_1043': 'Earlier94 boundary/conditional-contract work; no unmerged analyzer is imported.'},
              'limits': ['No original function/source/type/ABI identity', 'No caller or dispatch closure',
                         'No runtime table/region/state or CPU availability qualification',
                         'No whole-call/release behavior or equivalence', 'No reconstruction count or gate change',
                         'Admitted immutable bytes do not claim an atomic filesystem snapshot or stable original pathname'],
              'captured_target_or_emulator_executed': False}
    return report, instruction_records, native_outputs


def produce(output, paths=None, provider=native_listing):
    output = Path(output)
    if output.exists():
        raise FileExistsError('Refusing existing evidence directory: ' + str(output))
    paths = paths or {r: ROOT / 'artifacts/node' / r / 'hl-node' for r in TARGETS}
    images = {release: admit_image(paths[release], size, expected)
              for release, (size, expected, _) in TARGETS.items()}
    version = native_version()
    report, records, native_outputs = analyze(images, provider)
    report['objdump_version'] = version
    report['source_bindings'] = {p: digest((ROOT / p).read_bytes()) for p in (
        'tools/gap_candidate_release_mapping.py', 'tools/elf_index.py', 'tools/fde_extents.py')}
    report['all_facts_from_digest_authenticated_immutable_bytes'] = True
    del images
    outputs = {**native_outputs, 'instructions.json': json_bytes(records)}
    report['instructions_sha256'] = digest(outputs['instructions.json'])
    outputs['REPORT.json'] = json_bytes(report)
    outputs['OUTPUT-MANIFEST.json'] = json_bytes({name: digest(data) for name, data in sorted(outputs.items())})
    output.mkdir(parents=True, exist_ok=False)
    for name, data in sorted(outputs.items()):
        with (output / name).open('xb') as handle:
            handle.write(data)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--node94', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--node115', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    args = parser.parse_args()
    report = produce(args.output_dir, {'94': args.node94, '115': args.node115})
    print(json.dumps({'task': report['task'], **report['denominator'], 'captured_target_executed': False}))


if __name__ == '__main__':
    main()
