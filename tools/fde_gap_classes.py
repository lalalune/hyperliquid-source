#!/usr/bin/env python3
"""Classify .text gaps that no .eh_frame FDE covers and find validated references into them.

Static only: GNU objdump decodes bytes of the authenticated captured binary; nothing is executed.
"""
import argparse
import bisect
import collections
import csv
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
SHT_RELA, SHT_NOBITS = 4, 8
SHF_WRITE, SHF_ALLOC = 1, 2
MAX_INSN = 15  # Longest x86-64 instruction in bytes.
RELOCATION_KINDS = {8: 'relative', 37: 'irelative'}  # R_X86_64_RELATIVE, R_X86_64_IRELATIVE
PREFIXES = {'data16', 'cs', 'ds'}
FILL_MNEMONICS = {'int3', 'nop', 'nopl', 'nopw'}
# Canonical NOP bodies after optional 0x66 prefixes and one optional 0x2e, longest first.
NOP_BODIES = [bytes.fromhex(h) for h in ('0f1f840000000000', '0f1f8000000000', '0f1f440000', '0f1f4000', '0f1f00', '90')]
INSN = re.compile(r'^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*(?:\t(.*))?$')
STREAM = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
# objdump prints `1030 <sym+0x10>` when a symbol is near and `0x1030` when the file has none.
BRANCH = re.compile(r'^(?:(?:bnd|notrack)\s+)?(call|jmp|j[a-z]{1,3}|loop[a-z]*|j[er]?cxz)\s+(?:0x)?([0-9a-f]+)(?:\s+<.*)?$')
RIP_TARGET = re.compile(r'\(%rip\).*#\s+(?:0x)?([0-9a-f]+)(?:\s+<.*)?$')
UNLISTED_ROLES = ('internal_jump', 'internal_pointer')
LIMITATIONS = ('An island is the non-fill bytes between int3 runs in one FDE gap, decoded by objdump from the '
               'gap start; it is not a validated function boundary. References are direct branches and '
               'RIP-relative operands from a linear objdump sweep of .text, each re-decoded from its containing '
               'FDE or gap, plus RELATIVE/IRELATIVE relocation addends and RIP-relative reads of those '
               'relocation slots. Computed, register-indirect and '
               'relative jump-table targets are not followed, so an unreferenced island is not proven dead. '
               'Only FDE-covered code and relocation slots can make an entry: island bytes may be data decoded '
               'as instructions, and a pointer to a non-endbr64 address may address data. No island is '
               'attributed to a library or component.')


def objdump_version(objdump):
    return subprocess.check_output([objdump, '--version'], text=True).splitlines()[0]


def parse_instructions(text):
    """Parse `objdump -d -z --insn-width=15` lines into address, raw bytes and decoded text."""
    rows = []
    for line in text.splitlines():
        match = INSN.match(line)
        if not match:
            continue
        if match.group(3) is None:
            raise ValueError(f'Wrapped or empty instruction line: {line!r}')
        rows.append({'va': int(match.group(1), 16), 'raw': bytes.fromhex(match.group(2)),
                     'text': ' '.join(match.group(3).split())})
    for previous, current in zip(rows, rows[1:]):
        if current['va'] != previous['va'] + len(previous['raw']):
            raise ValueError(f'Non-contiguous decode at {current["va"]:#x}')
    return rows


def decode(binary, start, end, objdump='objdump'):
    command = [objdump, '-d', '-z', '--insn-width=15', f'--start-address={start:#x}',
               f'--stop-address={end:#x}', str(binary)]
    rows = parse_instructions(subprocess.check_output(command, text=True))
    if not rows or rows[0]['va'] != start:
        raise ValueError(f'Decode does not start at {start:#x}')
    return rows


def is_fill(text):
    words = text.split()
    while words and words[0] in PREFIXES:
        words.pop(0)
    return bool(words) and (words[0] in FILL_MNEMONICS or words == ['xchg', '%ax,%ax'])


def is_invalid(text):
    return '(bad)' in text or text.startswith('.byte')


def fill_length(raw, pos):
    """Independent byte matcher: length of an int3 or canonical NOP at raw[pos], else 0."""
    if raw[pos] == 0xcc:
        return 1
    cursor = pos
    while cursor < len(raw) and raw[cursor] == 0x66 and cursor - pos < 13:
        cursor += 1
    if cursor < len(raw) and raw[cursor] == 0x2e:
        cursor += 1
    for body in NOP_BODIES:
        if raw.startswith(body, cursor):
            return cursor + len(body) - pos
    return 0


def leading_fill(raw):
    pos = 0
    while pos < len(raw):
        step = fill_length(raw, pos)
        if not step:
            break
        pos += step
    return pos


def classify(raw, start, rows):
    """Class one gap from its decode and split its non-fill bytes into int3-separated islands.

    `rows` may run past the gap (objdump truncates an instruction at --stop-address into `.byte`,
    so the caller decodes MAX_INSN bytes further). The gap end must then be an instruction start.
    The independent byte matcher must agree with objdump on where leading fill stops.
    """
    end = start + len(raw)
    aligned = any(r['va'] == end for r in rows) or rows[-1]['va'] + len(rows[-1]['raw']) == end
    rows = [r for r in rows if r['va'] < end]
    code = [r for r in rows if not is_fill(r['text'])]
    result = {'start': start, 'end': end, 'leading_fill_bytes': (code[0]['va'] if code else end) - start,
              'fill_instruction_bytes': sum(len(r['raw']) for r in rows if is_fill(r['text'])),
              'decode_ends_at_gap_end': aligned}
    result['byte_matcher_agrees'] = leading_fill(raw) == result['leading_fill_bytes']
    starts = {r['va']: r['text'] for r in rows}
    islands, current = [], []
    for row in rows + [None]:
        if row is not None and row['text'] != 'int3':
            current.append(row)
            continue
        while current and is_fill(current[-1]['text']):
            current.pop()
        while current and is_fill(current[0]['text']):
            current.pop(0)
        if current:
            lower, upper = current[0]['va'], current[-1]['va'] + len(current[-1]['raw'])
            body = raw[lower - start:upper - start]
            islands.append({'start': lower, 'end': upper, 'gap_start': start, 'starts': starts,
                            'sha256': hashlib.sha256(body).hexdigest(), 'instructions': len(current),
                            'invalid_encodings': sum(is_invalid(r['text']) for r in current),
                            'zero_bytes_only': not body.strip(b'\0'),
                            'endbr64': [r['va'] for r in current if r['text'] == 'endbr64']})
        current = []
    if not islands:
        result['class'] = 'fill'
    elif all(i['zero_bytes_only'] for i in islands):
        result['class'] = 'zero_bytes'
    else:
        result['class'] = 'non_fill'
    result['islands'] = len(islands)
    return result, islands


def island_index(islands, target):
    index = bisect.bisect_right([i['start'] for i in islands], target) - 1
    return index if index >= 0 and target < islands[index]['end'] else None


def stream_references(lines, islands, slots=None):
    """Direct-branch and RIP-relative operands whose target lies inside an island.

    A RIP-relative operand that addresses a relocation slot in `slots` is a read of that pointer.
    """
    slots = slots or {}
    lowers = [i['start'] for i in islands]
    found = []
    for line in lines:
        match = STREAM.match(line)
        if not match:
            continue
        text = ' '.join(match.group(2).split())
        branch = BRANCH.match(text)
        if branch:
            kind, target = ('call' if branch.group(1) == 'call' else 'jump'), int(branch.group(2), 16)
        else:
            rip = RIP_TARGET.search(text)
            if not rip:
                continue
            kind, target = 'rip', int(rip.group(1), 16)
            if target in slots:
                pointer = slots[target]
                found.append({'source': int(match.group(1), 16), 'target': pointer['target'], 'kind': 'slot_read',
                              'slot': target, 'text': text, 'island': pointer['island']})
                continue
        index = bisect.bisect_right(lowers, target) - 1
        if index >= 0 and target < islands[index]['end']:
            found.append({'source': int(match.group(1), 16), 'target': target, 'kind': kind, 'text': text,
                          'island': islands[index]['start']})
    return found


def relocation_references(data, secs, islands):
    """RELATIVE and IRELATIVE relocations whose addend lies inside an island."""
    found = []
    for section in secs:
        if section['type'] != SHT_RELA:
            continue
        if section['size'] % 24:
            raise ValueError(f'{section["name"]} size is not a multiple of 24')
        for pos in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            kind = RELOCATION_KINDS.get(info & 0xffffffff)
            index = None if kind is None else island_index(islands, addend)
            if index is not None:
                found.append({'source': slot, 'target': addend, 'kind': kind, 'text': section['name'],
                              'island': islands[index]['start']})
    return found


def container(secs, va):
    """The allocated, file-backed section holding `va`; NOBITS .tbss overlaps later addresses."""
    for section in secs:
        if (section['type'] != SHT_NOBITS and section['flags'] & SHF_ALLOC
                and section['address'] <= va < section['address'] + section['size']):
            return section
    return None


def role(ref, island):
    """Entry: from FDE-covered code or a relocation slot, a branch or an endbr64-targeting pointer.

    Island bytes may be data decoded as instructions, so island sources never make an entry.
    """
    if not ref['validated']:
        return 'source_not_confirmed'
    if not ref['target_is_instruction_start']:
        return 'target_not_instruction_start'
    if ref['container'].startswith('island:'):
        if ref['container'] != f'island:{island["start"]:#x}' or ref['kind'] == 'slot_read':
            return 'from_other_island'
        return {'call': 'internal_call', 'jump': 'internal_jump'}.get(ref['kind'], 'internal_pointer')
    if ref['kind'] == 'slot_read':
        return 'slot_reader'
    if ref['kind'] in ('call', 'jump') or ref['target_is_endbr64']:
        return 'entry'
    return 'pointer_without_landing_pad'


def validate(binary, refs, ordered, islands, secs, objdump='objdump'):
    """Confirm each code source is the same instruction in a decode from its FDE or gap start."""
    starts = [f['start'] for f in ordered]
    by_start = {i['start']: i for i in islands}
    decoded = {}
    for ref in refs:
        island = by_start[ref['island']]
        ref['target_is_instruction_start'] = ref['target'] in island['starts']
        ref['target_is_endbr64'] = island['starts'].get(ref['target']) == 'endbr64'
        if ref['kind'] in RELOCATION_KINDS.values():
            slot = container(secs, ref['source'])
            if slot is None or not slot['flags'] & SHF_WRITE:
                raise ValueError(f'Relocation slot {ref["source"]:#x} is not in a writable section')
            ref['container'], ref['validated'] = f'section:{slot["name"]}', True
        else:
            owner = island_index(islands, ref['source'])
            index = bisect.bisect_right(starts, ref['source']) - 1
            if owner is not None:
                ref['container'] = f'island:{islands[owner]["start"]:#x}'
                ref['validated'] = islands[owner]['starts'].get(ref['source']) == ref['text']
            elif index >= 0 and ref['source'] < ordered[index]['end']:
                fde = ordered[index]
                if fde['start'] not in decoded:
                    rows = decode(binary, fde['start'], fde['end'], objdump)
                    decoded[fde['start']] = {r['va']: r['text'] for r in rows}
                ref['container'] = f'fde:{fde["start"]:#x}'
                ref['validated'] = decoded[fde['start']].get(ref['source']) == ref['text']
            else:
                ref['container'], ref['validated'] = 'outside_fde_and_islands', False
        ref['role'] = role(ref, island)
    return refs


def analyze(binary, objdump='objdump'):
    data = binary.read_bytes()
    secs = sections(data)
    fde_summary, ordered, gaps = fde_extents(data)
    by_name = {s['name']: s for s in secs}
    classes, islands = [], []
    for gap in gaps:
        if gap['int3_only']:
            continue
        section = by_name[gap['section']]
        offset = section['offset'] + gap['start'] - section['address']
        raw = data[offset:offset + gap['end'] - gap['start']]
        stop = min(gap['end'] + MAX_INSN, section['address'] + section['size'])
        result, found = classify(raw, gap['start'], decode(binary, gap['start'], stop, objdump))
        classes.append(result)
        islands += found
    pointers = relocation_references(data, secs, islands)
    command = [objdump, '-d', '-z', '--no-show-raw-insn', '-j', '.text', str(binary)]
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as proc:
        refs = stream_references(proc.stdout, islands, {p['source']: p for p in pointers})
        if proc.wait() != 0:
            raise ValueError('Full .text disassembly failed')
    refs = validate(binary, refs + pointers, ordered, islands, secs, objdump)
    refs.sort(key=lambda r: (r['target'], r['source'], r['kind']))
    return data, fde_summary, classes, islands, refs


def island_row(island, refs):
    mine = [r for r in refs if r['island'] == island['start']]
    entries = sorted({r['target'] for r in mine if r['role'] == 'entry'})
    pointers = sorted({r['target'] for r in mine if r['role'] == 'pointer_without_landing_pad'})
    if island['zero_bytes_only']:
        kind = 'zero_bytes'
    elif entries:
        kind = 'entered'
    elif pointers:
        kind = 'pointer_operand_only'
    else:
        kind = 'unreferenced'
    reached = set(entries) | {r['target'] for r in mine if r['role'] == 'internal_call'}
    return {'start_va': hex(island['start']), 'end_va': hex(island['end']), 'gap_va': hex(island['gap_start']),
            'bytes': island['end'] - island['start'], 'class': kind, 'sha256': island['sha256'],
            'instructions': island['instructions'], 'invalid_encodings': island['invalid_encodings'],
            'endbr64': len(island['endbr64']),
            'endbr64_not_entered': len([v for v in island['endbr64'] if v not in reached]),
            'entrypoints': [hex(v) for v in entries],
            'entrypoints_with_slot_reader': [hex(v) for v in sorted({r['target'] for r in mine
                                                                     if r['role'] == 'slot_reader'})],
            'pointer_targets_without_landing_pad': [hex(v) for v in pointers],
            'roles': dict(sorted(collections.Counter(r['role'] for r in mine).items()))}


def report(data, fde_summary, classes, islands, refs, version):
    counts = collections.Counter()
    for item in classes:
        counts[f'{item["class"]}_gaps'] += 1
        counts[f'{item["class"]}_bytes'] += item['end'] - item['start']
    rows = [island_row(island, refs) for island in islands]
    return {'binary_sha256': hashlib.sha256(data).hexdigest(), 'objdump': version,
            'fde_other_bytes_gaps': fde_summary['same_section_gaps']['other_bytes_gaps'],
            'classified_gaps': len(classes), 'gap_classes': dict(sorted(counts.items())),
            'byte_matcher_disagreements': sum(not c['byte_matcher_agrees'] for c in classes),
            'gaps_whose_decode_overruns_the_gap': sum(not c['decode_ends_at_gap_end'] for c in classes),
            'island_classes': dict(sorted(collections.Counter(r['class'] for r in rows).items())),
            'reference_roles': dict(sorted(collections.Counter(f'{r["kind"]}:{r["role"]}' for r in refs).items())),
            'islands': rows, 'captured_binary_executed': False, 'limitations': LIMITATIONS}


def write(prefix, summary, classes, refs):
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with prefix.with_name(prefix.name + '-gap-classes.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['gap_start_va', 'gap_end_va', 'size', 'class', 'islands', 'leading_fill_bytes',
                         'fill_instruction_bytes', 'byte_matcher_agrees', 'decode_ends_at_gap_end'])
        for c in classes:
            writer.writerow([hex(c['start']), hex(c['end']), c['end'] - c['start'], c['class'], c['islands'],
                             c['leading_fill_bytes'], c['fill_instruction_bytes'],
                             str(c['byte_matcher_agrees']).lower(), str(c['decode_ends_at_gap_end']).lower()])
    with prefix.with_name(prefix.name + '-gap-xrefs.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['target_va', 'island_va', 'kind', 'role', 'source_va', 'source_container', 'validated',
                         'target_is_instruction_start', 'target_is_endbr64', 'source_instruction'])
        for r in refs:
            if r['role'] in UNLISTED_ROLES:
                continue  # Internal jumps and pointer operands are counted per island, not listed.
            text = re.sub(r' <[^>]*>', '', r['text'])  # Nearest-symbol annotations are not evidence.
            writer.writerow([hex(r['target']), hex(r['island']), r['kind'], r['role'], hex(r['source']),
                             r['container'], *(str(r[k]).lower() for k in
                                               ('validated', 'target_is_instruction_start', 'target_is_endbr64')),
                             text])
    prefix.with_name(prefix.name + '-gap-classes.json').write_text(json.dumps(summary, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', choices=['94', '115'], required=True)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'work/index')
    parser.add_argument('--objdump', default='objdump')
    args = parser.parse_args()
    from artifacts import check
    rel = f'artifacts/node/{args.release}/hl-node'
    item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == rel)
    check(ROOT / rel, item)
    data, fde_summary, classes, islands, refs = analyze(ROOT / rel, args.objdump)
    if len(classes) != fde_summary['same_section_gaps']['other_bytes_gaps']:
        raise ValueError('Classified gap count differs from the FDE decoder')
    summary = report(data, fde_summary, classes, islands, refs, objdump_version(args.objdump))
    write(args.output_dir / f'node-{args.release}', summary, classes, refs)
    print(json.dumps({k: v for k, v in summary.items() if k != 'islands'}, indent=2))


if __name__ == '__main__':
    main()
