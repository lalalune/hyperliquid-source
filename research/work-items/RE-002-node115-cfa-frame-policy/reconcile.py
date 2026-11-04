"""Independent packet-local projection of native CFI exports; never runs the node."""
import argparse
from collections import Counter
import copy
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HEADER = re.compile(r'^([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+\s+(CIE|FDE)(.*)$')
SIMPLE = re.compile(r'(RSP|RBP|R11)[+-][0-9]+$')


def parse(path, provider):
    cies, fdes, current, columns = {}, [], None, []
    with path.open() as handle:
        for number, line in enumerate(handle, 1):
            line = line.rstrip('\n')
            header = HEADER.match(line)
            if header:
                current = dict(offset=int(header[1], 16), rows=[], saved_rbp=False,
                               line=number)
                columns = []
                if header[2] == 'CIE':
                    cies[current['offset']] = current
                else:
                    fields = re.fullmatch(r' cie=([0-9a-f]+) pc=([0-9a-f]+)\.{2,3}([0-9a-f]+)', header[3])
                    if not fields:
                        raise ValueError('Unrecognized FDE header')
                    current.update(cie=int(fields[1], 16), start=int(fields[2], 16),
                                   end=int(fields[3], 16))
                    fdes.append(current)
                continue
            if current is None:
                continue
            if provider == 'gnu':
                if line.strip().startswith('LOC '):
                    columns = line.split()
                    continue
                row = re.fullmatch(r'([0-9a-f]{16})\s+(\S+)(.*)', line)
                if row:
                    fields = line.split()
                    if len(fields) != len(columns):
                        raise ValueError('GNU row/column mismatch')
                    pc, cfa = int(row[1], 16), row[2].upper()
                    if 'rbp' in columns:
                        current['saved_rbp'] |= bool(re.fullmatch(r'c[+-][0-9]+', fields[columns.index('rbp')]))
                else:
                    continue
            elif provider == 'llvm':
                row = re.fullmatch(r'  (?:0x([0-9a-f]+): )?CFA=([^:]+)(?::(.*))?', line)
                if not row:
                    continue
                pc, cfa = int(row[1], 16) if row[1] else 0, row[2].upper()
                current['saved_rbp'] |= bool(re.search(r'(?:^|, )RBP=\[CFA[+-][0-9]+\]', (row[3] or '').strip()))
            else:
                raise ValueError('Unknown provider')
            if not SIMPLE.fullmatch(cfa):
                raise ValueError('Unsupported CFA expression: ' + cfa)
            current['rows'].append([pc, cfa])
    inherited = 0
    for fde in fdes:
        if fde['cie'] not in cies:
            raise ValueError('Missing CIE')
        if not fde['rows']:
            if provider != 'gnu' or len(cies[fde['cie']]['rows']) != 1:
                raise ValueError('Missing FDE state')
            initial = cies[fde['cie']]
            fde['rows'] = [[fde['start'], initial['rows'][0][1]]]
            fde['saved_rbp'] = initial['saved_rbp']
            fde['inherited_cie_only'] = True
            inherited += 1
        if fde['rows'][0][0] != fde['start']:
            raise ValueError('Missing initial FDE row')
        previous = fde['start'] - 1
        for pc, _ in fde['rows']:
            if not previous < pc <= fde['end']:
                raise ValueError('Unordered/out-of-range row')
            previous = pc
    return cies, fdes, inherited


def projection(fde):
    events = []
    for pc, cfa in fde['rows']:
        if not events or cfa != events[-1][1]:
            events.append([pc, cfa])
    return {**{key: fde[key] for key in ('offset', 'cie', 'start', 'end', 'saved_rbp')}, 'events': events}


def compare(left, right):
    if len(left) != len(right):
        raise ValueError('FDE count mismatch')
    for a, b in zip(left, right):
        if projection(a) != projection(b):
            raise ValueError('CFA/bounds/saved-RBP projection mismatch at ' + hex(a['offset']))


def controls(gnu, llvm):
    outcomes = {}
    def reject(name, left, right):
        try:
            compare(left, right)
        except ValueError as error:
            outcomes[name] = str(error)
        else:
            raise ValueError('Corruption accepted: ' + name)
    reject('missing_fde', gnu[:2], llvm[:1])
    for field in ('offset', 'cie', 'start', 'end'):
        changed = copy.deepcopy(llvm[:2])
        changed[0][field] += 1
        reject('changed_' + field, gnu[:2], changed)
    changed = copy.deepcopy(llvm[:2]); changed[0]['rows'][0][1] = 'RSP+16'
    reject('changed_cfa', gnu[:2], changed)
    changed = copy.deepcopy(llvm[:2]); changed[0]['saved_rbp'] = not changed[0]['saved_rbp']
    reject('changed_saved_rbp', gnu[:2], changed)
    changed = copy.deepcopy(llvm[:2]); changed[1]['rows'][1][0] += 1
    reject('changed_event_pc', gnu[:2], changed)
    reject('reordered_fdes', gnu[:2], llvm[:2][::-1])
    return outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository', type=Path)
    parser.add_argument('native', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    repo, native, output = args.repository.resolve(), args.native.resolve(), args.output.resolve()
    image = (repo / 'artifacts/node/115/hl-node').read_bytes()
    if hashlib.sha256(image).hexdigest() != TARGET or len(image) != 105896032:
        raise ValueError('Target identity mismatch')
    sys.path.insert(0, str(repo / 'tools'))
    from elf_index import sections
    from fde_extents import eh_frame_records
    secs = sections(image)
    frame = next(s for s in secs if s['name'] == '.eh_frame')
    _, binary_fdes = eh_frame_records(image, secs)
    native_records, metrics = {}, {}
    for provider in ('gnu', 'llvm'):
        cies, records, inherited = parse(native / (provider + '-frames.txt'), provider)
        if len(records) != len(binary_fdes):
            raise ValueError('Native/binary FDE count mismatch')
        for row, bound in zip(records, binary_fdes):
            if (row['offset'] + frame['address'], row['cie'] + frame['address'], row['start'], row['end']) != tuple(bound[k] for k in ('fde', 'cie', 'start', 'end')):
                raise ValueError('Native/binary FDE bounds mismatch')
            if not any(s['flags'] & 4 and s['address'] <= row['start'] < row['end'] <= s['address'] + s['size'] for s in secs):
                raise ValueError('FDE not contained in executable section')
        metrics[provider] = dict(cies=len(cies), fdes=len(records), rows=sum(len(x['rows']) for x in records), inherited_cie_only=inherited)
        native_records[provider] = records
    gnu, llvm = native_records['gnu'], native_records['llvm']
    compare(gnu, llvm)
    corruption = controls(gnu, llvm)
    categories, cross = Counter(), Counter()
    samples = {}
    for row in gnu:
        bases = ','.join(sorted({cfa.split('+')[0].split('-')[0] for _, cfa in row['rows']}))
        categories[bases] += 1
        cross[(bases, row['saved_rbp'])] += 1
        label = 'saved_rbp_without_rbp_cfa' if row['saved_rbp'] and 'RBP' not in bases else bases
        if label not in samples:
            samples[label] = row
        if row.get('inherited_cie_only') and 'cie_only' not in samples:
            samples['cie_only'] = row
    output.mkdir(parents=True, exist_ok=False)
    with gzip.GzipFile(filename='', mode='wb', fileobj=(output / 'cfa-projections.jsonl.gz').open('wb'), mtime=0) as handle:
        for row in gnu:
            handle.write((json.dumps(projection(row), sort_keys=True, separators=(',', ':')) + '\n').encode())
    summary = dict(target_sha256=TARGET, target_bytes=len(image), native=metrics,
                   fde_categories=dict(categories), saved_rbp=sum(x['saved_rbp'] for x in gnu),
                   cross_tab=[dict(cfa_bases=k[0], saved_rbp=k[1], fdes=v) for k, v in sorted(cross.items())],
                   projection_matches=len(gnu), corruption_controls=corruption, samples=samples,
                   raw={p.name:dict(bytes=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(native.iterdir()) if p.is_file()})
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('samples', 'raw')}, indent=2))


if __name__ == '__main__':
    main()
