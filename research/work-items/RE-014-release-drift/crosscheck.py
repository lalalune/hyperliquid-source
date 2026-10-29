#!/usr/bin/env python3
"""Independent spot check of RE-014 verdicts against bytes and a second objdump pass.

Takes a deterministic sample (every Nth row of each class, in TSV order) and checks:
  identical    -> file bytes equal (sliced via readelf section headers, not our tool),
                  and a per-function objdump --start/--stop-address disassembly has the same
                  instructions once hex numbers are masked (absolute branch targets move with the code)
  moved_only   -> file bytes differ, sizes equal, and the disassembly is equal once every
                  hex number is masked (a broader mask than the tool's)
  changed      -> file bytes differ
Prints one JSON summary; exits non-zero on any contradiction. No assert, so it holds under -O.
"""
from pathlib import Path
import argparse
import csv
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
BINARY = {r: ROOT / f'artifacts/node/{r}/hl-node' for r in ('94', '115')}
ENV = {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'}
HEX = re.compile(r'-?\b(?:0x)?[0-9a-f]+\b')


def text_section(path):
    out = subprocess.run(['readelf', '-W', '-S', str(path)], capture_output=True, text=True, check=True, env=ENV).stdout
    for line in out.splitlines():
        fields = line.replace('[ ', '[').split()
        if len(fields) > 5 and fields[1] == '.text':
            return int(fields[3], 16), int(fields[4], 16)
    raise SystemExit(f'no .text in {path}')


def disasm(path, start, size):
    out = subprocess.run(['objdump', '-d', '--no-show-raw-insn', '-w', '-j', '.text', f'--start-address={start:#x}',
                          f'--stop-address={start + size:#x}', str(path)], capture_output=True, text=True, check=True,
                         env=ENV).stdout
    insns = [line.split('\t', 1)[1].split('#')[0].split('<')[0].strip() for line in out.splitlines()
             if re.match(r'^\s+[0-9a-f]+:\t', line)]
    if not insns:
        raise SystemExit(f'no instructions at {start:#x} in {path}')
    return insns


def broad(a, sa, b, sb):
    return [[HEX.sub('N', i) for i in disasm(BINARY[r], s, n)] for r, s, n in (('94', a, sa), ('115', b, sb))]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--tsv', required=True)
    parser.add_argument('--every', type=int, default=97)
    args = parser.parse_args()
    data = {r: p.read_bytes() for r, p in BINARY.items()}
    text = {r: text_section(p) for r, p in BINARY.items()}

    def raw(release, start, size):
        addr, off = text[release]
        return data[release][off + start - addr:off + start - addr + size]

    seen, checked, problems = {}, {}, []
    with open(args.tsv, newline='') as handle:
        for row in csv.DictReader(handle, delimiter='\t'):
            kind = row['class']
            if kind not in ('identical', 'moved_only', 'changed'):
                continue
            seen[kind] = seen.get(kind, 0) + 1
            if (seen[kind] - 1) % args.every:
                continue
            checked[kind] = checked.get(kind, 0) + 1
            a, b = int(row['start_94'], 16), int(row['start_115'], 16)
            sa, sb = int(row['size_94']), int(row['size_115'])
            same_bytes = raw('94', a, sa) == raw('115', b, sb)
            label = f'{kind} {a:#x}/{b:#x}'
            if kind == 'identical':
                if not same_bytes or len(set(map(tuple, broad(a, sa, b, sb)))) != 1:
                    problems.append(label)
            elif same_bytes:
                problems.append(label + ': bytes equal')
            elif kind == 'moved_only':
                masked = broad(a, sa, b, sb)
                if sa != sb or masked[0] != masked[1]:
                    problems.append(label + ': differs beyond hex operands')
    print(json.dumps({'checked': checked, 'every': args.every, 'problems': problems}, sort_keys=True))
    if problems:
        raise SystemExit(f'{len(problems)} crosscheck contradictions')


if __name__ == '__main__':
    main()
