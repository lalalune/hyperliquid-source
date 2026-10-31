#!/usr/bin/env python3
"""Independently count CFA register sets in GNU readelf's interpreted CFI."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280


def register(token):
    match = re.fullmatch(r'(rsp|rbp|r11)[+-]\d+', token)
    if not match:
        raise ValueError(f'Unrecognized CFA rule: {token}')
    return {'rsp': 7, 'rbp': 6, 'r11': 11}[match[1]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = args.input.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('Expected exact node #94 size and SHA-256')
    expected = json.loads(args.summary.read_text(encoding='utf-8'))
    if expected['target_sha256'] != SHA256:
        raise ValueError('Summary target mismatch')
    start, end = int(expected['text_start_va'], 16), int(expected['text_end_va'], 16)
    counts, cies = Counter(), {}
    selected = {0x14509f0, 0x14027b0, 0x13c8e10, 0x151f6f0}
    samples, paragraph = [], []
    raw_digest = hashlib.sha256()

    def consume(lines):
        if not lines or not re.match(r'^[0-9a-f]+\s', lines[0]):
            return
        header = lines[0]
        if re.fullmatch(r'[0-9a-f]+\s+ZERO terminator', header):
            return
        rules = [register(line.split()[1]) for line in lines[1:]
                 if re.match(r'^[0-9a-f]+\s', line)]
        if ' CIE ' in header:
            if not rules:
                raise ValueError('CIE has no decoded CFA rule')
            cies[int(header.split()[0], 16)] = rules[-1]
            return
        match = re.search(r'FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)', header)
        if not match:
            raise ValueError(f'Unrecognized frame header: {header}')
        address = int(match[2], 16)
        if start <= address < end:
            # readelf elides an FDE table when the CIE rule never changes.
            states = set(rules) if rules else {cies[int(match[1], 16)]}
            counts[','.join(map(str, sorted(states)))] += 1
        if address in selected:
            samples.append('\n'.join(lines) + '\n')

    process = subprocess.Popen(['readelf', '-W', '--debug-dump=frames-interp', str(args.input)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None
    for raw_line in process.stdout:
        raw_digest.update(raw_line)
        line = raw_line.decode('ascii').rstrip('\r\n')
        if line:
            paragraph.append(line)
        else:
            consume(paragraph)
            paragraph = []
    consume(paragraph)
    _, error = process.communicate()
    if process.returncode:
        raise RuntimeError(error.decode('utf-8', errors='replace'))
    if dict(counts) != expected['cfa_register_sets']:
        raise ValueError(f'Independent counts differ: {dict(counts)}')
    if len(samples) != len(selected):
        raise ValueError('Selected readelf examples are missing')
    output = {'target_sha256': SHA256, 'readelf_version': subprocess.check_output(
        ['readelf', '--version'], text=True).splitlines()[0],
        'interpreted_output_sha256': raw_digest.hexdigest(),
        'fde_count': sum(counts.values()), 'cfa_register_sets': dict(sorted(counts.items())),
        'matches_pyelftools': True, 'captured_binary_executed': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8', newline='\n')
    args.output.with_suffix('.txt').write_text('\n'.join(samples), encoding='utf-8', newline='\n')
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
