#!/usr/bin/env python3
"""Check selected static evidence against the pinned ELF; never execute it."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
spec = importlib.util.spec_from_file_location(
    'registry_verify', ROOT / 'research/work-items/RE-001-node115-registry-row-labels/verify.py'
)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def check(data, evidence):
    if evidence['bytes'] != TARGET_SIZE or evidence['sha256'] != TARGET_SHA256:
        raise ValueError('evidence identity mismatch')
    if len(data) != TARGET_SIZE or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('artifact identity mismatch')
    image = helper.Image(data)
    _, fdes = helper.eh_frame_records(data, image.sections)
    bounds = {(f['start'], f['end']) for f in fdes}
    for window in evidence['windows']:
        start, end = int(window['start'], 16), int(window['end'], 16)
        fde = tuple(int(x, 16) for x in window['fde'])
        if fde not in bounds or not fde[0] <= start < end <= fde[1]:
            raise ValueError('window FDE mismatch')
        rows = window['rows']
        cursor = start
        raw = bytearray()
        for row in rows:
            b = bytes.fromhex(row['hex'])
            if int(row['address'], 16) != cursor or not b:
                raise ValueError('noncontiguous instruction record')
            if image.get(cursor, len(b)) != b:
                raise ValueError('instruction bytes mismatch')
            cursor += len(b)
            raw.extend(b)
        if cursor != end or len(raw) != window['bytes'] or hashlib.sha256(raw).hexdigest() != window['sha256']:
            raise ValueError('window length or digest mismatch')
    relocs = image.relocs()
    for row in evidence['relocations']:
        slot = int(row['slot'], 16)
        if slot not in relocs or relocs[slot][0] != row['type'] or relocs[slot][1] != int(row['target'], 16):
            raise ValueError('relocation mismatch')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=Path, default=helper.TARGET)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    data = args.target.read_bytes()
    evidence = json.loads((PACKET / 'evidence.json').read_text())
    check(data, evidence)
    print(f"PASS: {len(evidence['windows'])} selected windows and {len(evidence['relocations'])} relocation")
    if args.controls:
        controls = []
        bad = copy.deepcopy(evidence)
        bad['sha256'] = '0' * 64
        controls.append(bad)
        bad = copy.deepcopy(evidence)
        bad['windows'][0]['rows'][0]['hex'] = '90'
        controls.append(bad)
        bad = copy.deepcopy(evidence)
        bad['windows'][0]['fde'][1] = bad['windows'][0]['start']
        controls.append(bad)
        bad = copy.deepcopy(evidence)
        bad['relocations'][0]['target'] = '0x1'
        controls.append(bad)
        for bad in controls:
            try:
                check(data, bad)
            except ValueError:
                continue
            raise AssertionError('corrupt control unexpectedly passed')
        print(f'PASS: {len(controls)} corruption controls rejected')


if __name__ == '__main__':
    main()
