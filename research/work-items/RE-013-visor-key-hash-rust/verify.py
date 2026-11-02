#!/usr/bin/env python3
"""Static/corpus replay; optional source-absence gate before production Rust."""
import argparse
import copy
import gzip
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import collect
import corpus

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def inventory(base):
    return {p.relative_to(base).as_posix(): dict(bytes=p.stat().st_size, sha256=collect.sha(p.read_bytes()))
            for p in sorted(base.rglob('*')) if p.is_file()}


def controls(image, pins, frames):
    results = []
    def reject(name, kind, function, coordinates=None):
        try:
            function()
        except ValueError as error:
            results.append(dict(name=name, kind=kind, rejected=True, reason=str(error), coordinates=coordinates))
            return
        raise ValueError('negative control accepted: ' + name)
    reject('wrong-whole-image', 'identity only',
           lambda: collect.admit_image(image.data[:-1] + bytes([image.data[-1] ^ 1]), pins))
    reject('truncated-whole-image', 'identity only', lambda: collect.admit_image(image.data[:-1], pins))
    selected = [0x626769, 0x62677c, 0x6267b0, 0x6267b5, 0x6267bf, 0x6267c7,
                0x6267d1, 0x6267f4, 0x626821, 0x626824, 0x6268a2, 0x6268b7,
                0x628d01, 0x628d1d, 0x628d93, 0x628df5, 0x628dfb, 0x628e20,
                0x628e5a, 0x628e61, 0x628ed1, 0x5d3269, 0x5b912a]
    for va in selected:
        offset = image.offset(va, 1)
        data = bytearray(image.data)
        data[offset] ^= 1
        changed = collect.Image(bytes(data))
        reject('operand-' + hex(va), 'operand binding below image/body hashes',
               lambda changed=changed: collect.derive(changed, pins, frames, False),
               dict(va=hex(va), file_offset=offset, original=image.at(va, 1).hex(), changed=changed.at(va, 1).hex()))
    for va in [0x6d380, 0x6cfd0, 0xb72c6, 0xb72d3]:
        data = bytearray(image.data)
        off = image.offset(va, 1)
        data[off] ^= 1
        changed = collect.Image(bytes(data))
        reject('literal-' + hex(va), 'data binding below image/body hashes',
               lambda changed=changed: collect.derive(changed, pins, frames, False), dict(va=hex(va), file_offset=off))
    first = pins['bodies'][0]
    fde = int(first['fde_va'], 16)
    for label, relative in [('cie-pointer', 4), ('fde-start', 8), ('fde-size', 12)]:
        data = bytearray(image.data)
        data[image.offset(fde + relative, 1)] ^= 1
        changed = collect.Image(bytes(data))
        edited_pins = copy.deepcopy(pins)
        edited_pins['bodies'][0]['fde_raw'] = changed.record(fde).hex()
        reject(label, 'decoded field with FDE raw identity rebound',
               lambda changed=changed, edited_pins=edited_pins: collect.derive(changed, edited_pins, frames, False),
               dict(va=hex(fde + relative), file_offset=image.offset(fde + relative, 1)))
    rr = collect.relas(image)
    spare = next(r for r in rr if r['type'] == 8 and r['destination'] not in [int(p['slot'], 16) for p in pins['context_slots']])
    for label, destination in [('overlapping-writer', 0x626760 - 7), ('duplicate-context-slot', 0x7e4c78)]:
        data = bytearray(image.data)
        struct.pack_into('<Q', data, spare['file_offset'], destination)
        changed = collect.Image(bytes(data))
        reject(label, 'RELA structural binding below image/body hashes',
               lambda changed=changed: collect.derive(changed, pins, frames, False),
               dict(record_file_offset=spare['file_offset'], destination=hex(destination)))
    output = gzip.decompress((HERE / 'observed/outer.gnu.txt.gz').read_bytes()).decode()
    altered = output.replace('53 ', '52 ', 1)
    collect.require(altered != output, 'native corruption coordinate')
    reject('false-native-first-byte', 'independent provider byte partition',
           lambda: collect.rows(altered, image, 0x626760, 0x6268c0))
    lines = [line for line in output.splitlines(True) if not line.lstrip().startswith('6268bf:')]
    reject('truncated-native-final-ret', 'independent provider complete partition',
           lambda: collect.rows(''.join(lines), image, 0x626760, 0x6268c0))
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--require-source-absent', action='store_true')
    args = parser.parse_args()
    collect.require(not args.out.exists(), 'fresh output required')
    source_absent = not (ROOT / 'src/visor-key-hash').exists()
    if args.require_source_absent:
        collect.require(source_absent, 'pre-code gate requires source absence')
    pins = json.loads((HERE / 'BASIS-PINS.json').read_text())
    image = collect.authenticate(ROOT, pins)
    frames = collect.native(['/opt/homebrew/opt/binutils/bin/readelf', '--debug-dump=frames', pins['target']['path']], ROOT)
    collect.derive(image, pins, frames)
    a, c = struct.unpack('<QQ', image.at(0x6d380, 16))
    b, d = struct.unpack('<QQ', image.at(0x6cfd0, 16))
    collect.require(corpus.CONSTANTS == (a, b, c, d), 'oracle constants differ from actual seed lane literals')
    negative = controls(image, pins, frames)
    args.out.mkdir(parents=True)
    commands = []
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    for script, directory, retained in [('collect.py', 'native', 'observed'), ('corpus.py', 'corpus', 'frozen')]:
        argv = [sys.executable, str(HERE / script), '--out', str(args.out / directory)]
        process = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
        collect.require(process.returncode == 0 and not process.stderr, 'regeneration failed: ' + script)
        expected, actual = inventory(HERE / retained), inventory(args.out / directory)
        collect.require(actual == expected, 'fresh outputs differ: ' + script)
        commands.append(dict(argv=['<PYTHON>', '<PACKET>/' + script, '--out', '<OUTPUT>/' + directory],
                             exit_code=process.returncode, stdout=process.stdout, stderr=process.stderr,
                             byte_identical_files=len(actual)))
    source_after = not (ROOT / 'src/visor-key-hash').exists()
    if args.require_source_absent:
        collect.require(source_after, 'source appeared during pre-code gate')
    collect.authenticate(ROOT, pins)
    receipt = dict(status='PASS: static native and independent mathematical evidence',
                   phase='pre-code gate' if args.require_source_absent else 'static replay',
                   source_absence_required=args.require_source_absent,
                   source_absent_before=source_absent, source_absent_after=source_after,
                   controls=negative, regenerations=commands,
                   inputs={name: collect.sha((HERE / name).read_bytes()) for name in
                           ['CONTRACT.md', 'PROOF.md', 'BASIS-PINS.json', 'collect.py', 'corpus.py', 'verify.py', 'VALIDATION-PLAN.md']},
                   limits='Binding/arithmetic regeneration only, not Rust qualification or target execution; finite controls do not prove semantics.')
    collect.write_json(args.out / 'receipt.json', receipt)
    print(json.dumps(dict(status=receipt['status'], controls=len(negative),
                          byte_identical_files=sum(r['byte_identical_files'] for r in commands), source_absent=source_after)))


if __name__ == '__main__':
    main()
