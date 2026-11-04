#!/usr/bin/env python3
"""Replay one closed, target-bound static packet; never execute the target."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_cli_common_settings as common


def native_rows(text):
    rows = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)(.*)$', line)
        if not match:
            continue
        address, raw, asm = int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()
        if asm:
            rows.append([address, raw])
        else:
            common.require(rows and rows[-1][0] + len(rows[-1][1]) == address,
                           'native continuation address')
            rows[-1][1] += raw
    return rows


def compare_native(text, expected):
    actual = native_rows(text)
    wanted = [(int(row['va'], 16), bytes.fromhex(row['bytes'])) for row in expected]
    common.require(len(actual) == len(wanted), 'native instruction count')
    for row, wanted_row in zip(actual, wanted):
        common.require(tuple(row) == wanted_row, 'native address/bytes')
    return len(actual)


def verify_manifest():
    manifest = json.loads((PACKET / 'MANIFEST.json').read_text(encoding='utf-8'))
    common.require(not any(p.is_symlink() for p in PACKET.rglob('*')),
                   'packet symlink')
    expected = set(manifest['files'])
    actual = {p.relative_to(PACKET).as_posix() for p in PACKET.rglob('*')
              if p.is_file() and p.name != 'MANIFEST.sha256'}
    common.require(expected == actual and len(expected) == len(manifest['files']),
                   'closed packet inventory')
    wanted = {(PACKET.relative_to(ROOT) / path).as_posix() for path in expected}
    wanted.update(manifest['sourceFiles'])
    entries = {}
    for line in (PACKET / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./-]+)', line)
        common.require(match is not None and match[2] not in entries,
                       'manifest SHA row')
        entries[match[2]] = match[1]
    common.require(set(entries) == wanted, 'closed source SHA inventory')
    for name, expected_hash in entries.items():
        path = ROOT / name
        common.require('..' not in Path(name).parts and not path.is_symlink()
                       and path.resolve().is_relative_to(ROOT.resolve()),
                       'manifest containment/no symlink')
        common.require(path.is_file()
                       and hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash,
                       'manifest file bytes: ' + name)
    return len(entries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--native-output', type=Path)
    parser.add_argument('--objdump', type=Path)
    args = parser.parse_args()
    common.require(bool(args.native_output) == bool(args.objdump),
                   'native output and objdump must be paired')
    count = verify_manifest()
    spec = json.loads((PACKET / 'spec.json').read_text(encoding='utf-8'))
    records = common.collect(args.target.read_bytes(), spec)
    common.require(records == json.loads((PACKET / 'records.json').read_text(encoding='utf-8')),
                   're-derived records')
    independent = json.loads((PACKET / 'independent-instructions.json').read_text(encoding='utf-8'))
    total = 0
    exports = {'common-output-option-constructor': 'common-constructor.gnu.objdump',
               'style-validator': 'style-validator.gnu.objdump',
               'style-once': 'style-once.gnu.objdump'}
    for function in records['functions']:
        name = function['name']
        rows = independent[name]
        raw = bytes.fromhex(function['raw'])
        common.require(b''.join(bytes.fromhex(row['bytes']) for row in rows) == raw,
                       'independent complete raw bytes')
        cursor = int(function['start'], 16)
        for row in rows:
            common.require(int(row['va'], 16) == cursor, 'independent contiguous rows')
            cursor += len(bytes.fromhex(row['bytes']))
        common.require(cursor == int(function['end'], 16), 'independent full FDE end')
        total += compare_native((PACKET / exports[name]).read_text(encoding='utf-8-sig'), rows)
        if args.native_output:
            args.native_output.mkdir(parents=True, exist_ok=True)
            command = [str(args.objdump), '-d', '-Mintel', '--insn-width=16',
                       '--start-address=' + function['start'],
                       '--stop-address=' + function['end'], str(args.target)]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=60)
            (args.native_output / exports[name]).write_bytes(result.stdout)
            (args.native_output / (exports[name] + '.stderr')).write_bytes(result.stderr)
            common.require(result.returncode == 0, 'fresh native disassembly')
            compare_native(result.stdout.decode('utf-8-sig'), rows)
    print(json.dumps({'verifiedFiles': count, 'functions': 3, 'bytes': 11696,
                      'exactInstructionRows': total, 'freshNativeReplay': bool(args.native_output),
                      'masks': [], 'capturedExecution': False, 'componentGate': False}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('common-settings packet: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
