#!/usr/bin/env python3
"""Replay a closed Node115 registration evidence packet without target execution."""
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
import node115_cli_option_registration as contract

def native_rows(text):
    rows = []
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)(.*)$', line)
        if not m:
            continue
        address, raw = int(m[1], 16), bytes.fromhex(m[2])
        if m[3].strip():
            rows.append([address, raw])
        else:
            contract.require(rows and rows[-1][0] + len(rows[-1][1]) == address,
                             'native continuation address')
            rows[-1][1] += raw
    return rows

def compare_native(text, expected):
    rows = native_rows(text)
    wanted = [(int(r['address'], 16), bytes.fromhex(r['bytes'])) for r in expected]
    contract.require(len(rows) == len(wanted), 'native instruction count')
    for row, expected_row in zip(rows, wanted):
        contract.require(tuple(row) == expected_row, 'native address/bytes')
    return len(rows)

def verify_manifest():
    manifest = json.loads((PACKET / 'MANIFEST.json').read_text())
    declared = manifest['files']
    actual = {p.relative_to(PACKET).as_posix() for p in PACKET.rglob('*')
              if p.is_file() and p.name != 'MANIFEST.sha256'}
    contract.require(len(declared) == len(set(declared)) and set(declared) == actual,
                     'closed packet inventory')
    wanted = {(PACKET.relative_to(ROOT) / p).as_posix() for p in declared}
    wanted.update(manifest['sourceFiles'])
    entries = {}
    for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
        m = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./-]+)', line)
        contract.require(m is not None and m[2] not in entries, 'manifest SHA row')
        entries[m[2]] = m[1]
    contract.require(set(entries) == wanted, 'closed source SHA inventory')
    for relative, digest in entries.items():
        path = ROOT / relative
        contract.require('..' not in Path(relative).parts
                         and path.resolve().is_relative_to(ROOT.resolve()),
                         'manifest containment')
        current = path
        while current != ROOT:
            contract.require(not current.is_symlink(), 'manifest no symlinks')
            current = current.parent
        contract.require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                         'manifest bytes: ' + relative)
    return len(entries)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--native-output', type=Path)
    parser.add_argument('--objdump', type=Path)
    args = parser.parse_args()
    contract.require(bool(args.native_output) == bool(args.objdump), 'paired native options')
    count = verify_manifest()
    image = contract.Image(args.target.read_bytes())
    spec = json.loads((PACKET / 'spec.json').read_text())
    records = contract.derive(image, spec)
    contract.require(records == json.loads((PACKET / 'records.json').read_text()), 're-derived records')
    independent = json.loads((PACKET / 'independent-instructions.json').read_text())
    contract.require(set(independent) == {f['start'] for f in records['functions']},
                     'exact independent range inventory')
    total = 0
    fresh = []
    for function in records['functions']:
        start, end = int(function['start'], 16), int(function['end'], 16)
        rows = independent[function['start']]
        raw = b''.join(bytes.fromhex(r['bytes']) for r in rows)
        contract.require(raw == image.read(start, end - start), 'complete independent raw bytes')
        cursor = start
        boundaries = {end}
        for row in rows:
            contract.require(int(row['address'], 16) == cursor, 'contiguous independent rows')
            boundaries.add(cursor)
            cursor += len(bytes.fromhex(row['bytes']))
        contract.require(cursor == end, 'complete independent FDE end')
        for site in (function['exceptionTable'] or {}).get('sites', []):
            contract.require(int(site['start'], 16) in boundaries
                             and int(site['end'], 16) in boundaries
                             and (site['landing'] is None or int(site['landing'], 16) in boundaries),
                             'LSDA instruction boundaries')
        name = function['start'] + '.gnu.objdump'
        total += compare_native((PACKET / name).read_text(encoding='utf-8-sig'), rows)
        if args.native_output:
            args.native_output.mkdir(parents=True, exist_ok=True)
            argv = [str(args.objdump), '-d', '-Mintel', '--insn-width=16',
                    '--start-address=' + function['start'], '--stop-address=' + function['end'],
                    str(args.target)]
            p = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=60)
            (args.native_output / name).write_bytes(p.stdout)
            (args.native_output / (name + '.stderr')).write_bytes(p.stderr)
            contract.require(p.returncode == 0, 'fresh GNU exit')
            compare_native(p.stdout.decode('utf-8-sig'), rows)
            fresh.append({'start': function['start'], 'stdoutSHA256': hashlib.sha256(p.stdout).hexdigest()})
    print(json.dumps({'verifiedFiles': count, 'functions': len(records['functions']),
                      'bytes': sum(f['bytes'] for f in records['functions']),
                      'exactInstructionRows': total, 'freshNativeReplay': bool(args.native_output),
                      'freshOutputs': fresh, 'normalizationMasks': [],
                      'capturedExecution': False, 'componentGate': False}))
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('registration packet: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
