#!/usr/bin/env python3
"""Rebuild the RE-014 outputs from the pinned artifacts and check them against validation.json.

Exits non-zero on any mismatch. Uses no assert, so it holds under python -O.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUTPUTS = ('node-94-115-drift.tsv', 'node-94-115-drift.json', 'node-94-115-paths.json')
RETAINED = ('node-94-115-drift.json', 'node-94-115-paths.json')


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    expected = json.loads((HERE / 'validation.json').read_text())
    failures = []
    for name in RETAINED:
        if sha256(HERE / name) != expected['outputs'][name]:
            failures.append(f'retained {name} differs from validation.json')
    objdump = subprocess.run(['objdump', '--version'], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    if objdump != expected['pinned']['objdump']:
        raise SystemExit(f'RE-014 verify needs {expected["pinned"]["objdump"]!r}, found {objdump!r}')
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / 'drift'
        subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/release_drift.py'), '--output-dir', str(out)],
                       check=True, cwd=ROOT)
        for name in OUTPUTS:
            got = sha256(out / name)
            if got != expected['outputs'][name]:
                failures.append(f'rebuilt {name}: {got} != {expected["outputs"][name]}')
        summary = json.loads((out / 'node-94-115-drift.json').read_text())
        cross = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'crosscheck.py'), '--tsv',
                                str(out / 'node-94-115-drift.tsv')], capture_output=True, text=True, cwd=ROOT)
        if cross.returncode or json.loads(cross.stdout) != expected['crosscheck']:
            failures.append(f'crosscheck: {cross.stdout.strip()} {cross.stderr.strip()}')
    for key, want in expected['pinned'].items():
        got = summary
        for part in key.split('.'):
            got = got[part]
        if got != want:
            failures.append(f'{key}: {got!r} != {want!r}')
    controls = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'mutation_controls.py')], cwd=ROOT)
    if controls.returncode:
        failures.append('mutation_controls.py failed')
    if failures:
        raise SystemExit('RE-014 verify failed:\n' + '\n'.join(failures))
    print(f'RE-014 verify ok: {len(OUTPUTS)} outputs and {len(expected["pinned"])} pinned values match')


if __name__ == '__main__':
    main()
