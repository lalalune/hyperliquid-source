#!/usr/bin/env python3
"""Rebuild the RE-014 outputs from the pinned artifacts and check them against validation.json.

Exits non-zero on any mismatch. Uses no assert, so it holds under python -O.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import re
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUTPUTS = ('node-94-115-drift.tsv', 'node-94-115-drift.json', 'node-94-115-paths.json')
RETAINED = ('node-94-115-drift.json', 'node-94-115-paths.json')


_OBJDUMP_VERSION_TOKEN = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")


def parse_objdump_version(line):
    """Return the trailing dotted version token from an objdump --version first line.

    Deterministic: last whitespace-separated field must match N(.N)+ exactly
    (e.g. 2.44, 2.46.1). Returns None if missing or unparseable. 2.4 and 2.440
    are distinct from 2.44.
    """
    if not isinstance(line, str):
        return None
    text = line.strip()
    if not text:
        return None
    token = text.split()[-1]
    if _OBJDUMP_VERSION_TOKEN.fullmatch(token):
        return token
    return None


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    expected = json.loads((HERE / 'validation.json').read_text())
    failures = []
    for name in RETAINED:
        if sha256(HERE / name) != expected['outputs'][name]:
            failures.append(f'retained {name} differs from validation.json')
    sys.path.insert(0, str(ROOT / 'tools'))
    from release_drift import gnu_objdump
    objdump_path, objdump = gnu_objdump()
    if not objdump_path:
        # Evidence rebuild needs GNU; skip with reason — do not claim PASS.
        print(f'RE-014 verify SKIPPED (not a PASS): {objdump}', flush=True)
        raise SystemExit(2)
    version = parse_objdump_version(objdump)
    if version is None:
        print(
            'RE-014 verify SKIPPED (not a PASS): fingerprints pinned to GNU objdump 2.44; '
            f'could not parse version from {objdump!r}',
            flush=True,
        )
        raise SystemExit(2)
    if version != '2.44':
        print(
            'RE-014 verify SKIPPED (not a PASS): fingerprints pinned to GNU objdump 2.44; '
            f'detected {version} ({objdump!r})',
            flush=True,
        )
        raise SystemExit(2)
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
