#!/usr/bin/env python3
"""Check this evidence packet and replay its two bounded verifiers."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def need(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    manifest = json.loads((HERE / 'manifest.json').read_text())
    seen = set()
    for record in manifest['files']:
        name = record['path']
        path = PurePosixPath(name)
        need(not path.is_absolute() and '..' not in path.parts and
             str(path) == name and name not in seen and name != 'manifest.json',
             'unique relative manifest path')
        seen.add(name)
        local = HERE / name
        need(local.is_file() and not local.is_symlink(), 'regular evidence file: ' + name)
        raw = local.read_bytes()
        need(len(raw) == record['bytes'] and
             hashlib.sha256(raw).hexdigest() == record['sha256'],
             'evidence identity: ' + name)
    actual = {str(p.relative_to(HERE)) for p in HERE.rglob('*')
              if p.is_file() and '__pycache__' not in p.parts and p.name != 'manifest.json'}
    need(actual == seen, 'complete packet inventory')
    for script in ('verify_static.py', 'source-build/verify_export.py'):
        subprocess.run([sys.executable, '-O', '-B', str(HERE / script)],
                       cwd=HERE.parents[2], check=True)
    print(json.dumps({'packet': 'RE-012-listener-source-94', 'status': 'pass',
                      'manifest_files': len(seen), 'captured_execution': False}))


if __name__ == '__main__':
    main()
