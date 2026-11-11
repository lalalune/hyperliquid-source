#!/usr/bin/env python3
"""Verify the byte-prefix caller packet against the pinned target."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TOOL = ROOT / 'tools/re001_byte_prefix_caller_output_115.py'
SPEC = importlib.util.spec_from_file_location('byte_prefix_caller', TOOL)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def main():
    expected_files = {'README.md', 'records.json', 'verify.py'}
    manifest = {}
    for line in (HERE / 'MANIFEST.sha256').read_text().splitlines():
        digest, name = line.split('  ', 1)
        if name in manifest or Path(name).name != name:
            raise SystemExit(f'invalid manifest path: {name}')
        manifest[name] = digest
    if set(manifest) != expected_files:
        raise SystemExit(f'manifest entries differ: {sorted(manifest)}')
    for name, digest in manifest.items():
        if hashlib.sha256((HERE / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f'manifest mismatch: {name}')
    actual = module.extract(module.TARGET.read_bytes())
    if actual != json.loads((HERE / 'records.json').read_text()):
        raise SystemExit('records differ from regenerated target evidence')
    print(f"verified calls={len(actual['calls'])} values=" + ','.join(
        str(row['tag_9_action']['u64_value']) for row in actual['calls']))


if __name__ == '__main__':
    main()
