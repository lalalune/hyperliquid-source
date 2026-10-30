#!/usr/bin/env python3
"""Fail-closed packet manifest and target-bound regeneration verifier."""
import hashlib
import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST = frozenset({'README.md', 'RESULT.md', 'l1-evm-inventory.json',
                      'excerpts.txt', 'verify.py'})
JSON_SHA256 = '1cfe4d1be30790b7c7805251789e36dc9345c236583d974d651788500b3448e4'


def check_packet(here=HERE):
    lines = (here / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines()
    entries = {}
    for line in lines:
        m = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        if not m or m.group(2) in entries:
            raise ValueError('malformed or duplicate manifest entry')
        entries[m.group(2)] = m.group(1)
    if set(entries) != MANIFEST:
        raise ValueError('manifest whitelist mismatch')
    for name, expected in entries.items():
        path = here / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'manifest mismatch: {name}')
    sys.path.insert(0, str(ROOT / 'tools'))
    spec = importlib.util.spec_from_file_location('l1_evm_inventory', ROOT / 'tools/l1_evm_inventory.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.build((ROOT / 'artifacts/node/94/hl-node').read_bytes())
    generated = module.render(result)
    if hashlib.sha256(generated).hexdigest() != JSON_SHA256:
        raise ValueError('unexpected regenerated JSON digest')
    if (here / 'l1-evm-inventory.json').read_bytes() != generated:
        raise ValueError('JSON differs from regenerated evidence')
    if (here / 'excerpts.txt').read_bytes() != module.excerpts(result):
        raise ValueError('excerpts differ from regenerated evidence')
    if result['location_count'] != 10 or result['reference_site_count'] != 18 or result['fde_count'] != 11:
        raise ValueError('unexpected census totals')


def main():
    try:
        check_packet()
    except (OSError, ValueError, ImportError, KeyError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1
    print('PASS: manifest, target digest, census and regenerated evidence')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
