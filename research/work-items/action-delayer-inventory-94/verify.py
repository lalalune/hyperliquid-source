#!/usr/bin/env python3
"""Fail-closed verification of this bounded node #94 evidence packet."""
import hashlib
import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FILES = frozenset({'README.md', 'RESULT.md', 'inventory.json', 'excerpts.txt', 'verify.py'})
BIN_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def check(condition, msg):
    if not condition:
        raise ValueError(msg)


def verify_packet(here=HERE, root=ROOT):
    entries = {}
    for line in (here / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines():
        m = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        check(m is not None, 'malformed manifest')
        digest, name = m.groups()
        check(name not in entries, 'duplicate manifest entry')
        entries[name] = digest
    check(set(entries) == FILES, 'manifest file set mismatch')
    for name, digest in entries.items():
        check(hashlib.sha256((here / name).read_bytes()).hexdigest() == digest, f'manifest mismatch: {name}')
    binary = (root / 'artifacts/node/94/hl-node').read_bytes()
    check(hashlib.sha256(binary).hexdigest() == BIN_SHA256, 'target digest mismatch')
    sys.path.insert(0, str(root / 'tools'))
    spec = importlib.util.spec_from_file_location('action_delayer_inventory', root / 'tools/action_delayer_inventory.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    result = mod.build(binary)
    check((here / 'inventory.json').read_bytes() == mod.render(result), 'inventory regeneration mismatch')
    check((here / 'excerpts.txt').read_bytes() == mod.excerpts(binary), 'excerpt regeneration mismatch')
    check(len(result['locations']) == 1 and len(result['scoped_fdes']) == 1, 'census mismatch')
    check([c['status'] for c in result['constants']] == ['co-located comparison'] * 2 + ['unresolved'] * 4,
          'constant status mismatch')
    return True


def main():
    try:
        verify_packet()
    except (OSError, ValueError, KeyError, IndexError, ImportError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1
    print('PASS: manifest, pinned target, regenerated inventory and excerpts')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
