#!/usr/bin/env python3
"""Fail-closed manifest + byte-identical regeneration for the RE-012 packet."""
import hashlib
import importlib.util
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
# Exact allowlist: RESULT.md is required, not an optional unhashed attachment.
MANIFEST = frozenset({
    'README.md', 'RESULT.md', 'verify.py', 'startup-inventory.json', 'byte-excerpts.txt',
    '../../../tools/hl_node_startup_inventory.py',
    '../../../tests/test_hl_node_startup_inventory.py',
    '../../../tools/elf_index.py', '../../../tools/fde_extents.py',
})
OUTPUT_SHA256 = '58ea0049b4d1118fcb981e385549d792990589998f3d5b7e0c9a3aaafee963e8'


def check(condition, message):
    if not condition:
        raise ValueError(message)


def manifest_entries(text):
    entries = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        check(match is not None, 'malformed manifest entry')
        digest, name = match.groups()
        check(name in MANIFEST, f'non-whitelisted manifest path: {name}')
        check(name not in entries, f'duplicate manifest path: {name}')
        entries[name] = digest
    check(entries.keys() == MANIFEST, 'manifest whitelist incomplete (including RESULT.md)')
    return entries


def verify_manifest(here=HERE):
    entries = manifest_entries((here / 'MANIFEST.sha256').read_text())
    for name, expected in sorted(entries.items()):
        path = here / name
        check(path.is_file() and not path.is_symlink(), f'missing file or symlink: {name}')
        check(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
              f'manifest hash mismatch: {name}')


def main():
    try:
        verify_manifest()
        spec = importlib.util.spec_from_file_location(
            'hl_node_startup_inventory', ROOT / 'tools/hl_node_startup_inventory.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        r = tool.build((ROOT / 'artifacts/node/94/hl-node').read_bytes())
        for name, content in tool.generated_files(r).items():
            check((HERE / name).read_bytes() == content, f'regeneration differs: {name}')
        check(hashlib.sha256(tool.render(r)).hexdigest() == OUTPUT_SHA256, 'pinned JSON hash')
        check(r['counts'] == {
            'locations': 53, 'location_leas': 57, 'locations_without_lea': 0,
            'scoped_fdes': 15, 'decoded_fdes_total': 121299,
            'cli_candidates': 16, 'cli_bound': 10, 'cli_unresolved': 6,
        }, 'pinned counts')
        check(all(l['file'] == 'node/src/hl_node.rs' for l in r['locations']), 'primary scope')
        check(r['scoped_call']['bytes'] == 'e89a2dfcff', 'call bytes')
        check(r['scoped_call']['to_va'] == 0x2271d00, 'call destination')
        print('PASS: manifest, pinned node #94, JSON/excerpts byte-identical; 53 Locations / 57 LEAs / 15 FDEs; CLI 10 bound / 6 unresolved')
        return 0
    except (OSError, ValueError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
