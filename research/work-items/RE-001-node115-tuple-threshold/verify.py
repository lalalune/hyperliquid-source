#!/usr/bin/env python3
"""Whitelist and regenerate the tuple-threshold packet; static stdlib only (MIT)."""
import hashlib
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_tuple_threshold as subject

# Literal whitelist, independent of manifest content or filenames it supplies.
LOCAL = frozenset({'README.md', 'records.json', 'verify.py'})
EXTERNAL = frozenset({'../../../tools/node115_tuple_threshold.py',
                      '../../../tests/test_node115_tuple_threshold.py',
                      '../../../tools/elf_index.py', '../../../tools/fde_extents.py'})


def verify_manifest(folder=HERE, root=ROOT):
    folder, root = Path(folder), Path(root)
    if {p.name for p in folder.iterdir()} != LOCAL | {'MANIFEST.sha256'}:
        raise ValueError('Packet file whitelist mismatch')
    if any(p.is_symlink() or not p.is_file() for p in folder.iterdir()):
        raise ValueError('Packet must contain regular files only')
    seen = set()
    for line in (folder / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if match is None:
            raise ValueError('Malformed manifest line')
        want, relative = match.groups()
        if relative not in LOCAL | EXTERNAL or relative in seen:
            raise ValueError('Manifest whitelist/duplicate mismatch')
        seen.add(relative)
        path = root / relative[9:] if relative in EXTERNAL else folder / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing or nonregular manifest file')
        expected_root = root.resolve() if relative in EXTERNAL else folder.resolve()
        if not path.resolve().is_relative_to(expected_root):
            raise ValueError('Manifest path escape')
        if hashlib.sha256(path.read_bytes()).hexdigest() != want:
            raise ValueError('Manifest digest mismatch')
    if seen != LOCAL | EXTERNAL:
        raise ValueError('Missing manifest entry')


def verify(folder=HERE, root=ROOT):
    verify_manifest(folder, root)
    record = subject.collect_path(root / 'artifacts/node/115/hl-node')
    if (folder / 'records.json').read_bytes() != subject.json_bytes(record):
        raise ValueError('Regenerated records differ')
    if (folder / 'README.md').read_bytes() != subject.render_readme(record):
        raise ValueError('README differs from JSON-derived rendering')
    return record


if __name__ == '__main__':
    try:
        result = verify()
        print('Verified node #115 tuple-threshold evidence, exact whitelist and regeneration.')
    except (ValueError, OSError) as error:
        print(f'tuple-threshold verifier: {error}', file=sys.stderr)
        sys.exit(1)
