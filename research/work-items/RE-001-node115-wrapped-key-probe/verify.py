#!/usr/bin/env python3
"""Verify an exact packet whitelist and regenerate its static evidence."""
import hashlib
from pathlib import Path
import re
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_wrapped_key_probe as subject

WHITELIST = frozenset({
    'README.md', 'records.json', 'instructions.txt', 'verify.py',
    '../../../tools/node115_wrapped_key_probe.py',
    '../../../tests/test_node115_wrapped_key_probe.py',
    '../../../tools/elf_index.py', '../../../tools/fde_extents.py',
})
PAYLOADS = frozenset({'README.md', 'records.json', 'instructions.txt'})


def check_manifest(packet=HERE, root=ROOT):
    packet, root = Path(packet), Path(root).resolve()
    entries = {}
    for line in (packet / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if match is None:
            raise ValueError('malformed manifest row')
        digest, name = match.groups()
        if name not in WHITELIST or name in entries:
            raise ValueError('manifest whitelist or duplicate violation')
        entries[name] = digest
    if set(entries) != WHITELIST:
        raise ValueError('manifest whitelist incomplete')
    local_files = {p.name for p in packet.iterdir() if p.is_file()}
    if local_files != {n for n in WHITELIST if '/' not in n} | {'MANIFEST.sha256'}:
        raise ValueError('packet contains missing or unexpected files')
    for name, digest in entries.items():
        path = (packet / name).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError('manifest path escapes repository or is missing')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('manifest digest mismatch: ' + name)
    return len(entries)


def verify(packet=HERE, root=ROOT):
    count = check_manifest(packet, root)
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory)
        result = subject.generate(Path(root) / 'artifacts/node/115/hl-node', output)
        if {p.name for p in output.iterdir()} != PAYLOADS:
            raise ValueError('unexpected regenerated payload set')
        for name in PAYLOADS:
            if (output / name).read_bytes() != (Path(packet) / name).read_bytes():
                raise ValueError('regenerated evidence differs: ' + name)
    return count, result['counts']


if __name__ == '__main__':
    try:
        count, metrics = verify()
        print(f'Verified {count} whitelisted files; all generated evidence is byte-identical.')
        print(f"Bound leaf: {metrics['body_bytes']} bytes, {metrics['body_instructions']} instructions; "
              f"{metrics['callees']} callees, {metrics['direct_call_sites']} direct call site.")
    except (OSError, ValueError) as error:
        print('wrapped-key-probe verification failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
