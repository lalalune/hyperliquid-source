#!/usr/bin/env python3
"""Verify the exact packet whitelist and reproduce its static #115 evidence."""
import hashlib
from pathlib import Path
import re
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_wrapped_key56_search as bind

ALLOWED = frozenset(('README.md', 'records.json', 'verify.py',
                     '../../../tools/node115_wrapped_key56_search.py',
                     '../../../tests/test_node115_wrapped_key56_search.py',
                     '../../../tools/elf_index.py', '../../../tools/fde_extents.py'))
PACKET_FILES = frozenset(('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'))


def check_manifest(packet):
    packet = Path(packet)
    if {p.name for p in packet.iterdir()} != PACKET_FILES:
        raise ValueError('packet file whitelist mismatch')
    seen = set()
    for line in (packet / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('malformed manifest row')
        want, name = match.groups()
        if name not in ALLOWED or name in seen:
            raise ValueError('manifest whitelist or duplicate entry')
        seen.add(name)
        target = (ROOT / name[9:]) if name.startswith('../../../') else packet / name
        if target.is_symlink() or not target.is_file():
            raise ValueError('manifest target missing or symlinked')
        if hashlib.sha256(target.read_bytes()).hexdigest() != want:
            raise ValueError('manifest digest mismatch: ' + name)
    if seen != ALLOWED:
        raise ValueError('manifest entry set incomplete')


def verify(packet=bind.PACKET):
    packet = Path(packet)
    check_manifest(packet)
    with tempfile.TemporaryDirectory(prefix='node115-key56-') as tmp:
        record = bind.generate(bind.TARGET, Path(tmp))
        for name in PACKET_FILES:
            if (Path(tmp) / name).read_bytes() != (packet / name).read_bytes():
                raise ValueError('regenerated evidence differs: ' + name)
    return record


if __name__ == '__main__':
    try:
        result = verify()
        print(f"Verified node #115 {bind.START:#x}: complete body, exact whitelist, byte-identical regeneration.")
    except (OSError, ValueError) as error:
        raise SystemExit('verify: ' + str(error))
