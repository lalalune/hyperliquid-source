#!/usr/bin/env python3
"""Check only the packet's explicit file set against the authenticated target."""
import hashlib
import mmap
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools import aligned_quotient_94 as bind


def verify(packet, binary=bind.BINARY):
    packet = Path(packet)
    names = ('README.md', 'records.json', 'verify.py')
    expected_files = set(names) | {'MANIFEST.sha256'}
    if {p.name for p in packet.iterdir()} != expected_files:
        raise ValueError('packet file whitelist mismatch')
    manifest = ''.join(hashlib.sha256((packet/name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names)
    if (packet/'MANIFEST.sha256').read_text() != manifest:
        raise ValueError('manifest mismatch')
    with open(binary, 'rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        records = bind.inspect(data)
    if (packet/'records.json').read_text() != bind.render_records(records):
        raise ValueError('records mismatch')
    if (packet/'README.md').read_text() != bind.readme(records):
        raise ValueError('README mismatch')


if __name__ == '__main__':
    verify(Path(__file__).resolve().parent)
    print('Packet verified')
