"""Compare reproduced exports without treating their local filename as evidence.

The original bytes and manifest digests remain intact. Only the filename in
objdump's file-format header is normalized; formats, instructions and operands
remain exact. Manifests are authenticated before deriving comparable digests.
"""
import hashlib
from pathlib import Path
import re


def comparable_export(path):
    path = Path(path)
    raw = path.read_bytes()
    if path.name == 'MANIFEST.sha256':
        rows = []
        for line in raw.decode().splitlines():
            digest, name = line.split('  ', 1)
            target = path.parent / name
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise ValueError('export manifest digest mismatch: ' + name)
            normalized = comparable_export(target)
            rows.append(hashlib.sha256(normalized).hexdigest() + '  ' + name)
        return ('\n'.join(rows) + '\n').encode()
    if path.name.endswith('.objdump.txt'):
        return re.sub(rb'(?m)^.+(?=: +file format )', b'<binary>', raw)
    return raw
