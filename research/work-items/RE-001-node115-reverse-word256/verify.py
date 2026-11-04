#!/usr/bin/env python3
"""Verify only the fixed packet files against their SHA-256 manifest."""
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMES = ('README.md', 'records.json', 'verify.py')


def verify(directory=HERE):
    directory = Path(directory)
    lines = (directory / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines()
    if len(lines) != len(NAMES):
        raise ValueError('manifest length mismatch')
    for name, line in zip(NAMES, lines):
        fields = line.split('  ')
        if len(fields) != 2 or fields[1] != name or len(fields[0]) != 64:
            raise ValueError('manifest whitelist mismatch')
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != fields[0]:
            raise ValueError('manifest digest mismatch: ' + name)
    return True


if __name__ == '__main__':
    verify()
    print('Packet manifest OK')
