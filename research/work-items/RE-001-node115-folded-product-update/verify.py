#!/usr/bin/env python3
"""Check the fixed packet whitelist and reproduce its semantic record."""
import hashlib
from pathlib import Path
import sys
import tempfile

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_folded_product_update as producer

WHITELIST = ('README.md', 'records.json', 'verify.py')


def verify():
    if {p.name for p in PACKET.iterdir()} != set(WHITELIST) | {'MANIFEST.sha256'}:
        raise ValueError('unexpected packet file')
    lines = (PACKET / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines()
    if len(lines) != len(WHITELIST):
        raise ValueError('manifest size changed')
    expected = {}
    for line in lines:
        digest, sep, name = line.partition('  ')
        if not sep or name not in WHITELIST or name in expected or len(digest) != 64:
            raise ValueError('invalid manifest entry')
        expected[name] = digest
    if set(expected) != set(WHITELIST):
        raise ValueError('manifest whitelist changed')
    for name in WHITELIST:
        if hashlib.sha256((PACKET / name).read_bytes()).hexdigest() != expected[name]:
            raise ValueError('packet digest mismatch: ' + name)
    with tempfile.TemporaryDirectory() as tmp:
        producer.generate(producer.TARGET, Path(tmp))
        if (Path(tmp) / 'records.json').read_bytes() != (PACKET / 'records.json').read_bytes():
            raise ValueError('record differs from authenticated target')
    print('Packet whitelist and regenerated record verified')


if __name__ == '__main__':
    verify()
