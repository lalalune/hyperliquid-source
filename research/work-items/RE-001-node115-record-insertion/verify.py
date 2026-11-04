#!/usr/bin/env python3
"""Fail-closed whitelist and binary-derived evidence verification; static only."""
import hashlib
import mmap
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_record_insertion as bind

# Keep this whitelist independent of the producer's list.
WHITELIST = (
    'README.md', 'records.json', 'verify.py',
    'tools/node115_record_insertion.py', 'tests/test_node115_record_insertion.py',
    'tools/elf_index.py', 'tools/fde_extents.py', 'tools/gas_auction_price.py',
)


def parse_manifest(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('malformed manifest line')
        digest, name = match.groups()
        if name not in WHITELIST or name in result:
            raise ValueError('unexpected or duplicate manifest entry')
        result[name] = digest
    if set(result) != set(WHITELIST):
        raise ValueError('manifest does not cover exact whitelist')
    return result


def verify(packet=Path(__file__).resolve().parent):
    expected_files = {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}
    if {p.name for p in packet.iterdir()} != expected_files:
        raise ValueError('unexpected or missing packet file')
    expected = parse_manifest((packet / 'MANIFEST.sha256').read_text(encoding='ascii'))
    for name, digest in expected.items():
        path = packet / name if '/' not in name else ROOT / name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
            raise ValueError('invalid manifest input')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('manifest digest mismatch: ' + name)
    with bind.TARGET.open('rb') as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            record = bind.build_records(data)
    for name, text in [('records.json', bind.json_text(record)), ('README.md', bind.readme_text(record))]:
        if (packet / name).read_bytes() != text.encode('utf-8'):
            raise ValueError('regenerated evidence mismatch: ' + name)
    print('Verified exact whitelist, node #115 digest, leaf, caller census, Locations and README.')


if __name__ == '__main__':
    try:
        verify()
    except (ValueError, OSError) as error:
        print('record-insertion verify: ' + str(error), file=sys.stderr)
        sys.exit(1)
