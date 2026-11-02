#!/usr/bin/env python3
"""Check the retained CPU-cache packet against the authenticated capture."""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys

sys.dont_write_bytecode = True
PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import cpu_cache_static as cpu


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        cpu.require(key not in out, 'duplicate JSON key: ' + key)
        out[key] = value
    return out


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def check_inventory(packet, root):
    manifest = read_json(packet / 'manifest.json')
    files = manifest['files']
    actual = set()
    for path in packet.rglob('*'):
        cpu.require(not path.is_symlink(), 'symlink in packet')
        if path.is_file() and path != packet / 'manifest.json':
            actual.add(path.relative_to(root).as_posix())
    external = {'tools/cpu_cache_static.py', 'tests/test_cpu_cache_static.py'}
    cpu.require(set(files) == actual | external, 'packet file inventory changed')
    for name, digest in files.items():
        parts = PurePosixPath(name)
        cpu.require(not parts.is_absolute() and '..' not in parts.parts and str(parts) == name,
                    'noncanonical manifest path')
        path = root / name
        cpu.require(not any(p.is_symlink() for p in [path, *path.parents] if p != root.parent),
                    'symlink in manifest path')
        cpu.require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'file digest changed: ' + name)
    return len(files)


def main():
    count = check_inventory(PACKET, ROOT)
    data = cpu.TARGET.read_bytes()
    actual = cpu.analyze(data)
    recorded = read_json(PACKET / 'evidence/records.json')
    for key, value in actual.items():
        if key != 'ranges':
            cpu.require(recorded.get(key) == value, 'record changed: ' + key)
    cpu.require(len(recorded['ranges']) == len(actual['ranges']), 'range inventory changed')
    image = cpu.Image(data)
    for fresh, retained in zip(actual['ranges'], recorded['ranges']):
        for key, value in fresh.items():
            cpu.require(retained.get(key) == value, 'range field changed: ' + key)
        start, end = int(fresh['start_va'], 16), int(fresh['end_va_exclusive'], 16)
        body = image.read(start, end - start)
        exports = [cpu.decode_export((PACKET / 'evidence' / f'{start:x}.{kind}.txt').read_text(), start, end, body)
                   for kind in ['objdump', 'llvm']]
        cpu.require(exports[0] == exports[1], 'independent decoder boundaries disagree')
        cpu.require(len(exports[0]) == retained['decoded_instructions'], 'instruction count changed')
    spec = importlib.util.spec_from_file_location('frozen_cpu_oracle', PACKET / 'preparation/build_oracle.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    rows = read_json(PACKET / 'oracle/vectors.json')
    freeze = read_json(PACKET / 'oracle/FREEZE.json')
    cpu.require(len(rows) == freeze['vectors'], 'vector count changed')
    for name, key in [('oracle/vectors.json', 'vectors_sha256'), ('preparation/build_oracle.py', 'generator_sha256')]:
        cpu.require(hashlib.sha256((PACKET / name).read_bytes()).hexdigest() == freeze[key], 'frozen oracle changed')
    for row in rows:
        expected = oracle.expected(row['quota'], row['period'], row['logical'])
        cpu.require(all(row[key] == value for key, value in expected.items()), 'oracle arithmetic mismatch')
    print(json.dumps({'files': count, 'whole_fdes': len(actual['ranges']), 'oracle_vectors': len(rows),
                      'captured_binary_executed': False, 'source_byte_identity_claimed': False}))


if __name__ == '__main__':
    main()
