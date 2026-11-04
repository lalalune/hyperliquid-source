#!/usr/bin/env python3
"""Authenticate this static packet. Never execute captured node instructions."""
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
import runtime_entry_115_static as c

PACKET_FILES = {
    'README.md', 'CONTRACT.md', 'verify.py', 'records.json',
    'peer-review.py', 'peer-review.json', 'peer-streams.json.gz', 'research-check.json',
    'native-commands.json', 'commands.json', 'validation.json',
    'scope-review.json', 'research-handoff.json', 'tools.json', 'raw-streams.json.gz',
    'sources.json', 'upstream-source.json.gz', 'upstream-LICENSE-MIT', 'upstream-LICENSE-APACHE',
} | {f'{name}.{provider}.txt' for name in c.RANGES for provider in ('gnu', 'llvm')}
DEPENDENCIES = {'tools/runtime_entry_115_static.py', 'tests/test_runtime_entry_115_static.py',
                'tools/elf_index.py', 'tools/fde_extents.py'}


def read_json(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=c.unique)


def verify_packet_inventory(packet, expected):
    c.require(not packet.is_symlink() and packet.is_dir(), 'invalid packet directory')
    actual = set()
    for path in packet.rglob('*'):
        c.require(not path.is_symlink(), 'packet symlink')
        c.require(path.is_file(), 'unexpected packet directory or non-file')
        actual.add(path.relative_to(packet).as_posix())
    c.require(actual == expected | {'manifest.json'}, 'packet file inventory differs')


def verify_manifest(root, rows, expected):
    c.require(type(rows) is dict and set(rows) == expected, 'manifest inventory differs')
    for name, item in rows.items():
        path = root / name
        c.require(not Path(name).is_absolute() and '..' not in Path(name).parts,
                  'unsafe manifest path')
        component = root
        c.require(not root.is_symlink(), 'manifest root symlink')
        for part in Path(name).parts:
            component = component / part
            c.require(not component.is_symlink(), 'manifest parent/file symlink')
        c.require(not path.is_symlink() and path.is_file(), 'missing manifest file')
        c.require(type(item) is dict and set(item) == {'bytes', 'sha256'}, 'invalid manifest row')
        raw = path.read_bytes()
        c.require(type(item['bytes']) is int and item['bytes'] == len(raw)
                  and item['sha256'] == c.digest(raw), 'manifest hash differs: ' + name)


def verify_archive(path):
    archive = json.loads(gzip.decompress(Path(path).read_bytes()), object_pairs_hook=c.unique)
    c.require(archive['schema'] == 1 and type(archive['streams']) is list, 'invalid archive')
    labels = set()
    total = 0
    for row in archive['streams']:
        c.require(row['label'] not in labels, 'duplicate archived stream')
        labels.add(row['label'])
        raw = base64.b64decode(row['base64'], validate=True)
        c.require(type(row['bytes']) is int and len(raw) == row['bytes']
                  and c.digest(raw) == row['sha256'], 'archived stream differs')
        total += len(raw)
    return {'streams': len(labels), 'raw_bytes': total}


def verify_native(report, directory):
    commands = read_json(directory / 'native-commands.json')
    expected = {(name, provider) for name in c.RANGES for provider in ('gnu', 'llvm')}
    c.require({(r['name'], r['provider']) for r in commands} == expected
              and len(commands) == len(expected), 'native command inventory differs')
    for row in commands:
        name, provider = row['name'], row['provider']
        raw = (directory / f'{name}.{provider}.txt').read_bytes()
        c.require(c.digest(raw) == row['stdout_sha256'] and row['exit_code'] == 0,
                  'native output hash/exit differs')
        c.require(row['stderr_hex'] == '', 'unexpected retained disassembler stderr')
        rows = c.native_bytes(raw.decode(), *c.RANGES[name])
        want = [(int(i['va'], 16), bytes.fromhex(i['bytes'])) for i in report['instructions'][name]]
        c.require(rows == want and len(rows) == row['instruction_rows'], 'native instructions differ')
    return len(commands)


def read_json_gzip(path):
    return json.loads(gzip.decompress(Path(path).read_bytes()), object_pairs_hook=c.unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=c.TARGET)
    parser.add_argument('--native-output', type=Path)
    args = parser.parse_args()
    prefix = str(PACKET.relative_to(ROOT)) + '/'
    verify_packet_inventory(PACKET, PACKET_FILES)
    expected = {prefix + name for name in PACKET_FILES} | DEPENDENCIES
    verify_manifest(ROOT, read_json(PACKET / 'manifest.json'), expected)
    report = c.analyze(args.binary.read_bytes())
    c.require(report == read_json(PACKET / 'records.json'), 'recorded target facts differ')
    exports = verify_native(report, PACKET)
    archive = verify_archive(PACKET / 'raw-streams.json.gz')
    upstream = verify_archive(PACKET / 'upstream-source.json.gz')
    peer_archive = verify_archive(PACKET / 'peer-streams.json.gz')
    peer = read_json(PACKET / 'peer-review.json')
    c.require(peer['target_sha256'] == c.SHA256 and peer['bytes'] == 1857, 'peer target/extent mismatch')
    c.require(peer['review_script_sha256'] == c.digest((PACKET / 'peer-review.py').read_bytes()), 'peer script changed')
    for name, digest in peer['reviewed_files'].items():
        c.require(c.digest((ROOT / name).read_bytes()) == digest, 'peer-reviewed file changed')
    archived_peer = {r['label']: r for r in read_json_gzip(PACKET / 'peer-streams.json.gz')['streams']}
    c.require(set(archived_peer) == {name + '.gnu.stdout' for name in c.RANGES}, 'peer native inventory')
    for body in peer['bodies']:
        row = archived_peer[body['name'] + '.gnu.stdout']
        c.require(row['sha256'] == body['fresh_gnu_sha256'], 'peer native hash mismatch')
        actual = c.native_bytes(base64.b64decode(row['base64'], validate=True).decode(), *c.RANGES[body['name']])
        expected = [(int(i['va'], 16), bytes.fromhex(i['bytes'])) for i in report['instructions'][body['name']]]
        c.require(actual == expected, 'peer byte/boundary mismatch')
    source_rows = read_json(PACKET / 'sources.json')['pinned_files']
    archived = read_json_gzip(PACKET / 'upstream-source.json.gz')['streams']
    c.require({r['label']: (r['bytes'], r['sha256']) for r in archived} ==
              {r['path']: (r['bytes'], r['sha256']) for r in source_rows}, 'upstream source inventory differs')
    if args.native_output:
        c.require(not args.native_output.resolve().is_relative_to(PACKET), 'native output inside packet')
        fresh = c.export(args.binary, args.native_output)
        c.require(fresh == report, 'fresh export facts differ')
        verify_native(fresh, args.native_output)
        for path in args.native_output.iterdir():
            if path.suffix == '.stderr':
                c.require(path.read_bytes() == b'', 'unexpected fresh stderr')
                continue
            c.require(path.read_bytes() == (PACKET / path.name).read_bytes(),
                      'fresh native output differs: ' + path.name)
    print(json.dumps({'status': 'pass', 'primary_bytes': report['primary_bytes'],
        'complete_fdes': len(report['bodies']), 'callback_method_slots': 3,
        'native_exports': exports, 'archive': archive, 'peer_archive': peer_archive,
        'captured_binary_executed': False, 'behavioral_equivalence_claimed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
