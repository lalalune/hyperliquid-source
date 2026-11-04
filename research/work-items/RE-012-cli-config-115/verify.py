#!/usr/bin/env python3
"""Authenticate static node115 evidence; never execute the capture."""
import argparse
import base64
import gzip
import json
from pathlib import Path
import re
import stat
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parents[3]
PACKET = Path(__file__).absolute().parent
sys.path.insert(0, str(ROOT / 'tools'))
import node115_cli_config as c

PACKET_FILES = {
    'README.md', 'CONTRACT.md', 'verify.py', 'spec.json', 'records.json',
    'native-commands.json', 'commands.json', 'validation.json', 'scope-review.json',
    'research-handoff.json', 'tools.json', 'raw-streams.json.gz', 'sources.json',
    'upstream-source.json.gz', 'LICENSE-upstream-MIT', 'migration.json',
} | {f'{name}.{provider}.txt' for name in c.spec()['ranges'] for provider in ('gnu', 'llvm')}
DEPENDENCIES = {'tools/node115_cli_config.py', 'tests/test_node115_cli_config.py',
                'tools/elf_index.py', 'tools/fde_extents.py'}


def read_json(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=c.unique)


def regular(path, directory=False):
    path = Path(path).absolute()
    for parent in reversed(path.parents):
        c.require(stat.S_ISDIR(parent.lstat().st_mode), 'non-directory/symlink parent')
    mode = path.lstat().st_mode
    c.require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode), 'symlink/nonregular path')


def check_inventory(packet, expected):
    regular(packet, directory=True)
    actual = set()
    for path in packet.rglob('*'):
        regular(path)
        actual.add(path.relative_to(packet).as_posix())
    c.require(actual == expected | {'MANIFEST.sha256'}, 'packet inventory differs')


def manifest(root, packet, expected):
    rows = {}
    for line in (packet / 'MANIFEST.sha256').read_text().splitlines():
        m = re.fullmatch(r'([0-9a-f]{64})  ([^\r\n]+)', line)
        c.require(m is not None, 'malformed manifest row')
        digest, name = m.groups()
        c.require(name not in rows and not Path(name).is_absolute()
                  and '..' not in Path(name).parts, 'duplicate/unsafe manifest path')
        rows[name] = digest
    c.require(set(rows) == expected, 'manifest inventory differs')
    for name, digest in rows.items():
        path = root / name
        regular(path)
        c.require(c.digest(path.read_bytes()) == digest, 'manifest digest differs: ' + name)
    return len(rows)


def archive(path):
    value = json.loads(gzip.decompress(Path(path).read_bytes()), object_pairs_hook=c.unique)
    c.require(value['schema'] == 1 and type(value['streams']) is list, 'invalid archive schema')
    labels, total = set(), 0
    for row in value['streams']:
        c.require(row['label'] not in labels, 'duplicate stream label')
        labels.add(row['label'])
        raw = base64.b64decode(row['base64'], validate=True)
        c.require(type(row['bytes']) is int and len(raw) == row['bytes']
                  and c.digest(raw) == row['sha256'], 'archived bytes differ')
        total += len(raw)
    return {'streams': len(labels), 'raw_bytes': total}


def native(report, directory):
    commands = read_json(directory / 'native-commands.json')
    ranges = c.spec()['ranges']
    want = {(n, p) for n in ranges for p in ('gnu', 'llvm')}
    c.require({(r['name'], r['provider']) for r in commands} == want and len(commands) == len(want),
              'native command inventory differs')
    for row in commands:
        n, provider = row['name'], row['provider']
        raw = (directory / f'{n}.{provider}.txt').read_bytes()
        c.require(c.digest(raw) == row['stdout_sha256'] and row['exit_code'] == 0
                  and row['stderr_hex'] == '', 'native hash/exit/stderr differs')
        start, end = map(lambda v: int(v, 16), ranges[n])
        parsed = c.native_bytes(raw.decode(), start, end, llvm=(provider == 'llvm'))
        expected = [(int(i['va'], 16), bytes.fromhex(i['bytes'])) for i in report['instructions'][n]]
        c.require(parsed == expected and len(parsed) == row['instruction_rows'], 'native rows differ')
        c.require(row['display_joins'] == ([hex(a) for a in c.LLVM_LOCK_JOINS if start <= a < end]
                                         if provider == 'llvm' else []), 'display join declaration differs')
    return len(commands)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=c.TARGET)
    parser.add_argument('--native-output', type=Path)
    args = parser.parse_args()
    check_inventory(PACKET, PACKET_FILES)
    prefix = PACKET.relative_to(ROOT).as_posix() + '/'
    count = manifest(ROOT, PACKET, {prefix + n for n in PACKET_FILES} | DEPENDENCIES)
    report = c.analyze(args.binary.read_bytes())
    c.require(report == read_json(PACKET / 'records.json'), 'recorded target facts differ')
    exports = native(report, PACKET)
    raw = archive(PACKET / 'raw-streams.json.gz')
    archive(PACKET / 'upstream-source.json.gz')
    source = json.loads(gzip.decompress((PACKET / 'upstream-source.json.gz').read_bytes()), object_pairs_hook=c.unique)
    c.require({r['label']: (r['bytes'], r['sha256']) for r in source['streams']} ==
              {r['path']: (r['bytes'], r['sha256']) for r in read_json(PACKET / 'sources.json')['pinned_files']},
              'source archive inventory differs')
    if args.native_output:
        c.require(not args.native_output.resolve().is_relative_to(PACKET.resolve()), 'output inside packet')
        fresh = c.export(args.binary, args.native_output)
        c.require(fresh == report, 'fresh static records differ')
        native(fresh, args.native_output)
        for path in args.native_output.iterdir():
            c.require(path.read_bytes() == (PACKET / path.name).read_bytes(), 'repeat bytes differ: ' + path.name)
    print(json.dumps({'status': 'pass', 'manifest_entries': count, 'primary_bytes': report['primary_bytes'],
        'complete_fdes': len(report['bodies']), 'native_exports': exports, 'archive': raw,
        'captured_binary_executed': False, 'behavioral_equivalence_claimed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
