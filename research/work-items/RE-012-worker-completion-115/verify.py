#!/usr/bin/env python3
"""Offline replay of static evidence; never execute target code."""
import sys
sys.dont_write_bytecode = True
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

ROOT = Path(__file__).absolute().parents[3]
PACKET_REL = 'research/work-items/RE-012-worker-completion-115'
PACKET = ROOT / PACKET_REL
sys.path.insert(0, str(ROOT / 'tools'))
import node115_worker_completion as collector

NAMES = ('registration', 'thread_spawn', 'tokio_spawn', 'notification_callback', 'thread_monitor', 'tokio_monitor_a', 'tokio_monitor_b', 'notification_send', 'receiver_monitor', 'termination_request', 'runtime_exit', 'system_exit', 'registration_launcher', 'thread_launcher', 'tokio_launcher_a', 'tokio_launcher_b', 'receiver_schedule', 'receiver_schedule_alt', 'receiver_allocate', 'receiver_poll_tail', 'receiver_harness', 'receiver_adapter', 'delay_context', 'receiver_poll_context', 'thread_caller_context', 'tokio_caller_context', 'thread_adapter_context')
PACKET_FILES = {'README.md', 'CONTRACT.md', 'verify.py', 'spec.json', 'sources.json',
                'source-archive.json.gz', 'source-comparison.json', 'claims.json',
                'countersearch.json', 'commands.json', 'validation.json',
                'validation/raw-streams.json.gz', 'overlap/snapshot.json.gz',
                'static/records.json', 'static/native-commands.json'} | {
                    f'static/{name}.{provider}.txt' for name in NAMES for provider in ('gnu', 'llvm')}
EXTERNAL = {'tools/node115_worker_completion.py', 'tests/test_node115_worker_completion.py'}


def require(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular_path(root, relative, directory=False):
    require(not relative.startswith('/') and str(PurePosixPath(relative)) == relative
            and all(p not in ('', '.', '..') for p in relative.split('/')), 'unsafe path')
    cursor = root
    require(stat.S_ISDIR(cursor.lstat().st_mode), 'root is not a real directory')
    parts = relative.split('/')
    for i, part in enumerate(parts):
        cursor /= part
        mode = cursor.lstat().st_mode
        require(not stat.S_ISLNK(mode), 'symlink component')
        require(stat.S_ISDIR(mode) if i < len(parts) - 1 or directory else stat.S_ISREG(mode),
                'nonregular path')
    return cursor


def verify_manifest(root=ROOT):
    manifest = regular_path(root, PACKET_REL + '/MANIFEST.sha256')
    rows = {}
    for line in manifest.read_text().splitlines():
        m = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(m is not None and m[2] not in rows, 'malformed or duplicate manifest row')
        rows[m[2]] = m[1]
    expected = {PACKET_REL + '/' + x for x in PACKET_FILES} | EXTERNAL
    require(set(rows) == expected, 'manifest allowlist differs')
    for path, digest in rows.items():
        require(sha(regular_path(root, path).read_bytes()) == digest, 'manifest hash differs')
    expected_files = PACKET_FILES | {'MANIFEST.sha256'}
    expected_dirs = {str(p) for path in PACKET_FILES for p in PurePosixPath(path).parents if str(p) != '.'}
    actual_files, actual_dirs = set(), set()
    packet = regular_path(root, PACKET_REL, directory=True)
    def walk(path):
        with os.scandir(path) as entries:
            names = list(entries)
        for entry in names:
            p = Path(entry.path)
            relative = p.relative_to(packet).as_posix()
            mode = entry.stat(follow_symlinks=False).st_mode
            require(not stat.S_ISLNK(mode), 'inventory symlink')
            if stat.S_ISDIR(mode):
                actual_dirs.add(relative)
                walk(p)
            else:
                require(stat.S_ISREG(mode), 'inventory special file')
                actual_files.add(relative)
    walk(packet)
    require(actual_files == expected_files and actual_dirs == expected_dirs, 'recursive inventory differs')
    return len(rows)


def archive(path):
    value = json.loads(gzip.decompress(path.read_bytes()), object_pairs_hook=collector.unique)
    labels = set()
    for row in value['files']:
        require(row['path'] not in labels, 'duplicate archive entry')
        labels.add(row['path'])
        raw = base64.b64decode(row['base64'], validate=True)
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'archive payload mismatch')
    return value


def main():
    count = verify_manifest()
    expected = json.loads((PACKET / 'static/records.json').read_text(), object_pairs_hook=collector.unique)
    actual = collector.analyze(collector.TARGET.read_bytes())
    require(actual == expected, 'static observation differs')
    for name, (start, end) in collector.spec()['ranges'].items():
        rows = [(int(r['va'], 16), bytes.fromhex(r['bytes'])) for r in actual['instructions'][name]]
        for provider in ('gnu', 'llvm'):
            raw = (PACKET / f'static/{name}.{provider}.txt').read_text()
            require(collector.native_bytes(raw, int(start, 16), int(end, 16), provider == 'llvm') == rows,
                    'native exported bytes/boundaries differ')
    streams = archive(PACKET / 'validation/raw-streams.json.gz')
    source = archive(PACKET / 'source-archive.json.gz')
    source_map = {r['path']: base64.b64decode(r['base64'], validate=True) for r in source['files']}
    registry = json.loads((PACKET / 'sources.json').read_text())['sources']
    require(set(source_map) == {r['id'] for r in registry} | {'tag-1.43.0.json', 'tag-1.44.0.json'}, 'source inventory differs')
    for row in registry:
        require(len(source_map[row['id']]) == row['bytes'] and sha(source_map[row['id']]) == row['sha256'],
                'source registry hash differs')
    comparisons = json.loads((PACKET / 'source-comparison.json').read_text())['comparisons']
    for row in comparisons:
        pair = []
        for side in ('left', 'right'):
            info = row[side]
            lines = source_map[info['source']].splitlines(keepends=True)
            raw = b''.join(lines[info['start_line'] - 1:info['end_line']])
            require(len(raw) == info['bytes'] and sha(raw) == info['sha256'], 'source slice differs')
            pair.append(raw)
        require((pair[0] == pair[1]) == row['raw_source_bytes_equal'], 'version countercheck differs')
    overlap = archive(PACKET / 'overlap/snapshot.json.gz')
    print(json.dumps({'manifest_entries': count, 'bodies': len(actual['bodies']),
        'primary_bytes': actual['primary_bytes'], 'total_bytes': sum(r['bytes'] for r in actual['bodies']),
        'instructions': sum(r['instructions'] for r in actual['bodies']), 'native_exports': len(NAMES) * 2,
        'retained_streams': len(streams['files']), 'upstream_files': len(source['files']),
        'overlap_inputs': len(overlap['files']), 'captured_execution': False}, sort_keys=True))


if __name__ == '__main__':
    main()
