#!/usr/bin/env python3
"""Read-only receipt inspection; never execute or extract archive members.

MIT mechanics adapted from reviewed retry inspector SHA
7134e64331e05dcfceac1a94188276ade41af7ccdb9fcf346dcceebdefb93342.
The surrounding public manifest authenticates this helper/index/archive.
Indexed byte integrity is not a native semantic theorem or independent approval.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

MAX_INDEX = 4 << 20
MAX_ARCHIVE = 64 << 20
MAX_RAW = 64 << 20  # Distinct from the 45,062,982-byte input fixture.


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def load_json(raw):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def safe_path(name):
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name,
            'canonical relative member path')
    return path


def unpack(packed, cap):
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        raw = stream.read(cap + 1)
    require(len(raw) <= cap, 'gzip expansion cap')
    return raw


def inspect(index_path, archive_path):
    require(index_path.stat().st_size <= MAX_INDEX, 'index size cap')
    require(archive_path.stat().st_size <= MAX_ARCHIVE, 'archive stored size cap')
    index = load_json(index_path.read_bytes())
    packed = archive_path.read_bytes()
    require(identity(packed) == index['archive']['stored'], 'archive stored identity')
    raw = unpack(packed, MAX_ARCHIVE)
    require(identity(raw) == index['archive']['tar'], 'tar identity')
    members = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for item in archive:
            safe_path(item.name)
            require(item.type == tarfile.REGTYPE, 'regular members only')
            require(item.name not in members, 'duplicate member')
            require((item.uid, item.gid, item.uname, item.gname, item.mtime, item.mode)
                    == (0, 0, '', '', 0, 0o644), 'deterministic member metadata')
            require(item.name in index['members'], 'unindexed member')
            expected = index['members'][item.name]
            require(item.size == expected['bytes'] and item.size <= MAX_ARCHIVE, 'member size')
            handle = archive.extractfile(item)
            require(handle is not None, 'member reader')
            body = handle.read(MAX_ARCHIVE + 1)
            require(identity(body) == {k: expected[k] for k in ['bytes', 'sha256']}, 'member identity')
            members[item.name] = body
    require(set(members) == set(index['members']), 'complete member set')
    for name, expected in index['external_files'].items():
        relative = safe_path(name)
        path = index_path.parent.parent / relative
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_INDEX,
                'regular bounded external receipt')
        require(identity(path.read_bytes()) == expected, 'external receipt identity')
    raw_cache, references, command_count = {}, 0, 0
    for name, run in index['runs'].items():
        for original, reference in run['metadata'].items():
            require(identity(members[reference['member']]) == {k: reference[k] for k in ['bytes', 'sha256']},
                    'original metadata identity: ' + original)
        commands = load_json(members[run['metadata']['receipts/commands.json']['member']])
        require(len(commands) == run['command_count'], 'command count: ' + name)
        command_count += len(commands)
        used = set()
        for command in commands:
            for stream in ['stdout', 'stderr']:
                reference = command[stream]
                require(re.fullmatch(r'raw/[0-9a-f]{64}\.gz', reference['gzip_ref']) is not None,
                        'original raw ref shape')
                mapped = run['rawref_map'][reference['gzip_ref']]
                require({k: reference[k] for k in ['bytes', 'sha256']} == mapped['raw'], 'raw reference identity')
                packed_raw = members[mapped['member']]
                require(identity(packed_raw) == mapped['stored'], 'raw gzip identity')
                if mapped['member'] not in raw_cache:
                    raw_cache[mapped['member']] = identity(unpack(packed_raw, MAX_RAW))
                require(raw_cache[mapped['member']] == mapped['raw'], 'raw stream identity')
                references += 1
                used.add(reference['gzip_ref'])
        require(used == set(run['rawref_map']), 'unreferenced/missing raw mapping')
        require(len(commands) * 2 == run['raw_reference_count'], 'per-run reference count')
    require(command_count == index['counts']['commands'], 'total build commands')
    require(references == index['counts']['command_raw_references'], 'total build raw references')
    prep = index['preparation']
    projection = load_json(members[prep['commands_projection']['member']])
    require(projection['kind'] == 'explicit-path-metadata-projection-not-original-bytes', 'preparation projection label')
    require(projection['original_identity'] == prep['original_commands_private'], 'private command original identity')
    commands = projection['projected']
    require(len(commands) == prep['command_count'] == 8, 'preparation command count')
    require(all(row['state'] == 'completed' and row['exit_code'] == 0 for row in commands), 'preparation completions')
    safe, quarantined, used = 0, 0, set()
    for command in commands:
        for stream in ['stdout', 'stderr']:
            key = command['label'] + '.' + stream
            reference = prep['streams'][key]
            require(command[stream] == reference['raw'], 'preparation original stream identity')
            used.add(key)
            if reference['availability'] == 'exact-public-bytes':
                require(identity(members[reference['member']]) == reference['raw'], 'exact preparation raw bytes')
                safe += 1
            else:
                require(reference['availability'] == 'private-original-with-labelled-projection', 'quarantine label')
                projected = load_json(members[reference['projection_member']])
                require(projected['kind'] == 'explicit-path-metadata-projection-not-original-bytes' and
                        projected['original_identity'] == reference['raw'], 'quarantined projection binding')
                quarantined += 1
    require(used == set(prep['streams']), 'complete preparation stream map')
    require((safe, quarantined) == (14, 2), 'preparation safe/quarantined census')
    require(safe + quarantined == prep['raw_reference_count'] == 16, 'preparation references')
    return index, members


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path, default=Path(__file__).with_name('BUNDLE-INDEX.json'))
    parser.add_argument('--archive', type=Path, default=Path(__file__).with_name('receipts.tar.gz'))
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--show', metavar='MEMBER')
    args = parser.parse_args()
    index, members = inspect(args.index, args.archive)
    if args.show is not None:
        require(args.show in members, 'show requires an exact indexed member')
        sys.stdout.buffer.write(members[args.show])
    elif args.list:
        print('\n'.join(sorted(members)))
    else:
        print(json.dumps(dict(status='PASS indexed receipt bytes', members=len(members),
            build_commands=index['counts']['commands'], build_raw_references=index['counts']['command_raw_references'],
            preparation_commands=8, preparation_public_raw_references=14, preparation_private_raw_references=2,
            executes_contained_code=False, extracts_files=False)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, tarfile.TarError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
