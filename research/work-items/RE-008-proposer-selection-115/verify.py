#!/usr/bin/env python3
"""Offline static/fixture/retained-output replay. Never execute captured code."""
import base64
import gzip
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import proposer_selection115 as p


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def archive_rows(rows):
    table = {}
    for item in rows:
        raw = base64.b64decode(item['base64'], validate=True)
        if len(raw) != item['bytes'] or p.digest(raw) != item['sha256']:
            raise ValueError('raw archive corruption')
        if item['name'] in table:
            raise ValueError('duplicate raw stream name')
        table[item['name']] = raw
    return table


def archive(path):
    return archive_rows(json.loads(gzip.decompress(path.read_bytes())))


def verify_manifest(root, packet):
    """Closed task inventory; paths must stay ordinary throughout this check."""
    root, packet = Path(root), Path(packet)
    if not root.is_absolute() or not packet.is_relative_to(root):
        raise ValueError('manifest root/packet coordinate mismatch')
    external = {'tools/proposer_selection115.py', 'tests/test_proposer_selection115.py'}
    prefix = packet.relative_to(root).as_posix() + '/'

    def ordinary(path, directory=False):
        current = path
        while current != root:
            if not current.is_relative_to(root):
                raise ValueError('manifest path outside root')
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise ValueError('manifest symlink: ' + str(current))
            want_dir = current != path or directory
            if not (stat.S_ISDIR(mode) if want_dir else stat.S_ISREG(mode)):
                raise ValueError('manifest nonordinary path: ' + str(current))
            current = current.parent
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError('manifest root is not an ordinary directory')

    ordinary(packet, directory=True)
    manifest = packet / 'MANIFEST.sha256'
    ordinary(manifest)
    records = {}
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('malformed manifest row')
        wanted, name = match.groups()
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or relative.as_posix() != name:
            raise ValueError('noncanonical manifest path')
        if name in records:
            raise ValueError('duplicate manifest path')
        if name not in external and not name.startswith(prefix):
            raise ValueError('manifest path outside task inventory')
        if root / name == manifest:
            raise ValueError('manifest cannot hash itself')
        ordinary(root / name)
        if p.digest((root / name).read_bytes()) != wanted:
            raise ValueError('manifest mismatch: ' + name)
        records[name] = wanted
    if not external <= records.keys():
        raise ValueError('manifest omits task tool/test')
    expected_files = {root / name for name in records if name.startswith(prefix)} | {manifest}
    expected_dirs = {packet}
    for path in expected_files:
        parent = path.parent
        while parent != packet:
            expected_dirs.add(parent)
            parent = parent.parent
    actual_files, actual_dirs = set(), {packet}

    def walk_error(error):
        raise error

    for directory, dirs, files in os.walk(packet, followlinks=False, onerror=walk_error):
        for name in dirs:
            path = Path(directory) / name
            ordinary(path, directory=True)
            actual_dirs.add(path)
        for name in files:
            path = Path(directory) / name
            ordinary(path)
            actual_files.add(path)
    if actual_files != expected_files or actual_dirs != expected_dirs:
        raise ValueError('manifest inventory differs: unlisted file or directory')
    return len(records)


def main():
    count = verify_manifest(ROOT, HERE)
    expected_binding = json.loads(gzip.decompress((HERE / 'bindings.json.gz').read_bytes()))
    result = p.verify(p.TARGET.read_bytes(), expected_binding)
    freeze = json.loads((HERE / 'freeze.json').read_text())
    if p.digest((HERE / 'oracle.py').read_bytes()) != freeze['oracle_sha256']:
        raise ValueError('oracle drift')
    fixtures = {}
    for kind in ('inputs', 'expected'):
        compressed = (HERE / (kind + '.txt.gz')).read_bytes()
        raw = gzip.decompress(compressed)
        if p.digest(raw) != freeze['files'][kind]['raw_sha256'] or p.digest(compressed) != freeze['files'][kind]['gzip_sha256']:
            raise ValueError('fixture drift')
        if len(raw.splitlines()) != 9243:
            raise ValueError('fixture count differs')
        fixtures[kind] = raw
    oracle = module('proposer_oracle_replay', HERE / 'oracle.py')
    derived = [oracle.evaluate(line) for line in fixtures['inputs'].decode().splitlines()]
    if derived != fixtures['expected'].decode().splitlines():
        raise ValueError('independent mathematical re-derivation differs')
    validator = module('proposer_validator_replay', HERE / 'validate_native.py')
    streams_total = 0
    final_table = None
    for run in ('native-initial', 'native-final'):
        directory = HERE / 'validation' / run
        table = archive(directory / 'raw-streams.json.gz')
        records = json.loads((directory / 'commands.json').read_text())
        for command in records:
            for channel in ('stdout', 'stderr'):
                raw = table[command['label'] + '.' + channel]
                if command[channel] != {'sha256': p.digest(raw), 'bytes': len(raw)}:
                    raise ValueError('command stream metadata differs')
        if len(table) != 2 * len(records):
            raise ValueError('unaccounted raw streams')
        for opt in (0, 3):
            for repeat in (1, 2):
                label = f'opt{opt}-repeat{repeat}'
                if table[label + '-run.stdout'] != fixtures['expected']:
                    raise ValueError('retained positive comparison differs')
                for suffix in ('-compile', '-object', '-run'):
                    if next(c for c in records if c['label'] == label + suffix)['exit_code'] != 0:
                        raise ValueError('positive command failed')
        streams_total += len(table)
        if run == 'native-final':
            final_table, final_commands = table, records
    initial = json.loads((HERE / 'validation/native-initial/failure.json').read_text())
    if initial['error'] != 'mutation anchor diagnostic-wrapped-limit: 0 < 1':
        raise ValueError('initial failure record differs')
    final = json.loads((HERE / 'validation/native-final/result.json').read_text())
    source = (HERE / 'rust/lib.rs').read_text()
    for report in (initial, final):
        if report['source_sha256'] != p.digest(source.encode()) or report['driver_sha256'] != p.digest((HERE / 'rust/driver.rs').read_bytes()):
            raise ValueError('qualified source/client drift')
    if final['status'] != 'PASS' or len(final['mutants']) != len(validator.MUTANTS) or len(validator.MUTANTS) != 47:
        raise ValueError('native controls incomplete')
    selected_indices = [i for i, line in enumerate(fixtures['inputs'].splitlines()) if line[:1] in b'PHEQGR']
    lines = fixtures['expected'].splitlines(keepends=True)
    stage_expected = b''.join(lines[i] for i in selected_indices)
    for control, (name, old, new, occurrences) in zip(final['mutants'], validator.MUTANTS):
        if control['name'] != name or control['source_sha256'] != p.digest(source.replace(old, new, occurrences).encode()):
            raise ValueError('mutation source metadata differs')
        label = 'mutant-' + name
        if next(c for c in final_commands if c['label'] == label + '-compile')['exit_code'] != 0:
            raise ValueError('mutant did not compile')
        phase = control['phase']
        raw = final_table[label + '-' + phase + '-run.stdout']
        comparison = validator.compare(raw, stage_expected if phase == 'stage' else fixtures['expected'])
        if any(comparison[k] != control[k] for k in comparison):
            raise ValueError('mutation comparison differs')
        # Every final control actually returns normally and differs in values.
        if control['exit_code'] != 0 or comparison['exact'] or not control['effective']:
            raise ValueError('mutant lacks observable normal-return mismatch')
    for opt in (0, 3):
        objects = [x['object_sha256'] for x in final['correct_builds'] if x['label'].startswith(f'opt{opt}-')]
        if len(objects) != 2 or objects[0] != objects[1]:
            raise ValueError('repeated object hashes differ')
    if len(final['comparator_controls']) != 4 or any(c['exact'] for c in final['comparator_controls']):
        raise ValueError('comparator controls incomplete')
    upstream = archive(HERE / 'primary-source-files.json.gz')
    if len(upstream) != 5 or upstream['LICENSE-MIT'] != (HERE / 'upstream-LICENSE-MIT').read_bytes() or upstream['LICENSE-APACHE'] != (HERE / 'upstream-LICENSE-APACHE').read_bytes():
        raise ValueError('upstream notices differ')
    admission = archive(HERE / 'validation/admission/raw-streams.json.gz')
    if b'6 passed; 0 failed' not in admission['run.stdout']:
        raise ValueError('admission results incomplete')
    result.update(status='PASS', manifest_files=count, retained_native_streams=streams_total,
                  frozen_cases=9243, final_native_correct_observations=36972,
                  compiled_effective_mutants=47, safe_admission_tests=6,
                  comparator_controls=4, upstream_files=len(upstream))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
