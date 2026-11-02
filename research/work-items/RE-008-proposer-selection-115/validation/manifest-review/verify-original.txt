#!/usr/bin/env python3
"""Offline static/fixture/retained-output replay. Never execute captured code."""
import base64
import gzip
import importlib.util
import json
from pathlib import Path
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


def main():
    count = 0
    for line in (HERE / 'MANIFEST.sha256').read_text().splitlines():
        wanted, name = line.split('  ', 1)
        path = ROOT / name
        if not path.is_file() or p.digest(path.read_bytes()) != wanted:
            raise ValueError('manifest mismatch: ' + name)
        count += 1
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
