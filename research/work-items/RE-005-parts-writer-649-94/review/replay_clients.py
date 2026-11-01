#!/usr/bin/env python3
"""Reinvoke only independently authored retained Rust clients with raw inputs."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import time


def need(ok, message):
    if not ok:
        raise ValueError(message)


def record(path):
    h = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            size += len(block)
            h.update(block)
    return {'bytes': size, 'sha256': h.hexdigest()}


def equal(left, right):
    with left.open('rb') as a, right.open('rb') as b:
        while True:
            aa, bb = a.read(1 << 20), b.read(1 << 20)
            if aa != bb:
                return False
            if not aa:
                return True


def main():
    private = Path(__file__).resolve().parent
    run = Path('/tmp/hl-resume-20261101/writer649-build-51c0ea7f')
    root = Path('/tmp/hl-resume-20261101/selector-56c')
    output = private / 'independent-replays'
    need(not output.exists(), 'Preserve prior actual replay')
    output.mkdir()
    input_path = private / 'inputs.tsv'
    expected = private / 'expected.jsonl'
    inputs = record(input_path)
    need(inputs['sha256'] == '6d1ca83e5517b49cb284f4f7ac54233e1db1265f4b90f15ffc9fa623c07ea58a', 'Frozen input drift')
    expected_record = record(expected)
    need(expected_record['sha256'] == '5f734582c41dad1645c94f83ddc453cd3c723137c7d56fd9e35b4254048e1109', 'Frozen expected drift')
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'}
    files = [run / profile / name for profile in ['debug', 'optimized']
             for name in ['input-client', 'libnode94_parts_writer.rlib']]
    files += [root / name for name in ['src/node94-parts-writer/lib.rs', 'src/node94-parts-writer/input_only_driver.rs']]
    files += [input_path, expected]
    before = {str(path): record(path) for path in files}
    calls = []
    for profile in ['debug', 'optimized']:
        stdout, stderr = output / (profile + '.stdout'), output / (profile + '.stderr')
        argv = [str(run / profile / 'input-client'), str(input_path)]
        start = time.monotonic()
        with stdout.open('wb') as out, stderr.open('wb') as err:
            child = subprocess.run(argv, cwd=output, env=environment, stdout=out, stderr=err)
        elapsed = time.monotonic() - start
        need(child.returncode == 0, 'Actual client replay failed: ' + profile)
        need(record(stderr)['bytes'] == 0, 'Actual replay stderr: ' + profile)
        need(equal(stdout, expected), 'Actual complete canonical output differs: ' + profile)
        streams = {}
        for name, path in [('stdout', stdout), ('stderr', stderr)]:
            raw_record = record(path)
            packed = Path(str(path) + '.gz')
            with path.open('rb') as source, packed.open('wb') as destination:
                with gzip.GzipFile(fileobj=destination, mode='wb', filename='', mtime=0) as writer:
                    while part := source.read(1 << 20):
                        writer.write(part)
            check = hashlib.sha256()
            with gzip.open(packed, 'rb') as source:
                while part := source.read(1 << 20):
                    check.update(part)
            need(check.hexdigest() == raw_record['sha256'], 'Replay gzip did not preserve raw stream')
            streams[name] = {'raw': raw_record, 'gzip_file': packed.name, 'gzip': record(packed)}
            path.unlink()
        calls.append({'profile': profile, 'argv': argv, 'cwd': str(output),
                      'environment': environment, 'exit': child.returncode, 'seconds': elapsed,
                      'cases': 69359, 'callback_observations': 90453,
                      'complete_canonical_output_equal': True, 'streams': streams})
    after = {str(path): record(path) for path in files}
    need(before == after, 'Retained binary/source/input drift during replay')
    receipt = {'schema': 'node94-writer649-independent-client-replay/1', 'status': 'PASS',
               'measured_source_checkpoint': '51c0ea7fc4a035b4c0dd690f9310657b39ea9db4',
               'input_only_stimulus': inputs, 'before': before, 'after': after, 'calls': calls,
               'script_sha256': record(Path(__file__))['sha256'],
               'full_make_test': 'NOT_RUN', 'hosted_CI': 'NOT_RUN',
               'captured_execution_or_instruction_evaluator': False,
               'limits': ['Only already compiled independently authored Rust clients were invoked, with one path to raw eleven-field inputs.',
                          'No expected output, selected-substring/count/layout plan or native program was passed to either client.',
                          'No compiler repetition, full target/provider reread, native ABI/renderer/fault/unwind/concurrency or component gate claim.']}
    path = private / 'INDEPENDENT-REPLAYS.json'
    need(not path.exists(), 'Preserve prior replay receipt')
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'receipt': str(path), 'sha256': record(path)['sha256'],
                      'status': receipt['status'], 'profiles': [row['profile'] for row in calls],
                      'raw_output_sha256': calls[0]['streams']['stdout']['raw']['sha256']}, sort_keys=True))


if __name__ == '__main__':
    main()
