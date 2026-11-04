#!/usr/bin/env python3
"""Compare a pinned independently built node #115 nonce-text client.

No build, source edit, captured target access, oracle import or regeneration.
The host-only comparator records raw outputs against the frozen corpus.
"""

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

PINNED = {
    'inputs.tsv.gz': '03e9e171a07dcbe01fa3b0fa02c10273449b3050dfa9938a0965eb9d85c45cb1',
    'expected.tsv.gz': 'c307b46026aadb67f43d7c816db32b7cb43f2fd5b86f6281293097ec40e653d7',
    'coverage.json': 'ea3dcecfcbcd6c2179c60a3a8ff5f0b9c0e36f3bf4672d4e42a8b8818d145a73',
    'resource-arithmetic.json': '3525112ef1d722b30a396f5b63505dde8d82136317aca0bdbd2a984323c5563a',
}
INPUT_SHA = '4d03410b0233bd5fd71e83f0e9dddfbb51a6b08858593d7cec87d5ad6692ec5b'
EXPECTED_SHA = 'a7689b94fc2171b591ad1f609af2f16d1585c3ba26d957b7c272c4068c8e86d3'
TRANSPORT_SHA = '86d4f38f10858070d024d5e18419e404399b638eacf63d4aaef43af90ae7c3b9'
TARGET_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CAPTURED_SHAS = {TARGET_SHA,
    '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
    '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}
COUNT = 71175
DECIMAL = re.compile(rb'(?:0|[1-9][0-9]*)\Z')
ID = re.compile(rb'[A-Za-z0-9_-]+\Z')
OTHER = {b'not-admitted', b'depth-zero', b'depth-one', b'order-invariant', b'host-capacity', b'host-allocation'}
CLIENT_ENVIRONMENT = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identify(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': sha(data)}


def load_corpus(directory):
    retained = {}
    for name, expected in PINNED.items():
        data = (directory / name).read_bytes()
        if sha(data) != expected:
            raise ValueError('frozen corpus identity mismatch: ' + name)
        retained[name] = data
    inputs = gzip.decompress(retained['inputs.tsv.gz'])
    expected = gzip.decompress(retained['expected.tsv.gz'])
    if sha(inputs) != INPUT_SHA or sha(expected) != EXPECTED_SHA:
        raise ValueError('uncompressed corpus identity mismatch')
    if not inputs.endswith(b'\n') or not expected.endswith(b'\n'):
        raise ValueError('frozen corpus framing changed')
    input_rows = inputs[:-1].split(b'\n')
    expected_rows = expected[:-1].split(b'\n')
    if len(input_rows) != COUNT or len(expected_rows) != COUNT:
        raise ValueError('frozen corpus count changed')
    ids, lengths = [], []
    for row in input_rows:
        fields = row.split(b'\t')
        if len(fields) != 4 or not ID.fullmatch(fields[0]):
            raise ValueError('invalid frozen transport')
        for field in fields[1:3]:
            if not DECIMAL.fullmatch(field) or len(field) > 3 or int(field) > 255:
                raise ValueError('invalid frozen mode/depth')
        encoded = fields[3]
        if encoded == b'-':
            length = 0
        elif not re.fullmatch(rb'(?:[0-9a-f]{2})+', encoded):
            raise ValueError('invalid frozen input hex')
        else:
            length = len(encoded) // 2
        ids.append(fields[0])
        lengths.append(length)
    if len(set(ids)) != COUNT:
        raise ValueError('duplicate frozen case ID')
    coverage = json.loads(retained['coverage.json'])
    resource = json.loads(retained['resource-arithmetic.json'])
    if coverage['total_cases'] != COUNT or len(resource['cases']) != 55:
        raise ValueError('frozen coverage/resource cardinality changed')
    corpus = {'inputs': inputs, 'expected': expected, 'expected_rows': expected_rows, 'ids': ids, 'lengths': lengths}
    original = compare(corpus, expected, b'', 0, False)
    if original['status'] != 'MATCH':
        raise ValueError('frozen expected output fails structural validation')
    return corpus


def bounded_decimal(word, maximum):
    ceiling = str(maximum).encode('ascii')
    return bool(DECIMAL.fullmatch(word)) and (len(word) < len(ceiling) or (len(word) == len(ceiling) and word <= ceiling))


def compare(corpus, actual, stderr, exit_code, timed_out):
    report = {'expected_rows': COUNT, 'actual_stdout_sha256': sha(actual), 'actual_stderr_sha256': sha(stderr),
              'exit_code': exit_code, 'timed_out': timed_out, 'structural_errors': [], 'mismatches': 0, 'first_mismatches': []}
    if timed_out:
        report['status'] = 'TIMEOUT'
        return report
    if exit_code != 0:
        report['status'] = 'PROCESS_FAILURE'
        return report
    errors = report['structural_errors']
    if stderr:
        errors.append('nonempty stderr on valid transport')
    if not actual.endswith(b'\n'):
        errors.append('output does not end with LF')
    rows = actual[:-1].split(b'\n') if actual.endswith(b'\n') else actual.split(b'\n')
    report['actual_rows'] = len(rows)
    if len(rows) != COUNT:
        errors.append('output row count differs')
    mismatch_ids = []
    for index, (row, expected) in enumerate(zip(rows, corpus['expected_rows'])):
        parts = row.split(b'\t')
        valid = len(parts) >= 2 and parts[0] == corpus['ids'][index]
        if valid and parts[1] == b'parsed':
            valid = len(parts) == 4 and bounded_decimal(parts[2], corpus['lengths'][index])
            if valid:
                words = [] if parts[3] == b'-' else parts[3].split(b',')
                valid = all(bounded_decimal(word, (1 << 64) - 1) for word in words)
        elif valid:
            valid = len(parts) == 2 and parts[1] in OTHER
        if not valid and len(errors) < 16:
            errors.append(f'malformed or misplaced output frame at row {index + 1}')
        if row != expected:
            report['mismatches'] += 1
            mismatch_ids.append(corpus['ids'][index].decode('ascii'))
            if len(report['first_mismatches']) < 16:
                report['first_mismatches'].append({'row': index + 1, 'case_id': corpus['ids'][index].decode('ascii'),
                    'expected_hex': expected.hex(), 'actual_hex': row.hex()})
    report['mismatch_case_ids'] = mismatch_ids
    report['status'] = 'INVALID_OUTPUT' if errors else ('MATCH' if actual == corpus['expected'] else 'MISMATCH')
    return report


def checked_file(path, expected):
    actual = identify(path)
    if actual['sha256'] != expected:
        raise ValueError('pinned file identity mismatch: ' + str(path))
    return actual


def load_mutation(path, client_identity):
    record = json.loads(path.read_text())
    if record['mutant_binary_sha256'] != client_identity['sha256'] or record['baseline_binary_sha256'] == client_identity['sha256']:
        raise ValueError('mutant binary must differ from baseline and match the supplied executable')
    if not record['name'] or not record['witness_ids']:
        raise ValueError('mutation name and frozen witnesses required')
    base = path.parent
    source = checked_file(base / record['baseline_source']['path'], record['baseline_source']['sha256'])
    mutant = checked_file(base / record['mutant_source']['path'], record['mutant_source']['sha256'])
    if source['sha256'] == mutant['sha256'] or not source['path'].endswith('.rs') or not mutant['path'].endswith('.rs'):
        raise ValueError('operative source change required')
    patch = checked_file(base / record['patch']['path'], record['patch']['sha256'])
    build = checked_file(base / record['build_receipt']['path'], record['build_receipt']['sha256'])
    if not patch['bytes'] or record['build_exit_code'] != 0:
        raise ValueError('nonempty source patch and successful actual build required')
    return record, {'receipt': identify(path), 'baseline_source': source, 'mutant_source': mutant, 'patch': patch, 'build_receipt': build}


def invoke(client, stimulus, directory, timeout):
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'stdin.tsv').write_bytes(stimulus)
    work = directory / 'client-cwd'
    work.mkdir()
    try:
        result = subprocess.run([str(client)], input=stimulus, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=work, env=CLIENT_ENVIRONMENT, check=False, timeout=timeout)
        stdout, stderr, code, expired = result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code, expired = error.stdout or b'', error.stderr or b'', None, True
    (directory / 'stdout.tsv').write_bytes(stdout)
    (directory / 'stderr.txt').write_bytes(stderr)
    record = {'argv': [str(client)], 'cwd': str(work), 'stdin': identify(directory / 'stdin.tsv'),
              'environment': CLIENT_ENVIRONMENT,
              'stdout': identify(directory / 'stdout.tsv'), 'stderr': identify(directory / 'stderr.txt'),
              'exit_code': code, 'timed_out': expired, 'timeout_seconds': timeout}
    (directory / 'command.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return stdout, stderr, code, expired, record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--client-sha256', required=True)
    parser.add_argument('--profile', choices=('debug', 'release'), required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mutation-receipt', type=Path)
    parser.add_argument('--transport-cases', type=Path, default=Path(__file__).with_name('transport-cases.json'))
    parser.add_argument('--timeout', type=int, default=60)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 60:
        raise ValueError('timeout must be between 1 and 60 seconds')
    corpus = load_corpus(args.corpus.resolve())
    client = args.client.resolve(strict=True)
    captured_subpaths = ('/artifacts/node/', '/artifacts/visor/')
    if any(part in str(client) for part in captured_subpaths) or client.name in {'hl-node', 'hl-visor'}:
        raise ValueError('captured-artifact paths cannot be clients')
    client_identity = checked_file(client, args.client_sha256)
    if client_identity['sha256'] in CAPTURED_SHAS:
        raise ValueError('captured identity cannot be a client')
    if platform.system() != 'Darwin':
        raise ValueError('this reviewed-stage proposal permits macOS own-client execution only')
    mutation, mutation_binding = (None, None)
    if args.mutation_receipt:
        mutation, mutation_binding = load_mutation(args.mutation_receipt.resolve(), client_identity)
        if any(case_id.encode('ascii') not in corpus['ids'] for case_id in mutation['witness_ids']):
            raise ValueError('mutation witnesses must be frozen IDs')
    transport_identity, transport_cases = None, []
    if not mutation:
        transport_identity = checked_file(args.transport_cases.resolve(), TRANSPORT_SHA)
        transport_cases = json.loads(args.transport_cases.read_text())['cases']
        if len(transport_cases) != 27:
            raise ValueError('transport control count changed')
        for case in transport_cases:
            if not re.fullmatch(r'[A-Za-z0-9_-]+', case['id']):
                raise ValueError('invalid transport control ID')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    actual, stderr, code, expired, command = invoke(client, corpus['inputs'], out / 'corpus-run', args.timeout)
    comparison = compare(corpus, actual, stderr, code, expired)
    transport = []
    if not mutation:
        for case in transport_cases:
            data = bytes.fromhex(case['input_hex'])
            stdout, error, result, timeout, receipt = invoke(client, data, out / 'transport' / case['id'], args.timeout)
            if 'expected_stdout_hex' in case:
                passed = not timeout and result == 0 and stdout == bytes.fromhex(case['expected_stdout_hex']) and not error
            else:
                passed = not timeout and result == 2 and stdout == b''
            transport.append({'case_id': case['id'], 'pass': passed, 'command': receipt})
    if mutation:
        witnesses = sorted(set(mutation['witness_ids']) & set(comparison.get('mismatch_case_ids', [])))
        passed = comparison['status'] == 'MISMATCH' and bool(witnesses)
        outcome = 'OPERATIVE_MUTANT_KILLED' if passed else 'CONTROL_FAILED_OR_INCONCLUSIVE'
    else:
        witnesses = []
        passed = comparison['status'] == 'MATCH' and all(row['pass'] for row in transport)
        outcome = 'BASELINE_MATCH' if passed else 'BASELINE_FAILED'
    report = {'at': datetime.now(timezone.utc).isoformat(), 'outcome': outcome, 'pass': passed,
              'target_sha256': TARGET_SHA, 'profile_label_from_reviewed_build': args.profile,
              'client_before': client_identity, 'client_after': identify(client), 'python': sys.version,
              'platform': platform.platform(), 'harness': identify(Path(__file__).resolve()),
              'corpus_pins': PINNED, 'command': command, 'comparison': comparison, 'transport': transport,
              'transport_cases_identity': transport_identity,
              'mutation': mutation_binding, 'mismatching_named_witnesses': witnesses,
              'source_to_binary_binding': 'Requires independent review of the actual build receipt; this comparator does not compile or infer source provenance.',
              'claims': {'captured_execution': False, 'linux_execution': False, 'allocator_failure_test': False,
                         'native_error_state_equivalence': False, 'byte_equivalence': False}}
    if report['client_after']['sha256'] != client_identity['sha256']:
        report['pass'], report['outcome'] = False, 'CLIENT_CHANGED_DURING_RUN'
    (out / 'result.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'outcome': report['outcome'], 'pass': report['pass'], 'result': str(out / 'result.json')}, sort_keys=True))
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
