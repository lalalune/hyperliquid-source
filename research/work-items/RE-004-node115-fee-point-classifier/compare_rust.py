#!/usr/bin/env python3
"""Compare an explicitly admitted source-built driver with a frozen scalar corpus.

The executable must come from the reviewed dependency-free Rust build. Only
input TSV reaches its stdin; expected outputs stay in this comparison process.
Never supply a captured binary. No oracle or decoder is imported here.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


CLASSES = {
    'FirstProductNegative', 'NetAndBaseNegative', 'SecondProductNegative',
    'RoundedMagnitudeAtLeastQuantity', 'Pass',
}
IDENTIFIER = re.compile(r'[A-Za-z0-9_-]+\Z')
CAPTURE_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def outcome_rows(raw):
    require(raw.endswith(b'\n') and b'\r' not in raw, 'LF-terminated outcomes required')
    rows = []
    seen = set()
    for line in raw.decode('ascii').split('\n')[:-1]:
        fields = line.split('\t')
        require(len(fields) == 2, 'exactly two outcome fields required')
        case_id, category = fields
        require(IDENTIFIER.fullmatch(case_id) and case_id not in seen, 'unique valid outcome ID required')
        require(category in CLASSES, 'unknown outcome category')
        seen.add(case_id)
        rows.append((case_id, category))
    require(bool(rows), 'nonempty outcomes required')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'fresh output directory required')
    executable = args.executable.resolve(strict=True)
    binary_raw = executable.read_bytes()
    require(sha(binary_raw) == args.sha256 and args.sha256 != CAPTURE_SHA,
            'source-built executable identity mismatch or captured input')
    manifest_raw = (args.corpus / 'MANIFEST.sha256').read_bytes()
    require(sha(manifest_raw) == args.manifest_sha256, 'frozen corpus manifest identity')
    manifest = {}
    for line in manifest_raw.decode('ascii').splitlines():
        digest, name = line.split('  ', 1)
        require('/' not in name and '\\' not in name and name not in ('', '.', '..'), 'simple manifest filename')
        require(name not in manifest, 'duplicate manifest filename')
        raw = (args.corpus / name).read_bytes()
        require(sha(raw) == digest, 'frozen corpus entry identity: ' + name)
        manifest[name] = digest
    inputs = gzip.decompress((args.corpus / 'inputs.tsv.gz').read_bytes())
    expected_raw = gzip.decompress((args.corpus / 'expected.tsv.gz').read_bytes())
    expected = outcome_rows(expected_raw)
    require(inputs.endswith(b'\n') and b'\r' not in inputs, 'LF-terminated input required')
    input_rows = [line.split('\t') for line in inputs.decode('ascii').split('\n')[:-1]]
    require(all(len(row) == 8 for row in input_rows), 'input-only eight-field frames required')
    require([row[0] for row in input_rows] == [row[0] for row in expected], 'input/expected ID order differs')
    args.output.mkdir()
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
    started = time.monotonic()
    code, failure = None, None
    stdout, stderr = b'', b''
    try:
        child = subprocess.run([str(executable)], input=inputs, cwd=args.output,
                               env=environment, capture_output=True, timeout=30)
        code, stdout, stderr = child.returncode, child.stdout, child.stderr
    except subprocess.TimeoutExpired as error:
        stdout, stderr, failure = error.stdout or b'', error.stderr or b'', 'timeout'
    except OSError as error:
        failure = type(error).__name__
        (args.output / 'launch-error.txt').write_text(str(error) + '\n')
    (args.output / 'actual.stdout').write_bytes(stdout)
    (args.output / 'actual.stderr').write_bytes(stderr)
    mismatches, format_error = [], None
    if code == 0 and failure is None:
        try:
            actual = outcome_rows(stdout)
            require([row[0] for row in actual] == [row[0] for row in expected], 'actual row IDs/count/order differ')
            mismatches = [{'id': e[0], 'expected': e[1], 'actual': a[1]}
                          for e, a in zip(expected, actual) if e != a]
        except (ValueError, UnicodeError) as error:
            format_error = str(error)
    executable_unchanged = sha(executable.read_bytes()) == args.sha256
    passed = code == 0 and failure is None and not stderr and format_error is None and not mismatches and executable_unchanged
    result = {
        'scope': 'Source-built Rust classification against pre-source mathematical expectations, no captured execution',
        'argv': [str(executable)], 'cwd': str(args.output), 'env': environment,
        'executable_sha256': args.sha256, 'executable_unchanged': executable_unchanged,
        'corpus_manifest_sha256': args.manifest_sha256,
        'input_sha256': sha(inputs), 'expected_sha256': sha(expected_raw),
        'expected_sent_to_child': False, 'case_count': len(expected),
        'exit_code': code, 'launch_failure': failure, 'format_error': format_error,
        'duration_seconds': time.monotonic() - started,
        'stdout': {'bytes': len(stdout), 'sha256': sha(stdout)},
        'stderr': {'bytes': len(stderr), 'sha256': sha(stderr)},
        'mismatch_count': len(mismatches), 'mismatches': mismatches,
        'passed': passed,
    }
    (args.output / 'comparison.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: result[k] for k in ('passed', 'case_count', 'exit_code', 'mismatch_count', 'format_error', 'launch_failure')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
