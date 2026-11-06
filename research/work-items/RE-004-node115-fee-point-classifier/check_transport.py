#!/usr/bin/env python3
"""Exercise the source-built driver's chosen transport policy, never native ABI.

The caller must admit the source build and supply its exact executable digest.
Expected values stay in this process; the child receives scalar-only stdin.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'fresh output directory required')
    binary = args.executable.resolve(strict=True)
    require(sha(binary.read_bytes()) == args.sha256, 'source-built executable identity')
    require(args.sha256 != 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301', 'never execute captured input')
    manifest = (args.corpus / 'MANIFEST.sha256').read_bytes()
    require(sha(manifest) == 'c54df191f0f8b83e6816d6cc31b78e0a61c601c333f096fe7eb34bc8a4bd586b', 'frozen corpus identity')
    for line in manifest.decode('ascii').split('\n')[:-1]:
        digest, filename = line.split('  ', 1)
        require('/' not in filename and '\\' not in filename, 'flat corpus filenames')
        require(sha((args.corpus / filename).read_bytes()) == digest, 'corpus file identity')
    inputs = gzip.decompress((args.corpus / 'inputs.tsv.gz').read_bytes())
    expected = gzip.decompress((args.corpus / 'expected.tsv.gz').read_bytes())
    input_lines = inputs.split(b'\n')[:-1]
    expected_lines = expected.split(b'\n')[:-1]
    require(len(input_lines) == len(expected_lines) == 5900, 'frozen case count')
    renamed_inputs, renamed_expected = [], []
    for index, (inp, exp) in enumerate(zip(input_lines, expected_lines)):
        old_id, fields = inp.split(b'\t', 1)
        exp_id, category = exp.split(b'\t')
        require(old_id == exp_id, 'paired frozen IDs')
        new_id = ('opaque_' + str(index)).encode('ascii')
        renamed_inputs.append(new_id + b'\t' + fields + b'\n')
        renamed_expected.append(new_id + b'\t' + category + b'\n')

    zero = b'zero\t1\t3ff0000000000000\t0000000000000000\t0000000000000000\t0000000000000000\t0000000000000000\t0000000000000000\n'
    def replace_field(index, value):
        parts = zero[:-1].split(b'\t')
        parts[index] = value
        return b'\t'.join(parts) + b'\n'

    maximum_rows = b''.join(('r' + str(i)).encode('ascii') + zero[4:] for i in range(8192))
    maximum_expected = b''.join(('r' + str(i) + '\tPass\n').encode('ascii') for i in range(8192))
    cases = [
        ('renamed-all-5900', b''.join(renamed_inputs), [], b''.join(renamed_expected)),
        ('maximum-records', maximum_rows, [], maximum_expected),
        ('empty', b'', [], None),
        ('missing-final-LF', zero[:-1], [], None),
        ('CRLF', zero[:-1] + b'\r\n', [], None),
        ('extra-expected-field', zero[:-1] + b'\tPass\n', [], None),
        ('missing-field', b'\t'.join(zero[:-1].split(b'\t')[:-1]) + b'\n', [], None),
        ('zero-quantity', replace_field(1, b'0'), [], None),
        ('large-quantity', replace_field(1, b'10000001'), [], None),
        ('leading-zero', replace_field(1, b'01'), [], None),
        ('signed-quantity', replace_field(1, b'+1'), [], None),
        ('negative-quantity', replace_field(1, b'-1'), [], None),
        ('decimal-overflow', replace_field(1, b'18446744073709551616'), [], None),
        ('unsupported-scale', replace_field(2, b'0000000000000000'), [], None),
        ('uppercase-bits', replace_field(2, b'3FF0000000000000'), [], None),
        ('short-bits', replace_field(3, b'0'), [], None),
        ('prefixed-bits', replace_field(3, b'0x0000000000000000'), [], None),
        ('empty-ID', replace_field(0, b''), [], None),
        ('invalid-ID', replace_field(0, b'bad id'), [], None),
        ('non-ASCII', replace_field(0, b'\xff'), [], None),
        ('duplicate-ID', zero + zero, [], None),
        ('interior-blank-row', zero + b'\n', [], None),
        ('later-malformed-no-partial-output', zero + b'bad\n', [], None),
        ('extra-argument', zero, ['unexpected'], None),
        ('excess-records', maximum_rows + b'overflow' + zero[4:], [], None),
        ('excess-bytes', b'x' * (2 * 1024 * 1024 + 1), [], None),
    ]
    args.output.mkdir()
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
    results = []
    for name, payload, extra, wanted in cases:
        run = subprocess.run([str(binary), *extra], input=payload, cwd=args.output,
                             env=environment, capture_output=True, timeout=10)
        (args.output / (name + '.stdout')).write_bytes(run.stdout)
        (args.output / (name + '.stderr')).write_bytes(run.stderr)
        passed = (run.returncode == 0 and not run.stderr and run.stdout == wanted
                  if wanted is not None else run.returncode == 2 and not run.stdout and bool(run.stderr))
        results.append({'name': name, 'argv': [str(binary), *extra], 'input_bytes': len(payload),
                        'input_sha256': sha(payload), 'expected_kind': 'exact-output' if wanted is not None else 'host-refusal-empty-stdout',
                        'expected_sha256': sha(wanted) if wanted is not None else None,
                        'exit_code': run.returncode, 'stdout_sha256': sha(run.stdout),
                        'stderr_sha256': sha(run.stderr), 'passed': passed})
        (args.output / 'results.json').write_text(json.dumps(results, indent=2, sort_keys=True) + '\n')
        require(passed, 'transport control failed: ' + name)
    require(sha(binary.read_bytes()) == args.sha256, 'executable changed')
    print(json.dumps({'passed': True, 'controls': len(results), 'renamed_classifications': 5900,
                      'scope': 'chosen host protocol only; no native parser or captured execution'}))


if __name__ == '__main__':
    main()
