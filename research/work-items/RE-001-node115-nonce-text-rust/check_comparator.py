#!/usr/bin/env python3
"""Pure-data comparator controls; no child process or code build.

These are not operative Rust mutants. They challenge output framing/value
comparison with temporary bytes and never change the frozen on-disk corpus.
Run separately from own-client or compiled-source qualification.
"""

import argparse
import json
from pathlib import Path

from validate import compare, identify, load_corpus, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    corpus = load_corpus(args.corpus.resolve())
    original = corpus['expected']
    rows = corpus['expected_rows']
    lookup = {case_id: index for index, case_id in enumerate(corpus['ids'])}

    def replace(case_id, replacement):
        changed = list(rows)
        changed[lookup[case_id]] = replacement
        return b'\n'.join(changed) + b'\n'

    controls = [
        ('unaltered', original, b'', 0, False, 'MATCH', 0),
        ('wrong-value', replace(b'anchor-004', b'anchor-004\tparsed\t3\t1'), b'', 0, False, 'MISMATCH', 1),
        ('wrong-consumption', replace(b'anchor-004', b'anchor-004\tparsed\t2\t0'), b'', 0, False, 'MISMATCH', 1),
        ('wrong-class', replace(b'anchor-000', b'anchor-000\torder-invariant'), b'', 0, False, 'MISMATCH', 1),
        ('wrong-id', replace(b'anchor-004', b'other\tparsed\t3\t0'), b'', 0, False, 'INVALID_OUTPUT', None),
        ('missing-column', replace(b'anchor-004', b'anchor-004\tparsed\t3'), b'', 0, False, 'INVALID_OUTPUT', None),
        ('noncanonical-value', replace(b'anchor-004', b'anchor-004\tparsed\t3\t00'), b'', 0, False, 'INVALID_OUTPUT', None),
        ('out-of-range-value', replace(b'anchor-004', b'anchor-004\tparsed\t3\t18446744073709551616'), b'', 0, False, 'INVALID_OUTPUT', None),
        ('missing-lf', original[:-1], b'', 0, False, 'INVALID_OUTPUT', None),
        ('extra-row', original + rows[0] + b'\n', b'', 0, False, 'INVALID_OUTPUT', None),
        ('missing-row', b'\n'.join(rows[:-1]) + b'\n', b'', 0, False, 'INVALID_OUTPUT', None),
        ('reordered-rows', b'\n'.join([rows[1], rows[0], *rows[2:]]) + b'\n', b'', 0, False, 'INVALID_OUTPUT', None),
        ('unexpected-crlf', original.replace(b'\n', b'\r\n'), b'', 0, False, 'INVALID_OUTPUT', None),
        ('stderr-on-valid-input', original, b'diagnostic\n', 0, False, 'INVALID_OUTPUT', None),
        ('client-error', original, b'error\n', 2, False, 'PROCESS_FAILURE', None),
        ('client-signal', original, b'', -6, False, 'PROCESS_FAILURE', None),
        ('client-timeout', b'', b'', None, True, 'TIMEOUT', None),
    ]
    results = []
    for name, stdout, stderr, code, expired, status, mismatches in controls:
        actual = compare(corpus, stdout, stderr, code, expired)
        passed = actual['status'] == status and (mismatches is None or actual['mismatches'] == mismatches)
        results.append({'name': name, 'expected_status': status, 'expected_mismatches': mismatches,
                        'actual_status': actual['status'], 'actual_mismatches': actual['mismatches'],
                        'stdout_sha256': sha(stdout), 'pass': passed})
    if args.out.exists():
        raise FileExistsError('preserve original comparator controls; use a new report path')
    report = {'script': identify(Path(__file__).resolve()), 'comparator': identify(Path(__file__).with_name('validate.py')),
              'controls': results, 'pass': all(row['pass'] for row in results),
              'scope': 'Pure actual-output comparator controls; no Rust mutant, child process, captured execution, corpus mutation or allocator test.'}
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'pass': report['pass'], 'controls': len(results), 'report': str(args.out)}, sort_keys=True))
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
