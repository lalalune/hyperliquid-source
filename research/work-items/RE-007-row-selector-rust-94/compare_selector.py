#!/usr/bin/env python3
"""Authenticate a frozen snapshot; compare separately produced selector output."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import shutil


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def files(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        need(not path.is_symlink(), 'snapshot symlink')
        if path.is_file() and path != directory / 'FREEZE.json':
            raw = path.read_bytes()
            result[str(path.relative_to(directory))] = dict(bytes=len(raw), sha256=sha(raw))
    return result


def authenticate(snapshot, digest):
    raw = (snapshot / 'FREEZE.json').read_bytes()
    need(sha(raw) == digest, 'freeze identity changed')
    frozen = json.loads(raw)
    need(files(snapshot) == frozen['manifest'], 'frozen snapshot files changed')
    return frozen


def mismatches(actual, expected):
    need(len(actual) == len(expected), 'output size differs')
    need(actual[:12] == expected[:12], 'output magic/count differs')
    need((len(actual) - 12) % 14 == 0, 'output record extent')
    return [case for case in range((len(actual) - 12) // 14)
            if actual[12 + case * 14:26 + case * 14] != expected[12 + case * 14:26 + case * 14]]


def compare(snapshot, digest, actual_path, expected_relative='expected.bin'):
    authenticate(snapshot, digest)
    expected_path = snapshot / expected_relative
    need(actual_path.resolve() != expected_path.resolve(), 'actual output must be separate')
    expected = expected_path.read_bytes()
    actual = actual_path.read_bytes()
    misses = mismatches(actual, expected)
    need(not misses, 'selector output mismatches: ' + str(misses[:10]))
    return dict(records=(len(actual)-12)//14, actual_sha256=sha(actual), mismatches=0)


def self_check(snapshot, digest):
    frozen = authenticate(snapshot, digest)
    expected = (snapshot / 'expected.bin').read_bytes()
    need(not mismatches(expected, expected), 'comparator self-admission')
    rejected = []
    for label, offset in [('id', 12), ('kind', 16), ('late-state-predicate', 17), ('bucket-index', 18)]:
        changed = bytearray(expected)
        changed[offset] ^= 1
        need(mismatches(changed, expected) == [0], 'result corruption missed: ' + label)
        rejected.append(label)
    for label, changed in [('magic', b'BADOUT01'+expected[8:]),
                           ('truncated', expected[:-1]), ('trailing', expected+b'\0')]:
        try:
            mismatches(changed, expected)
        except ValueError:
            rejected.append(label)
        else:
            raise ValueError('malformed output accepted: ' + label)
    for label, relative in [('selector', 'repo/src/node94-margin-risk/src/row_selector.rs'),
                            ('unrelated-component-input', 'repo/src/node94-margin-risk/src/types.rs'),
                            ('external-include-fixture', 'repo/research/work-items/RE-007-margin-path-94/boundaries.tsv'),
                            ('input', 'input.bin'), ('expected', 'expected.bin')]:
        with tempfile.TemporaryDirectory(prefix='selector-frozen-review-') as temporary:
            copy = Path(temporary) / 'snapshot'
            shutil.copytree(snapshot, copy)
            path = copy / relative
            path.write_bytes(path.read_bytes()+b'\0')
            try:
                authenticate(copy, digest)
            except ValueError:
                rejected.append(label)
            else:
                raise ValueError('snapshot corruption accepted: ' + label)
    with tempfile.TemporaryDirectory(prefix='selector-extra-review-') as temporary:
        copy = Path(temporary) / 'snapshot'
        shutil.copytree(snapshot, copy)
        (copy/'repo/src/node94-margin-risk/src/untracked.rs').write_text('// unexpected compiler input\n')
        try:
            authenticate(copy, digest)
        except ValueError:
            rejected.append('extra-untracked-input')
        else:
            raise ValueError('extra input accepted')
    try:
        authenticate(snapshot, '0'*64)
    except ValueError:
        rejected.append('freeze-digest')
    else:
        raise ValueError('wrong freeze digest accepted')
    return dict(status='comparator and snapshot controls only; no Rust output',
                cases=frozen['qualified_posthash_cases'], rejected_controls=rejected,
                compiler_executed=False, target_executed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--freeze-sha256', required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--actual', type=Path)
    group.add_argument('--self-check', action='store_true')
    args = parser.parse_args()
    result = self_check(args.snapshot, args.freeze_sha256) if args.self_check else compare(args.snapshot, args.freeze_sha256, args.actual)
    print(json.dumps(result, indent=2, sort_keys=True))
