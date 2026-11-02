#!/usr/bin/env python3
"""Build a bounded Rust reconstruction and compare target-grounded expectations.

No captured program, native excerpt, network or chain operation is executed.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SOURCE = ROOT / 'src/node94-checkpoint-retention/lib.rs'
CRATE = 'node94_checkpoint_retention'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()

import checkpoint_retention as target
from evm_amount_scale import Image


def bind(data):
    return target.build(data)


def cases(data):
    image = Image(data)
    inputs, expected = [], []
    maximum = (1 << 64) - 1
    points = [0, 1, 2, 9, 10, 11, (1 << 63) - 1, 1 << 63, maximum - 1, maximum]

    def outcome(marker, height, lower, upper, cap):
        if marker:
            return True, False
        observed = target.replay_unmarked(image, height, lower, upper, cap)
        formula = target.expected(height, lower, upper, cap)
        require(observed == formula, 'decoded bound program disagrees with order oracle')
        return observed['keep'], observed['diagnostic']

    def add(marker, height, lower, upper, cap):
        keep, diagnostic = outcome(marker, height, lower, upper, cap)
        inputs.append(f'D {marker} {height} {lower} {upper} {cap}')
        expected.append(f'{int(keep)} {int(diagnostic)}')

    for height, lower, upper, cap in itertools.product(points, repeat=4):
        add(0, height, lower, upper, cap)
    for marker in range(256):
        for height, lower, upper, cap in [(0, 10, 1, 0), (10, 10, 20, 10),
                                          (20, 10, 20, 30), (maximum, 0, maximum, maximum)]:
            add(marker, height, lower, upper, cap)
    rng = random.Random(0x33084A0)
    for _ in range(512):
        height, lower, upper, cap = [rng.getrandbits(64) for _ in range(4)]
        add(rng.randrange(256), height, lower, upper, cap)
    for index in range(256):
        row = bytes((index + j * 17) & 255 for j in range(24))
        h = points[index % len(points)]
        row += h.to_bytes(8, 'little')
        for marker, lower, upper, cap in [(0, h, min(h + 1, maximum), h),
                                          (0, h, h, maximum), (255, maximum, 0, 0)]:
            keep, _ = outcome(marker, h, lower, upper, cap)
            inputs.append(f'R {marker} {lower} {upper} {cap} {row.hex()}')
            expected.append(row.hex() if keep else 'N')
    return inputs, expected


PREDICATE = 'keep: lower <= height && height < upper && height <= cap,'
MUTANTS = [
    ('one_instead_of_nonzero_marker', 'marker_al != 0', 'marker_al == 1'),
    ('exclusive_lower', PREDICATE, 'keep: lower < height && height < upper && height <= cap,'),
    ('inclusive_upper', PREDICATE, 'keep: lower <= height && height <= upper && height <= cap,'),
    ('exclusive_cap', PREDICATE, 'keep: lower <= height && height < upper && height < cap,'),
    ('wrong_height_endianness', 'u64::from_le_bytes', 'u64::from_be_bytes'),
    ('changed_opaque_row_bytes', '        Some(row)', '        Some([0; 32])'),
]


def run(command, **kwargs):
    return subprocess.run([str(x) for x in command], check=True, text=True,
                          capture_output=True, **kwargs).stdout


def compile_runner(rustc, source, directory, opt):
    directory.mkdir()
    lib = directory / ('lib' + CRATE + '.rlib')
    flags = ['--edition=2021', '-D', 'warnings', '-C', 'overflow-checks=on',
             '-C', f'opt-level={opt}']
    run([rustc, *flags, '--crate-name', CRATE, '--crate-type=rlib', source, '-o', lib])
    exe = directory / 'compare'
    run([rustc, *flags, PACKET / 'harness.rs', '--extern', f'{CRATE}={lib}', '-o', exe])
    return lib, exe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and digest(data) == SHA, 'wrong node94 identity')
    evidence = bind(data)
    require(evidence == json.loads((PACKET / 'evidence.json').read_text()), 'evidence differs')
    inputs, expected = cases(data)
    inputs = '\n'.join(inputs) + '\n'
    answers = '\n'.join(expected) + '\n'
    (args.output / 'inputs.txt').write_text(inputs)
    (args.output / 'expected.txt').write_text(answers)
    compiler = run([args.rustc, '--version', '--verbose'])
    require(compiler.startswith('rustc 1.94.1 '), 'use pinned research rustc 1.94.1')
    builds, libs = [], []
    for name, opt in [('debug', 0), ('optimized', 3), ('repeat', 3)]:
        lib, exe = compile_runner(args.rustc, SOURCE, args.output / name, opt)
        actual = run([exe], input=inputs)
        require(actual.splitlines() == expected, name + ' output differs')
        (args.output / (name + '.txt')).write_text(actual)
        libs.append(digest(lib.read_bytes()))
        builds.append({'name': name, 'cases': len(expected), 'mismatches': 0,
                       'output_sha256': digest(actual.encode())})
    require(libs[1] == libs[2], 'own optimized libraries differ')
    unit = args.output / 'unit-tests'
    run([args.rustc, '--edition=2021', '--test', '-D', 'warnings', '-C',
         'overflow-checks=on', SOURCE, '-o', unit])
    (args.output / 'unit-tests.txt').write_text(run([unit]).rstrip() + '\n')
    controls = []
    if args.controls:
        source = SOURCE.read_text()
        production, boundary, tests = source.partition('#[cfg(test)]')
        for name, old, new in MUTANTS:
            require(production.count(old) == 1, 'ambiguous mutation ' + name)
            mutated = args.output / (name + '.rs')
            mutated.write_text(production.replace(old, new) + boundary + tests)
            _, exe = compile_runner(args.rustc, mutated, args.output / name, 3)
            actual = run([exe], input=inputs).splitlines()
            require(len(actual) == len(expected), 'mutant output count differs')
            differences = sum(a != b for a, b in zip(actual, expected))
            require(differences > 0, 'undetected mutation ' + name)
            controls.append({'name': name, 'mismatches': differences})
    result = {'target_sha256': SHA, 'rustc': compiler.splitlines(),
              'source_sha256': digest(SOURCE.read_bytes()),
              'inputs_sha256': digest(inputs.encode()), 'expected_sha256': digest(answers.encode()),
              'builds': builds, 'own_rlib_sha256': libs, 'mutants': controls,
              'captured_code_executed': False,
              'limits': 'Selected scalar/byte policy only; static-derived expectations, not original execution or binary identity.'}
    (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
