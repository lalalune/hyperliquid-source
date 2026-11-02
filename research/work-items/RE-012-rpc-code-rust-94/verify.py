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
SOURCE = ROOT / 'src/node94-rpc-code/lib.rs'
CRATE = 'node94_rpc_code'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()

import rpc_code_static as target


def bind(data):
    return target.build(data)


def cases(data):
    record = bind(data)
    tags = tuple(row['tag'] for row in record['table_rows'])
    bias = record['wrapping_add_u32']
    independent = {-32700: 0, -32007: 1, -32600: 2, -32601: 3, -32602: 5, -32603: 6}
    words = {value & 0xffffffff for value in range(-65536, 65536)}
    words.update([0x7fffffff, 0x80000000, 0x80000001, 0xfffffffe, 0xffffffff])
    rng = random.Random(0x15BB930)
    words.update(rng.getrandbits(32) for _ in range(4096))
    inputs, expected = [], []
    for raw in sorted(words):
        signed = raw - (1 << 32) if raw & 0x80000000 else raw
        kind = independent.get(signed, 7)
        require(kind == target.classify(raw, tags, bias), 'table and dictionary oracles disagree')
        inputs.append(str(raw))
        expected.append(f'{kind} {raw}')
    return inputs, expected


MUTANTS = [
    ('wrong_invalid_request_kind', '-32600 => 2', '-32600 => 4'),
    ('swapped_method_kind', '-32601 => 3', '-32601 => 5'),
    ('missing_parse_singleton', '-32700 => 0', '-32701 => 0'),
    ('wrong_default', '_ => 7', '_ => 4'),
    ('lost_original_code', 'code: raw', 'code: 0'),
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
