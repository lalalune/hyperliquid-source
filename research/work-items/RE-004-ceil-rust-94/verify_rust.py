#!/usr/bin/env python3
"""Build new Rust only; compare its scalar results to the prior static proof."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
PRIOR = ROOT / 'research/work-items/RE-001-ceil-f64-94'
SOURCE = ROOT / 'src/node94-ceil'
SIGN, FRACTION = 1 << 63, (1 << 52) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def corpus():
    """Reproduce the predecessor's published input hash without its bit rule."""
    values = set()
    for exponent in range(2048):
        fractions = {0, 1, 2, (1 << 51) - 1, 1 << 51, FRACTION - 1, FRACTION}
        if 1023 <= exponent <= 1074:
            boundary = 1 << (1075 - exponent)
            fractions.update(v for v in (boundary - 1, boundary, boundary + 1) if v <= FRACTION)
        values.update(sign | exponent << 52 | fraction
                      for sign in (0, SIGN) for fraction in fractions)
    values.update(int.from_bytes(hashlib.sha256(f'ceil94:{i}'.encode()).digest()[:8], 'little')
                  for i in range(4096))
    return sorted(values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='new directory for builds and logs')
    parser.add_argument('--rustc', default='rustc', help='Rust 1.94.1 compiler on PATH or absolute path')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(command, label, data=None, success=True):
        command = [str(x) for x in command]
        result = subprocess.run(command, cwd=ROOT, input=data, capture_output=True)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        commands.append({'label': label,
                         'argv': [s.replace(str(ROOT), '<repo>') for s in command],
                         'returncode': result.returncode})
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        require((result.returncode == 0) == success, label + ': unexpected process status')
        return result.stdout

    version = run([args.rustc, '-vV'], 'rustc-version').decode()
    require(version.startswith('rustc 1.94.1 '), 'use the pinned rustc 1.94.1 toolchain')
    host = next(line.split(': ', 1)[1] for line in version.splitlines() if line.startswith('host: '))
    run([sys.executable, '-B', PRIOR / 'verify.py'], 'target-static-binding')
    spec = importlib.util.spec_from_file_location('ceil_static_oracle', PRIOR / 'verify.py')
    prior = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prior)
    retained = json.loads((PRIOR / 'evidence.json').read_text())
    cases = corpus()
    inputs = b''.join(struct.pack('<Q', b) for b in cases)
    expected_words = [prior.rational_ceiling(b) for b in cases]
    expected = b''.join(struct.pack('<Q', b) for b in expected_words)
    require(len(cases) == retained['numerical_controls']['cases'] == 33066, 'case count drift')
    require(sha(inputs) == retained['numerical_controls']['inputs_sha256'], 'input hash drift')
    require(sha(expected) == retained['numerical_controls']['expected_sha256'], 'oracle hash drift')
    (out / 'inputs.bin').write_bytes(inputs)
    (out / 'expected.bin').write_bytes(expected)
    flags = ['--edition=2024', '--target', host, '-D', 'warnings',
             '-C', 'codegen-units=1', '-C', 'overflow-checks=yes',
             '--remap-path-prefix', str(ROOT) + '=/source']

    def library(source, name, optimization):
        directory = out / name
        directory.mkdir()
        artifact = directory / 'libnode94_ceil.rlib'
        run([args.rustc, *flags, '-C', 'panic=abort', '-C', 'opt-level=' + str(optimization),
             '--crate-name', 'node94_ceil', '--crate-type', 'rlib', source, '-o', artifact], name)
        return artifact

    def client(artifact, name, optimization):
        executable = out / name
        run([args.rustc, *flags, '-C', 'panic=abort', '-C', 'opt-level=' + str(optimization),
             '--extern', 'node94_ceil=' + str(artifact), SOURCE / 'input_only_driver.rs',
             '-o', executable], name + '-build')
        raw = run([executable], name + '-run', inputs)
        require(len(raw) == len(cases) * 16, 'client output framing differs')
        pairs = list(struct.iter_unpack('<QQ', raw))
        mismatches = [i for i, ((bits, typed), want) in enumerate(zip(pairs, expected_words))
                      if bits != want or typed != want]
        first = None
        if mismatches:
            i = mismatches[0]
            first = {'input': f'{cases[i]:016x}', 'expected': f'{expected_words[i]:016x}',
                     'ceil_bits': f'{pairs[i][0]:016x}', 'ceil_f64_bits': f'{pairs[i][1]:016x}'}
        return executable, {'mismatching_inputs': len(mismatches), 'output_sha256': sha(raw),
                            'first_mismatch': first}

    builds = {}
    for optimization in (0, 3):
        name = 'opt' + str(optimization)
        artifact = library(SOURCE / 'lib.rs', name + '-library', optimization)
        executable, result = client(artifact, name + '-client', optimization)
        require(result['mismatching_inputs'] == 0, name + ': reconstructed Rust differs')
        rejected = run([executable], name + '-partial-word', b'\x01\x02\x03', success=False)
        require(not rejected and b'partial input word' in
                (out / (name + '-partial-word.stderr')).read_bytes(),
                name + ': malformed input was not rejected for its framing')
        test = out / (name + '-unit-tests')
        run([args.rustc, *flags, '-C', 'opt-level=' + str(optimization), '--test',
             SOURCE / 'lib.rs', '-o', test], name + '-unit-build')
        run([test], name + '-unit-run')
        builds[name] = {**result, 'rlib_sha256': sha(artifact.read_bytes()), 'unit_tests': 2}
    repeated = library(SOURCE / 'lib.rs', 'opt3-repeat-library', 3)
    require(sha(repeated.read_bytes()) == builds['opt3']['rlib_sha256'], 'two-build rlib mismatch')

    text = (SOURCE / 'lib.rs').read_text()
    changes = {
        'truncate_positive_fraction': ('bits & SIGN == 0 && fraction != 0',
                                       'bits & SIGN == 0 && fraction != 0 && false'),
        'lose_negative_zero': ('            SIGN\n', '            0\n'),
        'quiet_signaling_nan': ('        return bits;\n',
                               '        return if exponent == 2047 && bits & 0x000f_ffff_ffff_ffff != 0 {\n'
                               '            bits | (1 << 51)\n        } else { bits };\n'),
        'early_large_exponent_return': ('exponent >= 1075', 'exponent >= 1074'),
    }
    controls = {}
    for name, (before, after) in changes.items():
        require(text.count(before) == 1, 'mutation anchor is not unique: ' + name)
        source = out / (name + '.rs')
        source.write_text(text.replace(before, after))
        artifact = library(source, name + '-library', 3)
        _, result = client(artifact, name + '-client', 3)
        require(result['mismatching_inputs'] ==
                retained['numerical_controls']['semantic_control_mismatches'][name],
                'native mutant differs from the predecessor control: ' + name)
        controls[name] = {**result, 'source_sha256': sha(source.read_bytes())}

    result = {'target_sha256': retained['target_sha256'],
              'target_leaf': retained['body'], 'prior_packet': str(PRIOR.relative_to(ROOT)),
              'prior_inputs': {name: sha((PRIOR / name).read_bytes()) for name in
                               ('PROOF.md', 'verify.py', 'evidence.json', 'samples.tsv')},
              'rust_sources': {name: sha((SOURCE / name).read_bytes()) for name in
                               ('lib.rs', 'input_only_driver.rs')},
              'rustc': version, 'host': host, 'platform': sys.platform,
              'machine': platform.machine(), 'cases': len(cases),
              'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected),
              'builds': builds, 'two_optimized_rlibs_raw_equal': True,
              'native_mutants': controls, 'captured_code_executed': False,
              'target_instruction_emulation': False,
              'compiled_target_byte_comparison': 'not measured; host scalar value reconstruction only'}
    (out / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'cases': len(cases), 'host': host,
                      'base_mismatches': {k: v['mismatching_inputs'] for k, v in builds.items()},
                      'native_mutant_mismatches': {k: v['mismatching_inputs'] for k, v in controls.items()},
                      'two_optimized_rlibs_raw_equal': True}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print('ceil Rust verification: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
