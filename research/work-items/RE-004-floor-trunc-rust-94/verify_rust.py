#!/usr/bin/env python3
"""Compile only new Rust; compare to the frozen exact-rational static contract."""
import argparse
import base64
import gzip
import json
from pathlib import Path
import struct
import subprocess
import sys

from verify_static import PACKET, ROOT, corpus, oracle, require, sha

SOURCE = ROOT / 'src/node94-floor-trunc'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--rustc', default='rustc')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands = []
    streams = {}

    def run(argv, label, data=None, success=True):
        argv = [str(x) for x in argv]
        result = subprocess.run(argv, cwd=ROOT, input=data, capture_output=True)
        for suffix, raw in [('stdout', result.stdout), ('stderr', result.stderr)]:
            path = out / (label + '.' + suffix + '.gz')
            path.write_bytes(gzip.compress(raw, mtime=0))
            streams[path.name] = {'raw_bytes': len(raw), 'raw_sha256': sha(raw)}
        commands.append({'argv': [x.replace(str(ROOT), '<repo>') for x in argv],
                         'label': label, 'returncode': result.returncode})
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        require((result.returncode == 0) == success, label + ' process status')
        return result

    run([sys.executable, '-B', PACKET / 'verify_static.py'], 'static')
    retained = json.loads((PACKET / 'static.json').read_text())['frozen_oracle']
    cases = [(bits, daz) for bits in corpus() for daz in (False, True)]
    expected_rows = [oracle(bits, daz) for bits, daz in cases]
    inputs = b''.join(struct.pack('<QB', bits, daz) for bits, daz in cases)
    expected = b''.join(struct.pack('<QQ', *row) for row in expected_rows)
    require(len(cases) == retained['cases'] and sha(inputs) == retained['inputs_sha256'] and
            sha(expected) == retained['expected_sha256'], 'frozen oracle drift')
    for name, data in [('inputs', inputs), ('expected', expected)]:
        (out / (name + '.bin.gz')).write_bytes(gzip.compress(data, mtime=0))
    version = run([args.rustc, '-vV'], 'rustc-version').stdout.decode()
    require(version.startswith('rustc 1.94.1 '), 'use pinned rustc 1.94.1')
    host = next(line.split(': ', 1)[1] for line in version.splitlines() if line.startswith('host: '))
    flags = ['--edition=2024', '--target', host, '-D', 'warnings', '-C', 'codegen-units=1',
             '-C', 'overflow-checks=yes', '--remap-path-prefix', str(ROOT) + '=/source']

    def build(source, name, opt):
        directory = out / name
        directory.mkdir()
        artifact = directory / 'libnode94_floor_trunc.rlib'
        executable = directory / 'client'
        specific = [*flags, '-C', 'panic=abort', '-C', 'opt-level=' + str(opt)]
        run([args.rustc, *specific, '--crate-name', 'node94_floor_trunc', '--crate-type', 'rlib',
             source, '-o', artifact], name + '-library')
        run([args.rustc, *specific, '--extern', 'node94_floor_trunc=' + str(artifact),
             SOURCE / 'input_only_driver.rs', '-o', executable], name + '-client')
        raw = run([executable], name + '-run', inputs).stdout
        require(len(raw) == len(expected), 'native framing')
        rows = list(struct.iter_unpack('<QQ', raw))
        mismatches = [i for i, (got, want) in enumerate(zip(rows, expected_rows)) if got != want]
        first = None
        if mismatches:
            i = mismatches[0]
            first = {'input_bits': f'{cases[i][0]:016x}', 'daz': cases[i][1],
                     'expected_trunc_floor': [f'{x:016x}' for x in expected_rows[i]],
                     'actual_trunc_floor': [f'{x:016x}' for x in rows[i]]}
        return executable, {'mismatches': len(mismatches), 'first_mismatch': first,
                            'output_sha256': sha(raw), 'rlib_sha256': sha(artifact.read_bytes()),
                            'client_sha256': sha(executable.read_bytes())}

    builds = {}
    for opt in (0, 3):
        name = 'opt' + str(opt)
        executable, record = build(SOURCE / 'lib.rs', name, opt)
        require(record['mismatches'] == 0, name + ' native mismatch')
        _, repeat = build(SOURCE / 'lib.rs', name + '-repeat', opt)
        require(record == repeat, name + ' repeated bytes/results differ')
        for invalid, label in [(b'\0', 'partial'), (b'\0' * 8 + b'\2', 'invalid-daz')]:
            bad = run([executable], name + '-' + label, invalid, success=False)
            require(not bad.stdout and b'invalid input framing or DAZ byte' in bad.stderr,
                    'malformed input not rejected before output')
        test = out / (name + '-tests')
        run([args.rustc, *flags, '-C', 'opt-level=' + str(opt), '--test', SOURCE / 'lib.rs',
             '-o', test], name + '-test-build')
        run([test], name + '-test-run')
        builds[name] = record

    source_text = (SOURCE / 'lib.rs').read_text()
    changes = {
        'ignore_daz': ('(daz && exponent == 0)', '(daz && false && exponent == 0)'),
        'flush_daz_result': ('        if bits == SIGN || (daz && exponent == 0) {\n            return bits;',
                             '        if bits == SIGN || (daz && exponent == 0) {\n            return SIGN;'),
        'truncate_negative_fraction': ('bits & SIGN != 0 && truncated != bits',
                                       'bits & SIGN != 0 && truncated != bits && false'),
        'increment_integral_negative': ('bits & SIGN != 0 && truncated != bits',
                                        'bits & SIGN != 0'),
        'lose_trunc_signed_zero': ('return bits & SIGN;', 'return 0;'),
        'early_floor_large_return': ('    if exponent >= 1075 {\n        return bits;\n    }\n    if exponent < 1023 {\n        if',
                                     '    if exponent >= 1074 {\n        return bits;\n    }\n    if exponent < 1023 {\n        if'),
    }
    mutants = {}
    for name, (before, after) in changes.items():
        require(source_text.count(before) == 1, 'ambiguous mutation: ' + name)
        path = out / (name + '.rs')
        path.write_text(source_text.replace(before, after))
        _, record = build(path, name, 3)
        require(record['mismatches'] > 0, 'surviving mutant: ' + name)
        mutants[name] = {**record, 'source_sha256': sha(path.read_bytes())}
    archive = {name: base64.b64encode(gzip.decompress((out / name).read_bytes())).decode()
               for name in streams}
    (out / 'streams.json.gz').write_bytes(gzip.compress(
        (json.dumps(archive, sort_keys=True) + '\n').encode(), mtime=0))
    decoded = json.loads(gzip.decompress((out / 'streams.json.gz').read_bytes()))
    require(all(sha(base64.b64decode(decoded[name])) == record['raw_sha256']
                for name, record in streams.items()), 'raw archive mismatch')
    result = {'target_sha256': json.loads((PACKET / 'static.json').read_text())['target_sha256'],
              'static_sha256': sha((PACKET / 'static.json').read_bytes()), 'oracle': retained,
              'rust_sources': {x: sha((SOURCE / x).read_bytes()) for x in ('lib.rs', 'input_only_driver.rs')},
              'verification_sources': {x: sha((PACKET / x).read_bytes()) for x in
                                        ('verify_static.py', 'verify_rust.py')},
              'rustc': version, 'host': host, 'builds': builds, 'native_mutants': mutants,
              'raw_two_builds_equal_each_optimization': True, 'unit_tests_per_optimization': 2,
              'streams': streams, 'captured_code_executed': False, 'instruction_emulation': False,
              'compiled_target_byte_comparison': 'not measured; host scalar value projection only'}
    (out / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'cases': len(cases), 'base_mismatches': {k: v['mismatches'] for k,v in builds.items()},
                      'mutants': {k: v['mismatches'] for k,v in mutants.items()}}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
