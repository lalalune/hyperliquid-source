#!/usr/bin/env python3
"""Run only new native Rust against independently frozen arithmetic outputs."""
import argparse
import base64
import gzip
import json
from pathlib import Path
import platform
import struct
import subprocess

from verify_static import PACKET, ROOT, TARGET, encoded, require, sha, validate

SOURCE = ROOT / 'src/node94-mask-rounding'
CRATE = 'node94_mask_rounding'
RUSTC_SHA = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
RUSTC_COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
MUTATIONS = [
    ('exclusive_cutoff', 'input > CUTOFF', 'input >= CUTOFF'),
    ('signed_cutoff', 'input > CUTOFF', '(input as i64) > (CUTOFF as i64)'),
    ('missing_cutoff', 'input > CUTOFF', 'input > CUTOFF && false'),
    ('main_shift', 'input >> 8', 'input >> 9'),
    ('rounding_shift', '(0x20000 - input) >> 11', '(0x20000 - input) >> 10'),
    ('rounding_base', '(0x20000 - input) >> 11', '(0x1ffff - input) >> 11'),
    ('narrowed_addend', 'input.wrapping_add', '(input as u32 as u64).wrapping_add'),
    ('sentinel_bits', '0xffff_ffff_ffff_ffb8;', '0xffff_ffff_ffff_ffb7;'),
]


def compare(actual, expected, inputs):
    require(len(actual) == len(expected), 'native framing differs')
    count, first = 0, None
    for index, (got, want, stimulus) in enumerate(zip(struct.iter_unpack('<Q', actual),
            struct.iter_unpack('<Q', expected), struct.iter_unpack('<Q', inputs))):
        if got != want:
            count += 1
            if first is None:
                first = {'index': index, 'input': hex(stimulus[0]),
                         'actual': hex(got[0]), 'expected': hex(want[0])}
    return {'mismatches': count, 'first_witness': first, 'stdout_sha256': sha(actual)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--cc', type=Path, default=Path('/usr/bin/cc'))
    args = parser.parse_args()
    out, rustc, cc = args.out.absolute(), args.rustc.resolve(), args.cc.resolve()
    require(not out.exists(), 'use a new output directory')
    records, inputs, expected = validate()
    for name, raw in records.items():
        require((PACKET / name).read_bytes() == raw, name + ' drift')
    for name, raw in [('inputs', inputs), ('expected', expected)]:
        require(gzip.decompress((PACKET / (name + '.bin.gz')).read_bytes()) == raw,
                name + ' frozen fixture drift')
    require(sha(rustc.read_bytes()) == RUSTC_SHA, 'actual research compiler differs')
    hashed_paths = [SOURCE / 'lib.rs', SOURCE / 'input_only_driver.rs',
                    PACKET / 'verify_static.py', PACKET / 'verify_rust.py']
    before = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in hashed_paths}
    linker_sha = sha(cc.read_bytes())
    out.mkdir(parents=True)
    calls, streams = [], {}

    def run(label, argv, data=None, success=True):
        process = subprocess.run(list(map(str, argv)), cwd=ROOT, input=data, capture_output=True)
        logs = {}
        for suffix, raw in [('stdout', process.stdout), ('stderr', process.stderr)]:
            filename = label + '.' + suffix
            (out / filename).write_bytes(raw)
            logs[suffix] = {'file': filename, 'bytes': len(raw), 'sha256': sha(raw)}
            streams[filename] = raw
        calls.append({'label': label, 'argv': [str(v).replace(str(ROOT), '<repo>').replace(str(rustc), '<rustc>') for v in argv],
                      'exit_code': process.returncode, 'stdin_sha256': None if data is None else sha(data),
                      'logs': logs})
        (out / 'calls.json').write_bytes(encoded(calls))
        require((process.returncode == 0) == success, label + ' process failed; raw streams retained')
        return process

    version = run('compiler', [rustc, '-vV']).stdout.decode()
    require('release: 1.94.1\n' in version and f'commit-hash: {RUSTC_COMMIT}\n' in version
            and 'host: aarch64-apple-darwin\n' in version, 'compiler identity differs')
    linker_version = run('linker', [cc, '--version']).stdout.decode()
    source_text = (SOURCE / 'lib.rs').read_text()

    def build(name, source, optimization):
        directory = out / name
        directory.mkdir()
        library, client = directory / f'lib{CRATE}.rlib', directory / 'client'
        flags = ['--edition=2021', '--target=aarch64-apple-darwin', '-Dwarnings',
                 '-Ccodegen-units=1', '-Coverflow-checks=on', f'-Copt-level={optimization}',
                 f'-Clinker={cc}', '--remap-path-prefix', f'{ROOT}=/reconstruction']
        run(name + '-library', [rustc, '--crate-name', CRATE, '--crate-type=rlib', source,
                               '-Cmetadata=mask_rounding94', *flags, '-o', library])
        run(name + '-client', [rustc, '--crate-name', 'mask_rounding_client',
                              SOURCE / 'input_only_driver.rs', '--extern', f'{CRATE}={library}',
                              *flags, '-o', client])
        raw = run(name + '-run', [client], inputs).stdout
        return library, client, raw, flags

    builds, rebuilds, controls = [], [], []
    for opt in (0, 3):
        name = f'opt{opt}'
        lib, client, raw, flags = build(name, SOURCE / 'lib.rs', opt)
        comparison = compare(raw, expected, inputs)
        require(comparison['mismatches'] == 0, name + ' native value mismatch')
        unit = out / name / 'unit-tests'
        run(name + '-unit-build', [rustc, '--test', '--crate-name', CRATE, SOURCE / 'lib.rs',
                                  *flags, '-o', unit])
        tests = run(name + '-unit-run', [unit, '--test-threads=1']).stdout
        require(b'3 passed; 0 failed' in tests, 'unit tests did not run')
        lib2, client2, raw2, _ = build(name + '-repeat', SOURCE / 'lib.rs', opt)
        require(raw2 == expected, 'repeat output differs')
        for kind, a, b in [('rlib', lib, lib2), ('client', client, client2)]:
            require(a.read_bytes() == b.read_bytes(), 'own repeated artifact differs')
            rebuilds.append({'profile': name, 'artifact': kind, 'bytes': a.stat().st_size,
                             'sha256': sha(a.read_bytes()), 'raw_equal': True, 'normalization': 'none'})
        for malformed in [b'\0', b'\0' * 8 + b'\0']:
            bad = run(name + '-partial-' + str(len(malformed)), [client], malformed, success=False)
            require(not bad.stdout and b'partial u64 input' in bad.stderr, 'malformed input leaked output')
        builds.append({'profile': name, 'cases': len(inputs) // 8, 'unit_tests_passed': 3, **comparison})
        for label, needle, replacement in MUTATIONS:
            require(source_text.count(needle) == 1, label + ' mutation is not unique')
            mutant = out / (label + '.rs')
            mutant.write_text(source_text.replace(needle, replacement))
            _, _, wrong, _ = build(name + '-' + label, mutant, opt)
            result = compare(wrong, expected, inputs)
            require(result['mismatches'] > 0, 'wrong native implementation survived: ' + label)
            controls.append({'profile': name, 'mutation': label,
                             'source_sha256': sha(mutant.read_bytes()), **result})
    changed = bytes([expected[0] ^ 1]) + expected[1:]
    require(compare(changed, expected, inputs)['mismatches'] == 1, 'changed-output control failed')
    try:
        compare(expected[:-8], expected, inputs)
    except ValueError:
        pass
    else:
        raise ValueError('missing-output control survived')
    require(before == {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in hashed_paths},
            'source changed during qualification')
    require(sha(rustc.read_bytes()) == RUSTC_SHA and sha(cc.read_bytes()) == linker_sha,
            'compiler/linker changed during qualification')
    archive = {'encoding': 'base64', 'streams': {name: sha(raw) for name, raw in streams.items()},
               'payloads': {sha(raw): base64.b64encode(raw).decode() for raw in streams.values()}}
    archive_path = out / 'raw-streams.json.gz'
    archive_path.write_bytes(gzip.compress(encoded(archive), mtime=0))
    decoded = json.loads(gzip.decompress(archive_path.read_bytes()))
    require(all(base64.b64decode(decoded['payloads'][decoded['streams'][name]], validate=True) == raw
                for name, raw in streams.items()), 'lossless stream archive differs')
    result = {'target_sha256': TARGET, 'source_sha256': before, 'compiler_sha256': RUSTC_SHA,
              'compiler_version': version, 'linker_sha256': linker_sha, 'linker_version': linker_version,
              'python': platform.python_version(), 'platform': platform.platform(),
              'frozen_sha256': {name: sha(raw) for name, raw in records.items()},
              'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected),
              'comparisons': builds, 'repeated_builds': rebuilds, 'native_wrong_controls': controls,
              'comparator_controls': ['changed word detected', 'missing word rejected'],
              'raw_archive_sha256': sha(archive_path.read_bytes()),
              'captured_code_executed': False, 'instruction_emulator_executed': False,
              'target_compiled_byte_comparison': 'not performed; host value reconstruction only'}
    (out / 'results.json').write_bytes(encoded(result))
    print(json.dumps({'cases': len(inputs) // 8, 'native_profiles': builds,
                      'wrong_controls_detected': len(controls), 'repeated_artifacts_equal': len(rebuilds)}))


if __name__ == '__main__':
    main()
