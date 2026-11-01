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
from oracle import fixtures

SOURCE = ROOT / 'src/node94-reversed-record-copy'
CRATE = 'node94_reversed_record_copy'
RUSTC_SHA = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
RUSTC_COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
STAGES = """    copy_block::<4>(arena, source + 48, destination + 16, false);
    copy_block::<16>(arena, source + 32, destination, false);
    copy_block::<16>(arena, source + 16, destination + 20, true);
    copy_block::<16>(arena, source, destination + 36, true);"""
BLOCK = """    let mut block = [0_u8; N];
    block.copy_from_slice(&arena[source..source + N]);
    if reverse {
        block.reverse();
    }
    arena[destination..destination + N].copy_from_slice(&block);"""
SNAPSHOT = """    let mut detached = [0_u8; 104];
    detached[..52].copy_from_slice(&arena[source..source_end]);
    copy_block::<4>(&mut detached, 48, 68, false);
    copy_block::<16>(&mut detached, 32, 52, false);
    copy_block::<16>(&mut detached, 16, 72, true);
    copy_block::<16>(&mut detached, 0, 88, true);
    arena[destination..destination_end].copy_from_slice(&detached[52..]);"""
MUTATIONS = [
    ('whole_source_snapshot', STAGES, SNAPSHOT),
    ('bytewise_live_copy', BLOCK, '    for position in 0..N { arena[destination + position] = arena[source + if reverse { N - 1 - position } else { position }]; }'),
    ('reverse_each_half', 'block.reverse();', 'for half in block.chunks_exact_mut(8) { half.reverse(); }'),
    ('omit_first_reversal', 'source + 16, destination + 20, true', 'source + 16, destination + 20, false'),
    ('header_order', STAGES, '\n'.join([STAGES.splitlines()[1], STAGES.splitlines()[0], *STAGES.splitlines()[2:]])),
    ('header_dword_offset', 'source + 48, destination + 16', 'source + 48, destination + 12'),
    ('header_vector_offset', 'source + 32, destination, false', 'source + 31, destination, false'),
    ('swap_reversed_fields', STAGES, STAGES.replace('destination + 20', 'destination + TEMP').replace('destination + 36', 'destination + 20').replace('destination + TEMP', 'destination + 36')),
    ('returned_source', '\n    Some(destination)\n', '\n    Some(source)\n'),
    ('reject_exact_fit', 'source_end > arena.len()', 'source_end >= arena.len()'),
    ('signed_pack_saturation', 'block.reverse();', 'block.reverse(); for byte in &mut block { *byte = (*byte).min(127); }'),
]


def compare(actual, expected, inputs):
    require(len(actual) == len(expected), 'native framing differs')
    count, first, memory_cases, alias_cases, return_cases = 0, None, 0, 0, 0
    for index, (got, want, stimulus) in enumerate(zip(struct.iter_unpack('<BQ256s', actual),
            struct.iter_unpack('<BQ256s', expected), struct.iter_unpack('<QQQQQ', inputs))):
        if got != want:
            count += 1
            memory_cases += got[2] != want[2]
            return_cases += got[:2] != want[:2]
            alias_cases += got[0] == want[0] == 1 and abs(stimulus[0] - stimulus[1]) < 52 and got[2] != want[2]
            if first is None:
                differences = [i for i, (a, b) in enumerate(zip(got[2], want[2])) if a != b]
                first = {'index': index, 'descriptor_source_destination_length_seed_pattern': list(stimulus),
                         'actual_tag_offset': list(got[:2]), 'expected_tag_offset': list(want[:2]),
                         'memory_bytes_differ': len(differences),
                         'first_memory_difference': None if not differences else
                             {'offset': differences[0], 'actual': got[2][differences[0]], 'expected': want[2][differences[0]]}}
    return {'mismatches': count, 'memory_mismatch_cases': memory_cases, 'return_mismatch_cases': return_cases,
            'admitted_overlap_memory_mismatches': alias_cases, 'first_witness': first, 'stdout_sha256': sha(actual)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--cc', type=Path, default=Path('/usr/bin/cc'))
    args = parser.parse_args()
    out, rustc, cc = args.out.absolute(), args.rustc.resolve(), args.cc.resolve()
    require(not out.exists(), 'use a new output directory')
    initial_source = (SOURCE / 'lib.rs').read_text()
    for label, needle, _ in MUTATIONS:
        require(initial_source.count(needle) == 1, label + ' mutation is not unique')
    static = validate()
    inputs, expected, maps, coverage = fixtures()
    frozen = json.loads((PACKET / 'frozen.json').read_text())
    require(all(frozen[k] == v for k, v in coverage.items()), 'frozen metadata drift')
    require(frozen['oracle_sha256_at_freeze'] == sha((PACKET / 'oracle.py').read_bytes()), 'pre-Rust oracle drift')
    require(frozen['static_sha256_at_freeze'] == sha(encoded(static)), 'pre-Rust static binding drift')
    records = {'static.json': encoded(static)}
    require(gzip.decompress((PACKET / 'provenance-maps.bin.gz').read_bytes()) == maps, 'frozen provenance maps drift')
    for name, raw in records.items():
        require((PACKET / name).read_bytes() == raw, name + ' drift')
    for name, raw in [('inputs', inputs), ('expected', expected)]:
        require(gzip.decompress((PACKET / (name + '.bin.gz')).read_bytes()) == raw,
                name + ' frozen fixture drift')
    require(sha(rustc.read_bytes()) == RUSTC_SHA, 'actual research compiler differs')
    hashed_paths = [SOURCE / 'lib.rs', SOURCE / 'input_only_driver.rs',
                    PACKET / 'verify_static.py', PACKET / 'verify_rust.py', PACKET / 'oracle.py']
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
                               '-Cmetadata=reversed_record_copy94', *flags, '-o', library])
        run(name + '-client', [rustc, '--crate-name', 'reversed_record_copy_client',
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
        for malformed in [b'\0', b'\0' * 40 + b'\0']:
            bad = run(name + '-partial-' + str(len(malformed)), [client], malformed, success=False)
            require(not bad.stdout and b'partial arena descriptor' in bad.stderr, 'malformed input leaked output')
        oversized = run(name + '-allocation-limit', [client], struct.pack('<QQQQQ', 0, 0, 257, 0, 0), success=False)
        require(not oversized.stdout and b'backing storage' in oversized.stderr, 'harness backing-storage bound differs')
        unknown = run(name + '-unknown-pattern', [client], struct.pack('<QQQQQ', 0, 0, 256, 0, 3), success=False)
        require(not unknown.stdout and b'unknown fixture pattern' in unknown.stderr, 'unknown pattern accepted')
        builds.append({'profile': name, 'cases': len(inputs) // 40, 'unit_tests_passed': 3, **comparison})
        for label, needle, replacement in MUTATIONS:
            require(source_text.count(needle) == 1, label + ' mutation is not unique')
            mutant = out / (label + '.rs')
            mutant.write_text(source_text.replace(needle, replacement))
            _, _, wrong, _ = build(name + '-' + label, mutant, opt)
            result = compare(wrong, expected, inputs)
            require(result['mismatches'] > 0, 'wrong native implementation survived: ' + label)
            if label in ['whole_source_snapshot', 'bytewise_live_copy', 'header_order']:
                require(result['admitted_overlap_memory_mismatches'] > 0, 'alias control lacks normal memory mismatch')
            controls.append({'profile': name, 'mutation': label,
                             'source_sha256': sha(mutant.read_bytes()), **result})
    changed = bytes([expected[0] ^ 1]) + expected[1:]
    require(compare(changed, expected, inputs)['mismatches'] == 1, 'changed-output control failed')
    try:
        compare(expected[:-265], expected, inputs)
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
              'comparator_controls': ['changed output record detected', 'missing output record rejected'],
              'raw_archive_sha256': sha(archive_path.read_bytes()),
              'captured_code_executed': False, 'instruction_emulator_executed': False,
              'target_compiled_byte_comparison': 'not performed; host value reconstruction only'}
    (out / 'results.json').write_bytes(encoded(result))
    print(json.dumps({'cases': len(inputs) // 40, 'native_profiles': builds,
                      'wrong_controls_detected': len(controls), 'repeated_artifacts_equal': len(rebuilds)}))


if __name__ == '__main__':
    main()
