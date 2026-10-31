#!/usr/bin/env python3
"""Build our scalar Rust against freshly authenticated visor class intervals.

The captured visor is read only. This executes only newly authored Rust.
None outside the proved class domain is a chosen API restriction, not an
allocator error result. Production receives inputs only; this is data-flow
separation, not a filesystem sandbox claim.
"""
import argparse
import bisect
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import subprocess
import time

import visor_allocator_large_request as native

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/'artifacts/visor/captured/hl-visor'
COMPONENT = ROOT/'src/visor-large-request-class'
SOURCE = COMPONENT/'lib.rs'
FIXTURE = COMPONENT/'target-vectors.tsv'
NATIVE_FIXTURE = ROOT/'research/work-items/RE-013-visor-allocator-large-request/observed/class-intervals.tsv'
CRATE = 'visor_large_request_class'
MAX64 = (1 << 64) - 1
UPPER = 0x7000000000000000
COMPILER_SHA256 = 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for raw in iter(lambda: stream.read(1 << 20), b''):
            digest.update(raw)
    return digest.hexdigest()


def interval_rows(record):
    """Use the actual native proof output, never the producer's default constants."""
    intervals = record['proof']['intervals']
    need(len(intervals) == 203, 'Native proof must cover the exact203 class intervals')
    triples = [(row['lower'], row['upper'], row['class']) for row in intervals]
    need(triples[0] == (4097, 5120, 29) and triples[-1] == (0x6000000000000001, UPPER, 231),
         'Native class partition endpoints differ')
    need(all(a[1]+1 == b[0] and a[2]+1 == b[2] for a, b in zip(triples, triples[1:])),
         'Native class intervals are not an exact contiguous partition')
    return triples


def input_cases(intervals):
    """All class edges and neighbours plus reproducible uint64 cases."""
    values = {0, 1, 4095, 4096, 4097, UPPER-1, UPPER, UPPER+1, MAX64}
    for lower, upper, _ in intervals:
        for edge in (lower, upper):
            values.update(value for value in (edge-1, edge, edge+1) if 0 <= value <= MAX64)
    for bit in range(65):
        edge = 1 << bit
        values.update(value for value in (edge-1, edge, edge+1) if 0 <= value <= MAX64)
    state = 0xd19a65b92c0473ef
    for _ in range(1024):
        state = (state*0x5851f42d4c957f2d+0x14057b7ef767814f) & MAX64
        values.add(state)
    return sorted(values)


def expected_value(raw, intervals):
    """Independent integer-interval membership; no Rust/leading_zeros/formula call."""
    if not 4097 <= raw <= UPPER:
        return None
    index = bisect.bisect_right([row[0] for row in intervals], raw)-1
    lower, upper, result = intervals[index]
    need(lower <= raw <= upper, 'Input not covered by authenticated interval proof')
    return result


def encoded_rows(rows):
    return ''.join(f'{value}\t{"none" if result is None else result}\n'
                   for value, result in rows).encode('ascii')


def oracle(binary=TARGET):
    with Path(binary).open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        native.authenticate(data)
        record = native.inspect(data)
        native.authenticate(data)
    intervals = interval_rows(record)
    rows = [(value, expected_value(value, intervals)) for value in input_cases(intervals)]
    interval_tsv = ('lower\tupper\tclass\n'+''.join(f'{a}\t{b}\t{c}\n' for a, b, c in intervals)).encode('ascii')
    fixture = encoded_rows(rows)
    inputs = ''.join(f'{value}\n' for value, _ in rows).encode('ascii')
    some = sum(result is not None for _, result in rows)
    return {'record': record, 'intervals': intervals, 'rows': rows, 'fixture': fixture,
            'inputs': inputs, 'interval_tsv': interval_tsv,
            'metadata': {'target': record['target'], 'native_constants': record['proof']['constants'],
                         'class_interval_count': len(intervals), 'case_count': len(rows),
                         'some_cases': some, 'chosen_None_cases': len(rows)-some,
                         'fixture_sha256': sha(fixture), 'inputs_sha256': sha(inputs),
                         'class_intervals_sha256': sha(interval_tsv),
                         'expected_values': 'Membership in203 fresh actual-target-derived integer intervals; not Rust output or leading_zeros implementation.',
                         'None_meaning': 'Only outside the chosen numeric proof domain; not captured allocator failure/null/errno.',
                         'limits': 'No target execution, allocation interface, TLS/cache initialization, original ABI/types/units/compiler, byte identity or gate.'}}


def verify_fixtures(expected, fixture=FIXTURE, native_fixture=NATIVE_FIXTURE):
    need(Path(native_fixture).read_bytes() == expected['interval_tsv'],
         'Retained native intervals differ from fresh authenticated proof')
    need(Path(fixture).read_bytes() == expected['fixture'],
         'Rust vectors differ from fresh authenticated class/domain expectations')


def target_controls(expected):
    """Actual bounded raw-operand counterfactuals, never an admitted target."""
    original = {row['name']: bytes.fromhex(row['hex']) for row in expected['record']['fragments']}
    controls = []
    for name, fragment, site, replacement, witness in (
        ('class-bias-minus22', 'large-classifier', 0x70a672, b'\xea', 4097),
        ('small-guard4097', 'entry-guards', 0x70a1bd, (4097).to_bytes(4, 'little'), 4097),
        ('maximum-minus-one', 'large-classifier', 0x70a622, (UPPER-1).to_bytes(8, 'little'), UPPER)):
        start = next(start for key, start, _ in native.SCOPES if key == fragment)
        changed = dict(original)
        body = bytearray(changed[fragment]); offset = site-start
        body[offset:offset+len(replacement)] = replacement; changed[fragment] = bytes(body)
        proof = native.prove_fragments(changed)
        wanted = expected_value(witness, expected['intervals'])
        intervals = [(row['lower'], row['upper'], row['class']) for row in proof['intervals']]
        after = next((value for lower, upper, value in intervals if lower <= witness <= upper), None)
        need(after != wanted, 'Actual immediate mutation lacks an interval/domain counterexample')
        try:
            interval_rows({'proof': proof})
        except ValueError as error:
            rejection = str(error)
        else:
            raise ValueError('Altered native partition unexpectedly passes target-specific interval admission')
        controls.append({'name': name, 'fragment': fragment, 'site': hex(site), 'witness': witness,
                         'original_class': wanted, 'counterfactual_interval_class_or_outside': after,
                         'different': True, 'admission_rejection': rejection,
                         'None_in_counterfactual': 'Only outside that changed analytic domain, not allocation failure.',
                         'captured_target_executed_or_modified': False})
    return controls


HARNESS = r'''extern crate visor_large_request_class;
use std::io::{self, Write};
fn main() {
    let path = std::env::args().nth(1).expect("input-only corpus path");
    let inputs = std::fs::read_to_string(path).expect("input-only corpus");
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in inputs.lines() {
        let value: u64 = line.parse().expect("unsigned64 input");
        match visor_large_request_class::large_request_class(value) {
            Some(class) => writeln!(output, "{}\t{}", value, class).unwrap(),
            None => writeln!(output, "{}\tnone", value).unwrap(),
        }
    }
}
'''


def build(binary, rustc, output, controls=False):
    """Only our new Rust is executed; fresh native interval admission comes first."""
    output = Path(output)
    need(not output.exists(), 'Output directory must be new; previous evidence is preserved')
    expected = oracle(binary)
    verify_fixtures(expected)
    rustc = Path(rustc).absolute()
    compiler_before = file_digest(rustc)
    need(compiler_before == COMPILER_SHA256, 'Research compiler executable differs from verified1.94.1 pin')
    linker = shutil.which('cc')
    need(linker is not None, 'Host C linker driver cc is required')
    linker_before = file_digest(linker)
    paths = (SOURCE, FIXTURE, NATIVE_FIXTURE, Path(__file__), Path(native.__file__))
    source_before = {str(p.relative_to(ROOT)): file_digest(p) for p in paths}
    output.mkdir(parents=True, exist_ok=False)
    (output/'oracle.json').write_text(json.dumps(expected['metadata'], indent=2)+'\n')
    (output/'inputs.txt').write_bytes(expected['inputs'])
    (output/'expected.tsv').write_bytes(expected['fixture'])
    (output/'comparison-main.rs').write_text(HARNESS)
    calls = []
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    def execute(label, argv, required_exit=0):
        # Compiler jobs are sequential and owned; never execute a captured input.
        start = time.monotonic()
        process = subprocess.run([str(a) for a in argv], cwd=ROOT, env=environment,
                                 stdin=subprocess.DEVNULL, capture_output=True)
        logs = {}
        for kind, raw in (('stdout', process.stdout), ('stderr', process.stderr)):
            p = output/(label+'.'+kind); p.write_bytes(raw)
            logs[kind] = {'file': p.name, 'bytes': len(raw), 'sha256': sha(raw)}
        calls.append({'label': label, 'argv': [str(a) for a in argv], 'exit_code': process.returncode,
                      'seconds': round(time.monotonic()-start, 3), 'logs': logs})
        (output/'CALLS.json').write_text(json.dumps(calls, indent=2)+'\n')
        if required_exit is not None:
            need(process.returncode == required_exit, f'{label} failed; original stdout/stderr retained')
        return process
    try:
        version = execute('rustc-identity', [rustc, '-vV']).stdout.decode()
        need(version.startswith('rustc 1.94.1 ') and 'e408947bfd200af42db322daf0fadfe7e26d3bd1' in version,
             'Actual compiler version/fullcommit differs from repository research pin')
        linker_version = execute('linker-identity', [linker, '--version']).stdout.decode()
        def flags(opt):
            return ['--edition=2021', '-D', 'warnings', '-C', 'codegen-units=1',
                    '-C', f'opt-level={opt}', '-C', 'overflow-checks=on', '-C', 'linker='+linker,
                    '--remap-path-prefix', str(ROOT)+'=/reconstruction']
        def library(label, source, opt, directory):
            directory.mkdir(parents=True, exist_ok=False)
            target = directory/('lib'+CRATE+'.rlib')
            execute(label, [rustc, '--crate-name', CRATE, '--crate-type=rlib', source, '-o', target,
                            '-C', 'metadata=visor-large-request-class', *flags(opt)])
            return target
        def linked_values(label, library_path, opt, directory):
            executable = directory/'comparison'
            execute(label+'-link', [rustc, '--crate-name', 'visor_class_comparison', output/'comparison-main.rs',
                    '--extern', CRATE+'='+str(library_path), '-o', executable, *flags(opt)])
            return execute(label+'-run', [executable, output/'inputs.txt']).stdout
        profiles = []
        for name, opt in (('debug', 0), ('optimized', 3)):
            directory = output/name
            library_path = library(name+'-library', SOURCE, opt, directory)
            unit = directory/'module-tests'
            execute(name+'-test-build', [rustc, '--crate-name', CRATE, '--test', SOURCE, '-o', unit, *flags(opt)])
            tests = execute(name+'-tests', [unit, '--nocapture'])
            need(b'1 passed; 0 failed; 0 ignored' in tests.stdout, 'Ordinary Rust corpus test did not run')
            actual = linked_values(name+'-production', library_path, opt, directory)
            need(actual == expected['fixture'], f'{name} actual production differs from fresh target interval/domain expectations')
            profiles.append({'name': name, 'opt_level': opt, 'ordinary_Rust_tests': 1,
                             'independent_production_cases': len(expected['rows']),
                             'actual_values_sha256': sha(actual), 'expected_values_sha256': sha(expected['fixture']),
                             'library_sha256': file_digest(library_path), 'matched': True})
        first = library('repro-a', SOURCE, 3, output/'repro-a')
        second = library('repro-b', SOURCE, 3, output/'repro-b')
        reproducibility = {'build_a_bytes': first.stat().st_size, 'build_b_bytes': second.stat().st_size,
                          'build_a_sha256': file_digest(first), 'build_b_sha256': file_digest(second),
                          'raw_equal': first.read_bytes() == second.read_bytes(), 'normalization': 'none',
                          'original_visor_match_claimed': False}
        need(reproducibility['raw_equal'], 'Own same-toolchain class libraries are not raw reproducible')
        mutants = []
        if controls:
            source = SOURCE.read_text()
            changes = [('lower-inclusive', 'raw <= 4096', 'raw < 4096'),
                       ('upper-exclusive', 'raw > 0x7000_0000_0000_0000', 'raw >= 0x7000_0000_0000_0000'),
                       ('power-of-two-k', '64 - preceding.leading_zeros()', '64 - raw.leading_zeros()'),
                       ('fraction-mask', '(k - 3)) & 3', '(k - 3)) & 7'),
                       ('wrong-bias', '4 * k + fractional - 23', '4 * k + fractional - 22')]
            for name, needle, replacement in changes:
                need(source.count(needle) == 1, 'Semantic mutation site is ambiguous: '+name)
                directory = output/('mutant-'+name); directory.mkdir()
                path = directory/'lib.rs'; path.write_text(source.replace(needle, replacement))
                (directory/'target-vectors.tsv').write_bytes(expected['fixture'])
                library_path = library('mutant-'+name+'-library', path, 0, directory/'build')
                actual = linked_values('mutant-'+name+'-production', library_path, 0, directory)
                lines = actual.decode().splitlines()
                need(len(lines) == len(expected['rows']), 'Compiled mutant output count differs')
                mismatches = []
                for (value, wanted), line in zip(expected['rows'], lines):
                    shown, observed = line.split('\t'); shown = int(shown)
                    observed = None if observed == 'none' else int(observed)
                    need(shown == value, 'Mutant input order differs')
                    if observed != wanted:
                        mismatches.append({'input': value, 'expected': wanted, 'actual': observed})
                need(mismatches, 'Compiled semantic mutation escaped independent comparison')
                unit = directory/'module-tests'
                execute('mutant-'+name+'-test-build', [rustc, '--crate-name', CRATE, '--test', path,
                        '-o', unit, *flags(0)])
                failure = execute('mutant-'+name+'-tests', [unit, '--nocapture'], required_exit=None)
                need(failure.returncode == 101 and b'assertion' in failure.stdout+failure.stderr,
                     'Mutant did not fail the actual compiled semantic assertion')
                mutants.append({'name': name, 'compiled': True, 'ordinary_test_exit_code': failure.returncode,
                                'independent_production_mismatches': len(mismatches),
                                'first_witness': mismatches[0], 'source_sha256': file_digest(path),
                                'library_sha256': file_digest(library_path)})
        source_after = {str(p.relative_to(ROOT)): file_digest(p) for p in paths}
        need(source_before == source_after and compiler_before == file_digest(rustc)
             and linker_before == file_digest(linker), 'Source/compiler/linker changed during build')
        with Path(binary).open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            native.authenticate(data)
        result = {'status': 'VISOR_CLASS_SCALAR_BUILD_AND_COMPARISON_PASS',
                  'compiler': {'path': str(rustc), 'version': version, 'executable_sha256': compiler_before,
                               'meaning': 'Repository-pinned research compiler, not recovered original visor compiler.'},
                  'host_linker_driver': {'path': linker, 'version': linker_version, 'sha256': linker_before,
                                         'explicitly_passed_to_rustc': True},
                  'source_sha256s': source_before, 'source_compiler_and_target_unchanged': True,
                  'oracle': expected['metadata'], 'profiles': profiles,
                  'same_toolchain_reproducibility': reproducibility, 'compiled_Rust_mutations': mutants,
                  'target_operand_controls': target_controls(expected) if controls else [],
                  'commands': calls, 'captured_original_executed_or_emulated': False,
                  'limits': ['Only numeric class on4097..0x7000000000000000; None outside is a chosen API restriction.',
                             'Original TLS route/caches/tables/allocation and local error-call/store/return are unimplemented.',
                             'Finite comparisons support the integer proof; no private ABI/units/original compiler/byte identity/gates.',
                             'Production receives input values only, not expectations; no filesystem sandbox is claimed.']}
        (output/'RESULT.json').write_text(json.dumps(result, indent=2)+'\n')
        return result
    except Exception as error:
        failure = {'status': 'COMPONENT_RUN_FAILED_OR_PAUSED', 'error': str(error), 'commands': calls,
                   'preserved_outputs': True, 'captured_original_executed_or_emulated': False}
        (output/'FAILURE.json').write_text(json.dumps(failure, indent=2)+'\n')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--rustc', type=Path, required=True, help='Existing independently verified research1.94.1 executable')
    parser.add_argument('--output', type=Path, required=True, help='New physical owned directory for all compiler/test outputs')
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    result = build(args.binary, args.rustc, args.output, args.controls)
    print(json.dumps({'status': result['status'], 'profiles': result['profiles'],
                      'compiled_mutants': len(result['compiled_Rust_mutations']),
                      'own_builds_raw_equal': result['same_toolchain_reproducibility']['raw_equal']}, sort_keys=True))
