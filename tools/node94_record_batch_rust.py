#!/usr/bin/env python3
"""Build our scalar Rust and compare it with extracted unsigned native algebra.

Only independently authored Rust is executed. Native expectations evaluate a
finite arithmetic DAG with explicit raw scalar leaves, not a CPU/memory model.
"""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import subprocess
import time

import node94_gap56319fd_variable_records as static

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
COMPONENT = ROOT / 'src/node94-record-batch-limit'
SOURCE = COMPONENT / 'lib.rs'
FIXTURE = COMPONENT / 'target-vectors.tsv'
ORIGINAL_COMMIT = '2743f6ae9237405d46a93dc96ddb646a55819e89'
CRATE = 'node94_record_batch_limit'
MASK = (1 << 64) - 1


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def input_cases():
    """Total arithmetic cases; these are not observed successful loop entries."""
    cases = set()

    def add(d, remainders, outputs=(0, 0, 0, 0), lower=0):
        cases.add(((lower + d) & MASK, lower, *outputs,
                   *((cursor + distance) & MASK for cursor, distance in zip(outputs, remainders))))

    edges = [0, 1, 6, 7, 8, 9, 10, 11, 63, 64, 65, (1 << 32) - 1,
             1 << 32, (1 << 63) - 1, 1 << 63, MASK - 1, MASK]
    for d in edges:
        for r in edges:
            add(d, [r] * 4)
    # Every lane is separately the only limiting lane, at low and high boundaries.
    for lane in range(4):
        for r in edges:
            remainders = [MASK] * 4
            remainders[lane] = r
            add(MASK, remainders)
            add(MASK, remainders, [MASK - 3, 17, 1 << 63, MASK - 4], lower=MASK)
    for bit in range(64):
        for scale in (7, 10):
            for delta in (-1, 0, 1):
                value = (1 << bit) * scale + delta
                if 0 <= value <= MASK:
                    add(value, [MASK] * 4, lower=MASK)
                    for lane in range(4):
                        remaining = [MASK] * 4
                        remaining[lane] = value
                        add(MASK, remaining, [0, MASK, 1 << 63, MASK - 4])
    # A nonzero quotient can wrap stop exactly to zero without taking the guard.
    add(7, [10] * 4, outputs=[MASK - 4] * 4)
    # Independent raw words cover simultaneous underflow and unstructured minima.
    state = 0x56319FD249249249
    for _ in range(1024):
        words = []
        for _ in range(10):
            state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MASK
            words.append(state)
        cases.add(tuple(words))
    return sorted(cases)


def scalar_value(record, values):
    """Evaluate only the extracted finite scalar term DAG; never memory or CPU."""
    need(len(values) == 10 and all(0 <= v <= MASK for v in values), 'Expected ten raw u64 words')
    terms = record['terms']
    by_name = {t['name']: i for i, t in enumerate(terms) if t['op'] == 'variable'}
    bound = {by_name['current.input0']: values[0], record['input_lower_bound_term']: values[1]}
    bound.update({by_name[f'current.output{lane}']: values[2 + lane] for lane in range(4)})
    bound.update(zip(record['fixed_output_end_terms'], values[6:10]))

    def evaluate(index):
        if index in bound:
            return bound[index]
        term = terms[index]
        need(term['width'] == 64, 'Scalar expression width changed')
        op = term['op']
        args = [evaluate(i) for i in term['args']]
        if op == 'constant':
            result = term['value']
        elif op == 'sub':
            result = (args[0] - args[1]) & MASK
        elif op == 'add':
            result = (args[0] + args[1]) & MASK
        elif op == 'multiply_high_unsigned':
            result = (args[0] * args[1]) >> 64
        elif op == 'multiply_low':
            result = (args[0] * args[1]) & MASK
        elif op == 'logical_right':
            result = args[0] >> args[1]
        elif op == 'if_unsigned_above':
            result = args[2] if args[0] > args[1] else args[3]
        else:
            raise ValueError('Unbound or non-scalar term: ' + op)
        need(0 <= result <= MASK, 'Scalar intermediate left u64 domain')
        bound[index] = result
        return result

    quotient = evaluate(record['quotient_term'])
    stop = evaluate(record['stop_term'])
    guard = record['outer_guard_conditions'][0]
    need(guard['relation'] == 'equal', 'Numeric guard relation changed')
    zero_guard = int(evaluate(guard['operands'][0]) == evaluate(guard['operands'][1]))
    return quotient, stop, zero_guard


def oracle(binary=TARGET):
    report, rows, _ = static.inspect_target(Path(binary))
    values = input_cases()
    results = [scalar_value(report, case) for case in values]
    need(all(q <= MASK // 10 and bool(guard) == (q == 0) for q, _, guard in results),
         'Extracted quotient bound or numeric zero guard changed')
    inputs = ''.join('\t'.join(map(str, case)) + '\n' for case in values).encode('ascii')
    fixture = ''.join('\t'.join(map(str, (*case, *result))) + '\n'
                      for case, result in zip(values, results)).encode('ascii')
    return dict(report=report, rows=rows, values=values, results=results, inputs=inputs, fixture=fixture,
                metadata=dict(target_sha256=report['target_sha256'], target_bytes=report['target_bytes'],
                              original_static_commit=ORIGINAL_COMMIT, candidate=report['candidate'],
                              division_support=report['division_support'],
                              case_count=len(values), inputs_sha256=sha(inputs), fixture_sha256=sha(fixture),
                              input_fields=['I0', 'L', 'O0', 'O1', 'O2', 'O3', 'E0', 'E1', 'E2', 'E3'],
                              output_fields=['q', 'stop', 'numeric_stop_equals_O3'],
                              expected_values='Extracted finite unsigned MUL-high/shift/add/sub/min scalar DAG; no production division or Rust output.',
                              limits='Raw modular scalar words only, not caller/region/table/loop/ABI validity or successful native execution.'))


def verify_fixture(expected, fixture=FIXTURE):
    need(Path(fixture).read_bytes() == expected['fixture'], 'Fixture differs from fresh target-derived scalar oracle')


def target_controls(expected):
    by_va = {r['va']: r for r in expected['rows']}
    out = []
    for name, va, start, width, value, witness in (
        ('M7-minus-one', 0x5631A7A, 2, 8, static.M7 - 1, 7),
        ('M10-minus-one', 0x5631ACC, 2, 8, static.M10 - 1, 10)):
        row = dict(by_va[va])
        raw = bytearray.fromhex(row['bytes'])
        original_value = int.from_bytes(raw[start:start + width], 'little')
        raw[start:start + width] = value.to_bytes(width, 'little')
        row['bytes'] = raw.hex()
        extracted = int.from_bytes(raw[start:start + width], 'little')
        if va == 0x5631A7A:
            before_high = (witness * original_value) >> 64
            after_high = (witness * extracted) >> 64
            before = (before_high + ((witness - before_high) >> 1)) >> 2
            after = (after_high + ((witness - after_high) >> 1)) >> 2
        else:
            before = ((witness * original_value) >> 64) >> 3
            after = ((witness * extracted) >> 64) >> 3
        need(before == 1 and after == 0, 'Actual reciprocal mutation lost its scalar witness')
        changed = [row if r['va'] == va else r for r in expected['rows']]
        try:
            static.division_support(changed)
        except ValueError as error:
            reason = str(error)
        else:
            raise ValueError('Changed actual source operand was accepted')
        out.append(dict(name=name, va=hex(va), operand_byte_offset=start, witness=witness,
                        original_quotient=before, changed_quotient=after, rejection=reason,
                        captured_target_modified_or_executed=False))
    return out


HARNESS = r'''extern crate node94_record_batch_limit;
use std::io::{self, Write};
fn main() {
    let path = std::env::args().nth(1).expect("input-only corpus path");
    let inputs = std::fs::read_to_string(path).expect("input-only corpus");
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in inputs.lines() {
        let fields: Vec<u64> = line.split('\t').map(|s| s.parse().unwrap()).collect();
        assert_eq!(fields.len(), 10);
        let result = node94_record_batch_limit::batch_limit_stop(
            fields[0], fields[1], [fields[2], fields[3], fields[4], fields[5]],
            [fields[6], fields[7], fields[8], fields[9]]);
        writeln!(output, "{}\t{}\t{}\t{}", line, result.quotient,
                 result.stop, u64::from(result.zero_guard)).unwrap();
    }
}
'''


def mutation_sources(source):
    edits = [
        ('wrong-input-divisor', 'wrapping_sub(lower) / 7', 'wrapping_sub(lower) / 8'),
        ('wrong-output-divisor', 'wrapping_sub(outputs[lane]) / 10', 'wrapping_sub(outputs[lane]) / 9'),
        *[(f'omit-lane-{lane}', 'let output_limit = ends[lane]',
           f'if lane == {lane} {{ continue; }}\n        let output_limit = ends[lane]') for lane in range(4)],
        ('saturating-distances', '.wrapping_sub(', '.saturating_sub('),
        ('wrong-stop-factor', 'quotient * 5', 'quotient * 4'),
        ('saturating-stop', 'outputs[3].wrapping_add(', 'outputs[3].saturating_add('),
        ('wrong-zero-guard', 'zero_guard: stop == outputs[3]', 'zero_guard: stop == 0'),
    ]
    for name, before, after in edits:
        need(before in source, 'Missing mutation source site: ' + name)
        if name != 'saturating-distances':
            need(source.count(before) == 1, 'Ambiguous mutation source site: ' + name)
        yield name, source.replace(before, after)


def build(binary, rustc, output, controls=False):
    """Run our own real no_std library/tests with an external answer stream."""
    output = Path(output).absolute()
    need(not output.exists(), 'Output directory must be new; previous evidence is preserved')
    expected = oracle(binary)
    verify_fixture(expected)
    rustc = Path(rustc).absolute()
    version = subprocess.check_output([str(rustc), '-vV'], text=True)
    need(version.startswith('rustc 1.94.1 '), 'Requires the repository research compiler1.94.1')
    linker = shutil.which('cc')
    need(linker is not None, 'Host linker driver cc is required')
    linker_version = subprocess.check_output([linker, '--version'], text=True)
    source_paths = [SOURCE, FIXTURE, Path(__file__), ROOT / 'tools/node94_gap56319fd_variable_records.py']
    source_before = {str(p.relative_to(ROOT)): digest_file(p) for p in source_paths}
    compiler_hash, linker_hash = digest_file(rustc), digest_file(linker)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'inputs.txt').write_bytes(expected['inputs'])
    (output / 'expected.tsv').write_bytes(expected['fixture'])
    (output / 'comparison-main.rs').write_text(HARNESS, encoding='utf-8', newline='\n')
    (output / 'oracle.json').write_text(json.dumps(expected['metadata'], indent=2) + '\n', encoding='utf-8', newline='\n')
    calls = []

    def execute(label, argv, required_exit=0):
        start = time.monotonic()
        process = subprocess.run([str(x) for x in argv], cwd=ROOT, stdin=subprocess.DEVNULL,
                                 capture_output=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        logs = {}
        for kind, raw in [('stdout', process.stdout), ('stderr', process.stderr)]:
            path = output / (label + '.' + kind)
            path.write_bytes(raw)
            logs[kind] = dict(file=path.name, bytes=len(raw), sha256=sha(raw))
        calls.append(dict(label=label, argv=[str(x) for x in argv], exit_code=process.returncode,
                          seconds=round(time.monotonic() - start, 3), logs=logs))
        if required_exit is not None:
            need(process.returncode == required_exit, label + ' failed; raw subprocess output retained')
        return process

    def flags(opt):
        return ['--edition=2021', '-D', 'warnings', '-C', 'codegen-units=1', '-C', f'opt-level={opt}',
                '-C', 'overflow-checks=on', '-C', 'linker=' + linker,
                '--remap-path-prefix', str(ROOT) + '=/reconstruction']

    def library(label, source, opt, directory):
        directory.mkdir(parents=True, exist_ok=False)
        path = directory / ('lib' + CRATE + '.rlib')
        execute(label, [rustc, '--crate-name', CRATE, '--crate-type=rlib', source, '-o', path,
                        '-C', 'metadata=node94-record-batch-limit', *flags(opt)])
        return path

    def comparison(label, library_path, opt, directory):
        program = directory / 'comparison'
        execute(label + '-link', [rustc, '--crate-name', 'batch_scalar_comparison', output / 'comparison-main.rs',
                                 '--extern', CRATE + '=' + str(library_path), '-o', program, *flags(opt)])
        return execute(label + '-run', [program, output / 'inputs.txt']).stdout

    profiles = []
    for name, opt in [('debug', 0), ('optimized', 3)]:
        directory = output / name
        lib = library(name + '-library', SOURCE, opt, directory)
        unit = directory / 'module-tests'
        execute(name + '-test-build', [rustc, '--crate-name', CRATE, '--test', SOURCE, '-o', unit, *flags(opt)])
        result = execute(name + '-tests', [unit, '--nocapture'])
        need(b'1 passed; 0 failed; 0 ignored' in result.stdout, 'Ordinary Rust corpus test did not run')
        actual = comparison(name + '-production', lib, opt, directory)
        need(actual == expected['fixture'], name + ' production scalar result differs from native algebra')
        profiles.append(dict(name=name, opt_level=opt, ordinary_Rust_tests=1,
                             independent_production_cases=len(expected['values']), matched=True,
                             actual_values_sha256=sha(actual), expected_values_sha256=sha(expected['fixture']),
                             library_sha256=digest_file(lib)))
    first = library('repro-a', SOURCE, 3, output / 'repro-a')
    second = library('repro-b', SOURCE, 3, output / 'repro-b')
    reproducibility = dict(build_a_bytes=first.stat().st_size, build_b_bytes=second.stat().st_size,
                           build_a_sha256=digest_file(first), build_b_sha256=digest_file(second),
                           raw_equal=first.read_bytes() == second.read_bytes(), normalization='none',
                           original_binary_match_claimed=False)
    need(reproducibility['raw_equal'], 'Own optimized scalar library builds differ')
    mutants = []
    if controls:
        for name, changed in mutation_sources(SOURCE.read_text(encoding='utf-8')):
            directory = output / ('mutant-' + name)
            directory.mkdir()
            path = directory / 'lib.rs'
            path.write_text(changed, encoding='utf-8', newline='\n')
            (directory / 'target-vectors.tsv').write_bytes(expected['fixture'])
            lib = library('mutant-' + name + '-library', path, 0, directory / 'build')
            actual = comparison('mutant-' + name + '-production', lib, 0, directory)
            lines = actual.decode('ascii').splitlines()
            need(len(lines) == len(expected['values']), 'Mutant output count changed')
            mismatches = []
            for case, wanted, line in zip(expected['values'], expected['results'], lines):
                fields = tuple(map(int, line.split('\t')))
                need(len(fields) == 13 and fields[:10] == case, 'Mutant input order or field count changed')
                if fields[10:] != wanted:
                    mismatches.append(dict(input=list(case), expected=list(wanted), actual=list(fields[10:])))
            need(mismatches, 'Compiled semantic mutant escaped independent production comparison')
            unit = directory / 'module-tests'
            execute('mutant-' + name + '-test-build', [rustc, '--crate-name', CRATE, '--test', path, '-o', unit, *flags(0)])
            failure = execute('mutant-' + name + '-tests', [unit, '--nocapture'], required_exit=None)
            need(failure.returncode != 0 and b'assertion' in failure.stdout + failure.stderr,
                 'Compiled mutant did not fail an actual semantic assertion')
            mutants.append(dict(name=name, compiled=True, ordinary_test_failed=True,
                                independent_production_mismatches=len(mismatches), first_witness=mismatches[0],
                                source_sha256=digest_file(path), library_sha256=digest_file(lib)))
    need(source_before == {str(p.relative_to(ROOT)): digest_file(p) for p in source_paths}, 'Source/fixture changed during build')
    need(compiler_hash == digest_file(rustc) and linker_hash == digest_file(linker), 'Compiler/linker changed during build')
    with Path(binary).open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        need(sha(data) == static.DIGEST, 'Target changed during component run')
    result = dict(status='TOTAL_SCALAR_BATCH_LIMIT_RUST_COMPARISON_PASS', original_static_commit=ORIGINAL_COMMIT,
                  compiler=dict(path=str(rustc), version=version, sha256=compiler_hash,
                                meaning='Pinned research compiler, not recovered original compiler'),
                  host_linker_driver=dict(path=linker, version=linker_version, sha256=linker_hash, explicitly_passed=True),
                  source_sha256s=source_before, source_compiler_target_unchanged=True, oracle=expected['metadata'],
                  profiles=profiles, same_toolchain_reproducibility=reproducibility,
                  compiled_Rust_mutations=mutants, target_operand_controls=target_controls(expected) if controls else [],
                  commands=calls, captured_original_executed_or_emulated=False,
                  limits=['Only total raw-u64 scalar expressions; no table/write/refill/BSF loop or original caller contract.',
                          'New chosen API, not original types/ABI/compiler, full helper, byte match or progress gate.',
                          'Finite compiled comparisons support independently proved arithmetic; not a machine-equivalence proof.'])
    (output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='Fresh owned output directory')
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    result = build(args.binary, args.rustc, args.output, args.controls)
    print(json.dumps(dict(status=result['status'], profiles=result['profiles'],
                          compiled_semantic_mutants=len(result['compiled_Rust_mutations']),
                          actual_operand_controls=len(result['target_operand_controls']),
                          own_library_builds_raw_equal=result['same_toolchain_reproducibility']['raw_equal']), sort_keys=True))
