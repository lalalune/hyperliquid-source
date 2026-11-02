#!/usr/bin/env python3
"""Compile two private point projections against pre-source frozen wire bytes."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT = ROOT / 'src/node94-orderbook'
MODULE = COMPONENT / 'src/j9_first_front.rs'
FREEZE_SHA = '122af21ab3e379a398fa5c87b33ea0867d5041928834992bd31ef15e20bc6357'
spec = importlib.util.spec_from_file_location('j9_fixed_snapshot', HERE / 'source_snapshot.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
S.bind(ROOT, COMPONENT, MODULE, HERE)
require, sha = S.require, S.sha


def render(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def frozen():
    raw = (HERE / 'PRE-SOURCE-WIRE-FREEZE.json').read_bytes()
    require(sha(raw) == FREEZE_SHA, 'pre-source wire freeze changed')
    record = json.loads(raw)
    rows = record['cases']
    require(len(rows) == 10 and [r['kind'] for r in rows] == [0] * 5 + [1] * 5, 'two-domain denominator')
    inputs, expected = bytes.fromhex(record['input_hex']), bytes.fromhex(record['expected_hex'])
    require(len(inputs) == len(expected) == 1932, 'frozen wire length')
    require(sha(inputs) == record['input_sha256'] and sha(expected) == record['expected_sha256'], 'frozen wire identity')
    return record, rows, inputs, expected


def compare(raw, rows):
    require(len(raw) == 12 + 192 * len(rows) and raw[:8] == b'J9OUT001', 'output frame/length')
    require(struct.unpack_from('<I', raw, 8)[0] == len(rows), 'output count')
    values, observations = [], []
    for i, row in enumerate(rows):
        got_id, kind, index, side, output, *scratch = struct.unpack_from('<IIIIQ21Q', raw, 12 + 192 * i)
        require(got_id == i and kind == row['kind'], 'output ID/kind/order')
        differences = [j for j, (a, b) in enumerate(zip(scratch, row['expected_scratch21'])) if a != b]
        item = dict(name=row['name'], kind=kind, expected_index=row['expected_index'], actual_index=index,
                    expected_side=row['expected_side'], actual_side=side,
                    expected_A0=row['expected_A0'], actual_A0=output,
                    changed_scratch_indices=differences,
                    expected_scratch_sha256=sha(struct.pack('<21Q', *row['expected_scratch21'])),
                    actual_scratch_sha256=sha(struct.pack('<21Q', *scratch)))
        if differences or output != row['expected_A0']:
            values.append(item)
        elif index != row['expected_index'] or side != row['expected_side']:
            observations.append(item)
    return values, observations


def variants(source):
    replacements = {
        'j9-signed-comparisons': ('value < words[destination - 1]', '(value as i64) < (words[destination - 1] as i64)'),
        'j9-skip-first-predecessor': ('let mut destination = 9;', 'let mut destination = 8;'),
        'j9-wrong-shift-value': ('words[destination] = words[destination - 1];', 'words[destination] = value;'),
        'j9-omit-final-insert': ('        words[destination] = value;', '        // final insertion omitted'),
        'j9-omit-initial-append': ('    words[9] = value;', '    // initial append omitted'),
        'j9-stop-before-front': ('destination > 0', 'destination > 1'),
        'j9-truncate-loaded-value': ('    words[9] = value;', '    let value = u64::from(value as u32);\n    words[9] = value;'),
        'j9-shift-equal-predecessors': ('value < words[destination - 1]', 'value <= words[destination - 1]'),
        'front-signed-comparison': ('if right < left {', 'if (right as i64) < (left as i64) {'),
        'front-choose-greater': ('if right < left {', 'if right > left {'),
        'front-omit-output-store': ('    *output = word;', '    let _ = (output, word);'),
        'front-truncate-output-word': ('    *output = word;', '    *output = u64::from(word as u32);'),
        'front-equality-chooses-right': ('if right < left {', 'if right <= left {'),
    }
    record, _, _, _ = frozen()
    require(set(replacements) == {m['name'] for m in record['mutants']}, 'control plan denominator')
    result = {}
    for name, (before, after) in replacements.items():
        require(source.count(before) == 1, 'source mutation anchor changed: ' + name)
        result[name] = source.replace(before, after)
    return result


def checked_input(out, identity):
    payloads = {}
    for name in ('input.bin', 'expected.bin'):
        path = out / name
        require(path.is_file() and not path.is_symlink(), 'fixture missing/symlink')
        payloads[name] = path.read_bytes()
        require(sha(payloads[name]) == identity[name], 'frozen fixture artifact changed: ' + name)
    return payloads['input.bin']


def run(out, rustc=None):
    record, rows, inputs, expected = frozen()
    require(compare(expected, rows) == ([], []), 'frozen literal/wire mismatch')
    require(not out.exists(), 'choose a fresh output directory')
    out.mkdir(parents=True)
    snapshot = out / 'source-snapshot'
    snapshot.mkdir()
    for name, path in S.source_files().items():
        require(path.is_file() and not path.is_symlink(), 'source missing/symlink')
        destination = snapshot / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes())
    source_manifest = S.manifest(snapshot)
    S.check_live(source_manifest)
    identity = {'input.bin': sha(inputs), 'expected.bin': sha(expected)}
    (out / 'input.bin').write_bytes(inputs)
    (out / 'expected.bin').write_bytes(expected)
    harness_files = {str(p.relative_to(HERE)): sha(p.read_bytes()) for p in (HERE / 'verify_rust.py', HERE / 'source_snapshot.py')}
    base = dict(frozen_wire_sha256=FREEZE_SHA, fixture_identity=identity, source_manifest=source_manifest,
                harness_files=harness_files, j9_cases=5, conditional_front_cases=5,
                target_execution=False, instruction_evaluation=False)
    (out / 'preparation.json').write_text(render(base))
    if rustc is None:
        return base
    rustc = rustc.resolve()
    version = subprocess.check_output([str(rustc), '-vV'], text=True)
    require(version.startswith('rustc 1.94.1 '), 'official pinned compiler required')
    compiler_sha = sha(rustc.read_bytes())
    component, driver = snapshot / 'component', snapshot / 'driver/input_only_driver.rs'
    commands = []

    def command(label, argv, stdin=None):
        result = subprocess.run(list(map(str, argv)), input=stdin, capture_output=True)
        for kind in ('stdout', 'stderr'):
            (out / (label + '.' + kind)).write_bytes(getattr(result, kind))
        commands.append(dict(label=label, argv=list(map(str, argv)), exit_code=result.returncode,
                             stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr)))
        require(result.returncode == 0, 'command failed: ' + label)
        return result.stdout

    builds = []
    for opt in (0, 3):
        flags = ['--edition=2024', '-D', 'warnings', '-C', f'opt-level={opt}', '-C', 'overflow-checks=yes']
        for repeat in (0, 1):
            prefix = f'o{opt}-r{repeat}'
            S.check_snapshot(snapshot, source_manifest)
            library, client = out / ('libnode94_orderbook-' + prefix + '.rlib'), out / (prefix + '-client')
            command(prefix + '-library', [rustc, '--crate-name', 'node94_orderbook', '--crate-type=rlib', component / 'src/lib.rs', '-o', library, *flags])
            command(prefix + '-client-build', [rustc, driver, '--extern', 'node94_orderbook=' + str(library), '-o', client, *flags])
            output = command(prefix + '-client-run', [client], checked_input(out, identity))
            require(compare(output, rows) == ([], []), 'production scratch/output/observation mismatch')
            builds.append(dict(profile=prefix, library_sha256=sha(library.read_bytes()), client_sha256=sha(client.read_bytes()), output_sha256=sha(output), value_mismatches=0, observation_mismatches=0))
        unit = out / f'o{opt}-unit-tests'
        command(f'o{opt}-unit-build', [rustc, '--test', component / 'src/lib.rs', '-o', unit, *flags])
        command(f'o{opt}-unit-run', [unit])
    mutants = []
    for name, source in variants((component / 'src/j9_first_front.rs').read_text()).items():
        S.check_snapshot(snapshot, source_manifest)
        directory = out / ('mutant-' + name)
        shutil.copytree(component, directory)
        (directory / 'src/j9_first_front.rs').write_text(source)
        mutant_manifest = S.manifest(directory)
        library, client = out / ('libnode94_orderbook-' + name + '.rlib'), out / (name + '-client')
        flags = ['--edition=2024', '-C', 'opt-level=3', '-C', 'overflow-checks=yes']
        command(name + '-library', [rustc, '--crate-name', 'node94_orderbook', '--crate-type=rlib', directory / 'src/lib.rs', '-o', library, *flags])
        command(name + '-client-build', [rustc, driver, '--extern', 'node94_orderbook=' + str(library), '-o', client, *flags])
        output = command(name + '-client-run', [client], checked_input(out, identity))
        values, observations = compare(output, rows)
        if name == 'front-equality-chooses-right':
            require(not values and bool(observations) and all(r['kind'] == 1 for r in observations), 'side-only control denominator')
        elif name.startswith('j9-'):
            require(bool(values) and all(r['kind'] == 0 and r['changed_scratch_indices'] and r['expected_A0'] == r['actual_A0'] for r in values), 'j9 scratch-value denominator')
        else:
            require(bool(values) and all(r['kind'] == 1 and not r['changed_scratch_indices'] and r['expected_A0'] != r['actual_A0'] for r in values), 'front output-word denominator')
        S.check_snapshot(directory, mutant_manifest)
        mutants.append(dict(name=name, value_mismatches=len(values), observation_only_mismatches=len(observations), first_value_counterexample=values[0] if values else None, first_observation_counterexample=observations[0] if observations else None, source_manifest=mutant_manifest))
    S.check_snapshot(snapshot, source_manifest)
    S.check_live(source_manifest)
    checked_input(out, identity)
    frozen()
    require(sha(rustc.read_bytes()) == compiler_sha, 'compiler executable changed')
    require(all(sha((HERE / name).read_bytes()) == digest for name, digest in harness_files.items()), 'running harness source changed')
    result = dict(base, compiler_version=version, compiler_sha256=compiler_sha, builds=builds, mutants=mutants,
                  commands=commands, limits='Two separate local value projections compared to pre-source static expectations; no target runtime, original ABI, physical store trace, seed/right/global sort or whole merge.')
    (out / 'build-report.json').write_text(render(result))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rustc', type=Path)
    args = parser.parse_args()
    result = run(args.out.resolve(), args.rustc)
    print('PASS: four ten-record builds,12 value mutants and one separately labeled side-only control' if args.rustc else 'Prepared frozen wire only; no Rust run')
