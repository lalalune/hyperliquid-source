#!/usr/bin/env python3
"""Compare independent Rust with pre-source native-derived local state vectors."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT = ROOT / 'src/node94-orderbook'
MODULE = COMPONENT / 'src/first_left_insertion.rs'
FREEZE_SHA = 'd6c3e42b061125f42a420b3b3e08e94bd896f4eae020e2b355f752282cbe50e4'
PLAN_SHA = '33dfd94bf2b10691b5d921ce4bb76b5b27393eece0538495dcc63fcf30f4ca0b'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def render(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def cases():
    raw = (HERE / 'frozen-states.json').read_bytes()
    require(sha(raw) == FREEZE_SHA, 'pre-source state freeze changed')
    plan = (HERE / 'PRE-SOURCE-PLAN.json').read_bytes()
    require(sha(plan) == PLAN_SHA, 'pre-source Rust control plan changed')
    frozen = json.loads(raw)
    rows = frozen['vectors']
    require(len(rows) == 18 and len({r['name'] for r in rows}) == 18, 'state denominator changed')
    for row in rows:
        require(len(row['prefix']) == 8 and len(row['expected_first9']) == 9, 'state width')
        require(0 <= row['insertion_index'] <= 8, 'state index')
        require(all(0 <= x < 2**64 for x in row['prefix'] + row['expected_first9'] + [row['x']]), 'qword domain')
    return rows, frozen['scratch_slot8_before']


def protocol(rows, old_slot, expected=False):
    raw = bytearray(b'I8OUT001' if expected else b'I8IN0001')
    raw += struct.pack('<I', len(rows))
    for index, row in enumerate(rows):
        if expected:
            raw += struct.pack('<II9Q', index, row['insertion_index'], *row['expected_first9'])
        else:
            raw += struct.pack('<IQ9Q', index, row['x'], *row['prefix'], old_slot)
    return bytes(raw)


def compare(raw, rows):
    require(raw[:8] == b'I8OUT001' and len(raw) == 12 + 80 * len(rows), 'output frame/length')
    require(struct.unpack_from('<I', raw, 8)[0] == len(rows), 'output count')
    arrays, indices = [], []
    for index, row in enumerate(rows):
        got_id, got_index, *words = struct.unpack_from('<II9Q', raw, 12 + 80 * index)
        require(got_id == index, 'output ID/order')
        record = dict(name=row['name'], expected_index=row['insertion_index'], actual_index=got_index,
                      expected_words=row['expected_first9'], actual_words=words)
        if words != row['expected_first9']:
            arrays.append(record)
        elif got_index != row['insertion_index']:
            indices.append(record)
    return arrays, indices


def source_files():
    raw = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z', '--', 'src/node94-orderbook'])
    paths = {ROOT / name for name in raw.decode().split('\0') if name}
    paths.add(MODULE)
    result = {'component/' + str(p.relative_to(COMPONENT)): p for p in paths}
    result['driver/input_only_driver.rs'] = HERE / 'input_only_driver.rs'
    return result


def manifest(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        require(not path.is_symlink(), 'snapshot symlink')
        if path.is_file():
            raw = path.read_bytes()
            result[str(path.relative_to(directory))] = dict(bytes=len(raw), sha256=sha(raw))
    return result


def check_snapshot(directory, expected):
    require(manifest(directory) == expected, 'fixed source snapshot changed')


def check_live(expected):
    actual = {}
    for name, path in source_files().items():
        require(path.is_file() and not path.is_symlink(), 'live source missing/symlink')
        raw = path.read_bytes()
        actual[name] = dict(bytes=len(raw), sha256=sha(raw))
    require(actual == expected, 'live source differs from compiled snapshot')


def variants(source):
    replacements = {
        'signed-comparisons': ('value < words[destination - 1]', '(value as i64) < (words[destination - 1] as i64)'),
        'skip-first-predecessor': ('let mut destination = 8;', 'let mut destination = 7;'),
        'wrong-shift-value': ('words[destination] = words[destination - 1];', 'words[destination] = value;'),
        'omit-final-insert': ('        words[destination] = value;', '        // final insertion omitted'),
        'omit-initial-append': ('    words[8] = value;', '    // initial append omitted'),
        'stop-before-front': ('destination > 0', 'destination > 1'),
        'truncate-loaded-value': ('    words[8] = value;', '    let value = u64::from(value as u32);\n    words[8] = value;'),
        'shift-equal-predecessors': ('value < words[destination - 1]', 'value <= words[destination - 1]'),
    }
    result = {}
    for name, (before, after) in replacements.items():
        require(source.count(before) == 1, 'mutation anchor changed: ' + name)
        result[name] = source.replace(before, after)
    plan = json.loads((HERE / 'PRE-SOURCE-PLAN.json').read_text())
    require(set(result) == set(plan['value_mutants'] + plan['index_only_controls']), 'mutation denominator')
    return result


def checked_input(out, fixture):
    payloads = {}
    for name in ('input.bin', 'expected.bin'):
        path = out / name
        require(path.is_file() and not path.is_symlink(), 'fixture missing/symlink')
        payloads[name] = path.read_bytes()
        require(sha(payloads[name]) == fixture[name], 'fixture artifact changed: ' + name)
    return payloads['input.bin']


def run(out, rustc=None):
    rows, old_slot = cases()
    require(not out.exists(), 'choose a fresh output directory')
    out.mkdir(parents=True)
    snapshot = out / 'source-snapshot'
    snapshot.mkdir()
    for name, path in source_files().items():
        require(path.is_file() and not path.is_symlink(), 'source missing/symlink')
        destination = snapshot / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes())
    source_manifest = manifest(snapshot)
    check_live(source_manifest)
    fixture = {}
    for name, expected in [('input.bin', False), ('expected.bin', True)]:
        raw = protocol(rows, old_slot, expected)
        (out / name).write_bytes(raw)
        fixture[name] = sha(raw)
    require(compare((out / 'expected.bin').read_bytes(), rows) == ([], []), 'frozen output admission')
    base = dict(cases=18, native_count_admissions=12, frozen_states_sha256=FREEZE_SHA,
                plan_sha256=PLAN_SHA, fixture=fixture, source_manifest=source_manifest,
                target_execution=False, instruction_evaluation=False)
    (out / 'preparation.json').write_text(render(base))
    if rustc is None:
        return base
    rustc = rustc.resolve()
    version = subprocess.check_output([str(rustc), '-vV'], text=True)
    require(version.startswith('rustc 1.94.1 '), 'pinned compiler required')
    compiler_sha = sha(rustc.read_bytes())
    component = snapshot / 'component'
    driver = snapshot / 'driver/input_only_driver.rs'
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
            check_snapshot(snapshot, source_manifest)
            library = out / ('libnode94_orderbook-' + prefix + '.rlib')
            client = out / (prefix + '-client')
            command(prefix + '-library', [rustc, '--crate-name', 'node94_orderbook', '--crate-type=rlib', component / 'src/lib.rs', '-o', library, *flags])
            command(prefix + '-client-build', [rustc, driver, '--extern', 'node94_orderbook=' + str(library), '-o', client, *flags])
            output = command(prefix + '-client-run', [client], checked_input(out, fixture))
            require(compare(output, rows) == ([], []), 'compiled array/index mismatch')
            builds.append(dict(profile=prefix, library_sha256=sha(library.read_bytes()), client_sha256=sha(client.read_bytes()), output_sha256=sha(output), array_mismatches=0, index_mismatches=0))
        unit = out / f'o{opt}-unit-tests'
        command(f'o{opt}-unit-build', [rustc, '--test', component / 'src/lib.rs', '-o', unit, *flags])
        command(f'o{opt}-unit-run', [unit])
    mutants = []
    for name, source in variants((component / 'src/first_left_insertion.rs').read_text()).items():
        check_snapshot(snapshot, source_manifest)
        directory = out / ('mutant-' + name)
        shutil.copytree(component, directory)
        (directory / 'src/first_left_insertion.rs').write_text(source)
        mutant_manifest = manifest(directory)
        library = out / ('libnode94_orderbook-' + name + '.rlib')
        client = out / (name + '-client')
        flags = ['--edition=2024', '-C', 'opt-level=3', '-C', 'overflow-checks=yes']
        command(name + '-library', [rustc, '--crate-name', 'node94_orderbook', '--crate-type=rlib', directory / 'src/lib.rs', '-o', library, *flags])
        command(name + '-client-build', [rustc, driver, '--extern', 'node94_orderbook=' + str(library), '-o', client, *flags])
        output = command(name + '-client-run', [client], checked_input(out, fixture))
        arrays, indices = compare(output, rows)
        # The original pre-source index-only prediction for equality was
        # falsified by an already-frozen arbitrary-prefix case. Preserve that
        # plan and failed receipt; require the observed array witness here.
        require(bool(arrays), 'native array mutant has no value counterexample: ' + name)
        if name == 'shift-equal-predecessors':
            require(any(r['name'] == 'unsorted-last-equality-no-shift' for r in arrays)
                    and bool(indices), 'equality array/index partition changed')
        check_snapshot(directory, mutant_manifest)
        mutants.append(dict(name=name, domain='native-derived array values; matching-array/wrong-index observations counted separately', array_mismatches=len(arrays), index_only_mismatches=len(indices), first_array_counterexample=arrays[0] if arrays else None, first_index_counterexample=indices[0] if indices else None, source_manifest=mutant_manifest))
    check_snapshot(snapshot, source_manifest)
    check_live(source_manifest)
    checked_input(out, fixture)
    require(sha(rustc.read_bytes()) == compiler_sha, 'compiler changed')
    result = dict(base, compiler_version=version, compiler_sha256=compiler_sha,
                  builds=builds, mutants=mutants, commands=commands,
                  limits='Compiled local Rust compared with frozen static native expectations; no original ABI, physical store trace, seed/global sorting or target execution claim.')
    (out / 'build-report.json').write_text(render(result))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rustc', type=Path)
    args = parser.parse_args()
    result = run(args.out.resolve(), args.rustc)
    print('PASS: four compiled18-state comparisons; eight native-array mutants with separate index-only mismatch counts' if args.rustc else 'Prepared18 frozen states only; no Rust run')
