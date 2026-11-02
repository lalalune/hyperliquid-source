"""Compile a fixed existing-component candidate against76 pre-source inputs.

The integrated reproduction snapshots the current component. The earlier46
executed commands used ddb3681f plus one module/export in a private snapshot;
its exact guard is retained in RAW-COMPARISONS.json. This adapted script did
not produce that historical receipt. Nothing invokes node94.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess

HERE = Path(__file__).resolve().parent
PACKET = HERE
ROOT = HERE.parents[2]
COMPONENT = ROOT / 'src/node94-orderbook'
PREFIX = Path('/workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin')
RUSTC = PREFIX / 'rustc'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def render(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def live_sources():
    names = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z', '--', 'src/node94-orderbook']).decode().split('\0')
    result = {'component/' + str((ROOT / name).relative_to(COMPONENT)): ROOT / name for name in names if name}
    result['component/src/n21_outer_admission.rs'] = COMPONENT / 'src/n21_outer_admission.rs'
    result['candidate/n21_outer_admission.rs'] = COMPONENT / 'src/n21_outer_admission.rs'
    result['driver/input_only_driver.rs'] = HERE / 'input_only_driver.rs'
    return result


def manifest(paths):
    result = {}
    for name, path in sorted(paths.items()):
        require(path.is_file() and not path.is_symlink(), 'ordinary compiler input ' + name)
        raw = path.read_bytes()
        result[name] = dict(bytes=len(raw), sha256=sha(raw))
    return result


def tree(directory):
    return manifest({str(path.relative_to(directory)): path for path in directory.rglob('*') if path.is_file() or path.is_symlink()})


def fixture():
    freezes = {'PRE-SOURCE-BOUNDARIES.json': 'c5840053ecfa7976768d2d861e344bf7b2f8f7e9fb441532226200863ab093f4',
               'PRE-SOURCE-RUST-PLAN.json': 'dc62b2f059e7b4b612e3711160eb77efae118b3973d2cce6385d3bd57650c1a4'}
    for name, digest in freezes.items():
        require(sha((PACKET / name).read_bytes()) == digest, 'pre-source freeze pin')
    native = json.loads((PACKET / 'PRE-SOURCE-BOUNDARIES.json').read_text())
    plan = json.loads((PACKET / 'PRE-SOURCE-RUST-PLAN.json').read_text())
    stimulus, expected = b'', b''
    for case, projection in zip(native['cases'], plan['cases']):
        require(case['name'] == projection['name'], 'input/output frozen ID')
        words = [int(value, 16) for value in case['a21']]
        stimulus += struct.pack('<22Q', *words, int(projection['opaque_context'], 16))
        e = projection['expected']
        expected += struct.pack('<27Q', *words, int(e['admitted']), e['natural_run'], int(e['ascending']), e['word_count'], e['scratch_capacity_qwords'], int(e['opaque_context'], 16))
    require(len(native['cases']) == len(plan['cases']) == 76 and len(stimulus) == 13376 and len(expected) == 16416, 'literal wire denominator')
    require(sha(stimulus) == '504ae6a3a479c7433a01123921b1604a393cc54181922a68465047c815ee5e27' and sha(expected) == '60bea63167fe7f994c6d6eaf34c6891d15d943c5c64efbfe5a88baa30ea4a2b0', 'precompiled wire hashes')
    return native['cases'], plan, stimulus, expected


def variants(source, plan):
    edits = {
        'initial-signed-direction': ('let ascending = words[1] >= words[0];', 'let ascending = (words[1] as i64) >= (words[0] as i64);'),
        'ascending-ties-stop': ('words[run] >= words[run - 1]', 'words[run] > words[run - 1]'),
        'descending-ties-continue': ('words[run] < words[run - 1]', 'words[run] <= words[run - 1]'),
        'include-r11': ('if run < 11 {', 'if run <= 11 {'),
        'threshold-ten': ('if run < 11 {', 'if run < 10 {'),
        'always-ascending': ('let ascending = words[1] >= words[0];', 'let ascending = true;'),
        'capacity-36': ('scratch_capacity_qwords: 512,', 'scratch_capacity_qwords: 36,'),
        'count-32': ('word_count: 21,', 'word_count: 32,'),
        'truncate-context': ('            opaque_context,', '            opaque_context: u64::from(opaque_context as u32),'),
        'omit-dispatch': ('if run < 11 {', 'if false {'),
    }
    require(set(edits) == {row['name'] for row in plan['controls']}, 'ten preplanned controls')
    result = {}
    for name, (before, after) in edits.items():
        require(source.count(before) == 1, 'single semantic anchor ' + name)
        result[name] = source.replace(before, after)
    return result


def run(out, compile_now):
    require(not out.exists(), 'fresh output required')
    cases, plan, stimulus, expected = fixture()
    inputs = live_sources()
    origin = manifest(inputs)
    out.mkdir(parents=True)
    snapshot = out / 'source-snapshot'
    for name, path in inputs.items():
        dest = snapshot / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(path.read_bytes())
    require(tree(snapshot) == origin and manifest(live_sources()) == origin, 'fixed origin snapshot')
    component = snapshot / 'component'
    lib = component / 'src/lib.rs'
    libraw = lib.read_text()
    require(libraw.count('pub mod n21_outer_admission;') == 1, 'current integrated export')
    require((snapshot / 'candidate/n21_outer_admission.rs').read_bytes() == (component / 'src/n21_outer_admission.rs').read_bytes(), 'module/source alias identity')
    compiler_manifest = tree(snapshot)
    variant_sources = variants((component / 'src/n21_outer_admission.rs').read_text(), plan)
    for name, payload in [('input.bin', stimulus), ('expected.bin', expected)]:
        (out / name).write_bytes(payload)
    wire = {'input.bin': sha(stimulus), 'expected.bin': sha(expected)}
    report = dict(status='prepared, not compiled', origin_manifest=origin, compiler_manifest=compiler_manifest,
                  candidate_base='ddb3681faf405ad005b835079ae41469c084136e',
                  export_edit='None: current integrated component already exports the module.',
                  harness_sha256=sha(Path(__file__).read_bytes()), fixture_identity=wire,
                  native_cases=76, admitted=56, excluded=20, controls=10,
                  planned_variant_sha256={name: sha(source.encode()) for name, source in variant_sources.items()},
                  captured_execution=False, instruction_evaluation=False,
                  limits='Conditional first-short-run admission/arguments only; no delegate effect, whole-sort, allocator freshness, actual stack pointer, original ABI or gate claim.')
    (out / 'preparation.json').write_text(render(report))
    if not compile_now:
        print('PREPARED: fixed source/wire snapshot; no compiler invoked')
        return
    active_mutant = None
    def check():
        require(tree(snapshot) == compiler_manifest, 'compiler snapshot changed')
        require(manifest(live_sources()) == origin, 'origin source drift')
        for name, digest in wire.items():
            require(sha((out / name).read_bytes()) == digest, 'client input/expected drift')
        require(sha(Path(__file__).read_bytes()) == report['harness_sha256'], 'harness drift')
        if active_mutant is not None:
            require(tree(active_mutant[0]) == active_mutant[1], 'active mutant source drift')
    def reserve():
        require(shutil.disk_usage(out).free >= 300 * 1024 * 1024 + 100 * 1024 * 1024, 'disk reserve below400MiB; no command started')
    require(sha(RUSTC.read_bytes()) == 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d', 'official pinned compiler digest')
    report['rustc_vV'] = subprocess.check_output([str(RUSTC), '-vV'], text=True)
    require(report['rustc_vV'].startswith('rustc 1.94.1 '), 'pinned compiler version')
    report['rustc_sha256'] = sha(RUSTC.read_bytes())
    report['toolchain_provenance_sha256'] = sha((HERE / 'toolchain-provenance.json').read_bytes())
    commands = []
    def command(label, argv, stdin=None, env=None):
        check()
        reserve()
        process = subprocess.run(list(map(str, argv)), input=stdin, capture_output=True, env=env)
        for kind in ['stdout', 'stderr']:
            (out / (label + '.' + kind)).write_bytes(getattr(process, kind))
        commands.append(dict(label=label, argv=list(map(str, argv)), exit_code=process.returncode,
                             stdout_sha256=sha(process.stdout), stderr_sha256=sha(process.stderr)))
        (out / 'commands.json').write_text(render(commands))
        require(process.returncode == 0 and not process.stderr, 'command exit/stderr ' + label)
        return process.stdout
    driver = snapshot / 'driver/input_only_driver.rs'
    flags = ['--edition=2024', '-D', 'warnings', '-C', 'overflow-checks=yes']
    artifact = out / 'libnode94_orderbook.rlib'
    client = out / 'client'
    outputs = []
    for opt in [0, 3]:
        for repeat in [0, 1]:
            label = f'o{opt}-r{repeat}'
            command(label + '-library', [RUSTC, '--crate-name', 'node94_orderbook', '--crate-type=rlib', component / 'src/lib.rs', '-o', artifact, *flags, '-C', f'opt-level={opt}'])
            command(label + '-client-build', [RUSTC, driver, '--extern', 'node94_orderbook=' + str(artifact), '-o', client, *flags, '-C', f'opt-level={opt}'])
            raw = command(label + '-client-run', [client], (out / 'input.bin').read_bytes())
            require(raw == (out / 'expected.bin').read_bytes(), 'production literal output mismatch')
            outputs.append(dict(label=label, client_sha256=sha(client.read_bytes()), library_sha256=sha(artifact.read_bytes()), output_sha256=sha(raw)))
        unit = out / 'unit'
        command(f'o{opt}-unit-build', [RUSTC, '--test', component / 'src/lib.rs', '-o', unit, *flags, '-C', f'opt-level={opt}'])
        command(f'o{opt}-unit-run', [unit])
        unit.unlink()
    controls = []
    for name, source in variant_sources.items():
        mutant = out / ('mutant-' + name)
        shutil.copytree(component, mutant)
        (mutant / 'src/n21_outer_admission.rs').write_text(source)
        mutant_manifest = tree(mutant)
        active_mutant = (mutant, mutant_manifest)
        command(name + '-library', [RUSTC, '--crate-name', 'node94_orderbook', '--crate-type=rlib', mutant / 'src/lib.rs', '-o', artifact, *flags, '-C', 'opt-level=3'])
        command(name + '-client-build', [RUSTC, driver, '--extern', 'node94_orderbook=' + str(artifact), '-o', client, *flags, '-C', 'opt-level=3'])
        raw = command(name + '-client-run', [client], (out / 'input.bin').read_bytes())
        require(tree(mutant) == mutant_manifest, 'mutant source drift')
        require(len(raw) == len(expected), 'mutant frame length')
        differences = []
        for index, case in enumerate(cases):
            actual = struct.unpack_from('<27Q', raw, index * 216)
            frozen = struct.unpack_from('<27Q', expected, index * 216)
            changed = [field for field, (a, b) in enumerate(zip(actual, frozen)) if a != b]
            if changed:
                differences.append(dict(name=case['name'], changed_word_indices=changed))
        prediction = next(item for item in plan['controls'] if item['name'] == name)
        require(any(item['name'] == prediction['witness'] for item in differences), 'preplanned witness missing ' + name)
        witness_index = next(index for index, case in enumerate(cases) if case['name'] == prediction['witness'])
        field = {'admission': 21, 'word_count': 24, 'scratch_capacity_qwords': 25, 'opaque_context': 26}[prediction['field']]
        def number(value):
            return int(value, 16) if isinstance(value, str) else int(value)
        require(struct.unpack_from('<27Q', expected, witness_index * 216)[field] == number(prediction['expected_original']), 'preplanned original field')
        require(struct.unpack_from('<27Q', raw, witness_index * 216)[field] == number(prediction['predicted_mutant']), 'preplanned mutant field ' + name)
        require(differences and all(all(index >= 21 for index in item['changed_word_indices']) for item in differences), 'routing-only mutant effects')
        controls.append(dict(name=name, source_manifest=mutant_manifest, output_sha256=sha(raw), differences=differences))
        active_mutant = None
    check()
    require(sha(RUSTC.read_bytes()) == report['rustc_sha256'], 'compiler drift')
    report.update(status='compiled conditional routing comparisons pass', commands=commands, production=outputs, controls=controls)
    (out / 'compiled-report.json').write_text(render(report))
    print('PASS: four×76 frozen routing records; ten operative admission/argument source controls; complete existing-component direct units opt0/3; no captured target execution')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--compile', action='store_true')
    parser.add_argument('--rustc', type=Path, default=RUSTC)
    args = parser.parse_args()
    RUSTC = args.rustc.resolve()
    run(args.out.resolve(), args.compile)
