"""Guarded existing-component comparison to the immutable r20 pre-source wire.

Preparation invokes no compiler. Compilation requires the shared slot and the
fixed disk preflights; no captured target is executed/evaluated. The source
snapshot is the real predecessor component plus one module/export, never a
replacement Cargo workspace. Local dependency receipts exclude sysroot identity.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import re
import shutil
import struct
import subprocess
import zlib

HERE = Path(__file__).resolve().parent
PACKET = HERE
ROOT = HERE.parents[2]
COMPONENT = ROOT / 'src/node94-orderbook'
RUSTC = Path('/workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin/rustc')
COMPILER_SHA = 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'
FREEZE_SHA = '6e83dde660d28198ce140eae49b615cdae66c0ccec5e8be3fb9536d1eaabe65c'
PLAN_SHA = '883554ad4b75a73beedaa48f21dccf9c4d4a2daed4f1075de574d3eb6af532ac'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def render(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def source_files():
    names = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z', '--', 'src/node94-orderbook']).decode().split('\0')
    result = {'component/' + str((ROOT / name).relative_to(COMPONENT)): ROOT / name for name in names if name}
    result['component/src/n21_run20_tail1.rs'] = COMPONENT / 'src/n21_run20_tail1.rs'
    result['candidate/n21_run20_tail1.rs'] = COMPONENT / 'src/n21_run20_tail1.rs'
    result['driver/input_only_driver.rs'] = HERE / 'input_only_driver.rs'
    return result


def manifest(paths):
    result = {}
    for name, path in sorted(paths.items()):
        require(path.is_file() and not path.is_symlink(), 'ordinary input ' + name)
        raw = path.read_bytes()
        result[name] = dict(bytes=len(raw), sha256=sha(raw))
    return result


def tree(directory):
    return manifest({str(path.relative_to(directory)): path for path in directory.rglob('*') if path.is_file() or path.is_symlink()})


def wire(name):
    """Restore exact frozen synthetic bytes from their bounded text archive."""
    archive = json.loads((PACKET / 'RAW-COMPARISONS.json').read_text())
    entry = archive['members']['compiled/' + name]
    require(type(entry['bytes']) is int and 0 <= entry['bytes'] <= 2 * 1024 * 1024, 'wire bound')
    raw = base64.b64decode(entry['zlib_base64'], validate=True)
    decoder = zlib.decompressobj()
    payload = decoder.decompress(raw, entry['bytes'] + 1)
    require(len(payload) == entry['bytes'] and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, 'wire compressed boundary')
    require(sha(payload) == entry['sha256'], 'wire archive hash')
    return payload


def frozen():
    require(sha((PACKET / 'PRE-SOURCE-FREEZE.json').read_bytes()) == FREEZE_SHA, 'pre-source array identity')
    require(sha((PACKET / 'PRE-SOURCE-RUST-PLAN-v2.json').read_bytes()) == PLAN_SHA, 'corrected pre-source plan')
    freeze = json.loads((PACKET / 'PRE-SOURCE-FREEZE.json').read_text())
    plan = json.loads((PACKET / 'PRE-SOURCE-RUST-PLAN-v2.json').read_text())
    rows = [dict(row, native_domain=True) for row in freeze['cases']] + [dict(row, native_domain=False) for row in freeze['exclusions_cases']]
    stimulus, expected = wire('input.bin'), wire('expected.bin')
    require(len(rows) == 54 and len(stimulus) == plan['input_bytes'] == 11028 and len(expected) == plan['expected_bytes'] == 101964, '48native+6policy wire denominator')
    require(sha(stimulus) == plan['input_sha256'] == 'e351101b430808fe44e51a164e3837cf16e0c58e22e0fc63cf501b818d747433', 'input hash')
    require(sha(expected) == plan['expected_sha256'] == 'e44064ab0b2e5d2e00cf8f62d3ba990c6c220311c28e15c5b4cbadee913c90e5', 'expected hash')
    require(stimulus[:8] == b'R20IN001' and expected[:8] == b'R20OUT01', 'wire tags')
    for i, row in enumerate(rows):
        rid, status = struct.unpack_from('<II', expected, 12 + i * 1888)
        require(rid == i and status == (0 if row['native_domain'] else 1), 'frozen policy separation')
    return rows, plan, stimulus, expected


def variants(source, plan):
    edits = {
        'omit-prefix-reversal': [('    if descending_normalized {\n        words[..20].reverse();', '    if descending_normalized && false {\n        words[..20].reverse();')],
        'reverse18-not20': [('words[..20].reverse();', 'words[..18].reverse();')],
        'copy-left-not-tail': [('let tail = words[20];', 'let tail = words[0];')],
        'merge-signed-compare': [
            ('let loaded_bits_provider = if tail > previous {', 'let loaded_bits_provider = if (tail as i64) > (previous as i64) {'),
            ('let output = if tail > previous {', 'let output = if (tail as i64) > (previous as i64) {'),
            ('let take_tail = tail >= previous;', 'let take_tail = (tail as i64) >= (previous as i64);')],
        'choose-min-at-back': [('let output = if tail > previous {', 'let output = if tail < previous {')],
        'truncate-tail32': [('let tail = words[20];', 'let tail = u64::from(words[20] as u32);')],
        'omit-left-empty-terminal-copy': [('    if tail_live {\n        words[left] = scratch[0];', '    if tail_live && false {\n        words[left] = scratch[0];')],
        'tie-loaded-bits-tail': [('let loaded_bits_provider = if tail > previous {', 'let loaded_bits_provider = if tail >= previous {')],
        'retire-left-on-tie': [('let take_tail = tail >= previous;', 'let take_tail = tail > previous;')],
        'omit-zero-copy-observation': [('copy_call_count: 2,', 'copy_call_count: if tail_live { 2 } else { 1 },')],
    }
    require(set(edits) == {row['name'] for row in plan['source_controls']}, 'ten preplanned v2 source controls')
    result = {}
    for name, replacements in edits.items():
        changed = source
        for before, after in replacements:
            require(changed.count(before) == 1, 'single source anchor ' + name)
            changed = changed.replace(before, after)
        result[name] = changed
    return result


def compare(raw, expected, rows):
    require(len(raw) == len(expected) and raw[:12] == expected[:12], 'output framing')
    changed = []
    for i, row in enumerate(rows):
        at = 12 + i * 1888
        rid, status = struct.unpack_from('<II', raw, at)
        want_id, want_status = struct.unpack_from('<II', expected, at)
        require(rid == want_id == i, 'output ID/order')
        words, wanted = struct.unpack_from('<235Q', raw, at + 8), struct.unpack_from('<235Q', expected, at + 8)
        diff = [j for j, pair in enumerate(zip(words, wanted)) if pair[0] != pair[1]]
        if diff or status != want_status:
            changed.append(dict(name=row['name'], native_domain=row['native_domain'], status_changed=status != want_status,
                                final_array_indices=[j for j in diff if j < 25],
                                normalization_indices=[j - 25 for j in diff if 25 <= j < 46],
                                observation_indices=[j - 46 for j in diff if j >= 46]))
    return changed


def run(out, compile_now, rustc, resume=False):
    require(out.exists() if resume else not out.exists(), 'existing resume or fresh output required')
    rows, plan, stimulus, expected = frozen()
    inputs = source_files()
    origin = manifest(inputs)
    snapshot = out / 'source-snapshot'
    component = snapshot / 'component'
    retained, stop = {}, None
    if resume:
        old = json.loads((out / 'preparation.json').read_text())
        stop = json.loads((PACKET / 'GUARD-STOP.json').read_text())
        require(origin == old['conservative_origin_manifest'], 'resume live origin identity')
        require(tree(snapshot) == old['conservative_compiler_manifest'], 'resume snapshot identity')
        require(sha((out / 'executed-harness-before-stop.py').read_bytes()) == old['harness_sha256'] == stop['executed_harness_sha256'], 'executed pre-stop harness identity')
        require(sha((out / 'commands.json').read_bytes()) == stop['commands_receipt_sha256'], 'original command receipt')
        previous = json.loads((out / 'commands.json').read_text())
        require([item['label'] for item in previous] == ['rustc-version', 'o0-r0-library'], 'exact two-command resume boundary')
        for item in previous:
            require(item['exit_code'] == 0, 'retained command failure')
            for channel in ['stdout', 'stderr']:
                raw = (out / (item['label'] + '.' + channel)).read_bytes()
                require(sha(raw) == item[channel + '_sha256'], 'retained raw channel identity')
                if channel == 'stderr':
                    require(not raw, 'retained command stderr')
            retained[item['label']] = item
        require(sha((out / 'libnode94_orderbook.rlib').read_bytes()) == stop['retained_library']['sha256'], 'retained opt0 library')
        require(sha((out / 'o0-r0-library.d').read_bytes()) == stop['dependency_receipt']['sha256'], 'retained local dependency file')
    else:
        out.mkdir(parents=True)
        for name, path in inputs.items():
            dest = snapshot / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(path.read_bytes())
        require(tree(snapshot) == origin and manifest(source_files()) == origin, 'origin source snapshot')
        lib = component / 'src/lib.rs'
        source = lib.read_text()
        require(source.count('pub mod n21_run20_tail1;') == 1, 'current integrated export')
        require((snapshot / 'candidate/n21_run20_tail1.rs').read_bytes() == (component / 'src/n21_run20_tail1.rs').read_bytes(), 'candidate alias identity')
    compiler_manifest = tree(snapshot)
    mutant_sources = variants((component / 'src/n21_run20_tail1.rs').read_text(), plan)
    for name, raw in [('input.bin', stimulus), ('expected.bin', expected)]:
        if resume:
            require((out / name).read_bytes() == raw, 'retained wire bytes')
        else:
            (out / name).write_bytes(raw)
    identity = {'input.bin': sha(stimulus), 'expected.bin': sha(expected)}
    report = dict(status='prepared, no compiler invoked', conservative_origin_manifest=origin,
                  conservative_compiler_manifest=compiler_manifest, fixture_identity=identity,
                  frozen_sha256=FREEZE_SHA, corrected_plan_sha256=PLAN_SHA,
                  harness_sha256=sha(Path(__file__).read_bytes()), native_cases=48, api_policy_cases=6,
                  preplanned_variant_sha256={name: sha(raw.encode()) for name, raw in mutant_sources.items()},
                  snapshot_edit='Current integrated component, no export change; historical executed snapshots are recorded separately.',
                  disk_guard=dict(floor_mib=300, build_transient_mib=32, run_transient_mib=2),
                  captured_execution=False, instruction_evaluation=False,
                  limits='Value correspondence conditional on external memcpy/disjointness/normal-return premises; no element identity/stability, physical trace, original ABI, generic count, provider/sysroot or full component gate claim.')
    if resume:
        require(report['preplanned_variant_sha256'] == old['preplanned_variant_sha256'], 'all retained source-control variants identical')
        report['resume_qualification'] = dict(retained_commands=2, stop_record_sha256=sha((PACKET / 'GUARD-STOP.json').read_bytes()),
                                            original_preparation_sha256=sha((out / 'preparation.json').read_bytes()),
                                            original_harness_sha256=old['harness_sha256'], resume_harness_sha256=report['harness_sha256'],
                                            compiler_start_limit=stop['compiler_start_qualification'],
                                            limits='Original47-slot sequence will contain2 actual retained pre-stop commands and45 actual resumed commands; no completed compiler/library step is rerun.')
    preparation = out / ('resume-preparation.json' if resume else 'preparation.json')
    payload = render(report)
    require(not preparation.exists() or preparation.read_text() == payload, 'preparation changed')
    preparation.write_text(payload)
    if not compile_now:
        print('PREPARED18-file real-component candidate;48native+6policy literal wires and10 source variants; no compiler invoked')
        return
    active_mutant = None
    def check():
        require(tree(snapshot) == compiler_manifest, 'fixed compiler snapshot drift')
        require(manifest(source_files()) == origin, 'live origin source drift')
        require(sha(Path(__file__).read_bytes()) == report['harness_sha256'], 'harness drift')
        for name, digest in identity.items():
            require(sha((out / name).read_bytes()) == digest, 'wire drift')
        if active_mutant is not None:
            require(tree(active_mutant[0]) == active_mutant[1], 'active mutant snapshot drift')
    commands = []
    def command(label, argv, build=False, stdin=None):
        check()
        if label in retained:
            original = retained.pop(label)
            require(list(map(str, argv)) == original['argv'] and stdin is None, 'retained command exact argv')
            if label == 'o0-r0-library':
                require(sha((out / 'libnode94_orderbook.rlib').read_bytes()) == stop['retained_library']['sha256'], 'retained library before client link')
            commands.append(dict(original, execution_phase='actual pre-stop command, reused without execution'))
            (out / 'resumed-commands.json').write_text(render(commands))
            return (out / (label + '.stdout')).read_bytes()
        before = shutil.disk_usage(out).free
        require(before >= (300 + (32 if build else 2)) * 1024 * 1024, 'disk preflight stopped before ' + label)
        child = subprocess.run(list(map(str, argv)), input=stdin, capture_output=True)
        for channel in ['stdout', 'stderr']:
            (out / (label + '.' + channel)).write_bytes(getattr(child, channel))
        after = shutil.disk_usage(out).free
        commands.append(dict(label=label, argv=list(map(str, argv)), exit_code=child.returncode,
                             execution_phase='actual resumed command' if resume else 'actual initial command',
                             free_bytes_before=before, free_bytes_after=after,
                             stdout_sha256=sha(child.stdout), stderr_sha256=sha(child.stderr)))
        (out / ('resumed-commands.json' if resume else 'commands.json')).write_text(render(commands))
        require(child.returncode == 0 and not child.stderr, 'command exit/stderr ' + label)
        require(after >= 300 * 1024 * 1024, 'postcommand disk floor ' + label)
        check()
        return child.stdout
    require(sha(rustc.read_bytes()) == COMPILER_SHA, 'official pinned compiler digest')
    report['rustc_vV'] = command('rustc-version', [rustc, '-vV']).decode()
    require(report['rustc_vV'].startswith('rustc 1.94.1 '), 'pinned compiler version')
    report['rustc_sha256'] = COMPILER_SHA
    report['toolchain_provenance_sha256'] = sha((HERE / 'toolchain-provenance.json').read_bytes())
    flags = ['--edition=2024', '-D', 'warnings', '-C', 'overflow-checks=yes']
    library, client, unit = out / 'libnode94_orderbook.rlib', out / 'client', out / 'unit'
    driver = snapshot / 'driver/input_only_driver.rs'
    dependencies, artifacts = [], []
    def dependency(label, dep, directory, unit_mode=False, driver_mode=False):
        raw = dep.read_bytes()
        seen = {str(Path(name).resolve()) for name in re.findall(r'[^\s:]+\.rs', raw.decode())}
        if driver_mode:
            wanted = {str(driver)}
        else:
            wanted = {str(path) for path in (directory / 'src').glob('*.rs') if unit_mode or path.name != 'tests.rs'}
        require(seen == wanted, 'local Rust .d dependencies ' + label)
        dependencies.append(dict(label=label, bytes=len(raw), sha256=sha(raw), local_rust_sources=sorted(seen),
                                 limits='Observed localRust source dependencies only, not exhaustive compiler/sysroot input identity.'))
    def build_library(label, directory, opt, unit_mode=False):
        dest = unit if unit_mode else library
        dep = out / (label + '.d')
        argv = [rustc, directory / 'src/lib.rs', '--crate-name', 'node94_orderbook', '--test' if unit_mode else '--crate-type=rlib',
                '--emit=link=' + str(dest) + ',dep-info=' + str(dep), *flags, '-C', f'opt-level={opt}']
        command(label, argv, build=True)
        dependency(label, dep, directory, unit_mode=unit_mode)
    def build_client(label, opt):
        dep = out / (label + '.d')
        command(label, [rustc, driver, '--extern', 'node94_orderbook=' + str(library),
                        '--emit=link=' + str(client) + ',dep-info=' + str(dep), *flags, '-C', f'opt-level={opt}'], build=True)
        dependency(label, dep, component, driver_mode=True)
    def remove_completed(label, paths):
        item = dict(label=label, files=[])
        for path in paths:
            item['files'].append(dict(file=path.name, bytes=path.stat().st_size, sha256=sha(path.read_bytes())))
            path.unlink()
        artifacts.append(item)
    production = []
    for opt in [0, 3]:
        for repeat in [0, 1]:
            label = f'o{opt}-r{repeat}'
            build_library(label + '-library', component, opt)
            build_client(label + '-client-build', opt)
            raw = command(label + '-client-run', [client], stdin=(out / 'input.bin').read_bytes())
            require(raw == (out / 'expected.bin').read_bytes() and not compare(raw, expected, rows), 'literal production mismatch')
            production.append(dict(label=label, output_sha256=sha(raw)))
            remove_completed(label, [library, client])
        build_library(f'o{opt}-unit-build', component, opt, unit_mode=True)
        unit_raw = command(f'o{opt}-unit-run', [unit])
        require(b'test result: ok. 46 passed;' in unit_raw, 'complete46-unit denominator')
        remove_completed(f'o{opt}-unit', [unit])
    controls = []
    for name, source in mutant_sources.items():
        directory = out / ('mutant-' + name)
        shutil.copytree(component, directory)
        (directory / 'src/n21_run20_tail1.rs').write_text(source)
        current = tree(directory)
        active_mutant = (directory, current)
        build_library(name + '-library', directory, 3)
        build_client(name + '-client-build', 3)
        raw = command(name + '-client-run', [client], stdin=(out / 'input.bin').read_bytes())
        changes = compare(raw, expected, rows)
        prediction = next(item for item in plan['source_controls'] if item['name'] == name)
        witness = next((row for row in changes if row['name'] == prediction['witness']), None)
        require(witness is not None and witness['native_domain'], 'preplanned qualified witness ' + name)
        if prediction['planned_kind'] == 'array-values':
            require(witness['final_array_indices'], 'actual finalA/S array witness ' + name)
        else:
            require(all(not row['final_array_indices'] and not row['normalization_indices'] and not row['status_changed'] for row in changes), 'metadata-only classification ' + name)
            require(witness['observation_indices'], 'observation witness ' + name)
        require(all(row['native_domain'] for row in changes), 'safeAPI policy cases changed by native-domain control')
        controls.append(dict(name=name, planned_kind=prediction['planned_kind'], source_manifest=current,
                             output_sha256=sha(raw), differences=changes))
        remove_completed(name, [library, client])
        active_mutant = None
    check()
    require(not retained, 'retained boundary fully consumed')
    require(sha(rustc.read_bytes()) == COMPILER_SHA, 'final compiler digest')
    report.update(status='PASS qualified r20 relation', commands=commands, production=production,
                  controls=controls, local_dependency_receipts=dependencies,
                  removed_completed_binary_cache=artifacts, artifact_policy='Only self-built reproducible binaries removed after hashes/logs; source, wires, rawchannels, .d files and receipts retained.')
    (out / 'compiled-report.json').write_text(render(report))
    print('PASS four×(48native+6policy) literal235qword+status records;46units/profile;7array+3metadata controls; no captured execution')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--compile', action='store_true')
    parser.add_argument('--resume-existing', action='store_true')
    parser.add_argument('--rustc', type=Path, default=RUSTC)
    args = parser.parse_args()
    run(args.out.resolve(), args.compile, args.rustc.resolve(), args.resume_existing)
