#!/usr/bin/env python3
"""Build only authored Rust in the fixed component overlay; never execute node94."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from compare_selector import authenticate, files, mismatches, need, sha


def render(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def run_all(snapshot, digest, out, rustc, cargo):
    frozen = authenticate(snapshot, digest)
    need(not out.exists(), 'choose a fresh build-output directory')
    out.mkdir(parents=True)
    rustc = rustc.resolve()
    cargo = cargo.resolve()
    version = subprocess.check_output([str(rustc), '-vV'], text=True)
    need(version.startswith('rustc 1.94.1 '), 'required compiler version unavailable')
    compiler_sha = sha(rustc.read_bytes())
    cargo_sha = sha(cargo.read_bytes())
    cargo_version = subprocess.check_output([str(cargo), '-V'], text=True)
    rustdoc = rustc.with_name('rustdoc')
    need(rustdoc.is_file(), 'approved toolchain rustdoc is missing')
    rustdoc_sha = sha(rustdoc.read_bytes())
    rustdoc_version = subprocess.check_output([str(rustdoc), '-V'], text=True)
    logs = []

    def run(label, argv, payload=None, *, expected_exit=0, environment=None):
        command = list(map(str, argv))
        result = subprocess.run(command, input=payload, capture_output=True, env=environment, timeout=120)
        (out/(label+'.stdout')).write_bytes(result.stdout)
        (out/(label+'.stderr')).write_bytes(result.stderr)
        logs.append(dict(label=label, argv=command, exit_code=result.returncode,
                         stdin_sha256=None if payload is None else sha(payload),
                         explicit_environment={} if environment is None else {key:environment[key] for key in ('RUSTC','RUSTDOC','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','RUST_TEST_THREADS')},
                         stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr)))
        (out/'commands.json').write_text(render(logs))
        need(result.returncode == expected_exit, 'unexpected command exit: ' + label)
        return result.stdout

    component = snapshot/'repo/src/node94-margin-risk'
    driver = snapshot/'driver/input_only.rs'
    builds = []
    for opt in (0, 3):
        for repeat in (0, 1):
            authenticate(snapshot, digest)
            prefix = f'o{opt}-r{repeat}'
            library = out/('libnode94_margin_risk-'+prefix+'.rlib')
            client = out/(prefix+'-driver')
            flags = ['--edition=2024', '-D', 'warnings', '-C', f'opt-level={opt}', '-C', 'overflow-checks=yes']
            run(prefix+'-library', [rustc, '--crate-name', 'node94_margin_risk', '--crate-type=rlib', component/'src/lib.rs', '-o', library, *flags])
            run(prefix+'-driver-build', [rustc, driver, '--extern', 'node94_margin_risk='+str(library), '-o', client, *flags])
            authenticate(snapshot, digest)
            payload = (snapshot/'input.bin').read_bytes()
            output = run(prefix+'-driver-run', [client], payload)
            expected = (snapshot/'expected.bin').read_bytes()
            need(not mismatches(output, expected), 'baseline compiled output mismatch: ' + prefix)
            builds.append(dict(profile=prefix, cases=frozen['total_comparison_cases'],
                               qualified_posthash_cases=frozen['qualified_posthash_cases'],
                               safe_api_cases=frozen['chosen_safe_api_cases'],
                               library_sha256=sha(library.read_bytes()), driver_sha256=sha(client.read_bytes()),
                               output_sha256=sha(output), mismatches=0))
        environment = os.environ.copy()
        environment['RUSTC'] = str(rustc)
        environment['RUSTDOC'] = str(rustdoc)
        environment['CARGO_HOME'] = str(out/'cargo-home')
        environment['CARGO_TARGET_DIR'] = str(out/f'cargo-o{opt}')
        environment['CARGO_BUILD_JOBS'] = '2'
        environment['RUST_TEST_THREADS'] = '2'
        command = [cargo, 'test', '--offline', '--locked', '--manifest-path', component/'Cargo.toml']
        if opt == 3:
            command.append('--release')
        run(f'o{opt}-component-tests', command, environment=environment)
    # Isolate each source mutant's one frozen admitted value counterexample.
    # No compile error, panic or timeout counts as a semantic value distinction.
    controls = []
    for plan in json.loads((snapshot/'mutants.json').read_text()):
        authenticate(snapshot, digest)
        name = plan['name']
        directory = out/('mutant-'+name)
        shutil.copytree(component, directory)
        (directory/'src/row_selector.rs').write_bytes((snapshot/'mutants'/name/'row_selector.rs').read_bytes())
        source_manifest = files(directory)
        library = out/('lib-mutant-'+name+'.rlib')
        client = out/('mutant-'+name+'-driver')
        run(name+'-library', [rustc, '--edition=2024', '--crate-name', 'node94_margin_risk', '--crate-type=rlib', directory/'src/lib.rs', '-C', 'opt-level=3', '-C', 'overflow-checks=yes', '-o', library])
        run(name+'-driver-build', [rustc, '--edition=2024', driver, '--extern', 'node94_margin_risk='+str(library), '-o', client])
        authenticate(snapshot, digest)
        payload = (snapshot/'mutants'/name/'input.bin').read_bytes()
        output = run(name+'-driver-run', [client], payload)
        expected = (snapshot/'mutants'/name/'expected.bin').read_bytes()
        differences = mismatches(output, expected)
        need(bool(differences), 'source mutant has no compiled value witness: ' + name)
        if plan['scope'] == 'qualified conditional posthash native value relation':
            need(output[16] < 2 and expected[16] < 2, 'native mutant witness became only an API refusal')
        else:
            need(output[16] == 2 and expected[16] == 2, 'safe-API mutant has wrong distinction domain')
        need(files(directory) == source_manifest, 'mutant compiler input changed')
        controls.append(dict(name=name, domain=plan['scope'], witness_name=plan['witness_name'],
                             witness_id=plan['witness_id'], output_sha256=sha(output),
                             source_manifest=source_manifest, value_mismatches=len(differences)))
    baseline_client = out/'o3-r1-driver'
    raw = (snapshot/'input.bin').read_bytes()
    malformed = {
        'bad-magic': b'BADIN001'+raw[8:],
        'truncated': raw[:-1],
        'trailing': raw+b'\0',
        'case-bound': raw[:8]+(4097).to_bytes(4, 'little')+raw[12:],
        'allocation-bound': b'R94SIN01'+(1).to_bytes(4, 'little')
            +(0).to_bytes(4, 'little')+(1).to_bytes(8, 'little')+(0).to_bytes(8, 'little')
            +(0).to_bytes(4, 'little')+(257).to_bytes(4, 'little')+(0).to_bytes(4, 'little')+bytes(20),
    }
    for name, payload in malformed.items():
        output = run('framing-'+name, [baseline_client], payload, expected_exit=2)
        need(not output, 'malformed driver input emitted partial output')
    authenticate(snapshot, digest)
    need(sha(rustc.read_bytes()) == compiler_sha and sha(cargo.read_bytes()) == cargo_sha
         and sha(rustdoc.read_bytes()) == rustdoc_sha,
         'compiler/Cargo executable changed')
    report = dict(status='observed authored Rust value comparisons in ignored fixed component overlay',
                  freeze_sha256=digest, compiler=dict(path=str(rustc), version=version, sha256=compiler_sha),
                  cargo=dict(path=str(cargo), version=cargo_version, sha256=cargo_sha),
                  rustdoc=dict(path=str(rustdoc), version=rustdoc_version, sha256=rustdoc_sha),
                  frozen=frozen, builds=builds,
                  native_relation_source_mutants=[c for c in controls if c['domain'].startswith('qualified')],
                  chosen_selector_safe_api_mutants=[c for c in controls if c['domain'].startswith('chosen')],
                  driver_framing_controls=list(malformed),
                  commands=logs, captured_node_execution=False,
                  limits='Conditional posthash bucket/default and late-state predicate only; no native hash/Once/row lifetime/ABI or physical memory-access equivalence claim.')
    (out/'REPORT.json').write_text(render(report))
    print(render(dict(cases=frozen['total_comparison_cases'], qualified_posthash_cases=frozen['qualified_posthash_cases'],
                      safe_api_cases=frozen['chosen_safe_api_cases'], successful_profiles=len(builds),
                      compiled_native_relation_mutants=10, safe_api_mutants=3,
                      driver_controls=len(malformed), report_sha256=sha((out/'REPORT.json').read_bytes()))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--freeze-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--cargo', type=Path, required=True)
    args = parser.parse_args()
    run_all(args.snapshot.resolve(), args.freeze_sha256, args.out.resolve(), args.rustc, args.cargo)
