#!/usr/bin/env python3
"""Compare independent Rust with freshly evaluated, authenticated node94 bytes.

No captured executable is launched. Native disassemblers read an owned mode600
snapshot; Rust receives only the resulting data ledger. No packages are fetched.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import kind5_reader as k

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / 'src/node94-kind5-reader'
PACKET = ROOT / 'research/work-items/RE-005-kind5-reader-94'


def require(value, message):
    if not value:
        raise SystemExit(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/kind5-reader-rust')
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.exists(), 'output exists; preserve evidence and select another directory')
    cargo = shutil.which('cargo')
    require(cargo is not None, 'an existing Cargo toolchain is required; this command installs nothing')
    data = k.bv.TARGET.read_bytes()
    require(sha(data) == k.bv.SHA256, 'authenticated node94 required')
    with tempfile.TemporaryDirectory(prefix='kind5-rust-snapshot-') as tmp:
        snapshot = Path(tmp) / 'input.elf'
        snapshot.write_bytes(data)
        snapshot.chmod(0o600)
        report, ledger, native = k.collect(data, snapshot)
    require(ledger == gzip.decompress((PACKET / 'cases.tsv.gz').read_bytes()),
            'fresh instruction outcomes differ from retained packet')
    require(report == json.loads((PACKET / 'reader.json').read_text()),
            'fresh static record differs from retained packet')
    output.mkdir(parents=True)
    (output / 'vectors.tsv').write_bytes(ledger)
    (output / 'static-report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    for name, text in zip(['static-gnu.txt', 'static-llvm.txt'], native):
        (output / name).write_text(text)

    env = dict(os.environ)
    env['NODE94_KIND5_VECTORS'] = str(output / 'vectors.tsv')
    # The two clean builds have the same source and explicit path mapping.
    env['RUSTFLAGS'] = f'--remap-path-prefix={ROOT}=/workspace/hyperliquid-source'
    commands = []

    def run(label, argv, target, expect_failure=False):
        actual_env = env | {'CARGO_TARGET_DIR': str(target)}
        result = subprocess.run(argv, cwd=ROOT, env=actual_env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        text = result.stdout.replace(str(ROOT), '<repository>').replace(str(output), '<run-output>')
        (output / f'{label}.log').write_text(text)
        commands.append({'label': label, 'argv': [x.replace(str(ROOT), '<repository>') for x in argv],
                         'exit_code': result.returncode})
        if expect_failure:
            require(result.returncode == 101 and 'test result: FAILED' in result.stdout,
                    f'{label}: expected a compiled test failure; inspect its log')
        else:
            require(result.returncode == 0, f'{label}: failed; inspect its log')
        return result.stdout

    manifest = str(COMPONENT / 'Cargo.toml')
    target = output / 'target-tests'
    run('format', [cargo, 'fmt', '--manifest-path', manifest, '--', '--check'], target)
    run('clippy', [cargo, 'clippy', '--manifest-path', manifest, '--offline', '--locked',
                   '--all-targets', '--', '-D', 'warnings'], target)
    profiles = {}
    for name, flags in [('debug', []), ('release', ['--release'])]:
        text = run(f'{name}-tests', [cargo, 'test', '--manifest-path', manifest,
                   '--offline', '--locked', *flags, '--', '--include-ignored', '--nocapture'], target)
        require('Compared 28992 authenticated instruction fixtures' in text,
                f'{name}: complete target-grounded corpus did not run')
        require('7 passed; 0 failed; 0 ignored' in text, f'{name}: unexpected test denominator')
        profiles[name] = {'cases': report['fixture_count'], 'tests_passed': 7, 'ignored': 0}

    builds = []
    for name in ['a', 'b']:
        directory = output / f'target-build-{name}'
        run(f'release-build-{name}', [cargo, 'build', '--manifest-path', manifest,
                                    '--offline', '--locked', '--release'], directory)
        archive = directory / 'release/libhyperliquid_node94_kind5_reader.rlib'
        retained = output / 'build-archives' / f'{name}.rlib'
        retained.parent.mkdir(exist_ok=True)
        shutil.copy2(archive, retained)
        builds.append({'name': name, 'sha256': sha(retained.read_bytes()),
                       'bytes': retained.stat().st_size,
                       'retained_archive': f'build-archives/{name}.rlib'})
        shutil.rmtree(directory)
    require(builds[0]['sha256'] == builds[1]['sha256'], 'two clean release archives differ')

    controls = []
    mutations = [
        ('tag-consumption', 'self.position += 1;', 'self.position += 0;'),
        ('payload-width', '251 => 2,', '251 => 4,'),
        ('endian-direction', 'if endian == 0', 'if endian != 0'),
        ('fast-threshold', 'if self.remaining() > 8 {', 'if self.remaining() >= 8 {'),
        ('fixed-charge', 'state.charged.checked_add(8)', 'state.charged.checked_add(7)'),
        ('limit-store-order',
         'state.charged = next;\n            if next > state.limit {\n                return Outcome::Charge;\n            }',
         'if next > state.limit {\n                return Outcome::Charge;\n            }\n            state.charged = next;'),
        ('expected-kind', '[3, 5, if self', '[3, 6, if self'),
        ('invalid-255-code', 'if self == Self::Tag254 { 4 } else { 12 }', 'if self == Self::Tag254 { 4 } else { 4 }'),
        ('success-tag', '\n                    18\n', '\n                    19\n'),
    ]
    if args.controls:
        original = (COMPONENT / 'src/lib.rs').read_text()
        for name, before, after in mutations:
            require(original.count(before) == 1, f'{name}: mutation site is not unique')
            mutant = output / 'mutants' / name
            shutil.copytree(COMPONENT, mutant)
            (mutant / 'src/lib.rs').write_text(original.replace(before, after))
            local_manifest = str(mutant / 'Cargo.toml')
            local_target = output / 'target-mutants' / name
            run(f'mutation-{name}-compile', [cargo, 'test', '--manifest-path', local_manifest,
                                           '--offline', '--locked', '--no-run'], local_target)
            run(f'mutation-{name}', [cargo, 'test', '--manifest-path', local_manifest,
                                    '--offline', '--locked', '--', '--include-ignored'], local_target, True)
            controls.append({'name': name, 'compiled': True, 'test_exit_code': 101})
            # This newly created directory contains only disposable compiler
            # output; retain the mutant source, compile/test logs and result.
            shutil.rmtree(local_target)
    gnu, llvm = k.native_tools()
    versions = {name: subprocess.check_output(argv, text=True) for name, argv in [
        ('cargo', [cargo, '--version']), ('rustc', [env.get('RUSTC', 'rustc'), '-vV']),
        ('gnu', [gnu, '--version']), ('llvm', [llvm, '--version'])]}
    (output / 'toolchain.json').write_text(json.dumps(versions, indent=2, sort_keys=True) + '\n')
    result = {'target_sha256': k.bv.SHA256, 'target_fdes': report['fde_ranges'],
              'fixture_sha256': sha(ledger), 'fresh_ledger_matches_retained': True,
              'static_instructions': report['instruction_count'], 'static_bytes': report['instruction_bytes'],
              'fixture_count': report['fixture_count'], 'output_bytes_per_fixture': 24,
              'state_bytes_per_fixture': 40, 'profiles': profiles, 'rust_source_controls': controls,
              'clean_release_builds': builds, 'raw_archive_equal': True,
              'commands': commands, 'captured_execution': False, 'gate_requested': False,
              'limits': ['new Rust interface, not target ABI or recovered kind5 source type',
                         'finite static instruction fixtures, not captured runtime equivalence',
                         'macOS arm64 component builds, not target Linux builds',
                         'fixture pointer base and sentinel padding exist only in the test adapter']}
    (output / 'comparison.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    shutil.rmtree(target)
    print(json.dumps({key: result[key] for key in ['fixture_count', 'profiles', 'raw_archive_equal']}))
    print(f'Compiled Rust source controls rejected: {len(controls)}')


if __name__ == '__main__':
    main()
