#!/usr/bin/env python3
"""Compile only independently authored Rust; compare against frozen expectations."""
import argparse
import json
import os
import subprocess
from pathlib import Path

import corpus
import evidence as e

COMPONENT = e.ROOT / 'src/bincode-varint'
SOURCE = COMPONENT / 'src/lib.rs'
LINKER = Path('/usr/bin/cc')


def build(rustc, output, controls):
    rustc = Path(rustc).resolve(); output = Path(output).absolute()
    e.need(not output.exists(), 'preserve existing build output')
    fixtures = corpus.generate()
    freeze = json.loads((e.HERE / 'PRE-RUST-FREEZE.json').read_text())
    for name, data in fixtures.items():
        e.need(data == (e.HERE / name).read_bytes() and e.sha(data) == freeze['fixtureHashes'][name], 'frozen corpus changed')
    # Direct rustc never invokes Cargo hooks or configuration. Review/pin the
    # real component rather than inventing a replacement manifest/workspace.
    e.need(not (COMPONENT / 'build.rs').exists(), 'unexpected component build hook')
    manifest = (COMPONENT / 'Cargo.toml').read_text()
    e.need(manifest.split('[dependencies]', 1)[1].strip() == '' and 'publish = false' in manifest,
           'component build scope changed')
    version = subprocess.check_output([str(rustc), '-vV'], text=True)
    e.need(version.startswith('rustc 1.94.1 '), 'repository research compiler must be1.94.1')
    tracked = [SOURCE, rustc, LINKER, e.HERE / 'driver.rs', e.HERE / 'protocol.rs',
               COMPONENT / 'Cargo.toml', COMPONENT / 'Cargo.lock', *sorted((COMPONENT / 'tests').glob('*.rs'))]
    before = {str(p).replace(str(e.ROOT), '$REPO').replace(str(rustc), '$RUSTC'): e.sha(p.read_bytes()) for p in tracked}
    output.mkdir(parents=True)
    for name, data in fixtures.items():
        (output / name).write_bytes(data)
    commands = []
    def execute(label, argv, fail=False):
        result = subprocess.run(list(map(str, argv)), cwd=e.ROOT, capture_output=True,
                                stdin=subprocess.DEVNULL, timeout=60)
        for suffix, raw in [('stdout', result.stdout), ('stderr', result.stderr)]:
            (output / (label + '.' + suffix)).write_bytes(raw)
        commands.append({'label': label, 'exit': result.returncode,
                         'argv': [str(a).replace(str(output), '$OUTPUT').replace(str(e.ROOT), '$REPO')
                                  .replace(str(rustc), '$RUSTC').replace(str(LINKER), '$LINKER') for a in argv],
                         'stdoutSha256': e.sha(result.stdout), 'stderrSha256': e.sha(result.stderr)})
        e.need(result.returncode != 0 if fail else result.returncode == 0, label + ' unexpected exit; inspect retained logs')
        return result.stdout
    def profile(name, source, opt):
        directory = output / name; directory.mkdir()
        library = directory / 'libhl_bincode_varint.rlib'
        flags = ['--edition=2024', '-D', 'warnings', '-C', f'opt-level={opt}',
                 '-C', 'overflow-checks=on', '-C', 'codegen-units=1', '-C', 'linker=' + str(LINKER),
                 '--remap-path-prefix', str(e.ROOT) + '=/reconstruction']
        execute(name + '-library', [rustc, '--crate-name', 'hl_bincode_varint', '--crate-type=rlib', source, '-o', library, *flags])
        driver = directory / 'driver'
        execute(name + '-driver', [rustc, e.HERE / 'driver.rs', '--extern', 'hl_bincode_varint=' + str(library), '-o', driver, *flags])
        actual = execute(name + '-run', [driver, output / 'inputs.tsv'])
        e.need(len(actual.splitlines()) == len(fixtures['expected.tsv'].splitlines()), 'production row count differs')
        mismatches = sum(a != b for a, b in zip(actual.splitlines(), fixtures['expected.tsv'].splitlines()))
        return {'name': name, 'optLevel': opt, 'mismatches': mismatches,
                'outputSha256': e.sha(actual), 'librarySha256': e.sha(library.read_bytes())}, directory, library, flags
    profiles = []
    for name, opt in [('debug', 0), ('optimized', 3)]:
        result, directory, library, flags = profile(name, SOURCE, opt)
        e.need(result['mismatches'] == 0, 'Rust disagrees with frozen target-grounded relation')
        for test in sorted((COMPONENT / 'tests').glob('*.rs')):
            binary = directory / test.stem
            execute(name + '-' + test.stem + '-build', [rustc, '--test', test, '--extern', 'hl_bincode_varint=' + str(library), '-o', binary, *flags])
            execute(name + '-' + test.stem + '-test', [binary])
        profiles.append(result)
    repeated, _, _, _ = profile('optimized-repeat', SOURCE, 3)
    e.need(repeated['librarySha256'] == profiles[1]['librarySha256'], 'own optimized build is not raw reproducible')
    mutants = []
    if controls:
        original = SOURCE.read_text()
        mutations = [
            ('rollback-limit-charge', 'self.charge = next;\n            if next > self.limit {\n                return Err(SliceError::LimitExceeded);\n            }',
             'if next > self.limit {\n                return Err(SliceError::LimitExceeded);\n            }\n            self.charge = next;'),
            ('always-reader', 'if self.input.len() > width as usize {', 'if false {'),
            ('inclusive-fast-threshold', 'if self.input.len() > width as usize {', 'if self.input.len() >= width as usize {'),
            ('charge-after-decode', 'self.claim(width)?;\n        self.read_value(width, expected)',
             'let result = self.read_value(width, expected);\n        self.claim(width)?;\n        result'),
        ]
        for name, old, replacement in mutations:
            e.need(original.count(old) == 1, 'ambiguous mutation site: ' + name)
            source = output / (name + '.rs'); source.write_text(original.replace(old, replacement))
            result, directory, library, flags = profile('mutant-' + name, source, 0)
            e.need(result['mismatches'] > 0, 'compiled behavioral mutant survived')
            test = directory / 'wrapper-tests'
            execute(name + '-assertions-build', [rustc, '--test', COMPONENT / 'tests/wrapper_vectors.rs',
                    '--extern', 'hl_bincode_varint=' + str(library), '-o', test, *flags])
            execute(name + '-assertions', [test], fail=True)
            mutants.append(result)
    after = {str(p).replace(str(e.ROOT), '$REPO').replace(str(rustc), '$RUSTC'): e.sha(p.read_bytes()) for p in tracked}
    e.need(before == after, 'source/compiler/linker changed during build')
    e.admit(e.TARGET.read_bytes())
    report = {'status': 'PASS', 'targetSha256': e.DIGEST, 'compiler': version,
              'linker': subprocess.check_output([str(LINKER), '--version'], text=True),
              'sdkroot': os.environ.get('SDKROOT'), 'casesPerProfile': len(fixtures['inputs.tsv'].splitlines()),
              'fixtureHashes': {k: e.sha(v) for k, v in fixtures.items()}, 'sourceHashes': before,
              'profiles': profiles, 'ownOptimizedRlibRawReproducible': True, 'compiledMutants': mutants,
              'commands': commands, 'capturedExecution': False, 'instructionEvaluation': False,
              'scope': 'Own host Rust values/state and caller composition adapter; no target Rust ABI, original compiler or machine-code identity claim.'}
    (output / 'RESULT.json').write_bytes(e.encoded(report))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    try:
        report = build(args.rustc, args.output, args.controls)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps({'status': report['status'], 'casesPerProfile': report['casesPerProfile'],
                      'compiledMutants': report['compiledMutants']}, indent=2))
