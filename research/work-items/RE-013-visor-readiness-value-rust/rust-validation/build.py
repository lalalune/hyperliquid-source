#!/usr/bin/env python3
"""Build only the authored readiness-value component, offline and locked.

MIT orchestration adapted from RE-013-visor-key-hash-rust/rust-validation/
build.py SHA256 2f33cd34a38809e19e8105b86ee725e9cbbc3816a528d4a2c4115f09802ba80b.
No key-hash semantics, oracle, dependency or expected data is reused.
This script must not run until the later root source/build gate authorizes it.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib

HERE = Path(__file__).resolve().parent
PACKET = HERE.parent
ROOT = PACKET.parents[2]
SOURCE = ROOT / 'src/visor-readiness-value'
SOURCE_FILES = ['Cargo.lock', 'Cargo.toml', 'README.md', 'src/lib.rs', 'tests/value_contract.rs']
PRE_FREEZE = '4c6243e6b61e350f73ca05095e142d5c3512de6f7d5078da9022f47dae40ee45'
PRE_MANIFEST = '119e21ea7af7c7c90079f8d7a98df2159be5137865f4456081487c604e841d11'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha(raw)}


def inventory(path):
    return {p.relative_to(path).as_posix(): identity(p)
            for p in sorted(path.rglob('*')) if p.is_file()}


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')


def check_precode():
    freeze = json.loads((PACKET / 'PRE-RUST-FREEZE.json').read_text())
    require(freeze['source_exists'] is False, 'pre-code chronology source absence')
    require(len(freeze['files']) == 35, 'pre-code exact file count')
    for entry in freeze['files']:
        relative = Path(entry['path'])
        require(not relative.is_absolute() and '..' not in relative.parts, 'pre-code path')
        require(identity(PACKET / relative) == {'bytes': entry['bytes'], 'sha256': entry['sha256']},
                'changed pre-code file: ' + entry['path'])
    return len(freeze['files'])


def admit_sources(expected_source_freeze):
    require(identity(PACKET / 'PRE-RUST-FREEZE.json')['sha256'] == PRE_FREEZE, 'pre-code freeze identity')
    require(identity(PACKET / 'MANIFEST.json')['sha256'] == PRE_MANIFEST, 'pre-code manifest identity')
    require(check_precode() == 35, 'original pre-code entries')
    require(identity(HERE / 'SOURCE-FREEZE.json')['sha256'] == expected_source_freeze, 'source freeze identity')
    freeze = json.loads((HERE / 'SOURCE-FREEZE.json').read_text())
    require(not SOURCE.is_symlink() and not any(p.is_symlink() for p in SOURCE.rglob('*')), 'source symlink')
    require(sorted(inventory(SOURCE)) == SOURCE_FILES, 'unexpected source file/hook')
    require(inventory(SOURCE) == freeze['source'], 'actual source differs from freeze')
    for name, expected in freeze['harness'].items():
        require(not (HERE / name).is_symlink(), 'harness symlink')
        require(identity(HERE / name) == expected, 'harness differs from freeze: ' + name)
    manifest = tomllib.loads((SOURCE / 'Cargo.toml').read_text())
    lock = tomllib.loads((SOURCE / 'Cargo.lock').read_text())
    require(set(manifest) == {'package', 'lib', 'dependencies', 'profile'} and
            manifest['lib'] == {'path': 'src/lib.rs'} and
            manifest['dependencies'] == {} and 'workspace' not in manifest and
            'build' not in manifest['package'] and not (SOURCE / 'build.rs').exists(), 'dependency/hook admission')
    require(lock['package'] == [{'name': 'visor-readiness-value', 'version': '0.1.0'}], 'actual dependency-free lock')
    return freeze, manifest, lock


def compare(actual, expected):
    left, right = actual.splitlines(keepends=True), expected.splitlines(keepends=True)
    differences = [i for i in range(max(len(left), len(right)))
                   if (left[i] if i < len(left) else None) != (right[i] if i < len(right) else None)]
    return {'equal': actual == expected, 'actual_rows': len(left), 'expected_rows': len(right),
            'different_rows': len(differences), 'first_different_rows': differences[:12],
            'actual_sha256': sha(actual), 'expected_sha256': sha(expected)}


def comparator_controls(expected):
    rows = expected.splitlines(keepends=True)
    def replace(index, value):
        changed = rows.copy()
        changed[index] = value
        return b''.join(changed)
    changed_value = rows[0].split(b'\t')
    changed_value[2] = str(int(changed_value[2])+1).encode()
    values = {
        'missing-row': b''.join(rows[:-1]), 'extra-row': expected+rows[0],
        'reordered': b''.join([rows[1], rows[0], *rows[2:]]),
        'duplicate-id': replace(1, rows[0]),
        'changed-id': replace(0, b'ffffffff'+rows[0][8:]),
        'changed-value': replace(0, b'\t'.join(changed_value)),
        'wrong-kind': replace(0, b'00000000\tDOMAIN\n'),
        'missing-LF': expected[:-1], 'CRLF': expected.replace(b'\n', b'\r\n'), 'empty': b'',
    }
    require(compare(expected, expected)['equal'], 'positive comparator')
    result = {name: compare(value, expected) for name, value in values.items()}
    require(all(not row['equal'] for row in result.values()), 'missed comparator corruption')
    return result


def mutants(original):
    definitions = [
        ('epoch-plus-day', [(' / 86400 + 719528;', ' / 86400 + 719529;')]),
        ('cycle-length', [('days / 146097 * 400', 'days / 146096 * 400')]),
        ('sample-zero-refused', [('(0..=MAX_SAMPLE)', '(1..=MAX_SAMPLE)')]),
        ('sample-maximum-refused', [('MAX_SAMPLE: i64 = 8210266876799', 'MAX_SAMPLE: i64 = 8210266876798')]),
        ('century-exception-omitted', [('(year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)', '(year.rem_euclid(100) != 0 || year.rem_euclid(400) < 400)')]),
        ('400-year-exception-wrong', [('year.rem_euclid(400) == 0', 'year.rem_euclid(400) == 1')]),
        ('negative-residue', [('let residue = self.year.rem_euclid(400);', 'let residue = self.year % 400;')]),
        ('packed-stride', [('8192 * self.year', '4096 * self.year')]),
        ('zero-ordinal-admitted', [('ordinal == 0', 'ordinal == u16::MAX')]),
        ('minimum-year-refused', [('MIN_YEAR: i32 = -262143', 'MIN_YEAR: i32 = -262142')]),
        ('upper-year-admitted', [('MAX_YEAR: i32 = 262142', 'MAX_YEAR: i32 = 262143')]),
        ('extended-nano-admitted', [('            || nano >= 1000000000', '            || nano > 1000000000')]),
        ('sample-nano-truncated', [('nano as u32,', '(nano / 1000) as u32,')]),
        ('sample-second-modulus', [('(seconds % 86400) as u32', '(seconds % 86401) as u32')]),
        ('duration-59', [('result.second += 60;', 'result.second += 59;')]),
        ('carry-equality-missed', [('result.second >= 86400', 'result.second > 86400')]),
        ('day-not-advanced', [('result.ordinal += 1;', 'result.ordinal += 0;')]),
        ('year-not-advanced', [('result.year += 1;', 'result.year += 0;')]),
        ('fallback-nano-zero', [('nano: 999999999,', 'nano: 0,')]),
        ('nonstrict-comparison', [('current.raw_words() > source.deadline_60().raw_words()', 'current.raw_words() >= source.deadline_60().raw_words()')]),
        ('no-deadline-comparison', [('current.raw_words() > source.deadline_60().raw_words()', 'current.raw_words() > source.raw_words()')]),
        ('unsigned-date-comparison', [('    current.raw_words() > source.deadline_60().raw_words()', '    let a = current.raw_words();\n    let b = source.deadline_60().raw_words();\n    (a.0 as u32, a.1, a.2) > (b.0 as u32, b.1, b.2)')]),
    ]
    result = []
    for name, edits in definitions:
        changed = original
        for before, after in edits:
            require(changed.count(before) == 1, 'mutation coordinate: '+name)
            changed = changed.replace(before, after, 1)
        require(changed != original, 'unchanged mutation')
        result.append((name, changed, {'name': name, 'edits': edits, 'source_sha256': sha(changed.encode())}))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='fresh direct child of canonical /tmp')
    parser.add_argument('--private-map', type=Path, required=True, help='fresh path outside public packet')
    parser.add_argument('--source-freeze-sha', required=True)
    args = parser.parse_args()
    toolchain = args.toolchain.resolve()
    lexical_out = args.out.absolute()
    require(not lexical_out.is_symlink(), "build output symlink")
    out = lexical_out.resolve()
    private_map = args.private_map.resolve()
    require(out.parent == Path('/tmp').resolve() and not out.exists(), 'fresh canonical /tmp output required')
    require(not private_map.exists() and not private_map.is_relative_to(PACKET), 'private mapping path')
    freeze, manifest, lock = admit_sources(args.source_freeze_sha)
    original_source = (SOURCE / 'src/lib.rs').read_text()
    variations = mutants(original_source)
    pins = json.loads((HERE / 'TOOLCHAIN-PINS.json').read_text())
    tools_before = {directory + '/' + name: value for directory in ['bin', 'lib']
                    for name, value in inventory(toolchain / directory).items()}
    require(tools_before == pins['payload_files'], 'toolchain payload differs from pre-build pins')
    tool_links = {str(p.relative_to(toolchain)): os.readlink(p) for d in ['bin', 'lib'] for p in (toolchain / d).rglob('*') if p.is_symlink()}
    require(tool_links == pins['symlinks'], 'toolchain symlinks differ')
    out.mkdir(mode=0o700)
    receipts = out / 'receipts'
    (receipts / 'raw').mkdir(parents=True)
    cargo_home = out / 'cargo-home'
    cargo_home.mkdir()
    mapping = {'<BUILD>': str(out), '<TOOLCHAIN>': str(toolchain), '<SOURCE>': str(SOURCE), '<PACKET>': str(PACKET)}
    write_json(private_map, {'logical_to_private': mapping, 'canonical_build': str(out)})

    def logical(value):
        text = str(value)
        for name, physical in sorted(mapping.items(), key=lambda item: -len(item[1])):
            text = text.replace(physical, name)
        return text

    env_base = {'PATH': str(toolchain / 'bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
                'CARGO_HOME': str(cargo_home), 'RUSTC': str(toolchain / 'bin/rustc'),
                'RUSTDOC': str(toolchain / 'bin/rustdoc'), 'CARGO_NET_OFFLINE': 'true',
                'CARGO_INCREMENTAL': '0', 'CARGO_TERM_COLOR': 'never', 'LANG': 'C',
                'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1', 'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'}
    if 'HOME' in os.environ:
        env_base['HOME'] = os.environ['HOME']  # Preserve; never repurpose or inspect user credentials/config.
    config_checks = set()
    workspace_checks = {}

    def audit_ancestors(directory):
        for start in {directory.absolute(), directory.resolve()}:
            for ancestor in [start, *start.parents]:
                for name in ('config', 'config.toml'):
                    candidate = ancestor / '.cargo' / name
                    require(not candidate.exists() and not candidate.is_symlink(),
                            'unexpected lexical/canonical ancestor Cargo configuration')
                    config_checks.add(logical(candidate))
                cargo_manifest = ancestor / 'Cargo.toml'
                require(not cargo_manifest.is_symlink(), 'ancestor Cargo manifest symlink')
                if cargo_manifest.exists():
                    parsed = tomllib.loads(cargo_manifest.read_text())
                    require('workspace' not in parsed, 'unexpected ancestor Cargo workspace')
                    workspace_checks[logical(cargo_manifest)] = dict(
                        state='present without workspace', **identity(cargo_manifest))
                else:
                    workspace_checks[logical(cargo_manifest)] = {'state': 'absent'}

    audit_ancestors(lexical_out)
    audit_ancestors(out)
    commands = []

    def retain(raw):
        digest = sha(raw)
        relative = 'raw/' + digest + '.gz'
        path = receipts / relative
        if not path.exists():
            path.write_bytes(gzip.compress(raw, mtime=0))
        return {'bytes': len(raw), 'sha256': digest, 'gzip_ref': relative}

    def run(label, argv, cwd=None, env=None, stdin=None, allowed=(0,)):
        used_env = env or env_base
        started = time.monotonic()
        process = subprocess.run([str(x) for x in argv], cwd=cwd or out, env=used_env,
                                 input=stdin, capture_output=True, timeout=180)
        # Preserve raw streams; reject rather than silently redact private home paths.
        for raw in (process.stdout, process.stderr):
            if 'HOME' in used_env:
                require(used_env['HOME'].encode() not in raw, 'private home path in raw stream: ' + label)
        commands.append({'label': label, 'argv': [logical(x) for x in argv], 'cwd': logical(cwd or out),
                         'exit_code': process.returncode, 'elapsed_seconds': round(time.monotonic() - started, 3),
                         'stdin': None if stdin is None else {'bytes': len(stdin), 'sha256': sha(stdin)},
                         'stdout': retain(process.stdout), 'stderr': retain(process.stderr)})
        write_json(receipts / 'commands.json', commands)
        require(process.returncode in allowed, 'command failed: ' + label)
        return process.stdout

    for tool, flag in [('cargo', '--version'), ('rustc', '-vV'), ('rustdoc', '--version'),
                       ('rustfmt', '--version'), ('clippy-driver', '--version')]:
        run(tool + '-version', [toolchain / 'bin' / tool, flag])
    run('clang-version', ['/usr/bin/clang', '--version'])
    sdk = run('sdk-path', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()
    env_base['SDKROOT'] = sdk
    run('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'])
    external_tools = {}
    for tool in ('clang', 'ld'):
        path = Path(run('resolved-' + tool, ['/usr/bin/xcrun', '--find', tool]).decode().strip())
        external_tools[str(path)] = identity(path)
    for path in ['/usr/bin/clang', '/usr/bin/xcrun', '/usr/bin/ld', '/usr/bin/ar', sys.executable]:
        external_tools[logical(path)] = identity(Path(path))
    sdk_pins = {name: identity(Path(sdk) / name) for name in ('SDKSettings.json', 'usr/lib/libSystem.tbd')}
    run('post-source-static-replay', [sys.executable, '-B', PACKET / 'verify.py',
        '--scratch', out / 'static-replay', '--receipt', out / 'static-replay.json'])
    corpus = json.loads((PACKET / 'corpus/summary.json').read_text())
    input_bytes = gzip.decompress((PACKET / 'corpus/inputs.tsv.gz').read_bytes())
    expected_bytes = gzip.decompress((PACKET / 'corpus/expected.tsv.gz').read_bytes())
    require(sha(input_bytes) == corpus['inputs_sha256'] and
            sha(expected_bytes) == corpus['expected_sha256'], 'frozen corpus identity')
    controls = comparator_controls(expected_bytes)
    driver_controls = []
    compile_environments = {}
    snapshots = {}

    def build(label, profiles, test=False, altered=None):
        phase = (out / label).resolve()
        phase.mkdir()
        component = phase / 'component'
        shutil.copytree(SOURCE, component)
        if altered is not None:
            (component / 'src/lib.rs').write_text(altered)
        client_source = phase / 'input_client.rs'
        shutil.copyfile(HERE / 'input_client.rs', client_source)
        require(not any(p.is_symlink() for p in component.rglob('*')), 'copied source symlink')
        before = inventory(component)
        expected_copy = dict(freeze['source'])
        if altered is not None:
            expected_copy['src/lib.rs'] = {'bytes': len(altered.encode()), 'sha256': sha(altered.encode())}
        require(before == expected_copy, 'copied source differs from admitted freeze/mutation')
        require(identity(client_source) == freeze['harness']['input_client.rs'], 'copied input driver differs')
        audit_ancestors(component)
        # Both clean roots have identical relative layout. Only canonical paths
        # reach remapping/config audits, including macOS /tmp -> /private/tmp.
        flags = ['-Dwarnings', '-C', 'overflow-checks=on', '-C', 'linker=/usr/bin/clang',
                 '--remap-path-prefix=' + str(phase) + '=/readiness-value-build',
                 '--remap-path-prefix=' + str(toolchain) + '=/readiness-value-toolchain']
        env = dict(env_base, CARGO_TARGET_DIR=str(phase / 'target'), CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags))
        compile_environments[label] = {k: ('<ORIGINAL_HOME_UNCHANGED_NOT_RECORDED>' if k == 'HOME' else logical(v))
                                       for k, v in env.items()}
        write_json(receipts / 'compile-environments.json', compile_environments)
        if altered is None:
            metadata = json.loads(run(label + '-metadata', [toolchain / 'bin/cargo', 'metadata', '--offline', '--locked', '--format-version', '1'], component, env))
            require(len(metadata['packages']) == len(metadata['workspace_members']) == 1, 'one-package graph')
            require(Path(metadata['workspace_root']).resolve() == component.resolve(),
                    'actual Cargo workspace root must be copied component')
            package = metadata['packages'][0]
            require(package['dependencies'] == [] and package['source'] is None and
                    sorted((target['name'], target['kind']) for target in package['targets']) ==
                    [('value_contract', ['test']), ('visor_readiness_value', ['lib'])], 'exact dependency-free targets')
            run(label + '-rustfmt-check', [toolchain / 'bin/rustfmt', '--edition', '2024', '--check',
                component / 'src/lib.rs', component / 'tests/value_contract.rs', client_source], component, env)
        results = {}
        for profile in profiles:
            release = ['--release'] if profile == 'release' else []
            run(label + '-' + profile + '-cargo-build', [toolchain / 'bin/cargo', 'build', '--offline', '--locked', '--lib', *release], component, env)
            if test:
                run(label + '-' + profile + '-cargo-test', [toolchain / 'bin/cargo', 'test', '--offline', '--locked', '--lib', '--tests', *release], component, env)
            rlib = phase / 'target' / profile / 'libvisor_readiness_value.rlib'
            client = phase / ('client-' + profile)
            run(label + '-' + profile + '-link-driver', [toolchain / 'bin/rustc', '--edition=2024',
                '--crate-name', 'readiness_value_input_client', client_source, '--extern',
                'visor_readiness_value=' + str(rlib), '-L', 'dependency=' + str(phase / 'target' / profile / 'deps'),
                '-C', 'opt-level=' + ('3' if profile == 'release' else '0'), '-C',
                'debuginfo=' + ('0' if profile == 'release' else '2'), *flags, '-o', client], component, env)
            output = run(label + '-' + profile + '-values', [client], component, env, input_bytes)
            if label == 'clean-one' and profile == 'debug':
                first = b'00000000\tP\t1970\t1\t0\t0\n'
                malformed = {
                    'missing-LF': first[:-1], 'wrong-ID': first.replace(b'00000000', b'BAD'),
                    'uppercase-ID': first.replace(b'00000000', b'AAAAAAAA'),
                    'duplicate-ID': first+first, 'unknown-operation': first.replace(b'\tP\t', b'\tX\t'),
                    'plus-number': first.replace(b'1970', b'+1970'),
                    'leading-zero': first.replace(b'1970', b'01970'),
                    'negative-zero': first.replace(b'1970', b'-0'),
                    'signed-year-overflow': first.replace(b'1970', b'2147483648'),
                    'unsigned-negative': first.replace(b'\t1\t', b'\t-1\t'),
                    'ordinal-overflow': first.replace(b'\t1\t', b'\t65536\t'),
                    'extra-field': first[:-1]+b'\textra\n',
                    'CRLF': first.replace(b'\n', b'\r\n'),
                    'invalid-UTF8': first+b'\xff\n',
                    'later-malformed': first+b'00000001\tC\t0\t18446744073709551616\n',
                }
                for control, bad_input in malformed.items():
                    raw = run('input-control-'+control, [client], component, env, bad_input, allowed=(2,))
                    require(not raw, 'malformed stream produced partial value output')
                    driver_controls.append({'name': control, 'exit_code': 2, 'input_sha256': sha(bad_input),
                                            'output_bytes': len(raw)})
                raw = run('input-control-empty-valid', [client], component, env, b'')
                require(not raw, 'empty input must emit empty output')
                driver_controls.append({'name': 'empty-valid', 'exit_code': 0, 'input_sha256': sha(b''), 'output_bytes': 0})
            result = compare(output, expected_bytes)
            require(result['actual_rows'] == corpus['cases'], 'driver output count')
            results[profile] = {'comparison': result, 'rlib': identity(rlib), 'driver': identity(client),
                                'canonical_build_prefix_absent_in_rlib': str(phase).encode() not in rlib.read_bytes(),
                                'canonical_build_prefix_absent_in_driver': str(phase).encode() not in client.read_bytes()}
        if test:
            run(label + '-clippy', [toolchain / 'bin/cargo', 'clippy', '--offline', '--locked', '--all-targets', '--', '-D', 'warnings'], component, env)
        require(inventory(component) == before, 'copied component changed during build')
        snapshots[label] = before
        return results

    baseline = build('clean-one', ('debug', 'release'), test=True)
    require(all(row['comparison']['equal'] for row in baseline.values()), 'production corpus mismatch')
    rebuild = build('clean-two', ('debug', 'release'))
    require(all(row['comparison']['equal'] for row in rebuild.values()), 'clean rebuild corpus mismatch')
    own_byte_comparisons = {profile: {
        'rlib_raw_equal': baseline[profile]['rlib'] == rebuild[profile]['rlib'],
        'driver_raw_equal': baseline[profile]['driver'] == rebuild[profile]['driver'],
        'normalization': None, 'masks': []} for profile in ('debug', 'release')}
    mutation_results = []
    for name, changed, details in variations:
        observation = build('mutant-' + name, ('debug', 'release'), altered=changed)
        require(all(not p['comparison']['equal']
                    for p in observation.values()), 'compiled mutant not distinguished: ' + name)
        mutation_results.append({'definition': details, 'profiles': observation})
        print('compiled mutant detected: ' + name, flush=True)
    tools_after = {directory + '/' + name: value for directory in ['bin', 'lib']
                   for name, value in inventory(toolchain / directory).items()}
    require(tools_after == tools_before, 'toolchain changed during build')
    require(tool_links == {str(p.relative_to(toolchain)): os.readlink(p) for d in ['bin', 'lib'] for p in (toolchain / d).rglob('*') if p.is_symlink()}, 'toolchain symlinks changed')
    for path, expected in external_tools.items():
        actual = path.replace('<TOOLCHAIN>', str(toolchain)).replace('<BUILD>', str(out))
        require(identity(Path(actual)) == expected, 'external tool changed')
    for name, expected in sdk_pins.items():
        require(identity(Path(sdk) / name) == expected, 'selected SDK input changed')
    admit_sources(args.source_freeze_sha)
    write_json(receipts / 'source-copies.json', snapshots)
    write_json(receipts / 'build-audit.json', {
        'source_freeze_sha256': args.source_freeze_sha, 'source': freeze['source'],
        'manifest': manifest, 'lock': lock, 'canonical_ancestor_config_absent': sorted(config_checks),
        'lexical_canonical_ancestor_manifests': workspace_checks,
        'fresh_CARGO_HOME': True, 'inherited_environment_except_HOME': False,
        'toolchain_payload_pins_sha256': identity(HERE / 'TOOLCHAIN-PINS.json')['sha256'],
        'toolchain_payload_unchanged': True, 'external_tools': external_tools, 'SDKROOT': sdk,
        'sdk_inputs': sdk_pins, 'python_version': sys.version,
        'limit': 'Toolchain bin/lib and selected linker/SDK bytes are pinned; host OS/dyld and all SDK files are not a hermetic or captured-target toolchain claim.'})
    result = {'source_freeze_sha256': args.source_freeze_sha, 'corpus_cases': corpus['cases'], 'handwritten_tests_per_profile': 8,
              'baseline': baseline, 'independent_clean_directory_rebuild': rebuild,
              'own_build_byte_comparisons': own_byte_comparisons,
              'compiled_two_profile_mutants': mutation_results, 'comparator_controls': controls, 'input_driver_controls': driver_controls,
              'commands': len(commands), 'raw_stream_policy': 'Every stdout/stderr byte retained, content-addressed gzip; no output normalization or expected-file substitution.',
              'actual_source_unchanged': True, 'copied_source_unchanged': True,
              'original_pre_code_phase_unchanged': True,
              'scope': 'Host-compiled safe sample/calendar/fixed60 values only; no target execution, native ABI/type/compiler/byte equivalence, live clock, opaque native errors or whole-readiness claim.'}
    write_json(receipts / 'results.json', result)
    print(json.dumps({'receipt_directory': logical(receipts), 'baseline_rows_per_profile': corpus['cases'],
                      'baseline_mismatches': {p: r['comparison']['different_rows'] for p, r in baseline.items()},
                      'clean_rebuild_byte_comparisons': own_byte_comparisons,
                      'compiled_mutants': len(mutation_results), 'commands': len(commands)}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
