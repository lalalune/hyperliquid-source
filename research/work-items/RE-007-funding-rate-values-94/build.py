#!/usr/bin/env python3
"""Build only the authored standalone Rust value component, offline and locked."""
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
PACKET = HERE
ROOT = PACKET.parents[2]
SOURCE = ROOT / 'src/node94-funding-rate-values'
SOURCE_FILES = ['Cargo.lock', 'Cargo.toml', 'README.md', 'src/lib.rs', 'tests/rate_values.rs']
PRE_FREEZE = '9549a435f609bcaed7293a0eedf7fd3961573bb0d9e07ab3b05a8effd720444b'
PRE_MANIFEST = '9772ad4bd05c8a2808183356e8bc56dec7be0596aed66f686e09dd8b7b6d731e'
LAST_RECEIPTS = None


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


def no_symlink_path(path, base):
    require(path.is_relative_to(base), 'admitted path outside base')
    for item in [path, *path.parents]:
        require(not item.is_symlink(), 'symlink in admitted path')
        if item == base:
            break


def no_source_symlinks(path):
    require(path.is_dir() and not path.is_symlink(), 'source directory admission')
    for item in path.rglob('*'):
        require(not item.is_symlink() and (item.is_file() or item.is_dir()),
                'source symlink or non-regular entry')


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')


def admit_sources(expected_source_freeze):
    require(not Path(__file__).is_symlink(), 'symlinked build harness')
    no_symlink_path(HERE, ROOT)
    for path, expected in [(PACKET / 'PRE-RUST-FREEZE.json', PRE_FREEZE),
                           (PACKET / 'MANIFEST.sha256', PRE_MANIFEST),
                           (HERE / 'SOURCE-FREEZE.json', expected_source_freeze)]:
        no_symlink_path(path, PACKET)
        require(identity(path)['sha256'] == expected, 'phase freeze identity: ' + path.name)
    precode = json.loads((PACKET / 'PRE-RUST-FREEZE.json').read_text())
    require(len(precode['files']) == 35, 'pre-code file count')
    for row in precode['files']:
        relative = Path(row['path'])
        require(not relative.is_absolute() and '..' not in relative.parts, 'pre-code path')
        no_symlink_path(PACKET / relative, PACKET)
        require(identity(PACKET / relative) == {'bytes': row['bytes'], 'sha256': row['sha256']},
                'pre-code identity: ' + row['path'])
    freeze = json.loads((HERE / 'SOURCE-FREEZE.json').read_text())
    no_symlink_path(SOURCE, ROOT)
    no_source_symlinks(SOURCE)
    require(sorted(inventory(SOURCE)) == SOURCE_FILES, 'unexpected source file/hook')
    require(inventory(SOURCE) == freeze['source'], 'actual source differs from freeze')
    for name, expected in freeze['harness'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'harness path')
        no_symlink_path(HERE / relative, HERE)
        require(identity(HERE / relative) == expected, 'harness differs from freeze: ' + name)
    manifest = tomllib.loads((SOURCE / 'Cargo.toml').read_text())
    lock = tomllib.loads((SOURCE / 'Cargo.lock').read_text())
    require(manifest['dependencies'] == {} and 'workspace' not in manifest and
            'build' not in manifest['package'] and not (SOURCE / 'build.rs').exists(), 'dependency/hook admission')
    require(lock['package'] == [{'name': 'node94-funding-rate-values', 'version': '0.1.0'}],
            'actual dependency-free Cargo lock')
    return freeze, manifest, lock


def frames(raw):
    require(not raw or raw.endswith(b'\n'), 'missing final LF')
    rows, seen = [], set()
    for line in raw.splitlines(keepends=True):
        require(line.endswith(b'\n') and b'\r' not in line, 'invalid line ending')
        words = line[:-1].split(b'\t')
        require(len(words) == 3, 'output field count')
        def word(value):
            return len(value) == 16 and all(c in b'0123456789abcdef' for c in value)
        require(word(words[0]) and word(words[2]) and (words[1] == b'-' or word(words[1])), 'output word')
        require(words[0] not in seen, 'duplicate output ID')
        seen.add(words[0])
        rows.append(tuple(words))
    return rows


def pack_frames(rows):
    return b''.join(b'\t'.join(row) + b'\n' for row in rows)


def compare(actual, expected):
    right = frames(expected)
    try:
        left, parse_error = frames(actual), None
    except ValueError as error:
        left, parse_error = [], str(error)
    differences = [i for i in range(max(len(left), len(right)))
                   if (left[i] if i < len(left) else None) != (right[i] if i < len(right) else None)]
    return {'equal': actual == expected and parse_error is None,
            'actual_rows': len(left), 'expected_rows': len(right), 'parse_error': parse_error,
            'different_rows': len(differences), 'first_different_rows': differences[:12],
            'actual_sha256': sha(actual), 'expected_sha256': sha(expected)}


def comparator_controls(expected):
    rows = frames(expected)
    index = next(i for i, row in enumerate(rows) if row[1] != b'-')
    altered = list(rows)
    row = rows[index]
    altered[index] = (row[0], f'{int(row[1], 16) ^ 1:016x}'.encode(), row[2])
    projection = list(rows)
    index_none = next(i for i, row in enumerate(rows) if row[1] == b'-')
    row = rows[index_none]
    projection[index_none] = (row[0], row[1], b'8000000000000000')
    values = {'omit-final': pack_frames(rows[:-1]),
              'extra-row': expected + pack_frames([(b'ffffffffffffffff', b'-', b'0000000000000000')]),
              'reorder': pack_frames([rows[1], rows[0], *rows[2:]]),
              'duplicate-ID': pack_frames([rows[0], rows[0], *rows[2:]]),
              'change-active-bit': pack_frames(altered), 'wrong-absence-projection': pack_frames(projection),
              'missing-final-LF': expected[:-1], 'empty': b'',
              'short-ID': pack_frames([(rows[0][0][1:], *rows[0][1:]), *rows[1:]]),
              'invalid-hex': pack_frames([(rows[0][0], rows[0][1], b'g000000000000000'), *rows[1:]])}
    require(compare(expected, expected)['equal'], 'positive comparator')
    result = {name: compare(value, expected) for name, value in values.items()}
    require(all(not row['equal'] for row in result.values()), 'missed comparator corruption')
    return result


def malformed_inputs(raw):
    first = raw.splitlines(keepends=True)[0]
    fields = first[:-1].split(b'\t')
    def replace(index, value):
        return b'\t'.join([*fields[:index], value, *fields[index + 1:]]) + b'\n'
    return {'truncated-fields': b'0000000000000000\n', 'missing-final-LF': first[:-1],
            'duplicate-ID': first + first, 'extra-field': first[:-1] + b'\t0\n',
            'huge-count-short-input': replace(4, b'18446744073709551615'),
            'count-type-overflow': replace(4, b'18446744073709551616'),
            'leading-zero-count': replace(4, b'00'), 'negative-count': replace(4, b'-1'),
            'uppercase-hex': replace(3, b'3FF0000000000000'), 'non-ASCII': first + b'\xff\n',
            'valid-then-malformed': first + b'broken\n'}


def mutants(original):
    definitions = [
        ('positive-sum-seed', [('let mut sum = SIGN;', 'let mut sum = 0;')]),
        ('reverse-sample-order', [('for &sample in samples {', 'for &sample in samples.iter().rev() {')]),
        ('omit-final-sample', [('for &sample in samples {', 'for &sample in &samples[..samples.len() - 1] {')]),
        ('zero-default-interest', [('const DEFAULT_INTEREST: u64 = 0x3f1a_36e2_eb1c_432d;', 'const DEFAULT_INTEREST: u64 = 0;')]),
        ('zero-default-multiplier', [('const ONE: u64 = 0x3ff0_0000_0000_0000;', 'const ONE: u64 = 0;')]),
        ('empty-is-present-zero', [('if samples.is_empty() {\n        return None;', 'if samples.is_empty() {\n        return Some(0);')]),
        ('omit-mean-division', [('let mean = divide_by_count(sum, samples.len() as u64);', 'let mean = divide_by_count(sum, 1);')]),
        ('division-ties-away', [('(remainder == complement && quotient & 1 != 0)', '(remainder == complement)')]),
        ('dyadic-ties-away', [('(remainder == halfway && quotient & 1 != 0)', '(remainder == halfway)')]),
        ('second-source-NaN-priority', [('if first & !SIGN > INFINITY {\n        Some(first | QUIET)\n    } else if second & !SIGN > INFINITY {\n        Some(second | QUIET)', 'if second & !SIGN > INFINITY {\n        Some(second | QUIET)\n    } else if first & !SIGN > INFINITY {\n        Some(first | QUIET)')]),
        ('canonicalize-NaN', [('Some(first | QUIET)', 'Some((first | QUIET) & 0xfff8_0000_0000_0000)'), ('Some(second | QUIET)', 'Some((second | QUIET) & 0xfff8_0000_0000_0000)')]),
        ('erase-clamp-zero-sign', [('let interest = interest_bits.unwrap_or(DEFAULT_INTEREST);', 'let interest = interest_bits.unwrap_or(DEFAULT_INTEREST);\n    let clamp_bits = clamp_bits & !SIGN;')]),
        ('either-finite-clamp-guard', [('if gap & !SIGN < INFINITY && clamp_bits & !SIGN < INFINITY {', 'if gap & !SIGN < INFINITY || clamp_bits & !SIGN < INFINITY {')]),
        ('omit-final-finite-bound', [('if product & !SIGN < INFINITY {', 'if false && product & !SIGN < INFINITY {')]),
        ('ignore-supplied-multiplier', [('multiplier_bits.unwrap_or(ONE)', 'multiplier_bits.map_or(ONE, |_| ONE)')]),
        ('omit-eighth-factor', [('const EIGHTH: u64 = 0x3fc0_0000_0000_0000;', 'const EIGHTH: u64 = 0x3ff0_0000_0000_0000;')]),
        ('absence-is-negative-zero', [('rate.unwrap_or(0)', 'rate.unwrap_or(SIGN)')]),
        ('flush-subnormal-results', [('return sign | rounded as u64;', 'return sign | ((rounded as u64) & 0);')]),
    ]
    result = []
    for name, edits in definitions:
        changed = original
        for before, after in edits:
            require(changed.count(before) == 1, 'mutation coordinate: ' + name)
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
    requested_out = Path(os.path.abspath(args.out))  # lexical /tmp is retained separately
    out = args.out.resolve()
    private_map = args.private_map.resolve()
    require(out.parent == Path('/tmp').resolve() and not out.exists(), 'fresh canonical /tmp output required')
    require(not private_map.exists() and not private_map.is_relative_to(PACKET), 'private mapping path')
    freeze, manifest, lock = admit_sources(args.source_freeze_sha)
    original_source = (SOURCE / 'src/lib.rs').read_text()
    variations = mutants(original_source)
    pins = json.loads((HERE / 'TOOLCHAIN-PINS.json').read_text())
    for directory in ['bin', 'lib']:
        no_source_symlinks(toolchain / directory)
    tools_before = {directory + '/' + name: value for directory in ['bin', 'lib']
                    for name, value in inventory(toolchain / directory).items()}
    require(tools_before == pins['payload_files'], 'toolchain payload differs from pre-build pins')
    out.mkdir(mode=0o700)
    global LAST_RECEIPTS
    receipts = out / 'receipts'
    LAST_RECEIPTS = receipts
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
                'LC_ALL': 'C', 'TZ': 'UTC', 'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'}
    if 'HOME' in os.environ:
        env_base['HOME'] = os.environ['HOME']  # Preserve; never repurpose or inspect user credentials/config.
    config_checks = set()

    def audit_ancestors(directory, form, own_manifest=False):
        for distance, ancestor in enumerate([directory, *directory.parents]):
            manifest_path = ancestor / 'Cargo.toml'
            if distance != 0 or not own_manifest:
                require(not manifest_path.exists() and not manifest_path.is_symlink(), 'ancestor Cargo manifest/workspace')
                config_checks.add((form, logical(manifest_path)))
            for name in ('config', 'config.toml'):
                candidate = ancestor / '.cargo' / name
                require(not candidate.exists() and not candidate.is_symlink(),
                        'unexpected ' + form + ' ancestor Cargo configuration')
                config_checks.add((form, logical(candidate)))

    audit_ancestors(requested_out, 'lexical')
    audit_ancestors(out, 'canonical')
    source_ancestor_context = []
    for distance, ancestor in enumerate([SOURCE, *SOURCE.parents]):
        cargo = ancestor / 'Cargo.toml'
        # Context only: the isolated copy never consumes ancestor workspace/config.
        # Do not read configuration contents or record private ancestor names.
        row = {'ancestor_distance_from_source': distance,
               'Cargo.toml_present': cargo.exists(),
               'config_presence': {name: (ancestor / '.cargo' / name).exists()
                                   or (ancestor / '.cargo' / name).is_symlink()
                                   for name in ('config', 'config.toml')}}
        if cargo.is_file() and not cargo.is_symlink():
            row['Cargo.toml_identity'] = identity(cargo)
            row['workspace_table_present'] = 'workspace' in tomllib.loads(cargo.read_text())
        source_ancestor_context.append(row)
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
        timed_out = False
        try:
            process = subprocess.run([str(x) for x in argv], cwd=cwd or out, env=used_env,
                                     input=stdin, capture_output=True, timeout=180)
        except subprocess.TimeoutExpired as error:
            timed_out = True
            process = subprocess.CompletedProcess(argv, -999, error.stdout or b'', error.stderr or b'')
        commands.append({'label': label, 'argv': [logical(x) for x in argv], 'cwd': logical(cwd or out),
                         'exit_code': process.returncode, 'timed_out': timed_out, 'elapsed_seconds': round(time.monotonic() - started, 3),
                         'stdin': None if stdin is None else {'bytes': len(stdin), 'sha256': sha(stdin)},
                         'stdout': retain(process.stdout), 'stderr': retain(process.stderr)})
        write_json(receipts / 'commands.json', commands)
        # Raw private receipts are complete; any home-path appearance blocks publication/admission.
        for raw in (process.stdout, process.stderr):
            if 'HOME' in used_env:
                require(used_env['HOME'].encode() not in raw, 'private home path in raw stream: ' + label)
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
    corpus = json.loads((PACKET / 'corpus/summary.json').read_text())
    input_bytes = gzip.decompress((PACKET / 'corpus/inputs.tsv.gz').read_bytes())
    expected_bytes = gzip.decompress((PACKET / 'corpus/expected.tsv.gz').read_bytes())
    for name, raw in [('inputs.tsv.gz', input_bytes), ('expected.tsv.gz', expected_bytes)]:
        require(sha(raw) == corpus['files'][name]['raw_sha256'], 'corpus raw identity')
    controls = comparator_controls(expected_bytes)
    compile_environments = {}
    snapshots = {}

    def build(label, profiles, test=False, altered=None):
        phase = (out / label).resolve()
        phase.mkdir()
        component = phase / 'component'
        shutil.copytree(SOURCE, component)
        if altered is not None:
            (component / 'src/lib.rs').write_text(altered)
        client_source = phase / 'driver.rs'
        shutil.copyfile(HERE / 'driver.rs', client_source)
        before = inventory(component)
        no_source_symlinks(component)
        no_symlink_path(client_source, phase)
        expected_copy = dict(freeze['source'])
        if altered is not None:
            expected_copy['src/lib.rs'] = {'bytes': len(altered.encode()), 'sha256': sha(altered.encode())}
        require(before == expected_copy, 'copied source differs from admitted freeze/mutation')
        require(identity(client_source) == freeze['harness']['driver.rs'], 'copied input driver differs')
        audit_ancestors(requested_out / label / 'component', 'lexical', own_manifest=True)
        audit_ancestors(component.resolve(), 'canonical', own_manifest=True)
        # Both clean roots have identical relative layout. Only canonical paths
        # reach remapping/config audits, including macOS /tmp -> /private/tmp.
        flags = ['-Dwarnings', '-C', 'overflow-checks=on', '-C', 'linker=/usr/bin/clang',
                 '--remap-path-prefix=' + str(phase) + '=/funding-rate-build',
                 '--remap-path-prefix=' + str(toolchain) + '=/funding-toolchain']
        env = dict(env_base, CARGO_TARGET_DIR=str(phase / 'target'), CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags))
        compile_environments[label] = {k: ('<ORIGINAL_HOME_UNCHANGED_NOT_RECORDED>' if k == 'HOME' else logical(v))
                                       for k, v in env.items()}
        write_json(receipts / 'compile-environments.json', compile_environments)
        if altered is None:
            metadata = json.loads(run(label + '-metadata', [toolchain / 'bin/cargo', 'metadata', '--offline', '--locked', '--format-version', '1'], component, env))
            require(Path(metadata['workspace_root']).resolve() == component.resolve(), 'workspace root escaped isolated component')
            require(len(metadata['packages']) == len(metadata['workspace_members']) == 1, 'one-package graph')
            package = metadata['packages'][0]
            require(Path(package['manifest_path']).resolve() == component / 'Cargo.toml' and
                    all(Path(target['src_path']).resolve().is_relative_to(component)
                        for target in package['targets']), 'metadata target/source escape')
            require(package['dependencies'] == [] and package['source'] is None and
                    sorted((target['name'], target['kind']) for target in package['targets']) ==
                    [('node94_funding_rate_values', ['lib']), ('rate_values', ['test'])], 'exact dependency-free targets')
            run(label + '-rustfmt-check', [toolchain / 'bin/rustfmt', '--edition', '2024', '--check',
                component / 'src/lib.rs', component / 'tests/rate_values.rs', client_source], component, env)
        results = {}
        for profile in profiles:
            release = ['--release'] if profile == 'release' else []
            run(label + '-' + profile + '-cargo-build', [toolchain / 'bin/cargo', 'build', '--offline', '--locked', '--lib', *release], component, env)
            if test:
                run(label + '-' + profile + '-cargo-test', [toolchain / 'bin/cargo', 'test', '--offline', '--locked', '--lib', '--tests', *release], component, env)
            rlib = phase / 'target' / profile / 'libnode94_funding_rate_values.rlib'
            client = phase / ('client-' + profile)
            run(label + '-' + profile + '-link-driver', [toolchain / 'bin/rustc', '--edition=2024',
                '--crate-name', 'funding_rate_input_client', client_source, '--extern',
                'node94_funding_rate_values=' + str(rlib), '-L', 'dependency=' + str(phase / 'target' / profile / 'deps'),
                '-C', 'opt-level=' + ('3' if profile == 'release' else '0'), '-C',
                'debuginfo=' + ('0' if profile == 'release' else '2'), *flags, '-o', client], component, env)
            output = run(label + '-' + profile + '-values', [client], component, env, input_bytes)
            result = compare(output, expected_bytes)
            require(result['actual_rows'] == corpus['cases'], 'driver output count')
            results[profile] = {'comparison': result, 'rlib': identity(rlib), 'driver': identity(client),
                                'canonical_build_prefix_absent_in_rlib': str(phase).encode() not in rlib.read_bytes(),
                                'canonical_build_prefix_absent_in_driver': str(phase).encode() not in client.read_bytes()}
        if test:
            run(label + '-clippy', [toolchain / 'bin/cargo', 'clippy', '--offline', '--locked', '--all-targets', '--', '-D', 'warnings'], component, env)
        require(inventory(component) == before, 'copied component changed during build')
        no_source_symlinks(component)
        no_symlink_path(client_source, phase)
        require(identity(client_source) == freeze['harness']['driver.rs'], 'input driver changed during build')
        snapshots[label] = before
        return results

    baseline = build('clean-one', ('debug', 'release'), test=True)
    require(all(row['comparison']['equal'] for row in baseline.values()), 'production corpus mismatch')
    parser_controls = {}
    client = out / 'clean-one/client-release'
    for name, raw in malformed_inputs(input_bytes).items():
        rejected_output = run('malformed-' + name, [client], stdin=raw, allowed=(2,))
        require(rejected_output == b'', 'malformed input emitted partial output')
        parser_controls[name] = {'exit_code': commands[-1]['exit_code'], 'command_index': len(commands)-1}
    require(run('malformed-extra-argument', [client, 'unexpected'], stdin=b'', allowed=(2,)) == b'', 'argument rejection output')
    parser_controls['extra-argument'] = {'exit_code': commands[-1]['exit_code'], 'command_index': len(commands)-1}
    empty = run('empty-input', [client], stdin=b'')
    require(empty == b'', 'empty input emitted output')
    parser_controls['empty-valid'] = {'exit_code': commands[-1]['exit_code'], 'command_index': len(commands)-1}
    rebuild = build('clean-two', ('debug', 'release'))
    require(all(row['comparison']['equal'] for row in rebuild.values()), 'clean rebuild corpus mismatch')
    require((out / 'clean-one').resolve() != (out / 'clean-two').resolve() and
            not (out / 'clean-one').samefile(out / 'clean-two'), 'clean roots must be physically distinct')
    own_byte_comparisons = {profile: {
        'rlib_raw_equal': baseline[profile]['rlib'] == rebuild[profile]['rlib'],
        'driver_raw_equal': baseline[profile]['driver'] == rebuild[profile]['driver'],
        'normalization': None, 'masks': []} for profile in ('debug', 'release')}
    mutation_results = []
    for name, changed, details in variations:
        observations = build('mutant-' + name, ('debug', 'release'), altered=changed)
        mutation_results.append({'definition': details, 'observations': observations})
        write_json(receipts / 'mutation-progress.json', mutation_results)
        require(all(not row['comparison']['equal'] and row['comparison']['different_rows'] > 0
                    for row in observations.values()), 'compiled mutant not distinguished in both profiles: ' + name)
    tools_after = {directory + '/' + name: value for directory in ['bin', 'lib']
                   for name, value in inventory(toolchain / directory).items()}
    require(tools_after == tools_before, 'toolchain changed during build')
    for path, expected in external_tools.items():
        actual = path.replace('<TOOLCHAIN>', str(toolchain)).replace('<BUILD>', str(out))
        require(identity(Path(actual)) == expected, 'external tool changed')
    for name, expected in sdk_pins.items():
        require(identity(Path(sdk) / name) == expected, 'selected SDK input changed')
    admit_sources(args.source_freeze_sha)
    write_json(receipts / 'source-copies.json', snapshots)
    write_json(receipts / 'build-audit.json', {
        'source_freeze_sha256': args.source_freeze_sha, 'source': freeze['source'],
        'manifest': manifest, 'lock': lock, 'lexical_and_canonical_ancestor_config_absent': sorted(config_checks),
        'actual_source_ancestor_context_excluded_from_isolated_build': source_ancestor_context,
        'fresh_CARGO_HOME': True, 'distinct_clean_roots_samefile_false': True, 'inherited_environment_except_HOME': False,
        'toolchain_payload_pins_sha256': identity(HERE / 'TOOLCHAIN-PINS.json')['sha256'],
        'toolchain_payload_unchanged': True, 'external_tools': external_tools, 'SDKROOT': sdk,
        'sdk_inputs': sdk_pins, 'python_version': sys.version,
        'limit': 'Toolchain bin/lib and selected linker/SDK bytes are pinned; host OS/dyld and all SDK files are not a hermetic or captured-target toolchain claim.'})
    result = {'source_freeze_sha256': args.source_freeze_sha, 'corpus_cases': corpus['cases'],
              'baseline': baseline, 'independent_clean_directory_rebuild': rebuild,
              'own_build_byte_comparisons': own_byte_comparisons,
              'compiled_both_profile_mutants': mutation_results, 'comparator_controls': controls,
              'input_parser_controls': parser_controls,
              'commands': len(commands), 'raw_stream_policy': 'Every stdout/stderr byte retained, content-addressed gzip; no output normalization or expected-file substitution.',
              'actual_source_unchanged': True, 'copied_source_unchanged': True,
              'original_static_and_pre_source_phases_unchanged': True,
              'scope': 'Host-compiled conditional raw rate values only; no captured execution, native ABI/layout/byte equivalence, measured MXCSR/CPU or map/scheduler/economic policy claim.'}
    write_json(receipts / 'results.json', result)
    print(json.dumps({'receipt_directory': logical(receipts), 'baseline_rows_per_profile': corpus['cases'],
                      'baseline_mismatches': {p: r['comparison']['different_rows'] for p, r in baseline.items()},
                      'clean_rebuild_byte_comparisons': own_byte_comparisons,
                      'compiled_mutants': len(mutation_results), 'commands': len(commands)}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        if LAST_RECEIPTS is not None and LAST_RECEIPTS.exists():
            write_json(LAST_RECEIPTS / 'qualification-failure.json', {'error': str(error), 'complete_success': False, 'commands_retained': (LAST_RECEIPTS / 'commands.json').exists()})
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
