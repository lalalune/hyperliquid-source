#!/usr/bin/env python3
"""Build only the authored supplied-book premium component, offline/locked.

MIT orchestration adapted from the separately authored duration build.py,
SHA25651dbaf7652cfd5a0309385ec2533cf97afef31c391d4cdb214cbaed5b208cd43.
No duration source, semantics, oracle or dependency is imported or reused.
This new source/harness must receive its own exact build gate before execution.
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
PRE = PACKET / 'pre-rust'
ROOT = PACKET.parents[2]
SOURCE = ROOT / 'src/node94-funding-premium-values'
SOURCE_FILES = ['Cargo.lock', 'Cargo.toml', 'README.md', 'src/lib.rs', 'tests/value_contract.rs']
PRE_FREEZE = 'b1c53a69adb1b9d85af70e397cf2b6828f7f11009ce2256563fa45411b3ae9b2'
PRE_MANIFEST = 'bf3fb112837566ac38363b7b95ab9b98b98eaa112b44eac072f3c814d919e6f6'


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
    require(not PRE.is_symlink() and not any(p.is_symlink() for p in PRE.rglob('*')),
            'pre-code symlink')
    freeze = json.loads((PRE / 'PRE-RUST-FREEZE.json').read_text())
    require(freeze['source_absence']['component_absent'] is True, 'pre-code chronology source absence')
    require(len(freeze['files_sha256']) == 30, 'pre-code exact file count')
    for name, digest in freeze['files_sha256'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'pre-code path')
        require(not (PRE / relative).is_symlink() and identity(PRE / relative)['sha256'] == digest,
                'changed pre-code file: ' + name)
    prior = json.loads((PRE / 'ORIGINAL-DISTRIBUTION.json').read_text())
    require(len(prior['files']) == 20, 'original distribution count')
    for name, expected in prior['files'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'prior path')
        require(not any(parent.is_symlink() for parent in (PACKET / name).parents), 'prior parent symlink')
        require(not (PACKET / name).is_symlink() and identity(PACKET / name) == expected,
                'published original20 changed: ' + name)
    return 32


def admit_sources(expected_source_freeze):
    require(identity(PRE / 'PRE-RUST-FREEZE.json')['sha256'] == PRE_FREEZE, 'pre-code freeze identity')
    require(identity(PRE / 'MANIFEST.sha256')['sha256'] == PRE_MANIFEST, 'pre-code manifest identity')
    require(check_precode() == 32, 'original pre-code entries')
    require(identity(HERE / 'SOURCE-FREEZE.json')['sha256'] == expected_source_freeze, 'source freeze identity')
    freeze = json.loads((HERE / 'SOURCE-FREEZE.json').read_text())
    require(not any(parent.is_symlink() for parent in SOURCE.parents), 'source parent symlink')
    require(not SOURCE.is_symlink() and not any(p.is_symlink() for p in SOURCE.rglob('*')), 'source symlink')
    require(sorted(inventory(SOURCE)) == SOURCE_FILES, 'unexpected source file/hook')
    require(inventory(SOURCE) == freeze['source'], 'actual source differs from freeze')
    for name, expected in freeze['harness'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'harness path')
        require(not (HERE / name).is_symlink(), 'harness symlink')
        require(identity(HERE / name) == expected, 'harness differs from freeze: ' + name)
    manifest = tomllib.loads((SOURCE / 'Cargo.toml').read_text())
    lock = tomllib.loads((SOURCE / 'Cargo.lock').read_text())
    require(set(manifest) == {'package', 'lib', 'dependencies', 'profile'} and
            manifest['lib'] == {'path': 'src/lib.rs'} and
            manifest['dependencies'] == {} and 'workspace' not in manifest and
            'build' not in manifest['package'] and not (SOURCE / 'build.rs').exists(), 'dependency/hook admission')
    require(lock['package'] == [{'name': 'node94-funding-premium-values', 'version': '0.1.0'}], 'actual dependency-free lock')
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
    changed_value = rows[0].rstrip(b'\n').split(b' ')
    changed_value[-1] = f'{int(changed_value[-1], 16) ^ 1:016x}'.encode()
    values = {
        'missing-row': b''.join(rows[:-1]), 'extra-row': expected+rows[0],
        'reordered': b''.join([rows[1], rows[0], *rows[2:]]),
        'duplicate-id': replace(1, rows[0]),
        'changed-id': replace(0, b'ffffffffffffffff'+rows[0][16:]),
        'changed-value': replace(0, b' '.join(changed_value) + b'\n'),
        'missing-field': replace(0, b' '.join(rows[0].rstrip(b'\n').split(b' ')[:-1]) + b'\n'),
        'missing-LF': expected[:-1], 'CRLF': expected.replace(b'\n', b'\r\n'), 'empty': b'',
    }
    require(compare(expected, expected)['equal'], 'positive comparator')
    result = {name: compare(value, expected) for name, value in values.items()}
    require(all(not row['equal'] for row in result.values()), 'missed comparator corruption')
    return result


def mutants(original):
    first = """    let first = impact(input.book.first, input.book.slots, input.target)
        .map_err(|()| Refusal::CycleFirst)?;"""
    second = """    let second = impact(input.book.second, input.book.slots, input.target)
        .map_err(|()| Refusal::CycleSecond)?;"""
    scale = """    if input.scale > 6 {
        return Err(Refusal::InvalidScale);
    }"""
    zero_oracle = """    if input.oracle == 0 {
        return Ok(absent(input.asset, input.oracle));
    }"""
    divide = """    if input.divide_by_100 {
        value = positive_divisor_div(value, HUNDRED);
    }"""
    clamp = '    value = source_min(HALF, source_max(HALF | SIGN, value));'
    definitions = [
        ('reverse-entry-order', [('for entry in entries {', 'for entry in entries.iter().rev() {')]),
        ('unsigned-key', [('entry.key.unsigned_abs()', 'entry.key as u64')]),
        ('product-cap-too-large', [('const PRODUCT_CAP: u128 = (1 << 63) - 2;', 'const PRODUCT_CAP: u128 = (1 << 64) - 1;')]),
        ('wrap-chain-quantity', [('level_quantity.saturating_add(slot.quantity)', 'level_quantity.wrapping_add(slot.quantity)')]),
        ('skip-invalid-initial-head', [('let Some(mut cursor) = index(entry.head, slots.len()) else {\n            return Ok(0);\n        };', 'let Some(mut cursor) = index(entry.head, slots.len()) else {\n            continue;\n        };')]),
        ('invalid-later-head-discards-quantity', [('let Some(next) = index(slot.next, slots.len()) else {\n                break;\n            };', 'let Some(next) = index(slot.next, slots.len()) else {\n                return Ok(0);\n            };')]),
        ('byte-tag', [('slot.tag == 2', 'slot.tag & 255 == 2')]),
        ('byte-continuation', [('slot.continuation == 0', 'slot.continuation & 255 == 0')]),
        ('wrong-active-bit', [('entry.active & 1 == 0', 'entry.active & 2 == 0')]),
        ('ceil-partial-fill', [('let partial = (target - cost) / price;', 'let partial = (target - cost).div_ceil(price);')]),
        ('forget-previous-quantity', [('let final_quantity = quantity.saturating_add(partial);', 'let final_quantity = quantity.saturating_sub(quantity).saturating_add(partial);')]),
        ('discard-zero-price-entry', [('let price = entry.key.unsigned_abs();', 'let price = entry.key.unsigned_abs();\n        if price == 0 { continue; }')]),
        ('mode-only-one', [('input.mode != 0', 'input.mode == 1')]),
        ('reverse-scale', [('10_u64.pow(u32::from(6 - input.scale))', '10_u64.pow(u32::from(input.scale))')]),
        ('scaled-round-ties-odd', [('remainder == halfway && lower & 1 == 1', 'remainder == halfway && lower & 1 == 0')]),
        ('divide-round-wrong-side', [('twice > divisor', 'twice < divisor')]),
        ('discard-smaller-addend', [('if distance > 75 {', 'if distance > 0 {')]),
        ('omit-midpoint-half', [('let midpoint = total - (1 << 52);', 'let midpoint = total;')]),
        ('divide-after-clamp', [(divide + '\n' + clamp, clamp + '\n' + divide)]),
        ('converted-fallback', [('payload: oracle,', 'payload: unsigned_bits(oracle),')]),
        ('absent-tag-zero', [('tag: 1,', 'tag: 0,')]),
        ('swap-shared-book-views', [(first + '\n' + second,
            first.replace('input.book.first,', 'input.book.second,') + '\n' +
            second.replace('input.book.second,', 'input.book.first,'))]),
        # These last two are explicitly new safe-policy controls. A CycleSecond
        # mismatch does not prove ordinary native call order from output alone.
        ('policy-scale-after-oracle', [(scale + '\n' + zero_oracle, zero_oracle + '\n' + scale)]),
        ('policy-first-zero-shortcut', [(first, first + '\n    if first == 0 { return Ok(absent(input.asset, input.oracle)); }')]),
    ]
    result = []
    for name, edits in definitions:
        changed = original
        for before, after in edits:
            require(changed.count(before) == 1, 'mutation coordinate: ' + name)
            changed = changed.replace(before, after, 1)
        require(changed != original, 'unchanged mutation')
        result.append((name, changed, {'name': name, 'edits': edits,
            'scope': 'new-safe-policy-only' if name.startswith('policy-') else 'ordinary-supplied-value',
            'source_sha256': sha(changed.encode())}))
    return result


def malformed_inputs(input_bytes):
    first = input_bytes.splitlines(keepends=True)[0]
    words = first.rstrip(b'\n').split(b' ')
    # Use an actual admitted corpus frame, never an unrelated placeholder.
    require(len(words) == 24 and words[7:10] == [b'0000000000000001', b'0000000000000001', b'0000000000000002'],
            'malformed-control source frame shape')
    def changed(index, value):
        result = words.copy()
        result[index] = value
        return b' '.join(result) + b'\n'
    values = {
        'missing-LF': first[:-1], 'tab-separator': first.replace(b' ', b'\t', 1),
        'short-ID': first[1:], 'uppercase-ID': changed(0, b'AAAAAAAAAAAAAAAA'),
        'duplicate-ID': first + first, 'short-word': changed(1, b'000000000000000'),
        'uppercase-word': changed(1, b'000000000000000A'), 'invalid-hex': changed(1, b'000000000000000g'),
        'extra-word': first[:-1] + b' 0000000000000000\n',
        'missing-word': b' '.join(words[:-1]) + b'\n',
        'missing-header': b' '.join(words[:9]) + b'\n', 'empty-line': b'\n',
        'CRLF': first.replace(b'\n', b'\r\n'), 'invalid-UTF8': first + b'\xff\n',
        'later-malformed': first + b'0000000000000001 bad\n',
        'scale-byte-range': changed(4, b'0000000000000100'),
        'mode-byte-range': changed(5, b'0000000000000100'),
        'membership-range': changed(6, b'0000000000000002'),
        'active-byte-range': changed(11, b'0000000000000100'),
        'tag-dword-range': changed(16, b'0000000100000000'),
        'count-overflow': changed(7, b'ffffffffffffffff'),
        'count-data-mismatch': changed(9, b'0000000000000003'),
    }
    return first, values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='fresh direct child of canonical /tmp')
    parser.add_argument('--private-map', type=Path, required=True, help='fresh path outside public packet')
    parser.add_argument('--source-freeze-sha', required=True)
    args = parser.parse_args()
    require(Path(__file__).absolute() == Path(__file__).resolve() and not Path(__file__).is_symlink(),
            'harness invocation must use its canonical nonsymlink path')
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
    mapping = {'<BUILD>': str(out), '<TOOLCHAIN>': str(toolchain), '<SOURCE>': str(SOURCE),
               '<PACKET>': str(PACKET), '<REPO>': str(ROOT)}
    for index, parent in enumerate(ROOT.parents, 1):
        if str(parent) not in ('/', '/Users', '/home'):
            mapping['<REPO_PARENT_' + str(index) + '>'] = str(parent)
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
    audit_ancestors(SOURCE)
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
        completion = 'completed'
        failure = None
        try:
            process = subprocess.run([str(x) for x in argv], cwd=cwd or out, env=used_env,
                                     input=stdin, capture_output=True, timeout=180)
            stdout, stderr, code = process.stdout, process.stderr, process.returncode
        except subprocess.TimeoutExpired as error:
            completion, code = 'timeout', None
            stdout, stderr = error.stdout or b'', error.stderr or b''
            failure = 'timeout after180seconds'
        except OSError as error:
            completion, code = 'launch-error', None
            stdout, stderr = b'', str(error).encode()
            failure = 'launch errno=' + str(error.errno)
        commands.append({'label': label, 'argv': [logical(x) for x in argv], 'cwd': logical(cwd or out),
                         'completion': completion, 'exit_code': code,
                         'elapsed_seconds': round(time.monotonic() - started, 3),
                         'stdin': None if stdin is None else {'bytes': len(stdin), 'sha256': sha(stdin)},
                         'stdout': retain(stdout), 'stderr': retain(stderr), 'failure': failure})
        write_json(receipts / 'commands.json', commands)
        # Retain private scratch evidence before rejecting accidental home paths.
        # A rejected run stays private; successful public streams are never redacted.
        for raw in (stdout, stderr):
            if 'HOME' in used_env:
                require(used_env['HOME'].encode() not in raw, 'private home path in raw stream: ' + label)
        require(completion == 'completed' and code in allowed, 'command failed: ' + label)
        return stdout

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
    static = run('post-source-static-replay', [sys.executable, '-B', PRE / 'verify.py'])
    require(json.loads(static) == json.loads((PRE / 'verification.json').read_text()), 'static replay differs')
    (receipts / 'static-replay.json').write_bytes(static)
    corpus = json.loads((PRE / 'corpus/report.json').read_text())
    input_bytes = gzip.decompress((PRE / 'corpus/inputs.txt.gz').read_bytes())
    expected_bytes = gzip.decompress((PRE / 'corpus/expected.txt.gz').read_bytes())
    require(sha(input_bytes) == corpus['streams']['inputs.txt']['raw_sha256'] and
            sha(expected_bytes) == corpus['streams']['expected.txt']['raw_sha256'], 'frozen corpus identity')
    controls = comparator_controls(expected_bytes)
    driver_controls = []
    compile_environments = {}
    snapshots = {}
    driver_snapshots = {}
    observations = {}

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
        snapshots[label] = before
        driver_snapshots[label] = identity(client_source)
        write_json(receipts / 'source-copies.json', snapshots)
        write_json(receipts / 'driver-copies.json', driver_snapshots)
        audit_ancestors(component)
        # Both clean roots have identical relative layout. Only canonical paths
        # reach remapping/config audits, including macOS /tmp -> /private/tmp.
        flags = ['-Dwarnings', '-C', 'overflow-checks=on', '-C', 'linker=/usr/bin/clang',
                 '--remap-path-prefix=' + str(phase) + '=/impact-premium-build',
                 '--remap-path-prefix=' + str(toolchain) + '=/impact-premium-toolchain']
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
                    [('node94_funding_premium_values', ['lib']), ('value_contract', ['test'])], 'exact dependency-free targets')
            run(label + '-rustfmt-check', [toolchain / 'bin/rustfmt', '--edition', '2024', '--check',
                component / 'src/lib.rs', component / 'tests/value_contract.rs', client_source], component, env)
        results = {}
        for profile in profiles:
            release = ['--release'] if profile == 'release' else []
            run(label + '-' + profile + '-cargo-build', [toolchain / 'bin/cargo', 'build', '--offline', '--locked', '--lib', *release], component, env)
            if test:
                run(label + '-' + profile + '-cargo-test', [toolchain / 'bin/cargo', 'test', '--offline', '--locked', '--lib', '--tests', *release], component, env)
            rlib = phase / 'target' / profile / 'libnode94_funding_premium_values.rlib'
            client = phase / ('client-' + profile)
            run(label + '-' + profile + '-link-driver', [toolchain / 'bin/rustc', '--edition=2024',
                '--crate-name', 'impact_premium_input_client', client_source, '--extern',
                'node94_funding_premium_values=' + str(rlib), '-L', 'dependency=' + str(phase / 'target' / profile / 'deps'),
                '-C', 'opt-level=' + ('3' if profile == 'release' else '0'), '-C',
                'debuginfo=' + ('0' if profile == 'release' else '2'), *flags, '-o', client], component, env)
            output = run(label + '-' + profile + '-values', [client], component, env, input_bytes)
            result = compare(output, expected_bytes)
            results[profile] = {'comparison': result, 'rlib': identity(rlib), 'driver': identity(client),
                                'canonical_build_prefix_absent_in_rlib': str(phase).encode() not in rlib.read_bytes(),
                                'canonical_build_prefix_absent_in_driver': str(phase).encode() not in client.read_bytes(),
                                'private_home_absent_in_rlib': 'HOME' not in env or env['HOME'].encode() not in rlib.read_bytes(),
                                'private_home_absent_in_driver': 'HOME' not in env or env['HOME'].encode() not in client.read_bytes(),
                                'binary_retention': 'Exact private build artifacts only; public identities do not assert public raw-byte availability.'}
            observations[label] = results
            write_json(receipts / 'build-results.json', observations)
            require(result['actual_rows'] == corpus['case_count'], 'driver output count')
            require(result['equal'] if altered is None else not result['equal'],
                    ('production mismatch: ' if altered is None else 'compiled mutant not distinguished: ') + label + '/' + profile)
            if label == 'clean-one' and profile == 'debug':
                first, malformed = malformed_inputs(input_bytes)
                for control, bad_input in malformed.items():
                    raw = run('input-control-'+control, [client], component, env, bad_input, allowed=(2,))
                    require(not raw, 'malformed stream produced partial value output')
                    driver_controls.append({'name': control, 'exit_code': 2, 'input_sha256': sha(bad_input),
                                            'output_bytes': len(raw)})
                raw = run('input-control-extra-argument', [client, 'unexpected'], component, env, first, allowed=(2,))
                require(not raw, 'extra argument produced value output')
                driver_controls.append({'name': 'extra-argument', 'exit_code': 2,
                                        'input_sha256': sha(first), 'output_bytes': 0})
                raw = run('input-control-empty-valid', [client], component, env, b'')
                require(not raw, 'empty input must emit empty output')
                driver_controls.append({'name': 'empty-valid', 'exit_code': 0, 'input_sha256': sha(b''), 'output_bytes': 0})
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
        actual = path
        for name, physical in mapping.items():
            actual = actual.replace(name, physical)
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
    result = {'source_freeze_sha256': args.source_freeze_sha, 'corpus_cases': corpus['case_count'], 'authored_tests_per_profile': 13,
              'baseline': baseline, 'independent_clean_directory_rebuild': rebuild,
              'own_build_byte_comparisons': own_byte_comparisons,
              'compiled_two_profile_mutants': mutation_results, 'comparator_controls': controls, 'input_driver_controls': driver_controls,
              'commands': len(commands), 'raw_stream_policy': 'Every stdout/stderr byte retained, content-addressed gzip; no output normalization or expected-file substitution.',
              'actual_source_unchanged': True, 'copied_source_unchanged': True,
              'original_pre_code_phase_unchanged': True,
              'scope': 'Host-compiled supplied shared-slab impact/premium values only; no target execution, native ABI/type/compiler/byte equivalence, floating state, live economics, callbacks or whole-settlement claim.'}
    write_json(receipts / 'results.json', result)
    print(json.dumps({'receipt_directory': logical(receipts), 'baseline_rows_per_profile': corpus['case_count'],
                      'baseline_mismatches': {p: r['comparison']['different_rows'] for p, r in baseline.items()},
                      'clean_rebuild_byte_comparisons': own_byte_comparisons,
                      'compiled_mutants': len(mutation_results), 'commands': len(commands)}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
