#!/usr/bin/env python3
"""Offline/locked qualification of the authored request-throttle supplied-state operation.

MIT orchestration adapted from the author-owned impact-premium build.py,
SHA256 cdd4aecec53c710bbe2419a8e577d72426dbda9d3dc4f9524eccce88b754541f.
No impact source, formula, corpus or dependency is imported. This harness needs
its own exact source/build gate before execution. Stops on first required failure.
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
import struct
import tomllib

HERE = Path(__file__).resolve().parent
PACKET = HERE.parent
PRE = PACKET
ROOT = PACKET.parents[2]
SOURCE = ROOT / 'src/node94-consensus-admission'
SOURCE_FILES = ['Cargo.lock', 'Cargo.toml', 'README.md', 'src/admission.rs', 'src/auth.rs', 'src/error.rs', 'src/lib.rs', 'src/qc.rs', 'src/request_throttle.rs', 'src/stake.rs', 'src/state.rs', 'src/tc.rs', 'src/types.rs', 'tests/evidence_contract.rs', 'tests/request_throttle.rs']
PRE_FREEZE = '4e3664fccb352b37f4df8ca3c4036ce3bb3c6bd8b20a23e9221d1c743c16f5b1'
PRE_MANIFEST = '96bf0a5006a8afb850dccb078a89a64bbfcd2b9fcc30985677cbf59d8b41a8cd'


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
    freeze = json.loads((PRE / 'PRE-RUST-FREEZE.json').read_text())
    require(len(freeze['files']) == 51, 'pre-code exact bound count')
    require(freeze['task_client_build_harness_absent'] is True, 'pre-code source chronology')
    for name, digest in freeze['files'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'pre-code path')
        require(not any(parent.is_symlink() for parent in (PRE / name).parents), 'pre-code parent symlink')
        require(not (PRE / name).is_symlink() and identity(PRE / name)['sha256'] == digest,
                'changed pre-code file: ' + name)
    return 52


def admit_sources(expected_source_freeze):
    require(identity(PRE / 'PRE-RUST-FREEZE.json')['sha256'] == PRE_FREEZE, 'pre-code freeze identity')
    require(identity(PRE / 'MANIFEST.sha256')['sha256'] == PRE_MANIFEST, 'pre-code manifest identity')
    require(check_precode() == 52, 'original pre-code entries')
    require(identity(HERE / 'SOURCE-FREEZE.json')['sha256'] == expected_source_freeze, 'source freeze identity')
    freeze = json.loads((HERE / 'SOURCE-FREEZE.json').read_text())
    require(not any(parent.is_symlink() for parent in SOURCE.parents), 'source parent symlink')
    require(not SOURCE.is_symlink() and not any(p.is_symlink() for p in SOURCE.rglob('*')), 'source symlink')
    require(sorted(inventory(SOURCE)) == SOURCE_FILES, 'unexpected source file/hook')
    require(inventory(SOURCE) == freeze['source'], 'actual source differs from freeze')
    for name, expected in freeze['harness'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'harness path')
        require(not (HERE / name).is_symlink() and not any(p.is_symlink() for p in (HERE / name).parents), 'harness symlink')
        require(identity(HERE / name) == expected, 'harness differs from freeze: ' + name)
    manifest = tomllib.loads((SOURCE / 'Cargo.toml').read_text())
    lock = tomllib.loads((SOURCE / 'Cargo.lock').read_text())
    require(set(manifest) == {'package', 'lib'} and
            manifest['lib'] == {'path': 'src/lib.rs'} and
            manifest.get('dependencies', {}) == {} and 'workspace' not in manifest and
            'build' not in manifest['package'] and not (SOURCE / 'build.rs').exists(), 'dependency/hook admission')
    require(lock['package'] == [{'name': 'node94-consensus-admission', 'version': '0.1.0'}], 'actual dependency-free lock')
    baseline = json.loads((PRE / 'baseline.json').read_text())['source_files']
    for name, expected in baseline.items():
        relative = Path(name).relative_to('src/node94-consensus-admission')
        if relative.as_posix() not in ('src/lib.rs', 'README.md'):
            require(identity(SOURCE / relative) == expected, 'unplanned baseline change: ' + name)
    require((SOURCE / 'src/lib.rs').read_text().count('pub mod request_throttle;') == 1, 'bounded module export')
    # The original module bytes must be exactly recovered by removing the insertion.
    original_lib = (SOURCE / 'src/lib.rs').read_bytes().replace(b'pub mod request_throttle;\n', b'', 1)
    require(sha(original_lib) == baseline['src/node94-consensus-admission/src/lib.rs']['sha256'], 'other lib changes')
    readme = (SOURCE / 'README.md').read_bytes()
    start = readme.index(b'## Retained request rows\n')
    end = readme.index(b'## Authentication boundary\n', start)
    require(sha(readme[:start]+readme[end:]) == baseline['src/node94-consensus-admission/README.md']['sha256'], 'other README changes')
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
        changed = rows.copy(); changed[index] = value; return b''.join(changed)
    ident, raw = rows[0].rstrip(b'\n').split(b'\t', 1)
    value = json.loads(raw); value[0]['registered'] = not value[0]['registered']
    values = {
        'missing-row': b''.join(rows[:-1]), 'extra-row': expected + rows[0],
        'reordered': b''.join([rows[1], rows[0], *rows[2:]]),
        'duplicate-id': replace(1, rows[0]), 'changed-id': replace(0, b'WRONG\t'+raw+b'\n'),
        'changed-value': replace(0, ident+b'\t'+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'),
        'missing-field': replace(0, ident+b'\t[]\n'), 'missing-LF': expected[:-1],
        'CRLF': expected.replace(b'\n', b'\r\n'), 'empty': b'',
    }
    require(compare(expected, expected)['equal'], 'positive comparator')
    result = {name: compare(value, expected) for name,value in values.items()}
    require(all(not row['equal'] for row in result.values()), 'missed comparator corruption')
    return result


def mutants(original):
    reason = '        row.reasons.insert(reason);'
    invalid = """        if !time.is_valid() {
            return ThrottleOutcome::InvalidTime;
        }
"""
    definitions = [
        ('refresh-stamp', [(reason, '        row.stamp = time;\n'+reason)]),
        ('ignore-round', [('        let (row, registered) = match self.rows.entry(key) {', '        let key = RequestKey { round: 0, ..key };\n        let (row, registered) = match self.rows.entry(key) {')]),
        ('ignore-last-hash-byte', [('        let (row, registered) = match self.rows.entry(key) {', '        let mut key = key; key.hash[31] = 0;\n        let (row, registered) = match self.rows.entry(key) {')]),
        ('omit-reason', [(reason, '        let _ = reason;')]),
        ('reason-after-suppression', [(reason, ''), ('            row.sent = true;', reason+'\n            row.sent = true;')]),
        ('clear-sent', [(reason, reason+'\n        row.sent = false;')]),
        ('default-zero', [('delay_bits.map_or(1_000_000_000, delay_nanoseconds)', 'delay_bits.map_or(0, delay_nanoseconds)')]),
        ('reverse-delay-sign', [('delay_bits.map_or(1_000_000_000, delay_nanoseconds)', 'delay_bits.map(|bits| bits ^ (1 << 63)).map_or(1_000_000_000, delay_nanoseconds)')]),
        ('strict-deadline', [('if time < deadline || row.sent {', 'if time <= deadline || row.sent {')]),
        ('ignore-sent', [('if time < deadline || row.sent {', 'if time < deadline {')]),
        ('nonfinite-saturates', [('if exponent == 2047 {\n        return 0;', 'if exponent == 2047 {\n        return i64::MAX;')]),
        ('overflow-saturates', [('if top_power > 1023 {\n        return 0;', 'if top_power > 1023 {\n        return if bits >> 63 != 0 { i64::MIN } else { i64::MAX };')]),
        ('omit-implicit-leading-bit', [('fraction | (1_u64 << 52)', 'fraction')]),
        ('round-at-52-bits', [('width.saturating_sub(53)', 'width.saturating_sub(52)')]),
        ('round-wrong-side', [('discarded > halfway', 'discarded < halfway')]),
        ('negative-clamp-off-by-one', [('return if negative { i64::MIN } else { i64::MAX };', 'return if negative { i64::MIN + 1 } else { i64::MAX };')]),
        ('negative-day-truncation', [('total.div_euclid(86_400_000_000_000)', '(total / 86_400_000_000_000)')]),
        ('omit-deadline-nanos', [('nano: (remainder % 1_000_000_000) as u32,', 'nano: 0,')]),
        ('policy-invalid-after-registration', [(invalid, ''), (reason, reason+'\n'+invalid.rstrip())]),
        ('policy-range-omits-reason', [(reason, ''), ('        if time < deadline || row.sent {', reason+'\n        if time < deadline || row.sent {')]),
    ]
    results=[]
    for name,edits in definitions:
        changed=original
        for before,after in edits:
            require(changed.count(before)==1, 'mutation coordinate: '+name)
            changed=changed.replace(before,after,1)
        require(changed!=original,'unchanged mutation')
        results.append((name,changed,dict(name=name,edits=edits,scope='new-safe-policy-only' if name.startswith('policy-') else 'native-conditional-value',source_sha256=sha(changed.encode()))))
    return results


def malformed_inputs(input_bytes):
    first = input_bytes.splitlines(keepends=True)[0]
    ident, text = first.rstrip(b'\n').split(b'\t'); frame = bytes.fromhex(text.decode())
    require(frame[:8] == b'TH01'+b'\0'*4 and struct.unpack_from('<I',frame,8)[0] == 5, 'first actual history shape')
    def line(raw):return ident+b'\t'+raw.hex().encode()+b'\n'
    def at(offset,value):return line(frame[:offset]+value+frame[offset+len(value):])
    # One row and one step have exact protocol offsets, built from the first
    # actual event; these are malformed transport controls, not new expectations.
    event=frame[12:66]
    row=event[:52]+b'\0'+struct.pack('<H',0)
    initial=b'TH01'+struct.pack('<I',1)+row+struct.pack('<I',0)
    reason_row=event[:52]+b'\0'+struct.pack('<H',2)+b'\1\1'
    values={
        'missing-LF':first[:-1], 'empty-line':b'\n', 'missing-tab':first.replace(b'\t',b' ',1),
        'empty-ID':first[first.index(b'\t'):], 'bad-ID':b'!'+first,
        'odd-hex':ident+b'\t0\n','bad-hex':ident+b'\tgg\n',
        'uppercase-hex':ident+b'\tAB\n','short-frame':line(frame[:-1]),
        'bad-magic':at(0,b'BAD!'),'trailing-frame':line(frame+b'\0'),
        'delay-option':at(65,b'\2'),'count-overflow':at(4,b'\xff'*4),
        'initial-invalid-time':line(initial[:48]+b'\0'*4+initial[52:]),
        'initial-invalid-bool':line(initial[:60]+b'\2'+initial[61:]),
        'duplicate-initial-key':line(b'TH01'+struct.pack('<I',2)+row+row+struct.pack('<I',0)),
        'duplicate-reasons':line(b'TH01'+struct.pack('<I',1)+reason_row+struct.pack('<I',0)),
        'CRLF':first.replace(b'\n',b'\r\n'),'invalid-UTF8':first+b'\xff\n',
        'later-malformed':first+b'BAD\tgg\n',
    }
    return first,values


def admit_amendment(expected_amendment_sha, supplied_source_freeze):
    """Bind this additive entrypoint and immutable original admission before/after work."""
    original_freeze = '054552ab23d80266b7ed7d6d13344d7b14cff6bb239bb8b6f6a40fc9d0b0deed'
    original_build = '43974fae650e4ab6f33d99c1853fc443cbec52d19f615ce3ac20dd70430e7a98'
    path = HERE / 'AMENDMENT.json'
    require(not path.is_symlink() and not any(parent.is_symlink() for parent in path.parents), 'amendment symlink')
    require(identity(path)['sha256'] == expected_amendment_sha, 'exact amendment identity')
    record = json.loads(path.read_text())
    require(record['original_source_freeze_sha256'] == supplied_source_freeze == original_freeze,
            'amendment original source freeze')
    require(identity(HERE / 'SOURCE-FREEZE.json')['sha256'] == original_freeze, 'original source freeze changed')
    require(record['original_build_sha256'] == original_build == identity(HERE / 'build.py')['sha256'],
            'original build changed')
    require(record['amended_entrypoint'] == 'build-amended.py' and Path(__file__).name == 'build-amended.py',
            'amendment entrypoint')
    require(record['amended_build_sha256'] == identity(Path(__file__))['sha256'], 'amended build changed')
    for name, expected in record['supporting_files'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'amendment supporting path')
        require(not (HERE / name).is_symlink() and identity(HERE / name) == expected,
                'amendment supporting file changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='fresh direct child of canonical /tmp')
    parser.add_argument('--private-map', type=Path, required=True, help='fresh path outside public packet')
    parser.add_argument('--source-freeze-sha', required=True)
    parser.add_argument('--amendment-sha', required=True)
    args = parser.parse_args()
    require(Path(__file__).absolute() == Path(__file__).resolve() and not Path(__file__).is_symlink(),
            'harness invocation must use its canonical nonsymlink path')
    toolchain = args.toolchain.resolve()
    lexical_out = args.out.absolute()
    require(not lexical_out.is_symlink(), "build output symlink")
    out = lexical_out.resolve()
    private_map = args.private_map.resolve()
    require(out.parent == Path('/tmp').resolve() and not out.exists(), 'fresh canonical /tmp output required')
    require(out != SOURCE.resolve() and out != HERE.resolve(), 'isolated build root')
    require(not private_map.exists() and not private_map.is_relative_to(PACKET), 'private mapping path')
    admit_amendment(args.amendment_sha, args.source_freeze_sha)
    freeze, manifest, lock = admit_sources(args.source_freeze_sha)
    original_source = (SOURCE / 'src/request_throttle.rs').read_text()
    variations = mutants(original_source)
    require(json.dumps([details for _,_,details in variations], sort_keys=True, separators=(',', ':')) == json.dumps(json.loads((HERE / 'MUTANTS.json').read_text()), sort_keys=True, separators=(',', ':')), 'exact frozen mutant matrix')
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
        launch_error_diagnostic = None
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
            stdout, stderr = b'', b''
            launch_error_diagnostic = str(error).encode()
            failure = 'launch errno=' + str(error.errno)
        commands.append({'label': label, 'argv': [logical(x) for x in argv], 'cwd': logical(cwd or out),
                         'completion': completion, 'exit_code': code,
                         'elapsed_seconds': round(time.monotonic() - started, 3),
                         'stdin': None if stdin is None else {'bytes': len(stdin), 'sha256': sha(stdin)},
                         'stdout': retain(stdout), 'stderr': retain(stderr), 'failure': failure,
                         'launch_error_diagnostic': None if launch_error_diagnostic is None else retain(launch_error_diagnostic)})
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
    static = run('post-source-static-replay', [sys.executable, '-B', PRE / 'verify.py', '--out', out / 'static-verification'])
    replay = json.loads((out / 'static-verification/validation.json').read_text())
    old = json.loads((PRE / 'validation/normal.json').read_text())
    require(replay['freeze_sha256'] == PRE_FREEZE, 'static final freeze binding')
    replay['freeze_sha256'] = None
    require(replay == old, 'static replay differs beyond declared phase marker')
    (receipts / 'static-replay.json').write_bytes(static)
    cases = [json.loads(line) for line in gzip.decompress((PRE / 'fixtures/cases.jsonl.gz').read_bytes()).splitlines()]
    corpus = {'case_count': len(cases), 'step_count': sum(len(c['steps']) for c in cases)}
    input_bytes = gzip.decompress((PRE / 'fixtures/inputs.tsv.gz').read_bytes())
    expected_bytes = gzip.decompress((PRE / 'fixtures/expected.tsv.gz').read_bytes())
    require(corpus == {'case_count':949,'step_count':3776}, 'frozen corpus denominators')
    require(len(input_bytes.splitlines()) == len(expected_bytes.splitlines()) == 949, 'whole frozen stream')
    controls = comparator_controls(expected_bytes)
    driver_controls = []
    compile_environments = {}
    snapshots = {}
    driver_snapshots = {}
    observations = {}
    first_artifacts = {}

    def build(label, profiles, test=False, altered=None):
        phase = (out / label).resolve()
        phase.mkdir()
        component = phase / 'component'
        shutil.copytree(SOURCE, component)
        if altered is not None:
            (component / 'src/request_throttle.rs').write_text(altered)
        client_source = phase / 'input_client.rs'
        shutil.copyfile(HERE / 'input_client.rs', client_source)
        require(not any(p.is_symlink() for p in component.rglob('*')), 'copied source symlink')
        before = inventory(component)
        expected_copy = dict(freeze['source'])
        if altered is not None:
            expected_copy['src/request_throttle.rs'] = {'bytes': len(altered.encode()), 'sha256': sha(altered.encode())}
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
                 '--remap-path-prefix=' + str(phase) + '=/request-throttle-build',
                 '--remap-path-prefix=' + str(toolchain) + '=/request-throttle-toolchain']
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
                    [('evidence_contract', ['test']), ('node94_consensus_admission', ['lib']), ('request_throttle', ['test'])], 'exact dependency-free targets')
            run(label + '-rustfmt-check', [toolchain / 'bin/rustfmt', '--edition', '2021', '--check',
                component / 'src/request_throttle.rs', component / 'tests/request_throttle.rs', client_source], component, env)
        results = {}
        for profile in profiles:
            release = ['--release'] if profile == 'release' else []
            run(label + '-' + profile + '-cargo-build', [toolchain / 'bin/cargo', 'build', '--offline', '--locked', '--lib', *release], component, env)
            rlib = phase / 'target' / profile / 'libnode94_consensus_admission.rlib'
            retained = phase / 'first-artifacts' / profile
            retained.mkdir(parents=True)
            shutil.copyfile(rlib, retained / rlib.name)
            first_artifacts[label + '/' + profile] = {'rlib': identity(rlib), 'path': logical(retained)}
            write_json(receipts / 'first-artifacts.json', first_artifacts)
            if test:
                run(label + '-' + profile + '-cargo-test-lib', [toolchain / 'bin/cargo', 'test', '--offline', '--locked', '--lib', *release], component, env)
                run(label + '-' + profile + '-cargo-test-request-throttle', [toolchain / 'bin/cargo', 'test', '--offline', '--locked', '--test', 'request_throttle', *release], component, env)
            rlib = phase / 'target' / profile / 'libnode94_consensus_admission.rlib'
            require(identity(rlib) == first_artifacts[label + '/' + profile]['rlib'], 'library changed after first artifact retention')
            client = phase / ('client-' + profile)
            run(label + '-' + profile + '-link-driver', [toolchain / 'bin/rustc', '--edition=2021',
                '--crate-name', 'request_throttle_input_client', client_source, '--extern',
                'node94_consensus_admission=' + str(rlib), '-L', 'dependency=' + str(phase / 'target' / profile / 'deps'),
                '-C', 'opt-level=' + ('3' if profile == 'release' else '0'), '-C',
                'debuginfo=' + ('0' if profile == 'release' else '2'), *flags, '-o', client], component, env)
            shutil.copyfile(client, retained / client.name)
            first_artifacts[label + '/' + profile]['driver'] = identity(client)
            write_json(receipts / 'first-artifacts.json', first_artifacts)
            output = run(label + '-' + profile + '-values', [client], component, env, input_bytes)
            result = compare(output, expected_bytes)
            require(output.endswith(b'\n'), 'complete LF-terminated value stream')
            actual_lines=output.splitlines(keepends=True); expected_lines=expected_bytes.splitlines(keepends=True)
            require(len(actual_lines)==len(cases), 'complete mutant/production stream')
            domain_counts={domain:0 for domain in ('native_corresponding_under_premises','new_safe_refusal')}
            for c,actual_line,expected_line in zip(cases,actual_lines,expected_lines):
                require(actual_line.split(b'\t',1)[0].decode()==c['id'], 'client full ordered IDs')
                decoded=json.loads(actual_line.split(b'\t',1)[1])
                require(isinstance(decoded,list) and len(decoded)==len(c['steps']), 'complete history output')
                canonical = c['id'].encode()+b'\t'+json.dumps(decoded,sort_keys=True,separators=(',',':')).encode()+b'\n'
                require(actual_line == canonical, 'canonical compact JSON line frame')
                if actual_line!=expected_line:domain_counts[c['domain']]+=1
            result['different_histories_by_domain']=domain_counts
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
            if altered is not None:
                if label.startswith('mutant-policy-'):
                    require(domain_counts['new_safe_refusal'] > 0 and domain_counts['native_corresponding_under_premises'] == 0,
                            'policy mutant must discriminate only new-policy histories: ' + label)
                else:
                    require(domain_counts['native_corresponding_under_premises'] > 0,
                            'native-conditional mutant lacks native-domain discrimination: ' + label)
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
            run(label + '-clippy', [toolchain / 'bin/cargo', 'clippy', '--offline', '--locked', '--lib', '--test', 'request_throttle', '--', '-D', 'warnings'], component, env)
        require(inventory(component) == before, 'copied component changed during build')
        snapshots[label] = before
        return results

    baseline = build('clean-one', ('debug', 'release'), test=True)
    require(all(row['comparison']['equal'] for row in baseline.values()), 'production corpus mismatch')
    rebuild = build('clean-two', ('debug', 'release'))
    require(all(row['comparison']['equal'] for row in rebuild.values()), 'clean rebuild corpus mismatch')
    require((out / 'clean-one').resolve() != (out / 'clean-two').resolve(), 'distinct clean roots')
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
    admit_amendment(args.amendment_sha, args.source_freeze_sha)
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
    result = {'source_freeze_sha256': args.source_freeze_sha, 'amendment_sha256': args.amendment_sha, 'amended_build_sha256': identity(Path(__file__))['sha256'], 'corpus_cases': corpus['case_count'], 'new_tests_per_profile': {'private':2,'integration':8}, 'baseline_library_tests':36,
              'baseline': baseline, 'independent_clean_directory_rebuild': rebuild,
              'own_build_byte_comparisons': own_byte_comparisons,
              'compiled_two_profile_mutants': mutation_results, 'comparator_controls': controls, 'input_driver_controls': driver_controls,
              'commands': len(commands), 'raw_stream_policy': 'Every stdout/stderr byte retained, content-addressed gzip; no output normalization or expected-file substitution.',
              'first_compiled_artifacts': first_artifacts, 'actual_source_unchanged': True, 'copied_source_unchanged': True,
              'original_pre_code_phase_unchanged': True,
              'scope': 'Host-compiled finite request-row state operation only under frozen native premises; no captured execution, native ABI/allocator/lock/log equivalence, live requests or consensus completeness.'}
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
