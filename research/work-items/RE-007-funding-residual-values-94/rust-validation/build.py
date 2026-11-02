#!/usr/bin/env python3
"""Qualify only independently authored residual Rust, after a separate build gate.

MIT orchestration mechanics adapted from our RE-013-visor-keccak-value-closure
build.py SHA3f2d9755c41a55e688893ab36264ee21af4ef3b62ab7d9d430d1a569f9e5d065.
No production algorithm or oracle is imported from that package. Compiled bytes
are private; only unchanged stdout/stderr and identities may be published.
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
from qualification import compare, comparator_controls, malformed_inputs, mutate, need, sha

HERE = Path(__file__).resolve().parent
PACKET = HERE.parent
ROOT = PACKET.parents[2]
SOURCE = ROOT / 'src/node94-funding-residual-values'
PRE_FREEZE = '122007baa10ea76e4bcaa84320e68fe5f484157db5cb7609dcf1fc0b83d4cc1e'


def identity(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=sha(raw))


def inventory(root):
    return {str(p.relative_to(root)): identity(p) for p in sorted(root.rglob('*')) if p.is_file()}


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')


def admit(expected):
    need(identity(PACKET/'PRE-RUST-FREEZE.json')['sha256'] == PRE_FREEZE, 'precode freeze')
    pre = json.loads((PACKET/'PRE-RUST-FREEZE.json').read_text())
    need(len(pre['files']) == 88, 'precode census')
    for name, digest in pre['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'precode path')
        need(not (PACKET/name).is_symlink() and identity(PACKET/name)['sha256'] == digest, 'precode changed: '+name)
    for name, digest in json.loads((PACKET/'dependencies.json').read_text()).items():
        need(not (ROOT/name).is_symlink() and identity(ROOT/name)['sha256'] == digest, 'static parser dependency')
    need(identity(HERE/'SOURCE-FREEZE.json')['sha256'] == expected, 'source freeze')
    freeze = json.loads((HERE/'SOURCE-FREEZE.json').read_text())
    need(not any(p.is_symlink() for p in [SOURCE, *SOURCE.parents]), 'source ancestor link')
    need(not any(p.is_symlink() for p in SOURCE.rglob('*')), 'source link')
    need(inventory(SOURCE) == freeze['source'] and len(freeze['source']) == 5, 'complete source graph')
    for name, expected_file in freeze['harness'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'harness path')
        need(not (HERE/name).is_symlink() and identity(HERE/name) == expected_file, 'harness changed: '+name)
    manifest = tomllib.loads((SOURCE/'Cargo.toml').read_text())
    lock = tomllib.loads((SOURCE/'Cargo.lock').read_text())
    need(set(manifest) == {'package', 'lib', 'dependencies'} and manifest['dependencies'] == {} and
         manifest['lib'] == {'path': 'src/lib.rs'} and 'build' not in manifest['package'], 'manifest hooks')
    need(lock['package'] == [{'name': 'node94-funding-residual-values', 'version': '0.1.0'}], 'lock graph')
    return freeze, manifest, lock


def main():
    ap = argparse.ArgumentParser()
    for name in ['toolchain', 'out', 'private-map']:
        ap.add_argument('--'+name, type=Path, required=True)
    ap.add_argument('--source-freeze-sha', required=True)
    args = ap.parse_args()
    need(Path(__file__).absolute() == HERE/'build.py', 'canonical harness invocation')
    freeze, manifest, lock = admit(args.source_freeze_sha)
    lexical = args.out.absolute()
    out = lexical.resolve()
    private = args.private_map.resolve()
    toolchain = args.toolchain.resolve()
    need(out.parent == Path('/tmp').resolve() and not out.exists() and not lexical.is_symlink(), 'fresh direct tmp output')
    need(not private.exists() and not private.is_relative_to(PACKET), 'fresh private map')
    pins = json.loads((HERE/'TOOLCHAIN-PINS.json').read_text())
    def tool_files():
        return {directory+'/'+name: value for directory in ['bin', 'lib'] for name, value in inventory(toolchain/directory).items()}
    def tool_links():
        return {str(p.relative_to(toolchain)): os.readlink(p) for directory in ['bin', 'lib'] for p in (toolchain/directory).rglob('*') if p.is_symlink()}
    need(tool_files() == pins['payload_files'] and tool_links() == pins['symlinks'], 'toolchain payload identity')
    variants = mutate((SOURCE/'src/lib.rs').read_text(), json.loads((HERE/'MUTANTS.json').read_text()))
    out.mkdir(mode=0o700)
    receipts = out/'receipts'
    (receipts/'raw').mkdir(parents=True)
    (out/'compiled-private').mkdir()
    cargo_home = out/'cargo-home'
    cargo_home.mkdir()
    mapping = {'<BUILD>': str(out), '<BUILD_LEXICAL>': str(lexical), '<TOOLCHAIN>': str(toolchain),
               '<SOURCE>': str(SOURCE), '<PACKET>': str(PACKET), '<REPO>': str(ROOT)}
    for i, parent in enumerate(ROOT.parents):
        if str(parent) not in ('/', '/Users', '/home'):
            mapping[f'<REPO_PARENT_{i}>'] = str(parent)
    write(private, dict(logical_to_private=mapping))
    def logical(value):
        text = str(value)
        for token, original in sorted(mapping.items(), key=lambda item: -len(item[1])):
            text = text.replace(original, token)
        return text
    env0 = {'PATH': str(toolchain/'bin')+':/usr/bin:/bin:/usr/sbin:/sbin', 'CARGO_HOME': str(cargo_home),
            'RUSTC': str(toolchain/'bin/rustc'), 'RUSTDOC': str(toolchain/'bin/rustdoc'),
            'CARGO_NET_OFFLINE': 'true', 'CARGO_INCREMENTAL': '0', 'CARGO_TERM_COLOR': 'never',
            'CARGO_BUILD_JOBS': '2', 'RUST_TEST_THREADS': '2', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
            'PYTHONDONTWRITEBYTECODE': '1', 'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'}
    if 'HOME' in os.environ:
        env0['HOME'] = os.environ['HOME']  # Preserve real HOME; use only fresh CARGO_HOME for Cargo.
    configs, manifests, alias_paths = set(), {}, {}
    def ancestors(start):
        for location in {start.absolute(), start.resolve()}:
            for directory in [location, *location.parents]:
                if directory.is_symlink():
                    need(directory == Path('/tmp') and directory.resolve() == Path('/private/tmp'), 'unexpected ancestor link')
                    alias_paths[str(directory)] = os.readlink(directory)
                for name in ['config', 'config.toml']:
                    config = directory/'.cargo'/name
                    need(not config.exists() and not config.is_symlink(), 'ancestor Cargo config')
                    configs.add(logical(config))
                path = directory/'Cargo.toml'
                need(not path.is_symlink(), 'ancestor manifest link')
                if path.exists():
                    need('workspace' not in tomllib.loads(path.read_text()), 'ancestor workspace')
                    manifests[logical(path)] = identity(path)
                else:
                    manifests[logical(path)] = dict(state='absent')
    for location in [lexical, out, SOURCE, HERE]:
        ancestors(location)
    commands = []
    def retain(raw):
        digest = sha(raw)
        p = receipts/'raw'/(digest+'.gz')
        if not p.exists():
            p.write_bytes(gzip.compress(raw, mtime=0))
        return dict(bytes=len(raw), sha256=digest, gzip_ref='raw/'+digest+'.gz')
    def run(label, argv, cwd=None, env=None, stdin=None, allowed=(0,), timeout=300):
        used = env or env0
        row = dict(label=label, argv=[logical(v) for v in argv], cwd=logical(cwd or out), completion='launching',
                   stdin=None if stdin is None else dict(bytes=len(stdin), sha256=sha(stdin)))
        commands.append(row)
        write(receipts/'commands.json', commands)
        started = time.monotonic()
        diagnostic = None
        try:
            result = subprocess.run(list(map(str, argv)), cwd=cwd or out, env=used, input=stdin, capture_output=True, timeout=timeout)
            stdout, stderr, code, completion = result.stdout, result.stderr, result.returncode, 'completed'
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code, completion = error.stdout or b'', error.stderr or b'', None, 'timeout'
        except OSError as error:
            stdout, stderr, code, completion = b'', b'', None, 'launch-error'
            diagnostic = retain(str(error).encode())
        row.update(completion=completion, exit_code=code, elapsed_seconds=round(time.monotonic()-started, 3),
                   stdout=retain(stdout), stderr=retain(stderr), launch_error_diagnostic=diagnostic)
        write(receipts/'commands.json', commands)
        for raw in [stdout, stderr]:
            need('HOME' not in used or used['HOME'].encode() not in raw, 'private home in retained stream: '+label)
        need(completion == 'completed' and code in allowed, 'command failed: '+label)
        return stdout
    for name, flag in [('cargo', '--version'), ('rustc', '-vV'), ('rustdoc', '--version'), ('rustfmt', '--version')]:
        run(name+'-version', [toolchain/'bin'/name, flag])
    run('clang-version', ['/usr/bin/clang', '--version'])
    sdk = run('sdk-path', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()
    env0['SDKROOT'] = sdk
    run('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'])
    external = {}
    for name in ['clang', 'ld']:
        path = Path(run('resolved-'+name, ['/usr/bin/xcrun', '--find', name]).decode().strip())
        external[str(path)] = identity(path)
    for name in ['/usr/bin/clang', '/usr/bin/xcrun', '/usr/bin/ld', '/usr/bin/ar', sys.executable]:
        external[logical(name)] = identity(Path(name))
    sdk_inputs = {name: identity(Path(sdk)/name) for name in ['SDKSettings.json', 'usr/lib/libSystem.tbd']}
    run('unchanged-static-replay', [sys.executable, '-B', PACKET/'verify.py', '--binary', ROOT/'artifacts/node/94/hl-node',
                                  '--out', receipts/'static-replay'], timeout=1800)
    expected_static = json.loads((PACKET/'validation/pre-freeze.json').read_text())
    expected_static['freeze_sha256'] = PRE_FREEZE  # Historical receipt predates the freeze; only this field is additive.
    need(json.loads((receipts/'static-replay/validation.json').read_text()) == expected_static, 'static replay differs')
    inputs = gzip.decompress((PACKET/'fixtures/vectors.tsv.gz').read_bytes())
    expected = gzip.decompress((PACKET/'fixtures/expected.tsv.gz').read_bytes())
    ids = [line.split(b'\t')[0] for line in inputs.splitlines()]
    need(len(ids) == len(set(ids)) == 912, 'frozen input census')
    cases = [json.loads(line) for line in gzip.decompress((PACKET/'fixtures/cases.jsonl.gz').read_bytes()).splitlines()]
    domains = [case['domain'] for case in cases]
    need(len(cases) == 912 and domains.count('native_corresponding') == 853 and domains.count('safe_policy') == 59, 'frozen domain census')
    need(ids == [f'C{i:06d}'.encode() for i in range(912)], 'frozen case/domain alignment')
    controls = comparator_controls(expected, ids)
    source_copies, environments, observations, artifacts, input_controls = {}, {}, {}, [], []
    def archive(path, label):
        raw = path.read_bytes()
        digest = sha(raw)
        saved = out/'compiled-private'/(digest+'.gz')
        if not saved.exists():
            saved.write_bytes(gzip.compress(raw, mtime=0))
        need(gzip.decompress(saved.read_bytes()) == raw, 'private artifact retention')
        row = dict(label=label, bytes=len(raw), sha256=digest, private_gzip=logical(saved), stored_sha256=sha(saved.read_bytes()),
                   public_bytes_distributed=False, private_home_prefix_present='HOME' in env0 and env0['HOME'].encode() in raw,
                   canonical_build_prefix_present=str(out).encode() in raw)
        artifacts.append(row)
        write(receipts/'compiled-artifact-identities.json', artifacts)
        return row
    def build(label, changed=None, test=False, repeat=False):
        phase = out/label
        record = label+('-same-path-repeat' if repeat else '')
        component = phase/'src/node94-funding-residual-values'
        driver = phase/'input_client.rs'
        if repeat:
            for profile in ['debug', 'release']:
                for kind, path in [('rlib', phase/'target'/profile/'libnode94_funding_residual_values.rlib'), ('client', phase/('client-'+profile))]:
                    matches = [x for x in artifacts if x['label'] == label+'/'+profile+'/'+kind]
                    need(len(matches) == 1, 'unique retained original')
                    item = matches[0]
                    saved = out/'compiled-private'/(item['sha256']+'.gz')
                    need(identity(path) == {k: item[k] for k in ['bytes', 'sha256']} and
                         sha(saved.read_bytes()) == item['stored_sha256'] and gzip.decompress(saved.read_bytes()) == path.read_bytes(), 'before-repeat originals')
            shutil.rmtree(phase/'target')
            for profile in ['debug', 'release']:
                (phase/('client-'+profile)).unlink()
        else:
            component.parent.mkdir(parents=True)
            shutil.copytree(SOURCE, component)
            shutil.copyfile(HERE/'input_client.rs', driver)
            if changed is not None:
                (component/'src/lib.rs').write_text(changed)
        need(not any(p.is_symlink() for p in phase.rglob('*')), 'copied graph link')
        wanted = dict(freeze['source'])
        if changed is not None:
            wanted['src/lib.rs'] = dict(bytes=len(changed.encode()), sha256=sha(changed.encode()))
        need(inventory(component) == wanted and identity(driver) == freeze['harness']['input_client.rs'], 'exact copied source/client')
        source_copies[record] = dict(source=inventory(component), client=identity(driver))
        write(receipts/'source-copies.json', source_copies)
        ancestors(component)
        ancestors(lexical/label/'src/node94-funding-residual-values')
        flags = ['-Dwarnings', '-C', 'overflow-checks=on', '-C', 'linker=/usr/bin/clang',
                 '--remap-path-prefix='+str(phase)+'=/residual-build',
                 '--remap-path-prefix='+str(lexical/label)+'=/residual-build',
                 '--remap-path-prefix='+str(toolchain)+'=/residual-toolchain']
        env = dict(env0, CARGO_TARGET_DIR=str(phase/'target'), CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags))
        environments[record] = {k: ('<ORIGINAL_HOME_UNCHANGED_NOT_RECORDED>' if k == 'HOME' else logical(v)) for k, v in env.items()}
        write(receipts/'compile-environments.json', environments)
        if changed is None:
            metadata = json.loads(run(record+'-metadata', [toolchain/'bin/cargo', 'metadata', '--offline', '--locked', '--format-version', '1'], component, env))
            need(len(metadata['packages']) == len(metadata['workspace_members']) == 1 and Path(metadata['workspace_root']).resolve() == component, 'real standalone graph')
            package = metadata['packages'][0]
            need(package['source'] is None and package['dependencies'] == [] and
                 sorted((t['name'], t['kind']) for t in package['targets']) == [('node94_funding_residual_values', ['lib']), ('residual_vectors', ['test'])], 'actual lib/test targets')
            run(record+'-format-check', [toolchain/'bin/rustfmt', '--edition', '2024', '--check', component/'src/lib.rs', component/'tests/residual_vectors.rs', driver], component, env)
        result = {}
        for profile in ['debug', 'release']:
            release = ['--release'] if profile == 'release' else []
            run(record+'-'+profile+'-build', [toolchain/'bin/cargo', 'build', '--offline', '--locked', '--lib', *release], component, env)
            if test:
                run(record+'-'+profile+'-tests', [toolchain/'bin/cargo', 'test', '--offline', '--locked', '--all-targets', *release], component, env)
            rlib = phase/'target'/profile/'libnode94_funding_residual_values.rlib'
            client = phase/('client-'+profile)
            rlib_identity = archive(rlib, record+'/'+profile+'/rlib')  # Preserve even if client linking fails.
            run(record+'-'+profile+'-link-client', [toolchain/'bin/rustc', '--edition=2024', '--crate-name', 'residual_input_client', driver,
                '--extern', 'node94_funding_residual_values='+str(rlib), '-L', 'dependency='+str(phase/'target'/profile/'deps'),
                '-C', 'opt-level='+('3' if profile == 'release' else '0'), '-C', 'debuginfo='+('0' if profile == 'release' else '2'), *flags, '-o', client], component, env)
            client_identity = archive(client, record+'/'+profile+'/client')
            raw = run(record+'-'+profile+'-values', [client], component, env, inputs)
            observation = compare(raw, expected, ids, domains)
            result[profile] = dict(comparison=observation, rlib=rlib_identity, client=client_identity)
            observations[record] = result
            write(receipts/'build-results.json', observations)
            need(observation['equal'] if changed is None else not observation['equal'], 'complete value qualification: '+record+'/'+profile)
            if label == 'clean-one' and not repeat and profile == 'debug':
                for name, bad in malformed_inputs().items():
                    raw = run('malformed-'+name, [client], component, env, bad, allowed=(2,))
                    need(raw == b'', 'malformed partial output')
                    input_controls.append(dict(name=name, exit_code=2, input_sha256=sha(bad), stdout_bytes=0))
                raw = run('extra-argument', [client, 'unexpected'], component, env, b'', allowed=(2,))
                need(raw == b'', 'argument output')
                input_controls.append(dict(name='extra-argument', exit_code=2, stdout_bytes=0))
                raw = run('empty-input', [client], component, env, b'')
                need(raw == b'', 'empty output')
                input_controls.append(dict(name='empty-input', exit_code=0, stdout_bytes=0))
        need(inventory(component) == wanted and identity(driver) == freeze['harness']['input_client.rs'], 'build changed source/client')
        return result
    baseline = build('clean-one', test=True)
    repeated = build('clean-one', repeat=True)
    separate = build('clean-two')
    def equal(a, b):
        return {profile: {kind: a[profile][kind]['sha256'] == b[profile][kind]['sha256'] for kind in ['rlib', 'client']} for profile in ['debug', 'release']}
    same_path = equal(baseline, repeated)
    need(all(value for row in same_path.values() for value in row.values()), 'same-path raw artifact inequality; retained originals and repeats')
    mutation_results = []
    for name, changed, definition in variants:
        result = build('mutant-'+name, changed=changed)
        for profile, observation in result.items():
            differences = observation['comparison']['different_rows_by_domain']
            if definition['expected_domain'] == 'native_corresponding':
                need(differences['native_corresponding'] > 0, 'native-domain mutation not distinguished: '+name+'/'+profile)
            else:
                need(differences['safe_policy'] > 0 and differences['native_corresponding'] == 0, 'policy-only mutation domain: '+name+'/'+profile)
        mutation_results.append(dict(definition=definition, profiles=result))
        print('compiled complete-stream mutant detected: '+name, flush=True)
    need(tool_files() == pins['payload_files'] and tool_links() == pins['symlinks'], 'toolchain changed')
    for name, expected_file in external.items():
        for token, original in mapping.items():
            name = name.replace(token, original)
        need(identity(Path(name)) == expected_file, 'external tool changed')
    need({name: identity(Path(sdk)/name) for name in sdk_inputs} == sdk_inputs, 'selected SDK changed')
    admit(args.source_freeze_sha)
    write(receipts/'build-audit.json', dict(source_freeze_sha256=args.source_freeze_sha, manifest=manifest, lock=lock,
          configs_absent=sorted(configs), ancestor_manifests=manifests, ancestor_aliases=alias_paths,
          external_tools=external, SDKROOT=sdk, sdk_inputs=sdk_inputs, toolchain_payloads_unchanged=True,
          limit='Pinned bin/lib and selected linker/SDK files, not hermetic OS/dyld/full SDK or target compiler equivalence.'))
    result = dict(source_freeze_sha256=args.source_freeze_sha, cases=912, native_conditional_cases=853, safe_policy_cases=59,
                  baseline=baseline, same_path_clean_repeat=repeated, separate_directory_rebuild=separate,
                  exact_raw_comparisons=dict(same_path=same_path, separate_directory=equal(baseline, separate), masks=[], normalization=None),
                  mutants=mutation_results, comparator_controls=controls, input_controls=input_controls, commands=len(commands),
                  value_streams=6+2*len(variants), source_unchanged=True, precode_unchanged=True,
                  scope='Independently authored Rust and input-only client; no captured execution or universal finite-corpus equivalence.')
    write(receipts/'results.json', result)
    print(json.dumps(dict(status='PASS actual host qualification', commands=len(commands), cases=912, mutants=len(variants), value_streams=result['value_streams'], receipts=logical(receipts))))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
