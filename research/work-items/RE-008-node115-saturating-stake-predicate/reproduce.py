#!/usr/bin/env python3
"""Build only the pinned authored stake component; compare stdin-only values.

No captured artifact, native verifier, reference or generator is executed.
--mutations additionally builds the twelve fixed release-only source variants.
Caller-supplied Cargo/rustc paths must be trusted installed executables. Their
recorded hashes and version checks establish identity, not executable safety.
Isolation is a clean graph/cwd/environment, not an operating-system sandbox.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types

SOURCE_PINS = {
    'Cargo.toml': '819ec89c303f8602098639a5017d692dacddb54e5147d6e0eb5da95589698e41',
    'Cargo.lock': 'fb340ef4281412b379210c295146c66a4dae1269a653129fddc9cf996bb8e8d1',
    'README.md': '2bb884162b8ced8b02d29d62da3a36601bf19b079312d6a771df6fba3280b928',
    'src/lib.rs': '2bc380ec6b23c593aee66d3356e7157c956edb80bb94e72b9f183905c6133b89',
    'src/main.rs': '8e03f6de50b324f7c10ea6dfd6faf4e34715075b4d517580df7f3fd9cdefc285',
}
SOURCE_FREEZE = '4203e5cbe053b143b5c012926371bc1b3bdf8462869d447ad8b5e2e06b119fd7'
COMPARATOR_SHA = '6c54e4539c16fc9cdf004bc52e15990d60d7b2673df9d6b5d3bbb680021b5f8e'
CORPUS_FREEZE_SHA = 'e97921cc0b00648319b053a661860cd3dc7ba5f10626dc355a0b1bd6d4070133'
STORAGE_SHA = 'a04fc75308342fdd1f67580add5bed33cd425b18826ef498ad42e8bb3ccfc0c4'
MUTATION_PINS = {
    'EXACT-EDITS.json': 'b9019416aa9bdeb5b306fc82f2ae8fad8613636d81a8dde9b00f078d44f811ce',
    'AUTHORING.json': '867cdd11ff2cd533a749bee045625c04e2c45f8b669332afcae5a2dab65feef8',
    'WITNESS-BINDINGS.json': '5c21bba5afe003d698eef00b39795a6aaad2760fc07ddbe4156f368618a52bac',
    'PORTABILITY.json': '91ff1fb50aece73b35f862267811ddf91ac06e75145f4b732e47a27f290e7a63',
}
IDS = [f'M{i:02d}' for i in range(1, 13)]


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    need(path.is_file() and not path.is_symlink(), 'regular file required: ' + str(path))


def read_pin(path, pin, limit=16 * 1024 * 1024):
    regular(path)
    need(path.stat().st_size <= limit, 'oversized admitted input')
    raw = path.read_bytes()
    need(sha(raw) == pin, 'input identity mismatch: ' + str(path))
    return raw


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def configs(path):
    observations = []
    for parent in (path, *path.parents):
        for candidate in (parent / '.cargo/config', parent / '.cargo/config.toml', parent / 'Cargo.toml'):
            present = candidate.exists() or candidate.is_symlink()
            observations.append({'path': str(candidate), 'present': present})
            need(not present, 'inherited Cargo configuration/workspace: ' + str(candidate))
    return observations


def source_graph(root, expected):
    need(root.is_dir() and not root.is_symlink(), 'source directory required')
    paths = list(root.rglob('*'))
    need(not any(p.is_symlink() for p in paths), 'source symlink')
    need({str(p.relative_to(root)) for p in paths if p.is_file()} == set(expected), 'exact five-file source graph required')
    return {name: read_pin(root / name, pin) for name, pin in expected.items()}


def load_corpus(packet):
    freeze = json.loads(read_pin(packet / 'corpus/CORPUS-FREEZE.json', CORPUS_FREEZE_SHA))
    storage = json.loads(read_pin(packet / 'corpus/STORAGE.json', STORAGE_SHA))
    stored = {item['destination']: item for item in storage['files']}
    need(len(freeze['entries']) == len(stored) == 8, 'corpus inventory')
    result = {}
    for entry in freeze['entries']:
        name = entry['path']
        need(Path(name).name == name and name not in result, 'corpus local filename')
        compressed = name in ('inputs.tsv', 'expected.tsv', 'index.jsonl')
        destination = 'corpus/' + name + ('.gz' if compressed else '')
        item = stored[destination]
        raw = read_pin(packet / destination, item['stored_sha256'])
        need(len(raw) == item['stored_bytes'], 'stored corpus size')
        if compressed:
            with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as stream:
                raw = stream.read(entry['bytes'] + 1)
        need(len(raw) == entry['bytes'] and sha(raw) == entry['sha256'], 'raw corpus identity')
        result[name] = raw
    return result


def load_mutations(packet, source, corpus):
    admitted = {name: read_pin(packet / 'mutations' / name, pin) for name, pin in MUTATION_PINS.items()}
    edits, author, witnesses = [json.loads(admitted[name]) for name in ('EXACT-EDITS.json', 'AUTHORING.json', 'WITNESS-BINDINGS.json')]
    need([x['id'] for x in edits['variants']] == IDS, 'fixed twelve mutation definitions')
    patches = {x['id']: x for x in author['patches']}
    witness_map = {x['id']: x for x in witnesses['cases']}
    need(set(patches) == set(witness_map) == set(IDS), 'mutation evidence inventory')
    inputs = {x.split(b'\t', 1)[0]: x for x in corpus['inputs.tsv'].splitlines(keepends=True)}
    expected = {x.split(b'\t', 1)[0]: x for x in corpus['expected.tsv'].splitlines(keepends=True)}
    need(len(inputs) == len(expected) == 8011, 'fixed corpus row inventory')
    prepared = []
    for variant in edits['variants']:
        ident = variant['id']; patch = patches[ident]; witness = witness_map[ident]
        changed = source['src/lib.rs'].decode('utf-8')
        for edit in variant['edits']:
            need(changed.count(edit['before']) == 1, 'exact mutation replacement count')
            changed = changed.replace(edit['before'], edit['after'], 1)
        changed = changed.encode('utf-8')
        need(changed != source['src/lib.rs'] and sha(changed) == patch['hypothetical_replacement_sha256'], 'fixed mutant source hash')
        need(patch['patch'] == ident + '/lib.patch', 'fixed patch path')
        patch_bytes = read_pin(packet / 'mutations' / patch['patch'], patch['patch_sha256'])
        need(len(patch_bytes) == patch['patch_bytes'], 'raw patch size')
        wid = variant['witness_id'].encode('ascii')
        need(wid.decode() == witness['canonical_corpus_id'], 'witness ID')
        need(sha(inputs[wid]) == witness['frozen_input_sha256'] and sha(expected[wid]) == witness['frozen_expected_sha256'], 'witness frozen rows')
        need(expected[wid] == ('\t'.join(witness['frozen_expected_fields']) + '\n').encode('ascii'), 'witness literal expectation')
        prepared.append((ident, changed, witness))
    return prepared


def checked_tool(path, name):
    need(path.is_absolute() and path.name == name, 'explicit absolute installed ' + name + ' path required')
    resolved = path.resolve(strict=True)
    regular(resolved)
    need(resolved.name == name and os.access(resolved, os.X_OK), 'direct executable required; no rustup shim')
    return resolved, {'requested': str(path), 'resolved': str(resolved), 'sha256': sha(resolved.read_bytes()), 'bytes': resolved.stat().st_size}


def unchanged_tools(tools):
    for path, info in tools.values():
        regular(path)
        need(sha(path.read_bytes()) == info['sha256'], 'tool changed during run')


def run(argv, cwd, env, stdin, directory, timeout, records):
    directory.mkdir()
    started = datetime.now(timezone.utc).isoformat()
    code, stdout, stderr, timed_out, launch_error = None, b'', b'', False, None
    try:
        child = subprocess.run(argv, input=stdin, cwd=cwd, env=env, shell=False,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        code, stdout, stderr = child.returncode, child.stdout, child.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout, stderr = error.stdout or b'', error.stderr or b''
    except OSError as error:
        launch_error = {'type': type(error).__name__, 'errno': error.errno}
        (directory / 'launch-error-diagnostic.txt').write_text(str(error) + '\n')
    (directory / 'stdout.bin').write_bytes(stdout)
    (directory / 'stderr.bin').write_bytes(stderr)
    receipt = {'argv': argv, 'cwd': str(cwd), 'environment': env,
               'started_utc': started, 'finished_utc': datetime.now(timezone.utc).isoformat(),
               'exit': code, 'timeout': timed_out, 'timeout_seconds': timeout,
               'timeout_scope': 'subprocess.run direct child; no process-tree cleanup guarantee',
               'launch_error': launch_error,
               'stdin_sha256': None if stdin is None else sha(stdin),
               'stdin_bytes': None if stdin is None else len(stdin),
               'stdout_sha256': sha(stdout), 'stdout_bytes': len(stdout),
               'stderr_sha256': sha(stderr), 'stderr_bytes': len(stderr)}
    if launch_error is not None:
        diagnostic = (directory / 'launch-error-diagnostic.txt').read_bytes()
        receipt['launch_error_diagnostic'] = {'path': 'launch-error-diagnostic.txt', 'bytes': len(diagnostic), 'sha256': sha(diagnostic)}
    save(directory / 'COMMAND.json', receipt)
    records.append(str(directory / 'COMMAND.json'))
    need(not timed_out and launch_error is None and code == 0, 'required child command failed; raw evidence retained')
    return stdout, stderr


def metadata_check(raw, copied, target):
    obj = json.loads(raw)
    packages = obj['packages']
    need(len(packages) == 1, 'resolved graph must have one package')
    package = packages[0]
    need(package['name'] == 'node115-stake-predicate' and package['version'] == '0.1.0', 'package identity')
    need(package['source'] is None and package['dependencies'] == [], 'no registry/path dependencies')
    need(Path(package['manifest_path']).resolve() == copied / 'Cargo.toml', 'resolved manifest')
    need(Path(obj['workspace_root']).resolve() == copied and Path(obj['target_directory']).resolve() == target, 'workspace/target identity')
    need(obj['workspace_members'] == [package['id']], 'workspace inventory')
    nodes = obj['resolve']['nodes']
    need(len(nodes) == 1 and nodes[0]['id'] == package['id'] and nodes[0]['dependencies'] == [] and nodes[0]['deps'] == [], 'resolved dependency edges')
    targets = {(x['name'], tuple(x['kind']), str(Path(x['src_path']).resolve())) for x in package['targets']}
    need(targets == {('node115_stake_predicate', ('lib',), str(copied / 'src/lib.rs')),
                     ('stake-predicate-driver', ('bin',), str(copied / 'src/main.rs'))}, 'exact library/bin targets; no build script')
    return {'packages': 1, 'dependency_edges': 0, 'workspace_root': str(copied), 'target_directory': str(target)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--mutations', action='store_true')
    args = parser.parse_args()
    packet = Path(__file__).resolve().parent
    repo = packet.parents[2]
    source_root = repo / 'src/node115-stake-predicate'
    need(args.out.is_absolute() and '..' not in args.out.parts, 'fresh absolute output path required')
    need(args.out.parent.is_dir() and not args.out.exists() and not args.out.is_symlink(), 'output parent must exist and output must be fresh')
    out = args.out.resolve()
    need(out != repo and repo not in out.parents, 'output must be outside repository')
    ancestor_audit = configs(args.out) + configs(out)
    out.mkdir()
    records, completed = [], []
    self_sha = sha(Path(__file__).read_bytes())
    try:
        source = source_graph(source_root, SOURCE_PINS)
        corpus = load_corpus(packet)
        comparator_source = read_pin(packet / 'comparator/compare_results.py', COMPARATOR_SHA)
        comparator = types.ModuleType('pinned_stake_parent_comparator')
        comparator.__file__ = str(packet / 'comparator/compare_results.py')
        exec(compile(comparator_source, comparator.__file__, 'exec'), comparator.__dict__)
        need(comparator.compare_bytes(corpus['expected.tsv'], corpus['expected.tsv'], 0, b'')['kind'] == 'match', 'frozen expected syntax')
        variants = load_mutations(packet, source, corpus) if args.mutations else []
        tools = {name: checked_tool(getattr(args, name), name) for name in ('cargo', 'rustc')}
        need(tools['cargo'][0] != tools['rustc'][0], 'direct distinct installed executables required')
        (out / 'inputs.tsv').write_bytes(corpus['inputs.tsv'])
        (out / 'expected.tsv').write_bytes(corpus['expected.tsv'])
        probe_cwd, probe_home = out / 'version-cwd', out / 'version-cargo-home'
        probe_cwd.mkdir(); probe_home.mkdir()
        tool_dirs = list(dict.fromkeys(str(tools[n][0].parent) for n in ('rustc', 'cargo')))
        build_base = {'PATH': ':'.join(tool_dirs + ['/usr/bin', '/bin']), 'LANG': 'C', 'LC_ALL': 'C',
                      'CARGO_NET_OFFLINE': 'true', 'RUSTC': str(tools['rustc'][0]), 'CARGO_HOME': str(probe_home)}
        save(out / 'ADMISSION.json', {'source_freeze_sha256': SOURCE_FREEZE, 'source_pins': SOURCE_PINS,
             'corpus_freeze_sha256': CORPUS_FREEZE_SHA, 'storage_sha256': STORAGE_SHA,
             'comparator_sha256': COMPARATOR_SHA, 'mutations': args.mutations,
             'mutation_pins': MUTATION_PINS if args.mutations else {},
             'tool_identities': {n: info for n, (_, info) in tools.items()}, 'ancestor_audit': ancestor_audit,
             'runner_sha256': self_sha, 'expected_data_in_child': False, 'runtime_environment': {},
             'filesystem_sandbox': False, 'captured_execution': False})
        for name in ('cargo', 'rustc'):
            unchanged_tools(tools)
            stdout, stderr = run([str(tools[name][0]), '--version'], probe_cwd, build_base, None, out / (name + '-version'), 30, records)
            need(not stderr and re.fullmatch(name.encode() + rb' 1\.95\.0 [^\r\n]+\n', stdout) is not None, 'installed tool version must be1.95.0')
            need(not any(probe_cwd.iterdir()), 'version cwd changed')
        prepared = [('baseline', source['src/lib.rs'], None)] + variants
        for ident, lib_bytes, witness in prepared:
            role = out / ident; role.mkdir()
            copied, cwd, cargo_home, target = role / 'source', role / 'empty-cwd', role / 'cargo-home', role / 'target'
            cwd.mkdir(); cargo_home.mkdir()
            audit = configs(cwd) + configs(cargo_home) + configs(target)
            for name, content in source.items():
                destination = copied / name; destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(lib_bytes if name == 'src/lib.rs' else content)
            role_pins = dict(SOURCE_PINS); role_pins['src/lib.rs'] = sha(lib_bytes)
            source_graph(copied, role_pins)
            env = dict(build_base, CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(target),
                       RUSTFLAGS='--remap-path-prefix=' + str(copied) + '=/stake-source')
            common = ['--offline', '--locked', '--manifest-path', str(copied / 'Cargo.toml')]
            unchanged_tools(tools)
            metadata_raw, _ = run([str(tools['cargo'][0]), 'metadata', *common, '--format-version', '1'], cwd, env, None, role / 'metadata', 120, records)
            graph = metadata_check(metadata_raw, copied, target)
            save(role / 'GRAPH.json', {'metadata': graph, 'source_pins': role_pins, 'ancestor_audit': audit})
            unchanged_tools(tools)
            run([str(tools['cargo'][0]), 'build', *common, '--release', '--target-dir', str(target)], cwd, env, None, role / 'build', 120, records)
            source_graph(copied, role_pins)
            binary = target / 'release/stake-predicate-driver'
            regular(binary); binary_sha = sha(binary.read_bytes())
            save(role / 'BINARY.json', {'path': str(binary), 'bytes': binary.stat().st_size,
                                      'sha256': binary_sha, 'source_pins': role_pins})
            need(not any(cwd.iterdir()), 'build cwd changed')
            stdout, stderr = run([str(binary)], cwd, {}, corpus['inputs.tsv'], role / 'driver', 30, records)
            comparison = comparator.compare_bytes(corpus['expected.tsv'], stdout, 0, stderr)
            save(role / 'comparison.json', comparison)
            wanted = 'match' if witness is None else 'value_mismatch'
            need(comparison['kind'] == wanted and comparison['actual_rows'] == 8011, 'not complete qualified value outcome')
            result = {'id': ident, 'profile': 'release', 'binary_sha256': binary_sha,
                      'lib_sha256': sha(lib_bytes), 'rows': 8011, 'kind': wanted,
                      'mismatch_count': comparison['mismatch_count'], 'stdout_sha256': sha(stdout),
                      'stderr_sha256': sha(stderr), 'build_exit': 0, 'driver_exit': 0}
            if witness is not None:
                actual = {line.split(b'\t', 1)[0]: line for line in stdout.splitlines(keepends=True)}
                wid = witness['canonical_corpus_id'].encode('ascii')
                expected_line = ('\t'.join(witness['frozen_expected_fields']) + '\n').encode('ascii')
                prediction = ('\t'.join(witness['anticipated_mutant_fields_not_executed']) + '\n').encode('ascii')
                need(actual[wid] != expected_line and actual[wid] == prediction, 'named witness must differ exactly as declared')
                result.update(witness_id=wid.decode(), witness_actual=actual[wid].decode().rstrip('\n'), qualified_detection=True)
            need(sha(binary.read_bytes()) == binary_sha and not any(cwd.iterdir()), 'driver binary/cwd changed')
            source_graph(copied, role_pins)
            completed.append(result)
            save(out / 'PROGRESS.json', completed)
        source_graph(source_root, SOURCE_PINS)
        need(load_corpus(packet) == corpus, 'public corpus changed')
        read_pin(packet / 'comparator/compare_results.py', COMPARATOR_SHA)
        if args.mutations:
            load_mutations(packet, source, corpus)
        unchanged_tools(tools)
        need(sha(Path(__file__).read_bytes()) == self_sha, 'runner changed during run')
        save(out / 'RESULTS.json', {'passed': True, 'records': completed, 'commands': records,
             'command_count': len(records), 'mutations_requested': args.mutations,
             'qualified_mutants': len(completed) - 1, 'source_and_inputs_unchanged': True,
             'captured_execution': False, 'linux_execution': False,
             'limits': 'Release-only finite source/reference comparison. No static control, generator, transport, debug-repeat or Linux execution. No whole-node or runtime native equivalence.'})
        print(json.dumps({'passed': True, 'commands': len(records), 'baseline_rows': 8011, 'qualified_mutants': len(completed) - 1}))
        return 0
    except Exception as error:
        save(out / 'ABORT.json', {'passed': False, 'exception': type(error).__name__, 'diagnostic': str(error),
                                'completed_roles': len(completed), 'commands': records,
                                'prior_results_preserved': True, 'no_retry': True})
        raise


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({'passed': False, 'exception': type(error).__name__, 'diagnostic': str(error)}), file=sys.stderr)
        sys.exit(2)
