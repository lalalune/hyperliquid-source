#!/usr/bin/env python3
"""Replay real LFS checkout with cached pinned inputs and isolated Git config.

Run after materializing the source checkout. No captured executable is run.
All Git transports except local files are disabled; cache misses fail closed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

BASE = '1f8c67c63ca4794c9689235471c60297f8a5c985'
REFERENCE = 'references/can1357-hl'
TARGETS = ('artifacts/node/94/hl-node', REFERENCE + '/bin/hl-node-mainnet-new')
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[3])
    root = parser.parse_args().root.resolve()
    for name in TARGETS:
        if digest(root / name) != SHA256:
            raise ValueError('Materialize and verify the pinned source checkout first')
    environment = {k: os.environ[k] for k in ('HOME', 'PATH', 'USER', 'LOGNAME', 'TMPDIR') if k in os.environ}
    records = []
    with tempfile.TemporaryDirectory(prefix='hl-lfs-repro-') as temporary:
        stage = Path(temporary)
        empty = stage / 'empty.gitconfig'
        empty.touch()
        environment.update(GIT_CONFIG_GLOBAL=str(empty), GIT_CONFIG_NOSYSTEM='1',
                           GIT_ALLOW_PROTOCOL='file', GIT_TERMINAL_PROMPT='0', LC_ALL='C')

        def run(command, cwd=root, expected=0):
            result = subprocess.run(command, cwd=cwd, env=environment, text=True,
                                    capture_output=True, timeout=120)
            if expected is not None and result.returncode != expected:
                raise RuntimeError(f'{command[0]} exited {result.returncode}: {result.stderr}')
            return result

        clone = stage / 'checkout'
        environment['GIT_LFS_SKIP_SMUDGE'] = '1'
        run(['git', 'clone', '--shared', '--no-checkout', str(root), str(clone)])
        run(['git', 'checkout', '--detach', BASE], clone)
        repositories = json.loads((root / 'provenance/sources.json').read_text())['repositories']
        for repository in repositories:
            name = repository['path']
            run(['git', 'config', 'submodule.' + name + '.url', str(root / name)], clone)
        run(['git', 'submodule', 'update', '--init', '--recursive'], clone)
        del environment['GIT_LFS_SKIP_SMUDGE']
        for relative in ('', REFERENCE):
            source = root / relative
            path = Path(run(['git', 'rev-parse', '--git-path', 'lfs/objects'], source).stdout.strip())
            cache = path if path.is_absolute() else source / path
            destination = Path(run(['git', 'rev-parse', '--git-path', 'lfs/objects'], clone / relative).stdout.strip())
            if not destination.is_absolute():
                destination = clone / relative / destination
            shutil.copytree(cache, destination, dirs_exist_ok=True)

        def phase(name, accepted):
            pulled = run(['make', 'pull'], clone)
            checked = run(['make', 'verify'], clone, expected=None)
            normalize = lambda text: text.replace(str(root), '<source>').replace(temporary, '<fixture>')
            if (checked.returncode == 0) != accepted:
                raise RuntimeError('Unexpected artifact verification outcome:\n' +
                                   normalize(checked.stdout + checked.stderr))
            files = {p: {'size': (clone / p).stat().st_size, 'sha256': digest(clone / p)} for p in TARGETS}
            records.append({'phase': name, 'pull_exit': pulled.returncode,
                            'verify_exit': checked.returncode, 'targets': files,
                            'pull_output': normalize(pulled.stdout + pulled.stderr),
                            'verify_output': normalize(checked.stdout + checked.stderr)})

        phase('base_without_filters', False)
        if not all(value['size'] == 133 for value in records[-1]['targets'].values()):
            raise RuntimeError('Expected both retained LFS pointers')
        if 'Artifact size/SHA-256 mismatch' not in records[-1]['verify_output']:
            raise RuntimeError('Base failed for a different reason')
        run(['git', 'lfs', 'install', '--local'], clone)
        phase('base_with_parent_filters_only', False)
        if (records[-1]['targets'][TARGETS[0]]['sha256'] != SHA256 or
                records[-1]['targets'][TARGETS[1]]['size'] != 133 or
                'Pinned upstream mismatch' not in records[-1]['verify_output']):
            raise RuntimeError('Parent-only setup failed for a different reason')
        run(['git', 'config', '--local', '--remove-section', 'filter.lfs'], clone)
        pointer = run(['git', 'show', BASE + ':' + TARGETS[0]], clone).stdout.encode('ascii')
        (clone / TARGETS[0]).write_bytes(pointer)
        if len(pointer) != 133:
            raise RuntimeError('Expected the authentic parent LFS pointer')
        shutil.copyfile(root / 'Makefile', clone / 'Makefile')
        phase('candidate', True)
        phase('candidate_repeated', True)
        if records[2]['targets'] != records[3]['targets'] or any(
                value['sha256'] != SHA256 for value in records[3]['targets'].values()):
            raise RuntimeError('Pinned target bytes changed')
        if empty.read_bytes():
            raise RuntimeError('Global configuration changed')
        for repository in repositories:
            location = clone / repository['path']
            if run(['git', 'rev-parse', 'HEAD'], location).stdout.strip() != repository['commit']:
                raise RuntimeError('Submodule pin changed')
            if run(['git', 'status', '--porcelain'], location).stdout:
                raise RuntimeError('Submodule contents changed')
    for name in TARGETS:
        if digest(root / name) != SHA256:
            raise RuntimeError('Source input changed')
    print(json.dumps({'base': BASE, 'target_sha256': SHA256,
                      'candidate_sha256': {p: digest(root / p) for p in
                          ('Makefile', 'scripts/setup.sh',
                           'research/work-items/RE-002-local-lfs/reproduce.py')},
                      'git_lfs': run(['git', 'lfs', 'version']).stdout.strip(),
                      'global_config_unchanged': True, 'submodule_pins_unchanged': True,
                      'captured_binaries_executed': False, 'phases': records}, indent=2))


if __name__ == '__main__':
    main()
