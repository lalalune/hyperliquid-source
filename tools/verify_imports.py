#!/usr/bin/env python3
"""Verify immutable imported files and source repository commit pins."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from artifacts import check

SETUP = 'run git submodule update --init --recursive'


def git(root, path, *args, env=None):
    env = dict(os.environ if env is None else env, GIT_OPTIONAL_LOCKS='0')
    try:
        return subprocess.check_output(['git', '-C', str(root / path), *args], text=True, stderr=subprocess.DEVNULL, env=env, encoding='utf-8').strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise ValueError(f'Unreadable pinned source: {path}; {SETUP}') from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate key in provenance manifest: {key}')
        result[key] = value
    return result


def _load(root, name):
    path = root / 'provenance' / name
    if not path.is_file():
        raise ValueError(f'Missing manifest: provenance/{name}')
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique_object)


def verify(root):
    manifest = _load(root, 'imports.json')
    if not isinstance(manifest, dict) or not isinstance(manifest.get('files'), list):
        raise ValueError('Invalid import manifest')
    if any(not isinstance(item, dict) or not isinstance(item.get('path'), str)
           for item in manifest['files']):
        raise ValueError('Invalid import manifest record')
    paths = [item['path'] for item in manifest['files']]
    if len(set(paths)) != len(paths):
        raise ValueError('Duplicate path in imports manifest')
    for item in manifest['files']:
        check(root / item['path'], item)
    sources = _load(root, 'sources.json')
    if not isinstance(sources, dict) or not isinstance(sources.get('repositories'), list):
        raise ValueError('Invalid sources manifest')
    for repo in sources['repositories']:
        if not isinstance(repo, dict) or not isinstance(repo.get('path'), str) or 'commit' not in repo:
            raise ValueError('Invalid source repository record')
        if not (root / repo['path'] / '.git').exists():
            raise ValueError(f'Missing pinned source: {repo["path"]}; {SETUP}')
        if git(root, repo['path'], 'rev-parse', 'HEAD') != repo['commit']:
            raise ValueError(f"Source commit mismatch: {repo['path']}")
        # A user's status display preference must not hide extra source inputs.
        if git(root, repo['path'], 'status', '--porcelain', '--untracked-files=all'):
            raise ValueError(f"Modified source reference: {repo['path']}")
        # The real index can hide changed tracked bytes with assume-unchanged
        # or skip-worktree. Compare HEAD through a fresh index without changing
        # the user's flags, stat cache, sparse checkout or split-index files.
        with tempfile.TemporaryDirectory(prefix='hl-source-index-') as temporary:
            env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / 'index'))
            options = ('-c', 'core.ignorestat=false', '-c', 'core.splitIndex=false')
            git(root, repo['path'], *options, 'read-tree', '--no-sparse-checkout', 'HEAD', env=env)
            if git(root, repo['path'], *options, 'status', '--porcelain', '--untracked-files=all', env=env):
                raise ValueError(f"Modified source reference: {repo['path']}")
    print(f"Verified {len(manifest['files'])} imported files and all pinned source repositories.")


if __name__ == '__main__':
    try:
        verify(Path(__file__).resolve().parents[1])
    except (ValueError, OSError) as error:
        print(f'verify_imports: {error}', file=sys.stderr)
        sys.exit(1)
