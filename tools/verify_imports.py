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
        return subprocess.check_output(['git', '-C', str(root / path), *args], text=True, stderr=subprocess.DEVNULL, env=env).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise ValueError(f'Unreadable pinned source: {path}; {SETUP}') from None


def verify(root):
    manifest = json.loads((root / 'provenance/imports.json').read_text())
    for item in manifest['files']:
        check(root / item['path'], item)
    for repo in json.loads((root / 'provenance/sources.json').read_text())['repositories']:
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
    verify(Path(__file__).resolve().parents[1])
