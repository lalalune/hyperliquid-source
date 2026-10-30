#!/usr/bin/env python3
"""Verify immutable imported files and source repository commit pins."""
import json
from pathlib import Path
import subprocess
import sys

from artifacts import check

SETUP = 'run git submodule update --init --recursive'


def git(root, path, *args):
    try:
        return subprocess.check_output(['git', '-C', str(root / path), *args], text=True, stderr=subprocess.DEVNULL).strip()
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
    return json.loads((root / 'provenance' / name).read_text(),
                      object_pairs_hook=_unique_object)


def verify(root):
    manifest = _load(root, 'imports.json')
    paths = [item['path'] for item in manifest['files']]
    if len(set(paths)) != len(paths):
        raise ValueError('Duplicate path in imports manifest')
    for item in manifest['files']:
        check(root / item['path'], item)
    for repo in _load(root, 'sources.json')['repositories']:
        if not (root / repo['path'] / '.git').exists():
            raise ValueError(f'Missing pinned source: {repo["path"]}; {SETUP}')
        if git(root, repo['path'], 'rev-parse', 'HEAD') != repo['commit']:
            raise ValueError(f"Source commit mismatch: {repo['path']}")
        if git(root, repo['path'], 'status', '--porcelain'):
            raise ValueError(f"Modified source reference: {repo['path']}")
    print(f"Verified {len(manifest['files'])} imported files and all pinned source repositories.")


if __name__ == '__main__':
    verify(Path(__file__).resolve().parents[1])
