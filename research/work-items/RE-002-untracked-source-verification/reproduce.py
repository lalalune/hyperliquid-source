#!/usr/bin/env python3
"""Compare source verification with Git's normal and hidden-untracked display."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile


def probe(repository):
    spec = importlib.util.spec_from_file_location('source_verifier', repository / 'tools/verify_imports.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix='source-pin-fixture-') as tmp:
        root = Path(tmp)
        source = root / 'refs/sub'
        source.mkdir(parents=True)

        def git(*args):
            return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()

        git('init', '-q')
        git('config', 'user.email', 'fixture@example.invalid')
        git('config', 'user.name', 'Local fixture')
        git('config', 'core.autocrlf', 'false')
        (source / 'retained.rs').write_text('// Synthetic retained source.\n')
        git('add', 'retained.rs')
        git('commit', '-q', '-m', 'fixture baseline')
        (root / 'provenance').mkdir()
        (root / 'provenance/imports.json').write_text(json.dumps({'files': []}))
        (root / 'provenance/sources.json').write_text(json.dumps({
            'repositories': [{'path': 'refs/sub', 'commit': git('rev-parse', 'HEAD')}]}))

        def accepted():
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    module.verify(root)
                return True
            except ValueError:
                return False

        git('config', 'status.showUntrackedFiles', 'no')
        clean = accepted()
        (source / 'unexpected.rs').write_text('// Synthetic extra source, never compiled.\n')
        git('config', 'status.showUntrackedFiles', 'normal')
        ordinary = accepted()
        git('config', 'status.showUntrackedFiles', 'no')
        hidden = accepted()
        return {'fixture_only': True, 'clean_accepted': clean,
                'extra_with_normal_status_accepted': ordinary,
                'same_extra_with_hidden_status_accepted': hidden,
                'default_status': git('status', '--porcelain'),
                'explicit_all_status': git('status', '--porcelain', '--untracked-files=all'),
                'source_paths': sorted(p.name for p in source.rglob('*.rs'))}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository-root', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    import sys
    sys.path.insert(0, str(args.repository_root.resolve() / 'tools'))
    result = probe(args.repository_root.resolve())
    print(json.dumps(result, indent=2))
    if args.check and (not result['clean_accepted'] or result['extra_with_normal_status_accepted']
                       or result['same_extra_with_hidden_status_accepted']):
        raise SystemExit(1)
