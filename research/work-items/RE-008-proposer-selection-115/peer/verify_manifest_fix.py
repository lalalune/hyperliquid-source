#!/usr/bin/env python3
"""Execute the unchanged fixed manifest-check function on isolated fixtures."""
import ast
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace

ap = argparse.ArgumentParser()
ap.add_argument('--root', type=Path, required=True)
ap.add_argument('--out', type=Path, required=True)
args = ap.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
source = (args.root / 'research/work-items/RE-008-proposer-selection-115/verify.py').read_bytes()
module = ast.parse(source)
function = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'verify_manifest')
namespace = {'Path': Path, 'os': os, 're': re, 'stat': stat,
             'p': SimpleNamespace(digest=lambda raw: hashlib.sha256(raw).hexdigest())}
exec(compile(ast.Module(body=[function], type_ignores=[]), 'unchanged-fixed-manifest-function', 'exec'), namespace)
check = namespace['verify_manifest']
prefix = 'research/work-items/RE-008-proposer-selection-115'
results = []
parent = args.out.resolve()
for mode in ['ordinary', 'unlisted-file', 'unlisted-directory', 'dangling-extra', 'file-symlink', 'parent-symlink']:
    with tempfile.TemporaryDirectory(prefix='manifest-control-', dir=parent) as temp:
        root = Path(temp).resolve()
        packet = root / prefix
        names = ['tools/proposer_selection115.py', 'tests/test_proposer_selection115.py', prefix + '/rust/lib.rs']
        for name in names:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('independent fixture\n')
        manifest = packet / 'MANIFEST.sha256'
        manifest.write_text(''.join(hashlib.sha256((root/name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names))
        if mode == 'unlisted-file':
            (packet/'extra').write_text('extra')
        elif mode == 'unlisted-directory':
            (packet/'extra').mkdir()
        elif mode == 'dangling-extra':
            (packet/'extra').symlink_to('absent')
        elif mode == 'file-symlink':
            lib = packet/'rust/lib.rs'
            lib.rename(packet/'rust/actual.rs')
            lib.symlink_to('actual.rs')
        elif mode == 'parent-symlink':
            (packet/'rust').rename(packet/'actual-rust')
            (packet/'rust').symlink_to('actual-rust', target_is_directory=True)
        try:
            count = check(root, packet)
        except (ValueError, OSError) as error:
            if mode == 'ordinary':
                raise
            results.append({'control': mode, 'rejected': True,
                            'error': str(error).replace(str(root), '<fixture>')})
        else:
            if mode != 'ordinary':
                raise ValueError('corruption accepted: ' + mode)
            results.append({'control': mode, 'accepted': True, 'manifest_entries': count})
record = {'status': 'PASS', 'fixed_verifier_sha256': hashlib.sha256(source).hexdigest(),
          'results': results, 'scope': 'Unchanged fixed verify_manifest AST function only, isolated temporary trees; no captured execution or new native builds.'}
(args.out / 'manifest-fix-result.json').write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps(record, indent=2))
