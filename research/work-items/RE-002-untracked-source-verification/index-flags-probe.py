"""Real Git fixture probe; does not change retained source or execute target binaries."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repository-root', type=Path, default=Path(__file__).resolve().parents[3])
parser.add_argument('--output', type=Path)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
repo = args.repository_root.resolve()
output = args.output or repo / 'work/index-flags-probe.json'
output.parent.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(repo / 'tools'))
spec = importlib.util.spec_from_file_location('verifier_under_test', repo / 'tools/verify_imports.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
rows = []
for flag in ('assume-unchanged', 'skip-worktree'):
    with tempfile.TemporaryDirectory(prefix='hyper-index-flag-') as tmp:
        root = Path(tmp)
        source = root / 'refs/sub'
        source.mkdir(parents=True)
        def git(*args):
            return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
        git('init', '-q')
        git('config', 'user.name', 'Local fixture')
        git('config', 'user.email', 'fixture@example.invalid')
        git('config', 'core.autocrlf', 'false')
        path = source / 'retained.rs'
        path.write_text('// original retained source\n')
        git('add', 'retained.rs')
        git('commit', '-q', '-m', 'fixture')
        (root / 'provenance').mkdir()
        (root / 'provenance/imports.json').write_text(json.dumps({'files': []}))
        (root / 'provenance/sources.json').write_text(json.dumps({'repositories': [{'path': 'refs/sub', 'commit': git('rev-parse', 'HEAD')}]}))
        git('update-index', '--' + flag, '--', 'retained.rs')
        def accepted():
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    module.verify(root)
                return True
            except ValueError:
                return False
        clean = accepted()
        path.write_text('// modified retained source\n')
        status = git('status', '--porcelain', '--untracked-files=all')
        original_index = (source / '.git/index').read_bytes()
        original_flag = git('ls-files', '-v', '--', 'retained.rs')
        modified = accepted()
        rows.append({'flag': flag, 'cleanAccepted': clean, 'modifiedAccepted': modified,
                     'status': status, 'indexFlag': original_flag.split()[0],
                     'indexPreserved': original_index == (source / '.git/index').read_bytes(),
                     'flagPreserved': original_flag == git('ls-files', '-v', '--', 'retained.rs'),
                     'sourceSha256': hashlib.sha256(path.read_bytes()).hexdigest()})
result = {'verifierSha256': hashlib.sha256((repo / 'tools/verify_imports.py').read_bytes()).hexdigest(),
          'fixture': 'Synthetic temporary Git source repository. Captured node/visor and imported evidence are not modified or executed.', 'cases': rows}
output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result))
if args.check and any(not r['cleanAccepted'] or r['modifiedAccepted'] or not r['indexPreserved'] or not r['flagPreserved'] for r in rows):
    raise SystemExit(1)
