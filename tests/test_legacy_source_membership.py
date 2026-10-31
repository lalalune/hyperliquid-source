"""Exercise the real reproduction driver; unrelated inventory/auth are explicit stubs.

The durable packet probe separately exercises all real artifacts and source pins.
No captured binary or reconstructed Rust implementation runs in these fixtures.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def literal_pipeline(versioned=True):
    with tempfile.TemporaryDirectory(prefix='hl-literal-pipeline-') as directory:
        root = Path(directory)
        reference = root / 'references/can1357-hl'
        (reference / 'base').mkdir(parents=True)
        (reference / 'base/example.rs').write_text('// "pinned diagnostic fixture"\n', encoding='utf-8')
        (reference / 'base/tracked.backup.rs').write_text('// "committed backup diagnostic"\n', encoding='utf-8')
        (reference / '.gitignore').write_text('*.backup.rs\n.history/\n', encoding='utf-8')
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')

        def git(*args):
            return subprocess.check_output(['git', '-C', str(reference), *args], env=env, stderr=subprocess.DEVNULL)

        if versioned:
            git('init', '--quiet')
            git('add', '.')
            git('add', '--force', 'base/tracked.backup.rs')
            git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Literal parser fixture')
        for name in ['tools/reproduce.py', 'tools/source_files.py', 'tools/legacy/drift.py']:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        # Only these unrelated stages are stubs. The production reproduction
        # driver, source selection and imported literal classifier are real.
        (root / 'tools/artifacts.py').write_text('# Explicit artifact-verification unit stub\n', encoding='utf-8')
        (root / 'tools/legacy/inv.py').write_text(
            'import pathlib,sys\npathlib.Path(sys.argv[2]).write_text("{}")\n', encoding='utf-8')
        for release in ['94', '115', 'visor']:
            artifact = (root / 'artifacts/visor/captured/hl-visor' if release == 'visor'
                        else root / f'artifacts/node/{release}/hl-node')
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(b'pinned diagnostic fixture\0committed backup diagnostic\0')
            imported = root / 'research/imported' / ('hl-visor.inventory.json' if release == 'visor'
                                                       else f'hl-node-{release}.inventory.json')
            imported.parent.mkdir(parents=True, exist_ok=True)
            imported.write_text('{}', encoding='utf-8')
        (root / 'provenance').mkdir()
        (root / 'provenance/literal-overrides.json').write_text('{"overrides": []}', encoding='utf-8')
        expected = root / 'research/imported/can1357-literal-classes.json'
        subprocess.run([sys.executable, '-I', str(root / 'tools/legacy/drift.py'),
                        str(reference), str(root / 'artifacts/node/94/hl-node'),
                        str(root / 'artifacts/node/115/hl-node'), str(expected)],
                       env=env, check=True, capture_output=True)
        original = json.loads(expected.read_text(encoding='utf-8'))
        assert original['counts'] == {'grounded': 2}
        assert any(Path(row['file']).parts == ('base', 'tracked.backup.rs') for row in original['items'])

        def run():
            process = subprocess.run([sys.executable, str(root / 'tools/reproduce.py')], env=env, capture_output=True)
            raw = json.loads((root / 'work/reproduced/can1357-literal-classes.raw.json').read_text(encoding='utf-8'))
            return process, raw

        def history():
            path = reference / '.history/base/example.rs'
            path.parent.mkdir(parents=True)
            shutil.copyfile(reference / 'base/example.rs', path)

        yield reference, git, run, history


class LegacySourceMembershipTests(unittest.TestCase):
    def test_reproduce_ignores_uncommitted_editor_history(self):
        with literal_pipeline() as (_reference, git, run, history):
            clean, original = run()
            self.assertEqual(clean.returncode, 0, clean.stderr)
            history()
            self.assertEqual(git('status', '--porcelain', '--untracked-files=all'), b'')
            result, actual = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(actual, original)

    def test_tracked_literal_changes_still_fail_reproduction(self):
        with literal_pipeline() as (reference, _git, run, _history):
            (reference / 'base/example.rs').write_text('// "committed backup diagnostic"\n', encoding='utf-8')
            result, actual = run()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(actual['counts'], {'grounded': 1})

    def test_unversioned_diagnostic_view_keeps_all_its_inputs(self):
        with literal_pipeline(versioned=False) as (_reference, _git, run, history):
            history()
            result, actual = run()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(actual['counts'], {'grounded': 3})


if __name__ == '__main__':
    unittest.main()
