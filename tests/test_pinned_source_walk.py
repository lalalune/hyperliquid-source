"""Ignored local backups must not alter analysis of a committed source tree."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import catalogue
import exchange_dispatch as ed

TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


@contextmanager
def source_view(binary, versioned=True):
    # Only independent comment fixtures enter this temporary Git repository;
    # this is not a Rust implementation, workspace or reconstructed function.
    with tempfile.TemporaryDirectory(prefix='hl-source-walk-') as temporary:
        root = Path(temporary)
        for name in ('research/components.json', 'research/progress.json',
                     'research/imported/hl-node-94.inventory.json',
                     'research/imported/hl-node-115.inventory.json',
                     'research/imported/hl-visor.inventory.json',
                     'research/imported/can1357-literal-classes.json'):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        target = root / 'artifacts/node/94/hl-node'
        target.parent.mkdir(parents=True)
        target.write_bytes(binary)
        reference = root / 'references/can1357-hl'
        for name, text in {
            '.gitignore': '*.backup.rs\n',
            'base/example.rs': '// independent source fixture\n',
            'base/tracked.backup.rs': '// deliberately committed ignored-name control\n',
            'l1/exchange/example.rs': '// unverified fixture seed 0x1343c80\n',
        }.items():
            path = reference / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_CONFIG_NOSYSTEM='1', GIT_OPTIONAL_LOCKS='0')

        def git(*args):
            return subprocess.check_output(['git', '-C', str(reference), *args],
                                           env=env, stderr=subprocess.DEVNULL)

        if versioned:
            git('init', '--quiet')
            git('add', '.')
            git('add', '--force', 'base/tracked.backup.rs')
            git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Source fixture')
        yield root, reference, git


class PinnedSourceWalkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = ed.TARGET.read_bytes()
        if cls.binary.startswith(b'version https://git-lfs.github.com/spec/v1'):
            raise unittest.SkipTest('node94 LFS input is not materialized')
        if hashlib.sha256(cls.binary).hexdigest() != TARGET_SHA256:
            raise AssertionError('Tests require authenticated node94')
        cls.starts, cls.ends = ed.fde_index(ed.Elf(cls.binary))

    def test_ignored_backups_leave_the_entire_catalogue_unchanged(self):
        with source_view(self.binary) as (root, reference, git):
            clean = catalogue.generate(root)
            document = json.loads(clean['research/catalogue/components.json'])
            self.assertEqual(document['path_totals']['reference'], 3)
            self.assertTrue(any('base/tracked.backup.rs' in row['reference_paths']
                                for row in document['components']))
            shutil.copyfile(reference / 'base/example.rs', reference / 'base/local.backup.rs')
            shutil.copyfile(reference / 'l1/exchange/example.rs', reference / 'l1/exchange/local.backup.rs')
            self.assertEqual(git('status', '--porcelain', '--untracked-files=all'), b'')
            self.assertEqual(catalogue.generate(root), clean)

    def test_ignored_exchange_backup_does_not_duplicate_address_evidence(self):
        with source_view(self.binary) as (_root, reference, git):
            directory = reference / 'l1/exchange'
            clean = ed.survey_addresses(directory, self.starts, self.ends)
            self.assertEqual(len(clean), 1)
            shutil.copyfile(directory / 'example.rs', directory / 'local.backup.rs')
            self.assertEqual(git('status', '--porcelain', '--untracked-files=all'), b'')
            self.assertEqual(ed.survey_addresses(directory, self.starts, self.ends), clean)

    def test_an_explicit_unversioned_diagnostic_view_remains_supported(self):
        with source_view(self.binary, versioned=False) as (root, _reference, _git):
            document = json.loads(catalogue.generate(root)['research/catalogue/components.json'])
            self.assertEqual(document['path_totals']['reference'], 3)


if __name__ == '__main__':
    unittest.main()
