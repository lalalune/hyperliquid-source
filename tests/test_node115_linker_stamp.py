import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-linker-stamp'
spec = importlib.util.spec_from_file_location('linker_stamp_probe', PACKET / 'probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class LinkerStampTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.retained = json.loads((PACKET / 'result.json').read_text())

    def test_authenticated_capture(self):
        self.assertEqual(probe.capture(ROOT / 'artifacts/node/115/hl-node'), self.retained['capture'])
        probe.check_controls(self.retained)

    def test_archive_digest_checked_before_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'compiler.tar.xz'
            path.write_bytes(b'not a compiler archive')
            with self.assertRaisesRegex(ValueError, 'archive SHA-256 mismatch'):
                probe.linux_candidate(path, self.retained['capture']['stamp'])

    def test_lost_contrasts_fail(self):
        for label, key in [('current_b', 'object_sha256'), ('older', 'stamp'),
                           ('changed_input', 'gnu_build_id'), ('changed_stamp', 'elf_sha256')]:
            with self.subTest(label=label, key=key):
                record = copy.deepcopy(self.retained)
                cases = record['fixture']['cases']
                cases[label][key] = 'altered-repeat' if label == 'current_b' else cases['current_a'][key]
                with self.assertRaises(ValueError):
                    probe.check_controls(record)

    def test_same_llvm_commit_with_different_repository_text_fails_linux_candidate(self):
        record = copy.deepcopy(self.retained)
        record['linux_distribution']['version'] = record['linux_distribution']['version'].replace(
            '/checkout/src/llvm-project/llvm', 'https://github.com/rust-lang/llvm-project.git')
        with self.assertRaisesRegex(ValueError, 'Linux candidate stamp differs'):
            probe.check_controls(record)
