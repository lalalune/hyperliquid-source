"""rea launcher must reject duplicate keys in config/rea.json.

Sibling of #151 (harness_plan), #155 (elf_index) and #156
(fde_extents), and of open #142 (catalogue): the launcher config that
pins the REA package version, the preferred Node, and the default
target is loaded with plain json.loads, so a duplicated key is
silently resolved to its last value — a config file carrying
"version": "0.0.0" followed by "6.8.0" passes the version pin check
while also declaring the wrong version. The same silent resolution
applies to default_target and preferred_node, which select the binary
and runtime the launcher runs.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
spec = importlib.util.spec_from_file_location(
    'hl_rea_launcher', Path(__file__).resolve().parents[1] / 'tools/rea.py')
rea = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rea)


def _load_text(text):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'rea.json'
        p.write_text(text)
        return rea.load_config(p)


class ConfigDuplicateKeyTests(unittest.TestCase):
    def test_duplicate_version_rejected(self):
        with self.assertRaises(ValueError):
            _load_text('{"version": "0.0.0", "version": "6.8.0"}')

    def test_duplicate_default_target_rejected(self):
        with self.assertRaises(ValueError):
            _load_text('{"default_target": "visor", "default_target": "94"}')

    def test_duplicate_nested_key_rejected(self):
        with self.assertRaises(ValueError):
            _load_text('{"targets": {"94": "a", "94": "b"}}')

    def test_clean_config_still_loads(self):
        doc = rea.load_config(rea.ROOT / 'config/rea.json')
        self.assertEqual(doc['version'], '6.8.0')
        self.assertEqual(doc['default_target'], '94')


if __name__ == '__main__':
    unittest.main()
