"""Entry selectors must point to captured executable bytes, never data."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import entry_file_offset, sections


class EntryExecutableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.targets = []
        manifest = json.loads((ROOT / 'provenance/artifacts.json').read_text())
        for item in manifest['files']:
            if item['path'].endswith(('/hl-node', '/hl-visor')):
                data = (ROOT / item['path']).read_bytes()
                if data.startswith(b'version https://git-lfs.github.com/spec/v1'):
                    continue
                if hashlib.sha256(data).hexdigest() != item['sha256']:
                    raise AssertionError('Target digest mismatch: ' + item['path'])
                cls.targets.append((item['path'], data))
        if not cls.targets:
            raise unittest.SkipTest('Captured ELF LFS objects not materialized')

    def test_authentic_entry_resolves_to_executable_bytes(self):
        for name, data in self.targets:
            with self.subTest(target=name):
                entry = struct.unpack_from('<Q', data, 24)[0]
                sec = next(s for s in sections(data)
                           if s['flags'] & 4 and s['address'] <= entry < s['address'] + s['size'])
                self.assertEqual(entry_file_offset(data), sec['offset'] + entry - sec['address'])

    def test_entry_in_read_only_data_is_rejected(self):
        for name, original in self.targets:
            with self.subTest(target=name):
                data = bytearray(original)
                rodata = next(s for s in sections(data) if s['name'] == '.rodata')
                struct.pack_into('<Q', data, 24, rodata['address'])
                with self.assertRaisesRegex(ValueError, 'executable file mapping'):
                    entry_file_offset(data)

    def test_entry_with_execution_flag_removed_is_rejected(self):
        for name, original in self.targets:
            with self.subTest(target=name):
                data = bytearray(original)
                entry = struct.unpack_from('<Q', data, 24)[0]
                shoff = struct.unpack_from('<Q', data, 40)[0]
                stride = struct.unpack_from('<H', data, 58)[0]
                for index, sec in enumerate(sections(data)):
                    if sec['address'] <= entry < sec['address'] + sec['size']:
                        struct.pack_into('<Q', data, shoff + index * stride + 8, sec['flags'] & ~4)
                with self.assertRaisesRegex(ValueError, 'executable file mapping'):
                    entry_file_offset(data)
