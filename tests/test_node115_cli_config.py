#!/usr/bin/env python3
"""Node115 bytes, call/data closure and comparator corruption controls; static only."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_cli_config as c


class Static(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = c.TARGET.read_bytes()
        cls.image = c.Image(cls.data)
        cls.report = c.analyze(cls.data)

    def overlay(self, va, replacement):
        image = copy.copy(self.image)
        original = image.read
        def read(address, length):
            raw = bytearray(original(address, length))
            for k, byte in enumerate(replacement, va):
                if address <= k < address + length:
                    raw[k - address] = byte
            return bytes(raw)
        image.read = read
        return image

    def test_recorded(self):
        self.assertEqual(self.report, json.loads((c.PACKET / 'records.json').read_text()))
        self.assertEqual(self.report['primary_bytes'], 7762)
        self.assertEqual(sum(r['bytes'] for r in self.report['bodies']), 23003)
        self.assertEqual(len(self.report['commands']), 14)
        self.assertEqual(self.report['relocations_scanned'], 61001)

    def test_digest_mutation(self):
        with self.assertRaisesRegex(ValueError, 'identity'):
            c.analyze(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_actual_fde_byte_mutation(self):
        frame = self.image.owner(0x564d700)
        data = bytearray(self.data)
        off = self.image.offset(frame['fde'] + 12, 4)
        struct.pack_into('<i', data, off, 2187)
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            c.extract(c.Image(data))

    def test_vtable_header(self):
        with self.assertRaisesRegex(ValueError, 'vtable header'):
            c.extract(self.overlay(0x64aac18, b'\x02'))

    def test_actual_vtable_rela_wrong_target(self):
        row = self.image.relocations[0x64aac28]
        data = bytearray(self.data)
        struct.pack_into('<q', data, int(row['file_offset'], 16) + 16, 0x564e0f0)
        with self.assertRaisesRegex(ValueError, 'slot binding'):
            c.extract(c.Image(data))

    def test_actual_rela_overlapping_writer(self):
        row = self.image.relocations[0x64df480]
        data = bytearray(self.data)
        struct.pack_into('<Q', data, int(row['file_offset'], 16), 0x64aac29)
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            c.extract(c.Image(data))

    def test_actual_duplicate_rela_destination(self):
        row = self.image.relocations[0x64df480]
        data = bytearray(self.data)
        struct.pack_into('<Q', data, int(row['file_offset'], 16), 0x64aac28)
        with self.assertRaisesRegex(ValueError, 'duplicate relocation'):
            c.Image(data)

    def test_actual_extra_entry_naming(self):
        row = self.image.relocations[0x64df480]
        data = bytearray(self.data)
        struct.pack_into('<q', data, int(row['file_offset'], 16) + 16, 0x564d700)
        with self.assertRaisesRegex(ValueError, 'naming inventory'):
            c.extract(c.Image(data))

    def test_lsda_encoding(self):
        frame = self.image.owner(0x564df90)
        data = bytearray(self.data)
        data[self.image.offset(frame['lsda'], 1)] = 0
        image = copy.copy(self.image)
        image.data = bytes(data)
        with self.assertRaisesRegex(ValueError, 'LPStart'):
            c.extract(image)

    def test_length_table_corruption(self):
        with self.assertRaisesRegex(ValueError, 'dispatch table'):
            c.extract(self.overlay(0x928884, b'\x00\x00\x00\x00'))

    def test_command_literal_corruption(self):
        with self.assertRaisesRegex(ValueError, 'command spelling'):
            c.extract(self.overlay(0x4547e0, b'S'))

    def test_simd_tail_nonzero_padding(self):
        with self.assertRaisesRegex(ValueError, 'padding'):
            c.extract(self.overlay(0x4515c2, b'\x01'))

    def test_old_ip_layout_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'anchor'):
            c.extract(self.overlay(0x56559e9, b'\x6e'))

    def test_ip_error_any_nonzero_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'anchor'):
            c.extract(self.overlay(0x56555f8, bytes.fromhex('84c0')))

    def test_missing_command_tag14_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'anchor'):
            c.extract(self.overlay(0x5655154, b'\x0e'))

    def test_native_missing_row(self):
        text = (c.PACKET / 'chain_validator.gnu.txt').read_text()
        text = '\n'.join(s for s in text.splitlines() if not s.lstrip().startswith('564df90:'))
        with self.assertRaisesRegex(ValueError, 'gap/overlap'):
            c.native_bytes(text, 0x564df90, 0x564e0e9)

    def test_native_duplicate_row(self):
        text = (c.PACKET / 'chain_validator.llvm.txt').read_text()
        line = next(s for s in text.splitlines() if s.lstrip().startswith('564df90:'))
        with self.assertRaisesRegex(ValueError, 'gap/overlap'):
            c.native_bytes(text.replace(line, line + '\n' + line), 0x564df90, 0x564e0e9)

    def test_exact_llvm_display_joins(self):
        text = (c.PACKET / 'caller_large.llvm.txt').read_text()
        raw = c.native_bytes(text, 0x2ae41e0, 0x2ae6d66)
        fixed = c.native_bytes(text, 0x2ae41e0, 0x2ae6d66, llvm=True)
        want = [(int(r['va'], 16), bytes.fromhex(r['bytes'])) for r in self.report['instructions']['caller_large']]
        self.assertNotEqual(raw, want)
        self.assertEqual(len(raw), len(fixed) + 2)
        self.assertEqual(fixed, want)
        self.assertEqual(b''.join(x[1] for x in raw), b''.join(x[1] for x in fixed))

    def test_bad_llvm_join_bytes(self):
        text = '2ae5dcb: f0\n2ae5dcc: 48 ff 00\n'
        with self.assertRaisesRegex(ValueError, 'LOCK'):
            c.native_bytes(text, 0x2ae5dcb, 0x2ae5dcf, llvm=True)

    def test_undeclared_llvm_join_is_not_normalized(self):
        text = '123: f0\n124: 48 ff 08\n'
        self.assertEqual(len(c.native_bytes(text, 0x123, 0x127, llvm=True)), 2)

    def test_duplicate_json(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            json.loads('{"x":1,"x":2}', object_pairs_hook=c.unique)


def anchor_control(label, row):
    def test(self):
        va = int(row['va'], 16)
        with self.assertRaises(ValueError):
            c.extract(self.overlay(va, bytes([self.image.read(va, 1)[0] ^ 1])))
    return test


for name, row in c.spec()['anchors'].items():
    setattr(Static, 'test_anchor_' + name, anchor_control(name, row))


def literal_control(label, row):
    def test(self):
        va = int(row['va'], 16)
        with self.assertRaisesRegex(ValueError, 'literal'):
            c.extract(self.overlay(va, bytes([self.image.read(va, 1)[0] ^ 1])))
    return test


for name, row in c.spec()['literals'].items():
    setattr(Static, 'test_literal_' + name, literal_control(name, row))


class Packaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        s = importlib.util.spec_from_file_location('cli115_verify', c.PACKET / 'verify.py')
        cls.v = importlib.util.module_from_spec(s)
        s.loader.exec_module(cls.v)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.p = Path(self.tmp.name).resolve()
        (self.p / 'a').write_bytes(b'x')
        (self.p / 'MANIFEST.sha256').write_text(c.digest(b'x') + '  a\n')

    def test_closed_inventory(self):
        self.v.check_inventory(self.p, {'a'})
        self.assertEqual(self.v.manifest(self.p, self.p, {'a'}), 1)

    def test_extra_file(self):
        (self.p / 'extra').write_bytes(b'x')
        with self.assertRaises(ValueError): self.v.check_inventory(self.p, {'a'})

    def test_extra_empty_directory(self):
        (self.p / 'extra').mkdir()
        with self.assertRaises(ValueError): self.v.check_inventory(self.p, {'a'})

    def test_extra_nested_file(self):
        (self.p / 'extra').mkdir()
        (self.p / 'extra' / 'file').write_bytes(b'x')
        with self.assertRaises(ValueError): self.v.check_inventory(self.p, {'a'})

    def test_dangling_symlink(self):
        (self.p / 'broken').symlink_to(self.p / 'absent')
        with self.assertRaises(ValueError): self.v.check_inventory(self.p, {'a'})

    def test_same_bytes_file_symlink(self):
        (self.p / 'link').symlink_to(self.p / 'a')
        with self.assertRaises(ValueError): self.v.check_inventory(self.p, {'a','link'})

    def test_parent_symlink(self):
        (self.p / 'real').mkdir()
        (self.p / 'real' / 'b').write_bytes(b'x')
        (self.p / 'link').symlink_to(self.p / 'real', target_is_directory=True)
        with self.assertRaises(ValueError): self.v.regular(self.p / 'link' / 'b')

    def test_manifest_corrupt_hash(self):
        (self.p / 'a').write_bytes(b'y')
        with self.assertRaisesRegex(ValueError, 'digest'): self.v.manifest(self.p, self.p, {'a'})

    def test_manifest_extra_name(self):
        with self.assertRaisesRegex(ValueError, 'inventory'): self.v.manifest(self.p, self.p, {'a','extra'})

    def test_manifest_duplicate(self):
        p = self.p / 'MANIFEST.sha256';p.write_text(p.read_text()*2)
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.v.manifest(self.p, self.p, {'a'})


if __name__ == '__main__':
    unittest.main()
