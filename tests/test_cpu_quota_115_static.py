"""Bind quota/cache facts below digest admission; reject altered loader semantics."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import cpu_quota_115_static as c


class CPUQuota115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = c.TARGET.read_bytes()
        cls.image = c.Image(cls.data)
        cls.record = c.analyze(cls.data)

    def changed(self, address, raw):
        image = copy.copy(self.image)
        off = image.offset(address, len(raw))
        data = bytearray(image.data)
        data[off:off + len(raw)] = raw
        image.data = bytes(data)
        return image

    def test_authenticated_complete_bodies_and_record(self):
        self.assertEqual(self.record, json.loads((c.PACKET / 'static/records.json').read_bytes()))
        self.assertEqual([r['bytes'] for r in self.record['bodies']], [6466, 18, 312, 119])
        self.assertEqual(sum(r['instructions'] for r in self.record['bodies']), 1449)
        self.assertEqual(self.record['primary_bytes'], 6796)
        self.assertFalse(self.record['captured_binary_executed'])

    def test_digest_gate_rejects_modified_truncated_and_non_elf(self):
        for data in [b'not an ELF', self.data[:-1], b'X' + self.data[1:]]:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                c.analyze(data)

    def test_each_selected_semantic_region_changes_below_digest_gate(self):
        for name, (address, raw) in c.ANCHORS.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                c.extract(self.changed(address, bytes([int(raw[:2], 16) ^ 1])))

    def test_actual_callback_import_and_ceil_binding_mutations(self):
        for slot, field, value in [(0x64bcce0, 'addend', 0x5ba8150),
                                   (0x64e7858, 'kind', 6),
                                   (0x64df9f0, 'addend', 0x5c87d51),
                                   (0x64ebfe8, 'symbol_index', 97)]:
            image = copy.copy(self.image)
            image.relocations = copy.deepcopy(image.relocations)
            image.relocations[slot][field] = value
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                c.extract(image)

    def test_loader_writes_cannot_replace_bodies_constants_or_globals(self):
        for address in [0x5ba91d2, 0x45120f, 0x64bccc7, 0x64fff08, 0x64fdfaf]:
            image = copy.copy(self.image)
            image.relocations = dict(image.relocations)
            image.relocations[address] = dict(image.relocations[0x64e7858])
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, 'overlapping selected data'):
                c.extract(image)
        image = copy.copy(self.image)
        image.relocations = dict(image.relocations)
        image.relocations[0x64e7857] = dict(image.relocations[0x64e7858])
        with self.assertRaisesRegex(ValueError, 'overlapping slot'):
            c.extract(image)

    def test_data_constants_and_file_state_are_not_names(self):
        for address in [0x451210, 0x450170, 0x459360, 0x458d58, 0x4592b0, 0x459458, 0x64bccd0, 0x64fdfb0]:
            with self.subTest(address=address), self.assertRaises(ValueError):
                original = self.image.read(address, 1)[0]
                c.extract(self.changed(address, bytes([original ^ 1])))
        globals_ = self.record['globals']
        self.assertEqual(globals_['once_state']['kind'], 'file')
        self.assertEqual(globals_['once_state']['hex'], '03000000')
        self.assertEqual(globals_['cpu_cache']['kind'], 'writable_PT_LOAD_zero_tail')
        for address, size in [(0x64ffe07, 2), (0x6728924, 8), (0xdeadbeef, 8)]:
            with self.subTest(address=address), self.assertRaises(ValueError):
                c.mapped_data(self.image, address, size)

    def test_fde_and_lsda_boundaries_remain_admission_requirements(self):
        image = copy.copy(self.image)
        image.fdes = copy.deepcopy(image.fdes)
        next(f for f in image.fdes if f['start'] == 0x5ba8150)['end'] -= 1
        with self.assertRaisesRegex(ValueError, 'FDE'):
            c.extract(image)
        table = self.record['exception_tables']['initializer']
        self.assertEqual(len(table['rows']), 31)
        self.assertFalse(table['action_records_decoded'])
        with self.assertRaisesRegex(ValueError, 'LPStart'):
            c.extract(self.changed(int(table['va'], 16), b'\x00'))

    def test_both_native_partitions_match_all_complete_bytes(self):
        for name, span in c.RANGES.items():
            expected = [(int(i['va'], 16), bytes.fromhex(i['bytes']))
                        for i in self.record['instructions'][name]]
            for provider in ('gnu', 'llvm'):
                text = (c.PACKET / f'static/{name}.{provider}.txt').read_text()
                with self.subTest(name=name, provider=provider):
                    self.assertEqual(c.native_bytes(text, *span), expected)

    def test_affinity_preparer_replays_the_original_frozen_bytes(self):
        path = c.PACKET / 'preparation/build_affinity_oracle.py'
        spec = importlib.util.spec_from_file_location('cpu115_affinity_preparer', path)
        module = importlib.util.module_from_spec(spec)
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = previous
        raw = (json.dumps(module.rows(), indent=2) + '\n').encode()
        self.assertEqual(raw, (c.PACKET / 'oracle/affinity-vectors.json').read_bytes())
        freeze = json.loads((c.PACKET / 'oracle/AFFINITY-FREEZE.json').read_bytes())
        self.assertEqual(c.digest(raw), freeze['sha256'])
        self.assertEqual(len(module.rows()), 1318)

    def test_closed_nested_packet_inventory_rejects_added_objects(self):
        spec = importlib.util.spec_from_file_location('cpu115_verifier', c.PACKET / 'verify.py')
        v = importlib.util.module_from_spec(spec)
        old = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec.loader.exec_module(v)
        finally:
            sys.dont_write_bytecode = old
        expected = {'known/data.txt'}
        for kind in ('extra-file', 'empty-dir', 'nested-extra', 'symlink', 'dangling'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'known').mkdir()
                (root / 'known/data.txt').write_bytes(b'x')
                (root / 'manifest.json').write_bytes(b'{}')
                v.verify_packet_inventory(root, expected)
                if kind == 'extra-file':
                    (root / 'extra').write_bytes(b'x')
                elif kind == 'empty-dir':
                    (root / 'empty').mkdir()
                elif kind == 'nested-extra':
                    (root / 'known/extra').write_bytes(b'x')
                elif kind == 'symlink':
                    (root / 'known/data.txt').unlink()
                    (root / 'known/data.txt').symlink_to(root / 'manifest.json')
                else:
                    (root / 'unknown').symlink_to(root / 'missing')
                with self.assertRaises(ValueError):
                    v.verify_packet_inventory(root, expected)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'a').write_bytes(b'x')
            row = {'a': {'bytes': 1, 'sha256': c.digest(b'x')}}
            v.verify_manifest(root, row, {'a'})
            for rows, expected in [({'a': {'bytes': True, 'sha256': c.digest(b'x')}}, {'a'}),
                                   ({'a': {'bytes': 1, 'sha256': '0' * 64}}, {'a'}),
                                   ({'../a': {'bytes': 1, 'sha256': c.digest(b'x')}}, {'../a'})]:
                with self.assertRaises(ValueError):
                    v.verify_manifest(root, rows, expected)
