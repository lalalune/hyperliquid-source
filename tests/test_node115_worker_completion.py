"""Target-backed boundary/corruption controls for the worker completion packet."""
import copy
import hashlib
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
import node115_worker_completion as m
VPATH = ROOT / 'research/work-items/RE-012-worker-completion-115/verify.py'
spec = importlib.util.spec_from_file_location('completion_packet_verifier', VPATH)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class TargetControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        cls.image = m.Image(cls.data)
        cls.spec = m.spec()
        cls.record = m.extract(cls.image)

    def mutated(self, va, raw):
        image = copy.copy(self.image)
        data = bytearray(self.data)
        off = image.offset(va, len(raw))
        data[off:off + len(raw)] = raw
        image.data = bytes(data)
        return image

    def test_complete_observation(self):
        actual = m.analyze(self.data)
        self.assertEqual(actual, json.loads((m.PACKET / 'static/records.json').read_text()))
        self.assertEqual((len(actual['bodies']), sum(r['bytes'] for r in actual['bodies'])), (27, 17695))
        self.assertEqual(actual['primary_bytes'], 8821)

    def test_all_semantic_instruction_corruptions(self):
        for name, row in self.spec['anchors'].items():
            with self.subTest(name=name):
                va = int(row['va'], 16)
                raw = bytearray.fromhex(row['hex'])
                raw[-1] ^= 1
                with self.assertRaises(ValueError):
                    m.extract(self.mutated(va, raw))

    def test_whole_body_and_extent_controls(self):
        for name, (start, end) in self.spec['ranges'].items():
            with self.subTest(name=name):
                start, end = int(start, 16), int(end, 16)
                raw = bytes([self.image.read(end - 1, 1)[0] ^ 1])
                with self.assertRaises(ValueError):
                    m.extract(self.mutated(end - 1, raw))
                frame = self.image.owner(start)
                changed = self.mutated(frame['fde'] + 12, struct.pack('<i', end - start - 1))
                with self.assertRaisesRegex(ValueError, 'FDE extent'):
                    m.extract(m.Image(changed.data))

    def test_selected_binding_targets_and_partial_writers(self):
        entries = {int(x[0], 16) for x in self.spec['ranges'].values()}
        protected = {int(x, 16) for x in self.spec['bindings']}
        protected |= {int(x['va'], 16) for x in self.spec['source_locations'].values()}
        spare = next(r for slot, r in self.image.relocations.items()
                     if slot not in protected and r['kind'] == 8 and r['addend'] not in entries)
        spare_offset = int(spare['file_offset'], 16)
        for slot in self.spec['bindings']:
            with self.subTest(slot=slot):
                slot = int(slot, 16)
                row = self.image.relocations[slot]
                data = bytearray(self.data)
                data[int(row['file_offset'], 16) + 16] ^= 1
                with self.assertRaises(ValueError):
                    m.extract(m.Image(data))
                data = bytearray(self.data)
                struct.pack_into('<Q', data, spare_offset, slot + 1)
                with self.assertRaisesRegex(ValueError, 'ambiguous|constant relocation changed'):
                    m.extract(m.Image(data))

    def test_constants_literals_and_source_location(self):
        addresses = [int(x, 16) for x in self.spec['constants']]
        addresses += [int(x['va'], 16) for x in self.spec['literals'].values()]
        addresses += [int(x['va'], 16) + 16 for x in self.spec['source_locations'].values()]
        for va in addresses:
            with self.subTest(va=hex(va)):
                with self.assertRaises(ValueError):
                    m.extract(self.mutated(va, bytes([self.image.read(va, 1)[0] ^ 1])))

    def test_wrong_target_and_code_relocation(self):
        with self.assertRaisesRegex(ValueError, 'identity'):
            m.analyze(self.data[:-1])
        changed = copy.copy(self.image)
        changed.relocations = dict(self.image.relocations)
        changed.relocations[0x15d63c0] = {'slot': '0x15d63c0'}
        with self.assertRaisesRegex(ValueError, 'overlaps body'):
            m.extract(changed)

    def test_jump_table_and_import_name_controls(self):
        for row in self.spec['jump_tables'].values():
            va = int(row['va'], 16)
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, 'jump table'):
                    m.extract(self.mutated(va, bytes([self.image.read(va, 1)[0] ^ 1])))
        binding = self.image.binding(0x64ec980)
        self.assertEqual(binding['symbol'], 'exit')
        sec = self.image.by_name['.dynsym']
        name = struct.unpack_from('<I', self.data, sec['offset'] + binding['symbol_index'] * 24)[0]
        strings = self.image.by_name['.dynstr']
        with self.assertRaisesRegex(ValueError, 'binding changed'):
            m.extract(self.mutated(strings['address'] + name, b'E'))

    def test_native_bytes_and_exact_display_joins(self):
        start, raw = next(iter(m.LLVM_LOCK_JOINS.items()))
        text = f'{start:x}: f0 lock\n{start+1:x}: {raw[1:].hex(" ")} x\n'
        self.assertEqual(m.native_bytes(text, start, start + len(raw), True), [(start, raw)])
        with self.assertRaises(ValueError):
            m.native_bytes(text.replace(raw[1:].hex(' '), '00 ' * (len(raw) - 1)), start, start + len(raw), True)
        with self.assertRaises(ValueError):
            m.native_bytes(text.splitlines()[0], start, start + len(raw), True)


class PacketInventory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.packet = self.root / v.PACKET_REL
        self.paths = {v.PACKET_REL + '/' + x for x in v.PACKET_FILES} | v.EXTERNAL
        for relative in self.paths:
            p = self.root / relative
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(relative.encode())
        self.manifest = self.packet / 'MANIFEST.sha256'
        self.lines = [hashlib.sha256((self.root / p).read_bytes()).hexdigest() + '  ' + p for p in sorted(self.paths)]
        self.manifest.write_text('\n'.join(self.lines) + '\n')

    def test_exact_inventory_passes(self):
        self.assertEqual(v.verify_manifest(self.root), len(self.paths))

    def test_nested_extra_file_and_empty_directory(self):
        p = self.packet / 'unexpected'
        p.mkdir()
        with self.assertRaises(ValueError):
            v.verify_manifest(self.root)
        (p / 'nested').write_text('extra')
        with self.assertRaises(ValueError):
            v.verify_manifest(self.root)

    def test_dangling_and_same_content_file_symlinks(self):
        p = self.packet / 'unexpected'
        p.symlink_to(self.root / 'absent')
        with self.assertRaises(ValueError):
            v.verify_manifest(self.root)
        p.unlink()
        p = self.packet / 'README.md'
        target = self.root / 'same-content'
        target.write_bytes(p.read_bytes())
        p.unlink()
        p.symlink_to(target)
        with self.assertRaises(ValueError):
            v.verify_manifest(self.root)

    def test_parent_and_manifest_symlinks(self):
        p = self.root / 'tools'
        target = self.root / 'real-tools'
        p.rename(target)
        p.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError):
            v.verify_manifest(self.root)
        p.unlink()
        target.rename(p)
        moved = self.root / 'manifest'
        self.manifest.rename(moved)
        self.manifest.symlink_to(moved)
        with self.assertRaises(ValueError):
            v.verify_manifest(self.root)

    def test_duplicate_escape_missing_hash_corruptions(self):
        for rows in [self.lines + [self.lines[0]], self.lines[:-1],
                     ['0' * 64 + '  ../outside'] + self.lines,
                     ['0' * 64 + self.lines[0][64:]] + self.lines[1:]]:
            with self.subTest(rows=rows[0]):
                self.manifest.write_text('\n'.join(rows) + '\n')
                with self.assertRaises(ValueError):
                    v.verify_manifest(self.root)


if __name__ == '__main__':
    unittest.main()
