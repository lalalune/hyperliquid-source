"""Corrupt real static inputs below digest admission; never execute the capture."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-current-thread-release'
MODULE = importlib.util.spec_from_file_location('current_thread_release', PACKET / 'collect.py')
release = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(release)


class CurrentThreadReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = release.load(ROOT)
        cls.core = release.prior(ROOT)
        cls.spec = json.loads((PACKET / 'spec.json').read_text())

    def changed(self, changes):
        data = bytearray(self.image.data)
        for va, raw in changes:
            off = self.image.offset(va, len(raw))
            data[off:off + len(raw)] = raw
        return self.core.Image(bytes(data), self.image.sections,
                               self.image.fdes, self.image.cies)

    def validate(self, image, spec=None):
        # Structural operands, FDE/CIE records and actual relocation writers
        # must still reject corruption when both byte equality shortcuts are off.
        release.validate(image, self.spec if spec is None else spec,
                         body_hashes=False, instruction_bytes=False)

    def test_authenticated_native_records(self):
        actual = release.collect(ROOT, PACKET)
        self.assertEqual(actual, json.loads((PACKET / 'records.json').read_text()))
        self.assertEqual([(b['bytes'], b['instructions']) for b in actual['bodies']],
                         [(73, 27), (288, 50)])
        self.assertEqual(actual['new_body_bytes'], 73)
        self.assertEqual(actual['acceptance_gates_changed'], 0)

    def test_operand_and_branch_corruptions_below_hashes(self):
        # Null branch, name offset, clear byte, length branch, sentinel,
        # weak-counter offset, weak-zero branch and both RIP displacements.
        changes = [(0x5c98b51, b'\x15'), (0x5c98b4c, b'\x10'),
                   (0x5c98b58, b'\x01'), (0x5c98b5d, b'\x09'),
                   (0x5c98b69, b'\xfe'), (0x5c98b70, b'\x10'),
                   (0x5c98b72, b'\x10'), (0x5c98b62, b'\x3b'),
                   (0x5c98b7e, b'\x57'), (0x5ca54e2, b'\x20')]
        for va, raw in changes:
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                self.validate(self.changed([(va, raw)]))

    def test_raw_fde_and_cie_corruptions(self):
        for body in self.spec['bodies']:
            for va in [body['fde']['fde'], body['fde']['cie']]:
                byte = self.image.read(va + 8, 1)[0] ^ 1
                with self.subTest(record=hex(va)), self.assertRaises(ValueError):
                    self.validate(self.changed([(va + 8, bytes([byte]))]))

    def test_duplicate_and_missing_frames(self):
        frame = self.spec['bodies'][0]['fde']
        for frames in [self.image.fdes + [frame],
                       [f for f in self.image.fdes if f != frame]]:
            image = self.core.Image(self.image.data, self.image.sections,
                                    frames, self.image.cies)
            with self.assertRaises(ValueError):
                self.validate(image)

    def test_unwind_metadata_and_execution_membership(self):
        cies = copy.deepcopy(self.image.cies)
        cies[self.spec['bodies'][0]['fde']['cie']]['augmentation'] = 'zPLR'
        with self.assertRaises(ValueError):
            self.validate(self.core.Image(self.image.data, self.image.sections,
                                          self.image.fdes, cies))
        sections = copy.deepcopy(self.image.sections)
        next(s for s in sections if s['name'] == '.text')['flags'] &= ~4
        with self.assertRaises(ValueError):
            self.validate(self.core.Image(self.image.data, sections,
                                          self.image.fdes, self.image.cies))

    def relocation_rows(self):
        for section in self.image.sections:
            if section['type'] == 4:
                for offset in range(section['offset'],
                                    section['offset'] + section['size'], 24):
                    yield offset, struct.unpack_from('<QQq', self.image.data, offset)

    def test_physical_relocation_mutations(self):
        for slot, _, _, _ in release.BINDINGS:
            offset, row = next((off, r) for off, r in self.relocation_rows() if r[0] == slot)
            data = bytearray(self.image.data)
            struct.pack_into('<q', data, offset + 16, row[2] ^ 1)
            with self.subTest(slot=hex(slot)), self.assertRaises(ValueError):
                self.validate(self.core.Image(bytes(data), self.image.sections,
                                              self.image.fdes, self.image.cies))

    def test_duplicate_physical_relocation_writer(self):
        offset, row = next(self.relocation_rows())
        data = bytearray(self.image.data)
        struct.pack_into('<Q', data, offset, release.BINDINGS[0][0])
        with self.assertRaises(ValueError):
            self.validate(self.core.Image(bytes(data), self.image.sections,
                                          self.image.fdes, self.image.cies))

    def test_import_name_is_bound_to_dynstr(self):
        symbols = next(s for s in self.image.sections if s['name'] == '.dynsym')
        strings = next(s for s in self.image.sections if s['name'] == '.dynstr')
        offset = struct.unpack_from('<I', self.image.data, symbols['offset'] + 59 * 24)[0]
        data = bytearray(self.image.data)
        data[strings['offset'] + offset] = ord('t')
        with self.assertRaises(ValueError):
            self.validate(self.core.Image(bytes(data), self.image.sections,
                                          self.image.fdes, self.image.cies))

    def test_native_capture_and_lock_corruptions(self):
        path = PACKET / 'native/release.objdump.txt'
        raw = path.read_bytes()
        with self.assertRaises(ValueError):
            self.core.native_rows(raw.replace(b'48 8b 1f', b'48 8b 1e', 1),
                                  self.image, 0x5c98b40, 0x5c98b89)
        for rows in [[(0x5c98b6c, b'\xf0'), (0x5c98b6d, bytes.fromhex('48ff4b10'))],
                     [(0x5c98b6d, b'\xf0'), (0x5c98b6e, bytes.fromhex('48ff4b08'))]]:
            with self.assertRaises(ValueError):
                release.join_lock(rows)

    def test_scope_cannot_relabel_existing_context_as_new(self):
        spec = copy.deepcopy(self.spec)
        spec['bodies'][1]['ownership'] = 'new'
        with self.assertRaises(ValueError):
            self.validate(self.image, spec)
        spec = copy.deepcopy(self.spec)
        spec['target_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.validate(self.image, spec)


if __name__ == '__main__':
    unittest.main()
