"""Target-grounded static path and tag certificates, without executing node115."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import u8_rejection_static as subject
from elf_index import sections


class U8RejectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('requires materialized node115 capture')
        cls.data = subject.TARGET.read_bytes()
        cls.secs = sections(cls.data)
        cls.report = subject.analyze(cls.data)

    def offset(self, va):
        s = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutate(self, va, value=None):
        b = bytearray(self.data)
        off = self.offset(va)
        b[off] = b[off] ^ 1 if value is None else value
        return b

    def test_complete_native_regeneration_and_retained_record(self):
        self.assertEqual(self.report, json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual(sum(x['bytes'] for x in self.report['ranges'].values()), 2074)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            subject.generate(subject.TARGET, out)
            for f in out.iterdir():
                self.assertEqual(f.read_bytes(), (subject.PACKET / f.name).read_bytes(), f.name)

    def test_three_local_return_paths_require_tag_store(self):
        graph = subject.constructor_graph(self.data)
        def paths(at, path):
            if not graph[at]:
                return [path + [at]]
            return [p for nxt in graph[at] for p in paths(nxt, path + [at])]
        found = paths(0x18be120, [])
        returning = [p for p in found if p[-1] == 0x18be1a0]
        self.assertEqual(len(returning), 3)
        self.assertEqual(len(found), 4)  # fourth leaves this local proof at allocation failure
        self.assertTrue(all(0x18be19d in p for p in returning))
        self.assertFalse(subject.has_path(graph, 0x18be120, 0x18be1a0, 0x18be19d))
        tag, comparisons = subject.tag_constants(self.data)
        self.assertEqual((tag, comparisons), (6, [9, 9]))
        # No scalar-byte-dependent branch exists in the two straight-line
        # helpers (native certificate checks this); tag6 excludes both tag9
        # continuations independently of the recorded 0..255 payload value.
        self.assertTrue(all(tag != c for c in comparisons))

    def test_actual_semantic_counterfactuals_change_the_certificate(self):
        changed = self.mutate(0x18be19f, 9)  # actual MOV [RBX],6 immediate ->9
        tag, comparisons = subject.tag_constants(changed)
        self.assertTrue(all(tag == c for c in comparisons))
        with self.assertRaisesRegex(ValueError, 'tag relation'):
            subject.analyze(changed)
        changed = self.mutate(0x186d17c, 6)  # actual CMP AL,9 immediate ->6
        tag, comparisons = subject.tag_constants(changed)
        self.assertEqual(tag, comparisons[0])
        with self.assertRaisesRegex(ValueError, 'tag relation'):
            subject.analyze(changed)
        # Actual short JMP -> epilogue instead of payload/store block.
        changed = self.mutate(0x18be144, 0x5b)
        graph = subject.constructor_graph(changed)
        self.assertTrue(subject.has_path(graph, 0x18be120, 0x18be1a0, 0x18be19d))
        with self.assertRaisesRegex(ValueError, 'bypasses'):
            subject.analyze(changed)

    def test_real_entry_propagation_and_call_controls(self):
        sites = [0x186d13d, 0x186d15f, 0x186d246, 0x186d250,
                 0x18500eb, 0x185011c, 0x1850124, 0x275170a,
                 0x2650305, 0x2773d23, 0x26a1423]
        sites += [a + 1 for a in subject.CALLS]
        for va in sites:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, 'instruction|direct call'):
                    subject.analyze(self.mutate(va))

    def test_real_expectation_relocations_and_fde_controls(self):
        sec = next(s for s in self.secs if s['name'] == '.rela.dyn')
        offsets = {struct.unpack_from('<Q', self.data, p)[0]: p
                   for p in range(sec['offset'], sec['offset'] + sec['size'], 24)}
        for slot in subject.RELATIVE:
            changed = bytearray(self.data)
            changed[offsets[slot] + 16] ^= 1
            with self.assertRaisesRegex(ValueError, 'relocation'):
                subject.analyze(changed)
        for va in [0x7c86dc, 0x5f44d6, 0x44f07b]:
            with self.assertRaisesRegex(ValueError, 'expectation|template'):
                subject.analyze(self.mutate(va))
        for name in ['config', 'enum_u8', 'carrier']:
            va = int(self.report['ranges'][name]['frame_records']['fde']['va'], 16) + 12
            with self.assertRaisesRegex(ValueError, 'FDE'):
                subject.analyze(self.mutate(va))

    def test_public_identity_rejects_changed_truncated_and_other_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            changed = root / 'changed'
            out = root / 'out'
            changed.write_bytes(self.mutate(0x18be19f, 9))
            with self.assertRaisesRegex(ValueError, 'pinned node115'):
                subject.generate(changed, out)
            changed.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'pinned node115'):
                subject.generate(changed, out)
            with self.assertRaisesRegex(ValueError, 'pinned node115'):
                subject.generate(subject.ROOT / 'artifacts/node/94/hl-node', out)
            self.assertFalse(out.exists())
