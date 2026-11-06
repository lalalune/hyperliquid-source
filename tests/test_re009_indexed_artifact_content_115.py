"""Tests for tools/re009_indexed_artifact_content_115.py (node #115 IndexedArtifactContentSerde path)."""
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re009_indexed_artifact_content_115 as tool  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-009-indexed-artifact-content-codec-115'


class IndexedArtifactContentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.TARGET.read_bytes()
        cls.image = tool.Image(cls.data)
        cls.result = tool.build(cls.data)
        cls.files = tool.render(cls.result)

    def test_capture_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tool.SHA115)

    def test_every_case_matches(self):
        s = self.result['summary']
        self.assertEqual(s['mismatches'], 0)
        self.assertEqual(self.result['mismatches'], [])
        self.assertEqual(s['functions'], 10)
        self.assertGreater(s['ident_cases'] + s['seed_cases'] + s['enum_cases'] + s['entry_cases'], 6000)

    def test_negative_controls_all_caught(self):
        rows = self.result['negatives']
        self.assertEqual(len(rows), len(tool.NEGATIVES))
        for level, label, caught, verdict in rows:
            self.assertEqual(verdict, 'caught', label)
            self.assertGreater(caught, 0, label)

    def test_packet_files_byte_identical(self):
        for name, text in self.files.items():
            self.assertEqual((PACKET / name).read_bytes(), text.encode('utf-8'), name)

    def test_manifest_covers_packet(self):
        listed = {}
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ', 1)
            listed[name] = digest
        present = sorted(p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256')
        self.assertEqual(sorted(listed), present)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_regeneration_writes_same_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(tool.main(['--out', tmp]), 0)
            for name, text in self.files.items():
                self.assertEqual((Path(tmp) / name).read_bytes(), text.encode('utf-8'), name)

    def test_variant_pools_decode_from_relocations(self):
        rows = [r for r in self.result['pools'] if r[1] == 'variants']
        self.assertEqual([r[5] for r in rows if r[0] == 1], [n.decode() for n in tool.NAMES])
        self.assertEqual([r[5] for r in rows if r[0] == 2], [n.decode() for n in tool.NAMES])
        fields = {r[1]: [] for r in self.result['pools'] if r[1].startswith('fields:')}
        for r in self.result['pools']:
            if r[1].startswith('fields:'):
                fields[r[1]].append(r[5])
        self.assertEqual(fields['fields:VisorMetadata'], ['bh'])
        self.assertEqual(fields['fields:NodeArtifact'], ['vts', 'hf', 'oqf'])

    def test_jump_tables_land_inside_their_bodies(self):
        ends = tool.fde_map(self.data)
        for fam, role, table, index, target in self.result['tables']:
            start = tool.FAMILIES[fam][role]
            self.assertTrue(start < int(target, 16) < ends[start], (fam, role, index))

    # ---------------------------------------------------------- negative controls

    def test_rejects_corrupted_capture(self):
        bad = bytearray(self.data)
        bad[0x1000] ^= 1
        with self.assertRaises(tool.Reject):
            tool.build(bytes(bad))

    def test_rejects_shifted_pool(self):
        with self.assertRaises(tool.Reject):
            rows = tool.decode_pool(self.image, tool.FAMILIES[1]['pool'] + 16, 5)
            if [r[2] for r in rows] != list(tool.NAMES):
                raise tool.Reject('pool text differs')

    def test_rejects_non_fde_entry(self):
        ends = tool.fde_map(self.data)
        self.assertNotIn(tool.FAMILIES[1]['ident'] + 1, ends)

    def test_unmodelled_call_is_rejected(self):
        m = tool.Machine(self.image, {})
        for k, b in enumerate(b'Nodemetadata'):
            m.store(tool.IN_BASE + k, b, 1)
        m.regs[7], m.regs[6], m.regs[2] = tool.OUT_BASE, tool.IN_BASE, 12
        with self.assertRaises(tool.Reject):
            m.run(tool.FAMILIES[1]['ident'])

    def test_patched_compare_immediate_is_detected(self):
        """Flip one byte of the NodeArtifact qword immediate: the interpreter must diverge."""
        va = 0x15004b1 + 2  # movabs rcx, imm64 ("NodeArti")
        sec = self.image.section_of(va)
        off = sec['offset'] + va - sec['address']
        self.assertEqual(self.data[off:off + 8], b'NodeArti')
        bad = bytearray(self.data)
        bad[off] ^= 0x20
        image = tool.Image(bytes(bad))
        got, calls, _ = tool.run_ident(image, 1, b'NodeArtifact')
        self.assertNotEqual((got, tool.norm(calls)), tool.r_ident(b'NodeArtifact', 1))

    def test_table_free_boundaries(self):
        self.assertEqual(tool.r_table_free(0), [])
        self.assertEqual(tool.r_table_free(1), [('dealloc', '0x%x' % (tool.CTRL_BASE - 0x10), 0x22, 0)])
        self.assertEqual(tool.r_table_free(0xffffffffffffffef), [('panic', 'mask_too_large')])
        self.assertEqual(tool.r_table_free(tool.MASK), [('panic', 'mask_all_ones')])
        self.assertEqual(tool.r_table_free(0xffffffffffffffee)[0][0], 'dealloc')

    def test_value_kind_niche(self):
        self.assertEqual(tool.value_kind(1 << 63 | 3), 3)
        self.assertEqual(tool.value_kind(0), 5)
        self.assertEqual(tool.value_kind((1 << 63) - 1), 5)
        self.assertEqual(struct.pack('<Q', tool.NONE_VALUE)[7], 0x80)


if __name__ == '__main__':
    unittest.main()
