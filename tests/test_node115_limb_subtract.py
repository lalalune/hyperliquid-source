"""Static corruption controls and arithmetic boundary cases for node #115."""
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_limb_subtract as bind
from elf_index import sections
from fde_extents import eh_frame_records

PACKET = ROOT / 'research/work-items/RE-001-node115-limb-subtract'


class LimbSubtractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = bind.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = json.loads((PACKET / 'records.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def test_digest_fails_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'wrong'
            target.write_bytes(b'not the captured node')
            out = Path(tmp) / 'output'
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.generate(out, target)
            self.assertFalse(out.exists())

    def test_window_mutation_rejected(self):
        offset = self.record['window']['file_offset']
        body = self.data[offset:offset + bind.END - bind.START]
        for index in (0, 5, 20, len(body) - 1):
            changed = bytearray(body)
            changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                bind.decode_body(changed)
        self.assertEqual(hashlib.sha256(body).hexdigest(), self.record['window']['body_sha256'])

    def test_shifted_fde_raw_pointer_rejected(self):
        # pcrel start field follows 4-byte length and 4-byte CIE displacement.
        pos = bind.FDE['fde'] + 8  # .eh_frame VA equals file offset here.
        original = self.data[pos:pos + 4]
        try:
            val = struct.unpack('<i', original)[0]
            self.data[pos:pos + 4] = struct.pack('<i', val + 1)
            _, rows = eh_frame_records(self.data, sections(self.data))
            with self.assertRaisesRegex(ValueError, 'FDE changed'):
                bind.check_fde(rows)
        finally:
            self.data[pos:pos + 4] = original

    def test_wrong_call_target_rejected(self):
        site = self.record['direct_branch_candidates'][0]
        raw = bytearray.fromhex(site['bytes'])
        self.assertEqual(bind.decode_call(raw, site['va']), bind.START)
        raw[1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target changed'):
            bind.decode_call(raw, site['va'])

    def test_location_relocation_corruption_rejected(self):
        location = self.record['caller_locations'][0]
        pos = location['relocation_file_offset'] + 16
        original = self.data[pos:pos + 8]
        try:
            self.data[pos:pos + 8] = struct.pack('<q', location['path_va'] + 1)
            with self.assertRaisesRegex(ValueError, 'path changed'):
                bind.source_locations(self.data, sections(self.data), next(s for s in sections(self.data) if s['name'] == '.text'))
        finally:
            self.data[pos:pos + 8] = original

    def test_location_reference_corruption_rejected(self):
        va = self.record['caller_locations'][0]['references'][0]['va']
        pos = va - 0x1000 + 3
        original = self.data[pos:pos + 1]
        try:
            self.data[pos:pos + 1] = bytes([original[0] ^ 1])
            with self.assertRaisesRegex(ValueError, 'reference changed'):
                bind.source_locations(self.data, sections(self.data), next(s for s in sections(self.data) if s['name'] == '.text'))
        finally:
            self.data[pos:pos + 1] = original

    def test_arithmetic_boundaries(self):
        m = (1 << 64) - 1
        vectors = [([0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], 0),
                   ([0, 0, 0, 0], [1, 0, 0, 0], [m, m, m, m], 1),
                   ([0, 1, 0, 0], [1, 0, 0, 0], [m, 0, 0, 0], 0),
                   ([0, 0, 0, 1], [1, 0, 0, 0], [m, m, m, 0], 0),
                   ([m, m, m, m], [m, m, m, m], [0, 0, 0, 0], 0),
                   ([0, 0, 0, 0], [m, m, m, m], [1, 0, 0, 0], 1)]
        for a, b, expected, borrow in vectors:
            with self.subTest(a=a, b=b):
                self.assertEqual(bind.model(a, b), (expected, borrow))
        with self.assertRaises(ValueError):
            bind.model([0] * 3, [0] * 4)
        with self.assertRaises(ValueError):
            bind.model([0] * 4, [0, 0, 0, 1 << 64])

    def test_model_against_whole_integer(self):
        # Deterministic non-random cross product covers limb carry propagation.
        choices = (0, 1, (1 << 63), (1 << 64) - 1)
        for i in range(256):
            a = [choices[(i >> (2 * j)) & 3] for j in range(4)]
            b = [choices[((i * 73 + 17) >> (2 * j)) & 3] for j in range(4)]
            result, borrow = bind.model(a, b)
            av = sum(x << (64 * j) for j, x in enumerate(a))
            bv = sum(x << (64 * j) for j, x in enumerate(b))
            self.assertEqual(sum(x << (64 * j) for j, x in enumerate(result)), (av - bv) % (1 << 256))
            self.assertEqual(borrow, int(av < bv))

    def test_readme_counts_match_records(self):
        r = self.record
        text = (PACKET / 'README.md').read_text()
        self.assertIn(f"{r['window']['size']} bytes, file offset", text)
        self.assertIn(f"{len(r['instructions'])} instructions;", text)
        self.assertIn(f"{len(bytes.fromhex(r['window']['padding_hex']))} `cc` bytes", text)
        self.assertIn(f"body has {len(r['callees'])} direct or indirect calls", text)
        self.assertIn(f"found {len(r['direct_branch_candidates'])} candidates:", text)
        self.assertEqual(len({c['containing_fde']['start'] for c in r['direct_branch_candidates']}), 2)
        self.assertEqual(len(r['caller_locations']), 2)
        self.assertEqual(sum(len(x['references']) for x in r['caller_locations']), 3)
        self.assertEqual(text, bind.readme(r))

    def test_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            bind.generate(tmp)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
