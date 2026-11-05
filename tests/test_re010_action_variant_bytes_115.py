import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('re010_action_variant_bytes_115', ROOT / 'tools' / 're010_action_variant_bytes_115.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / 'research' / 'work-items' / 'RE-010-action-variant-bytes-115'


class ActionVariantBytesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.BINARY.read_bytes()
        cls.img = tool.Image(cls.data)
        cls.names = cls.img.variants(0x644cc40)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.summary = tool.generate(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def machine(self, img=None, copy=None):
        copy = copy or tool.COPIES[0]
        end = tool.fde_end(self.data, copy[1])
        _, fdes = tool.eh_frame_records(self.data)
        sites = self.img.call_sites(next(f['lsda'] for f in fdes if f['start'] == copy[1]), copy[1])
        return tool.Machine(img or self.img, copy, end, {}, sites)

    def test_all_copies_match_reconstruction_with_full_coverage(self):
        copies = self.summary['copies']
        self.assertEqual([c['start'] for c in copies], ['0x2b99100', '0x3659d20', '0x2b9cdb0', '0x365d9d0', '0x4d63870'])
        for c in copies:
            self.assertEqual(c['mismatches'], 0)
            self.assertEqual(c['unwind_mismatches'], 0)
            self.assertGreater(c['cases'], 2500)
            self.assertEqual(c['instructions_executed'], c['instructions'])
            self.assertTrue(c['success_stores_one_to_one'])
            self.assertEqual(c['lsda_call_sites'], 3)
            self.assertEqual(c['ok_tag_bytes'], [0] if c['form'] == 'A' else [9])
        self.assertEqual(self.summary['same_shape_within_form'], {'A': True, 'B': True})

    def test_mutants_are_all_killed(self):
        self.assertEqual(self.summary['mutants']['killed'], self.summary['mutants']['total'])
        self.assertEqual(self.summary['image_mutants']['killed'], self.summary['image_mutants']['total'])
        self.assertGreaterEqual(self.summary['image_mutants']['total'], 30)

    def test_packet_files_match_regeneration(self):
        manifest = {}
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ', 1)
            manifest[name] = digest
        for name in sorted(p.name for p in Path(self.tmp.name).iterdir()):
            fresh = (Path(self.tmp.name) / name).read_bytes()
            self.assertEqual(fresh, (PACKET / name).read_bytes(), name)
            self.assertEqual(hashlib.sha256(fresh).hexdigest(), manifest[name], name)

    def test_reconstruction_borrowed_and_owned_paths(self):
        self.assertEqual(tool.reconstructed_visit_bytes(b'noop', self.names), ('ok', 0))
        self.assertEqual(tool.reconstructed_visit_bytes(b'noo', self.names), ('unknown', b'noo', 0))
        self.assertEqual(tool.reconstructed_visit_bytes(b'noop\xff', self.names), ('unknown', b'noop\xef\xbf\xbd', 1))
        self.assertEqual(tool.reconstructed_unwind(b'\xff'), ('unwind', 1))
        m = self.machine()
        self.assertEqual(m.run(b'noop\xff'), ('unknown', b'noop\xef\xbf\xbd', 1))
        self.assertEqual(m.run(b'zz', unwind=True), ('unwind', 0))

    def test_rejects_wrong_digest(self):
        bad = bytearray(self.data)
        bad[0x1000] ^= 1
        with self.assertRaises(ValueError):
            tool.Image(bytes(bad))

    def test_corrupted_compare_byte_diverges(self):
        # first arm of the length-4 switch compares 'n' at (%rsi); make it 'o'
        site = 0x2b9912a
        self.assertEqual(self.img.read(site, 1), b'n')
        buf = bytearray(self.data)
        buf[self.img.off(site)] ^= 0x01
        m = self.machine(tool.mutated_image(self.img, bytes(buf)))
        self.assertNotEqual(m.run(b'noop'), ('ok', 0))

    def test_out_of_range_and_unmapped_reads_fault(self):
        with self.assertRaises(ValueError):
            self.img.variants(0x644cc48)
        with self.assertRaises(tool.Fault):
            self.img.read(0x10, 4)
        with self.assertRaises(tool.Fault):
            tool.fde_end(self.data, 0x2b99101)

    def test_unwind_without_landing_pad_faults(self):
        copy = tool.COPIES[0]
        m = tool.Machine(self.img, copy, tool.fde_end(self.data, copy[1]), {}, [])
        with self.assertRaises(tool.Fault):
            m.run(b'zz', unwind=True)

    def test_wrong_variants_slice_faults(self):
        label, start, form, variants_va, callee = tool.COPIES[0]
        copy = (label, start, form, 0x6467f98, callee)
        with self.assertRaises(tool.Fault):
            self.machine(copy=copy).run(b'zz')

    def test_summary_is_json_with_digest(self):
        s = json.loads((Path(self.tmp.name) / 'summary.json').read_text())
        self.assertEqual(s['binary_sha256'], tool.SHA256)
        self.assertEqual(s['variant_count'], 92)


if __name__ == '__main__':
    unittest.main()
