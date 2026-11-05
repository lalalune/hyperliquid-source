import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_enum_variant_matchers_115 as tool  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

EVIDENCE = ROOT / 'research' / 'work-items' / 'RE-010-enum-variant-matchers-115'


class EnumVariantMatchersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.BINARY.read_bytes()
        cls.img = tool.Image(cls.data)
        _, cls.fdes = eh_frame_records(cls.data)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.summary = tool.generate(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def machine(self, label, kind, img=None):
        row = next(e for e in tool.ENUMS if e[0] == label)
        start = row[2] if kind == 'bytes' else row[3]
        rec = tool.fde_record(self.fdes, start)
        sites = self.img.call_sites(rec['lsda'], start) if rec['lsda'] is not None else []
        return tool.Machine(img or self.img, kind, start, rec['end'], (row[4], row[5]), {}, sites)

    def table(self, label):
        row = next(e for e in tool.ENUMS if e[0] == label)
        return tool.variant_table(self.img.variants(row[4], row[5]), tool.ALIAS_POSITIONS[label])

    def test_evidence_files_regenerate_byte_identically(self):
        names = sorted(p.name for p in Path(self.tmp.name).iterdir())
        committed = sorted(p.name for p in EVIDENCE.iterdir() if p.name not in ('README.md', 'MANIFEST.sha256'))
        self.assertEqual(names, committed)
        for name in names:
            self.assertEqual((Path(self.tmp.name) / name).read_bytes(), (EVIDENCE / name).read_bytes(), name)

    def test_manifest_matches_packet_files(self):
        rows = [line.split('  ', 1) for line in (EVIDENCE / 'MANIFEST.sha256').read_text().splitlines()]
        listed = {name: digest for digest, name in rows}
        on_disk = sorted(p.name for p in EVIDENCE.iterdir() if p.name != 'MANIFEST.sha256')
        self.assertEqual(sorted(listed), on_disk)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest(), digest, name)

    def test_every_function_matches_and_is_fully_covered(self):
        self.assertEqual(len(self.summary['functions']), 6)
        self.assertEqual(self.summary['failed_functions'], [])
        for fn in self.summary['functions']:
            self.assertEqual(fn['mismatches'], 0)
            self.assertEqual(fn['unwind_mismatches'], 0)
            self.assertEqual(fn['unexecuted_non_padding'], [])
            self.assertTrue(fn['success_stores_one_to_one'])
            self.assertGreater(fn['cases'], 500)
            self.assertEqual(fn['lsda'] is not None, fn['kind'] == 'bytes')

    def test_variant_counts_and_alias(self):
        enums = {e['label']: e for e in self.summary['enums']}
        self.assertEqual({k: (v['variants_len'], v['variant_count']) for k, v in enums.items()},
                         {'PERP': (17, 16), 'SHORT114': (114, 114), 'TAG18': (18, 18)})
        perp = self.table('PERP')
        self.assertEqual(perp[9], (b'setDeployerFees', 9))
        self.assertEqual(perp[10], (b'setFeeScale', 9))
        self.assertEqual(perp[16], (b'hip3Star', 15))
        for kind in ('bytes', 'str'):
            m = self.machine('PERP', kind)
            self.assertEqual(m.run(b'setFeeScale'), ('ok', 9))
            self.assertEqual(m.run(b'setDeployerFees'), ('ok', 9))
            self.assertEqual(m.run(b'hip3Star'), ('ok', 15))

    def test_str_and_bytes_entry_points_agree(self):
        for e in self.summary['enums']:
            self.assertEqual(e['str_bytes_agree_on_utf8_cases'], e['utf8_cases'])

    def test_decoder_bindings(self):
        for label, decoder, fbytes, fstr, _, _ in tool.ENUMS:
            for off in tool.BYTES_CALL_OFFSETS:
                self.assertEqual(self.img.direct_call_target(decoder + off), fbytes)
            self.assertEqual(self.img.direct_call_target(decoder + tool.STR_CALL_OFFSET), fstr)
        # negative control: one byte past a call site is not an e8 call
        with self.assertRaises(tool.Fault):
            self.img.direct_call_target(tool.ENUMS[0][1] + tool.STR_CALL_OFFSET + 1)

    def test_unknown_inputs_and_lossy_free(self):
        m = self.machine('TAG18', 'bytes')
        self.assertEqual(m.run(b'zz'), ('unknown', b'zz', 0))
        self.assertEqual(m.run(b'e\xff'), ('unknown', 'e�'.encode(), 1))
        self.assertEqual(m.run(b'e\xff', unwind=True), ('unwind', 1))
        self.assertEqual(m.run(b'E'), ('unknown', b'E', 0))

    def test_model_and_image_mutants_rejected(self):
        self.assertEqual(self.summary['mutants']['killed'], self.summary['mutants']['total'])
        self.assertEqual(self.summary['image_mutants']['killed'], self.summary['image_mutants']['total'])
        self.assertGreaterEqual(self.summary['image_mutants']['total'], 50)

    def test_wrong_alias_literal_is_rejected(self):
        names = [n for n, _ in self.table('PERP')]
        wrong = tool.variant_table(names, frozenset())
        m = self.machine('PERP', 'str')
        self.assertNotEqual(m.run(b'hip3Star'), tool.reconstructed_match(b'hip3Star', wrong))

    def test_corrupted_store_byte_changes_outcome(self):
        # 0x286cf74: movw $0x1109,(%rdi) is the TAG18 visit_str success store for `ri` (variant 17)
        buf = bytearray(self.data)
        buf[self.img.off(0x286cf74 + 4)] ^= 0x01
        m = self.machine('TAG18', 'str', tool.mutated_image(self.img, bytes(buf)))
        self.assertEqual(self.machine('TAG18', 'str').run(b'ri'), ('ok', 17))
        self.assertEqual(m.run(b'ri'), ('ok', 16))

    def test_rejects_wrong_digest_and_unmapped_reads(self):
        with self.assertRaises(ValueError):
            tool.Image(self.data[:-1] + bytes([self.data[-1] ^ 1]))
        with self.assertRaises(tool.Fault):
            self.img.read(0x10, 4)
        with self.assertRaises(tool.Fault):
            tool.fde_record(self.fdes, tool.ENUMS[0][3] + 1)

    def test_summary_is_json_and_bound_to_target(self):
        s = json.loads((EVIDENCE / 'summary.json').read_text())
        self.assertEqual(s['binary_sha256'], tool.SHA256)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tool.SHA256)


if __name__ == '__main__':
    unittest.main()
