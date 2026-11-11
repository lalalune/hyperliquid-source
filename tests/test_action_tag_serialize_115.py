import hashlib
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import action_tag_serialize_115 as tool  # noqa: E402

PACKET = os.path.join(ROOT, 'research', 'work-items', 'RE-010-action-serialize-tag-dispatch-115')


class ActionTagSerializeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, tool.BINARY), 'rb') as f:
            data = f.read()
        cls.img = tool.Image(data)
        cls.copies = [tool.decode_copy(cls.img, start) for start in tool.COPIES]
        cls.files, cls.ok = tool.build(ROOT)

    def test_build_passes_all_checks(self):
        self.assertTrue(self.ok)
        self.assertIn('baseline\tmatches', self.files['mutants.tsv'])
        self.assertNotIn('survived', self.files['mutants.tsv'])
        self.assertNotIn('\tNO\n', self.files['cases.tsv'])

    def test_every_copy_has_92_arms_and_full_byte_cover(self):
        for c in self.copies:
            self.assertEqual(len(c['entries']), len(tool.VARIANTS))
            self.assertEqual(len(set(c['entries'])), len(tool.VARIANTS))
            self.assertEqual(c['covered'], c['end'] - c['start'])
            self.assertEqual(c['base'], 0x86)
            self.assertEqual(c['default'], tool.VARIANTS.index('VoteGlobal'))
        self.assertEqual(sorted({c['form'] for c in self.copies}), ['A', 'B'])

    def test_selected_tags(self):
        spec = tool.default_spec()
        first = self.copies[0]
        self.assertEqual(tool.spec_serialize(spec, 0)[2:5], ('VoteGlobal', 'type', 'VoteGlobalAction'))
        self.assertEqual(tool.spec_serialize(spec, 0x85)[0], 20)
        self.assertEqual(tool.spec_serialize(spec, 0x86)[6], 'NoopAction')
        self.assertEqual(tool.spec_serialize(spec, 0x86 + 38)[4], 'topUpIsolatedOnlyMargin')
        self.assertEqual(tool.spec_serialize(spec, 0x86 + 68)[4], 'perpDeploy')
        self.assertEqual(tool.spec_serialize(spec, 0x86 + 92), ('outside-table',))
        self.assertEqual(tool.byte_serialize(self.img, first, 0x86 + 74)[4], 'borrowLend')
        self.assertEqual(tool.byte_serialize(self.img, first, 0x86 + 28)[5], 'load-u32@self+8')
        self.assertEqual(tool.byte_serialize(self.img, self.copies[4], 0x86 + 28)[5], 'self+8')

    def test_instruction_listing_covers_listed_extents(self):
        rows = [line.split('\t') for line in self.files['insns.tsv'].splitlines()[1:]]
        sizes = {}
        for row in rows:
            sizes[int(row[0], 16)] = sizes.get(int(row[0], 16), 0) + int(row[2])
            self.assertEqual(len(bytes.fromhex(row[3])), int(row[2]))
        self.assertEqual(sorted(sizes), [0x2bce570, 0x36aef70, 0x36b3f80, 0x4d84400])
        for c in self.copies:
            if c['start'] in sizes:
                self.assertEqual(sizes[c['start']], c['end'] - c['start'])

    def test_first_entry_after_table_is_not_an_arm(self):
        for c in self.copies:
            self.assertNotIn(c['stop_target'], set(c['entries']))

    def test_generated_files_match_packet(self):
        for name, text in self.files.items():
            with open(os.path.join(PACKET, name), encoding='ascii') as f:
                self.assertEqual(f.read(), text, name)

    def test_manifest_matches_packet(self):
        with open(os.path.join(PACKET, 'MANIFEST.sha256'), encoding='ascii') as f:
            rows = [line.split('  ', 1) for line in f.read().splitlines()]
        names = sorted(n for n in os.listdir(PACKET) if n != 'MANIFEST.sha256')
        self.assertEqual(sorted(n for _, n in rows), names)
        for digest, name in rows:
            with open(os.path.join(PACKET, name), 'rb') as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, name)

    # negative controls
    def test_spec_mutants_are_detected(self):
        spec = tool.default_spec()
        del spec['renames']['Bole']
        self.assertIsNotNone(tool.compare(self.img, self.copies, spec))
        spec = tool.default_spec()
        spec['niche_base'] = 0x87
        self.assertIsNotNone(tool.compare(self.img, self.copies, spec))
        spec = tool.default_spec()
        spec['inlined'].clear()
        self.assertIsNotNone(tool.compare(self.img, self.copies, spec))
        self.assertIsNone(tool.compare(self.img, self.copies, tool.default_spec()))

    def test_byte_mutants_are_detected(self):
        results = [tool.judge(self.img, self.copies, tool.default_spec(), m, tool.COPIES[0])
                   for _, m in tool.byte_mutants(self.img, tool.COPIES[0])]
        self.assertEqual(len(results), 6)
        self.assertTrue(all(r == 'killed' for r, _ in results))

    def test_unknown_bytes_fail_closed(self):
        with self.assertRaises(tool.DecodeError):
            tool.step(b'\x0f\x0b\x00\x00', 0x1000)
        with self.assertRaises(tool.DecodeError):
            tool.step(b'\x48\x8b\x45\x08', 0x1000)

    def test_out_of_extent_and_wrong_start(self):
        with self.assertRaises(tool.DecodeError):
            tool.decode_copy(self.img, tool.COPIES[0] + 1)
        with self.assertRaises(tool.DecodeError):
            tool.prologue(self.img, tool.COPIES[0] + 0x40)
        with self.assertRaises(tool.DecodeError):
            self.img.read(0x10, 4)

    def test_wrong_binary_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, tool.BINARY)
            os.makedirs(os.path.dirname(path))
            with open(path, 'wb') as f:
                f.write(b'\x7fELF\x02\x01' + b'\0' * 58)
            with self.assertRaises(SystemExit):
                tool.build(tmp)


if __name__ == '__main__':
    unittest.main()
