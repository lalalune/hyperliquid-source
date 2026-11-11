import hashlib
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hip3_subrecord_helpers_115',
                                              ROOT / 'tools/hip3_subrecord_helpers_115.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

PACKET = ROOT / 'research/work-items/dex-registry-hip3-subrecord-helpers-115'


class Hip3SubrecordHelpersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.TARGET.read_bytes()
        cls.result = tool.build(cls.data)
        cls.files = tool.render(cls.result)
        image = tool.Image(cls.data)
        _, recs, _ = tool.fde_extents.fde_extents(cls.data)
        by_start = {r['start']: r for r in recs}
        image.reloc = {tool.WRITE_CHAR_SLOT: int(cls.result['slots'][3][3], 16)}
        cls.helpers = {}
        for h in tool.HELPERS:
            h = dict(h, end=by_start[h['entry']]['end'])
            h['roles'] = tool.resolve_roles(image, h, tool.linear(image, h['entry'], h['end']), None)
            cls.helpers[h['entry']] = h

    def _off(self, va):
        s = tool.Image(self.data).section_of(va)
        return s['offset'] + va - s['address']

    def _patched(self, va, expect, raw):
        off = self._off(va)
        self.assertEqual(self.data[off:off + len(expect)], expect)
        out = bytearray(self.data)
        out[off:off + len(raw)] = raw
        return bytes(out)

    def _run(self, data, entry, inp, fail_at=None):
        image = tool.Image(data)
        image.reloc = {tool.WRITE_CHAR_SLOT: self.helpers[0x41b0e20]['roles']['write_char']}
        h = self.helpers[entry]
        return tool.run_helper(image, h, tool.make_stubs(h, tool.Script(fail_at)), inp)

    def _check(self, entry, inp, va, expect, raw, fail_at=None):
        want = tool.recon(self.helpers[entry], inp, fail_at)
        self.assertEqual(self._run(self.data, entry, inp, fail_at), want)
        bad = self._patched(va, bytes.fromhex(expect), bytes.fromhex(raw))
        try:
            got = self._run(bad, entry, inp, fail_at)
        except tool.Reject:
            return
        self.assertNotEqual(got, want)

    def test_capture_identity(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tool.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertEqual(s['mismatches'], 0)
        self.assertEqual(s['bodies'], 21)
        self.assertGreater(s['cases'], 5000)
        self.assertEqual({r[-1] for r in self.result['cases']}, {'match'})
        outcomes = {r[2] for r in self.result['paths']}
        self.assertEqual(outcomes, {'ok', 'err', 'panic'})

    def test_every_negative_control_is_caught(self):
        self.assertEqual(len(self.result['negatives']), len(tool.WRONG))
        for name, caught, verdict, first in self.result['negatives']:
            self.assertGreater(caught, 0, name)
            self.assertEqual(verdict, 'caught')

    def test_packet_files_are_reproduced_byte_for_byte(self):
        on_disk = sorted(p.name for p in PACKET.iterdir() if p.name not in ('README.md', 'MANIFEST.sha256'))
        self.assertEqual(on_disk, sorted(self.files))
        for name, text in self.files.items():
            self.assertEqual((PACKET / name).read_bytes(), text.encode('ascii'), name)

    def test_manifest_covers_packet(self):
        rows = [line.split('  ', 1) for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines()]
        self.assertEqual(sorted(n for _, n in rows),
                         sorted(p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'))
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_ring_iterator_examples(self):
        # capacity 4, head 3, length 3: slices [3,4) and [0,2).
        it = tool.oi_iterator((4, tool.BUF, 3, 3), {})
        self.assertEqual(it, (2, tool.BUF + 0x30, tool.BUF + 0x40, tool.BUF, tool.BUF + 0x20, 0,
                              tool.BUF + 0x40, tool.BUF, 3))
        # no wrap: the last word is the end index, not the length.
        it = tool.oi_iterator((8, tool.BUF, 2, 3), {})
        self.assertEqual(it[2], tool.BUF + 0x50)
        self.assertEqual(it[8], 5)
        # niche representation.
        self.assertEqual(tool.oi_iterator((tool.NICHE, 0, 3, 7), {}), (0, 0, 0, 3, 0, 0, 0, 3, 0))
        self.assertEqual(tool.oi_iterator((tool.NICHE, 9, 3, 7), {}), (1, 0, 9, 3, 1, 0, 9, 3, 7))

    def test_texts_are_read_from_bytes(self):
        texts = {r[0]: r for r in self.result['texts']}
        self.assertEqual(texts['time_text_panic'][1], 'a Display implementation returned an error unexpectedly')
        for name in ('address_ext_error', 'time_ext_error_copy1', 'time_ext_error_copy3'):
            self.assertEqual(texts[name][1], 'expected tuple')

    def test_oi_key_gate_mutation_is_detected(self):
        # cmp $0 -> cmp $1 before `je skip`: flag 1 then skips the key.
        inp = dict(flag=1, cap=4101, len=tool.START_LEN, words=(8, tool.BUF, 3, 4))
        self._check(0x2ce96a0, inp, 0x2ce96a9, '807e1b00', '807e1b01')

    def test_ring_wrap_mutation_is_detected(self):
        inp = dict(flag=0, cap=4101, len=tool.START_LEN, words=(2, tool.BUF, 1, 1))
        self._check(0x2ce96a0, inp, 0x2ce9755, '7711', '7311')

    def test_sub_deployers_gate_mutation_is_detected(self):
        # cmp $1 -> cmp $0 before `jne skip`: flag 0 then writes the key.
        inp = dict(flag=0, cap=4101, len=tool.START_LEN)
        self._check(0x2ce6f90, inp, 0x2ce6f98, '807e1b01', '807e1b00')

    def test_bool_marker_mutation_is_detected(self):
        inp = dict(flag=1, cap=4101, len=tool.START_LEN, b=1)
        self._check(0x226a340, inp, 0x226a359, '83cfc2', '83cfc0')

    def test_ext_name_mutation_is_detected(self):
        inp = dict(flag=1, cap=4101, len=tool.START_LEN, name=tool.EXT_NAME, r8=tool.IN_BASE + 8)
        self._check(0x226cf70, inp, 0x226cf80, '48b85f45787453747275', '48b85f45787453747276')

    def test_time_separator_mutation_is_detected(self):
        inp = dict(flag=1, cap=4101, len=tool.START_LEN)
        self._check(0x41b0e20, inp, 0x41b0e91, 'be54000000', 'be20000000')

    def test_ok_word_mutation_is_detected(self):
        inp = dict(flag=1, cap=4101, len=tool.START_LEN, b=0)
        self._check(0x226a340, inp, 0x226a370, '48b80400000000000080', '48b80300000000000080')

    def test_rejects_other_capture(self):
        with self.assertRaises(tool.Reject):
            tool.build(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_rejects_unmapped_address(self):
        with self.assertRaises(tool.Reject):
            tool.Image(self.data).read(0x10, 4)

    def test_role_table_is_checked(self):
        h = tool.HELPERS[6]
        saved = h['roles']['u64']
        h['roles']['u64'] = saved + 1
        try:
            with self.assertRaises(tool.Reject):
                tool.build(self.data)
        finally:
            h['roles']['u64'] = saved

    def test_entries_are_fde_starts(self):
        for row in self.result['functions']:
            self.assertGreater(row[6], 0)
            self.assertLessEqual(row[6], row[4])


if __name__ == '__main__':
    unittest.main()
