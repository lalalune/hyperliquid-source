import hashlib
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hip3_limits_schema_codec_115',
                                              ROOT / 'tools/hip3_limits_schema_codec_115.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

PACKET = ROOT / 'research/work-items/dex-registry-hip3-limits-schema-state-115'


def copy_at(entry):
    (copy,) = [c for c in tool.COPIES if c['entry'] == entry]
    return copy


class Hip3LimitsSchemaCodecTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.TARGET.read_bytes()
        cls.result = tool.build(cls.data)
        cls.files = tool.render(cls.result)

    def _off(self, va):
        s = tool.Image(self.data).section_of(va)
        return s['offset'] + va - s['address']

    def _patched(self, va, expect, raw):
        off = self._off(va)
        self.assertEqual(self.data[off:off + len(expect)], expect)
        out = bytearray(self.data)
        out[off:off + len(raw)] = raw
        return bytes(out)

    def _run(self, data, entry, flag, tags, cap):
        image = tool.Image(data)
        copy = copy_at(entry)
        stubs = tool.make_stubs(image, copy, tool.Script(None))
        return tool.run_serializer(image, copy, stubs, flag, tags, cap, tool.START_LEN)[:4]

    def test_capture_identity(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tool.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertEqual(s['mismatches'], 0)
        self.assertEqual(s['bodies'], 9)
        self.assertGreater(s['cases'], 5000)
        self.assertEqual({r[-1] for r in self.result['cases']}, {'match'})
        failing = [r for r in self.result['cases'] if r[6] != '']
        self.assertGreater(len(failing), 1000)

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

    def test_reconstruction_examples(self):
        data, log, end, result = tool.recon_serialize(copy_at(0x2bc1190), 1, {}, 4096, 0, None)
        self.assertEqual(data, b'\x86\xadtotal_oi_cap2\xb2oi_sz_cap_per_perp\xb1max_transfer_ntl2')
        self.assertEqual(result, (tool.OK_WORD, tool.PATTERN, tool.PATTERN))
        data, log, _, _ = tool.recon_serialize(copy_at(0x2bc0900), 0, {0x20: 2, 0x21: 1}, 4096, 0, None)
        self.assertEqual(data, b'\x95')
        self.assertNotIn(('call', 'str', ('key:disabled_state',)), log)
        data, log, _, _ = tool.recon_serialize(copy_at(0x2bc0900), 2, {0x20: 2, 0x21: 1}, 4096, 0, None)
        self.assertEqual(data, b'\xb5')
        self.assertIn(('call', 'str', ('key:disabled_state',)), log)
        self.assertIn(('call', 'str', ('key:ValidatorDisabled',)), log)
        self.assertNotIn(('call', 'str', ('key:m',)), log)

    def test_jump_tables_are_read_from_bytes(self):
        rows = self.result['tables']
        self.assertEqual(len(rows), 12)
        for r in rows:
            base = int(r[3], 16)
            off = struct.unpack('<i', self.data[self._off(base + 4 * r[4]):self._off(base + 4 * r[4]) + 4])[0]
            self.assertEqual(off, r[5])
            self.assertEqual(int(r[6], 16), base + off)

    def test_rejects_other_capture(self):
        with self.assertRaises(tool.Reject):
            tool.build(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_rejects_unmapped_address(self):
        with self.assertRaises(tool.Reject):
            tool.Image(self.data).read(0x10, 4)

    def test_header_immediate_mutation_is_detected(self):
        want = tool.recon_serialize(copy_at(0x2bc1190), 0, {}, 64, tool.START_LEN, None)
        self.assertEqual(self._run(self.data, 0x2bc1190, 0, {}, 64), want)
        # or $0x86,%bpl at 0x2bc11b7 (40 80 cd 86)
        bad = self._patched(0x2bc11b7, bytes.fromhex('4080cd86'), bytes.fromhex('4080cd85'))
        self.assertNotEqual(self._run(bad, 0x2bc1190, 0, {}, 64), want)

    def test_key_gate_mutation_is_detected(self):
        tags = {0x84: 0, 0x99: 0}
        want = tool.recon_serialize(copy_at(0x2bc17c0), 1, tags, 4096, tool.START_LEN, None)
        self.assertEqual(self._run(self.data, 0x2bc17c0, 1, tags, 4096), want)
        # cmpb $0x0,0x1b(%r15) at 0x2bc1955 gates the oracle_updater key;
        # comparing with 1 instead makes flag 1 skip the key.
        bad = self._patched(0x2bc1955, bytes.fromhex('41807f1b00'), bytes.fromhex('41807f1b01'))
        self.assertNotEqual(self._run(bad, 0x2bc17c0, 1, tags, 4096), want)

    def test_jump_table_mutation_is_detected(self):
        tags = {0x20: 1, 0x21: 0}
        want = tool.recon_serialize(copy_at(0x2bc0900), 1, tags, 4096, tool.START_LEN, None)
        self.assertEqual(self._run(self.data, 0x2bc0900, 1, tags, 4096), want)
        entry0 = self.data[self._off(0x60923c):self._off(0x60923c) + 4]
        bad = self._patched(0x60923c + 4, self.data[self._off(0x609240):self._off(0x609240) + 4], entry0)
        self.assertNotEqual(self._run(bad, 0x2bc0900, 1, tags, 4096), want)

    def test_role_table_is_checked(self):
        copy = tool.COPIES[0]
        saved = copy['roles']['u64']
        copy['roles']['u64'] = 0x25e9f11
        try:
            with self.assertRaises(tool.Reject):
                tool.build(self.data)
        finally:
            copy['roles']['u64'] = saved

    def test_entries_are_fde_starts(self):
        for row in self.result['functions']:
            self.assertGreater(row['decoded_bytes'], 0)
            self.assertLessEqual(row['decoded_bytes'], row['fde_bytes'])


if __name__ == '__main__':
    unittest.main()
