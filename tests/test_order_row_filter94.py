import csv
import hashlib
import importlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
packet = importlib.import_module('order_row_filter94')


def row(outer=3, inner=2, key=17, status=1, fill=0x5a):
    data = bytearray([fill] * 0x268)
    struct.pack_into('<Q', data, 0, outer)
    struct.pack_into('<Q', data, 8, inner)
    if inner == 2:
        struct.pack_into('<Q', data, 0xa8, key)
        data[0x100] = status
    else:
        struct.pack_into('<Q', data, 0xa0, key)
        data[0x119] = status
    return bytes(data)


class OrderRowFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        cls.secs = packet.sections(cls.data)

    def test_digest_and_wrong_input(self):
        self.assertEqual(packet.authenticate(self.data), packet.DIGEST)
        with self.assertRaises(packet.EvidenceError):
            packet.authenticate(self.data[:-1])
        with self.assertRaises(packet.EvidenceError):
            packet.authenticate(b'wrong')

    def test_full_selected_extents_and_corruption(self):
        _, fdes = packet.eh_frame_records(self.data, self.secs)
        by_start = {f['start']: f for f in fdes}
        for _, start, end, digest in packet.FUNCTIONS:
            self.assertEqual(by_start[start]['end'], end)
            raw = packet.read_va(self.data, self.secs, start, end - start, True)
            packet.verify_body(raw, digest)
            damaged = bytearray(raw)
            damaged[len(damaged) // 2] ^= 1
            with self.assertRaises(packet.EvidenceError):
                packet.verify_body(bytes(damaged), digest)

    def test_mapping_rejects_nobits_outside_and_ambiguous(self):
        bss = next(s for s in self.secs if s['type'] == 8 and s['size'])
        with self.assertRaises(packet.EvidenceError):
            packet.file_offset([bss], bss['address'], 1)
        with self.assertRaises(packet.EvidenceError):
            packet.file_offset(self.secs, 1 << 63, 4)
        with self.assertRaises(packet.EvidenceError):
            packet.file_offset(self.secs, -1, 4)
        with self.assertRaises(packet.EvidenceError):
            packet.file_offset(self.secs, 0, 0)
        text = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(packet.EvidenceError):
            packet.file_offset([text, dict(text)], text['address'], 1)

    def test_all_selected_branches_reject_condition_or_target_corruption(self):
        for name, site, kind, target in packet.BRANCHES:
            with self.subTest(name=name):
                raw = packet.read_va(self.data, self.secs, site, 6, True)
                inst, actual = packet.decode_branch(raw, site, kind, target)
                self.assertEqual(actual, target)
                bad = bytearray(inst)
                bad[-1] ^= 1
                with self.assertRaises(packet.EvidenceError):
                    packet.decode_branch(bad, site, kind, target)
                bad = bytearray(inst)
                bad[1 if bad[0] == 0x0f else 0] ^= 1
                with self.assertRaises(packet.EvidenceError):
                    packet.decode_branch(bad, site, kind, target)

    def test_all_transfers_reject_opcode_or_displacement_corruption(self):
        for name, site, kind, target in packet.CALLS:
            with self.subTest(name=name):
                raw = packet.read_va(self.data, self.secs, site, 6, True)
                inst, actual = packet.decode_call(raw, site, kind, target)
                self.assertEqual(actual, target)
                bad = bytearray(inst)
                bad[-1] ^= 1
                with self.assertRaises(packet.EvidenceError):
                    packet.decode_call(bad, site, kind, target)
                bad = bytearray(inst)
                bad[0] ^= 1
                with self.assertRaises(packet.EvidenceError):
                    packet.decode_call(bad, site, kind, target)

    def test_relocation_selection_rejects_missing_duplicate_and_partial(self):
        raw = struct.pack('<QQq', 0x120, 8, 0x1000)
        sec = {'type': 4, 'offset': 0, 'size': len(raw)}
        self.assertEqual(packet.relocations(raw, [sec], [0x120])[0x120][1], 0x1000)
        with self.assertRaises(packet.EvidenceError):
            packet.relocations(raw, [sec], [0x121])
        dup = raw + raw
        with self.assertRaises(packet.EvidenceError):
            packet.relocations(dup, [{'type': 4, 'offset': 0, 'size': len(dup)}], [0x120])
        with self.assertRaises(packet.EvidenceError):
            packet.relocations(raw, [{'type': 4, 'offset': 0, 'size': len(raw)-1}], [0x120])

    def test_operands_and_target_backed_layout(self):
        facts = {}
        for name, site, expected, offset, fmt in packet.OPERANDS:
            raw = packet.read_va(self.data, self.secs, site, len(bytes.fromhex(expected)), True)
            self.assertEqual(raw.hex(), expected)
            facts[name] = struct.unpack_from('<' + fmt, raw, offset)[0]
        self.assertEqual(facts['row-stride'], 0x268)
        self.assertEqual(facts['selected-outer-tag'], 3)
        for variant, key_off, value_off, status_off in (
                ('inner-two', 0xa8, 0xc0, 0x100),
                ('other-inner', 0xa0, 0xb8, 0x119)):
            record = facts[variant + '-record-offset']
            self.assertEqual(facts['row-stride'] + record + facts['key-displacement-from-record-cursor'], key_off)
            self.assertEqual(facts['row-stride'] + record + facts['write-displacement-from-record-cursor'], value_off)
            self.assertEqual(facts[variant + '-status-offset'], status_off)

    def test_target_lsda_first_and_later_drop_landing_pads(self):
        _, fdes = packet.eh_frame_records(self.data, self.secs)
        frame = next(f for f in fdes if f['start'] == 0x3bc29a0)
        sec = next(s for s in self.secs if s['name'] == '.gcc_except_table')
        off = packet.file_offset(self.secs, frame['lsda'], 1)
        raw = self.data[off:sec['offset'] + sec['size']]
        records = packet.lsda_calls(raw, frame['start'], frame['end'], frame['lsda'])
        landed = {r['start_va']: r['landing_va'] for r in records}
        self.assertEqual(landed['0x3bc2a8c'], '0x3bc2b7b')
        self.assertEqual(landed['0x3bc2b52'], '0x3bc2b73')
        with self.assertRaises(packet.EvidenceError):
            packet.lsda_calls(raw[:4], frame['start'], frame['end'], frame['lsda'])
        with self.assertRaises(packet.EvidenceError):
            packet.lsda_calls(b'\x00' + raw[1:12], frame['start'], frame['end'], frame['lsda'])

    def test_single_row_tag_key_flag_status_decisions(self):
        for inner in (0, 1, 2, 3, 5):
            off = 0xc0 if inner == 2 else 0xb8
            for status in (0, 1, 2, 255):
                for flag in (0, 1, 2, 255):
                    r = row(inner=inner, status=status)
                    action, write_off = packet.outcome(r, 17, flag)
                    if flag and not status:
                        self.assertEqual((action, write_off), ('drop', None))
                    else:
                        self.assertEqual((action, write_off), ('update', off))
                    self.assertEqual(packet.outcome(r, 18, flag), ('keep', None))
        self.assertEqual(packet.outcome(row(outer=2), 17, 1), ('keep', None))
        self.assertEqual(packet.outcome(row(inner=4), 17, 1), ('keep', None))
        # The first tag is checked as a low dword by the filter.
        self.assertEqual(packet.outcome(row(outer=(1 << 32) | 3), 17, 0), ('update', 0xc0))

    def test_value_bits_are_copied_without_float_arithmetic(self):
        original = row(inner=2, status=1)
        for bits in (0, 0x8000000000000000, 0x7ff8000000000042, (1 << 64)-1):
            result, actions = packet.project([original], 17, 1, bits)
            self.assertEqual(actions, ['update'])
            self.assertEqual(struct.unpack_from('<Q', result[0], 0xc0)[0], bits)
            self.assertEqual(result[0][:0xc0], original[:0xc0])
            self.assertEqual(result[0][0xc8:], original[0xc8:])

    def test_multiple_drops_stable_order_and_updates(self):
        rows = [row(inner=2,status=0,fill=10), row(inner=4,fill=20),
                row(inner=3,status=1,fill=30), row(inner=2,status=0,fill=40),
                row(inner=2,key=19,status=0,fill=50), row(inner=2,status=2,fill=60)]
        result, actions = packet.project(rows, 17, 1, 0x123456789abcdef0)
        self.assertEqual(actions, ['drop','keep','update','drop','keep','update'])
        self.assertEqual([r[0x30] for r in result], [20,30,50,60])
        self.assertEqual(struct.unpack_from('<Q', result[1], 0xb8)[0], 0x123456789abcdef0)
        self.assertEqual(struct.unpack_from('<Q', result[3], 0xc0)[0], 0x123456789abcdef0)
        self.assertEqual(packet.project([], 17, 1, 1), ([], []))

    def test_exception_projection_preserves_unprocessed_suffix(self):
        rows = [row(inner=2, status=0, fill=11),
                row(inner=3, status=1, fill=22),
                row(inner=3, status=0, fill=33),
                row(outer=2, fill=44)]
        first, actions = packet.project_with_drop_failure(rows, 17, 1, 42, 0)
        self.assertEqual(actions, ['drop-throws'])
        self.assertEqual(first, rows[1:])
        later, actions = packet.project_with_drop_failure(rows, 17, 1, 42, 1)
        self.assertEqual(actions, ['drop', 'update', 'drop-throws'])
        self.assertEqual([r[0x30] for r in later], [22, 44])
        self.assertEqual(struct.unpack_from('<Q', later[0], 0xb8)[0], 42)
        self.assertEqual(later[1], rows[3])
        with self.assertRaises(packet.EvidenceError):
            packet.project_with_drop_failure(rows, 17, 1, 42, 2)

    def test_projection_rejects_invalid_inputs(self):
        with self.assertRaises(packet.EvidenceError):
            packet.outcome(b'', 17, 1)
        with self.assertRaises(packet.EvidenceError):
            packet.outcome(row(), -1, 1)
        with self.assertRaises(packet.EvidenceError):
            packet.outcome(row(), 17, 256)
        with self.assertRaises(packet.EvidenceError):
            packet.project([row()], 17, 1, 1 << 64)

    def test_generated_evidence_exactly_matches_retained(self):
        expected = packet.ROOT / 'research/work-items/RE-006-pending-order-row-filter-94'
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            info = packet.generate(self.data, out)
            self.assertEqual(info['selected_fdes'], 3)
            self.assertEqual(info['selected_fde_bytes'], 1441)
            self.assertEqual(info['synthetic_rows'], 126)
            for f in sorted(out.iterdir()):
                with self.subTest(file=f.name):
                    self.assertEqual(f.read_bytes(), (expected / f.name).read_bytes())
            with (out / 'layout.tsv').open(newline='') as f:
                layouts = list(csv.DictReader(f, delimiter='\t'))
            self.assertEqual(layouts[0]['key_offset'], '0xa8')
            with (out / 'summary.json').open() as f:
                self.assertEqual(json.load(f)['target_sha256'], packet.DIGEST)


if __name__ == '__main__':
    unittest.main()
