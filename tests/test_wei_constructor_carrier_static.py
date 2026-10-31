import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import wei_constructor_carrier_static as carrier

PACKET = ROOT / 'research/work-items/RE-001-wei-constructor-carrier-94'
BINARY = ROOT / 'artifacts/node/94/hl-node'
GENERATED = ('producer.objdump.txt', 'constructor.objdump.txt', 'consumer.objdump.txt',
             'frames.txt', 'relocations.txt', 'records.json')


class CarrierEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = BINARY.open('rb')
        cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        carrier.authenticate(cls.data)
        cls.record = carrier.inspect_bytes(cls.data)
        cls.secs = carrier.sections(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.stream.close()

    def rejected_mutation(self, offset, replacement):
        # Kernel-private copy-on-write pages: the authenticated artifact is never written.
        with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY) as mutated:
            mutated[offset:offset + len(replacement)] = replacement
            with self.assertRaises(ValueError):
                carrier.inspect_bytes(mutated)

    def test_exact_three_fdes_and_call_bridges(self):
        self.assertEqual(sum(b['bytes'] for b in self.record['bodies'].values()), 512)
        for name, (start, end) in carrier.RANGES.items():
            b = self.record['bodies'][name]
            self.assertEqual((int(b['start'], 16), int(b['end'], 16)), (start, end))
            self.assertEqual(int(b['fde']['va'], 16), carrier.FDE_IDS[name][0])
        self.assertEqual(self.record['calls']['constructor'][1]['target'], '0x1704700')
        self.assertEqual(self.record['calls']['consumer'][1]['target'], '0x26bb3c0')
        self.assertEqual(len(self.record['relocations']), 8)

    def test_observed_writes_and_unresolved_alias_are_kept_distinct(self):
        self.assertEqual([(w['offset'], w['bytes']) for w in self.record['observed_output_writes']],
                         [(8, 8), (16, 8), (24, 8), (0, 1)])
        self.assertEqual(self.record['observed_output_writes'][-1]['value'], 6)
        self.assertIn('Bytes 1..7', self.record['direct_write_gap'])
        self.assertIn('0x1704770', self.record['post_store_opaque_call'])
        self.assertEqual(len(self.record['assumptions_for_conditional_six_flow']), 3)
        self.assertIn('qualified/unknown', self.record['conclusion'])
        self.assertIn('another consumer route directly stores 9', self.record['used_chain'][-1])
        self.assertFalse(self.record['captured_binary_executed'])
        self.assertFalse(self.record['component_gates_requested'])

    def test_lsda_first_call_uses_return_pc_minus_one(self):
        lsda = self.record['producer_lsda']
        self.assertEqual(lsda['raw'], 'ffff010a1b098a01002484010000')
        first, *later = lsda['call_associations']
        self.assertEqual(first, {'call_va': '0x170471e', 'return_pc': '0x1704724',
                                 'lookup_pc': '0x1704723', 'row_index': 0})
        self.assertEqual({r['row_index'] for r in later}, {1})
        self.assertEqual(lsda['rows'][0]['landing_pad'], '0x170478a')
        self.assertIsNone(lsda['rows'][1]['landing_pad'])

    def test_wrong_target_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            carrier.authenticate(b'not Node94')
        with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY) as mutated:
            mutated[0x170375f + 3] ^= 3
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                carrier.authenticate(mutated)

    def test_actual_dataflow_instruction_corruptions_are_rejected(self):
        controls = [(0x170475f + 3, b'\x09'), (0x1704753 + 3, b'\x10'),
                    (0x1704776 + 2, b'\xf0'), (0x26bb3f2 + 2, b'\xf7'),
                    (0x16ca300 + 4, b'\x11'), (0x16ca30f + 4, b'\x11'),
                    (0x16ca314 + 1, b'\x06'), (0x16ca316, b'\x74'),
                    (0x16ca344 + 1, b'\x0b'), (0x16ca2a4 + 2, b'\x06')]
        for va, value in controls:
            with self.subTest(va=hex(va)):
                offset, _ = carrier.read_va(self.data, self.secs, va, len(value))
                self.rejected_mutation(offset, value)

    def test_direct_call_bridge_corruptions_are_rejected(self):
        for va in (0x26bb3f8, 0x16ca30a):
            with self.subTest(va=hex(va)):
                offset, raw = carrier.read_va(self.data, self.secs, va, 5)
                self.rejected_mutation(offset + 1, bytes([raw[1] ^ 1]))

    def test_all_eight_selected_relocation_addends_are_required(self):
        for row in self.record['relocations']:
            with self.subTest(slot=row['slot']):
                offset = int(row['file_offset'], 16) + 16
                self.rejected_mutation(offset, bytes([self.data[offset] ^ 1]))

    def test_cfi_and_lsda_corruptions_are_rejected(self):
        fde = self.record['bodies']['producer']['fde']
        cie = self.record['bodies']['producer']['cie']['raw_record']
        controls = [(int(fde['file_offset'], 16) + 12, b'\xa9'),
                    (int(cie['file_offset'], 16) + 14, b'\x02'),
                    (int(cie['file_offset'], 16) + 19, b'\x01')]
        for va in (0x94f80a, 0x94f80c, 0x94f80e):
            offset, raw = carrier.read_va(self.data, self.secs, va, 1)
            controls.append((offset, bytes([raw[0] ^ 1])))
        for offset, value in controls:
            with self.subTest(offset=hex(offset)):
                self.rejected_mutation(offset, value)

    def test_bounded_native_exports_repeat_and_packet_records_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / 'first', Path(tmp) / 'second'
            supplied = Path(tmp) / 'supplied-node94'
            invalid = Path(tmp) / 'invalid-target'
            invalid.write_bytes(b'not Node94')
            supplied.symlink_to(invalid)
            rejected_before = Path(tmp) / 'rejected-before'
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                carrier.collect(supplied, rejected_before)
            self.assertFalse(rejected_before.exists())
            supplied.unlink()
            supplied.symlink_to(BINARY)
            native_run = carrier.subprocess.check_output
            substituted = []
            def replace_supplied_path(argv, **kwargs):
                if '-d' in argv and not substituted:
                    # Replace the public input name after snapshot acquisition.
                    # The native reader must still read the authenticated copy.
                    supplied.unlink()
                    supplied.write_bytes(b'not Node94')
                    native_input = Path(argv[-1])
                    self.assertNotEqual(native_input, supplied)
                    native_stat, source_stat = native_input.stat(), BINARY.stat()
                    self.assertNotEqual((native_stat.st_dev, native_stat.st_ino),
                                        (source_stat.st_dev, source_stat.st_ino))
                    self.assertEqual(native_input.parent.stat().st_mode & 0o777, 0o700)
                    substituted.append(True)
                return native_run(argv, **kwargs)
            with mock.patch.object(carrier.subprocess, 'check_output', side_effect=replace_supplied_path):
                actual = carrier.collect(supplied, first)
            self.assertEqual(substituted, [True])
            rejected_after = Path(tmp) / 'rejected-after'
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                carrier.collect(supplied, rejected_after)
            self.assertFalse(rejected_after.exists())
            carrier.collect(BINARY, second)
            for name in GENERATED:
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)
            committed = json.loads((PACKET / 'records.json').read_text())
            # Raw native text is retained for its stated GNU version. Normalized
            # records must match even when a compatible GNU version formats text differently.
            actual.pop('native_tool_versions')
            committed.pop('native_tool_versions')
            self.assertEqual(actual, committed)
            self.assertEqual(sum(r['instruction_count'] for r in actual['native'].values()), 157)
            self.assertTrue(actual['native']['producer']['byte6_store_dominates_local_normal_return'])
            before = {p.name: p.read_bytes() for p in first.iterdir()}
            with self.assertRaises(FileExistsError):
                carrier.collect(BINARY, first)
            self.assertEqual(before, {p.name: p.read_bytes() for p in first.iterdir()})

    def test_packet_manifest_covers_every_packet_file(self):
        entries = {}
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ', 1)
            self.assertNotIn(name, entries)
            entries[name] = digest
        self.assertEqual(set(entries), {p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'})
        for name, digest in entries.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main()
