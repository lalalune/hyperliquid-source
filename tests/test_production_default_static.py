"""Controls against the captured node94 initializer and its real ELF records."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import production_default_static as tool

PACKET = tool.ROOT / 'research/work-items/RE-001-production-default-context-94'


class ProductionDefaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (tool.ROOT / 'artifacts/node/94/hl-node').read_bytes()
        cls.result = tool.build(cls.data)
        cls.secs = tool.sections(cls.data)

    def mutate_va(self, va, value):
        changed = bytearray(self.data)
        section = next(s for s in self.secs if s['type'] != 8 and
                       s['address'] <= va < s['address'] + s['size'])
        offset = section['offset'] + va - section['address']
        changed[offset:offset + len(value)] = value
        return changed

    def test_pinned_record_and_real_nonzero_initializers(self):
        self.assertEqual(json.loads((PACKET / 'records.json').read_bytes()), self.result)
        self.assertEqual(self.result['range']['bytes'], 336)
        self.assertEqual([s['offset'] for s in self.result['sentinel_stores']], ['0x90', '0xa8'])
        for store in self.result['sentinel_stores']:
            self.assertEqual(int(store['value'], 16), 1 << 63)
            self.assertNotEqual(int(store['value'], 16), 0)
        self.assertEqual(self.result['static_copy']['relocated_first_qword'], 'load_bias + 0x202e90')
        self.assertEqual(self.result['helper_location']['path'].split('/')[-1], 'crit_msg.rs')
        self.assertEqual(len(self.result['calls']), 8)

    def test_zeroing_reference_control_is_rejected(self):
        changed = self.mutate_va(0x143f581, bytes(8))
        with self.assertRaisesRegex(ValueError, 'Sentinel value changed'):
            tool.observe(changed)

    def test_store_destination_and_flag_value_controls(self):
        for va, new, reason in [(0x143f58c, struct.pack('<I', 0x98), 'Sentinel destinations'),
                                 (0x143f56a, b'\x01', 'Flag word')]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, reason):
                    tool.observe(self.mutate_va(va, new))

    def test_actual_label_and_fde_controls(self):
        with self.assertRaisesRegex(ValueError, 'Label copy changed'):
            tool.observe(self.mutate_va(0x21964c, b'X'))
        fde = int(self.result['range']['fde_va'], 16)
        with self.assertRaisesRegex(ValueError, 'Initializer FDE changed'):
            tool.observe(self.mutate_va(fde + 12, struct.pack('<I', 335)))

    def test_real_relocation_controls(self):
        for slot, addend, message in [(0x566a228, 0x202e90, 'Static initializer relocation'),
                                     (0x577acf0, tool.START, 'function-pointer binding'),
                                     (0x576dfd8, 0x54c06b0, 'Call relocation')]:
            with self.subTest(slot=hex(slot)):
                changed = bytearray(self.data)
                record = struct.pack('<QQq', slot, 8, addend)
                offset = changed.find(record)
                self.assertGreaterEqual(offset, 0)
                self.assertEqual(changed.find(record, offset + 1), -1)
                changed[offset + 16] ^= 1
                with self.assertRaisesRegex(ValueError, message):
                    tool.observe(changed)

    def test_identity_gate_precedes_observation(self):
        changed = self.data[:-1] + bytes([self.data[-1] ^ 1])
        self.assertNotEqual(hashlib.sha256(changed).hexdigest(), tool.SHA256)
        with self.assertRaisesRegex(ValueError, 'Wrong node94 SHA-256'):
            tool.build(changed)
