"""Real node94 bucket_guard duration, fixed window roller, and latency sampling controls; no target execution."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check
from bucket_guard_static import CONTROLS, LITERALS, RELATIVE, controls, read_va, relocations

class BucketGuardStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target = ROOT / 'artifacts/node/94/hl-node'
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == 'artifacts/node/94/hl-node')
        check(target, identity)
        cls.data = target.read_bytes()

    def test_actual_instruction_data_and_global_bindings(self):
        controls(self.data)
        self.assertEqual(len(relocations(self.data)), 4)

    def test_actual_instruction_corruptions(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = read_va(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'instruction changed'):
                    controls(changed)

    def test_actual_source_location_and_global_retargets(self):
        for slot, target in RELATIVE.items():
            with self.subTest(slot=hex(slot)):
                changed = bytearray(self.data)
                offset = changed.find(struct.pack('<QQq', slot, 8, target))
                self.assertGreaterEqual(offset, 0)
                changed[offset + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'relocation changed'):
                    relocations(changed)

    def test_actual_source_path_corruption(self):
        changed = bytearray(self.data)
        offset, _ = read_va(changed, 0x1e2490, 1)
        changed[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'literal changed'):
            controls(changed)

    def test_fixed_window_roller_field_offsets_and_names(self):
        # Struct name 'FixedWindowRoller' (17 bytes) at 0x217634
        name_body = read_va(self.data, 0x217634, 17)[1]
        self.assertEqual(name_body, b'FixedWindowRoller')

        # Debug struct format field bindings in fixed-window-roller-debug
        # Field pattern at offset 0x1c
        self.assertEqual(read_va(self.data, 0x13e09b9, 4)[1], bytes.fromhex('488d4f1c'))
        # Field count at offset 0x18
        self.assertEqual(read_va(self.data, 0x13e09b5, 4)[1], bytes.fromhex('4c8d7718'))
        # Field compression at offset 0x20
        self.assertEqual(read_va(self.data, 0x13e09b1, 4)[1], bytes.fromhex('4c8d5720'))

    def test_bucket_duration_integer_scaling_constants(self):
        # 1000 millis per second (0x3e8)
        self.assertEqual(read_va(self.data, 0x13c8ea1, 7)[1], bytes.fromhex('4169cfe8030000'))
        # 1,000,000 nanos per millisecond (0xf4240)
        self.assertEqual(read_va(self.data, 0x13c8eab, 7)[1], bytes.fromhex('4169ce40420f00'))
        # 86,400 seconds per day (0x15180)
        self.assertEqual(read_va(self.data, 0x13c8eb6, 7)[1], bytes.fromhex('4969d480510100'))

    def test_guarded_latency_timing_flag_and_atomic_unlock(self):
        # Guarded check: enabled flag at offset 0x20 tested against 1
        check_body = read_va(self.data, 0x2227c91, 9)[1]
        self.assertEqual(check_body, bytes.fromhex('440fb677204180fe01'))

        # Location structure passed to sampler at bucket_guard.rs:118:21 (0x569e0a0)
        loc_ref = read_va(self.data, 0x2228053, 7)[1]
        self.assertEqual(loc_ref, bytes.fromhex('488d1546604703'))

        # Spinlock unlock via atomic compare-exchange: lock cmpxchg %cl, (%r15)
        unlock_body = read_va(self.data, 0x2228072, 5)[1]
        self.assertEqual(unlock_body, bytes.fromhex('f0410fb00f'))

if __name__ == '__main__':
    unittest.main()
