import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from field1_5_varint_reader_static import (PACKET, SHA, SIZE, SLOW_SLOT,
                                           TARGET, analyze,
                                           fast_marker_outcome, generate,
                                           slow_outcome)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class Field15VarintReaderStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != SIZE:
            raise unittest.SkipTest('pinned node115 target is not '
                                    'materialised')
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != SHA:
            raise unittest.SkipTest('target digest is not the pinned '
                                    'node115 distribution')
        cls.retained = payload(PACKET / 'records.json')
        cls.payload = analyze(cls.data)
        cls.regenerated = generate(TARGET, tempfile.mkdtemp())

    def mutated(self, va, delta, value):
        data = bytearray(self.data)
        offset = self.offset_of(va)
        data[offset + delta] = value
        return data

    def offset_of(self, va):
        for s in sections(self.data):
            if (s['type'] != 8 and s['address'] <= va
                    < s['address'] + s['size']):
                return s['offset'] + va - s['address']
        raise AssertionError('unmapped va')

    def test_native_regeneration_matches_retained_packet(self):
        self.assertEqual(self.regenerated, self.retained)
        self.assertEqual(self.payload, self.retained)
        regen_dir = Path(tempfile.mkdtemp())
        generate(TARGET, regen_dir)
        for name in ('frames.txt', 'copy_a.objdump.txt',
                     'copy_b.objdump.txt', 'slow_path.objdump.txt'):
            self.assertEqual((regen_dir / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_fast_marker_table_for_every_marker(self):
        classes = self.payload['fast_route']['marker_classes']
        by_marker = {}
        for row in classes:
            if 'markers' in row:
                lo, hi = row['markers'].split('..')
                for marker in range(int(lo), int(hi) + 1):
                    by_marker[marker] = {k: v for k, v in row.items()
                                         if k != 'markers'}
            else:
                by_marker[row['marker']] = {k: v for k, v in row.items()
                                            if k != 'marker'}
        self.assertEqual(len(by_marker), 256)
        for marker in range(256):
            self.assertEqual(by_marker[marker],
                             fast_marker_outcome(marker), marker)
        # The family boundary: marker 253 reads the u64 payload here
        # (the u32 reader of #2412 errors on it), and markers 254/255
        # error with field1 5 (the u64 reader of #2300 writes field1
        # 2 on this route), consuming nothing.
        self.assertEqual(fast_marker_outcome(253),
                         {'outcome': 'value',
                          'payload': 'u64 little-endian', 'consumed': 9})
        self.assertEqual(fast_marker_outcome(254),
                         {'outcome': 'error', 'field1': 5, 'field2': 4,
                          'consumed': 0})
        self.assertEqual(fast_marker_outcome(252)['consumed'], 5)
        self.assertEqual(fast_marker_outcome(251)['consumed'], 3)

    def test_slow_grid_matches_model(self):
        grid = self.payload['slow_path']['grid']
        self.assertEqual(len(grid), 77)
        for row in grid:
            model = slow_outcome(row['marker'], row['total_remaining'])
            self.assertEqual({k: row[k] for k in model}, model, row)
        # Shortfall arithmetic on the widest rung: a 253 marker with
        # 5 bytes in total needs 4 more and consumes only the marker;
        # with 0 bytes the marker is not even read and 1 is needed.
        self.assertEqual(slow_outcome(253, 5),
                         {'outcome': 'need', 'additional': 4,
                          'consumed': 1})
        self.assertEqual(slow_outcome(253, 0),
                         {'outcome': 'need', 'additional': 1,
                          'consumed': 0})
        self.assertEqual(slow_outcome(253, 9),
                         {'outcome': 'value', 'payload': 'u64',
                          'consumed': 9})
        # Slow-path errors consume the marker and keep field1 5 (the
        # #2300 slow reader writes field1 3 on this route);
        # fast-path errors consume nothing.
        self.assertEqual(slow_outcome(254, 4),
                         {'outcome': 'error', 'field1': 5, 'field2': 4,
                          'consumed': 1})
        self.assertEqual(fast_marker_outcome(254)['consumed'], 0)

    def test_charge_and_route_facts(self):
        charge = self.payload['charge']
        self.assertEqual(charge['amount'], 8)
        self.assertTrue(charge['stored_before_limit_compare'])
        self.assertEqual(self.payload['fast_route']['requires'],
                         'remaining > 8')
        state = self.payload['reader_state']
        self.assertIn('+0x20', state['charged_count'])
        self.assertIn('+0x18', state['remaining'])
        layout = self.payload['result_layout']
        self.assertIn('result +0x8, u64', layout['value'])

    def test_copies_and_callers(self):
        owners = {o['role']: o for o in self.payload['owners']}
        self.assertEqual(owners['copy_a']['bytes'], 229)
        self.assertEqual(owners['copy_b']['bytes'], 229)
        self.assertEqual(owners['slow_path']['bytes'], 316)
        # The copies share the slow slot but reach the shared error
        # constructor through different slots.
        self.assertEqual(owners['copy_a']['slow_slot'], '0x64e7f80')
        self.assertEqual(owners['copy_b']['slow_slot'], '0x64e7f80')
        self.assertEqual(owners['copy_a']['error_slot'], '0x64e7f88')
        self.assertEqual(owners['copy_b']['error_slot'], '0x64e7f78')
        calls = self.payload['call_sites']
        self.assertEqual(len(calls['copy_a']), 3)
        self.assertEqual(len(calls['copy_b']), 3)
        self.assertEqual(calls['slow_path'], [])
        self.assertEqual(self.payload['slow_slot_references'],
                         ['0x2cd7c5a', '0x58213ea'])
        self.assertFalse(self.payload['captured_code_executed'])

    def test_charge_increment_counterfactual(self):
        data = self.mutated(0x5821354, 3, 0x04)
        with self.assertRaisesRegex(ValueError,
                                    'mode-1 charge increment 8'):
            analyze(data)

    def test_marker_boundary_counterfactual(self):
        data = self.mutated(0x2cd7bea, 3, 0xfa)
        with self.assertRaisesRegex(ValueError, 'marker boundary 251'):
            analyze(data)

    def test_dispatch_table_counterfactual(self):
        data = bytearray(self.data)
        data[self.offset_of(0x935bec) + 8] ^= 0x01
        with self.assertRaisesRegex(ValueError,
                                    'dispatch table targets changed'):
            analyze(bytes(data))

    def test_field1_counterfactual(self):
        data = self.mutated(0x58213f8, 1, 0x02)
        with self.assertRaisesRegex(ValueError,
                                    'marker 254 error field1 5'):
            analyze(data)

    def test_fe_error_code_counterfactual(self):
        data = self.mutated(0x2cd7c6d, 1, 0x05)
        with self.assertRaisesRegex(ValueError,
                                    'marker 254 error field2 4'):
            analyze(data)

    def test_fd_payload_width_counterfactual(self):
        data = self.mutated(0x58213b6, 2, 0x08)
        with self.assertRaisesRegex(ValueError,
                                    'marker 253 consumes 9'):
            analyze(data)

    def test_slow_width_counterfactual(self):
        data = self.mutated(0x5822777, 3, 0x04)
        with self.assertRaisesRegex(ValueError,
                                    'marker 251 total width 3'):
            analyze(data)

    def test_slow_slot_relocation_counterfactual(self):
        data = bytearray(self.data)
        sec = next(s for s in sections(self.data)
                   if s['name'] == '.rela.dyn')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            r_offset, _, _ = struct.unpack_from('<QQq', self.data, off)
            if r_offset == SLOW_SLOT:
                struct.pack_into('<q', data, off + 16, 0x58225c0)
                break
        else:
            self.fail('slow slot relocation not found')
        with self.assertRaisesRegex(ValueError,
                                    'sibling slow-path slot relocation changed'):
            analyze(bytes(data))

    def test_frame_record_counterfactual(self):
        data = self.mutated(0xd8bc98, 24, 0x42)
        with self.assertRaisesRegex(ValueError, 'frame records changed'):
            analyze(data)

    def test_public_identity_rejection(self):
        output = Path(tempfile.mkdtemp()) / 'packet'
        wrong = Path(tempfile.mkdtemp()) / 'wrong'
        wrong.write_bytes(self.data[:SIZE // 2])
        with self.assertRaisesRegex(ValueError, 'pinned node115'):
            generate(wrong, output)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
