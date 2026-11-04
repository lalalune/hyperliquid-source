import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from u32_varint_reader_static import (PACKET, SHA, SIZE, SLOW_SLOT,
                                      TARGET, analyze,
                                      fast_marker_outcome, generate,
                                      slow_outcome)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class U32VarintReaderStaticTest(unittest.TestCase):
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
        # The width boundary: marker 253 is a u64 payload for the
        # claimed u64 reader but an error here, consuming nothing.
        self.assertEqual(fast_marker_outcome(253),
                         {'outcome': 'error', 'field1': 2, 'field2': 3,
                          'consumed': 0})
        self.assertEqual(fast_marker_outcome(252)['consumed'], 5)
        self.assertEqual(fast_marker_outcome(251)['consumed'], 3)

    def test_slow_grid_matches_model(self):
        grid = self.payload['slow_path']['grid']
        self.assertEqual(len(grid), 49)
        for row in grid:
            model = slow_outcome(row['marker'], row['total_remaining'])
            self.assertEqual({k: row[k] for k in model}, model, row)
        # Shortfall arithmetic: a 252 marker with 3 bytes in total
        # needs 2 more and consumes only the marker; with 0 bytes the
        # marker is not even read and 1 is needed.
        self.assertEqual(slow_outcome(252, 3),
                         {'outcome': 'need', 'additional': 2,
                          'consumed': 1})
        self.assertEqual(slow_outcome(252, 0),
                         {'outcome': 'need', 'additional': 1,
                          'consumed': 0})
        # Slow-path errors consume the marker, fast-path errors do not.
        self.assertEqual(slow_outcome(253, 4)['consumed'], 1)
        self.assertEqual(fast_marker_outcome(253)['consumed'], 0)

    def test_charge_and_route_facts(self):
        charge = self.payload['charge']
        self.assertEqual(charge['amount'], 4)
        self.assertTrue(charge['stored_before_limit_compare'])
        self.assertEqual(self.payload['fast_route']['requires'],
                         'remaining > 4')
        state = self.payload['reader_state']
        self.assertIn('+0x20', state['charged_count'])
        self.assertIn('+0x18', state['remaining'])

    def test_copies_and_callers(self):
        owners = {o['role']: o for o in self.payload['owners']}
        self.assertEqual(owners['copy_a']['bytes'], 243)
        self.assertEqual(owners['copy_b']['bytes'], 243)
        self.assertEqual(owners['slow_path']['bytes'], 293)
        calls = self.payload['call_sites']
        self.assertEqual(len(calls['copy_a']), 16)
        self.assertEqual(len(calls['copy_b']), 11)
        self.assertEqual(calls['slow_path'], [])
        self.assertEqual(self.payload['slow_slot_references'],
                         ['0x2cd7a60', '0x58211f0'])
        self.assertFalse(self.payload['captured_code_executed'])

    def test_charge_increment_counterfactual(self):
        data = self.mutated(0x5821164, 3, 0x08)
        with self.assertRaisesRegex(ValueError,
                                    'mode-1 charge increment 4'):
            analyze(data)

    def test_marker_boundary_counterfactual(self):
        data = self.mutated(0x2cd79fa, 2, 0xfa)
        with self.assertRaisesRegex(ValueError, 'marker boundary 251'):
            analyze(data)

    def test_dispatch_table_counterfactual(self):
        data = bytearray(self.data)
        data[self.offset_of(0x935bcc) + 8] ^= 0x01
        with self.assertRaisesRegex(ValueError,
                                    'dispatch table targets changed'):
            analyze(bytes(data))

    def test_fd_error_code_counterfactual(self):
        data = self.mutated(0x2cd7a8b, 1, 0x05)
        with self.assertRaisesRegex(ValueError,
                                    'marker 253 error field2 3'):
            analyze(data)

    def test_slow_width_counterfactual(self):
        data = self.mutated(0x58224f7, 3, 0x04)
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
                                    'slow-path slot relocation changed'):
            analyze(bytes(data))

    def test_frame_record_counterfactual(self):
        data = self.mutated(0xd8bc2c, 24, 0x42)
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
