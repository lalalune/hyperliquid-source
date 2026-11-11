import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import node115_be64_slot as bind

PACKET = ROOT/'research/work-items/RE-001-node115-be64-slot'

class BindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((PACKET/'records.json').read_text())
        cls.body = bytes.fromhex(cls.record['window']['bytes'])

    def test_instruction_coverage(self):
        rows = bind.decode(self.body)
        self.assertEqual(rows, self.record['instructions'])
        self.assertEqual(rows[-1]['va'] + 1, bind.END)
        self.assertEqual(len(self.body), bind.END-bind.START)

    def test_window_and_branch_corruption_rejected(self):
        for offset in (0, 11, 36, len(self.body)-1):
            damaged = bytearray(self.body)
            damaged[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                bind.decode(damaged)
        with self.assertRaises(ValueError):
            bind.decode(self.body[:-1])

    def test_shifted_fde_rejected(self):
        raw = bytearray.fromhex(self.record['window']['fde_bytes'])
        bind.check_fde(raw)
        raw[8] ^= 1
        with self.assertRaises(ValueError):
            bind.check_fde(raw)

    def test_wrong_digest_and_truncation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            bind.collect(b'wrong digest')
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'target'; path.write_bytes(b'\x7fELF')
            with self.assertRaisesRegex(ValueError, 'digest'):
                bind.produce(Path(d)/'out', path)
            self.assertFalse((Path(d)/'out').exists())

    def test_regenerate_and_reject_mutated_target(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d)/'packet'
            dest.mkdir()
            shutil.copyfile(PACKET/'verify.py', dest/'verify.py')
            result = bind.produce(dest)
            self.assertEqual(result, self.record)
            for name in ('README.md', 'records.json', 'MANIFEST.sha256'):
                self.assertEqual((dest/name).read_bytes(), (PACKET/name).read_bytes())
            target = Path(d)/'altered-node'
            shutil.copyfile(bind.TARGET, target)
            with target.open('r+b') as f:
                f.seek(self.record['window']['file_offset'])
                b = f.read(1)
                f.seek(-1, 1)
                f.write(bytes([b[0] ^ 1]))
            with self.assertRaisesRegex(ValueError, 'digest'):
                bind.produce(Path(d)/'rejected', target)
            self.assertFalse((Path(d)/'rejected').exists())

    def test_success_endian_and_boundaries(self):
        for count in (0, 1, 1022, 1023):
            r = bind.model(count, bytes.fromhex('0123456789abcdef'), 0x100)
            self.assertEqual(r, {'al': 0, 'rax': 0, 'count': count+1, 'cursor': 0x108,
                                'slot': 'efcdab8967452301'+'00'*24})
        self.assertEqual(bind.model(0, b'\xff'*8, (1<<64)-4)['cursor'], 4)
        self.assertEqual(bind.model(0, bytes(8))['slot'], '00'*32)

    def test_failure_preserves_count_and_upper_rax(self):
        for n in (1024, 1025, (1<<64)-1):
            r = bind.model(n, b'', 42)
            self.assertEqual(r, {'al': 45, 'rax': (n & ~255)|45,
                                 'count': n, 'cursor': 42, 'slot': None})

    def test_readme_counts_match_record(self):
        text = (PACKET/'README.md').read_text()
        self.assertIn(f"{self.record['window']['size']} bytes", text)
        self.assertIn(f"{len(self.record['instructions'])} instructions, {len(self.record['callees'])} callees", text)
        self.assertIn(f"found {len(self.record['direct_rel32_candidates'])} candidates", text)
        self.assertEqual(self.record['census']['count'], len(self.record['direct_rel32_candidates']))
        self.assertEqual(text, bind.render(self.record))

    def test_census_finds_relative_call_and_jump(self):
        # A tiny mapped text fixture tests both signed displacements and the
        # wholly-in-range rule, without claiming these are real callers.
        base = bind.TEXT_START
        payload = bytearray(24)
        for pos, op in ((1, 0xe8), (10, 0xe9)):
            payload[pos] = op
            struct.pack_into('<i', payload, pos+1, bind.START-(base+pos+5))
        payload[23] = 0xe8
        result = bind.scan(payload, {'offset': 0, 'size': len(payload)})
        self.assertEqual([(x['va'], x['opcode']) for x in result], [(base+1, '0xe8'), (base+10, '0xe9')])

    def test_model_rejects_bad_inputs(self):
        for count, source in ((-1, bytes(8)), (1<<64, bytes(8)), (0, b'123')):
            with self.assertRaises(ValueError): bind.model(count, source)

if __name__ == '__main__': unittest.main()
