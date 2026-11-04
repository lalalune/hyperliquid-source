"""Static controls for the node #115 saturating threshold function bind."""
import hashlib
import json
import mmap
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import node115_saturating_threshold as bind

PACKET = bind.ROOT/'research/work-items/RE-001-node115-saturating-threshold'


class Overlay:
    def __init__(self, data, offset, replacement):
        self.data, self.offset, self.replacement = data, offset, replacement

    def __getitem__(self, key):
        if not isinstance(key, slice):
            return self.replacement[key-self.offset] if self.offset <= key < self.offset+len(self.replacement) else self.data[key]
        start, stop, step = key.indices(len(self.data))
        if step != 1:
            raise ValueError('unsupported overlay slice')
        result = bytearray(self.data[start:stop])
        for index, byte in enumerate(self.replacement):
            if start <= self.offset+index < stop:
                result[self.offset+index-start] = byte
        return bytes(result)


class ThresholdBindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = bind.TARGET.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_READ)
        cls.record = bind.analyze(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def test_regeneration_and_readme_counts(self):
        self.assertEqual(self.record, json.loads((PACKET/'records.json').read_text()))
        self.assertEqual(bind.readme(self.record), (PACKET/'README.md').read_text())
        readme = (PACKET/'README.md').read_text()
        self.assertIn(f"is {self.record['window']['size']} bytes", readme)
        self.assertIn(f"The {len(self.record['instructions'])} instructions", readme)
        self.assertIn(f"callee count {len(self.record['callees'])}", readme)
        self.assertIn(f"finds {len(self.record['rel32_census']['sites'])} candidate sites", readme)
        self.assertIn(f"following {len(bytes.fromhex(self.record['window']['padding_hex']))} bytes", readme)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            bind.emit(out, self.record)
            for name in ('README.md','records.json','verify.py','MANIFEST.sha256'):
                self.assertEqual((out/name).read_bytes(), (PACKET/name).read_bytes(), name)

    def test_packet_whitelist_and_manifest_reject_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            bind.emit(out, self.record)
            check = lambda: subprocess.run([sys.executable,str(out/'verify.py')], capture_output=True)
            self.assertEqual(check().returncode, 0)
            (out/'unexpected').write_text('extra')
            self.assertNotEqual(check().returncode, 0)
            (out/'unexpected').unlink()
            (out/'records.json').write_text('{}\n')
            self.assertNotEqual(check().returncode, 0)

    def test_digest_is_fail_closed_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            wrong = tmp/'wrong'
            wrong.write_bytes(b'incorrect artifact')
            result = subprocess.run([sys.executable, str(bind.ROOT/'tools/node115_saturating_threshold.py'),
                                     '--target', str(wrong), '--out', str(tmp/'out')], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'digest mismatch', result.stderr)
            self.assertFalse((tmp/'out').exists())

    def test_mutated_instruction_rejected(self):
        off = bind.TEXT_OFFSET + bind.START - bind.TEXT_START
        body = bytearray(self.data[off:off+bind.END-bind.START])
        body[0] ^= 1
        with self.assertRaises(ValueError):
            bind.decode(body)

    def test_mutated_branch_rejected(self):
        off = bind.TEXT_OFFSET + bind.START - bind.TEXT_START
        body = bytearray(self.data[off:off+bind.END-bind.START])
        body[17] ^= 1
        with self.assertRaises(ValueError):
            bind.decode(body)

    def test_shifted_fde_rejected(self):
        original = self.data[bind.FDE+8:bind.FDE+12]
        changed = (int.from_bytes(original,'little')+1).to_bytes(4,'little')
        with self.assertRaises(ValueError):
            bind.frame(Overlay(self.data,bind.FDE+8,changed))

    def test_wrong_call_target_rejected(self):
        site = bind.CALLERS[0]
        raw = bytearray(self.data[site-0x1000:site-0x1000+5])
        raw[1] ^= 1
        with self.assertRaises(ValueError):
            bind.check_call(site, raw)

    def test_signed_first_and_unsigned_other_fields(self):
        f = bind.model
        self.assertEqual(f((0x80000000,0,0),(0x7fffffff,0,0),5,0,5),0)
        self.assertEqual(f((0x7fffffff,0,0),(0x80000000,0,0),5,0,5),2)
        self.assertEqual(f((0,0x80000000,0),(0,0x7fffffff,0),5,0,5),2)
        self.assertEqual(f((0,0,0x80000000),(0,0,0x7fffffff),5,0,5),2)
        self.assertEqual(f((0,0,0x7fffffff),(0,0,0x80000000),5,0,5),0)

    def test_equal_tuple_and_cutoff_boundaries(self):
        f = bind.model
        a = (0,0,0)
        self.assertEqual(f(a,a,8,0,9),0)
        self.assertEqual(f(a,a,9,0,9),2)
        self.assertEqual(f(a,a,5000,0,5001),1)
        self.assertEqual(f(a,a,4999,0,5001),0)

    def test_saturating_threshold_boundaries(self):
        f = bind.model
        a,b = (0,0,0),(1,0,0)
        maximum = 2**64-1
        for base in (0,1,maximum-5001,maximum-5000,maximum-4999,maximum):
            threshold = min(base+5000,maximum)
            self.assertEqual(f(a,b,threshold,base,0),1)
            self.assertEqual(f(a,b,threshold-1,base,0),0)

    def test_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            bind.model((2**32,0,0),(0,0,0),0,0,0)
        with self.assertRaises(ValueError):
            bind.model((0,0,0),(0,0,0),2**64,0,0)

    def test_census_and_instruction_coverage(self):
        rows = self.record['instructions']
        self.assertEqual(rows[0]['address'],bind.START)
        for one,two in zip(rows,rows[1:]):
            self.assertEqual(one['address']+len(bytes.fromhex(one['bytes'])),two['address'])
        self.assertEqual(rows[-1]['address']+len(bytes.fromhex(rows[-1]['bytes'])),bind.END)
        self.assertEqual(tuple(x['site'] for x in self.record['rel32_census']['sites']),bind.CALLERS)
        self.assertEqual(self.record['callees'],[])
        self.assertEqual(hashlib.sha256(bytes.fromhex(''.join(x['bytes'] for x in rows))).hexdigest(),bind.BODY_SHA)

if __name__ == '__main__':
    unittest.main()
