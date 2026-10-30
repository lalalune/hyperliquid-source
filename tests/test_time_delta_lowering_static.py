"""Actual-capture controls and independent arithmetic expectations, no target execution."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import time_delta_lowering_static as tool

PACKET=tool.ROOT/'research/work-items/RE-001-time-delta-lowering-94'


class TimeLoweringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.secs=tool.sections(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        off=s['offset']+va-s['address']
        changed=bytearray(self.data);changed[off:off+len(raw)]=raw
        return changed

    def test_real_record_and_independent_integer_comparison(self):
        self.assertEqual(json.loads((PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['range']['bytes'],343)
        self.assertEqual(self.record['signed_split_comparison'],{'samples':16417,'mismatches':0})
        self.assertEqual(len(self.record['scaled_bit_vectors']),17)

    def test_scaled_bit_boundaries_and_nonfinite_fallback(self):
        expected={0:(0,0,0),0x8000000000000000:(0,0,0),
                  0xbff0000000000000:(-1,-1,999999999),
                  0x3ff8000000000000:(1,0,1),
                  0xbff8000000000000:(-1,-1,999999999),
                  0x43e0000000000000:((1<<63)-1,9223372036,854775807),
                  0xc3e0000000000000:(-(1<<63),-9223372037,145224192),
                  0x7ff0000000000000:(0,0,0),0xfff0000000000000:(0,0,0),
                  0x7ff0000000000001:(0,0,0),0x7ff8000000000000:(0,0,0)}
        for bits,want in expected.items():
            with self.subTest(bits=hex(bits)):
                got=tool.lower_scaled_bits(bits,self.record['constants'])
                self.assertEqual(tuple(got[k] for k in ('nanoseconds_i64','seconds_i64','nanoseconds_u32')),want)

    def test_negative_remainder_correction(self):
        c=self.record['constants']
        for n in [-1,-1000000001,-999999999,-(1<<63),(1<<63)-1]:
            with self.subTest(n=n):
                q,r=tool.split_observed(n,c['magic'],c['shift'],c['radix'])
                self.assertEqual((q,r),divmod(n,1000000000))
                self.assertEqual(q*1000000000+r,n)
                self.assertTrue(0<=r<1000000000)
        # A truncating split gives (0,-1), unlike the real negative-remainder correction.
        self.assertNotEqual(tool.split_observed(-1,c['magic'],c['shift'],c['radix']),(0,-1))

    def test_actual_float_and_division_corruptions(self):
        cases=[(0x20a220,struct.pack('<d',1e6),'Scaling/clamp'),
               (0x20acb8,struct.pack('<d',-1.0),'Scaling/clamp'),
               (0x1459ce1,b'\x7e','Nonfinite branch'),
               (0x1459d2e,struct.pack('<Q',0x112e0be826d694b4),'Signed division'),
               (0x1459d46,b'\x19','Signed division'),
               (0x1459d5a,b'\x3e','Negative remainder')]
        for va,raw,reason in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,reason):tool.observe(self.changed(va,raw))

    def test_actual_fde_and_binding_corruptions(self):
        fde=int(self.record['range']['fde_va'],16)
        with self.assertRaisesRegex(ValueError,'Time helper FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<I',342)))
        for slot,addend in [(0x576efb8,tool.START),(0x576e8a8,0x15206e0)]:
            changed=bytearray(self.data);needle=struct.pack('<QQq',slot,8,addend)
            off=changed.find(needle);self.assertGreaterEqual(off,0)
            self.assertEqual(changed.find(needle,off+1),-1);changed[off+16]^=1
            with self.assertRaisesRegex(ValueError,'slot binding'):tool.observe(changed)

    def test_wrong_capture_rejected(self):
        with self.assertRaisesRegex(ValueError,'Wrong node94 SHA-256'):
            tool.build(self.data[:-1]+bytes([self.data[-1]^1]))
