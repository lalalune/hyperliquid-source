import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from artifacts import ROOT,check
from latency_sample_static import CONTROLS,LITERALS,RELATIVE,controls,read_va,relocations

class PacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target=ROOT/'artifacts/node/94/hl-node'
        identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']if i['path']=='artifacts/node/94/hl-node')
        check(target,identity);cls.data=target.read_bytes()

    def test_actual_control_baseline(self):
        controls(self.data);self.assertEqual(len(relocations(self.data)),len(RELATIVE))

    def test_actual_instruction_corruptions(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'instruction changed'):controls(changed)

    def test_actual_literal_corruptions(self):
        for va in LITERALS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'literal changed'):controls(changed)

    def test_actual_relocation_retargets(self):
        for slot,target in RELATIVE.items():
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);offset=changed.find(struct.pack('<QQq',slot,8,target))
                self.assertGreaterEqual(offset,0);changed[offset+16]^=1
                with self.assertRaisesRegex(ValueError,'relocation changed'):relocations(changed)

    def test_ordered_local_cap_and_nan_limit(self):
        self.assertEqual(read_va(self.data,0x3d229b0,4)[1],bytes.fromhex('f20f5dc8'))
        cap=struct.unpack('<d',read_va(self.data,0x20abf8,8)[1])[0]
        self.assertEqual(cap,60.0)
        # MINSD selects source on unordered operands; not a finite-only clamp.
        import math
        def architectural_min(source):return source if math.isnan(source) or source<cap else cap
        for value,want in [(-1.0,-1.0),(0.0,0.0),(59.0,59.0),(60.0,60.0),(61.0,60.0),(float('inf'),60.0)]:
            self.assertEqual(architectural_min(value),want)
        self.assertTrue(math.isnan(architectural_min(float('nan'))))

    def test_two_independent_guards_and_always_update_tail(self):
        body=read_va(self.data,0x3d2293d,14)[1]
        self.assertEqual(body[:8],bytes.fromhex('4183bed007000000'))
        self.assertEqual(0x3d2294b+struct.unpack_from('<i',body,10)[0],0x3d229cd)
        self.assertEqual(read_va(self.data,0x3d229d4,5)[1],bytes.fromhex('4084ed7471'))
        self.assertEqual(0x3d229d9+0x71,0x3d22a4a)
        self.assertEqual(read_va(self.data,0x3d22a70,28)[1],bytes.fromhex('4989078b442430418947088b4424344189470c488b44243849894710'))

if __name__=='__main__':unittest.main()
