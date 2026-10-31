"""Finite normal-helper dataflow controls; no native clock, metric or file IO."""
import json
import math
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import abci_latency_split as tool

def bits(value):return int.from_bytes(struct.pack('<d',value),'little')

class AbciLatencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_source_labels(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual([s['line'] for s in self.record['sources']],[67,55,58])

    def test_finite_cap_edges_and_raw_row_field(self):
        for value in (-100.0,-0.0,0.0,1.0,math.nextafter(60.0,-math.inf),60.0,math.nextafter(60.0,math.inf),90.0,1e300):
            raw=bits(value);result=tool.commit_selected(self.img,1,raw)
            self.assertEqual(result['metric'],raw if value<=60.0 else bits(60.0))
            self.assertEqual(result['prepared_row_bits'],raw)
        self.assertEqual(tool.commit_selected(self.img,0,bits(90.0)),{'metric':None,'prepared_row_bits':None})
        for value in (math.inf,-math.inf,math.nan):
            with self.assertRaisesRegex(ValueError,'finite'):tool.commit_selected(self.img,1,bits(value))

    def test_saved_word_and_low_byte_flag_routes(self):
        for saved in (0,1,2,1<<31,(1<<32)-1):
            for flag in (0,1,2,255,256,257,1<<31,(1<<32)-1):
                expected=[]
                if saved:expected.append((0,bits(60.0)))
                if flag%256:expected.append((0x260,bits(90.0)))
                self.assertEqual(tool.begin_selected(self.img,saved,flag,bits(90.0),bits(90.0)),expected)

    def test_actual_min_instruction_and_cap_mutations_change_sample_only(self):
        changed=self.changed(0x3d225e5+2,b'\x5f')
        result=tool.commit_selected(tool.Image(changed),1,bits(90.0))
        self.assertEqual(result,{'metric':bits(90.0),'prepared_row_bits':bits(90.0)})
        with self.assertRaisesRegex(ValueError,'dataflow'):tool.observe(changed)
        changed=self.changed(0x20abf8,struct.pack('<d',30.0))
        self.assertEqual(tool.commit_selected(tool.Image(changed),1,bits(90.0)),{'metric':bits(30.0),'prepared_row_bits':bits(90.0)})
        with self.assertRaisesRegex(ValueError,'dataflow'):tool.observe(changed)

    def test_real_presence_spill_reload_calls_weights_and_sources(self):
        for va in (0x3d22522+3,0x3d2293d+4,0x3d229d7,0x3d225d0+5,0x3d22603+5,
                   0x3d22609+5,0x3d2282e+3,0x3d229d9+3,0x3d22a6b+7,
                   0x3d225c6+2,0x3d22a2f+2,0x3d225f0+1,0x57193a0+16):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_two_fde_extents_and_identity(self):
        for owner in self.record['owners']:
            fde=int(owner['fde'],16);size=int(owner['end_exclusive'],16)-int(owner['start'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                tool.observe(self.changed(fde+12,struct.pack('<i',size-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.CASES[0][0],b'\x90'))
if __name__=='__main__':unittest.main()
