"""Conditional IEEE-754 loop model and real captured operand controls."""
import itertools
import json
import math
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import fee_percentiles_static as tool


class FeePercentileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_population(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(sum(r['vectors'] for r in self.record['population']),8421)
        self.assertEqual(sum(r['differs_from_reference_ordered_form'] for r in self.record['population']),2920)

    def test_relations_against_independent_float_comparisons(self):
        for a,b in itertools.product(tool.BITS,repeat=2):
            x,y=[struct.unpack('<d',struct.pack('<Q',w))[0] for w in (a,b)]
            expected=None if math.isnan(x) or math.isnan(y) else (x>y)-(x<y)
            self.assertEqual(tool.relation(a,b),expected)
        self.assertEqual(tool.relation(0,tool.SIGN),0)
        with self.assertRaisesRegex(ValueError,'binary64'):
            tool.relation(-1,0)

    def test_declared_vectors_and_specific_loop_boundaries(self):
        checked=0
        for length in range(4):
            for words in itertools.product(tool.BITS,repeat=length):
                values=[struct.unpack('<d',struct.pack('<Q',w))[0] for w in words]
                expected=not any(a>100.0 or a>b for a,b in zip(values,values[1:]))
                self.assertEqual(tool.passes_loop(words),expected);checked+=1
        self.assertEqual(checked,8421)
        nan=0x7ff8000000000000
        self.assertTrue(tool.passes_loop([nan,0]))
        self.assertFalse(tool.reference_ordered_form([nan,0]))
        self.assertTrue(tool.passes_loop([0,0x4069000000000000]))  # last value 200
        self.assertFalse(tool.passes_loop([tool.HUNDRED+1,nan]))
        self.assertTrue(tool.passes_loop([0x7ff0000000000000]))   # singleton infinity

    def test_actual_ucomisd_and_unsigned_conditions(self):
        for va in (0x27b680e,0x27b6840,0x27b6844,0x27b684b,0x27b684f,0x27b6854,0x27b685c):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))
        with self.assertRaisesRegex(ValueError,'upper-bound bits'):
            tool.observe(self.changed(0x20a960,struct.pack('<Q',tool.HUNDRED+1)))

    def test_actual_count_optional_and_stride_fields(self):
        for va in (0x27b6681,0x27b6683,0x27b6689,0x27b67da,0x27b6820,0x27b6827,0x27b6858):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))

    def test_actual_source_fde_and_identity(self):
        with self.assertRaisesRegex(ValueError,'source context'):
            tool.observe(self.changed(0x56c2ec0+16,struct.pack('<I',34)))
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',7882)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))


if __name__=='__main__':unittest.main()
