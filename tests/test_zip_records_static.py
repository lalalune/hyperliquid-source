"""Valid buffer/primitive models and controls on all four real FDEs."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import zip_records_static as tool


class ZipRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_record_sizes(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['output_stride'],64)
        self.assertEqual(len(self.record['owners']),4)

    def test_byte_copy_population_and_input_shape(self):
        for position in range(64):
            a=bytearray(40);b=bytearray(24)
            if position<40:a[position]=0xa5
            else:b[position-40]=0xa5
            expected=bytearray(64);expected[position]=0xa5
            self.assertEqual(tool.pack_records([bytes(a)],[bytes(b)]),bytes(expected))
        for count in range(129):
            left=[struct.pack('<5Q',*(i*8+j for j in range(5))) for i in range(count)]
            right=[struct.pack('<3Q',*(i*8+j for j in range(5,8))) for i in range(count)]
            expected=b''.join(struct.pack('<8Q',*(i*8+j for j in range(8))) for i in range(count))
            self.assertEqual(tool.pack_records(left,right),expected)
        with self.assertRaisesRegex(ValueError,'Unequal'):
            tool.pack_records([bytes(40)],[])
        with self.assertRaisesRegex(ValueError,'40/24'):
            tool.pack_records([bytes(39)],[bytes(24)])

    def test_modular_count_and_allocation_boundary_domains(self):
        self.assertEqual((5*0xcccccccccccccccd)&tool.MAX,1)
        self.assertEqual((3*0xaaaaaaaaaaaaaaab)&tool.MAX,1)
        for stride in (40,24):
            counts=list(range(4096))+[tool.MAX//stride-1,tool.MAX//stride]
            for count in counts:
                self.assertEqual(tool.recovered_count(stride*count,stride),count)
        boundary=(1<<57)-1
        counts=set(range(4096))|{0,tool.MAX}|{base+d for base in (1<<57,1<<58) for d in range(-8,9)}
        for count in counts:
            self.assertEqual(tool.allocation_allowed(count),count<=boundary)
        with self.assertRaisesRegex(ValueError,'strided'):
            tool.recovered_count(1,40)

    def test_actual_length_stride_inverse_and_guard_corruptions(self):
        for va in (0x2831613,0x471e123,0x2831623,0x471e142,0x2519c8e,
                   0x2519ca4,0x2519cc3,0x47f8edf,0x47f8ee6):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))

    def test_actual_copy_stores_and_collector_bindings(self):
        for va in (0x2519ded,0x2519de5,0x2519df1,0x2519e00,0x47f8fce,0x47f8fd2,0x47f8fe4):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))
        for va in (0x283166e,0x471e17e):
            raw=bytearray(self.img.read(va,5));raw[-1]^=1
            with self.assertRaisesRegex(ValueError,'collector call'):
                tool.observe(self.changed(va,raw))

    def test_actual_sources_fdes_and_identity(self):
        for loc in (0x56c4f80,0x572e878):
            with self.assertRaisesRegex(ValueError,'source binding'):
                tool.observe(self.changed(loc+16,struct.pack('<I',102)))
        for owner in self.record['owners']:
            fde=int(owner['fde'],16);size=int(owner['end_exclusive'],16)-int(owner['start'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                tool.observe(self.changed(fde+12,struct.pack('<i',size-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(0x28315f0,b'\x90'))


if __name__=='__main__':unittest.main()
