"""RE-001: bridge static coordinates must have a unique file interpretation."""
import hashlib,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from bridge_inventory import Mapping,load_segments

class BridgeMappingUniqueness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f':
            raise AssertionError('node94 identity')
        cls.rows=load_segments(cls.data)
        cls.text=next(r for r in cls.rows if r[3]&1)
        cls.phoff=struct.unpack_from('<Q',cls.data,32)[0]
        cls.stride,cls.count=struct.unpack_from('<HH',cls.data,54)
        cls.first=next(i for i in range(cls.count)
                       if struct.unpack_from('<I',cls.data,cls.phoff+i*cls.stride)[0]==1)

    def altered(self,field,value,fmt='<Q'):
        data=bytearray(self.data)
        struct.pack_into(fmt,data,self.phoff+self.first*self.stride+field,value)
        return load_segments(data)

    def test_original_and_reordered_mapping_preserve_actual_bytes(self):
        off,va,_,_=self.text
        for rows in (self.rows,list(reversed(self.rows))):
            mapping=Mapping(rows)
            self.assertEqual(mapping.va_to_offset(va+8,7),off+8)
            self.assertEqual(mapping.offset_to_va(off+8),va+8)
            self.assertEqual(mapping.read(self.data,va+8,7),self.data[off+8:off+15])

    def test_conflicting_virtual_mappings_are_not_selected_by_order(self):
        rows=self.altered(16,self.text[1])
        for order in (rows,list(reversed(rows))):
            with self.subTest(reversed=order is not rows):
                with self.assertRaisesRegex(ValueError,'ambiguous|unique'):
                    Mapping(order).va_to_offset(self.text[1]+8,7)

    def test_conflicting_file_mappings_are_not_selected_by_order(self):
        rows=self.altered(8,self.text[0])
        for order in (rows,list(reversed(rows))):
            with self.subTest(reversed=order is not rows):
                with self.assertRaisesRegex(ValueError,'ambiguous|unique'):
                    Mapping(order).offset_to_va(self.text[0]+8)

    def test_multiple_distinct_executable_regions_are_not_a_complete_single_scan(self):
        with self.assertRaisesRegex(ValueError,'executable|unique'):
            Mapping(self.altered(4,self.rows[0][3]|1,'<I')).execute_segment()

    def test_duplicate_identical_coordinates_still_have_one_interpretation(self):
        mapping=Mapping(self.rows+self.rows)
        off,va,size,_=self.text
        self.assertEqual(mapping.va_to_offset(va+8,7),off+8)
        self.assertEqual(mapping.offset_to_va(off+8),va+8)
        self.assertEqual(mapping.execute_segment(),(off,va,size))

if __name__=='__main__':unittest.main()
