"""Prepared-field domain controls and mutations of actual captured instructions."""
import itertools
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import three_field_map_static as tool


class ThreeFieldMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_real_packet_and_field_stores(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual([(f['key'],f['field_id']) for f in self.record['fields']],
                         [('chainId',0),('address',1),('nonce',2)])
        self.assertEqual(self.record['successful_stores']['address_bytes'],[48,68])
        self.assertEqual(self.record['prepared_item_stride'],64)

    def test_key_byte_mutations_against_independent_exact_lookup(self):
        lookup={k:i for i,k in enumerate(tool.KEYS)};checked=0
        for key in tool.KEYS:
            for index in range(len(key)):
                for byte in range(256):
                    value=key[:index]+bytes([byte])+key[index+1:]
                    self.assertEqual(tool.byte_key(value),lookup.get(value,3));checked+=1
        self.assertEqual(checked,4864)
        for key in (b'',b'ChainId',b'chainid',b'chain_id',b'Address',b'nonce\0',b'addressx'):
            self.assertEqual(tool.byte_key(key),3)

    def test_prepared_field_population_and_missing_path_order(self):
        alphabet=(*tool.KEYS,b'unknown');checked=0
        for length in range(7):
            for keys in itertools.product(alphabet,repeat=length):
                duplicate=next((key for i,key in enumerate(keys) if key in tool.KEYS and key in keys[:i]),None)
                if duplicate is not None:
                    expected={'path':'duplicate','field':duplicate.decode()}
                else:
                    missing=next((i for i,k in enumerate(tool.KEYS) if k not in keys),None)
                    names=('chainId_missing_path','address_missing_helper','nonce_missing_helper')
                    expected={'path':'success_candidate','field':None} if missing is None else {'path':names[missing],'field':tool.KEYS[missing].decode()}
                self.assertEqual(tool.prepared_fields(keys),expected);checked+=1
        self.assertEqual(checked,5461)
        for keys in itertools.permutations(tool.KEYS):
            self.assertEqual(tool.prepared_fields(keys)['path'],'success_candidate')

    def test_actual_duplicate_presence_and_result_controls(self):
        for va in (0x4674b6f,0x4674bfe,0x4674c8d,0x4674d27,0x4674da5,
                   0x4674f73,0x4674f81,0x4674fa7,0x4674fea,0x4674fce):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))

    def test_actual_field_table_and_helpers(self):
        for i in range(4):
            raw=struct.unpack('<i',self.img.read(0x6f7024+4*i,4))[0]
            with self.subTest(i=i),self.assertRaisesRegex(ValueError,'field table'):
                tool.observe(self.changed(0x6f7024+4*i,struct.pack('<i',raw+1)))
        for va in tool.CALLS:
            raw=bytearray(self.img.read(va,5));raw[-1]^=1
            with self.subTest(call=hex(va)),self.assertRaisesRegex(ValueError,'helper call'):
                tool.observe(self.changed(va,raw))

    def test_actual_key_data_diagnostics_fde_and_identity(self):
        for va in (0x7041cd,0x7040a8,0x7041d4,0x6f71da,0x6f708d,0x6f71e1):
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'binding|comparison data'):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))
        fde=int(self.record['owners'][0]['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',2107)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(0x4674b50,b'\x90'))


if __name__=='__main__':unittest.main()
