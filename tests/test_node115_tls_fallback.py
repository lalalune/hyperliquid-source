"""Static corruption controls for node115 TLS fallback; no target execution."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-001-node115-tls-fallback'
spec=importlib.util.spec_from_file_location('tls_fallback_evidence',PACKET/'collect.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class TlsFallback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=m.load(ROOT)
        cls.image.data=bytearray(cls.image.data)
    def mutate(self,va,index,call):
        off=self.image.offset(va,index+1)+index
        before=self.image.data[off]
        try:
            self.image.data[off]^=1
            with self.assertRaises((ValueError,IndexError,UnicodeDecodeError)):
                call()
        finally:self.image.data[off]=before
    def structural(self):
        return m.validate(self.image,body_hashes=False)
    def test_complete_packet_and_denominator(self):
        actual=m.collect(ROOT,PACKET)
        expected=json.loads((PACKET/'records.json').read_text())
        expected['capstone_version']=actual['capstone_version']
        self.assertEqual(expected,actual)
        self.assertEqual(sum(b['bytes'] for b in actual['bodies']),896)
        self.assertEqual(sum(b['bytes'] for b in actual['bodies'] if b['ownership']=='new'),288)
        self.assertFalse(actual['limitations']['captured_execution'])
    def test_every_selected_instruction_corrupts_without_digest_or_body_hash(self):
        for pc,b in m.ANCHORS.items():
            with self.subTest(pc=hex(pc)):
                self.mutate(pc,len(bytes.fromhex(b))-1,self.structural)
    def test_all_retained_data_and_plt_bytes_corrupt(self):
        for va,b in m.DATA_PINS.items():
            with self.subTest(va=hex(va)):
                self.mutate(va,len(bytes.fromhex(b))-1,self.structural)
    def test_each_physical_relocation_addend_and_type_corrupts(self):
        for slot,_,_,_ in m.BINDINGS:
            entries=[]
            for section in self.image.sections:
                if section['type']!=4:continue
                for delta in range(0,section['size'],24):
                    off=section['offset']+delta
                    if struct.unpack_from('<Q',self.image.data,off)[0]==slot:entries.append(off)
            self.assertEqual(len(entries),1)
            for index in (8,16):
                off=entries[0]+index;before=self.image.data[off]
                try:
                    self.image.data[off]^=1
                    with self.subTest(slot=hex(slot),field=index),self.assertRaises(ValueError):self.structural()
                finally:self.image.data[off]=before
    def test_import_symbol_bytes_corrupt_without_digest(self):
        sym=next(s for s in self.image.sections if s['name']=='.dynsym')
        strings=next(s for s in self.image.sections if s['name']=='.dynstr')
        for _,info,_,name in m.BINDINGS:
            if not name:continue
            index=info>>32;nameoff=struct.unpack_from('<I',self.image.data,sym['offset']+index*24)[0]
            off=strings['offset']+nameoff;before=self.image.data[off]
            try:
                self.image.data[off]^=1
                with self.subTest(name=name),self.assertRaises(ValueError):self.structural()
            finally:self.image.data[off]=before
    def test_duplicate_relocation_is_rejected(self):
        original=self.image.relocations
        def duplicate():
            data=original();data[0x64fedb0]*=2;return data
        self.image.relocations=duplicate
        try:
            with self.assertRaises(ValueError):self.structural()
        finally:self.image.relocations=original
    def test_each_raw_fde_rejects_corruption(self):
        for name,f,_,_ in m.FDE_PINS:
            with self.subTest(name=name):self.mutate(f['fde'],4,self.structural)
    def test_fde_and_cie_metadata_reject_mismatch(self):
        before=self.image.fdes;changed=copy.deepcopy(before)
        next(f for f in changed if f['start']==0x5ca53f0)['end']-=1
        try:
            self.image.fdes=changed
            with self.assertRaises(ValueError):self.structural()
        finally:self.image.fdes=before
        before=self.image.cies;changed=copy.deepcopy(before)
        changed[m.FDE_PINS[1][1]['cie']]['personality_slot']^=8
        try:
            self.image.cies=changed
            with self.assertRaises(ValueError):self.structural()
        finally:self.image.cies=before
    def test_lsda_branch_and_landing_bytes_reject_corruption(self):
        for va,index in [(0x3ffca0,4),(0x3ffca0,6),(0x3fff18,6),(0x3fff18,11)]:
            with self.subTest(va=hex(va),index=index):self.mutate(va,index,self.structural)
    def test_bad_uleb_and_lsda_bounds_are_rejected(self):
        for raw in [b'',b'\xff\x00\x01\x00',b'\xff\xff\x01\x80',
                    b'\xff\xff\x01\x04\x00\x7f\x00\x00',
                    b'\xff\xff\x01\x04\x00\x01\x7f\x00']:
            with self.subTest(raw=raw),self.assertRaises(ValueError):m.lsda_rows(raw,0x100,0x110)
    def test_unmapped_and_nobits_bytes_not_file_backed(self):
        before=self.image.sections
        changed=copy.deepcopy(before)
        next(s for s in changed if s['name']=='.text')['type']=8
        try:
            self.image.sections=changed
            with self.assertRaises(ValueError):self.image.read(0x5ca53f0,1)
        finally:self.image.sections=before
        with self.assertRaises(ValueError):self.image.read(0,100)
    def test_native_byte_gap_and_corruption_are_rejected(self):
        raw=(PACKET/'native/drain.objdump.txt').read_bytes()
        rows=m.native_rows(raw,self.image,0x5ca53f0,0x5ca5510)
        self.assertEqual(rows[0][0],0x5ca53f0)
        for bad in [raw.replace(b'5ca53f0:',b'5ca53f1:',1),
                    raw.replace(b'55 ',b'54 ',1),
                    b'\n'.join(line for line in raw.split(b'\n') if b'5ca542b:' not in line)]:
            with self.assertRaises(ValueError):m.native_rows(bad,self.image,0x5ca53f0,0x5ca5510)
    def test_lock_join_only_at_two_exact_sites(self):
        rows,joins=m.join_lock([(0x5ca54f3,b'\xf0'),(0x5ca54f4,bytes.fromhex('48ff48f0'))])
        self.assertEqual(joins,['0x5ca54f3']);self.assertEqual(len(rows),1)
        with self.assertRaises(ValueError):m.join_lock([(0x5ca54f3,b'\xf0'),(0x5ca54f4,b'\x90')])
        rows,joins=m.join_lock([(0x100,b'\xf0'),(0x101,b'\x90')])
        self.assertEqual(joins,[]);self.assertEqual(len(rows),2)
    def test_target_admission_rejects_wrong_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);file=root/'artifacts/node/115/hl-node';file.parent.mkdir(parents=True)
            file.write_bytes(b'not the captured artifact')
            with self.assertRaises(ValueError):m.load(root)
            with file.open('wb') as handle:
                handle.write(bytes([self.image.data[0]^1]))
                handle.write(memoryview(self.image.data)[1:])
            with self.assertRaisesRegex(ValueError,'Wrong target'):m.load(root)

if __name__=='__main__':unittest.main()
