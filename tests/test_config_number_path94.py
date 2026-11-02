"""Static evidence and abstract-contract controls; never execute the capture."""
import copy
from fractions import Fraction
from pathlib import Path
import struct
import unittest

from tools import config_number_path94 as c

class PatchedImage:
    """Modify selected byte reads beneath whole-artifact authentication."""
    def __init__(self, original, address=None, replacement=b''):
        self.original=original
        self.address=address
        self.replacement=replacement
        self.relocations=dict(original.relocations)
    def read(self,va,size):
        result=bytearray(self.original.read(va,size))
        if self.address is not None:
            for i,byte in enumerate(self.replacement):
                at=self.address+i
                if va<=at<va+size:result[at-va]=byte
        return bytes(result)
    def offset(self,va,size):return self.original.offset(va,size)
    def fde(self,va):return self.original.fde(va)

class ConfigNumberPath94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(c.ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.image=c.Image(cls.data)
        cls.records=c.collect(cls.image)
        c.qualify(cls.image,cls.records)
        cls.contract=c.Contract(cls.image,cls.records)
    def model(self,data,positive=True,syntax=False,position=0):
        return c.number_model(self.contract,data,positive,position,syntax)
    def test_artifact_identity_required(self):
        for data in (b'',b'\x7fELF',self.data[:100]):
            with self.subTest(size=len(data)),self.assertRaises(c.EvidenceError):c.Image(data)
    def test_file_backing_controls(self):
        for va,size in [(-1,1),(0,1),(1<<63,8),(0x164db50,-1)]:
            with self.subTest(va=va,size=size),self.assertRaises(c.EvidenceError):self.image.read(va,size)
        bss=next(s for s in self.image.sections if s['name']=='.bss')
        with self.assertRaises(c.EvidenceError):self.image.read(bss['address'],1)
        duplicate=copy.copy(self.image)
        text=next(s for s in self.image.sections if s['name']=='.text')
        duplicate.sections=self.image.sections+[dict(text)]
        with self.assertRaises(c.EvidenceError):duplicate.read(0x164db50,1)
    def test_truncated_instruction_and_unsupported_opcode(self):
        for raw in (b'\x48',b'\xe8\0',b'\x0f\x85\0',b'\x48\x8b\x84',b'\x62',b'\xff\xf0'):
            with self.subTest(raw=raw.hex()),self.assertRaises(c.EvidenceError):c.decode(raw,0x1000)
    def test_branch_into_operand_rejected(self):
        with self.assertRaises(c.EvidenceError):c.decode(bytes.fromhex('ebff'),0x1000)
    def test_selected_bodies_partition_without_holes(self):
        for f in self.records['functions']:
            rows=[r for r in self.records['instructions'] if r['function']==f['entry']]
            self.assertEqual(rows[0]['va'],f['entry'])
            self.assertEqual(rows[-1]['va']+rows[-1]['size'],f['end'])
            for a,b in zip(rows,rows[1:]):self.assertEqual(a['va']+a['size'],b['va'])
            self.assertEqual(b''.join(bytes.fromhex(r['bytes']) for r in rows),self.image.read(f['entry'],f['bytes']))
    def test_every_selected_body_corruption_rejected(self):
        for f in self.records['functions']:
            with self.subTest(entry=hex(f['entry'])):
                patched=PatchedImage(self.image,f['entry'],b'\x90')
                with self.assertRaises(c.EvidenceError):c.qualify(patched,c.collect(patched))
    def test_valid_wrong_branch_polarity_rejected(self):
        patched=PatchedImage(self.image,0x164db7a,b'\x74')
        records=c.collect(patched)
        with self.assertRaises(c.EvidenceError):c.qualify(patched,records)
    def test_wrong_integer_threshold_rejected(self):
        patched=PatchedImage(self.image,0x164dbc5,b'\x97')
        records=c.collect(patched)
        self.assertNotEqual(c.Contract(patched,records).uint_max,self.contract.uint_max)
        with self.assertRaises(c.EvidenceError):c.qualify(patched,records)
    def test_wrong_tag_rejected(self):
        patched=PatchedImage(self.image,0x164d866,b'\x02')
        records=c.collect(patched)
        self.assertEqual(c.Contract(patched,records).unsigned_tag,2)
        with self.assertRaises(c.EvidenceError):c.qualify(patched,records)
    def test_missing_and_retargeted_relocations(self):
        for slot in c.SLOT_GATES:
            with self.subTest(slot=hex(slot)):
                image=PatchedImage(self.image);del image.relocations[slot]
                with self.assertRaises(c.EvidenceError):c.qualify(image,self.records)
                image.relocations[slot]=0
                with self.assertRaises(c.EvidenceError):c.qualify(image,self.records)
    def test_fde_endpoint_control(self):
        records=copy.deepcopy(self.records)
        records['functions'][0]['end']-=1
        with self.assertRaises(c.EvidenceError):c.qualify(self.image,records)
        image=copy.copy(self.image);selected=self.image.fde(0x164db50)
        image.fdes=self.image.fdes+[selected]
        with self.assertRaises(c.EvidenceError):image.fde(0x164db50)
    def test_float_constant_corruption(self):
        for va in c.DATA_GATES:
            original=self.image.read(va,1)[0]
            patched=PatchedImage(self.image,va,bytes([original^1]))
            with self.subTest(va=hex(va)),self.assertRaises(c.EvidenceError):c.qualify(patched,self.records)
    def test_power_table_corruption(self):
        for i in (0,1,22,308):
            va=self.contract.table_va+8*i
            patched=PatchedImage(self.image,va,bytes([self.image.read(va,1)[0]^1]))
            with self.subTest(index=i),self.assertRaises(c.EvidenceError):c.Contract(patched,self.records)
    def test_power_table_out_of_range(self):
        image=PatchedImage(self.image);image.relocations[self.contract.table_slot]=1<<63
        with self.assertRaises(c.EvidenceError):c.Contract(image,self.records)
    def test_diagnostic_source_pool_identity(self):
        rows=c.source_locations(self.image,self.records)
        self.assertEqual({r['source_suffix'] for r in rows},
                         {'serde_json-1.0.120/src/de.rs','serde_json-1.0.120/src/read.rs'})
        for va in c.SOURCE_GATES:
            patched=PatchedImage(self.image,va,b'!')
            with self.subTest(va=va),self.assertRaises(c.EvidenceError):c.source_locations(patched,self.records)
    def test_diagnostic_source_length_and_pointer_controls(self):
        patched=PatchedImage(self.image,0x567b310,struct.pack('<Q',95))
        with self.assertRaises(c.EvidenceError):c.source_locations(patched,self.records)
        patched=PatchedImage(self.image);patched.relocations[0x567b308]=1<<63
        with self.assertRaises(c.EvidenceError):c.source_locations(patched,self.records)
    def test_owned_caller_edges_are_only_boundary_context(self):
        links=c.context_links(self.image)
        self.assertTrue(all(r['caller'] not in c.ENTRIES and r['target'] in c.ENTRIES for r in links))
        for site in c.CONTEXT_CALLS:
            patched=PatchedImage(self.image,site+1,b'\0')
            with self.subTest(site=site),self.assertRaises(c.EvidenceError):c.context_links(patched)
    def test_extracted_limits(self):
        k=self.contract
        self.assertEqual((k.uint_max,k.exp_max,k.pow_count,k.scale_chunk),(2**64-1,2**31-1,309,308))
        self.assertEqual((k.pointer_offset,k.length_offset,k.cursor_offset),(24,32,40))
    def test_all_initial_byte_classes(self):
        for i in range(256):
            for syntax in (False,True):
                with self.subTest(byte=i,syntax=syntax):
                    r=self.model(bytes([i]),syntax=syntax)
                    self.assertEqual(r['cursor'],1)
                    self.assertEqual(r['kind']=='error',not 48<=i<=57)
    def test_integer_domains_and_negative_zero(self):
        self.assertEqual(self.model(b'0',False)['bits'],'8000000000000000')
        self.assertEqual(self.model(b'0')['tag'],1)
        self.assertEqual(self.model(str(2**64-1).encode())['kind'],'unsigned')
        self.assertEqual(self.model(str(2**64).encode())['kind'],'binary64')
        self.assertEqual(self.model(str(2**63).encode(),False)['integer'],str(-2**63))
        self.assertEqual(self.model(str(2**63+1).encode(),False)['kind'],'binary64')
    def test_grammar_and_cursor_failure_controls(self):
        for data,p,code in [(b'01',1,13),(b'1.x',2,13),(b'1e-x',4,13),(b'1e+',3,5),(b'1.',2,5)]:
            with self.subTest(data=data):
                r=self.model(data);self.assertEqual((r['cursor'],r['code']),(p,code))
        self.assertEqual(self.model(b'01')['position']['column'],2)
        self.assertEqual(self.model(b'1.x')['position']['column'],3)
    def test_syntax_only_has_no_magnitude_limit(self):
        for data in (b'1e309',b'9'*400,b'1e2147483648999'):
            self.assertEqual(self.model(data)['kind'],'error')
            r=self.model(data,syntax=True)
            self.assertEqual((r['kind'],r['cursor']),('syntax_success',len(data)))
    def test_syntax_only_missing_digits(self):
        for data in (b'',b'1.',b'1e',b'1e+',b'1e-x'):
            r=self.model(data,syntax=True)
            self.assertEqual((r['kind'],r['code']),('error',13))
    def test_exponent_overflow_consumption(self):
        data=b'1e2147483648999'
        r=self.model(data);self.assertEqual((r['code'],r['cursor']),(14,12))
        for data in (b'0e2147483648999',b'1e-2147483648999'):
            for positive in (False,True):
                r=self.model(data,positive)
                self.assertEqual(r['cursor'],len(data))
                self.assertEqual(r['bits'],'0000000000000000' if positive else '8000000000000000')
    def test_fraction_tail_discards_digits(self):
        base=b'0.12345678901234567890'
        results=[self.model(base+tail) for tail in (b'123456',b'199999',b'999999')]
        self.assertEqual(len({r['bits'] for r in results}),1)
        for r in results:self.assertIn('overflow_fraction_tail',r['route'])
    def test_delimiter_is_unconsumed(self):
        for data,p in [(b'123,',3),(b'1.2.3',3),(b'1e1e1',3),(b'1 2',1)]:
            for syntax in (False,True):self.assertEqual(self.model(data,syntax=syntax)['cursor'],p)
    def test_position_counts_bytes_and_peek(self):
        data=b'ab\n\xc3\xa9x'
        self.assertEqual(c.location(data,5),{'line':2,'column':2})
        self.assertEqual(c.location(data,5,True),{'line':2,'column':3})
        for position in (-1,len(data)+1):
            with self.assertRaises(c.EvidenceError):c.location(data,position)
    def test_model_input_bounds(self):
        for position in (-1,2):
            with self.assertRaises(c.EvidenceError):self.model(b'1',position=position)
        with self.assertRaises(c.EvidenceError):self.model(b'1',positive=2)
        class UnallocatedLargeSlice(bytes):
            def __len__(self):return 2**31
        with self.assertRaises(c.EvidenceError):self.model(UnallocatedLargeSlice(b'1'))
    def test_rational_rounding_ties(self):
        self.assertEqual(c.binary64(1),0x3ff0000000000000)
        self.assertEqual(c.binary64(Fraction(2**53+1,2**53)),0x3ff0000000000000)
        self.assertEqual(c.binary64(Fraction(2**53+3,2**53)),0x3ff0000000000002)
        self.assertEqual(c.binary64(Fraction(1,2**1075)),0)
        self.assertEqual(c.binary64(Fraction(3,2**1075)),2)
        self.assertEqual(c.binary64(2**1024),0x7ff0000000000000)
    def test_simple_exact_float_cases(self):
        for data,bits in [(b'1.5','3ff8000000000000'),(b'1e2','4059000000000000'),(b'0.5','3fe0000000000000')]:
            self.assertEqual(self.model(data)['bits'],bits)
        self.assertEqual(self.model(b'1e-324')['bits'],'0000000000000000')
    def test_error_constructor_layout_bytes(self):
        self.assertEqual(self.image.read(0x4ebcd8f,5).hex(),'bf28000000')
        self.assertEqual(self.image.read(0x4ebcd85,10).hex(),'48897424184889542420')
    def test_regeneration_matches_packet(self):
        outputs=c.generate(self.data)
        packet=c.ROOT/'research/work-items/RE-015-config-number-path-94'
        self.assertEqual(set(outputs),{p.name for p in packet.iterdir() if p.suffix in ('.json','.tsv')})
        for name,text in outputs.items():self.assertEqual(text.encode(),(packet/name).read_bytes(),name)

if __name__=='__main__':unittest.main()
