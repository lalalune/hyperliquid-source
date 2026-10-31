"""Static target-grounded positive-path evidence; no execution/emulation of hl-node."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import priority_prefix_static as subject
from elf_index import sections


class PriorityPrefixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:
            raise ValueError('wrong node115 fixture')
        cls.secs=sections(cls.data)
        cls.report=subject.analyze(cls.data)

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        changed=bytearray(self.data)
        off=self.offset(va)
        changed[off]=changed[off]^1 if value is None else value
        return changed

    def test_native_regeneration_and_packet(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),3513)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            subject.generate(subject.TARGET,out)
            for p in out.iterdir():
                self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_two_extracted_numeric_predicates_cover_every_unsigned_byte(self):
        prefix=subject.read(self.data,subject.OWNERS[0][0],subject.PREFIX_SIZE)[1]
        for gate in subject.numeric_certificate(prefix):
            self.assertEqual(gate['accepted_u8'],list(range(256)))
            self.assertEqual((gate['addend'],gate['shift'],gate['threshold']),('0xfff0000000000000',53,1023))
        # Numeric conversion is exact: all these integer values fit binary64.
        for value in range(256):
            self.assertEqual(int(struct.unpack('<d',struct.pack('<d',value))[0]),value)
        self.assertEqual(self.report['number_of_three_u8_value_combinations'],16777216)
        self.assertEqual(self.report['calls_on_certified_path'],0)

    def test_real_semantic_counterfactuals(self):
        for relative in [0x65,0xb8]:
            start=subject.OWNERS[0][0]
            changed=bytearray(self.data)
            struct.pack_into('<I',changed,self.offset(start+relative),0)
            prefix=subject.read(changed,start,subject.PREFIX_SIZE)[1]
            gate=subject.numeric_certificate(prefix)[0 if relative==0x65 else 1]
            self.assertEqual(gate['accepted_u8'],[0])
            with self.assertRaisesRegex(ValueError,'numeric gate'):
                subject.analyze(changed)
        start=subject.OWNERS[0][0]
        changed=self.mutate(start+0x165,0xf6)  # actual JMP destination epilogue+1
        prefix=subject.read(changed,start,subject.PREFIX_SIZE)[1]
        self.assertEqual(subject.transfer_certificate(prefix)[0x164],0x25f)
        with self.assertRaisesRegex(ValueError,'destination'):
            subject.analyze(changed)

    def test_real_dataflow_boundary_and_state_controls_all_three_owners(self):
        for start,_,_ in subject.OWNERS:
            # Cursor/counter writes, float conversion, default tags, output
            # destinations and epilogue: actual operands, not unrelated bytes.
            for relative in [0x29,0x4a,0x4f,0xa4,0xe0,0x10a,0x10e,0x11f,0x137,0x142,0x153,0x162,0x25f]:
                with self.subTest(start=hex(start),relative=hex(relative)):
                    with self.assertRaisesRegex(ValueError,'dataflow|epilogue|opcode|destination|numeric'):
                        subject.analyze(self.mutate(start+relative))

    def test_real_relocations_fde_bounds_and_diagnostic_xrefs(self):
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        rels={struct.unpack_from('<Q',self.data,p)[0]:p for p in range(sec['offset'],sec['offset']+sec['size'],24)}
        for (start,_,slot),owner in zip(subject.OWNERS,self.report['owners']):
            changed=bytearray(self.data)
            changed[rels[slot]+16]^=1
            with self.assertRaisesRegex(ValueError,'diagnostic'):
                subject.analyze(changed)
            with self.assertRaisesRegex(ValueError,'LEA'):
                subject.analyze(self.mutate(start+0x16d+3))
            fde=int(owner['frames']['fde']['va'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                subject.analyze(self.mutate(fde+12))

    def test_public_identity_gate_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);p=root/'changed';out=root/'out'
            p.write_bytes(self.mutate(subject.OWNERS[0][0]+0x65))
            for source in [p,subject.ROOT/'artifacts/node/94/hl-node']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(source,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())
