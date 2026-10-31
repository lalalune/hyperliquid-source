"""Static real-target evidence and independent binary64 comparison controls."""
import copy
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import foundation_duration_guards as guards
from elf_index import sections


def bits(value):
    return struct.unpack('<Q',struct.pack('<d',value))[0]


class ArchitecturalModelTests(unittest.TestCase):
    def test_guard_matches_independent_float_comparison(self):
        # This checks architectural reasoning, not the captured program.
        values=[0.0,-0.0,1.0,-1.0,math.inf,-math.inf,math.nan,
                math.nextafter(0.0,1.0),math.nextafter(0.0,-1.0),
                math.nextafter(1.0,0.0),math.nextafter(1.0,math.inf)]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(bool(guards.guard_flags(bits(value))['CF']),not value>=0.0)
        self.assertEqual(guards.guard_flags(0x7ff0000000000001),dict(CF=1,PF=1,ZF=1))
        self.assertEqual(guards.guard_flags(0xfff8000000000001),dict(CF=1,PF=1,ZF=1))
        self.assertEqual(guards.guard_flags(bits(-0.0)),dict(CF=0,PF=0,ZF=1))

    def test_finite_prefix_and_nonfinite_bypass_are_distinct(self):
        for value in [-1e300,-1.0,-0.0,0.0,1e-300,0.5,1.0,1.0000000000000002,1e300]:
            # Ordered Python min/max oracle, with equal-zero source first.
            expected=bits(min(max(value,0.0),1.0))
            self.assertEqual(guards.prefix_result(bits(value)),expected)
        self.assertEqual(guards.prefix_result(bits(math.inf)),bits(math.inf))
        self.assertIsNone(guards.prefix_result(bits(-math.inf)))
        self.assertIsNone(guards.prefix_result(bits(math.nan)))
        self.assertEqual(guards.prefix_result(bits(-1.0)),0)
        self.assertEqual(guards.prefix_result(bits(-0.0)),guards.SIGN)

    def test_partition_covers_all_patterns_without_enumeration_claim(self):
        rows=guards.partition()
        self.assertEqual(len(rows),9)
        self.assertEqual(sum(row['pattern_count'] for row in rows),1<<64)
        for row in rows:
            first,last=int(row['first_bits'],16),int(row['last_bits'],16)
            for sample in [first,(first+last)//2,last]:
                self.assertEqual(guards.guard_flags(sample),row['isolated_guard_flags'])
                out=guards.prefix_result(sample)
                kind=row['prefix_result_kind']
                if kind=='error_arm':self.assertIsNone(out)
                elif kind=='constant_one':self.assertEqual(out,guards.ONE)
                elif kind=='constant_positive_zero':self.assertEqual(out,0)
                else:self.assertEqual(out,sample)


class DurationTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not guards.TARGET.is_file() or guards.TARGET.stat().st_size!=91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result=guards.inspect(guards.TARGET)
        cls.data=guards.TARGET.read_bytes()
        cls.records=json.loads((guards.PACKET/'records.json').read_text())
        cls.sections=sections(cls.data)

    def offset(self,va):
        sec=next(s for s in self.sections if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return sec['offset']+va-sec['address']

    def test_retained_record_matches_target(self):
        self.assertEqual(self.result,json.loads((guards.PACKET/'evidence.json').read_text()))

    def test_wrong_target_and_truncation_rejected(self):
        with self.assertRaisesRegex(ValueError,'size/SHA-256'):
            guards.inspect(guards.ROOT/'artifacts/node/115/hl-node')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input';path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'size/SHA-256'):guards.inspect(path)

    def test_target_instruction_and_bound_mutations_rejected(self):
        # Bypass the global digest in test-only structural checks, so the
        # downstream window / data checks see real-target byte mutations.
        for va,message in [(0x392fae6,'Instruction window'),(0x392faf3,'Instruction window'),
                           (0x392fb04,'Instruction window'),(0x392fb26,'Instruction window'),
                           (0x20a730,'Clamp bound')]:
            with self.subTest(va=hex(va)):
                data=bytearray(self.data);data[self.offset(va)]^=1
                with self.assertRaisesRegex(ValueError,message):guards.analyze(data,self.records)

    def test_source_location_and_assertion_text_mutations_rejected(self):
        for va,message in [(0x566ab58+16,'Source location'),(0x219d71,'Assertion text')]:
            data=bytearray(self.data);data[self.offset(va)]^=1
            with self.assertRaisesRegex(ValueError,message):guards.analyze(data,self.records)

    def test_fde_and_relative_slot_corruption_rejected(self):
        records=copy.deepcopy(self.records)
        raw=bytes.fromhex(records['fde_hex']);records['fde_hex']=(bytes([raw[0]^1])+raw[1:]).hex()
        with self.assertRaisesRegex(ValueError,'FDE changed'):guards.analyze(self.data,records)
        records=copy.deepcopy(self.records);records['relative_slots']['0x576e108']='0x157b7f1'
        with self.assertRaisesRegex(ValueError,'Relative call slot'):guards.analyze(self.data,records)

    def test_raw_disassembly_corruption_controls(self):
        start,end=0x392fab0,0x392fcba;off=self.offset(start);body=self.data[off:off+end-start]
        raw=(guards.PACKET/'function.objdump.txt').read_text()
        for changed in [raw.replace('392fb1e:','392fb1f:'),
                        raw.replace('66 0f 2e c8','66 0f 2e c9'),raw.rsplit('\n',2)[0]]:
            with self.assertRaises(ValueError):guards.decode_export(changed,start,end,body)


def synthetic_elf(rows,contents):
    """Minimal ELF64 carrying the given (name, address, size) section rows;
    contents maps a row index to the bytes placed at that row's offset."""
    shstr_row=len(rows)
    rows=list(rows)+[('.shstrtab',0,0)]
    names=b'\0';name_off={}
    for name,_addr,_size in rows:
        if name not in name_off:
            name_off[name]=len(names);names+=name.encode()+b'\0'
    rows[shstr_row]=('.shstrtab',0,len(names))
    shoff=0x1000
    data=bytearray(shoff+len(rows)*64)
    data[0:6]=b'\x7fELF\x02\x01'
    off=0x200;offsets=[]
    for i,(_name,_addr,size) in enumerate(rows):
        offsets.append(off)
        blob=contents.get(i,b'')
        data[off:off+len(blob)]=blob
        off+=max(size,len(blob))+0x10
    data[offsets[shstr_row]:offsets[shstr_row]+len(names)]=names
    struct.pack_into('<Q',data,40,shoff)
    struct.pack_into('<HHH',data,58,64,len(rows),shstr_row)
    for i,(name,addr,size) in enumerate(rows):
        struct.pack_into('<IIQQQQIIQQ',data,shoff+i*64,
                         name_off[name],1,0,addr,offsets[i],size,0,0,1,0)
    return bytes(data)


class DuplicateSectionNameTests(unittest.TestCase):
    """analyze() reads .eh_frame/.rela.dyn through a name->section dict
    that keeps only the last same-named section. A duplicate name must be
    refused: with the valid .eh_frame first the pinned FDE gate failed at
    once, with it last the same bytes passed every FDE/CIE gate, so the
    verdict flipped on section order alone."""
    START,END=0x392fab0,0x392fcba
    EH_GOOD,EH_BAD=0x3000000,0x4000000

    def fixture(self,eh_order):
        body=bytes(range(256))*3
        body=body[:self.END-self.START]
        fde=bytearray(16)
        struct.pack_into('<i',fde,8,self.START-(self.EH_GOOD+0x10+8))
        struct.pack_into('<I',fde,12,self.END-self.START)
        cie=b'CIE!'+b'\0'*12
        records=dict(target_sha256=guards.SHA256,start_va=hex(self.START),
                     end_va_exclusive=hex(self.END),
                     body_sha256=hashlib.sha256(body).hexdigest(),
                     fde_offset=hex(0x10),fde_hex=bytes(fde).hex(),
                     cie_offset=hex(0),cie_hex=cie.hex(),
                     relative_slots={},source_locations=[])
        eh=bytearray(0x100);eh[0:len(cie)]=cie;eh[0x10:0x10+len(fde)]=fde
        rows=[('.text',self.START,self.END-self.START),
              ('.eh_frame',self.EH_GOOD,0x100),
              ('.eh_frame',self.EH_BAD,0x100),
              ('.rela.dyn',0x5000000,0)]
        blobs={0:body,1:bytes(eh),2:b'\0'*0x100}
        if eh_order=='bad-first':
            rows=[rows[0],rows[2],rows[1],rows[3]]
            blobs={0:body,1:b'\0'*0x100,2:bytes(eh)}
        return synthetic_elf(rows,blobs),records,body,bytes(eh)

    def test_duplicate_eh_frame_rejected_in_either_order(self):
        for order in ('good-first','bad-first'):
            with self.subTest(order=order):
                data,records,_body,_eh=self.fixture(order)
                with self.assertRaisesRegex(ValueError,'Duplicate section: .eh_frame'):
                    guards.analyze(data,records)

    def test_duplicate_rela_dyn_rejected(self):
        _data,_records,body,eh=self.fixture('good-first')
        rows=[('.text',self.START,self.END-self.START),
              ('.eh_frame',self.EH_GOOD,0x100),
              ('.rela.dyn',0x5000000,0),('.rela.dyn',0x6000000,0)]
        data=synthetic_elf(rows,{0:body,1:eh})
        _d,records,_b,_e=self.fixture('good-first')
        with self.assertRaisesRegex(ValueError,'Duplicate section: .rela.dyn'):
            guards.analyze(data,records)

    def test_unconsumed_duplicate_names_still_tolerated(self):
        # The guard is scoped to the names analyze() reads; duplicates of a
        # section it never looks up must not be rejected.
        _data,_records,body,eh=self.fixture('good-first')
        rows=[('.text',self.START,self.END-self.START),
              ('.eh_frame',self.EH_GOOD,0x100),
              ('.rela.dyn',0x5000000,0),
              ('.debug_info',0x6000000,0),('.debug_info',0x7000000,0)]
        data=synthetic_elf(rows,{0:body,1:eh})
        _d,records,_b,_e=self.fixture('good-first')
        with self.assertRaises(ValueError) as caught:
            guards.analyze(data,records)
        self.assertNotIn('Duplicate section',str(caught.exception))


if __name__=='__main__':unittest.main()
