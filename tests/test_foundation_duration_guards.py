"""Static real-target evidence and independent binary64 comparison controls."""
import copy
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

    def test_gnu_objdump_wrapped_instruction_counts_once(self):
        # Recorded exports of the same window prefix: GNU objdump wraps the
        # 8-byte movsd at 0x392fabd after 7 bytes, and its last byte continues
        # on an addressed row with an empty mnemonic field. Both formats must
        # decode to the same 5 instructions, not 5 (LLVM) vs 6 (GNU).
        start,end=0x392fab0,0x392fac5;off=self.offset(start);body=self.data[off:off+end-start]
        gnu='\n'.join([
            ' 392fab0:\t53                   \tpush   %rbx',
            ' 392fab1:\t89 f3                \tmov    %esi,%ebx',
            ' 392fab3:\t40 80 ff 02          \tcmp    $0x2,%dil',
            ' 392fab7:\t0f 83 b7 00 00 00    \tjae    392fb74 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x167828c>',
            ' 392fabd:\tf2 0f 10 0d 6b ad 8d \tmovsd  -0x3725295(%rip),%xmm1        # 20a830 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x4d9d5d0>',
            ' 392fac4:\tfc '])
        llvm='\n'.join([
            ' 392fab0: 53                           \tpushq\t%rbx',
            ' 392fab1: 89 f3                        \tmovl\t%esi, %ebx',
            ' 392fab3: 40 80 ff 02                  \tcmpb\t$0x2, %dil',
            ' 392fab7: 0f 83 b7 00 00 00            \tjae\t0x392fb74 <.text+0x25ebef4>',
            ' 392fabd: f2 0f 10 0d 6b ad 8d fc      \tmovsd\t-0x3725295(%rip), %xmm1 # 0x20a830'])
        decoded=guards.decode_export(gnu,start,end,body)
        self.assertEqual(decoded,guards.decode_export(llvm,start,end,body))
        self.assertEqual(len(decoded),5)
        self.assertEqual(decoded[0x392fabd],bytes.fromhex('f2 0f 10 0d 6b ad 8d fc'))
        self.assertNotIn(0x392fac4,decoded)


if __name__=='__main__':unittest.main()
