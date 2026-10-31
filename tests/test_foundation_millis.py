"""Target-grounded corruption controls and finite reciprocal-division proofs."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import foundation_millis as millis
from elf_index import sections


class ReciprocalTests(unittest.TestCase):
    def test_complete_domain_certificates_and_critical_values(self):
        for c,k,d,n in [(0x20c49ba5e353f7cf,68,125,millis.U64>>3),
                         (0x31b5d43afe99ef,70,84375,millis.U64>>10),
                         (0x308b91419ca253,70,86400,millis.U64//1000)]:
            record = millis.prove_division(c,k,d,n)
            self.assertTrue(record['complete_integer_domain'])
            self.assertLess(record['worst_fractional_numerator'],1<<k)
            # Independent ordinary division at the top of every remainder class.
            for r in range(d):
                value=((n-r)//d)*d+r
                self.assertEqual((value*c)>>k,value//d)

    def test_wrong_reciprocal_and_shift_are_rejected(self):
        for c,k in [(0x20c49ba5e353f7cf-1,68),(0x20c49ba5e353f7cf,67),
                    (0x20c49ba5e353f7cf,69)]:
            with self.assertRaises(ValueError):
                millis.prove_division(c,k,125,millis.U64>>3)


class MillisEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not millis.TARGET.is_file() or millis.TARGET.stat().st_size!=91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result=millis.inspect(millis.TARGET)
        cls.data=millis.TARGET.read_bytes()
        cls.records=json.loads((millis.PACKET/'records.json').read_text())
        cls.sections=sections(cls.data)

    def offset(self,va):
        sec=next(s for s in self.sections if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return sec['offset']+va-sec['address']

    def test_retained_evidence_reproduces(self):
        self.assertEqual(self.result,json.loads((millis.PACKET/'evidence.json').read_text()))

    def test_wrong_target_and_truncated_input_rejected(self):
        with self.assertRaisesRegex(ValueError,'size/SHA-256'):
            millis.inspect(millis.ROOT/'artifacts/node/115/hl-node')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input';path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'size/SHA-256'):millis.inspect(path)

    def test_actual_instruction_and_error_message_mutations(self):
        # Structural checks deliberately bypass only the digest gate, to reach
        # the downstream checks; the public CLI always checks full identity.
        for va,expected in [(0x13c8e3b,'Instruction window'),
                            (0x13c8e4c,'Instruction window'),
                            (0x13c8e81,'Instruction window'),
                            (0x13c8f2d,'Instruction window'),
                            (0x1e1153,'Error message')]:
            with self.subTest(va=hex(va)):
                data=bytearray(self.data);data[self.offset(va)]^=1
                with self.assertRaisesRegex(ValueError,expected):millis.analyze(data,self.records)

    def test_fde_and_cie_record_corruption_rejected(self):
        for field in ['fde_hex','cie_hex']:
            records=copy.deepcopy(self.records)
            value=bytes.fromhex(records['windows'][0][field])
            records['windows'][0][field]=(bytes([value[0]^1])+value[1:]).hex()
            with self.assertRaisesRegex(ValueError,'FDE changed|CIE changed'):
                millis.analyze(self.data,records)

    def test_relative_slot_retargeting_rejected(self):
        records=copy.deepcopy(self.records)
        records['relative_slots']['0x576e890']='0x151f6f1'
        with self.assertRaisesRegex(ValueError,'Relative call slot'):millis.analyze(self.data,records)

    def test_disassembly_off_by_one_and_byte_corruption_rejected(self):
        row=self.records['windows'][0];start=int(row['start_va'],16);end=int(row['end_va_exclusive'],16)
        raw=(millis.PACKET/'conversion.objdump.txt').read_text()
        off=self.offset(start);body=self.data[off:off+end-start]
        for text in [raw.replace('13c8ef3:','13c8ef4:'),
                     raw.replace('e8 a8 7a 08 00','e8 a9 7a 08 00'),raw.rsplit('\n',2)[0]]:
            with self.assertRaises(ValueError):millis.decode_export(text,start,end,body)

    def test_calendar_tables_reject_corruption_past_digest_lock(self):
        for index,byte_index in [(0,100),(1,100)]:
            with self.subTest(table=index):
                data=bytearray(self.data);records=copy.deepcopy(self.records)
                table=records['calendar_tables'][index]
                off=self.offset(int(table['start_va'],16));data[off+byte_index]^=1
                # Recompute this lock only, so the independent Gregorian check
                # sees the altered century entry rather than stopping at SHA.
                table['sha256']=hashlib.sha256(data[off:off+table['bytes']]).hexdigest()
                with self.assertRaisesRegex(ValueError,'Gregorian table identity'):
                    millis.analyze(data,records)

    def test_calendar_location_line_corruption_rejected(self):
        data=bytearray(self.data)
        off=self.offset(0x5672140)+16
        struct.pack_into('<I',data,off,2324)
        with self.assertRaisesRegex(ValueError,'Calendar source location'):
            millis.analyze(data,self.records)

    def test_calendar_source_relocation_corruption_rejected(self):
        records=copy.deepcopy(self.records)
        records['calendar_source_locations'][0]['path_va']='0x1'
        with self.assertRaisesRegex(ValueError,'Calendar source relocation'):
            millis.analyze(self.data,records)

    def test_gnu_objdump_wrapped_instruction_counts_once(self):
        # Recorded exports of the same window prefix: GNU objdump wraps the
        # 10-byte movabs at 0x13c8e39 after 7 bytes, and its last 3 bytes
        # continue on an addressed row with an empty mnemonic field. Both
        # formats must decode to the same 14 instructions, not 14 vs 15.
        start,end=0x13c8e10,0x13c8e43;off=self.offset(start);body=self.data[off:off+end-start]
        gnu='\n'.join([
            ' 13c8e10:\t41 57                \tpush   %r15',
            ' 13c8e12:\t41 56                \tpush   %r14',
            ' 13c8e14:\t41 54                \tpush   %r12',
            ' 13c8e16:\t53                   \tpush   %rbx',
            ' 13c8e17:\t48 83 ec 18          \tsub    $0x18,%rsp',
            ' 13c8e1b:\t48 89 fb             \tmov    %rdi,%rbx',
            ' 13c8e1e:\t48 8b 46 08          \tmov    0x8(%rsi),%rax',
            ' 13c8e22:\t48 f7 26             \tmulq   (%rsi)',
            ' 13c8e25:\t0f 80 02 01 00 00    \tjo     13c8f2d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3bdeed3>',
            ' 13c8e2b:\t49 89 c6             \tmov    %rax,%r14',
            ' 13c8e2e:\t4c 89 34 24          \tmov    %r14,(%rsp)',
            ' 13c8e32:\t4c 89 f0             \tmov    %r14,%rax',
            ' 13c8e35:\t48 c1 e8 03          \tshr    $0x3,%rax',
            ' 13c8e39:\t48 b9 cf f7 53 e3 a5 \tmovabs $0x20c49ba5e353f7cf,%rcx',
            ' 13c8e40:\t9b c4 20 '])
        llvm='\n'.join([
            ' 13c8e10: 41 57                        \tpushq\t%r15',
            ' 13c8e12: 41 56                        \tpushq\t%r14',
            ' 13c8e14: 41 54                        \tpushq\t%r12',
            ' 13c8e16: 53                           \tpushq\t%rbx',
            ' 13c8e17: 48 83 ec 18                  \tsubq\t$0x18, %rsp',
            ' 13c8e1b: 48 89 fb                     \tmovq\t%rdi, %rbx',
            ' 13c8e1e: 48 8b 46 08                  \tmovq\t0x8(%rsi), %rax',
            ' 13c8e22: 48 f7 26                     \tmulq\t(%rsi)',
            ' 13c8e25: 0f 80 02 01 00 00            \tjo\t0x13c8f2d <.text+0x852ad>',
            ' 13c8e2b: 49 89 c6                     \tmovq\t%rax, %r14',
            ' 13c8e2e: 4c 89 34 24                  \tmovq\t%r14, (%rsp)',
            ' 13c8e32: 4c 89 f0                     \tmovq\t%r14, %rax',
            ' 13c8e35: 48 c1 e8 03                  \tshrq\t$0x3, %rax',
            ' 13c8e39: 48 b9 cf f7 53 e3 a5 9b c4 20\tmovabsq\t$0x20c49ba5e353f7cf, %rcx # imm = 0x20C49BA5E353F7CF'])
        decoded=millis.decode_export(gnu,start,end,body)
        self.assertEqual(decoded,millis.decode_export(llvm,start,end,body))
        self.assertEqual(len(decoded),14)
        self.assertEqual(decoded[0x13c8e39],bytes.fromhex('48 b9 cf f7 53 e3 a5 9b c4 20'))
        self.assertNotIn(0x13c8e40,decoded)

    def test_calendar_helper_disassembly_boundary_control(self):
        row=self.records['windows'][2];start=int(row['start_va'],16);end=int(row['end_va_exclusive'],16)
        raw=(millis.PACKET/'calendar_helper.objdump.txt').read_text()
        off=self.offset(start);body=self.data[off:off+end-start]
        for text in [raw.replace('151f755:','151f756:'),raw.rsplit('\n',2)[0]]:
            with self.assertRaises(ValueError):millis.decode_export(text,start,end,body)

    def test_millisecond_split_boundary_cases(self):
        first,day,second_day=self.result['division_proofs']
        for value in [0,1,999,1000,1001,86399999,86400000,86400001,millis.U64]:
            secs=(((value>>3)*int(first['multiplier'],16))>>first['shift'])
            days=(((value>>10)*int(day['multiplier'],16))>>day['shift'])
            days_from_seconds=(secs*int(second_day['multiplier'],16))>>second_day['shift']
            self.assertEqual(secs,value//1000)
            self.assertEqual(days,value//86400000)
            self.assertEqual(days_from_seconds,days)
            # The target computes the nanosecond remainder in low 32-bit regs.
            remainder=((value&0xffffffff)-(secs*1000&0xffffffff))&0xffffffff
            self.assertEqual(remainder,value%1000)
            self.assertLess(remainder*1000000,1<<32)


if __name__=='__main__':unittest.main()
