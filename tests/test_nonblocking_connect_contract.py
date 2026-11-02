"""Actual helper bytecode versus independent sockaddr/call/result equations."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import nonblocking_connect_contract as subject


class NonblockingConnectContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=subject.TARGET.read_bytes();cls.image,cls.native=subject.inspect(cls.data)
        cls.result=subject.analyse()

    def test_full_native_regeneration_and_all_instructions_exercised(self):
        self.assertEqual(self.result['case_count'],1200)
        self.assertEqual(self.result['instruction_coverage'],{'decoded':69,'seen':69})
        self.assertEqual(self.native['bytes'],247)
        self.assertEqual(subject.summary(self.result),json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual(subject.decoder_crosscheck(self.data),
                         {'instructions':69,'complete_bytes':247,'raw_instruction_rows_equal':True})

    def test_error_and_close_call_classes_and_inactive_output_words(self):
        initial=b'\xa5'*16
        for row in self.result['results']:
            p=row['plan'];events=row['events'];out=bytes.fromhex(row['output_hex'])
            accepted=p['socket']>=0 and (p['connect']>=0 or p['errno']==115)
            self.assertEqual(int.from_bytes(out[:4],'little'),0 if accepted else 1)
            if accepted:
                self.assertEqual(out[8:],initial[8:]);self.assertEqual(events[-1][0],'errno' if p['connect']<0 else 'connect')
            else:
                self.assertEqual(out[4:8],initial[4:8])
                self.assertEqual(int.from_bytes(out[8:],'little'),((p['errno']&0xffffffff)<<32)|2)
            self.assertEqual(sum(event[0]=='close' for event in events),int(p['socket']>=0 and not accepted))
            self.assertEqual(sum(event[0]=='errno' for event in events),int(p['socket']<0 or p['connect']<0))

    def test_sockaddr_visible_bytes_port_order_and_raw_ipv6_words(self):
        for family in (0,1):
            raw=subject.address(family,0x1234)
            plan={'socket':0,'connect':1,'errno':-1,'close':-1,'errno_after_close':-999}
            actual,_=subject.evaluate(self.image,raw,plan)
            event=actual['events'][1];wire=bytes.fromhex(event[2])
            self.assertEqual(event[0],'connect');self.assertEqual(wire[2:4],b'\x12\x34')
            self.assertEqual((wire[:2],len(wire)),(b'\x02\0',16) if family==0 else (b'\x0a\0',28))
            if family==0:self.assertEqual(wire[8:],bytes(8))
            else:self.assertEqual((wire[4:8],wire[8:24],wire[24:]),(raw[20:24],raw[4:20],raw[24:28]))

    def test_actual_mutations_require_call_trace_not_only_final_result(self):
        controls=subject.controls()
        self.assertEqual(len(controls),3)
        self.assertTrue(all(row['before']!=row['after'] and row['rejected'] for row in controls))
        self.assertTrue(controls[0]['result_words_unchanged'])
        self.assertTrue(controls[1]['result_words_unchanged'])
        self.assertFalse(controls[2]['result_words_unchanged'])

    def test_rol16_complete_value_domain_and_unused_flags_remain_unknown(self):
        m=subject.Machine(self.image,{'errno':0})
        for value in range(65536):
            m.flags=[True,False,True,False]
            expected=int.from_bytes(value.to_bytes(2,'little'),'big')
            self.assertEqual(m.shift(0,value,8,16),expected)
            self.assertEqual(m.flags,[None,False,True,None])
        with self.assertRaisesRegex(ValueError,'only observed'):
            m.shift(0,1,1,16)
        self.assertIsNone(m.condition(2))
        with self.assertRaises(subject.cpu.ToolError):m.jump(2,None,subject.START)

    def test_real_fde_symbol_identity_and_unsupported_call_fail_closed(self):
        private=bytearray(self.data);fde=int(self.native['unwind_records']['fde']['va'],16)
        struct.pack_into('<I',private,self.image.file_offset(fde)+12,246)
        with self.assertRaisesRegex(ValueError,'FDE'):subject.observe(private)
        private=bytearray(self.data);private[self.image.file_offset(0x3cd63dd)]^=1
        plan={'socket':7,'connect':0,'errno':0,'close':0,'errno_after_close':0}
        with self.assertRaises((ValueError,subject.cpu.ToolError)):
            subject.evaluate(subject.cpu.Image(private),subject.address(0,80),plan)
        with self.assertRaisesRegex(ValueError,'identity'):
            subject.inspect(bytes(64))
        m=subject.Machine(self.image,{'errno':0})
        with self.assertRaisesRegex(ValueError,'memory escaped'):m.load(subject.cpu.INPUT+32,1)
        with self.assertRaisesRegex(ValueError,'memory escaped'):m.store(subject.cpu.INPUT,1,0)
        m.pc=subject.END
        with self.assertRaisesRegex(ValueError,'control-flow'):m.step()
