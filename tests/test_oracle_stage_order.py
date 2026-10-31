"""Conditional opaque-helper outcomes and actual flag-branch controls."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import oracle_stage_order as tool

class OracleStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def run_stage(self,gate=390,lengths=(1,1),validation=390,slot=0,slots=1,word=0,img=None):
        return tool.stages(img or self.img,gate,lengths,validation,slot,slots,word)

    def test_packet_and_both_selected_length_fields(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['length_checks'],['action+0x10','action+0x40'])

    def test_complete_declared_gate_status_domain(self):
        for status in range(65536):
            result=self.run_stage(gate=status,lengths=(10001,10001))
            self.assertEqual(result['route'],'bounds_0' if status==390 else 'forward_gate')
            self.assertEqual(result['calls'],['gate'])

    def test_two_bounds_validation_and_slot_priority(self):
        for first in (0,10000,10001,(1<<64)-1):
            for second in (0,10000,10001,(1<<64)-1):
                result=self.run_stage(lengths=(first,second),validation=120)
                route='bounds_0' if first>=10001 else 'bounds_1' if second>=10001 else 'forward_validation'
                self.assertEqual(result['route'],route)
                self.assertNotIn('apply',result['calls'])
        self.assertEqual(self.run_stage(slot=1,slots=1)['route'],'slot_failure')
        self.assertEqual(self.run_stage(slot=0,slots=0)['route'],'slot_failure')

    def test_raw_neg_overflow_class_and_post_apply(self):
        for word in (0,1,(1<<63)-1,1<<63,(1<<63)+1,(1<<64)-1):
            result=self.run_stage(word=word)
            self.assertEqual(result['route'],'forward_apply_packet' if word==1<<63 else 'normal_return')
            self.assertEqual('post_apply' in result['calls'],word!=1<<63)

    def test_actual_jno_and_bound_mutations_change_routes(self):
        changed=self.changed(0x2707491,b'\x80')
        self.assertEqual(self.run_stage(word=1<<63,img=tool.Image(changed))['route'],'normal_return')
        with self.assertRaisesRegex(ValueError,'stage/operand'):tool.observe(changed)
        changed=self.changed(0x27072e1+4,struct.pack('<I',10000))
        self.assertEqual(self.run_stage(lengths=(10000,0),img=tool.Image(changed))['route'],'bounds_0')
        with self.assertRaisesRegex(ValueError,'stage/operand'):tool.observe(changed)

    def test_real_helpers_statuses_moves_fde_and_identity(self):
        for va in (0x27072cb+1,0x27072d5,0x2707368+3,0x2707394+1,0x27073a0,
                   0x27073c9+1,0x270742b+2,0x2707431+2,0x270743f+2,0x2707442+2,0x2707628+1,0x270764c):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',tool.END-tool.START-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))
if __name__=='__main__':unittest.main()
