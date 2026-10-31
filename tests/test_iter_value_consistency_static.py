import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from artifacts import ROOT,check
from iter_value_consistency_static import CONTROLS,LITERALS,RELATIVE,controls,read_va,relocations

class PacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target=ROOT/'artifacts/node/94/hl-node'
        identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']if i['path']=='artifacts/node/94/hl-node')
        check(target,identity);cls.data=target.read_bytes()

    def test_actual_control_baseline(self):
        controls(self.data);self.assertEqual(len(relocations(self.data)),len(RELATIVE))

    def test_actual_instruction_corruptions(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'instruction changed'):controls(changed)

    def test_actual_literal_corruptions(self):
        for va in LITERALS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'literal changed'):controls(changed)

    def test_actual_relocation_retargets(self):
        for slot,target in RELATIVE.items():
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);offset=changed.find(struct.pack('<QQq',slot,8,target))
                self.assertGreaterEqual(offset,0);changed[offset+16]^=1
                with self.assertRaisesRegex(ValueError,'relocation changed'):relocations(changed)


    def test_decoded_compare_widths_tags_and_assertion_edge(self):
        import subprocess
        text=subprocess.check_output(['objdump','-d','--start-address=0x33690c0','--stop-address=0x33694fc',str(ROOT/'artifacts/node/94/hl-node')],text=True)
        self.assertRegex(text,r'3369375:.*movdqu.*\(%rdx\),%xmm1')
        self.assertRegex(text,r'3369384:.*movd.*0x10\(%rdx\),%xmm2')
        self.assertRegex(text,r'336939d:.*jne.*3369190')
        self.assertRegex(text,r'3369408:.*movdqu.*0x61\(%rsp\),%xmm2')
        self.assertRegex(text,r'3369412:.*movdqu.*0x71\(%rsp\),%xmm0')
        self.assertRegex(text,r'336942c:.*jne.*33694b2')
        for address,tag in [('33690d3','97'),('3369462','2a'),('3369498','186')]:
            self.assertRegex(text,address+r':.*mov.*\$0x'+tag+r',%ax')
        self.assertRegex(text,r'336949c:.*mov.*%ax,\(%rdi\)')

    def test_actual_location_layout_corruption(self):
        changed=bytearray(self.data);offset,_=read_va(changed,91135544+16,1);changed[offset]^=1
        with self.assertRaisesRegex(ValueError,'Location layout changed'):controls(changed)

if __name__=='__main__':unittest.main()
