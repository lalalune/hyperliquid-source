import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from artifacts import ROOT,check
from u_path_sort_static import CONTROLS,LITERALS,RELATIVE,controls,read_va,relocations

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


    def test_decoded_path_guard_and_unsigned_sort_cutoffs(self):
        import subprocess
        text=subprocess.check_output(['objdump','-d','--start-address=0x13ca0e0','--stop-address=0x13ca362',str(ROOT/'artifacts/node/94/hl-node')],text=True)
        self.assertRegex(text,r'13ca105:.*cmpb.*\$0x2f,-0x1\(%rdx,%rcx,1\)')
        self.assertRegex(text,r'13ca10a:.*je.*13ca273')
        for address,cutoff,destination in [('13ca20b',2,'13ca28e'),('13ca28e',21,'13ca2f1')]:
            self.assertRegex(text,address+r':.*cmp.*\$0x'+format(cutoff,'x')+r',%r12')
            self.assertRegex(text,r'jae.*'+destination)
        self.assertRegex(text,r'13ca2c0:.*jae.*13ca2a9')
        self.assertRegex(text,r'13ca2db:.*jb.*13ca2c5')
        self.assertEqual(read_va(self.data,0x216df0,42)[1],b"assertion failed: !base_dir.ends_with('/')")

    def test_actual_location_layout_corruption(self):
        changed=bytearray(self.data);offset,_=read_va(changed,90598296+16,1);changed[offset]^=1
        with self.assertRaisesRegex(ValueError,'Location layout changed'):controls(changed)

if __name__=='__main__':unittest.main()
