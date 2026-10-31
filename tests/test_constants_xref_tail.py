"""RE-015: every complete terminal RIP-relative operand pattern is scanned."""
import hashlib,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from constants_scan import section,xrefs
from bridge_inventory import Mapping,rip_relative_xrefs

class XrefTail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f':
            raise AssertionError('node94 identity')
        # Packet site is the opcode; the complete 7-byte encoding starts one byte earlier.
        cls.va=0x164fbae;cls.off=0x164ebae;cls.target=0x1ef5f5
        if cls.data[cls.off:cls.off+7].hex()!='488d3540fab9fe':
            raise AssertionError('original packet bytes')

    def view(self,size):
        return dict(name='.text',address=self.va,offset=self.off,size=size)

    def test_complete_terminal_operand_is_included(self):
        for size in (7,8,9):
            with self.subTest(size=size):
                self.assertEqual(xrefs(self.data,self.view(size),[self.target]),
                                 {self.target:[(self.va+1,'488d3540fab9fe')]})

    def test_incomplete_terminal_operand_is_not_read_past_section(self):
        for size in range(7):
            with self.subTest(size=size):
                self.assertEqual(xrefs(self.data,self.view(size),[self.target]),{self.target:[]})

    def test_retained_whole_text_keeps_original_reference(self):
        self.assertEqual(xrefs(self.data,section(self.data,'.text'),[self.target]),
                         {self.target:[(self.va+1,'488d3540fab9fe')]})

    def test_bridge_scanner_includes_complete_terminal_displacement(self):
        for size in (7,8,9):
            with self.subTest(size=size):
                mapping=Mapping([(self.off,self.va,size,1)])
                rows=rip_relative_xrefs(self.data,mapping,self.target)
                self.assertEqual([(r['instruction_va'],r['insn_bytes']) for r in rows],
                                 [(self.va,'488d3540fab9fe')])

    def test_bridge_scanner_excludes_incomplete_displacement(self):
        for size in range(7):
            with self.subTest(size=size):
                self.assertEqual(rip_relative_xrefs(self.data,
                                 Mapping([(self.off,self.va,size,1)]),self.target),[])

if __name__=='__main__':unittest.main()
