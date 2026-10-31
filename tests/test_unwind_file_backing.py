"""RE-001: corrupt only section types in the authenticated node #94 image."""
import hashlib,json,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections,unwind_index

class UnwindFileBackingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.digest='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
        if hashlib.sha256(cls.data).hexdigest()!=cls.digest:
            raise AssertionError('node94 fixture identity')
        cls.sections=sections(cls.data)

    def test_nobits_sections_cannot_supply_unwind_or_code_bytes(self):
        offset=struct.unpack_from('<Q',self.data,40)[0]
        stride=struct.unpack_from('<H',self.data,58)[0]
        for name in ('.eh_frame_hdr','.eh_frame','.text'):
            with self.subTest(section=name):
                index=next(i for i,row in enumerate(self.sections) if row['name']==name)
                corrupt=bytearray(self.data)
                struct.pack_into('<I',corrupt,offset+index*stride+4,8)
                with self.assertRaises(ValueError):unwind_index(corrupt)

    def test_authentic_unwind_count_and_capture_remain_unchanged(self):
        inventory=json.loads((ROOT/'research/imported/hl-node-94.inventory.json').read_text())
        _sections,rows=unwind_index(self.data)
        self.assertEqual(len(rows),inventory['fde_count_eh_frame_hdr'])
        self.assertEqual(hashlib.sha256((ROOT/'artifacts/node/94/hl-node').read_bytes()).hexdigest(),self.digest)

if __name__=='__main__':unittest.main()
