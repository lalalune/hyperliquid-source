"""RE-002: section-attributed facts require actual section file contents."""
import hashlib,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from build_provenance import derive
from elf_index import sections

class ProvenanceBacking(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f':
            raise AssertionError('node94 fixture identity')
        cls.secs=sections(cls.data)

    def test_nobits_cannot_supply_comment_interpreter_or_dynamic_facts(self):
        offset=struct.unpack_from('<Q',self.data,40)[0]
        stride=struct.unpack_from('<H',self.data,58)[0]
        for name in ('.comment','.interp','.dynamic','.dynstr'):
            with self.subTest(section=name):
                index=next(i for i,s in enumerate(self.secs) if s['name']==name)
                data=bytearray(self.data)
                struct.pack_into('<I',data,offset+stride*index+4,8)
                with self.assertRaisesRegex(ValueError,'NOBITS|file-backed'):
                    derive(data)

if __name__=='__main__':unittest.main()
