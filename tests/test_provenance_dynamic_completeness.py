"""RE-002: a partial dynamic array cannot establish complete exact facts."""
import hashlib,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from build_provenance import derive
from elf_index import sections

class DynamicCompleteness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f':
            raise AssertionError('node94 identity')
        secs=sections(cls.data)
        cls.index=next(i for i,s in enumerate(secs) if s['name']=='.dynamic')
        cls.dyn=secs[cls.index]
        cls.null=next(i for i in range(0,cls.dyn['size'],16)
                      if struct.unpack_from('<q',cls.data,cls.dyn['offset']+i)[0]==0)

    def resized(self,size):
        data=bytearray(self.data)
        shoff=struct.unpack_from('<Q',data,40)[0]
        stride=struct.unpack_from('<H',data,58)[0]
        struct.pack_into('<Q',data,shoff+stride*self.index+32,size)
        return data

    def test_unterminated_array_is_not_complete_provenance(self):
        for size in (0,16,self.null):
            with self.subTest(size=size):
                with self.assertRaisesRegex(ValueError,'dynamic|DT_NULL'):
                    derive(self.resized(size))

    def test_partial_record_is_rejected(self):
        for size in (1,15,self.null+15):
            with self.subTest(size=size):
                with self.assertRaisesRegex(ValueError,'dynamic|DT_NULL'):
                    derive(self.resized(size))

    def test_complete_array_ending_at_dt_null_preserves_all_facts(self):
        self.assertEqual(derive(self.resized(self.null+16)),derive(self.data))

if __name__=='__main__':unittest.main()
