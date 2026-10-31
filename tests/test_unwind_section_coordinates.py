"""RE-001: unwind bounds follow section coordinates, never name uniqueness."""
import hashlib,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections,unwind_index

class UnwindCoordinates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f':
            raise AssertionError('node94 fixture identity')
        cls.secs,cls.original=unwind_index(cls.data)
        cls.offset=struct.unpack_from('<Q',cls.data,40)[0]
        cls.stride=struct.unpack_from('<H',cls.data,58)[0]
        cls.text=next(i for i,s in enumerate(cls.secs) if s['name']=='.text')
        cls.init=next(i for i,s in enumerate(cls.secs) if s['name']=='.init')

    def test_duplicate_names_cannot_change_bounds_without_changing_ranges(self):
        data=bytearray(self.data)
        text=self.offset+self.text*self.stride;init=self.offset+self.init*self.stride
        name=struct.unpack_from('<I',data,text)[0]
        struct.pack_into('<I',data,init,name)
        # Reorder the two headers so a name-only lookup sees .init's range first.
        first=bytes(data[text:text+self.stride]);second=bytes(data[init:init+self.stride])
        data[text:text+self.stride]=second;data[init:init+self.stride]=first
        _sections,rows=unwind_index(data)
        self.assertEqual(rows,self.original,'name aliases/header order cannot enlarge a code-section bound')

    def test_overlapping_executable_coordinates_are_not_guessed(self):
        data=bytearray(self.data)
        # Move only .init metadata over the first .text unwind start.
        struct.pack_into('<Q',data,self.offset+self.init*self.stride+16,self.original[0]['start'])
        with self.assertRaisesRegex(ValueError,'ambiguous|Ambiguous'):
            unwind_index(data)

    def test_original_last_bound_stays_in_its_actual_section(self):
        text=self.secs[self.text];last=self.original[-1]
        self.assertLessEqual(last['next_index_upper_bound'],text['address']+text['size'])
        self.assertEqual(len(self.original),121299)

if __name__=='__main__':unittest.main()
