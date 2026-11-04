"""Controls for the actual deadline evidence binding, not socket/runtime mocks."""
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-012-greeting-deadline-115'
spec=importlib.util.spec_from_file_location('greeting_deadline_115',PACKET/'collect.py')
collector=importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

class DeadlineBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/115/hl-node').read_bytes()
        cls.sections=sections(cls.data)
        _,cls.fdes=eh_frame_records(cls.data,cls.sections)
        cls.image=collector.Image(cls.data,cls.sections,cls.fdes)

    def test_actual_route_and_frozen_native_replay(self):
        actual=collector.collect(ROOT,PACKET)
        import json
        self.assertEqual(actual,json.loads((PACKET/'records.json').read_text()))

    def test_actual_operand_and_data_controls(self):
        # Mutations bypass the outer digest guard to exercise the actual binder.
        mutations=[('caller flag',0x2b68481,1),('provided seconds',0x2b6848d,0x34),
                   ('caller state',0x2b684aa,1),('call target',0x2b684b6,0xd7),
                   ('selector field',0x2b7b293,0x59),('selector direction',0x2b7b295,0x74),
                   ('default RIP',0x2b7b29b,0xd2),('default seconds',0x459b76,0x4e),
                   ('initial dispatch',0x604cbc,self.image.read(0x604cbc,1)[0]^1),
                   ('conversion arithmetic',0x15edb0c,1)]
        for name,va,value in mutations:
            with self.subTest(name=name):
                changed=bytearray(self.data)
                changed[self.image.offset(va,1)]=value
                image=collector.Image(changed,self.sections,self.fdes)
                with self.assertRaises(ValueError):
                    collector.bindings(image)

    def test_real_duplicate_relocation_writer_is_rejected(self):
        changed=bytearray(self.data)
        section=next(s for s in self.sections if s['name']=='.rela.dyn')
        positions=list(range(section['offset'],section['offset']+section['size'],24))
        original=next(p for p in positions if struct.unpack_from('<Q',changed,p)[0]==0x64e0f70)
        other=next(p for p in positions if p!=original)
        changed[other:other+24]=changed[original:original+24]
        with self.assertRaisesRegex(ValueError,'not unique/correct'):
            collector.bindings(collector.Image(changed,self.sections,self.fdes))

    def test_truncated_native_export_is_rejected(self):
        original=PACKET/'native/conversion.gnu.objdump'
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'truncated.objdump'
            path.write_bytes(original.read_bytes().split(b' 15edb80:')[0])
            with self.assertRaisesRegex(ValueError,'Incomplete native interval'):
                collector.native_rows(path,self.image,0x15ed960,0x15edb81)

if __name__=='__main__':
    unittest.main()
