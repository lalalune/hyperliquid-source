"""Actual constructor bytes and bounded decoded state/guard obligations."""
import json,re,struct,subprocess,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from artifacts import ROOT,check
from daily_constructor_static import CONTROLS,LITERALS,RELATIVE,controls,read_va,relocations

class DailyConstructorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target=ROOT/'artifacts/node/94/hl-node'
        identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']if i['path']=='artifacts/node/94/hl-node')
        check(cls.target,identity);cls.data=cls.target.read_bytes()

    def test_actual_baseline(self):
        controls(self.data);self.assertEqual(len(relocations(self.data)),6)

    def test_actual_instruction_corruptions(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'instruction changed'):controls(changed)

    def test_actual_literals(self):
        for va in LITERALS:
            changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
            with self.assertRaisesRegex(ValueError,'literal changed'):controls(changed)

    def test_actual_relocation_retargets(self):
        for slot,target in RELATIVE.items():
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);offset=changed.find(struct.pack('<QQq',slot,8,target));self.assertGreaterEqual(offset,0)
                changed[offset+16]^=1
                with self.assertRaisesRegex(ValueError,'relocation changed'):relocations(changed)

    def test_decoded_edge_byte_guard(self):
        raw=read_va(self.data,0x1402086,27)[1]
        self.assertEqual(raw[:5],bytes.fromhex('4d85ff7416'))
        self.assertEqual(0x140208b+raw[4],0x14020a1)
        self.assertEqual(raw[5:11],bytes.fromhex('43807c3eff2f'))
        self.assertEqual(raw[17:21],bytes.fromhex('41803e2f'))
        self.assertEqual(0x1402097+struct.unpack_from('<i',raw,13)[0],0x14022da)
        self.assertEqual(0x14020a1+struct.unpack_from('<i',raw,23)[0],0x14022da)
        self.assertEqual([value for value in range(256)if value==raw[10]],[47])
        self.assertEqual([value for value in range(256)if value==raw[20]],[47])
        # Local byte predicate only, not filesystem/path normalization.
        def rejected(value):return bool(value)and(value[0]==raw[20]or value[-1]==raw[10])
        for value,want in [(b'',False),(b'a',False),(b'/',True),(b'/a',True),(b'a/',True),(b'a/b',False),(b'\\a',False)]:
            self.assertEqual(rejected(value),want)

    def test_decoded_normal_return_field_writes(self):
        text=subprocess.check_output(['objdump','-d','--start-address=0x140224d','--stop-address=0x14022c7',str(self.target)],text=True)
        stores=[]
        for line in text.splitlines():
            match=re.search(r'\b(movups|movb|mov)\s+([^,]+),(?:(0x[0-9a-f]+))?\(%rbx\)',line)
            if not match:continue
            mnemonic,source,offset=match.groups();offset=int(offset or '0',16)
            size=16 if mnemonic=='movups' else 1 if mnemonic=='movb' else 4 if source in ('%eax','%ebp') else 8
            stores.append((offset,size))
        expected=[(0x38,16),(0x28,16),(0x18,16),(0x48,16),(0x58,16),(0x68,16),(0x78,16),(0x88,16),(0,8),(8,8),(0x10,8),(0x98,4),(0x9c,8),(0xa4,4),(0xa8,1),(0xaa,1)]
        self.assertEqual(stores,expected)
        written={offset+i for offset,size in stores for i in range(size)}
        self.assertEqual(len(written),170);self.assertNotIn(0xa9,written)
        self.assertEqual(read_va(self.data,0x14022b9,14)[1],bytes.fromhex('c683a800000000c683aa00000000'))
        self.assertEqual(read_va(self.data,0x14022c7,3)[1],bytes.fromhex('4889d8'))
        # Source count11 and exact helper identities are real decoded operands.
        self.assertEqual(read_va(self.data,0x1402119,5)[1],bytes.fromhex('ba0b000000'))
        self.assertEqual(read_va(self.data,0x21845c,11)[1],b'daily_liner')

if __name__=='__main__':unittest.main()
