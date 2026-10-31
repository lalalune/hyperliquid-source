"""RE-002: validate program-header layout using authenticated target bytes."""
import hashlib,json,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from build_provenance import program_headers

EXPECTED={'artifacts/node/94/hl-node': [12, '110099522c92ccdeb17ed326ecfad282c90fb1b41e874b65b1a4440e223efda1'], 'artifacts/node/115/hl-node': [12, '6efa2bb10db7b1c44627f2ae0e68145333dd88374fa4e2be7a15502be2cff063'], 'artifacts/visor/captured/hl-visor': [12, '855ddeea0725be932707f48e5619ca796a277314f33d46b7f1e9091aab41e752']}

class ProgramHeaderBounds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f':
            raise AssertionError('node94 fixture identity')

    def test_zero_short_or_wrong_stride_cannot_manufacture_segment_facts(self):
        for stride in (0,1,55,57):
            with self.subTest(stride=stride):
                data=bytearray(self.data);struct.pack_into('<H',data,54,stride)
                with self.assertRaises(ValueError):program_headers(data)

    def test_header_overlap_and_truncation_have_bounded_admission(self):
        for offset in (0,1,63,len(self.data)-1):
            with self.subTest(offset=offset):
                data=bytearray(self.data);struct.pack_into('<Q',data,32,offset)
                with self.assertRaises(ValueError):program_headers(data)

    def test_all_three_authenticated_target_tables_keep_exact_records(self):
        manifest=json.loads((ROOT/'provenance/artifacts.json').read_text())['files']
        for name in ('artifacts/node/94/hl-node','artifacts/node/115/hl-node','artifacts/visor/captured/hl-visor'):
            with self.subTest(target=name):
                data=(ROOT/name).read_bytes();item=next(item for item in manifest if item['path']==name)
                self.assertEqual(hashlib.sha256(data).hexdigest(),item['sha256'])
                rows=program_headers(data)
                count,digest=EXPECTED[name]
                self.assertEqual(len(rows),count)
                self.assertEqual(hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest(),digest)

    def test_section_only_inputs_without_program_headers_remain_supported(self):
        data=bytearray(64)
        self.assertEqual(program_headers(data),[])

if __name__=='__main__':unittest.main()
