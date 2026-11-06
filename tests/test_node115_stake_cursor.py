"""Original cursor/data observations, including actual C5 cleanup CALL/RET."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-001-stake-cursor-115'
sys.path.insert(0,str(PACKET));sys.path.insert(0,str(ROOT/'tools'))
spec=importlib.util.spec_from_file_location('stake_cursor_native115',PACKET/'native.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)

class StakeCursorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im=n.Image()
        if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:
            cls.im.close();raise ValueError('wrong115target')
        cls.proof=json.loads((PACKET/'FREEZE.json').read_text())
    @classmethod
    def tearDownClass(cls):cls.im.close()

    def test_original_streams_and_actual_cleanup_counts(self):
        inputs,expected,seen,calls=n.corpus(self.im)
        self.assertEqual(len(set(inputs.splitlines())),1403)
        self.assertEqual(hashlib.sha256(inputs).hexdigest(),self.proof['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(),self.proof['expected_sha256'])
        self.assertEqual(sorted(seen),self.proof['visited_addresses']);self.assertEqual(len(seen),86)
        self.assertEqual(calls,800);self.assertEqual(calls,self.proof['actual_cleanup_calls'])

    def test_cursor_stores_terminal_and_helper_boundaries(self):
        for row,expected in [((0,0,0,0,0,0x1a2),'E:1:1:418:H:0:1:0:'+n.PAYLOAD.hex()),((0,4,0,0,0,0x1a2),'E:4:1:418:T:4'),((0,n.cpu.U64,0,0,0,0x1a2),f'E:{n.cpu.U64}:0:418:D'),((0,0,n.cpu.U64,0,0,0x1a2),'E:0:0:418:D')]:
            with self.subTest(row=row):self.assertEqual(n.evaluate(self.im,row)[0],expected)

    def test_actual_C5_calls_and_active_output_normalization(self):
        for row,expected,calls in [((1,0,1,0,0,0x1a2),'P:418:0:Y:100000',1),((1,0,0,0,0,0xc5),'P:197:0:Y:0',1),((1,0,n.cpu.U64,1,0,0xc5),'P:197:1:F',1),((1,0,n.cpu.U64,1,0,0x1a2),'P:197:1:F',0),((1,0,n.cpu.U64,1,0,0),'P:0:0:X',0)]:
            with self.subTest(row=row):
                value,seen,count=n.evaluate(self.im,row);self.assertEqual(value,expected);self.assertEqual(count,calls)
                if calls:self.assertIn(n.CLEANUP,seen);self.assertIn(0x29ec566,seen)
        with self.assertRaisesRegex(ValueError,'forbidden'):n.Machine(self.im).call(0x2c58c70,0x294cf34)

    def test_observed_columns_aliases_and_no_native_range_invention(self):
        offsets=struct.unpack('<4i',self.im.view.read(n.TABLE,16))
        self.assertEqual([n.TABLE+off for off in offsets],n.ROWS)
        self.assertEqual(n.ROWS[0],n.ROWS[3])
        for row in self.proof['observed_rows']:
            self.assertEqual(list(struct.unpack('<4Q',self.im.view.read(int(row['va'],16),32))),row['columns'])
        rel=struct.unpack('<i',self.im.view.read(n.DROP_SLOT,4))[0]
        self.assertEqual(n.DROP_TABLE+rel,0x29ec55f)
        self.assertIsNone(self.im.read_only(n.ROWS[0]+32))
        with self.assertRaisesRegex(ValueError,'domain'):n.evaluate(self.im,(1,0,1,0,4,0x1a2))
        with self.assertRaisesRegex(ValueError,'domain'):n.evaluate(self.im,(1,4,1,0,0,0x1a2))

    def test_real_output_controls_and_separate_cleanup_rejections(self):
        controls=json.loads((PACKET/'native-controls.json').read_text());self.assertEqual(len(controls),18)
        rejected=json.loads((PACKET/'cleanup-negative-controls.json').read_text());self.assertEqual(len(rejected),2)
        for c in controls+rejected:
            with self.subTest(name=c['name']):
                changed=n.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
                try:
                    a=int(c['va'],16);off=changed.view.offset(a)
                    self.assertEqual(changed.data[off],int(c['original_byte'],16))
                    changed.data[off]=int(c['changed_byte'],16);row=tuple(c['input'])
                    if 'rejection' in c:
                        with self.assertRaises((ValueError,n.cpu.ToolError)) as result:n.evaluate(changed,row)
                        self.assertEqual(str(result.exception),c['rejection'])
                    else:
                        self.assertEqual(n.evaluate(self.im,row)[0],c['original']);self.assertEqual(n.evaluate(changed,row)[0],c['changed']);self.assertNotEqual(c['original'],c['changed'])
                finally:changed.close()

    def test_complete_owners_unwind_and_selected_decode(self):
        import capstone
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);selected=[]
        self.assertEqual(len(self.proof['owners']),2)
        self.assertEqual(sum(o['bytes'] for o in self.proof['owners']),758)
        for owner in self.proof['owners']:
            lo,hi=int(owner['start'],16),int(owner['end'],16);self.assertEqual(self.im.view.fde(lo),(lo,hi))
            body=self.im.view.read(lo,hi-lo);self.assertEqual(hashlib.sha256(body).hexdigest(),owner['sha256'])
            rows=list(cs.disasm(body,lo));self.assertEqual(sum(i.size for i in rows),hi-lo);self.assertEqual(len(rows),owner['instructions'])
            selected.extend(i for i in rows if any(a<=i.address<b for a,b in n.RANGES))
            for r in owner['unwind'].values():
                raw=bytes.fromhex(r['raw_hex']);self.assertEqual(self.im.view.read(int(r['va'],16),len(raw)),raw)
        self.assertEqual(sum(i.size for i in selected),298);self.assertEqual(len(selected),86)
        self.assertEqual({i.address for i in selected},set(self.proof['visited_addresses']))
        for i in selected:self.assertEqual(self.im.fetch(i.address).size,i.size)

    def test_owned_builds_bind_source_and_sealed_original(self):
        report=json.loads((PACKET/'rust-results.json').read_text());self.assertEqual(report['target_sha256'],n.SHA)
        for file,key in [('src/node115-stake-cursor/lib.rs','source_sha256'),('src/node115-stake-cursor/input_only_driver.rs','driver_sha256'),('research/work-items/RE-001-stake-cursor-115/client_fixture.rs','fixture_sha256')]:
            self.assertEqual(hashlib.sha256((ROOT/file).read_bytes()).hexdigest(),report[key])
        self.assertEqual(report['input_sha256'],self.proof['input_sha256']);self.assertEqual(report['expected_sha256'],self.proof['expected_sha256'])
        original=[r for r in report['runs'] if r['variant']=='original'];self.assertEqual([r['opt'] for r in original],['0','3'])
        self.assertTrue(all(r['mismatches']==0 and r['smoke_exit']==0 and r['rows']==1403 for r in original))
        mutated=[r for r in report['runs'] if r['variant']!='original'];self.assertEqual(len(mutated),13)
        self.assertTrue(all(r['mismatches']>0 and r['smoke_exit']==101 and r['rows']==1403 for r in mutated))
        self.assertFalse(report['captured_process_executed']);self.assertFalse(report['ABI_or_whole_caller_equivalence'])

if __name__=='__main__':unittest.main()
