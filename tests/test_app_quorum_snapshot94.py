import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import app_quorum_snapshot94 as q
from elf_index import unwind_index


class AppQuorumSnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = q.BINARY.read_bytes()
        cls.secs, _ = unwind_index(cls.data)
        cls.evidence = q.extract(cls.data)

    def altered(self, va, delta=1):
        data = bytearray(self.data)
        section = next(s for s in self.secs if s['type'] != 8 and
                       s['address'] <= va < s['address'] + s['size'])
        data[section['offset'] + va - section['address']] ^= delta
        return bytes(data)

    def test_target_identity_and_corruption(self):
        self.assertEqual(q.identity(self.data), q.TARGET)
        for wrong in (b'', self.altered(0x1eaa210)):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                q.identity(wrong)

    def test_selected_function_extents(self):
        functions = self.evidence['functions']
        self.assertEqual(len(functions), 18)
        rows = {x['start']:x for x in functions}
        self.assertEqual(rows['0x1eaa210']['end_exclusive'], '0x1eaa394')
        self.assertEqual(rows['0x24d94f0']['end_exclusive'], '0x24d9765')
        body = q.read_va(self.data,self.secs,0x1eaa210,0x184)
        self.assertEqual(hashlib.sha256(body).hexdigest(),q.BODIES[0x1eaa210])
        with self.assertRaisesRegex(ValueError, 'function bytes'):
            q.extract(self.altered(0x1eaa210), authenticate=False)

    def test_map_and_nested_layout(self):
        fields = self.evidence['fields']
        self.assertEqual([(r['name'],r['input_offset']) for r in fields[:3]],
                         [('tracker','0x0'),('quorum_app_hashes','0x30'),
                          ('highest_quorum_height','0x48')])
        self.assertEqual([r['name'] for r in fields[3:6]],['name','hsc','i'])
        self.assertEqual(fields[4]['handoff'],'empty sequence header')
        self.assertEqual([(r['name'],r['input_offset']) for r in fields[6:8]],
                         [('app_hash','0x0'),('hot_user_to_signature','0x20')])
        self.assertEqual([(r['name'],r['input_offset']) for r in fields[8:]],
                         [('r','0x0'),('s','0x20'),('v','0x40')])
        with self.assertRaisesRegex(ValueError, 'field changed'):
            q.extract(self.altered(0x3bfdd4),authenticate=False)

    def test_outer_key_classifier_negative_controls(self):
        keys, rows = q.compare_rows(self.data,self.secs)
        self.assertEqual(keys,[b'tracker',b'quorum_app_hashes',b'highest_quorum_height'])
        self.assertEqual(len(rows),45)
        mutations = 0
        for selector,key in enumerate(keys):
            self.assertEqual(q.classify(key,keys),selector)
            for i in range(len(key)):
                for replacement in range(256):
                    if replacement == key[i]:
                        continue
                    altered=key[:i]+bytes([replacement])+key[i+1:]
                    self.assertEqual(q.classify(altered,keys),3)
                    mutations += 1
            self.assertEqual(q.classify(key[:-1],keys),3)
            self.assertEqual(q.classify(key+b'_',keys),3)
        self.assertEqual(mutations,11475)

    def test_corrupt_comparison_or_branch(self):
        changed, _ = q.compare_rows(self.altered(0x16d1b69),self.secs)
        self.assertNotEqual(changed[0],b'tracker')
        self.assertEqual(q.classify(b'tracker',changed),3)
        with self.assertRaises(ValueError):
            q.compare_rows(self.altered(0x16d1b6a),self.secs)
        with self.assertRaises(ValueError):
            q.branch(self.altered(0x1eaa234,0x74),self.secs,0x1eaa234)

    def test_outer_dispatch_and_reader_paths(self):
        e=self.evidence
        self.assertEqual(e['dispatch']['targets'],
                         ['0x17ec5ea','0x17ec74e','0x17ec6ce','0x17ec71f'])
        self.assertEqual(e['nested_dispatch']['targets'],
                         ['0x16a9b4b','0x16a9ba3','0x16a9d2d'])
        self.assertEqual(e['nested_after_i_dispatch']['targets'],
                         ['0x16a9dda','0x16a9e32','0x16aa7b7'])
        routes={r['role']:r for r in e['branches']}
        self.assertEqual(routes['reader_map_first_duplicate']['target'],'0x17ecb5b')
        self.assertEqual(routes['reader_map_second_duplicate']['target'],'0x17eca76')
        self.assertEqual(routes['reader_map_third_duplicate']['target'],'0x17ecaea')
        with self.assertRaisesRegex(ValueError, 'dispatch table'):
            q.extract(self.altered(0x2e2afc),authenticate=False)
        with self.assertRaisesRegex(ValueError, 'nested tracker dispatch'):
            q.extract(self.altered(0x289700),authenticate=False)
        with self.assertRaisesRegex(ValueError, 'nested after-i dispatch'):
            q.extract(self.altered(0x289714),authenticate=False)

    def test_writer_reader_edges(self):
        calls={r['role']:r['target'] for r in self.evidence['calls']}
        self.assertEqual(calls['hash_capture_context'],'0x1eaa210')
        self.assertEqual(calls['outer_tracker'],'0x2326d20')
        self.assertEqual(calls['outer_rows'],'0x1e31c90')
        self.assertEqual(calls['tracker_hsc_empty_array'],'0x25a9bd0')
        self.assertEqual(calls['rows_reader_sequence_visitor'],'0x24d94f0')
        self.assertEqual(calls['rows_reader_item'],'0x1978910')
        self.assertEqual(calls['row_reader_quorum'],'0x188d500')
        self.assertEqual(calls['row_quorum'],'0x1ea9da0')
        self.assertEqual(calls['signature_loop'],'0x1ddc5b0')
        self.assertEqual(calls['signature_pair_value'],'0x1e10640')
        self.assertEqual(calls['signature_value_adapter'],'0x1eac430')
        self.assertEqual(calls['signature_s_value'],'0x219b770')
        with self.assertRaisesRegex(ValueError,'direct call'):
            q.call(self.altered(0x1eaa2b5,0xe8),self.secs,0x1eaa2b5)

    def test_outer_sequence_and_pair_branches(self):
        routes={r['role']:r for r in self.evidence['branches']}
        self.assertEqual(routes['reader_seq_zero']['target'],'0x17eb20f')
        self.assertEqual(routes['reader_seq_one']['fallthrough'],'0x17eaf7f')
        self.assertEqual(routes['reader_seq_two']['fallthrough'],'0x17eb00b')
        self.assertEqual(routes['reader_seq_three']['target'],'0x17eb51b')
        self.assertEqual(routes['row_first_absent']['target'],'0x19790f5')
        self.assertEqual(routes['row_second_absent']['target'],'0x197914f')
        self.assertEqual(routes['row_exact_two']['target'],'0x1979084')

    def test_type_descriptors_and_relocation_corruption(self):
        descriptors={d['role']:d for d in self.evidence['descriptors']}
        self.assertEqual(descriptors['tracker']['text'],'struct AppHashVoteTracker with 3 elements')
        self.assertEqual(descriptors['quorum']['text'],'struct QuorumAppHash with 2 elements')
        sec=next(s for s in self.secs if s['name']=='.rela.dyn')
        data=bytearray(self.data)
        for off in range(sec['offset'],sec['offset']+sec['size'],24):
            if struct.unpack_from('<Q',data,off)[0]==0x5687798:
                data[off+16] ^= 1
                break
        else:
            self.fail('tracker relocation absent')
        with self.assertRaises(ValueError):
            q.extract(bytes(data),authenticate=False)

    def test_diagnostics(self):
        diag={x['role']:x for x in self.evidence['diagnostics']}
        self.assertEqual(diag['missing_tracker']['name'],'tracker')
        self.assertEqual(diag['missing_rows']['name'],'quorum_app_hashes')
        self.assertEqual(diag['missing_height']['name'],'highest_quorum_height')
        self.assertEqual(diag['duplicate_tracker']['name'],'tracker')
        self.assertEqual(diag['duplicate_rows']['name'],'quorum_app_hashes')
        self.assertEqual(diag['duplicate_height']['name'],'highest_quorum_height')
        self.assertEqual(diag['nested_duplicate_i']['name'],'i')
        self.assertEqual(diag['nested_duplicate_hsc']['name'],'hsc')
        self.assertEqual(diag['quorum_missing_hash']['name'],'app_hash')
        self.assertEqual(diag['quorum_duplicate_hash']['name'],'app_hash')
        self.assertEqual(diag['quorum_missing_signatures']['name'],'hot_user_to_signature')
        self.assertEqual(diag['quorum_duplicate_signatures']['name'],'hot_user_to_signature')

    def test_capacity_boundary_and_invalid_input(self):
        cap=self.evidence['reservation']['cap']
        stride=self.evidence['reservation']['stride']
        self.assertEqual((cap,stride),(16384,64))
        self.assertEqual(q.reservation(0,cap,stride),(0,0))
        self.assertEqual(q.reservation(cap-1,cap,stride),(16383,1048512))
        self.assertEqual(q.reservation(cap,cap,stride),(16384,1048576))
        self.assertEqual(q.reservation(cap+1,cap,stride),(16384,1048576))
        self.assertEqual(q.reservation(0xffffffff,cap,stride),(16384,1048576))
        for count in (-1,0x100000000):
            with self.assertRaises(ValueError):
                q.reservation(count,cap,stride)
        with self.assertRaisesRegex(ValueError,'function bytes'):
            q.extract(self.altered(0x24d950b),authenticate=False)

    def test_file_backed_address_controls(self):
        self.assertEqual(q.read_va(self.data,self.secs,0x1eaa210,1),b'\x41')
        for va in (-1,0xffffffffffffffff):
            with self.assertRaises(ValueError):
                q.read_va(self.data,self.secs,va,1)
        bss=next(s for s in self.secs if s['name']=='.bss')
        with self.assertRaises(ValueError):
            q.read_va(self.data,self.secs,bss['address'],1)

    def test_repeated_generation_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as base:
            first=Path(base)/'a'; second=Path(base)/'b'
            q.generate(self.data,first)
            q.generate(self.data,second)
            names=sorted(p.name for p in first.iterdir())
            self.assertEqual(names,sorted(p.name for p in second.iterdir()))
            self.assertEqual(len(names),7)
            for name in names:
                self.assertEqual((first/name).read_bytes(),(second/name).read_bytes(),name)


if __name__ == '__main__':
    unittest.main()
