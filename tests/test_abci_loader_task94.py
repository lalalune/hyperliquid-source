"""Controls for the byte-bound ABCI loader task-handoff evidence."""
import csv
import hashlib
import io
import json
import mmap
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / 'tools'))
import abci_loader_task94 as evidence


class Overlay:
    """A read-only, one-byte corruption without copying or modifying the capture."""
    def __init__(self, source, va, xor=1):
        self.source, self.va, self.xor = source, va, xor

    def read(self, va, size, executable=False):
        raw = bytearray(self.source.read(va,size,executable))
        if va <= self.va < va + size:
            raw[self.va-va] ^= self.xor
        return bytes(raw)

    def offset(self, va, size, executable=False):
        return self.source.offset(va,size,executable)


class LoaderTaskEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = evidence.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(),0,access=mmap.ACCESS_READ)
        cls.image = evidence.Image(cls.data)
        cls.output = evidence.collect(cls.data)
        cls.summary = json.loads(cls.output['summary.json'])
        cls.fdes = list(csv.DictReader(io.StringIO(cls.output['functions.tsv'].decode()),delimiter='\t'))

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def test_capture_and_counts(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),evidence.DIGEST)
        counts = self.summary['counts']
        self.assertEqual(counts, {'selected_fde_extents':26, 'fixed_windows':84,
                                  'direct_transfer_sites':30, 'conditional_branches':87, 'diagnostic_witnesses':18,
                                  'queue_field_correspondences':4, 'rip_references':3, 'tls_flow_witnesses':11, 'runtime_locations':1,
                                  'jump_tables':7, 'jump_table_entries':28,
                                  'selected_relocations':6, 'raw_transfer_candidates':14})
        self.assertEqual({x['object_displacement'] for x in self.summary['layout']['entries']},{0x216})
        self.assertEqual(self.summary['layout']['copied_future_bytes'],0x6368)
        self.assertEqual(self.summary['layout']['task_allocation_bytes'],0x80)
        self.assertEqual(self.summary['layout']['replacement_copy_bytes'],0x20)

    def test_identity_refuses_mutated_capture(self):
        altered = bytearray(self.data)
        altered[0] ^= 1
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            evidence.check_digest(altered)
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            evidence.check_digest(b'not the target')

    def test_fixed_windows_reject_mutations_at_each_stage(self):
        categories = ['entry_a_outer','entry_a_launch','launcher_select','allocate_a','poll_b_pre',
                      'poll_a_post','bridge_outcome','drop_variants','replace_slot',
                      'reader_gate','thunk_poll_a']
        pins = {row[0]:row for row in evidence.WINDOWS}
        for name in categories:
            with self.subTest(stage=name):
                row = pins[name]
                evidence.check_window(self.image,*row)
                bad = Overlay(self.image,row[2])
                with self.assertRaisesRegex(ValueError,'window mismatch'):
                    evidence.check_window(bad,*row)
        row = pins['entry_a_launch']
        with self.assertRaisesRegex(ValueError,'outside selected FDE'):
            evidence.check_window(self.image,row[0],row[1],row[1]-1,row[3])

    def test_each_branch_opcode_and_displacement_are_bound_to_a_window(self):
        for name,site,opcode,_ in evidence.BRANCHES:
            width = len(opcode) + (1 if len(opcode) == 1 else 4)
            row = next(w for w in evidence.WINDOWS
                       if w[2] <= site and site + width <= w[2] + len(bytes.fromhex(w[3])))
            for position in (site,site+len(opcode)):
                with self.subTest(branch=name,position=position), self.assertRaisesRegex(ValueError,'window mismatch'):
                    evidence.check_window(Overlay(self.image,position),*row)

    def test_fde_header_and_body_corruptions(self):
        row = next(r for r in self.fdes if r['start_va'] == hex(0x22a3d20))
        start = int(row['start_va'],16)
        fde = {'start':start,'end':int(row['end_va'],16),'fde':int(row['fde_va'],16),
               'cie':int(row['cie_va'],16),'lsda':None}
        header = {'start':start,'fde':fde['fde']}
        evidence.check_extent(self.image,start,fde,header)
        with self.assertRaisesRegex(ValueError,'extent mismatch'):
            evidence.check_extent(self.image,start,{**fde,'end':fde['end']+1},header)
        with self.assertRaisesRegex(ValueError,'header entry mismatch'):
            evidence.check_extent(self.image,start,fde,{**header,'fde':header['fde']+4})
        with self.assertRaisesRegex(ValueError,'body hash mismatch'):
            evidence.check_extent(Overlay(self.image,start),start,fde,header)

    def test_rip_reference_opcode_and_displacement_corruptions(self):
        for name,site,prefix,target in evidence.RIP_REFERENCES:
            raw = self.image.read(site,7,True)
            self.assertEqual(evidence.decode_rip_reference(raw,site,prefix,target),target)
            for offset in (0,3):
                altered = bytearray(raw)
                altered[offset] ^= 1
                with self.subTest(reference=name,offset=offset), self.assertRaises(ValueError):
                    evidence.decode_rip_reference(bytes(altered),site,prefix,target)

    def test_runtime_location_rejects_corrupt_path_coordinates_and_reference(self):
        records = evidence.collect_relocations(self.data,self.image.secs)
        loc = evidence.read_runtime_location(self.image,records)
        self.assertEqual((loc['path'],loc['line'],loc['column']),('src/hl_node.rs',5,47))
        for va in (0x289320d,0x56c6710,0x56c6718,0x56c671c,0x1e6593):
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                evidence.read_runtime_location(Overlay(self.image,va),records)
        invalid = [(slot,info,add+1 if slot == 0x56c6708 else add) for slot,info,add in records]
        with self.assertRaises(ValueError):
            evidence.read_runtime_location(self.image,invalid)

    def test_tls_pointer_flow_requires_matching_slots_and_copy_offsets(self):
        rows = evidence.derive_tls_handoff(self.image)
        values = {r['role']:r['value'] for r in rows}
        self.assertEqual(values['worker_tls_base'],values['launcher_tls_base'])
        self.assertEqual(values['tls_source_stack'],values['copy_source_stack'])
        self.assertEqual(values['tls_pointer_store'],values['launcher_slot_address'])
        self.assertEqual(values['worker_pointer_load'],'0x158')
        for va in (0x14c5c37,0x229ece3,0x14c60e1,0x14c6125,0x14c61bd,
                   0x14c61e3,0x14c625f,0x14c627f,0x14c6761,0x229eda9,0x288835d):
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                evidence.derive_tls_handoff(Overlay(self.image,va))

    def test_queue_field_relations_and_corruptions(self):
        rows = evidence.derive_queue_layout(self.image)
        self.assertEqual([(r['field'],r['queue_offset'],r['effective_offset']) for r in rows],
                         [('lock','0x0','0xb0'),('head','0x8','0xb8'),
                          ('tail','0x10','0xc0'),('count','0x20','0xd0')])
        for va in (0x4f6c8de,0x14c6768,0x4f6d0f5,0x4f721f5,0x4f6d120):
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                evidence.derive_queue_layout(Overlay(self.image,va))

    def test_diagnostic_binding_rejects_bytes_and_lengths(self):
        for row in evidence.DIAGNOSTICS:
            result = evidence.read_diagnostic(self.image,*row)
            target = int(result['literal_va'],16)
            with self.subTest(role=row[0]), self.assertRaisesRegex(ValueError,'diagnostic bytes mismatch'):
                evidence.read_diagnostic(Overlay(self.image,target),*row)
        exact = evidence.DIAGNOSTICS[0]
        with self.assertRaisesRegex(ValueError,'diagnostic length mismatch'):
            evidence.read_diagnostic(Overlay(self.image,exact[3]+1),*exact)

    def test_table_relocation_rejects_missing_duplicate_type_symbol_and_addend(self):
        rows = evidence.collect_relocations(self.data,self.image.secs)
        _,slot,target = evidence.TABLE_RELOCS[0]
        valid = [r for r in rows if r[0] == slot][0]
        self.assertEqual(evidence.check_relocation(rows,slot,target)[3],target)
        bad_sets = [[],[valid,valid],[(slot,7,target)],[(slot,(1 << 32) | 8,target)],
                    [(slot,8,target+1)]]
        for invalid in bad_sets:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                evidence.check_relocation(invalid,slot,target)

    def test_jump_tables_reject_changed_displacements_and_outside_target(self):
        for name,lea,owner,expected in evidence.TABLES:
            base = evidence.decode_lea(self.image.read(lea,7,True),lea)
            entries = evidence.parse_relative_table(self.image,base,owner,expected)
            self.assertEqual(tuple(x[2] for x in entries),expected)
            with self.subTest(table=name), self.assertRaisesRegex(ValueError,'entry mismatch'):
                evidence.parse_relative_table(Overlay(self.image,base),base,owner,expected)
        name,lea,owner,expected = evidence.TABLES[0]
        base = evidence.decode_lea(self.image.read(lea,7,True),lea)
        outside = evidence.OWNERS[owner][0]
        class Crafted:
            def read(self, va, size):
                self_outer.assertEqual(size,4)
                if va == base:
                    return struct.pack('<i',outside-base)
                return self_outer.image.read(va,size)
        self_outer = self
        with self.assertRaisesRegex(ValueError,'outside owner'):
            evidence.parse_relative_table(Crafted(),base,owner,(outside,)+expected[1:])

    def test_section_mapping_rejects_nobits_ambiguity_and_out_of_bounds(self):
        section = {'type':1,'flags':6,'address':0x1000,'offset':0x200,'size':0x10}
        self.assertEqual(evidence.address_to_offset([section],0x100f,1,executable=True),0x20f)
        with self.assertRaises(ValueError):
            evidence.address_to_offset([{**section,'type':8}],0x1000,1)
        with self.assertRaises(ValueError):
            evidence.address_to_offset([section,dict(section)],0x1000,1)
        with self.assertRaises(ValueError):
            evidence.address_to_offset([section],0x100f,2)
        with self.assertRaises(ValueError):
            evidence.address_to_offset([section],0xffffffffffffffff,2)
        with self.assertRaises(ValueError):
            evidence.address_to_offset([{**section,'flags':2}],0x1000,1,executable=True)

    def test_decoders_enforce_opcodes_and_signed_displacements(self):
        self.assertEqual(evidence.decode_transfer(bytes.fromhex('e8fbffffff'),0x100),0x100)
        self.assertEqual(evidence.decode_branch(bytes.fromhex('74fe'),0x100),0x100)
        self.assertEqual(evidence.decode_branch(bytes.fromhex('0f85faffffff'),0x100),0x100)
        self.assertEqual(evidence.decode_lea(bytes.fromhex('488d0df9ffffff'),0x100),0x100)
        for function,raw in [(evidence.decode_transfer,b'\x90\0\0\0\0'),
                             (evidence.decode_branch,b'\xeb\0'),
                             (evidence.decode_lea,b'\x48\x8d\x05\0\0\0\0')]:
            with self.subTest(function=function.__name__), self.assertRaises(ValueError):
                function(raw,0x100)

    def test_launcher_boundaries_and_priority(self):
        self.assertEqual(evidence.launch_case(False,2,evidence.MASK64,2),'allocation_failure')
        self.assertEqual(evidence.launch_case(True,2,evidence.MASK64,2),'tls_flag_2_cleanup')
        self.assertEqual(evidence.launch_case(True,1,0x7fffffffffffffff,2),'counter_limit_failure')
        self.assertEqual(evidence.launch_case(True,1,0x7ffffffffffffffe,2),'mode_2_cleanup')
        self.assertEqual(evidence.launch_case(True,1,0,0),'lane_b')
        self.assertEqual(evidence.launch_case(True,1,0,1),'lane_a')
        self.assertEqual(evidence.launch_case(True,0,0,3),'lane_a')
        for args in [(True,256,0,0),(True,1,-1,0),(True,1,0,1 << 64),(1,1,0,0)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                evidence.launch_case(*args)

    def test_initial_atomic_dispatch_exhaustive_low_byte(self):
        # Independent partitions of the observed compare/bit tests, assuming CAS succeeds.
        for word in range(256):
            kind,new,index = evidence.before_poll_case(word)
            if word % 8 < 4:
                self.assertEqual(kind,'missing_bit_2')
            elif word % 4 == 0:
                self.assertEqual((kind,index),('table',1 if word % 64 >= 32 else 0))
                self.assertEqual(new,(word // 8) * 8 + 1)
            elif word < 64:
                self.assertEqual(kind,'reference_underflow')
            else:
                self.assertEqual((kind,new,index),('table',word-64,3 if word < 128 else 2))
        self.assertEqual(evidence.before_poll_case(0xfffffffffffffffc),
                         ('table',0xfffffffffffffff9,1))
        self.assertEqual(evidence.before_poll_case(0x8000000000000005),
                         ('table',0x7fffffffffffffc5,2))
        with self.assertRaises(ValueError):
            evidence.before_poll_case(1 << 64)

    def test_nonzero_callback_atomic_dispatch_exhaustive_low_byte(self):
        for word in range(256):
            kind,new,index = evidence.after_poll_case(word)
            if word % 2 == 0:
                self.assertEqual(kind,'missing_bit_0')
            elif word % 64 >= 32:
                self.assertEqual((kind,new,index),('table',None,3))
            elif word % 8 >= 4:
                self.assertEqual((kind,index),('table',1))
                self.assertEqual(new,word-1+64)
            elif word < 64:
                self.assertEqual(kind,'reference_underflow')
            else:
                self.assertEqual((kind,new,index),('table',word-65,2 if word < 129 else 0))
        self.assertEqual(evidence.after_poll_case(0x8000000000000005)[0],'negative_word')
        self.assertEqual(evidence.after_poll_case(0x8000000000000025),('table',None,3))
        self.assertEqual(evidence.after_poll_case(0x8000000000000001)[2],0)
        with self.assertRaises(ValueError):
            evidence.after_poll_case(-1)

    def test_result_gate_transfer_and_negative_variants(self):
        payload = bytes(range(24))
        self.assertEqual(evidence.result_case(False,1,payload),('unchanged',None,None))
        self.assertEqual(evidence.result_case(True,1,payload),('copied',2,payload))
        for tag in (0,2,3,0xffffffff):
            self.assertEqual(evidence.result_case(True,tag,payload),('bad_task_tag',2,None))
        for payload in (b'',bytes(23),bytes(25)):
            with self.subTest(length=len(payload)), self.assertRaises(ValueError):
                evidence.result_case(True,1,payload)


if __name__ == '__main__':
    unittest.main()
