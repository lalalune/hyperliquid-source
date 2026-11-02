"""Target-grounded controls for the RE-015 checkpoint policy record."""
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_evm_prune_policy as subject

PACKET = subject.ROOT / 'research/work-items/RE-015-evm-prune-policy-115'


def rows(path):
    with path.open(encoding='utf-8', newline='') as source:
        return list(csv.DictReader(source, delimiter='\t'))


class CheckpointPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing or mismatched binary is a hard failure, never a skip.
        cls.data = subject.TARGET.read_bytes()
        cls.image = subject.Image(cls.data)
        cls.params = subject.parameters(cls.image)
        cls.frames = subject.frame_records(cls.image)
        cls.image.relocation(0x64e0918)

    def corrupt_read(self, va, offset=0):
        original = self.image.read
        def changed(address, size, executable=False):
            b=original(address,size,executable)
            if address==va:
                buf=bytearray(b)
                buf[offset]^=1
                return bytes(buf)
            return b
        return mock.patch.object(self.image,'read',side_effect=changed)

    def test_target_identity_and_selected_extents(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),subject.SHA115)
        self.assertEqual((len(self.frames),sum(f['end']-f['start'] for f in self.frames)),(14,14880))
        self.assertEqual(len({f['start'] for f in self.frames}),len(self.frames))
        self.assertTrue(all(f['end']>f['start'] for f in self.frames))

    def test_full_regeneration_matches_retained_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary)
            report=subject.collect(self.image,out)
            self.assertEqual(report['selected_branch_count'],116)
            self.assertEqual(report['selected_call_count'],46)
            self.assertEqual(report['selected_exception_site_count'],103)
            self.assertEqual(report['selected_window_count'],49)
            self.assertEqual(report['selected_relocation_count'],28)
            self.assertEqual(report['selected_pool_count'],15)
            self.assertEqual(len(list(out.iterdir())),19)
            for path in out.iterdir():
                self.assertEqual(path.read_bytes(),(PACKET/path.name).read_bytes(),path.name)

    def test_wrong_artifact_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):
            subject.Image(self.data[:4096])
        with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):
            subject.Image(self.data,'0'*64)
        with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):
            subject.compare_old(self.image,b'not the historical artifact')

    def test_name_gate_is_exact_for_every_u8(self):
        self.assertEqual([x for x in range(256) if subject.name_suppressed(x,self.params)],[19,20])
        for byte in range(256):
            self.assertEqual(subject.name_suppressed(byte,self.params),byte in (19,20))
        self.assertEqual(self.params['name_diagnostic_bound'],79)

    def test_name_gate_rejects_nonbyte_and_boolean_inputs(self):
        for bad in (-1,256,True,1.0,'19',None):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                subject.name_suppressed(bad,self.params)

    def test_name_descriptors_and_shift_neighbors(self):
        expected={18:'Ee',19:'SoloTestnet',20:'SoloMainnet',21:'LockerTestnet',33:'NvTestnet',34:'NvTestnet2'}
        observed={}
        for tag in expected:
            _,_,text,_=self.image.descriptor(0x63f8788+16*tag)
            observed[tag]=text.decode('ascii')
        self.assertEqual(observed,expected)
        self.assertEqual(subject.name_suppressed(146,self.params),False)
        self.assertEqual(subject.name_suppressed(147,self.params),False)

    def test_gate_instruction_corruption_fails(self):
        with self.corrupt_read(0x156413f,1), self.assertRaisesRegex(ValueError,'bytes changed'):
            subject.parameters(self.image)
        with self.corrupt_read(0x1564141,1), self.assertRaisesRegex(ValueError,'bytes changed'):
            subject.parameters(self.image)
        with self.corrupt_read(0x1564143,1), self.assertRaisesRegex(ValueError,'bytes changed'):
            subject.parameters(self.image)

    def test_keep_and_flow_corruption_fail(self):
        for site,index in [(0x4d98d51,1),(0x4d98c82,4),(0x4d98c8e,1),
                           (0x4d98c99,3),(0x4d98ebf,1),(0x4d98ed4,1),
                           (0x4d98ee6,1),(0x4d98d4c,1),(0x4d98d62,2),
                           (0x4d98df1,1),(0x4d98e7a,11),(0x2dd4fdb,4),
                           (0x3d5de85,4)]:
            with self.subTest(site=site), self.corrupt_read(site,index), self.assertRaisesRegex(ValueError,'bytes changed'):
                subject.parameters(self.image)

    def test_decimal_component_controls(self):
        samples={b'':None,b'+':None,b'-':None,b'0':0,b'+0':0,b'000':0,b'+123':123,
                 b'-1':None,b'1x':None,b' 1':None,b'\xff':None,
                 b'18446744073709551615':(1<<64)-1,b'18446744073709551616':None,
                 b'000000000000000000001':1,b'+18446744073709551615':(1<<64)-1,
                 b'9999999999999999':9999999999999999}
        for raw,want in samples.items():
            with self.subTest(raw=raw): self.assertEqual(subject.parse_component(raw),want)
        with self.assertRaises(ValueError): subject.parse_component('1')

    def test_all_two_byte_components_against_independent_oracle(self):
        count=0
        for first in range(256):
            for second in range(256):
                raw=bytes((first,second))
                if 48<=first<=57 and 48<=second<=57:
                    expected=(first-48)*10+second-48
                elif first==43 and 48<=second<=57:
                    expected=second-48
                else:
                    expected=None
                actual=subject.parse_component(raw)
                self.assertEqual(actual,expected)
                count+=actual is not None
        self.assertEqual(count,110)

    def test_decimal_maximum_and_long_leading_zero_boundaries(self):
        self.assertEqual(subject.parse_component(b'0'*80+b'18446744073709551615'),(1<<64)-1)
        self.assertIsNone(subject.parse_component(b'0'*80+b'18446744073709551616'))
        for n in range(14,21):
            b=b'9'*n
            expected=int(b) if int(b)<=subject.U64_MAX else None
            self.assertEqual(subject.parse_component(b),expected)

    def test_skip_count_all_small_lengths_and_keeps(self):
        for length in range(256):
            for keep in range(256):
                expected=len(list(range(length))[keep:])
                self.assertEqual(subject.selection_count(length,keep),expected)
        for length in (0,1,99,100,101,102,(1<<64)-1):
            self.assertEqual(subject.selection_count(length,100),max(length-100,0))

    def test_skip_rejects_out_of_range_values(self):
        for n,k in [(-1,0),(0,-1),(1<<64,1),(1,1<<64),(True,1),(1,False)]:
            with self.subTest(n=n,k=k), self.assertRaises(ValueError):
                subject.selection_count(n,k)

    def test_sort_dispatch_and_count_model_boundaries(self):
        table={int(x['record_count']):x for x in rows(PACKET/'retention-cases.tsv')}
        for n,kind,copied in [(0,'none',0),(1,'none',0),(2,'small',0),(20,'small',0),(21,'large',0),
                              (99,'large',0),(100,'large',0),(101,'large',1),(102,'large',2)]:
            self.assertEqual(table[n]['sort_dispatch'],kind)
            self.assertEqual(int(table[n]['copied_tail_count']),copied)

    def test_archive_filter_all_small_boundary_combinations(self):
        for lower in range(6):
            for upper in range(6):
                for cap in range(6):
                    for height in range(7):
                        for marker in (False,True):
                            want = True if marker else (height>=lower and height<upper and height<=cap)
                            self.assertEqual(subject.archive_selected(marker,height,lower,upper,cap),want)
        self.assertTrue(subject.archive_selected(True,0,10,20,15))
        self.assertFalse(subject.archive_selected(False,20,10,20,20))
        self.assertTrue(subject.archive_selected(False,15,10,20,15))
        self.assertFalse(subject.archive_selected(False,16,10,20,15))

    def test_archive_filter_rejects_invalid_inputs(self):
        for args in [(1,1,1,2,1),(False,-1,0,1,1),(False,1,0,1,1<<64)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                subject.archive_selected(*args)

    def test_merge_choices_match_unsigned_order_for_all_byte_pairs(self):
        for left in range(256):
            for right in range(256):
                forward=subject.merge_choice(left,right)
                backward=subject.merge_choice(left,right,True)
                self.assertEqual(left if forward=='left' else right,max(left,right))
                self.assertEqual(left if backward=='left' else right,min(left,right))
        self.assertEqual(subject.merge_choice(5,5),'left')
        self.assertEqual(subject.merge_choice(5,5,True),'right')
        self.assertEqual(subject.merge_choice(0,(1<<64)-1),'right')
        self.assertEqual(subject.merge_choice(0,(1<<64)-1,True),'left')

    def test_merge_model_rejects_invalid_operands_and_corrupted_opcodes(self):
        for args in [(-1,0),(1<<64,0),(True,0),(0,1,1)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                subject.merge_choice(*args)
        for va in [0x3e3fc80,0x3e3fc10]:
            with self.corrupt_read(va,3), self.assertRaisesRegex(ValueError,'bytes changed'):
                subject.parameters(self.image)

    def test_normal_flow_and_failure_cases(self):
        table=rows(PACKET/'flow-cases.tsv')
        self.assertEqual(len(table),30)
        for row in table:
            mode=int(row['mode_bit'])
            first=int(row['first_helper_error'])
            second=None if row['second_helper_error']=='' else int(row['second_helper_error'])
            name=int(row['name_byte'])
            self.assertIn(mode,(0,1))
            self.assertEqual(second is not None,mode==1)
            self.assertEqual(int(row['first_error_log_boundary']),first)
            self.assertEqual(int(row['second_helper_called']),mode)
            self.assertEqual(int(row['second_error_log_boundary']),int(mode==1 and second==1 and name not in (19,20)))
            self.assertEqual(int(row['second_error_drop']),int(mode==1 and second==1))
            self.assertEqual(row['outer_completion_on_normal_returns'],'1')

    def test_mode_specific_flow_rejects_impossible_inputs(self):
        no_archive=subject.maintenance_flow(0,False,None,33,self.params)
        self.assertFalse(no_archive['second_helper_called'])
        for tag in (19,20):
            archive=subject.maintenance_flow(1,False,True,tag,self.params)
            self.assertTrue(archive['second_helper_called'])
            self.assertFalse(archive['second_error_log_boundary'])
            self.assertTrue(archive['second_error_drop'])
        for tag in (18,21,33):
            self.assertTrue(subject.maintenance_flow(1,False,True,tag,self.params)['second_error_log_boundary'])
        for args in [(0,False,False,19),(1,False,None,19),(2,False,None,19),
                     (True,False,False,19),(1,0,False,19),(1,False,True,256)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                subject.maintenance_flow(*args,self.params)

    def test_date_failure_branches_and_unreachable_inputs(self):
        expected=[('0','','local_time_range_failure'),('1','0','date_subtract_failure'),
                  ('1','1','continue')]
        observed=[(r['local_date_nonzero'],r['previous_date_nonzero'],r['selected_branch'])
                  for r in rows(PACKET/'date-cases.tsv')]
        self.assertEqual(observed,expected)
        for args in [(False,False),(False,True),(True,None),(0,None),(True,1)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                subject.date_transition(*args)

    def test_checked_windows_and_mapping_reject_corruption(self):
        with self.corrupt_read(0x44c7fa,2), self.assertRaisesRegex(ValueError,'bytes changed'):
            subject.must_bytes(self.image,0x44c7fa,b'\xc0\x14/MARKED_FOR_DELETION\x00',False)
        for address in (0,(1<<64)-1):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.image.offset(address,8)
        with self.assertRaises(ValueError): self.image.offset(0x1564120,0)
        # TLS NOBITS can share a linked VA with a file-backed section; choose
        # this non-overlapping zero-fill section for the negative control.
        bss=next(s for s in self.image.secs if s['name']=='.bss' and s['type']==8)
        with self.assertRaises(ValueError): self.image.offset(bss['address'],8)
        with self.assertRaises(ValueError): self.image.offset(0x44ab69,1,True)

    def test_branch_decoder_accepts_signed_offsets_and_rejects_bad_forms(self):
        self.assertEqual(subject.decode_branch(bytes.fromhex('7679'),0x1564143),(2,'be',0x15641be))
        self.assertEqual(subject.decode_branch(bytes.fromhex('75ee'),0x1000),(2,'ne',0xff0))
        for code in (b'',b'\x0f',b'\x0f\x84\x00',b'\x90\x00'):
            with self.subTest(code=code), self.assertRaises(ValueError): subject.decode_branch(code,0)
        with self.assertRaises(ValueError): subject.relative(b'\xe8\x00',0,b'\xe8')
        with self.assertRaises(ValueError): subject.relative(b'\xe9\x00\x00\x00\x00',0,b'\xe8')

    def test_relocation_corruption_is_rejected(self):
        altered=dict(self.image._relocs)
        info,addend,offset=altered[0x64e9548]
        altered[0x64e9548]=(info,addend+1,offset)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(self.image,'_relocs',altered):
            with self.assertRaisesRegex(ValueError,'call target mismatch'):
                subject.collect(self.image,Path(tmp))
        altered[0x64e9548]=(1,addend,offset)
        with mock.patch.object(self.image,'_relocs',altered), self.assertRaisesRegex(ValueError,'relative relocation'):
            self.image.relocation(0x64e9548)

    def test_duplicate_and_truncated_relocation_tables_fail(self):
        fake=object.__new__(subject.Image)
        rec=struct.pack('<QQq',0x1000,8,0x2000)
        fake.data=rec+rec
        fake.secs=[dict(name='.rela.dyn',type=4,offset=0,size=len(fake.data))]
        fake._relocs=None
        with self.assertRaisesRegex(ValueError,'duplicate'):
            fake.relocation(0x1000)
        fake.secs[0]['size']=25
        fake._relocs=None
        with self.assertRaisesRegex(ValueError,'invalid dynamic'):
            fake.relocation(0x1000)

    def test_descriptor_bad_pointer_and_length_are_rejected(self):
        slot=0x63f88b8
        altered=dict(self.image._relocs)
        info,_,offset=altered[slot]
        altered[slot]=(info,0,offset)
        with mock.patch.object(self.image,'_relocs',altered), self.assertRaises(ValueError):
            self.image.descriptor(slot)
        original=self.image.read
        def fake_read(va,size,executable=False):
            if va==slot+8 and size==8: return struct.pack('<Q',257)
            return original(va,size,executable)
        with mock.patch.object(self.image,'read',side_effect=fake_read), self.assertRaisesRegex(ValueError,'descriptor length'):
            self.image.descriptor(slot)

    def test_fde_and_index_mismatch_is_rejected(self):
        name,start,end,_=subject.FRAME_SPECS[0]
        idx={'start':start,'fde':0x123,'index':0}
        wrong={'fde':0x123,'start':start,'end':end+1,'cie':0,'lsda':None}
        with mock.patch.object(subject,'unwind_index',return_value=(self.image.secs,[idx])), \
             mock.patch.object(subject,'eh_frame_records',return_value=({},[wrong])):
            with self.assertRaisesRegex(ValueError,'FDE and unwind index mismatch'):
                subject.frame_records(self.image)

    def test_exception_table_negative_controls(self):
        frame={'lsda':0x2000,'start':0x1000,'end':0x1010}
        class Fake:
            def __init__(self,data):
                self.data=data
                self.secs=[dict(name='.gcc_except_table',type=1,offset=0,size=len(data))]
            def offset(self,va,size): return 0
        good=Fake(bytes.fromhex('ffff010400010200'))
        entries=subject.exception_entries(good,frame)
        self.assertEqual((entries[0]['start'],entries[0]['end'],entries[0]['landing']),(0x1000,0x1001,0x1002))
        for bad in (bytes.fromhex('ffff010500010200'),bytes.fromhex('ffff010400011100'),
                    bytes.fromhex('00ff010400010200'),bytes.fromhex('ffff010480'),
                    bytes.fromhex('ff9b7f0100'),bytes.fromhex('ffff01080004000002010000')):
            with self.subTest(data=bad.hex()), self.assertRaises(ValueError):
                subject.exception_entries(Fake(bad),frame)

    def test_selected_exception_landing_and_cleanup_are_recorded(self):
        entries={r['role']:r for r in rows(PACKET/'exception-edges.tsv')}
        self.assertEqual(entries['name_gate_log_boundary']['landing_va'],'0x1564203')
        self.assertEqual(entries['count_remove_boundary']['landing_va'],'0x38c56b1')
        self.assertEqual(entries['archive_remove_boundary']['landing_va'],'0x38c64d9')
        self.assertEqual(entries['outer_to_maintenance']['landing_va'],'0x2dd5070')
        self.assertEqual(entries['name_gate_unwind_drop']['landing_va'],'0x1564217')

    def test_generated_summary_separates_models_from_observations(self):
        summary=json.loads((PACKET/'summary.json').read_text(encoding='utf-8'))
        self.assertEqual(summary['suppressed_name_bytes'],[19,20])
        self.assertEqual(summary['parameters']['keep_count'],100)
        self.assertEqual(summary['binary_sha256'],subject.SHA115)
        self.assertIn('no target execution',summary['limitations'])


if __name__ == '__main__':
    unittest.main()
