"""Static target-bound controls for the configuration sequence evidence."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from tools import config_string_sequence94 as subject


class Overlay:
    """Alter a selected VA for a lower-level negative control, without a file copy."""
    def __init__(self, view, address, replacement):
        self.view = view
        self.address = address
        self.replacement = replacement
        self.sections = view.sections
        self.data = view.data

    def offset(self, address, size, executable=False):
        return self.view.offset(address,size,executable)

    def read(self, address, size, executable=False):
        raw=bytearray(self.view.read(address,size,executable))
        left=max(address,self.address)
        right=min(address+size,self.address+len(self.replacement))
        if left < right:
            raw[left-address:right-address]=self.replacement[left-self.address:right-self.address]
        return bytes(raw)


class ConfigurationSequenceEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=subject.TARGET.read_bytes()
        cls.result=subject.collect(cls.data)
        cls.view=subject.View(cls.data)
        _,cls.fdes=subject.eh_frame_records(cls.data,cls.view.sections)

    def test_target_identity(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),subject.DIGEST)
        self.assertEqual(len(self.data),subject.SIZE)

    def test_corrupted_artifact_is_rejected(self):
        damaged=bytearray(self.data)
        damaged[-1]^=1
        with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):
            subject.verify_identity(damaged)

    def test_wrong_expected_digest_is_rejected(self):
        with self.assertRaises(ValueError):
            subject.verify_identity(self.data,'0'*64)

    def test_invalid_ranges_rejected(self):
        for address,size in ((-1,1),(0,0),(1<<64,1),((1<<64)-1,2),(True,1)):
            with self.subTest(address=address,size=size),self.assertRaises(ValueError):
                self.view.offset(address,size)

    def test_unmapped_address_rejected(self):
        with self.assertRaises(ValueError):
            self.view.read(0x100,4,True)

    def test_nobits_cannot_supply_file_bytes(self):
        row={'name':'synthetic','type':8,'flags':6,'address':0x10000,'offset':0,'size':16}
        with self.assertRaises(ValueError):
            subject.View(self.data,[row]).read(0x10000,1)

    def test_ambiguous_sections_rejected(self):
        row=next(x for x in self.view.sections if x['name']=='.text')
        with self.assertRaises(ValueError):
            subject.View(self.data,[row,row]).read(row['address'],1,True)

    def test_fde_extents_and_body_hashes(self):
        self.assertEqual(len(self.result['selected']),9)
        self.assertEqual(sum(x['size'] for x in self.result['selected']),1798)
        raw=next(x for x in self.result['selected'] if x['role']=='raw_byte_collector')
        self.assertEqual((raw['start'],raw['end'],raw['lsda']),(0x14c06a0,0x14c08cd,0x92f8f0))

    def test_body_corruption_rejected(self):
        va=0x14c0775
        changed=bytes([self.view.read(va,1,True)[0]^1])
        with self.assertRaisesRegex(ValueError,'body digest'):
            subject.select_functions(Overlay(self.view,va,changed),self.fdes)

    def test_fde_extent_corruption_rejected(self):
        altered=list(self.fdes)
        ix=next(i for i,f in enumerate(altered) if f['start']==0x14c06a0)
        altered[ix]=dict(altered[ix],end=altered[ix]['end']+1)
        with self.assertRaisesRegex(ValueError,'FDE'):
            subject.select_functions(self.view,altered)

    def test_duplicate_fde_rejected(self):
        duplicate=next(f for f in self.fdes if f['start']==0x14c08d0)
        with self.assertRaisesRegex(ValueError,'FDE'):
            subject.select_functions(self.view,self.fdes+[duplicate])

    def test_pin_corruption_rejected(self):
        va=0x14c0775
        overlay=Overlay(self.view,va,b'\x00')
        with self.assertRaisesRegex(ValueError,'byte contract'):
            subject.require(overlay,va,bytes.fromhex('0fb67500'),True)

    def test_conditional_branch_targets(self):
        rows=self.result['branches']
        self.assertEqual(len(rows),46)
        tag_branch=next(r for r in rows if r[0]==0x14c078a)
        self.assertEqual(tag_branch[3:],('not_equal',0x14c078c,0x14c07f2))
        self.assertEqual(subject.branch(self.view,0x13b5b1a,0x13b5b57)[-1],0x13b5b57)
        fresh_branch=next(r for r in rows if r[0]==0x13b581b)
        self.assertEqual(fresh_branch[3:],('sign',0x13b5821,0x13b59b8))

    def test_parent_length_paths_and_truncation_contract(self):
        pins={r[0]:r for r in self.result['pins']}
        self.assertEqual(pins['parent_c5_len'][-1],self.view.read(0x13b56c1,38,True).hex())
        self.assertEqual(pins['parent_c6_len'][-1],self.view.read(0x13b570b,30,True).hex())
        self.assertTrue(pins['parent_truncated'][-1].endswith('c60701'))
        with self.assertRaisesRegex(ValueError,'byte contract'):
            subject.require(Overlay(self.view,0x13b56d3,b'\x00'),0x13b56c1,
                            bytes.fromhex(pins['parent_c5_len'][-1]),True)

    def test_valid_opcode_wrong_branch_target_rejected(self):
        overlay=Overlay(self.view,0x14c078b,b'\x65')
        with self.assertRaisesRegex(ValueError,'branch target'):
            subject.branch(overlay,0x14c078a,0x14c07f2)

    def test_call_target_corruption_rejected(self):
        overlay=Overlay(self.view,0x14c077f,b'\xfc')
        with self.assertRaisesRegex(ValueError,'transfer target'):
            subject.transfer(overlay,0x14c077e,0x14d2180)

    def test_unsupported_transfer_rejected(self):
        with self.assertRaises(ValueError):
            subject.transfer(Overlay(self.view,0x14c077e,b'\x90'),0x14c077e,0x14d2180)

    def test_direct_and_dynamic_boundaries(self):
        calls={r[0]:r for r in self.result['calls']}
        self.assertEqual(calls[0x14c077e][3:],('direct_call',0x14d2180))
        self.assertEqual(calls[0x14c0979][3:],('direct_call',0x13bdcd0))
        self.assertEqual(calls[0x14c3ea7][3:],('register_tail',None))

    def test_field_handoffs(self):
        fields={row[0]:row for row in self.result['fields']}
        self.assertEqual(len(fields),5)
        self.assertEqual((fields['etherscan_keys'][6],fields['etherscan_keys'][9]),(0x1f,0x13acd78))
        self.assertEqual((fields['zip_and_upload_skip_cp'][6],fields['zip_and_upload_skip_cp'][9]),(0x26,0x13acacf))
        self.assertTrue(all(row[-1]==0x13b0144 for row in fields.values()))

    def test_field_literal_corruption_rejected(self):
        overlay=Overlay(self.view,0x21bba7,b'X')
        with self.assertRaisesRegex(ValueError,'byte contract'):
            subject.fields(overlay)

    def test_field_leaf_corruption_rejected(self):
        overlay=Overlay(self.view,0x13c836f,b'\x90')
        with self.assertRaisesRegex(ValueError,'field-tag leaf'):
            subject.fields(overlay)

    def test_wrong_field_arm_rejected(self):
        slot=0x20fac4
        wrong=struct.pack('<i',0x13ad564-0x20faa0)
        with self.assertRaisesRegex(ValueError,'dispatcher changed'):
            subject.fields(Overlay(self.view,slot,wrong))

    def test_marker_tables_and_selected_cells(self):
        table={(r[0],r[1]):r[-1] for r in self.result['tables']}
        self.assertEqual(len(table),275)
        self.assertEqual(table['cached_class',0xc4],0x13b56e7)
        self.assertEqual(table['cached_class',1],0x13b57f7)
        self.assertEqual(table['fresh_c0_df',4],0x13b56ef)
        self.assertEqual(table['fresh_c0_df',5],0x13b56c1)
        self.assertEqual(table['fresh_c0_df',6],0x13b570b)

    def test_valid_but_wrong_table_target_rejected(self):
        base=0x2103ac
        slot=base+4*4
        wrong=struct.pack('<i',0x13b56c1-base)
        parent=next(f for f in self.fdes if f['start']==0x13b5630)
        with self.assertRaisesRegex(ValueError,'table digest'):
            subject.tables(Overlay(self.view,slot,wrong),parent)

    def test_relocation_contracts(self):
        rel={row[0]:row[-1] for row in self.result['relocations']}
        self.assertEqual(rel['sequence_expected_method'],0x14c3e90)
        self.assertEqual(rel['string_expected_method_boundary'],0x14c3f10)
        self.assertEqual(rel['prior_static_config_cell'],0x577b288)

    def test_relocation_corruption_rejected(self):
        row=next(r for r in self.result['relocations'] if r[0]=='sequence_expected_method')
        damaged=bytearray(self.data)
        damaged[row[2]+16]^=1
        with self.assertRaisesRegex(ValueError,'relocation contract'):
            subject.relocs(subject.View(damaged,self.view.sections))

    def test_error_descriptor_method_bindings(self):
        rows={r[0]:r for r in self.result['descriptors']}
        self.assertEqual(len(rows),5)
        self.assertEqual((rows['byte_element'][5],rows['byte_element'][9:12]),
                         (1,(0x566f150,0x566f168,0x14c3f10)))
        self.assertEqual((rows['map'][5],rows['map'][9:12]),
                         (11,(0x566ef70,0x566ef88,0x14c3e90)))
        self.assertTrue(all(r[-1]==0x20193e for r in rows.values()))

    def test_descriptor_corruption_rejected(self):
        with self.assertRaisesRegex(ValueError,'kind contract'):
            subject.error_descriptors(Overlay(self.view,0x14d2195,b'\x02'),self.result['relocations'])
        with self.assertRaisesRegex(ValueError,'binding changed'):
            subject.error_descriptors(Overlay(self.view,0x14d21a3,b'\xa8'),self.result['relocations'])

    def test_exception_tables(self):
        self.assertEqual(len(self.result['lsda_headers']),2)
        self.assertEqual(len(self.result['lsda_sites']),9)
        call=next(r for r in self.result['lsda_sites'] if r[4]==0x14c0779)
        self.assertEqual(call[5:7],(0x14c0783,0x14c08ba))

    def test_exception_corruption_rejected(self):
        overlay=Overlay(self.view,0x92f8f4,b'\xff')
        with self.assertRaisesRegex(ValueError,'LSDA bytes changed'):
            subject.exception_sites(overlay,self.fdes,self.result['selected'])

    def test_expected_sequence_literal(self):
        self.assertEqual(self.view.read(0x21c515,10),b'a sequence')
        self.assertEqual(next(x for x in self.result['literals'] if x[0]=='expected_sequence')[3],10)
        raw=self.view.read(0x14c3e9b,12,True)
        self.assertEqual(0x14c3e9b+7+struct.unpack('<i',raw[3:7])[0],0x21c515)
        self.assertEqual(struct.unpack('<I',raw[8:12])[0],10)

    def test_raw_empty_and_nonempty(self):
        self.assertEqual(subject.raw_probe(bytes.fromhex('c400')),(9,2,0,0,'empty_vector'))
        self.assertEqual(subject.raw_probe(bytes.fromhex('c40100')),(6,3,0,1,'first_byte_error_boundary'))
        self.assertEqual(subject.raw_probe(bytes.fromhex('c40141')),(6,3,0,1,'first_byte_error_boundary'))
        self.assertEqual(subject.raw_probe(bytes.fromhex('c40180')),(6,3,0,1,'first_byte_error_boundary'))
        self.assertEqual(subject.raw_probe(bytes.fromhex('c401ff')),(6,3,0,1,'first_byte_error_boundary'))

    def test_raw_truncation_preserves_payload_boundary(self):
        self.assertEqual(subject.raw_probe(bytes.fromhex('c40241')),(1,2,1,0,'truncated_payload'))
        self.assertEqual(subject.raw_probe(bytes.fromhex('c500')),(1,2,0,0,'truncated_length'))
        self.assertEqual(subject.raw_probe(bytes.fromhex('c6000000')),(1,4,0,0,'truncated_length'))
        self.assertEqual(subject.raw_probe(bytes.fromhex('c6ffffffff')),(1,5,0,0,'truncated_payload'))

    def test_raw_big_endian_and_trailing(self):
        self.assertEqual(subject.raw_probe(bytes.fromhex('c5000141'))[:3],(6,4,0))
        self.assertEqual(subject.raw_probe(bytes.fromhex('c60000000141'))[:3],(6,6,0))
        self.assertEqual(subject.raw_probe(bytes.fromhex('c400ff'))[:3],(9,2,1))

    def test_raw_mode_and_invalid_input(self):
        self.assertEqual(subject.raw_probe(bytes.fromhex('c400'),1)[0],6)
        for data,mode in ((b'',0),(b'\x90',0),(b'\xc4\x00',2),('c400',0)):
            with self.subTest(data=data,mode=mode),self.assertRaises(ValueError):
                subject.raw_probe(data,mode)

    def test_reservation_operands_are_extracted(self):
        raw=struct.unpack('<I',self.view.read(0x14c06c7,4,True))[0]
        seq=struct.unpack('<I',self.view.read(0x14c08e8,4,True))[0]
        self.assertEqual((raw,seq),(0xaaaa,0xaaaa))
        self.assertEqual((self.result['reservation_limit'],self.result['reservation_stride']),(raw,24))

    def test_reservation_boundaries(self):
        self.assertEqual(subject.allocation_plan(0),(0,0))
        self.assertEqual(subject.allocation_plan(0xaaaa),(43690,1048560))
        self.assertEqual(subject.allocation_plan(0xaaab),(43690,1048560))
        self.assertEqual(subject.allocation_plan(0xffffffff),(43690,1048560))
        for bad in (-1,1<<32,True,1.5):
            with self.subTest(count=bad),self.assertRaises(ValueError):
                subject.allocation_plan(bad)

    def test_sequence_depth_and_error_transition(self):
        self.assertEqual(subject.sequence_probe(0,2,()),('success',9,0,0,2))
        self.assertEqual(subject.sequence_probe(2,2,('ok','tag6')),('child_error',6,1,0,1))
        self.assertEqual(subject.sequence_probe(2,2,('tag6',)),('child_error',6,0,1,1))
        self.assertEqual(subject.sequence_probe(1,1,()),('depth_error',8,0,1,0))
        self.assertEqual(subject.sequence_probe(1,0,()),('underflow_boundary',None,0,1,0))

    def test_sequence_niche_is_conditional(self):
        self.assertEqual(subject.sequence_probe(2,2,('niche',)),('partial_drop',4,0,1,2))
        self.assertEqual(subject.sequence_probe(1,2,('niche',)),('short_success',9,0,0,2))
        self.assertEqual(subject.sequence_probe(2,2,('ok',)),('external_child_pending',None,1,1,1))

    def test_sequence_invalid_inputs(self):
        for count,depth,outcomes in ((-1,2,()),(1,65536,()),(0,2,('ok',)),(1,2,('unknown',))):
            with self.subTest(count=count,depth=depth,outcomes=outcomes),self.assertRaises(ValueError):
                subject.sequence_probe(count,depth,outcomes)

    def test_generated_evidence_matches_packet(self):
        committed=subject.ROOT/'research/work-items/RE-015-config-string-sequence-94'
        with tempfile.TemporaryDirectory() as directory:
            generated=Path(directory)
            subject.write_evidence(generated,self.result)
            names=sorted(p.name for p in generated.iterdir())
            self.assertEqual(len(names),16)
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual((generated/name).read_bytes(),(committed/name).read_bytes())


if __name__=='__main__':
    unittest.main()
