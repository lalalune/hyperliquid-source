"""Offline target-byte and negative controls for the selected RE-015 path."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'tools'))
import re015_db_root_open_115 as packet


class DbRootEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(packet.TARGET.read_bytes())
        packet.check_identity(cls.data)
        cls.image = packet.Image(cls.data)
        cls.params = packet.number_parameters(cls.image)
        cls.generated = packet.build(cls.data)

    def mutate(self, address, count=1):
        offset,_ = self.image.offset(address,count)
        saved = bytes(self.data[offset:offset+count])
        self.addCleanup(self.data.__setitem__,slice(offset,offset+count),saved)
        self.data[offset] ^= 1
        return offset

    def test_authenticated_input(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),packet.TARGET_SHA256)
        self.mutate(0x5a007c0)
        with self.assertRaisesRegex(packet.EvidenceError,'SHA-256'):
            packet.check_identity(self.data)

    def test_wrong_release_rejected_before_analysis(self):
        with self.assertRaisesRegex(packet.EvidenceError,'SHA-256'):
            packet.build(b'not the target')
        with self.assertRaisesRegex(packet.EvidenceError,'SHA-256'):
            packet.compare_old(self.data,b'not the historical target')

    def test_fde_body_digest_rejects_changed_instruction(self):
        label,start,end,expected = next(x for x in packet.FUNCTIONS if x[0]=='root_guard')
        packet.validate_body(self.image,start,end,expected,label)
        self.mutate(0x5a007ee)
        with self.assertRaisesRegex(packet.EvidenceError,'FDE bytes'):
            packet.validate_body(self.image,start,end,expected,label)

    def test_complete_pool_entry_and_terminator(self):
        expected = b'\xc0\x18/hyperliquid_data/db_hub\x00'
        self.assertEqual(self.image.entry(0x443e39,expected),expected)
        self.mutate(0x443e39+len(expected)-1)
        with self.assertRaisesRegex(packet.EvidenceError,'entry differs'):
            self.image.entry(0x443e39,expected)

    def test_rex_instruction_and_target(self):
        raw=self.image.rip(0x5a0081e,0x443e39)
        self.assertEqual(raw[:3],bytes.fromhex('488d15'))
        with self.assertRaisesRegex(packet.EvidenceError,'RIP target'):
            self.image.rip(0x5a0081e,0x443e3b)
        self.mutate(0x5a00821)
        with self.assertRaisesRegex(packet.EvidenceError,'RIP target'):
            self.image.rip(0x5a0081e,0x443e39)

    def test_direct_call_displacement_control(self):
        self.image.direct(0x57c65df,0x5a007c0)
        self.mutate(0x57c65e0)
        with self.assertRaisesRegex(packet.EvidenceError,'direct call target'):
            self.image.direct(0x57c65df,0x5a007c0)

    def test_branch_displacement_control(self):
        label,site,expected,target=packet.BRANCHES[0]
        self.assertEqual(self.image.branch(site,expected,target)[1],target)
        self.mutate(site+1)
        with self.assertRaisesRegex(packet.EvidenceError,'branch bytes'):
            self.image.branch(site,expected,target)

    def test_branch_wrong_expected_target_rejected(self):
        _,site,expected,target=packet.BRANCHES[-1]
        with self.assertRaisesRegex(packet.EvidenceError,'branch target'):
            self.image.branch(site,expected,target+1)

    def test_indirect_call_slot_control(self):
        self.image.rip(0x582896e,0x64e6f90,call=True)
        self.mutate(0x5828970)
        with self.assertRaisesRegex(packet.EvidenceError,'RIP target'):
            self.image.rip(0x582896e,0x64e6f90,call=True)

    def test_relative_relocation_corruption(self):
        rel=self.image.relocations([0x64e0918])[0x64e0918]
        offset=rel[3]+16
        before=bytes(self.data[offset:offset+8])
        self.addCleanup(self.data.__setitem__,slice(offset,offset+8),before)
        self.data[offset] ^= 1
        with self.assertRaisesRegex(packet.EvidenceError,'relocation differs'):
            packet.selected_relocations(self.image)

    def test_dynamic_symbol_name_corruption(self):
        sec=self.image.section('.dynstr')
        i=self.data.find(b'bcmp\x00',sec['offset'],sec['offset']+sec['size'])
        self.assertGreaterEqual(i,sec['offset'])
        old=self.data[i]
        self.addCleanup(self.data.__setitem__,i,old)
        self.data[i] ^= 1
        with self.assertRaisesRegex(packet.EvidenceError,'dynamic symbol differs'):
            packet.selected_relocations(self.image)

    def test_plt_link_target_and_symbol_controls(self):
        self.image.plt_link(0x63f0da0,0x64ee320,'strdup')
        with self.assertRaisesRegex(packet.EvidenceError,'PLT symbol'):
            self.image.plt_link(0x63f0da0,0x64ee320,'free')
        self.mutate(0x63f0da2)
        with self.assertRaisesRegex(packet.EvidenceError,'PLT target'):
            self.image.plt_link(0x63f0da0,0x64ee320,'strdup')

    def test_nv_descriptor_length_and_corruption(self):
        self.assertEqual(packet.verify_name_descriptor(self.image),9)
        self.mutate(0x63f8998+8)
        with self.assertRaisesRegex(packet.EvidenceError,'length differs'):
            packet.verify_name_descriptor(self.image)

    def test_out_of_range_and_nobits_are_rejected(self):
        bss=self.image.section('.text')
        with self.assertRaises(packet.EvidenceError):
            self.image.offset(bss['address']+bss['size']-1,2,True)
        zero_fill=[s for s in self.image.sections if s['name']=='.bss' and s['type']==8 and s['size']]
        self.assertTrue(zero_fill)
        with self.assertRaises(packet.EvidenceError):
            self.image.offset(zero_fill[0]['address'],1)
        with self.assertRaises(packet.EvidenceError):
            self.image.offset(-1,1)
        with self.assertRaises(packet.EvidenceError):
            self.image.offset(0,0)

    def test_size_shift_byte_corruption(self):
        self.assertEqual(self.params,(54,10,0x4000,44,20))
        self.mutate(0x57c6617)
        with self.assertRaisesRegex(packet.EvidenceError,'size parameters'):
            packet.number_parameters(self.image)

    def test_size_model_full_width_boundaries(self):
        limit=1<<34
        max_u64=(1<<64)-1
        for flag in (0,1,2,3,255):
            for value in list(range(256))+[limit-1,limit,limit+1,(1<<54)-1,1<<54,max_u64]:
                with self.subTest(flag=flag,value=value):
                    expected=(1<<34) if not flag&1 else ((value<<30) if value<limit else max_u64)
                    self.assertEqual(packet.capacity_model(flag,value,self.params),expected)
        for flag,value in ((-1,0),(256,0),(0,-1),(0,1<<64)):
            with self.assertRaises(packet.EvidenceError):
                packet.capacity_model(flag,value,self.params)

    def test_root_selector_signed_minimum_and_neighbors(self):
        for word in (0,(1<<63)-1,(1<<63)+1,(1<<64)-1):
            self.assertEqual(packet.root_model(word),'input_template')
        self.assertEqual(packet.root_model(1<<63),'global_template')
        for bad in (-1,1<<64):
            with self.assertRaises(packet.EvidenceError):
                packet.root_model(bad)

    def test_root_input_handoffs_and_corruption(self):
        rows=packet.input_flow(self.image)
        self.assertEqual(len(rows),9)
        self.image.direct(0x4e3401d,0x5165970)
        self.image.direct(0x5165983,0x5b77f30)
        self.mutate(0x4e34007)
        with self.assertRaisesRegex(packet.EvidenceError,'input flow instruction'):
            packet.input_flow(self.image)

    def test_parent_key_bytes_and_bound_control(self):
        keys=packet.parent_keys(self.image)
        self.assertEqual([row[1] for row in keys],['0x0','0x1'])
        self.mutate(0x4e33ff9)
        with self.assertRaisesRegex(packet.EvidenceError,'setup values'):
            packet.parent_keys(self.image)

    def test_constructor_keys_and_label_selection(self):
        self.assertEqual([r[1] for r in packet.constructor_keys(self.image)],['0x0','0x1'])
        for value,expected in ((0,b'Exchange'),(1,b'Rpc'),(2,b'EvmState'),(255,b'EvmState')):
            self.assertEqual(packet.key_label(self.image,value),expected)
        for bad in (-1,256):
            with self.assertRaises(packet.EvidenceError):
                packet.key_label(self.image,bad)
        self.mutate(0x1696dbd)
        with self.assertRaisesRegex(packet.EvidenceError,'key display'):
            packet.key_label(self.image,0)

    def test_short_path_guard_and_long_boundary(self):
        pattern=packet.path_guard_pattern(self.image)
        self.assertEqual(pattern,b'checkpoint')
        for n in range(25):
            samples=[b'x'*n]
            samples += [b'x'*i+pattern+b'x'*(n-i-len(pattern))
                        for i in range(max(0,n-len(pattern)+1))]
            for sample in samples:
                self.assertEqual(packet.bounded_path_guard(sample,pattern),pattern in sample)
        with self.assertRaisesRegex(packet.EvidenceError,'outside model'):
            packet.bounded_path_guard(b'x'*25,pattern)
        self.mutate(0x16961de)
        with self.assertRaisesRegex(packet.EvidenceError,'pattern differs'):
            packet.path_guard_pattern(self.image)

    def test_collection_count_thresholds_and_corruption(self):
        limits=packet.collection_limits(self.image)
        self.assertEqual(limits,(1,21))
        for n,expected in ((0,'empty'),(1,'single'),(2,'small_boundary'),
                           (20,'small_boundary'),(21,'large_boundary'),((1<<64)-1,'large_boundary')):
            self.assertEqual(packet.collection_model(n,limits),expected)
        for n in (-1,1<<64):
            with self.assertRaises(packet.EvidenceError):
                packet.collection_model(n,limits)
        self.mutate(0x5165a79)
        with self.assertRaisesRegex(packet.EvidenceError,'thresholds'):
            packet.collection_limits(self.image)

    def test_guard_outcome_order(self):
        self.assertEqual(packet.outcome_model(0,0,0,0,0),'normal_return')
        self.assertEqual(packet.outcome_model(1,1,1,1,1),'root_format_error')
        self.assertEqual(packet.outcome_model(0,1,1,1,1),'first_label_error')
        self.assertEqual(packet.outcome_model(0,0,1,1,1),'first_search_nonzero')
        self.assertEqual(packet.outcome_model(0,0,0,1,1),'second_label_error')
        self.assertEqual(packet.outcome_model(0,0,0,0,1),'second_search_nonzero')
        with self.assertRaises(packet.EvidenceError):
            packet.outcome_model(0,0,0,0,2)

    def test_guard_and_loop_terminal_witnesses(self):
        self.image.entry(0x5a00a95,bytes.fromhex('0f0b'))
        self.image.entry(0x543e73b,bytes.fromhex('0f0b'))
        self.mutate(0x5a00a95)
        with self.assertRaisesRegex(packet.EvidenceError,'entry differs'):
            self.image.entry(0x5a00a95,bytes.fromhex('0f0b'))

    def test_native_status_and_duplicate_pointer_outcomes(self):
        self.image.branch(0x5d33cfe,'7450',0x5d33d50)
        self.image.direct(0x5d33d06,0x5d2e0e0)
        self.image.direct(0x5d2e11d,0x63f0da0)
        self.assertEqual(self.image.read(0x5d2e125,3,True),bytes.fromhex('488903'))
        self.assertEqual(self.image.read(0x5d2e141,5,True),bytes.fromhex('b801000000'))
        self.assertEqual(packet.native_outcome_model(0,None),('allocated_box','signed_min_and_box'))
        for status in (1,2,255):
            self.assertEqual(packet.native_outcome_model(status,1),('null','error_pointer_nonzero'))
            self.assertEqual(packet.native_outcome_model(status,0),('null','signed_min_and_null'))
        for status,duplicate in ((-1,0),(256,0),(0,0),(1,None),(1,2)):
            with self.assertRaises(packet.EvidenceError):
                packet.native_outcome_model(status,duplicate)

    def test_size_argument_is_forwarded_to_factory(self):
        self.assertEqual(self.image.read(0x5d3525a,3,True),bytes.fromhex('4989fe'))
        self.assertEqual(self.image.read(0x5d35292,3,True),bytes.fromhex('4c89f6'))
        self.image.direct(0x5d352b8,0x5d3db50)
        self.image.direct(0x5d3dbb6,0x5d3d550)
        self.mutate(0x5d352b9)
        with self.assertRaisesRegex(packet.EvidenceError,'direct call target'):
            self.image.direct(0x5d352b8,0x5d3db50)

    def test_equal_length_search_boundary(self):
        self.image.branch(0x59dc057,'0f8543030000',0x59dc3a0)
        self.image.rip(0x59dc066,0x64df9f8,call=True)
        rows=packet.selected_relocations(self.image)
        self.assertTrue(any(r[-1]=='bcmp' for r in rows))
        self.assertEqual(self.image.entry(0x4595c0,b'Exchange'),b'Exchange')
        self.assertEqual(self.image.entry(0x47b428,b'Rpc'),b'Rpc')
        self.assertNotEqual(b'Exchange',b'exchange')

    def test_literal_scan_overlapping_terminal_and_missing(self):
        self.assertEqual(packet.find_offsets(b'ababa',b'aba'),[0,2])
        self.assertEqual(packet.find_offsets(b'abc',b'c'),[2])
        self.assertEqual(packet.find_offsets(b'ab',b'abc'),[])
        self.assertEqual(packet.find_offsets(self.data,b'/no_db_hub'),[])
        with self.assertRaises(packet.EvidenceError):
            packet.find_offsets(b'abc',b'')

    def test_ambiguous_section_mapping_rejected(self):
        real=self.image.section('.text')
        duplicate=dict(real)
        self.image.sections.append(duplicate)
        self.addCleanup(self.image.sections.pop)
        with self.assertRaisesRegex(packet.EvidenceError,'uniquely file-backed'):
            self.image.offset(real['address'],1,True)

    def test_bounded_search_matches_independent_membership(self):
        limit=packet.scalar_search_limit(self.image)
        for pattern in (b'Exchange',b'Rpc'):
            for length in range(len(pattern)+limit):
                no_match=b'x'*length
                self.assertEqual(packet.scalar_search_model(pattern,no_match,limit),pattern in no_match)
                for index in range(max(0,length-len(pattern)+1)):
                    sample=no_match[:index]+pattern+no_match[index+len(pattern):]
                    self.assertEqual(packet.scalar_search_model(pattern,sample,limit),pattern in sample)
                    changed=sample[:index]+bytes([sample[index]^1])+sample[index+1:]
                    self.assertEqual(packet.scalar_search_model(pattern,changed,limit),pattern in changed)
            with self.assertRaisesRegex(packet.EvidenceError,'vector search'):
                packet.scalar_search_model(pattern,b'x'*(len(pattern)+limit),limit)
        with self.assertRaises(packet.EvidenceError):
            packet.scalar_search_model(b'aaa',b'aaa',limit)

    def test_search_threshold_corruption(self):
        self.assertEqual(packet.scalar_search_limit(self.image),15)
        self.mutate(0x59dc172)
        with self.assertRaisesRegex(packet.EvidenceError,'threshold'):
            packet.scalar_search_limit(self.image)

    def test_options_initial_then_overridden_values(self):
        rows=packet.option_values(self.image)
        self.assertEqual([r[3] for r in rows],[4096,32768,1,134217728])
        self.assertEqual([r[2] for r in rows],[0x58,0x58,0,0x4a8])
        self.mutate(0x5d34c47)
        with self.assertRaisesRegex(packet.EvidenceError,'setter bytes'):
            packet.option_values(self.image)

    def test_size_reference_and_options_attachment_fields(self):
        rows=packet.binding_fields(self.image)
        self.assertEqual([r[2] for r in rows],['0x38','0x40','0x548','0x550'])
        selected=packet.selected_relocations(self.image)
        self.assertTrue(any(row[0]=='size_reference_setter' and row[6]=='0x5d35ae0' for row in selected))
        self.assertTrue(any(row[0]=='options_attachment' and row[6]=='0x5d356e0' for row in selected))
        self.mutate(0x5d3571c)
        with self.assertRaisesRegex(packet.EvidenceError,'binding field offset'):
            packet.binding_fields(self.image)

    def test_outputs_have_bounded_counts(self):
        summary=json.loads(self.generated['summary.json'])
        self.assertEqual(summary['sha256'],packet.TARGET_SHA256)
        self.assertEqual(summary['counts']['selected_fdes'],26)
        self.assertEqual(summary['counts']['size_cases'],14)
        self.assertEqual(summary['counts']['guard_cases'],32)
        self.assertEqual(summary['counts']['bounded_search_probes'],96)
        self.assertEqual(summary['counts']['plt_links'],3)
        self.assertEqual(summary['counts']['native_cases'],5)
        self.assertEqual(summary['counts']['binding_fields'],4)
        self.assertEqual(summary['counts']['input_flow_sites'],9)
        self.assertEqual(summary['counts']['parent_keys'],2)
        self.assertEqual(summary['counts']['constructor_keys'],2)
        self.assertEqual(summary['counts']['key_label_cases'],4)
        self.assertEqual(summary['counts']['path_guard_cases'],8)
        self.assertEqual(summary['counts']['collection_cases'],6)
        self.assertEqual(len(self.generated),24)


if __name__ == '__main__':
    unittest.main()
