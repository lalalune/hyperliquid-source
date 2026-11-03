"""Native target evidence and actual dl-route counterfactuals."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import priority_prefix_dl_route_static as subject
from elf_index import sections


class PriorityPrefixDlRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs=sections(cls.data);cls.report=subject.analyze(cls.data)

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);o=self.offset(va);b[o]=b[o]^1 if value is None else value
        return b

    def test_native_regeneration_matches_retained_packet(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),378)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_census_facts(self):
        census=self.report['census']
        for key,spec in subject.CALLERS.items():
            row=census['decoder_callers'][key]
            self.assertEqual(row['e8_call_sites'],
                             [hex(s) for s in subject.PARENTS['parent_'+key[-1]]['sites']])
            self.assertEqual((row['e9_jumps'],row['rel8_jumps'],row['conditional_jumps'],
                              row['rip_relative_references'],row['rela_dyn_addends'],
                              row['raw_qword_occurrences']),(0,0,0,0,0,0))
        self.assertEqual(census['decoder_callers']['caller_a']['raw_dword_occurrences'],[])
        self.assertEqual(census['decoder_callers']['caller_c']['raw_dword_occurrences'],[])
        note=census['decoder_callers']['caller_b']['raw_dword_occurrences']
        self.assertEqual(len(note),1)
        self.assertEqual(note[0]['file_offset'],'0xe7a3e0')
        self.assertEqual(note[0]['section'],'.eh_frame')
        for key,spec in subject.ALTS.items():
            row=census['alternates'][key]
            ca=subject.CALLERS[spec['caller']]['fde'][0]
            self.assertEqual(row['e8_call_sites'],
                             [hex(ca+subject.OFF['site2_alt_call']),hex(ca+subject.OFF['alt']+9)])
            self.assertEqual(row['raw_qword_occurrences'],0)
        self.assertEqual(census['slot_bindings'],
                         {'descriptor':hex(subject.DESCRIPTOR_FN[0]),
                          'gate':hex(subject.GATE_FN[0]),
                          'helper_first':hex(subject.HELPER_SLOT_FN[0])})
        self.assertEqual(census['established_rdx_at_decoder_entries'],[0])
        self.assertEqual(self.report['route_model'],
                         {'dl_values_at_censused_entries':[0],
                          'route_for_dl_zero':'byte-fed entry',
                          'route_for_dl_nonzero':'alternate (traced here)',
                          'alternate_reachable_from_censused_callers':False})
        self.assertFalse(self.report['captured_code_executed'])

    def test_trace_facts(self):
        traces={t['alternate']:t for t in self.report['traces']}
        self.assertEqual(set(traces),{'alt_a','alt_b','alt_c'})
        for key,spec in subject.ALTS.items():
            trace=traces[key]
            self.assertEqual(trace['slice_stores']['discriminant_byte'],{'at':'rsp+0x18','value':6})
            self.assertEqual(trace['slice_stores']['payload_pointer'],{'from':'rsi','at':'rsp+0x20'})
            self.assertEqual(trace['slice_stores']['payload_length'],{'from':'rdx','at':'rsp+0x28'})
            self.assertEqual(trace['helper']['target'],hex(subject.HELPERS[spec['helper']]['fde'][0]))
            self.assertEqual(trace['helper']['args']['rsi'],hex(subject.PIECE_VA))
            self.assertEqual(trace['result_write'],{'at':'[out]','qword':2})
            self.assertFalse(trace['calls_entry'])
            self.assertFalse(trace['dereferences_payload'])
        self.assertEqual(self.report['piece']['bytes_hex'],subject.PIECE_HEX)
        self.assertEqual(self.report['piece']['legible_fragments'],['invalid type: ',', expected '])
        callers={c['caller']:c for c in self.report['caller_boundaries']}
        for key,spec in subject.CALLERS.items():
            start=spec['fde'][0];row=callers[key]
            self.assertEqual(row['dl_test'],hex(start+0xe67))
            self.assertEqual(row['alt_sites'],{'dl_tail':hex(start+subject.OFF['alt']+9),
                                               'gated':hex(start+subject.OFF['site2_alt_call'])})
            self.assertEqual(row['gate']['slot'],hex(subject.SLOTS['gate']))
            self.assertEqual(row['entry_call_site'],hex(start+subject.OFF['call']))
        for parent in self.report['parents']:
            self.assertEqual(parent['rdx_at_call'],0)
            self.assertEqual(parent['pre_call_bytes'],'4c89f631d2')

    def test_alternate_counterfactuals(self):
        start=subject.ALTS['alt_a']['fde'][0]
        # Discriminant immediate, the helper call displacement and the
        # payload-length store opcode all live inside the owner template.
        for va in [start+0x17,start+0x6a,start+0x0d]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'alternate trace'):
                    subject.analyze(self.mutate(va))

    def test_caller_window_counterfactuals(self):
        start=subject.CALLERS['caller_a']['fde'][0]
        # dl test byte in the shared tail, and the gated site's mov rsi,r15.
        for va in [start+0xe68,start+subject.OFF['site2_alt_call']-6]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'caller boundary'):
                    subject.analyze(self.mutate(va))

    def test_parent_counterfactual(self):
        site=subject.PARENTS['parent_a']['sites'][0]
        with self.assertRaisesRegex(ValueError,'parent'):
            subject.analyze(self.mutate(site-1))

    def test_census_counterfactual(self):
        # Turning a parent's E8 call into an E9 jump breaks the census:
        # caller_a loses an E8 site and gains an E9 reference.
        site=subject.PARENTS['parent_a']['sites'][0]
        with self.assertRaisesRegex(ValueError,'census'):
            subject.analyze(self.mutate(site,0xe9))

    def test_body_and_fde_controls(self):
        with self.assertRaisesRegex(ValueError,'body changed'):
            subject.analyze(self.mutate(subject.HELPERS['helper_a']['fde'][0]+0x30))
        fde=int(self.report['owners'][0]['frames']['fde']['va'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            subject.analyze(self.mutate(fde+12))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(subject.ALTS['alt_a']['fde'][0]))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
