"""Native target evidence and actual bin-supply counterfactuals."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import priority_prefix_caller_static as subject
from elf_index import sections


class PriorityPrefixCallerTests(unittest.TestCase):
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
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']),47193)
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGET,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_supply_model_contract(self):
        model=self.report['supply_model']
        self.assertEqual(model['header_bytes'],subject.MARKERS)
        self.assertEqual(model['error_qword'],'0x2500000003')
        for marker,header in subject.MARKERS.items():
            for length in (0,1,3,6,300):
                with self.subTest(marker=marker,length=length):
                    # One byte short of the header: never reaches the tail.
                    self.assertEqual(subject.supply_route(marker,header-1,length,0),
                                     ('short_header',None))
                    # Header complete but payload short: pinned error record.
                    if length:
                        self.assertEqual(subject.supply_route(marker,header+length-1,length,0),
                                         ('error_record',subject.ERROR_QWORD))
                    # Exact fit: dl picks the entry or the alternate decoder.
                    self.assertEqual(subject.supply_route(marker,header+length,length,0),
                                     ('entry',length))
                    self.assertEqual(subject.supply_route(marker,header+length,length,1),
                                     ('nested',length))
                    # Surplus bytes are not capped by the caller.
                    self.assertEqual(subject.supply_route(marker,header+length+9,length,0),
                                     ('entry',length))

    def test_trace_facts(self):
        traces={t['caller']:t for t in self.report['caller_traces']}
        self.assertEqual(set(traces),{'caller_a','caller_b','caller_c'})
        for key,spec in subject.CALLERS.items():
            start=spec['fde'][0];trace=traces[key]
            self.assertEqual(trace['landings']['0xc5'],hex(start+0xb4b))
            self.assertEqual(trace['landings']['0xc6'],hex(start+0xb2c))
            self.assertEqual(trace['landings']['0xc4'],hex(start+0xc05))
            self.assertEqual(trace['state']['call_target'],hex(subject.ENTRIES[spec['entry']][0]))
            self.assertEqual(trace['state']['call_site'],hex(start+subject.OFF['call']))
            self.assertEqual(trace['alternate']['call_target'],hex(spec['alt_target']))
            self.assertEqual(trace['error']['record_qword'],'0x2500000003')
            self.assertEqual(trace['error']['common_tail_qword'],2)
            self.assertEqual(trace['header_bytes'],subject.MARKERS)
        parents={p['parent']:p for p in self.report['parents']}
        for key,spec in subject.PARENTS.items():
            self.assertEqual(parents[key]['call_sites'],[hex(s) for s in spec['sites']])
            self.assertEqual(parents[key]['rdx_at_call'],0)
        self.assertEqual(self.report['census'],
                         {'entry_direct_callers':{'entry_a':1,'entry_b':1,'entry_c':1},
                          'caller_direct_callers':{'caller_a':2,'caller_b':2,'caller_c':2},
                          'relocation_references':0,'address_as_data':0})
        self.assertEqual(self.report['entry_citation']['body_sha256'],
                         {k:subject.ENTRIES[k][2] for k in subject.ENTRIES})
        self.assertFalse(self.report['captured_code_executed'])

    def test_caller_window_counterfactuals(self):
        start=subject.CALLERS['caller_a']['fde'][0]
        # Entry call displacement, the error-record immediate and the dl
        # branch opcode all live inside pinned caller windows.
        for va in [start+subject.OFF['call']+1,start+subject.OFF['error_block']+6,start+0xe6a]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'caller trace'):
                    subject.analyze(self.mutate(va))

    def test_jump_table_counterfactual(self):
        table=subject.CALLERS['caller_a']['table']
        with self.assertRaisesRegex(ValueError,'jump table'):
            subject.analyze(self.mutate(table+4*0xc5))

    def test_parent_counterfactual(self):
        site=subject.PARENTS['parent_a']['sites'][0]
        with self.assertRaisesRegex(ValueError,'parent'):
            subject.analyze(self.mutate(site-1))

    def test_body_and_fde_controls(self):
        with self.assertRaisesRegex(ValueError,'body changed'):
            subject.analyze(self.mutate(subject.ENTRIES['entry_a'][0]+0x100))
        fde=int(self.report['owners'][3]['frames']['fde']['va'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            subject.analyze(self.mutate(fde+12))

    def test_public_identity_rejection_precedes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'changed';out=Path(directory)/'out'
            p.write_bytes(self.mutate(subject.CALLERS['caller_a']['fde'][0]))
            for path in [p,subject.ROOT/'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError,'pinned node115'):
                    subject.generate(path,out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(p,out)
            self.assertFalse(out.exists())


if __name__=='__main__':
    unittest.main()
