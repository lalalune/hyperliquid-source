import hashlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import re21_inspected_call94 as p


class InspectedCallEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = p.TARGET.read_bytes()
        cls.secs = p.sections(cls.data)
        cls.evidence = p.collect(cls.data)
        cls.rels = p.relocations(cls.data, cls.secs)

    def test_identity_and_corruption(self):
        p.authenticate(self.data)
        data = bytearray(self.data)
        data[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest'):
            p.authenticate(data)
        with self.assertRaises(ValueError):
            p.authenticate(b'')

    def test_every_retained_file_matches_recollection(self):
        folder = p.ROOT / 'research/work-items/RE-021-inspected-call-loop-94'
        for name, expected in p.render(self.evidence).items():
            with self.subTest(name=name):
                self.assertEqual((folder / name).read_bytes(), expected.encode())

    def test_exact_selected_corpus(self):
        counts = self.evidence['summary']['counts']
        self.assertEqual((counts['selected_fdes'], counts['selected_code_bytes']), (12, 6324))
        self.assertEqual((counts['address_lanes'], counts['opcode_relocations']), (40, 512))
        self.assertEqual((counts['lsdas'], counts['lsda_call_sites']), (6, 33))
        for row in self.evidence['functions']:
            a, end = int(row[0],16), int(row[1],16)
            code = p.read(self.data,self.secs,a,end-a,True)
            self.assertEqual(hashlib.sha256(code).hexdigest(), row[7])

    def test_selected_fde_missing_and_duplicate_fail(self):
        fdes = []
        for r in self.evidence['functions']:
            fdes.append({'start':int(r[0],16),'end':int(r[1],16),'index':0})
        p.selected_fdes(self.data,self.secs,fdes)
        with self.assertRaisesRegex(ValueError,'ambiguous FDE'):
            p.selected_fdes(self.data,self.secs,fdes+fdes[:1])
        with self.assertRaisesRegex(ValueError,'ambiguous FDE'):
            p.selected_fdes(self.data,self.secs,fdes[1:])

    def test_all_reviewed_pins_reject_mutation(self):
        data=bytearray(self.data)
        for name,site,expected in p.PINS:
            with self.subTest(pin=name):
                off=p.file_offset(self.secs,site,1,True)
                data[off]^=1
                with self.assertRaisesRegex(ValueError,'bytes changed'):
                    p.check_pin(data,self.secs,site,expected)
                data[off]^=1

    def test_file_backed_ranges_reject_bss_crossing_and_ambiguity(self):
        sections=[{'type':1,'flags':6,'address':0x1000,'size':8,'offset':0},
                  {'type':8,'flags':6,'address':0x2000,'size':8,'offset':8}]
        self.assertEqual(p.file_offset(sections,0x1000,8,True),0)
        for va,n in ((0x1007,2),(0x2000,1),(0x3000,1),(0x1000,0),(-1,1)):
            with self.subTest(va=va,n=n), self.assertRaises(ValueError):
                p.file_offset(sections,va,n,True)
        with self.assertRaises(ValueError):
            p.file_offset(sections+[dict(sections[0])],0x1000,1,True)
        with self.assertRaises(ValueError):
            p.file_offset([dict(sections[0],flags=2)],0x1000,1,True)

    def test_selected_edges_and_wrong_displacements(self):
        for _, site, target in p.EDGES:
            raw,got=p.read_edge(self.data,self.secs,site,target)
            self.assertEqual(got,target)
            changed=bytearray(raw);changed[-1]^=1
            self.assertNotEqual(p.relative(changed,site),target)
        for raw in (b'',b'\xe8',b'\x90\x00',b'\x0f\x80'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                p.relative(raw,0x1000)

    def test_relocations_and_invalid_records(self):
        for kind,base in p.TABLES.items():
            slot=base+8*0xf4
            got=p.relative_slot(self.data,self.secs,self.rels,slot,p.HANDLERS[kind])
            self.assertEqual(int(got['addend'],16),p.HANDLERS[kind])
            entry=self.rels[slot][0]
            for bad in ([],[entry,entry],[(7,entry[1],entry[2])],[(8,entry[1]+1,entry[2])]):
                with self.subTest(kind=kind,bad=bad):
                    altered=dict(self.rels);altered[slot]=bad
                    with self.assertRaises(ValueError):
                        p.relative_slot(self.data,self.secs,altered,slot,p.HANDLERS[kind])

    def test_each_opcode_table_entry_has_one_symbol_free_relative_record(self):
        rows=self.evidence['tables']
        self.assertEqual(len(rows),512)
        for label,base in sorted(p.TABLES.items()):
            table=[r for r in rows if r[0]==label]
            self.assertEqual([r[2] for r in table],list(range(256)))
            for r in table:
                self.assertEqual(int(r[3],16),base+8*r[2])
                info=struct.unpack_from('<Q',bytes.fromhex(r[7]),8)[0]
                self.assertEqual(info,8)

    def test_descriptor_targets_are_distinct(self):
        r=self.evidence['wrappers']
        self.assertEqual({(int(x['descriptor'],16),int(x['addend'],16)) for x in r},
                         {(0x56e70f0,0x329a050),(0x56e70f0,0x3291a00),
                          (0x56ee670,0x3587550),(0x56f38e0,0x37d05b0)})
        self.assertEqual(len({x['addend'] for x in r}),4)

    def test_symbolic_copy_import_and_corruptions(self):
        imp=p.imported_slot(self.data,self.secs,self.rels,0x576dfe0,'memcpy')
        self.assertEqual(imp['name'],'memcpy')
        self.assertGreater(imp['symbol_index'],0)
        slot=0x576dfe0
        info,addend,offset=self.rels[slot][0]
        for entries in ([],[(info,addend,offset),(info,addend,offset)],
                        [(8,addend,offset)],[(info,1,offset)]):
            altered=dict(self.rels);altered[slot]=entries
            with self.assertRaises(ValueError):
                p.imported_slot(self.data,self.secs,altered,slot,'memcpy')
        data=bytearray(self.data)
        name_at=int(imp['name_file_offset'],16);data[name_at]^=1
        with self.assertRaises(ValueError):
            p.imported_slot(data,self.secs,self.rels,slot,'memcpy')

    def test_cost_instructions_reject_corruption(self):
        self.assertEqual(p.read_costs(self.data,self.secs),self.evidence['costs'])
        data=bytearray(self.data)
        for va in (0x37bf48c,0x37be95c,0x37be961):
            pos=p.file_offset(self.secs,va,1,True);data[pos]^=1
            with self.assertRaises(ValueError):p.read_costs(data,self.secs)
            data[pos]^=1

    def test_input_copy_slots_constants_and_corruption(self):
        for base in p.TABLES.values():
            slot=base+8*0x37
            record=p.relative_slot(self.data,self.secs,self.rels,slot,0x37b9060)
            self.assertEqual(record['addend'],'0x37b9060')
        self.assertEqual(p.input_copy_constants(self.data,self.secs),
                         {'rounding_add':31,'shift':5,'per_word':3,'base':3})
        self.assertEqual(p.imported_slot(self.data,self.secs,self.rels,0x576e1f8,'memset')['name'],'memset')
        data=bytearray(self.data)
        for address in (0x37b90f0,0x37b90ff,0x37b9100,0x37b9107):
            off=p.file_offset(self.secs,address,1,True);data[off]^=1
            with self.subTest(address=address), self.assertRaises(ValueError):
                p.input_copy_constants(data,self.secs)
            data[off]^=1

    def test_input_copy_source_and_charge_boundaries(self):
        constants=self.evidence['copy_constants']
        for size in (0,1,31,32,33,212,213,214):
            for offset in (0,1,212,213,214,1<<64):
                plan=p.input_copy_plan(size,offset,213,constants)
                oracle=min(size,max(0,213-min(offset,(1<<64)-1)))
                self.assertEqual(plan['prefix'],oracle)
                self.assertEqual(plan['zero_fill'],size-oracle)
                self.assertEqual(plan['charge'],3+3*((size+31)//32))
        largest=(1<<64)-1
        self.assertEqual(p.input_copy_plan(largest,0,0,constants)['charge'],3+3*(largest>>5))
        self.assertEqual(p.input_copy_plan(2,largest-1,largest,constants)['outcome'],'source_add_failure')
        for args in ((-1,0,1),(1,-1,1),(1,1<<256,1),(1,0,1<<64)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                p.input_copy_plan(*args,constants)

    def test_conditional_input_to_frame_copy(self):
        source=bytes(range(213))
        for size in (212,213,214):
            plan=p.input_copy_plan(size,0,len(source),self.evidence['copy_constants'])
            memory=bytearray(256)
            memory[16:16+plan['prefix']]=source[:plan['prefix']]
            memory[16+plan['prefix']:16+size]=bytes(plan['zero_fill'])
            frame_payload=bytes(memory[16:16+size])
            expected=source[:size]+bytes(max(0,size-len(source)))
            self.assertEqual(frame_payload,expected)

    def test_adapter_comparison_masks_only_reviewed_pc_relative_fields(self):
        a=bytes.fromhex(self.evidence['bodies']['0x3291a00'])
        b=bytes.fromhex(self.evidence['bodies']['0x329a050'])
        comparison=p.compare_adapters(a,b)
        self.assertEqual(len(comparison['masks']),8)
        self.assertEqual(sum(x['length'] for x in comparison['masks']),32)
        for offset in (0x1,0x3c,0x7e,0xf8):
            bad=bytearray(a);bad[offset]^=1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                p.compare_adapters(bad,b)

    def test_lanes_use_only_low_160_stack_bits(self):
        for handler in p.HANDLERS.values():
            rows=[r for r in self.evidence['lanes'] if int(r[0],16)==handler]
            self.assertEqual([r[2] for r in rows],list(range(19,-1,-1)))
            def observed(word):
                little=word.to_bytes(32,'little')
                return bytes(little[r[2]] for r in rows)
            for bit in range(256):
                got=observed(1 << bit)
                expected=((1 << bit)&((1 << 160)-1)).to_bytes(20,'big')
                self.assertEqual(got,expected)
            self.assertEqual(observed(9),bytes(19)+b'\x09')

    def test_each_lane_stage_rejects_changed_operands(self):
        for name, base in p.HANDLERS.items():
            row=next(x for x in self.evidence['functions'] if int(x[0],16)==base)
            body=p.read(self.data,self.secs,base,int(row[1],16)-base,True)
            pos=0x39d if name=='early' else 0x3c5
            self.assertEqual(len(p.lane_rows(body,base,pos)),20)
            for offset in (0x51,0x55,0x1f4,0x1fe,pos,pos+18):
                with self.subTest(handler=name,offset=offset):
                    altered=bytearray(body);altered[offset]^=1
                    with self.assertRaises(ValueError):
                        p.lane_rows(altered,base,pos)

    def test_payload_length_copies_and_corruption_controls(self):
        rows=p.payload_flow(self.data,self.secs)
        self.assertEqual([r['frame_length_offset'] for r in rows],[0x38,0x38])
        for row in rows:
            for length in (212,213,214):
                result=bytearray(48)
                struct.pack_into('<Q',result,row['helper_output_offset'],length)
                temp=bytearray(256)
                save_at=row['handler_save_stack']
                temp[save_at:save_at+len(result)]=result
                word=temp[save_at+row['helper_output_offset']:save_at+row['helper_output_offset']+8]
                frame=bytearray(160)
                frame[row['frame_length_offset']:row['frame_length_offset']+8]=word
                self.assertEqual(struct.unpack_from('<Q',frame,0x38)[0],length)
        data=bytearray(self.data)
        for site,displacement in ((0x37bd2a6,4),(0x37bd4af,4),(0x37bd530,9),
                                  (0x37bf3a8,4),(0x37bf4f7,14),(0x37beb81,4)):
            off=p.file_offset(self.secs,site+displacement,1,True);data[off]^=1
            with self.subTest(site=site), self.assertRaises(ValueError):p.payload_flow(data,self.secs)
            data[off]^=1

    def test_charge_boundaries_and_host_precedence(self):
        c=self.evidence['costs']
        self.assertEqual(c,{'early':700,'low':100,'high':2600})
        self.assertEqual([p.host_cost(x,c) for x in (0,1,2,0x100,0x101,0x200,0x201)],
                         [200,2700,None,2700,5200,100,2600])
        self.assertEqual(p.host_cost(2,c,True),None)
        self.assertEqual(p.host_cost(0x201,c,True),700)
        for row in self.evidence['synthetic_cases']:
            if row['result']=='underflow':
                self.assertLess(row['available'],row['cost'])
            elif row['result']=='continue':
                left=row['available']-row['cost']
                self.assertEqual(row['maximum_forwarded'],left-left//64)
        for x in (-1,1<<24,1.0):
            with self.assertRaises(ValueError): p.host_cost(x,c)

    def test_landing_protects_old_action_drop(self):
        tables={x['function']:x for x in self.evidence['exceptions']}
        for fn,call,land in (('0x37be6a0',0x37beb9b,'0x37bebde'),
                             ('0x37bf1d0',0x37bf6a3,'0x37bf6e6'),
                             ('0x37a5840',0x37a5865,'0x37a59a1'),
                             ('0x37a59c0',0x37a59e5,'0x37a5b16')):
            matches=[e for e in tables[fn]['entries'] if int(e['start'],16)<=call<int(e['start'],16)+e['size']]
            self.assertEqual(len(matches),1)
            self.assertEqual(matches[0]['landing'],land)
            self.assertEqual(matches[0]['action'],0)

    def test_exception_header_corruption_rejected(self):
        row=next(x for x in self.evidence['functions'] if x[0]=='0x37be6a0')
        f={'start':int(row[0],16),'end':int(row[1],16),'lsda':int(row[6],16)}
        self.assertGreater(len(p.exceptions(self.data,self.secs,f)['entries']),0)
        data=bytearray(self.data); pos=p.file_offset(self.secs,f['lsda'],1);data[pos]=0
        with self.assertRaises(ValueError): p.exceptions(data,self.secs,f)

    def test_action_table_slots_are_in_the_selected_body(self):
        rows=self.evidence['action_table']
        self.assertEqual([int(r['target'],16) for r in rows],
                         [0x37f95b3,0x37f95fe,0x37f95d0,0x37f95e2])
        # An instruction-derived projection of the comparison and clamp.
        for tag in range(256):
            idx=3 if tag<0x6c else tag-0x6c
            dest=rows[idx]['target'] if idx<4 else None
            if tag==0x6c: self.assertEqual(dest,'0x37f95b3')
            if tag>=0x70: self.assertIsNone(dest)


if __name__=='__main__':
    unittest.main()
