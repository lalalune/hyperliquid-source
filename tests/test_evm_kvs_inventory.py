"""Target-grounded and corruption controls; Python 3.10+ stdlib only (MIT)."""
import copy
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from contextlib import contextmanager

from tools import evm_kvs_inventory as n

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/evm-kvs-inventory-94'
spec = importlib.util.spec_from_file_location('evm_packet_verify', PACKET / 'verify.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = (ROOT / n.TARGET).open('rb')
        cls.data = mmap.mmap(cls.f.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.results = n.build(cls.data)
        cls.e = cls.results['inventory.json']
        cls.image = n.Image(cls.data)
        cls.reloc = n.relative_relocations(cls.image)
        cls.decoded = {int(f['start'], 16): n.decode_fde(cls.image, {
            'start': int(f['start'], 16), 'end': int(f['end_exclusive'], 16)})
            for f in cls.e['fdes']}

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.f.close()

    @contextmanager
    def mutate(self, offset, replacement):
        original = self.data[offset:offset+len(replacement)]
        self.data[offset:offset+len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset+len(replacement)] = original

    @contextmanager
    def packet_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            here = Path(tmp)
            for name in v.MANIFEST | {'MANIFEST.sha256'}:
                shutil.copyfile(PACKET/name, here/name)
            yield here

    def test_target_facts(self):
        v.verify_facts(self.e)
        self.assertEqual(len(self.e['locations']), 24)
        self.assertEqual(len(self.e['location_leas']), 38)
        self.assertEqual(len(self.e['fdes']), 7)

    def test_wrong_digest_fails_closed(self):
        with self.mutate(0x100, b'X'):
            with self.assertRaises(n.EvidenceError): n.build(self.data)

    def test_truncated_input_fails_digest(self):
        with self.assertRaises(n.EvidenceError): n.build(b'\x7fELF')

    def test_missing_section_rejected(self):
        image = n.Image(self.data)
        name = image.by_name['.eh_frame']['name']
        self.assertEqual(name, '.eh_frame')
        # Mutate the section name string, not its payload.
        shstr = image.by_name['.shstrtab']
        off = self.data.find(b'.eh_frame\0', shstr['offset'], shstr['offset'] + shstr['size'])
        self.assertGreaterEqual(off, 0)
        with self.mutate(off, b'X'):
            with self.assertRaises(n.EvidenceError): n.Image(self.data)

    def test_location_length_corruption(self):
        loc = self.e['locations'][0]; slot = int(loc['va'], 16)
        with self.mutate(int(loc['file_offset'], 16)+8, struct.pack('<Q', loc['path_length']-1)):
            with self.assertRaises(n.EvidenceError): n.decode_location(self.image, slot, self.reloc[slot])

    def test_location_zero_line_and_pointer_rejected(self):
        loc = self.e['locations'][0]; slot = int(loc['va'], 16); off = int(loc['file_offset'],16)
        for delta, value in ((16, b'\0'*4), (0, b'\1')):
            with self.subTest(delta=delta), self.mutate(off+delta, value):
                with self.assertRaises(n.EvidenceError): n.decode_location(self.image, slot, self.reloc[slot])

    def test_path_corruption_rejected(self):
        loc = self.e['locations'][0]; slot = int(loc['va'],16)
        with self.mutate(int(loc['path_bytes']['file_offset'],16)+5,b'X'):
            with self.assertRaises(n.EvidenceError): n.decode_location(self.image, slot, self.reloc[slot])

    def test_shifted_lea_rejected(self):
        lea = self.e['location_leas'][0]; site = int(lea['instruction']['va'],16)
        xs = self.decoded[int(lea['owner'],16)]
        with self.assertRaises(n.EvidenceError): n.verified_lea(self.image, xs, site+1, int(lea['location'],16))

    def test_lea_displacement_mutation_rejected(self):
        lea = self.e['location_leas'][0]; site = int(lea['instruction']['va'],16)
        xs = copy.deepcopy(self.decoded[int(lea['owner'],16)])
        insn = next(x for x in xs if x['site']==site)
        insn['raw'] = insn['raw'][:3] + struct.pack('<i',struct.unpack_from('<i',insn['raw'],3)[0]+1)
        with self.assertRaises(n.EvidenceError): n.verified_lea(self.image,xs,site,int(lea['location'],16))

    def test_lea_opcode_and_truncation_rejected(self):
        for raw in (bytes.fromhex('488b0500000000'),bytes.fromhex('488d05000000')):
            with self.subTest(raw=raw), self.assertRaises(n.EvidenceError): n.decode_lea(raw,0)

    def test_decoder_unknown_and_truncated_fail(self):
        for raw in (b'\x0f\x0b\x0f', b'\x48\x8d\x05\x00', b'\xc4\x00'):
            with self.subTest(raw=raw), self.assertRaises(n.EvidenceError):
                n.decode_instruction(raw, 2 if raw.startswith(b'\x0f\x0b') else 0)

    def test_internal_branch_inside_instruction_rejected(self):
        insns = [n.decode_instruction(b'\xeb\x01',0,0x1000), n.decode_instruction(b'\x48\x89\xc0',0,0x1002)]
        with self.assertRaises(n.EvidenceError): n.validate_branch_boundaries(insns,0x1000,0x1005)

    def test_full_decode_reproduces_fde_hash(self):
        for fde in self.e['fdes']:
            rows = self.decoded[int(fde['start'],16)]
            self.assertEqual(hashlib.sha256(b''.join(x['raw'] for x in rows)).hexdigest(),fde['code_sha256'])
            self.assertEqual(sum(len(x['raw']) for x in rows),fde['size'])

    def test_literal_length_pair_and_mutation(self):
        xs = self.decoded[0x1fd7810]
        i = next(i for i,x in enumerate(xs) if x['site']==0x1fd786f)
        pair = n.pointer_length_pair(self.image,xs,i,b'write evm kv batch')
        self.assertEqual(pair['length'],18)
        changed = copy.deepcopy(xs[i:i+3]); changed[2]['raw'] = changed[2]['raw'][:-4]+struct.pack('<i',19)
        with self.assertRaises(n.EvidenceError): n.pointer_length_pair(self.image,changed,0,b'write evm kv batch')

    def test_literal_pointer_register_mutation(self):
        xs = self.decoded[0x1fd7810]; i = next(i for i,x in enumerate(xs) if x['site']==0x1fd786f)
        changed = copy.deepcopy(xs[i:i+3]); changed[1]['raw'] = bytes.fromhex('48895348')
        with self.assertRaises(n.EvidenceError): n.pointer_length_pair(self.image,changed,0,b'write evm kv batch')

    def test_literal_noncontiguous_rejected(self):
        xs = self.decoded[0x1fd7810]; i = next(i for i,x in enumerate(xs) if x['site']==0x1fd786f)
        changed = copy.deepcopy(xs[i:i+3]); changed[1]['site'] += 1
        with self.assertRaises(n.EvidenceError): n.pointer_length_pair(self.image,changed,0,b'write evm kv batch')

    def test_literal_bytes_mutation_rejected(self):
        xs = self.decoded[0x1fd7810]; i = next(i for i,x in enumerate(xs) if x['site']==0x1fd786f)
        target,_ = n.decode_lea(xs[i]['raw'],xs[i]['site']); _,off = self.image.mapping(target)
        with self.mutate(off,b'X'):
            with self.assertRaises(n.EvidenceError): n.pointer_length_pair(self.image,xs,i,b'write evm kv batch')

    def test_counted_chunk_length_and_separator_controls(self):
        anchor = next(a for d in self.e['diagnostics'] for a in d['anchors'] if a['kind']=='counted_ascii_chunks')
        probe = next(d['probe'].encode() for d in self.e['diagnostics'] if anchor in d['anchors'])
        chunk = anchor['chunks'][-1]; pos = int(chunk['record']['file_offset'],16); length = chunk['length']
        for off in (pos,pos+length+1):
            with self.subTest(off=off), self.mutate(off,b'\0'):
                with self.assertRaises(n.EvidenceError): n.counted_fragment(self.image,int(anchor['anchor'],16),int(anchor['occurrence'],16),probe)

    def test_present_unbound_absent(self):
        status = {x['probe']:x['status'] for x in self.e['diagnostics']}
        self.assertEqual(status['RocksDb too large'],'present-but-unbound')
        self.assertEqual(status['evm_kvs_checkpoint'],'present-but-unbound')
        self.assertEqual(status['rocksdb bug'],'absent')
        self.assertTrue(all(not x['anchors'] for x in self.e['diagnostics'] if x['status']!='bound'))

    def test_constants_ambiguous_not_promoted(self):
        c = {x['value']:x for x in self.e['constants']}
        self.assertEqual(c[-1]['status'],'unresolved'); self.assertEqual(len(c[-1]['co_locations']),4)
        self.assertEqual(c[8]['status'],'unresolved')

    def test_edges_and_shifted_target(self):
        self.assertEqual(n.scoped_edges(self.image,self.decoded),self.e['call_edges'])
        changed = copy.deepcopy(self.decoded); x = next(x for x in changed[0x1fd6300] if x['site']==0x1fd64d8)
        x['raw'] = b'\xe8'+struct.pack('<i',struct.unpack_from('<i',x['raw'],1)[0]+1)
        self.assertEqual(len(n.scoped_edges(self.image,changed)),1)

    def test_stale_edge_bytes_rejected(self):
        changed = copy.deepcopy(self.decoded); x = next(x for x in changed[0x1fd6300] if x['site']==0x1fd64d8)
        # Still targets the scoped entry, but differs from actual bytes due to changed site.
        x['raw'] = b'\xe8'+struct.pack('<i',0x1fd7810-x['site']-5)
        x['site'] += 1
        x['raw'] = b'\xe8'+struct.pack('<i',0x1fd7810-x['site']-5)
        with self.assertRaises(n.EvidenceError): n.scoped_edges(self.image,changed)

    def test_metrics_recompute(self):
        e = self.e
        diagnostics, constants, edges = e['diagnostics'], e['constants'], e['call_edges']
        anchors = [a for d in diagnostics for a in d['anchors']]
        all_insns = [x for xs in self.decoded.values() for x in xs]
        transfers = [x for x in all_insns if x['kind'] in ('call_rel32', 'jmp_rel32')]
        expected = {
            'locations': len(e['locations']), 'location_leas': len(e['location_leas']),
            'scoped_fdes': len(e['fdes']),
            'unique_line_column': len({(x['line'],x['column']) for x in e['locations']}),
            'scoped_fde_bytes': sum(x['size'] for x in e['fdes']),
            'decoded_instructions': len(all_insns), 'diagnostics_probed': len(diagnostics),
            'diagnostics_bound': sum(d['status']=='bound' for d in diagnostics),
            'diagnostics_unresolved': sum(d['status']=='present-but-unbound' for d in diagnostics),
            'diagnostics_absent': sum(d['status']=='absent' for d in diagnostics),
            'pointer_length_anchors': sum(a['kind']!='counted_ascii_chunks' for a in anchors),
            'counted_fragment_anchors': sum(a['kind']=='counted_ascii_chunks' for a in anchors),
            'constants_bound': sum(c['status']=='bound' for c in constants),
            'constants_unresolved': sum(c['status']=='unresolved' for c in constants),
            'scoped_rel32_calls': sum(x['instruction']['kind']=='call_rel32' for x in edges),
            'scoped_rel32_jumps': sum(x['instruction']['kind']=='jmp_rel32' for x in edges),
            'out_of_scope_rel32_transfers': len(transfers)-len(edges),
        }
        self.assertEqual(e['metrics'], expected)

    def test_relocation_addend_corruption_rejected(self):
        loc = self.e['locations'][0]; slot = int(loc['va'],16)
        off = int(loc['relocation']['entry_file_offset'],16) + 16
        addend = self.reloc[slot]['target']
        with self.mutate(off, struct.pack('<q',addend+1)):
            changed = n.relative_relocations(self.image)
            with self.assertRaises(n.EvidenceError): n.decode_location(self.image,slot,changed[slot])

    def test_byte_identical_and_document_counts(self):
        v.verify_outputs(PACKET,n,self.results)
        for name in ('README.md','RESULT.md'):
            with self.subTest(name=name), self.packet_copy() as here:
                p=here/name; p.write_text(p.read_text().replace('| locations | 24 |','| locations | 25 |'))
                with self.assertRaises(ValueError): v.verify_docs(here,n,self.e['metrics'])

    def test_manifest_whitelist_and_tampering(self):
        v.verify_manifest(PACKET)
        for kind in ('extra','symlink','directory','missing','duplicate','traversal','modified'):
            with self.subTest(kind=kind), self.packet_copy() as here:
                manifest=here/'MANIFEST.sha256'; lines=manifest.read_text().splitlines()
                if kind=='extra': (here/'extra').write_text('x')
                elif kind=='symlink': (here/'extra').symlink_to('README.md')
                elif kind=='directory': (here/'extra').mkdir()
                elif kind=='missing': manifest.write_text('\n'.join(lines[1:])+'\n')
                elif kind=='duplicate': manifest.write_text('\n'.join(lines+[lines[0]])+'\n')
                elif kind=='traversal': manifest.write_text(lines[0][:66]+'../README.md\n'+'\n'.join(lines[1:])+'\n')
                else: (here/'RESULT.md').write_text('changed')
                with self.assertRaises(ValueError): v.verify_manifest(here)

    def test_rehashed_corrupt_json_still_fails_regeneration(self):
        with self.packet_copy() as here:
            p=here/'inventory.json'; x=json.loads(p.read_text()); x['locations'][0]['line']+=1; p.write_bytes(n.render(x))
            (here/'MANIFEST.sha256').write_text(''.join(hashlib.sha256((here/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in sorted(v.MANIFEST)))
            v.verify_manifest(here)
            with self.assertRaises(ValueError): v.verify_outputs(here,n,self.results)


if __name__ == '__main__': unittest.main()
