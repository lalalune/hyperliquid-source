"""Target-grounded controls for the node #94 spot metadata codec packet."""
import contextlib
import unittest

from tools import spot_meta_snapshot94 as tool


class SpotMetaSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(tool.BINARY.read_bytes())
        tool.authenticate(cls.data)
        cls.image = tool.Image(cls.data)
        cls.evidence, cls.cases = tool.extract(cls.image)
        _, cls.targets = tool.classifier_table(cls.image)

    @contextlib.contextmanager
    def mutate(self, va, new):
        _, pos = self.image.mapping(va,len(new))
        old = self.data[pos:pos+len(new)]
        try:
            self.data[pos:pos+len(new)] = new
            yield
        finally:
            self.data[pos:pos+len(new)] = old

    def test_fourteen_fields_and_complete_static_decisions(self):
        fields = self.evidence['fields']
        self.assertEqual([x['field'] for x in fields], [
            'spot_infos','token_infos','token_id_to_token','canonical_tokens2',
            'allow_duplicate_token_names','token_to_approx_usdc_pxs',
            'liquid_base_tokens','token_name_to_canonical_deployer',
            'token_to_first_time_enabled_as_quote',
            'quote_token_to_aligned_quote_token_info','liquid_quote_tokens',
            'quote_token_to_status','outr','ta2'])
        self.assertEqual([x['object_offset'] for x in fields],
                         [0x160,0x178,0x1a8,0x190,0x280,0x1c0,0x1d8,
                          0x1f0,0x208,0x220,0x238,0x250,0,0x268])
        self.assertEqual([x['tag'] for x in fields],list(range(14)))
        self.assertEqual(sum(x['missing_label'] is None for x in fields),1)
        self.assertEqual(fields[-1]['field'],'ta2')
        self.assertEqual(len(self.cases),320)
        self.assertEqual(len(self.evidence['functions']),19)
        self.assertEqual(len(self.evidence['classifier_length_targets']),37)

    def test_json_diagnostic_extraction_and_corruption(self):
        records=self.evidence['json_diagnostics']
        self.assertEqual(len(records),27)
        self.assertEqual(sum(x['kind']=='missing' for x in records),13)
        self.assertEqual(sum(x['kind']=='duplicate' for x in records),14)
        self.assertFalse(any(x['field']=='ta2' and x['kind']=='missing' for x in records))
        names=[x['field'] for x in self.evidence['fields']]
        site=int(next(x['label_site'] for x in records
                      if x['field']=='spot_infos' and x['kind']=='missing'),16)
        with self.mutate(site,b'\x90'):
            with self.assertRaisesRegex(tool.EvidenceError,'diagnostic set changed'):
                tool.json_diagnostics(self.image,names)

    def test_classifier_all_single_byte_substitutions(self):
        # Every possible byte replacement, including NUL and non-ASCII.
        # These are synthetic inputs to the fixed compare grammar only.
        fields=self.evidence['fields']
        checked=0
        for row in fields:
            name=row['field'].encode('ascii')
            self.assertEqual(tool.classify(self.image,name,self.targets),row['tag'])
            for i,original in enumerate(name):
                for replacement in range(256):
                    if replacement == original:
                        continue
                    changed=name[:i]+bytes([replacement])+name[i+1:]
                    self.assertEqual(tool.classify(self.image,changed,self.targets),14)
                    checked+=1
        self.assertEqual(checked, sum(len(row['field']) for row in fields) * 255)

    def test_classifier_length_boundaries(self):
        for size in range(65):
            self.assertEqual(tool.classify(self.image,b'\x00'*size,self.targets),14)
        for row in self.evidence['fields']:
            key=row['field'].encode('ascii')
            self.assertEqual(tool.classify(self.image,key[:-1],self.targets),14)
            self.assertEqual(tool.classify(self.image,key+b'_',self.targets),14)

    def test_bad_digest_is_rejected(self):
        with self.mutate(0x2390b60,b'\x90'):
            with self.assertRaisesRegex(tool.EvidenceError,'SHA-256'):
                tool.authenticate(self.data)

    def test_corrupt_body_rejected_even_below_digest_gate(self):
        # Replacing a direct call target remains structurally valid E8, but the
        # captured full-body hash and independently pinned edge must reject it.
        site=0x2390c0c
        old=self.image.read(site+1,1)
        with self.mutate(site+1,bytes([old[0]^1])):
            self.assertNotEqual(tool.call(self.image,site),tool.COMPACT_CALLEES[0])
            with self.assertRaisesRegex(tool.EvidenceError,'body changed'):
                tool.extract(self.image)

    def test_classifier_opcode_and_branch_corruption(self):
        with self.mutate(0x22e0701,b'\x90'):
            with self.assertRaises(tool.EvidenceError):
                tool.classify(self.image,b'ta2',self.targets)
        with self.mutate(0x22e06eb,b'\x90'):
            with self.assertRaises(tool.EvidenceError):
                tool.classifier_table(self.image)
        with self.mutate(0x3d8b80,b'\xff\xff\xff\x7f'):
            with self.assertRaises(tool.EvidenceError):
                tool.classifier_table(self.image)

    def test_mutated_field_reference_and_offset(self):
        self.assertEqual(tool.name(self.image,0x2390bdf)[0],'spot_infos')
        with self.mutate(0x2390bdf,b'\x90'):
            with self.assertRaises(tool.EvidenceError):
                tool.name(self.image,0x2390bdf)
        self.assertEqual(tool.offset(self.image,0x2390bfd),0x160)
        with self.mutate(0x2390bfd,b'\x90'):
            with self.assertRaises(tool.EvidenceError):
                tool.offset(self.image,0x2390bfd)
        # A data change is detected independently by comparing both names.
        ptr=tool.rip(self.image,0x2390bdf)
        with self.mutate(ptr,b'X'):
            with self.assertRaisesRegex(tool.EvidenceError,'classifier/tag mismatch'):
                tool.extract(self.image)

    def test_duplicate_and_missing_corruption(self):
        site=0x1790469
        with self.mutate(site,b'\x0f\x84'):
            with self.assertRaises(tool.EvidenceError):
                tool.duplicate(self.image,site)
        site=0x178c3d4
        ptr=tool.rip(self.image,site)
        with self.mutate(ptr,b'X'):
            self.assertNotEqual(tool.missing(self.image,site),'spot_infos')
            with self.assertRaisesRegex(tool.EvidenceError,'duplicate label differs'):
                tool.extract(self.image)

    def test_missing_and_duplicate_branches_route_to_distinct_templates(self):
        for row in self.evidence['fields']:
            at=int(row['duplicate_branch'],16)
            self.assertEqual(tool.duplicate(self.image,at)[1],row['field'])
            if row['missing_label'] is not None:
                self.assertEqual(tool.missing(self.image,int(row['missing_label'],16)),row['field'])
        self.assertEqual(tool.branch(self.image,0x178f731),0x178f89c)

    def test_fde_record_corruption_rejected(self):
        record=int(self.evidence['functions'][0]['fde'],16)
        # FDE's encoded range is a signed 32-bit value after the start pointer.
        at=record+12
        b=self.image.read(at,1)
        with self.mutate(at,bytes([b[0]^1])):
            with self.assertRaises(ValueError):
                tool.fde_records(self.image)

    def test_unmapped_nobits_and_invalid_ranges_rejected(self):
        for va,n in ((-1,1),(0,0),(2**64-1,8)):
            with self.assertRaises(tool.EvidenceError):
                self.image.read(va,n)
        bss=next(s for s in self.image.sections if s['type']==8 and s['name']=='.bss')
        with self.assertRaises(tool.EvidenceError):
            self.image.read(bss['address'],1)
        text=next(s for s in self.image.sections if s['name']=='.text')
        with self.assertRaises(tool.EvidenceError):
            self.image.read(text['address']+text['size']-1,2)


if __name__=='__main__':
    unittest.main()
