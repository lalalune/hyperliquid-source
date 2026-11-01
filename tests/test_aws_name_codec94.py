"""Static decoder controls; none executes the captured node or machine code."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import aws_name_codec94 as codec


class CodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = codec.Image((ROOT / 'artifacts/node/94/hl-node').read_bytes())
        cls.record = codec.collect(cls.image)
        # Reuse one buffer for mutations rather than retaining per-test ELF copies.
        cls.image.blob = bytearray(cls.image.blob)

    def corrupt(self, address, replacement):
        im = self.image
        off = im.offset(address, len(replacement))
        original = im.blob[off:off + len(replacement)]
        im.blob[off:off + len(replacement)] = replacement
        try:
            with self.assertRaises(ValueError):
                codec.collect(im)
        finally:
            im.blob[off:off + len(replacement)] = original

    def test_full_input_authentication(self):
        im = self.image
        off = im.offset(codec.PARSER, 1)
        original = im.blob[off]
        im.blob[off] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                codec.Image(im.blob)
        finally:
            im.blob[off] = original
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            codec.Image(b'\x7fELF')

    def test_real_fdes_and_complete_partitions(self):
        c = self.record['counts']
        self.assertEqual(c, {'recognizer_predicates': 76, 'renderer_leaves': 76,
                             'length_buckets': 12, 'parser_instructions': 550,
                             'parser_covered_bytes': 2174, 'renderer_covered_bytes': 1618})
        for function in self.record['functions']:
            self.assertEqual(int(function['end'], 16)-int(function['start'], 16), function['size'])
        self.assertEqual([f['end'] for f in self.record['functions']], ['0x164d62e', '0x164cda2'])

    def test_independent_predicates_match_render_leaves(self):
        parser = self.record['parser']['rows']
        render = self.record['renderer']['rows']
        self.assertEqual({r['result'] for r in parser}, set(range(76)))
        self.assertEqual({r['text'] for r in parser}, {r['text'] for r in render})
        for p, r in zip(parser, render):
            with self.subTest(tag=p['result']):
                self.assertEqual((p['text_hex'], p['length']), (r['text_hex'], r['length']))
                self.assertEqual(p['result'], r['tag'])
        self.assertEqual(parser[32]['text'], 'NvTestnet')
        self.assertEqual(parser[72]['predicate'], 'zero => 72; nonzero => 76')
        self.assertEqual(parser[75]['predicate'], 'zero => 75; nonzero => 76')

    def test_prior_table_is_only_a_cross_check(self):
        prior=self.record['prior_table_comparison']
        self.assertEqual((prior['entries_compared'],prior['same_pointer'],
                          prior['equal_text_at_different_pointer']), (76,14,62))
        # Alter a prior table pointer without changing either new code body.
        im=self.image
        slot=codec.PRIOR_TABLE
        old=im.relocations[slot]
        im.relocations[slot]=(old[0],old[1]+1)
        try:
            with self.assertRaisesRegex(ValueError,'spelling disagree'):
                codec.collect(im)
        finally:
            im.relocations[slot]=old

    def test_length_buckets_and_load_bounds(self):
        parser = self.record['parser']
        self.assertEqual((parser['minimum_length'], parser['maximum_length'], parser['failure_value']), (2, 13, 76))
        self.assertEqual([r['accepted'] for r in parser['buckets']], [9, 2, 1, 0, 0, 1, 13, 20, 11, 11, 6, 2])
        # Outside [2,13], (len-2) mod 2^64 > 11, even for zero/one.
        for n in [0,1,14,15,255,2**32,2**63,2**64-1]:
            self.assertGreater((n-2) % 2**64, 11)
        for row in parser['rows']:
            self.assertEqual(len(bytes.fromhex(row['text_hex'])), row['length'])

    def test_contract_boundary_corpus(self):
        # These are tests of the statically extracted contract, not target runs.
        parsed = {bytes.fromhex(r['text_hex']): r['result'] for r in self.record['parser']['rows']}
        rendered = {bytes.fromhex(r['text_hex']): r['tag'] for r in self.record['renderer']['rows']}
        for name in rendered:
            variants = [b'',name[:-1],name+b'\0',b' '+name,name+b' ',name.lower(),b'"'+name+b'"']
            variants += [name[:i]+b'\x00'+name[i+1:] for i in range(len(name))]
            for value in variants:
                with self.subTest(value=value):
                    self.assertEqual(parsed.get(value,76), rendered.get(value,76))
            for value in [b' '+name,name+b' ',name+b'\0',b'"'+name+b'"']:
                self.assertNotIn(value, parsed)

    def test_branch_and_return_corruption(self):
        for address, value in [(0x164cdbb,b'\0'),  # range failure rel32
                               (0x164cdd4,b'\x85'), # equality inverted
                               (0x164d590,b'\x21'), # NvTestnet returns wrong code
                               (0x164d055,b'\x90'), # folded failure arithmetic
                               (0x164d458,b'\x29'), # second folded failure arithmetic
                               (0x164ce94,b'\x31'), # no modeled equality flag after XOR
                               (0x164ce7e,b'\x66'), # unmodeled 16-bit MOV form
                               (0x164d62d,b'\x90')]: # final ret
            with self.subTest(address=hex(address)):
                self.corrupt(address,value)

    def test_length_and_input_load_corruption(self):
        for address,value in [(0x164cdb3,b'\xfd'),(0x164cdb7,b'\x0c'),
                              (0x164ce8e,b'\x09')]:
            with self.subTest(address=hex(address)):
                self.corrupt(address,value)

    def test_dispatch_corruption(self):
        ptable=int(self.record['parser']['table'],16)
        rtable=int(self.record['renderer']['table'],16)
        for address,replacement in [(ptable,struct.pack('<i',0)),
                                    (ptable,self.image.read(ptable+4,4)),
                                    (rtable,self.image.read(rtable+4,4)),
                                    (rtable,struct.pack('<i',codec.RENDERER-ptable))]:
            with self.subTest(address=hex(address),replacement=replacement.hex()):
                self.corrupt(address,replacement)

    def test_render_pool_and_leaf_corruption(self):
        for row in self.record['renderer']['rows']:
            with self.subTest(tag=row['tag']):
                arm=int(row['arm'],16)
                self.corrupt(arm+8,b'\xff')
        row=self.record['renderer']['rows'][32]
        self.corrupt(int(row['text_va'],16),b'n')
        self.corrupt(int(row['arm'],16)+15,b'\xe8')

    def test_relocation_and_fde_boundary_controls(self):
        im=self.image
        sink=int(self.record['renderer']['rows'][0]['tail_slot'],16)
        old=im.relocations.pop(sink)
        try:
            with self.assertRaisesRegex(ValueError,'relocation'):
                codec.collect(im)
        finally:
            im.relocations[sink]=old
        im.relocations[sink]=(old[0], 0)
        try:
            with self.assertRaisesRegex(ValueError,'executable'):
                codec.collect(im)
        finally:
            im.relocations[sink]=old
        for start in [codec.PARSER,codec.RENDERER]:
            old=im.fdes[start]['end']
            im.fdes[start]['end']=old-1
            try:
                with self.assertRaises(ValueError):
                    codec.collect(im)
            finally:
                im.fdes[start]['end']=old

    def test_file_backing_and_ranges(self):
        im=self.image
        for address,size in [(0,0),(-1,1),(2**64,1),(codec.PARSER,-1)]:
            with self.assertRaises(ValueError):
                im.read(address,size)
        nobits=next(s for s in im.sections if s['name']=='.bss' and s['type']==8)
        with self.assertRaises(ValueError):
            im.read(nobits['address'],1)
        fake=dict(next(s for s in im.sections if s['name']=='.text'))
        im.sections.append(fake)
        try:
            with self.assertRaises(ValueError):
                im.read(codec.PARSER,1)
        finally:
            im.sections.pop()

    def test_constraint_algebra_controls(self):
        load=tuple(frozenset([('input',i)]) for i in range(2))
        good=codec.xor(load,codec.constant(0x6345,2),2)
        self.assertEqual(codec.constraints(good,2),b'Ec')
        with self.assertRaisesRegex(ValueError,'every input'):
            codec.constraints(good,3)
        with self.assertRaisesRegex(ValueError,'beyond'):
            codec.constraints(good,1)
        bad=codec.xor(load,codec.constant(0x6145,2),2)
        with self.assertRaisesRegex(ValueError,'overlapping'):
            codec.constraints(['or',good,bad],2)
        with self.assertRaisesRegex(ValueError,'symbolic'):
            codec.numeric(load)

    def test_repeated_output_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            codec.write_outputs(self.record,root/'one')
            codec.write_outputs(codec.collect(self.image),root/'two')
            self.assertEqual(sorted(p.name for p in (root/'one').iterdir()),
                             ['conversion-paths.tsv','evidence.json','length-dispatch.tsv'])
            for p in (root/'one').iterdir():
                self.assertEqual(p.read_bytes(),(root/'two'/p.name).read_bytes())


if __name__ == '__main__':
    unittest.main()
