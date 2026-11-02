import copy
import csv
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_hyperliquidity_root as tool

EVIDENCE = ROOT / 'research/work-items/RE-017-hyperliquidity-root-94'


class Overlay:
    def __init__(self, base, patches):
        self.base = base
        self.patches = patches
        self.by_name = base.by_name

    def read(self, va, size, executable=False):
        raw = bytearray(self.base.read(va, size, executable))
        for pos, patch in self.patches.items():
            for i, byte in enumerate(patch):
                if va <= pos+i < va+size:
                    raw[pos+i-va] = byte
        return bytes(raw)

    mapping = lambda self, *args, **kwargs: self.base.mapping(*args, **kwargs)
    literal = tool.Image.literal


class PacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = tool.BINARY.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_READ)
        tool.digest_ok(cls.data)
        cls.image = tool.Image(cls.data)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / 'generated'
        cls.summary = tool.generate(cls.data, cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        cls.data.close()
        cls.file.close()

    def private_image(self):
        return mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY)

    def test_full_artifact_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tool.SHA256)

    def test_corrupted_artifact_rejected_before_output(self):
        with self.private_image() as changed:
            changed[0] ^= 1
            destination = self.out.parent / 'must-not-exist'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                tool.generate(changed, destination)
            self.assertFalse(destination.exists())

    def test_altered_fde_body_rejected(self):
        with self.private_image() as changed:
            _,off = self.image.mapping(0x26cd810, 1, True)
            changed[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'unexpected bytes'):
                tool.Image(changed)

    def test_fde_extent_and_unwind_index_corruption(self):
        fde_va = self.image.frames[0x26cd7f0]['fde']
        for relative in (8,12):
            with self.subTest(fde_field=relative),self.private_image() as changed:
                _,off = self.image.mapping(fde_va+relative,1)
                changed[off] ^= 1
                with self.assertRaises(ValueError):
                    tool.Image(changed)

    def test_fde_extent_and_counts(self):
        self.assertEqual(self.summary['fde_count'], 27)
        self.assertEqual(self.summary['selected_branch_count'], 294)
        self.assertEqual(self.summary['selected_direct_call_count'], 124)
        self.assertEqual(self.summary['checked_path_edges'], 25)
        self.assertEqual((self.summary['lsda_headers'],self.summary['lsda_decoded_headers'],
                          self.summary['lsda_unsupported_headers']),(13,12,1))
        self.assertEqual(len({f[1] for f in tool.FUNCTIONS}), 27)
        for _, start, end, _ in tool.FUNCTIONS:
            self.assertEqual(self.image.frames[start]['end'], end)
            self.image.mapping(start,end-start,True)

    def test_extent_bytes_agree_with_each_fde_and_digest(self):
        specs = {name:(start,end,digest) for name,start,end,digest in tool.FUNCTIONS}
        with (self.out/'extents.tsv').open(encoding='utf-8',newline='') as handle:
            rows = list(csv.DictReader(handle,delimiter='\t'))
        self.assertEqual(len(rows),len(specs))
        for row in rows:
            start,end,digest = specs[row['role']]
            body = bytes.fromhex(row['bytes'])
            self.assertEqual((int(row['start_va'],16),int(row['end_va_exclusive'],16)),(start,end))
            self.assertEqual(body,self.image.read(start,end-start,True))
            self.assertEqual(hashlib.sha256(body).hexdigest(),digest)
        self.assertEqual(sum(len(bytes.fromhex(row['bytes'])) for row in rows),self.summary['fde_bytes'])

    def test_recreated_evidence_exactly_matches_checked_in(self):
        actual = sorted(p.name for p in self.out.iterdir())
        wanted = sorted(p.name for p in EVIDENCE.iterdir()
                        if p.name not in ('README.md','MANIFEST.sha256'))
        self.assertEqual(actual, wanted)
        for name in actual:
            self.assertEqual((self.out/name).read_bytes(), (EVIDENCE/name).read_bytes(), name)

    def test_manifest_covers_exact_folder(self):
        lines = (EVIDENCE/'MANIFEST.sha256').read_text(encoding='utf-8').splitlines()
        entries = [line.split('  ',1) for line in lines]
        self.assertTrue(all(len(row) == 2 for row in entries))
        self.assertEqual(sorted(name for _,name in entries),
                         sorted(p.name for p in EVIDENCE.iterdir() if p.name != 'MANIFEST.sha256'))
        for digest,name in entries:
            self.assertEqual(hashlib.sha256((EVIDENCE/name).read_bytes()).hexdigest(),digest,name)

    def test_call_path_targets(self):
        for _,site,target in tool.EDGES:
            with self.subTest(site=hex(site)):
                raw,got = tool.checked_edge(lambda va,n:self.image.read(va,n,True),site,target)
                self.assertEqual(got,target)
                self.assertEqual(raw[0],0xe8)
        self.assertEqual(tool.decode_call(0x18df5cb,self.image.read(0x18df5cb,5,True)),0x24dc4a0)

    def test_call_opcode_and_redirect_corruption(self):
        with self.assertRaises(ValueError):
            tool.decode_call(0x100,b'\xff\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            tool.decode_call(0x100,b'\xe8')
        site,target = 0x26cd892,0x25ecf10
        bad = Overlay(self.image,{site+1:b'\x00\x00\x00\x00'})
        with self.assertRaisesRegex(ValueError,'target'):
            tool.checked_edge(lambda va,n:bad.read(va,n,True),site,target)

    def test_each_checked_edge_rejects_corrupted_instruction(self):
        for label,site,target in tool.EDGES:
            original = self.image.read(site,5,True)
            for index,byte in enumerate(original):
                bad = Overlay(self.image,{site+index:bytes([byte^1])})
                with self.subTest(label=label,index=index),self.assertRaises(ValueError):
                    tool.checked_edge(lambda va,n:bad.read(va,n,True),site,target)

    def test_relative_branch_sign_and_bad_opcodes(self):
        self.assertEqual(tool.decode_branch(0x100, bytes.fromhex('75fc00000000')),(2,5,0xfe))
        self.assertEqual(tool.decode_branch(0x100, bytes.fromhex('0f84f0ffffff')),(6,4,0xf6))
        for raw in (b'',b'\x90\x00',b'\x0f\x84\x00'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                tool.decode_branch(0x100,raw)

    def test_branch_out_of_extent_rejected(self):
        class Fake:
            by_name = {'f':(0x100,0x110,'')}
            def read(self,va,size,executable=False):
                return bytes.fromhex('757f00000000')
        with self.assertRaisesRegex(ValueError,'target'):
            tool.bounded_branch(Fake(),'f',0x100)
        with self.assertRaisesRegex(ValueError,'site'):
            tool.bounded_branch(Fake(),'f',0x110)

    def test_file_mapping_rejects_outside_and_nobits(self):
        end = max(s['address']+s['size'] for s in self.image.sections)
        for va,size in ((end+1,1),(0,0)):
            with self.assertRaises(ValueError):
                self.image.mapping(va,size)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'],8)
        with self.assertRaises(ValueError):
            self.image.mapping(bss['address']+bss['size']-1,1)
        ambiguous = copy.copy(self.image)
        text = next(s for s in self.image.sections if s['name'] == '.text')
        ambiguous.sections = self.image.sections+[text.copy()]
        with self.assertRaises(ValueError):
            ambiguous.mapping(0x26cd7f0,1,True)

    def test_literal_sites_and_corrupted_bytes(self):
        for label,site,text in tool.LITERALS:
            va,n,raw = self.image.literal(site,text)
            self.assertEqual((n,raw),(len(text),text))
            self.image.mapping(va,n)
            for index,byte in enumerate(text):
                bad = Overlay(self.image,{va+index:bytes([byte^1])})
                with self.subTest(label=label,index=index),self.assertRaises(ValueError):
                    bad.literal(site,text)
        bad = Overlay(self.image,{0x26cd86c:b'\x90'})
        with self.assertRaisesRegex(ValueError,'literal reference'):
            bad.literal(0x26cd86c,b'spot_to_range')
        bad = Overlay(self.image,{0x3ef143:b'X'})
        with self.assertRaisesRegex(ValueError,'field literal'):
            bad.literal(0x26cd86c,b'spot_to_range')

    def test_predicate_bytes_are_pinned(self):
        read = lambda va,n:self.image.read(va,n,True)
        self.assertEqual(len(tool.pinned_predicates(read)),9)
        for _,site,pattern in tool.PREDICATES:
            for index,byte in enumerate(bytes.fromhex(pattern)):
                bad = Overlay(self.image,{site+index:bytes([byte^1])})
                with self.subTest(site=hex(site),index=index),self.assertRaisesRegex(ValueError,'predicate'):
                    tool.pinned_predicates(lambda va,n:bad.read(va,n,True))

    def test_builder_capture_handoffs_and_corruption(self):
        rows = tool.capture_rows(self.image)
        self.assertEqual([(r[0],r[3],r[8],r[10]) for r in rows], [
            ('low','0x38d0',19,'0x56bdc98'),('secondary','0x38d0',19,'0x5744948'),
            ('primary','0x4350',19,'0x5744948')])
        for lane,capture,install,_,_ in tool.CAPTURE_SITES:
            for site in (capture,capture+3,install+8,install+18,install+25):
                original = self.image.read(site,1,True)
                bad = Overlay(self.image,{site:bytes([original[0]^1])})
                with self.subTest(lane=lane,site=hex(site)),self.assertRaises(ValueError):
                    tool.capture_rows(bad)

    def test_field_order_and_displacements(self):
        rows = tool.field_bindings(self.image)
        self.assertEqual([(r[0],r[1],r[-1]) for r in rows], [
            ('holder','spot_to_range','0x10'),('holder','ensure_order_bucket_guard','0x0'),
            ('guard','last_bucket','0x8'),('guard','bucket_millis','0x0'),
            ('range','order_sz','0x18'),('range','points','0x0'),
            ('point','o','0x8'),('point','p','0x10')])
        for _,_,site,pattern,_ in tool.FIELD_BINDINGS:
            for index,byte in enumerate(bytes.fromhex(pattern)):
                bad = Overlay(self.image,{site+index:bytes([byte^1])})
                with self.subTest(site=hex(site),index=index),self.assertRaisesRegex(ValueError,'field load'):
                    tool.field_bindings(bad)

    def test_named_decision_opcode_and_displacement_corruption(self):
        self.assertEqual(len(tool.decision_rows(self.image)),26)
        for label,_,site,pattern in tool.DECISIONS:
            for index,byte in enumerate(bytes.fromhex(pattern)):
                bad = Overlay(self.image,{site+index:bytes([byte^1])})
                with self.subTest(label=label,index=index),self.assertRaises(ValueError):
                    tool.decision_rows(bad)

    def test_key_classification_exhaustive_bytes_and_length(self):
        for value in range(256):
            want = 0 if value == ord('o') else 1 if value == ord('p') else 2
            self.assertEqual(tool.classify_key(bytes([value])),want)
        for key in (b'',b'op',b'oo',b'\x00o'):
            self.assertEqual(tool.classify_key(key),2)

    def test_reader_initial_reservation_boundaries(self):
        for count,want in ((0,0),(1,1),(0xaaaa,0xaaaa),(0xaaab,0xaaaa),(0xffffffff,0xaaaa)):
            self.assertEqual(tool.reserve_count(count),want)
        for count in (-1,1<<32):
            with self.assertRaises(ValueError):
                tool.reserve_count(count)

    def test_point_tag_and_mode_boundary_models(self):
        self.assertEqual(tool.point_shape(0,1),(1,False,False,True))
        self.assertEqual(tool.point_shape(1,1),(2,True,True,True))
        self.assertEqual(tool.point_shape(1,0),(2,True,False,False))
        self.assertEqual(tool.point_shape(1,2),(2,True,True,False))
        self.assertEqual(tool.point_shape(256,1),(257,False,False,True))
        self.assertEqual(tool.point_shape(0xffffffff,1),(0,True,True,True))
        for tag,mode in ((-1,1),(1<<64,1),(1,-1),(1,256)):
            with self.assertRaises(ValueError):
                tool.point_shape(tag,mode)

    def test_row_relocations_and_tampered_addend(self):
        rows = tool.relocation_tables(self.image)
        self.assertEqual(len(rows),2)
        self.assertEqual([r[-1] for r in rows],['0x26bb320','0x42c0580'])
        with self.private_image() as changed:
            off = int(rows[0][4],16)
            struct.pack_into('<q',changed,off+16,0)
            image = copy.copy(self.image)
            image.data = changed
            with self.assertRaisesRegex(ValueError,'relocation'):
                tool.relocation_tables(image)

    def test_row_relocation_type_corruption(self):
        rows = tool.relocation_tables(self.image)
        for info in (9,(1<<32)|8):
            with self.subTest(info=info),self.private_image() as changed:
                off = int(rows[1][4],16)
                struct.pack_into('<Q',changed,off+8,info)
                image = copy.copy(self.image)
                image.data = changed
                with self.assertRaisesRegex(ValueError,'relocation'):
                    tool.relocation_tables(image)

    def test_missing_and_duplicate_relocations_rejected(self):
        low = tool.relocation_tables(self.image)[0]
        low_off = int(low[4],16)
        with self.private_image() as changed:
            struct.pack_into('<Q',changed,low_off,0)
            image = copy.copy(self.image)
            image.data = changed
            with self.assertRaisesRegex(ValueError,'missing'):
                tool.relocation_tables(image)
        with self.private_image() as changed:
            sec = next(s for s in self.image.sections if s['name'] == '.rela.dyn')
            other = sec['offset']
            self.assertNotEqual(other,low_off)
            struct.pack_into('<QQq',changed,other,0x56bdcb0,8,0x26bb320)
            image = copy.copy(self.image)
            image.data = changed
            with self.assertRaisesRegex(ValueError,'duplicate'):
                tool.relocation_tables(image)

    def test_lsda_supported_and_unsupported(self):
        frame = self.image.frames[0x24dc4a0]
        encoding,rows = tool.parse_lsda(self.image,frame)
        self.assertEqual(encoding,'omit-omit-uleb')
        self.assertTrue(rows)
        frame = self.image.frames[0x17234e0]
        self.assertEqual(tool.parse_lsda(self.image,frame),('unsupported-header',[]))

    def test_lsda_truncation_and_invalid_range(self):
        class Fake:
            def __init__(self,data):
                self.data = data
            def mapping(self,va,size):
                return {'name':'.gcc_except_table','offset':0,'size':len(self.data)},0
        frame = {'lsda':1,'start':0x100,'end':0x110}
        for data in (bytes.fromhex('ffff010180'),bytes.fromhex('ffff0105ff01010100')):
            with self.subTest(data=data.hex()),self.assertRaises(ValueError):
                tool.parse_lsda(Fake(data),frame)

    def test_structured_counts_match_rows(self):
        for name,key in (('functions.tsv','fde_count'),('extents.tsv','fde_count'),('branches.tsv','selected_branch_count'),
                         ('calls.tsv','selected_direct_call_count'),('edges.tsv','checked_path_edges'),
                         ('windows.tsv','selected_window_count'),('literals.tsv','literal_count'),
                         ('lsda.tsv','lsda_rows'),('lsda-headers.tsv','lsda_headers'),('predicates.tsv','predicate_pins'),
                         ('tables.tsv','row_relocations'),('diagnostic-data.tsv','diagnostic_data_pins'),
                         ('field-order.tsv','field_bindings'),('decisions.tsv','named_decisions'),
                         ('capture-rows.tsv','prior_capture_rows')):
            with (self.out/name).open(encoding='utf-8',newline='') as handle:
                count = sum(1 for _ in csv.DictReader(handle,delimiter='\t'))
            self.assertEqual(count,self.summary[key],name)
        self.assertEqual(json.loads((self.out/'summary.json').read_text()),self.summary)


if __name__ == '__main__':
    unittest.main()
