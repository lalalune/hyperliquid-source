"""Node115 runtime admission, actual pointer bindings and corruption controls."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import runtime_entry_115_static as r


def verifier():
    spec = importlib.util.spec_from_file_location('runtime115_packet', r.PACKET / 'verify.py')
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


class Runtime115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = r.TARGET.read_bytes()
        cls.image = r.Image(cls.data)
        cls.record = r.analyze(cls.data)

    def test_authenticated_current_target_and_complete_extents(self):
        self.assertEqual(self.record, json.loads((r.PACKET / 'records.json').read_bytes()))
        self.assertEqual([b['bytes'] for b in self.record['bodies']], [39,1749,13,13,5,38])
        self.assertEqual(sum(b['instructions'] for b in self.record['bodies']), 434)
        self.assertEqual(self.record['elf_entry'], '0x1419300')
        self.assertFalse(self.record['whole_runtime_equivalence'])

    def test_wrong_capture_and_truncation_rejected(self):
        for data in (self.data[:-1], b'not an ELF', b'X'+self.data[1:]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                r.analyze(data)

    def altered(self, va, raw):
        image = copy.copy(self.image)
        off = image.offset(va, len(raw))
        data = bytearray(image.data); data[off:off+len(raw)] = raw
        image.data = bytes(data)
        return image

    def test_every_semantic_region_corruption_below_digest_admission(self):
        for name, (va, raw) in r.ANCHORS.items():
            with self.subTest(region=name), self.assertRaises(ValueError):
                r.extract(self.altered(va, bytes([int(raw[:2],16)^1])))

    def test_actual_vtable_slot_identity_and_overlapping_writers(self):
        for slot, field, value in [(0x6440b70,'addend',0x292e230),
                                   (0x64e6c30,'kind',6), (0x64ec808,'addend',1)]:
            image=copy.copy(self.image);image.relocations=copy.deepcopy(image.relocations)
            image.relocations[slot][field]=value
            with self.subTest(slot=slot,field=field), self.assertRaises(ValueError):r.extract(image)
        image=copy.copy(self.image);image.relocations=dict(image.relocations)
        image.relocations[0x6440b6f]=dict(image.relocations[0x6440b70])
        with self.assertRaisesRegex(ValueError,'overlapping'):r.extract(image)

    def test_vtable_header_and_jump_targets_are_data_not_labels(self):
        with self.assertRaisesRegex(ValueError,'vtable header'):
            r.extract(self.altered(0x6440b50,struct.pack('<Q',16)))
        with self.assertRaisesRegex(ValueError,'jump table'):
            r.extract(self.altered(0x9486e8,struct.pack('<i',0)))
        with self.assertRaisesRegex(ValueError,'literal'):
            r.extract(self.altered(0x44fa5e,b'X'))

    def test_real_zero_tail_and_file_cleanup_state_are_distinct(self):
        for name in ('thread_counter','main_thread','sigpipe_explicit','argc','argv','exit_owner'):
            self.assertEqual(self.record['globals'][name]['kind'],'writable_PT_LOAD_zero_tail')
            self.assertEqual(set(bytes.fromhex(self.record['globals'][name]['hex'])),{0})
        self.assertEqual(self.record['globals']['cleanup_once']['hex'],'03000000')
        for start,size in [(0x6728924,1),(0x64ffe07,2),(0xdeadbeef,8)]:
            with self.subTest(start=start), self.assertRaises(ValueError):r.mapped_data(self.image,start,size)

    def test_selected_data_cannot_hide_loader_relocations(self):
        for slot in (0x6500077, 0x6500000, 0x9486e7, 0x44fa5d):
            image=copy.copy(self.image); image.relocations=dict(image.relocations)
            image.relocations[slot]=dict(image.relocations[0x64e6c30])
            with self.subTest(slot=slot),self.assertRaisesRegex(ValueError,'overlapping selected data'):
                r.extract(image)

    def test_selected_lsda_is_bounded_not_a_panic_proof(self):
        table=self.record['exception_tables']['runtime']
        self.assertFalse(table['action_records_decoded'])
        self.assertEqual(len(table['rows']),8)
        callback=[x for x in table['rows'] if x['start']=='0x5c99e19']
        self.assertEqual(callback[0]['landing_pad'],'0x5c99f54')
        self.assertEqual(callback[0]['action_index'],5)
        with self.assertRaises(ValueError):r.extract(self.altered(0x3ff828,b'\x00'))

    def test_complete_fde_and_entry_corruption(self):
        image=copy.copy(self.image);image.fdes=copy.deepcopy(image.fdes)
        next(f for f in image.fdes if f['start']==0x5c99970)['end']-=1
        with self.assertRaisesRegex(ValueError,'FDE'):r.extract(image)
        image=copy.copy(self.image);data=bytearray(image.data);struct.pack_into('<Q',data,24,0x1419301);image.data=bytes(data)
        with self.assertRaisesRegex(ValueError,'ELF entry'):r.extract(image)

    def test_native_exports_and_LOCK_presentation(self):
        self.assertEqual(verifier().verify_native(self.record,r.PACKET),12)
        text=' 100: f0 lock\n 101: 48 ff 08 decq (%rax)\n'
        self.assertEqual(r.native_bytes(text,0x100,0x104),[(0x100,bytes.fromhex('f048ff08'))])
        for text,end in [('100: f0 lock\n',0x101),('100: f0 lock\n101: c3 ret\n',0x102),
                         ('100: 90 nop\n102: c3 ret\n',0x103)]:
            with self.subTest(text=text),self.assertRaises(ValueError):r.native_bytes(text,0x100,end)


class PacketBoundaryTests(unittest.TestCase):
    def test_inventory_rejects_hidden_files_directories_and_symlinks(self):
        v=verifier()
        for kind in ('unknown','empty_directory','dangling_symlink','known_symlink','nested'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'manifest.json').write_text('{}');(root/'known').write_text('evidence')
                v.verify_packet_inventory(root,{'known'})
                if kind=='unknown':(root/'extra').write_text('extra')
                if kind=='empty_directory':(root/'empty').mkdir()
                if kind=='dangling_symlink':(root/'dangling').symlink_to(root/'missing')
                if kind=='known_symlink':
                    (root/'known').unlink();(root/'known').symlink_to(root/'manifest.json')
                if kind=='nested':
                    (root/'__pycache__').mkdir();(root/'__pycache__'/'hidden').write_text('x')
                with self.assertRaises(ValueError):v.verify_packet_inventory(root,{'known'})

    def test_manifest_wrong_digest_extra_key_and_path_traversal_rejected(self):
        v=verifier()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'data').write_bytes(b'valid')
            row={'bytes':5,'sha256':r.digest(b'valid')}
            v.verify_manifest(root,{'data':row},{'data'})
            for rows,expected in [({'data':{**row,'bytes':True}},{'data'}),
                 ({'data':{**row,'sha256':'0'*64}},{'data'}),
                 ({'../data':row},{'../data'}),({'data':row,'extra':row},{'data'})]:
                with self.subTest(rows=rows),self.assertRaises(ValueError):v.verify_manifest(root,rows,expected)

    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(ValueError):json.loads('{"x":1,"x":2}',object_pairs_hook=r.unique)


if __name__=='__main__':unittest.main()
