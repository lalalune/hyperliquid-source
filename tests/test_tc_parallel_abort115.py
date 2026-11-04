"""Actual target corruption, retained native replay and packet admission controls."""
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import tc_parallel_abort115 as p


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


class TcParallel115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=p.TARGET.read_bytes()
        cls.elf=p.Elf(cls.data)
        cls.bind=json.loads(gzip.decompress((p.PACKET/'bindings.json.gz').read_bytes()))
        cls.replay=module('tc115_packet_test',p.PACKET/'verify.py')

    def changed(self,address):
        s=self.elf.section(address);offset=s['offset']+address-s['address']
        b=bytearray(self.data);b[offset]^=1;return bytes(b)

    def test_public_identity_before_capture(self):
        for data in (self.data[:-1],b'other target',self.changed(p.CORE[0])):
            with self.subTest(size=len(data)),self.assertRaisesRegex(ValueError,'complete target'):
                p.verify(data,{})

    def test_full_target_bindings_and_two_native_decoders(self):
        result=p.verify(self.data,self.bind)
        self.assertEqual((result['core_fdes'],result['core_bytes']),(7,6034))
        self.assertEqual(result['incoming_sites'],20)
        self.assertEqual(self.replay.disassembly_replay(self.bind)['decoded_bytes'],26297)
        self.assertTrue(all(len(x)==1 for x in self.bind['fde_overlaps'].values()))

    def test_complete_subject_first_and_final_bytes_below_identity_guard(self):
        for address in p.CORE:
            f=self.elf.fde(address);expected=p.body(self.elf,f)
            for at in (f['start'],f['end']-1):
                with self.subTest(address=hex(at)):
                    e=copy.copy(self.elf);e.data=self.changed(at)
                    try: actual=p.body(e,f)
                    except ValueError: continue
                    self.assertNotEqual(actual,expected)

    def test_real_control_operands_change_decoded_facts(self):
        facts=p.anchor_facts(self.elf)
        # Flip an operand/condition byte in each actual anchored instruction.
        # This bypasses only the complete-target identity guard, not decoding.
        for name,old in facts.items():
            with self.subTest(anchor=name):
                e=copy.copy(self.elf);e.data=self.changed(old['address']+len(bytes.fromhex(old['hex']))-1)
                self.assertNotEqual(p.anchor_facts(e)[name],old)
        self.assertEqual(facts['inline-stop']['immediates'],[47])
        self.assertEqual(facts['pointer-stop']['immediates'],[47])
        self.assertEqual(facts['inline-stride']['immediates'],[104])
        self.assertEqual(facts['pointer-stride']['immediates'],[16])
        self.assertEqual(facts['closure-allocation']['immediates'],[56])
        self.assertEqual(facts['caller-round-branch']['mnemonic'],'jae')

    def test_actual_fde_range_fields(self):
        for address in p.CORE:
            old=self.elf.fde(address)
            with self.subTest(address=hex(address)):
                # Actual zR/zPLR encodings here have sdata4 pc/range fields.
                e=p.Elf(self.changed(old['fde']+12))
                self.assertNotEqual(e.fde(address)['end'],old['end'])

    def test_actual_import_relocation_writers_and_source_descriptors(self):
        for slot in (0x64df4a0,0x64e4e70,0x64e64b8,0x64e64b0,0x64e8780,0x64bcbd8,0x64bcbf0):
            row=next(r for r in self.elf.relas if r['address']==slot)
            data=bytearray(self.data);data[row['file_offset']+16]^=1
            changed=p.Elf(bytes(data));new=next(r for r in changed.relas if r['address']==slot)
            self.assertNotEqual(new['addend'],row['addend'])
            self.assertEqual(self.elf.read(slot,8),bytes(8))
        self.assertEqual(next(r['addend'] for r in self.elf.relas if r['address']==0x64e64b8),0x57e8bd0)

    def test_retained_native_and_independent_frozen_oracle(self):
        r=self.replay.native_replay()
        self.assertEqual((r['frozen_cases'],r['correct_observations'],r['compiled_mutants']),(15412,61648,36))

    def test_actual_stream_comparator_and_archive_corruptions(self):
        v=module('tc115_validator_test',p.PACKET/'validate_native.py')
        expected=gzip.decompress((p.PACKET/'expected.tsv.gz').read_bytes())
        self.assertEqual(v.compare(expected,expected)['mismatches'],0)
        self.assertGreater(v.compare(b'X'+expected[1:],expected)['mismatches'],0)
        for raw in (expected+b'0\n',expected[:expected.find(b'\n')+1]):
            with self.assertRaises(ValueError):v.compare(raw,expected)
        import base64
        raw=expected.splitlines(keepends=True)[0]
        row={'sha256':p.digest(raw),'bytes':len(raw),'base64':base64.b64encode(raw).decode()}
        self.assertEqual(self.replay.archive_rows({'actual-first-line':row})['actual-first-line'],raw)
        for field,value in [('bytes',0),('sha256','0'*64)]:
            bad=dict(row);bad[field]=value
            with self.assertRaises(ValueError):self.replay.archive_rows({'actual-first-line':bad})

    def test_closed_manifest_temporary_corruptions(self):
        prefix='research/work-items/RE-008-tc-parallel-abort-115'
        for mode in ('ordinary','extra-file','empty-dir','dangling','file-symlink','parent-symlink','duplicate','escape','missing'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve();packet=root/prefix
                names=['tools/tc_parallel_abort115.py','tests/test_tc_parallel_abort115.py',prefix+'/rust/lib.rs']
                for n in names:
                    f=root/n;f.parent.mkdir(parents=True,exist_ok=True);f.write_text('fixture\n')
                mf=packet/'MANIFEST.sha256';rows=''.join(hashlib.sha256((root/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names);mf.write_text(rows)
                if mode=='extra-file':(packet/'extra').write_text('extra')
                if mode=='empty-dir':(packet/'empty').mkdir()
                if mode=='dangling':(packet/'dangling').symlink_to('missing')
                if mode=='file-symlink':
                    f=packet/'rust/lib.rs';f.rename(packet/'actual.rs');f.symlink_to('../actual.rs')
                if mode=='parent-symlink':
                    (packet/'rust').rename(packet/'actual-rust');(packet/'rust').symlink_to('actual-rust',target_is_directory=True)
                if mode=='duplicate':mf.write_text(rows+rows.splitlines()[0]+'\n')
                if mode=='escape':mf.write_text(rows+'0'*64+'  ../outside\n')
                if mode=='missing':mf.write_text('\n'.join(rows.splitlines()[1:])+'\n')
                if mode=='ordinary':self.assertEqual(self.replay.verify_manifest(root,packet),3)
                else:
                    with self.assertRaises((ValueError,OSError)):self.replay.verify_manifest(root,packet)


if __name__=='__main__':unittest.main()
