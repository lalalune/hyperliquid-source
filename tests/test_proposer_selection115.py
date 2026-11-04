"""Bounded static/fixture/corruption tests. Never execute the captured node."""
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import proposer_selection115 as p


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


class ProposerBindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=p.TARGET.read_bytes()
        cls.elf=p.Elf(cls.data)
        cls.expected=json.loads(gzip.decompress((p.PACKET/'bindings.json.gz').read_bytes()))
        cls.actual=p.capture(cls.data)

    def test_complete_binding(self):
        self.assertEqual(self.actual,self.expected)
        self.assertEqual(self.actual['target_sha256'],p.SHA256)
        self.assertEqual((self.actual['fde_count'],self.actual['cie_count']),(135313,3))
        self.assertEqual(sum(b['length'] for b in self.actual['bodies']),17654)

    def test_full_main_and_call_boundaries(self):
        b=self.actual['bodies'][0]
        self.assertEqual((b['start'],b['end'],b['length']),(0x595cb30,0x595e5b8,6792))
        calls=[e for e in b['edges'] if e['kind']=='call']
        recorded=json.loads((p.PACKET/'call-boundaries.json').read_text())
        self.assertEqual(len(calls),57)
        self.assertEqual([x['site'] for x in calls],[x['site'] for x in recorded])
        self.assertTrue(all(x['contract'] for x in recorded))

    def test_actual_slot_incoming_closure(self):
        self.assertEqual(len(self.actual['incoming']),6)
        self.assertEqual(sum(len(c['sites']) for c in self.actual['incoming']),8)
        for caller in self.actual['incoming']:
            for site in caller['sites']:
                self.assertEqual(site['slot_word'],0)
                self.assertEqual(site['linked_target'],p.MAIN)
                self.assertTrue(any(r['kind']==8 and r['addend']==p.MAIN for r in site['relocations']))

    def test_wrong_target_rejected(self):
        with self.assertRaisesRegex(ValueError,'complete target digest'):
            p.verify(self.data[:-1],self.expected)

    def test_each_complete_body_corruption(self):
        # Exercise body decoding/binding independently of the top-level hash gate.
        for original in self.actual['bodies']:
            with self.subTest(start=hex(original['start'])):
                data=bytearray(self.data)
                sec=self.elf.section(original['start'])
                offset=sec['offset']+original['start']-sec['address']
                data[offset]^=1
                changed=p.Elf(bytes(data))
                try: b=p.body(changed,changed.fde(original['start']))
                except ValueError: continue
                self.assertNotEqual(b,original)

    def test_fde_range_corruption(self):
        f=self.elf.fde(p.MAIN);sec=self.elf.section(f['fde']);off=sec['offset']+f['fde']-sec['address']+12
        data=bytearray(self.data);old=struct.unpack_from('<i',data,off)[0];struct.pack_into('<i',data,off,old-1)
        changed=p.Elf(bytes(data))
        self.assertNotEqual(changed.fde(p.MAIN),f)

    def test_constant_and_jump_table_corruptions(self):
        spans=self.actual['data_spans']+self.actual['history_jump_tables']
        for original in spans:
            va=original['address']
            with self.subTest(address=hex(va)):
                sec=self.elf.section(va);offset=sec['offset']+va-sec['address']
                data=bytearray(self.data);data[offset]^=1;changed=p.Elf(bytes(data))
                self.assertNotEqual(changed.read(va,len(bytes.fromhex(original['hex']))).hex(),original['hex'])

    def test_relocation_writer_corruption(self):
        row=next(r for r in self.actual['naming_relocations'] if r['addend']==p.MAIN)
        data=bytearray(self.data);data[row['file_offset']+16]^=1
        changed=p.Elf(bytes(data))
        self.assertNotEqual(changed.relas_at(row['address'],8),self.elf.relas_at(row['address'],8))

    def test_full_gnu_agreement_archive(self):
        exports=json.loads(gzip.decompress((p.PACKET/'disassembly.json.gz').read_bytes()))
        commands=json.loads((p.PACKET/'disassembly-commands.json').read_text())
        self.assertEqual(len(exports),34)
        self.assertEqual(len(commands),34)
        for record,command in zip(exports,commands):
            self.assertEqual(p.digest(record['stdout'].encode()),command['stdout_sha256'])
            self.assertEqual(p.digest(record['stderr'].encode()),command['stderr_sha256'])
            self.assertEqual(command['exit_code'],0)
            body=next(b for b in self.actual['bodies']+[c['body'] for c in self.actual['incoming']] if b['start']==record['start'])
            rows=[]
            for line in record['stdout'].splitlines():
                match=re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)',line)
                if match:rows.append((int(match[1],16),''.join(match[2].split())))
            self.assertEqual(rows,[(x[0],x[1]) for x in body['instructions']])

    def test_history_table_destinations(self):
        for start,table in zip((0x4d38fd0,0x4d391b0),self.actual['history_jump_tables']):
            b=next(b for b in self.actual['bodies'] if b['start']==start)
            self.assertEqual(len(table['targets']),4)
            self.assertTrue(set(table['targets']) <= {i[0] for i in b['instructions']})

    def test_separate_rounds_and_actual_history_targets(self):
        main=self.actual['bodies'][0]
        self.assertIn([0x595cb41,'4989cf','mov','r15, rcx'],main['instructions'])
        self.assertIn([0x595cb44,'4989d5','mov','r13, rdx'],main['instructions'])
        calls=[e for e in main['edges'] if e['kind']=='call']
        self.assertEqual([e['linked_target'] for e in calls[1:3]],[0x595c3a0,0x595e5c0])



class ProposerOracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.o=module('proposer_oracle',p.PACKET/'oracle.py')

    def test_original_freeze_hashes(self):
        frozen=json.loads((p.PACKET/'freeze.json').read_text())
        self.assertEqual(frozen['oracle_sha256'],p.digest((p.PACKET/'oracle.py').read_bytes()))
        for name in ('inputs','expected'):
            compressed=(p.PACKET/f'{name}.txt.gz').read_bytes();raw=gzip.decompress(compressed)
            self.assertEqual(p.digest(compressed),frozen['files'][name]['gzip_sha256'])
            self.assertEqual(p.digest(raw),frozen['files'][name]['raw_sha256'])
            self.assertEqual(len(raw.splitlines()),9243)

    def test_all_frozen_mathematical_results(self):
        inputs=gzip.decompress((p.PACKET/'inputs.txt.gz').read_bytes()).decode().splitlines()
        expected=gzip.decompress((p.PACKET/'expected.txt.gz').read_bytes()).decode().splitlines()
        self.assertEqual([self.o.evaluate(x) for x in inputs],expected)

    def test_saturated_total_and_union(self):
        k=lambda n:bytes([0]*19+[n]).hex()
        p=self.o.prepare([k(1)],[k(1),k(2)],[(k(1),2**64-1),(k(2),2**64-1),(k(3),1)])
        self.assertEqual(p[0],2**64-1)
        self.assertEqual(p[1],(2**64-1001)//2)
        self.assertEqual(p[2][0][0],k(2))

    def test_diagnostic_max_inclusive_and_wrapping_counter(self):
        self.assertEqual(self.o.evaluate('G 0 0 0 2000 18446744073709551615 1 0'),'G 2000 1800 0 0 1')
        self.assertEqual(self.o.evaluate('G 0 2000 0 2200 5 0'),'G 2201 2000 -1 5 0')

    def test_ring_wrap_predecessor(self):
        self.assertEqual(self.o.evaluate('R 2 3 14 4 25 999 3 14'),'R 2 3')
        self.assertEqual(self.o.evaluate('R 2 3 25 4 25 999 3 14'),'R 3 0')
        self.assertEqual(self.o.evaluate('R 0 0 0 0'),'R 0 -1')

    def test_history_exact_switch_and_inclusive(self):
        self.assertEqual(self.o.history(0,[0,1799,1800,1801],1999),(0,0))
        self.assertEqual(self.o.history(0,[0,1799,1800,1801],2000),(1800,2))
        self.assertEqual(self.o.history(2**64-1000,[0,2**64-1000],2**64-1),(2**64-201,1))

    def test_integer_rounding_ties(self):
        self.assertEqual(self.o.rn(2**53+1),0x4340000000000000)
        self.assertEqual(self.o.rn(2**53+3),0x4340000000000002)
        self.assertEqual(self.o.rn(2**64-1),0x43f0000000000000)

    def test_comparator_rejects_truncation_and_extra_records(self):
        v=module('proposer_validator',p.PACKET/'validate_native.py')
        for actual in (b'',b'a',b'a\nb\n',b'b\n'):
            self.assertFalse(v.compare(actual,b'a\n')['exact'])
        self.assertTrue(v.compare(b'a\n',b'a\n')['exact'])

    def test_native_mutation_anchors(self):
        v=module('proposer_mutant_anchors',p.PACKET/'validate_native.py')
        source=(p.PACKET/'rust/lib.rs').read_text()
        self.assertEqual(len(v.MUTANTS),47)
        for name,old,new,count in v.MUTANTS:
            with self.subTest(name=name):
                self.assertGreaterEqual(source.count(old),count)
                self.assertNotEqual(source.replace(old,new,count),source)

    def test_archive_corruption_and_duplicate_rejected(self):
        v=module('proposer_archive_replay',p.PACKET/'verify.py')
        row={'name':'test','bytes':1,'sha256':p.digest(b'a'),'base64':'YQ=='}
        self.assertEqual(v.archive_rows([row]),{'test':b'a'})
        wrong=dict(row,base64='Yg==')
        with self.assertRaisesRegex(ValueError,'archive corruption'):
            v.archive_rows([wrong])
        with self.assertRaisesRegex(ValueError,'duplicate'):
            v.archive_rows([row,row])


class ProposerManifest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.packet=self.root/'research/work-items/RE-008-proposer-selection-115'
        self.v=module('proposer_manifest_controls',p.PACKET/'verify.py')
        self.paths=[self.packet/'data/payload',self.root/'tools/proposer_selection115.py',self.root/'tests/test_proposer_selection115.py']
        for path in self.paths:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b'known exact bytes')
        self.manifest=self.packet/'MANIFEST.sha256'
        self.manifest.write_text(''.join(p.digest(path.read_bytes())+'  '+path.relative_to(self.root).as_posix()+'\n' for path in self.paths))

    def test_closed_manifest_accepts_exact_inventory(self):
        self.assertEqual(self.v.verify_manifest(self.root,self.packet),3)

    def test_unlisted_file_and_empty_directory_rejected(self):
        for name,directory in [('extra',False),('empty',True)]:
            with self.subTest(name=name):
                path=self.packet/name
                path.mkdir() if directory else path.write_bytes(b'unlisted')
                with self.assertRaisesRegex(ValueError,'inventory differs'):
                    self.v.verify_manifest(self.root,self.packet)
                path.rmdir() if directory else path.unlink()
        (self.packet/'dangling').symlink_to(self.root/'absent')
        with self.assertRaisesRegex(ValueError,'symlink'):
            self.v.verify_manifest(self.root,self.packet)

    def test_same_content_file_symlinks_rejected(self):
        for path in [*self.paths,self.manifest]:
            with self.subTest(path=str(path.relative_to(self.root))):
                raw=path.read_bytes();saved=self.root/'saved';saved.write_bytes(raw)
                path.unlink();path.symlink_to(saved)
                with self.assertRaisesRegex(ValueError,'symlink'):
                    self.v.verify_manifest(self.root,self.packet)
                path.unlink();path.write_bytes(raw);saved.unlink()

    def test_parent_directory_symlinks_rejected(self):
        for parent in [self.packet/'data',self.root/'tools',self.packet]:
            with self.subTest(parent=str(parent.relative_to(self.root))):
                saved=self.root/'saved-directory';parent.rename(saved);parent.symlink_to(saved,target_is_directory=True)
                with self.assertRaisesRegex(ValueError,'symlink'):
                    self.v.verify_manifest(self.root,self.packet)
                parent.unlink();saved.rename(parent)

    def test_duplicate_missing_and_escape_rows_rejected(self):
        original=self.manifest.read_text();rows=original.splitlines(keepends=True)
        corruptions=[original+rows[0],''.join(rows[:-1]),original+p.digest(b'x')+'  ../outside\n',original+p.digest(b'x')+'  unexpected.txt\n']
        for value in corruptions:
            with self.subTest(value=value[-90:]):
                self.manifest.write_text(value)
                with self.assertRaises(ValueError):
                    self.v.verify_manifest(self.root,self.packet)
        self.manifest.write_text(original)

    def test_hash_mismatch_rejected(self):
        self.paths[0].write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'manifest mismatch'):
            self.v.verify_manifest(self.root,self.packet)


if __name__=='__main__':unittest.main()
