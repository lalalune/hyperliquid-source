"""Target-grounded guard controls; synthetic text is only a local branch model."""
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from artifacts import ROOT,check
from gnu_binutils import requires_gnu
from truncated_debug_static import PROFILES,SLOTS,PATH_VA,read_va,source_bindings,profile,census,rejects_boundary_byte

@requires_gnu('readelf')
class TruncatedDebugTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target=ROOT/'artifacts/node/94/hl-node'
        identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if i['path']=='artifacts/node/94/hl-node')
        check(target,identity)
        cls.data=target.read_bytes()
        frames=subprocess.check_output(['readelf','-wf',str(target)],text=True)
        cls.fdes=[(int(a,16),int(b,16)) for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
        cls.rows=census(cls.data,cls.fdes)

    def test_actual_family_and_source_bindings(self):
        self.assertEqual(len(source_bindings(self.data)),5)
        self.assertEqual(sum(r['bytes'] for r in self.rows),17952)
        self.assertEqual({k:sum(r['guard_profile']==k for r in self.rows) for k in PROFILES},{'bf-jle':27,'c0-jl':39})

    def test_actual_guard_and_prefix_corruptions(self):
        for kind in PROFILES:
            row=next(r for r in self.rows if r['guard_profile']==kind)
            body=bytes.fromhex(row['body_hex'])
            for offset in (0x3a,0x3e,0x4a,0x4c,0x5c,0xe0,0xec):
                with self.subTest(kind=kind,offset=offset):
                    changed=bytearray(body);changed[offset]^=1
                    with self.assertRaises(ValueError):profile(changed)

    def test_actual_source_retargets_and_path(self):
        for slot in SLOTS:
            changed=bytearray(self.data)
            offset=changed.find(struct.pack('<QQq',slot,8,PATH_VA))
            self.assertGreaterEqual(offset,0);changed[offset+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation changed'):source_bindings(changed)
        changed=bytearray(self.data);offset,_=read_va(changed,PATH_VA,1);changed[offset]^=1
        with self.assertRaisesRegex(ValueError,'path changed'):source_bindings(changed)

    def test_both_decoded_signed_predicates_all256_bytes(self):
        for kind,body in PROFILES.items():
            # Decode actual immediate and signed Jcc, independent of the helper.
            immediate=body[20];immediate=immediate if immediate<128 else immediate-256
            jcc=body[22]
            self.assertIn(jcc,(0x8c,0x8e))
            rejected=[]
            for value in range(256):
                signed=value if value<128 else value-256
                actual=signed<immediate if jcc==0x8c else signed<=immediate
                self.assertEqual(actual,rejects_boundary_byte(value,kind))
                if actual:rejected.append(value)
            self.assertEqual(rejected,list(range(0x80,0xc0)))

    def test_length_and_fixed_cutpoint_branch_destinations(self):
        for row in self.rows:
            body=bytes.fromhex(row['body_hex'])
            cutoff=struct.unpack_from('<I',body,0x3a)[0]
            self.assertEqual(cutoff,10000)
            self.assertEqual(0x40+body[0x3f],0x8e)
            self.assertEqual(0x52+struct.unpack_from('<i',body,0x4e)[0],0xd8)
            self.assertEqual([length for length in (9999,10000,10001) if length>cutoff],[10001])

    def test_valid_utf8_boundary_examples_and_local_limit(self):
        for character in ('é','€','😀'):
            for offset in range(len(character.encode())):
                data=('a'*(10000-offset)+character+'z').encode()
                try:data[:10000].decode('utf-8');valid=True
                except UnicodeDecodeError:valid=False
                self.assertEqual(not rejects_boundary_byte(data[10000],'bf-jle'),valid)
        # This local guard is not a complete validator: invalid leader bytes pass.
        self.assertFalse(rejects_boundary_byte(0xc0,'bf-jle'))
        self.assertFalse(rejects_boundary_byte(0xff,'c0-jl'))

if __name__=='__main__':unittest.main()
