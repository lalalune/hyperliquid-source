"""Raw state brackets and actual-byte controls; no native TLS/thread access."""
import collections
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import runtime_state_static as tool


class RuntimeStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_real_packet_and_four_owners(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(len(self.record['owners']),4)
        self.assertEqual([s['line'] for s in self.record['sources']],[28,17])

    def test_complete_declared_byte_and_context_domain(self):
        counts=collections.Counter()
        for prior in range(256):
            for after in range(256):
                for present in (False,True):
                    result=tool.bracket(prior,after,present);counts[result['path']]+=1
                    if prior==2:
                        self.assertIsNone(result['body_state'])
                        self.assertEqual(result['path'],'pre_body_state_failure')
                    else:
                        self.assertEqual(result['body_state'],2)
                        expected='post_body_context_missing' if not present else 'restore_prior_state' if after==2 else 'post_body_state_failure'
                        self.assertEqual(result['path'],expected)
                    self.assertEqual(result['restored'],prior if prior!=2 and present and after==2 else None)
        self.assertEqual(dict(counts),{'post_body_context_missing':65280,'post_body_state_failure':65025,
                                     'restore_prior_state':255,'pre_body_state_failure':512})

    def test_all_saved_flag_words_and_model_domain(self):
        for flags in range(65536):
            saved,cleared=tool.saved_flags(flags)
            self.assertEqual(saved,flags)
            self.assertEqual(cleared//256,flags//256)
            self.assertEqual(cleared%256,0)
        with self.assertRaisesRegex(ValueError,'raw state'):
            tool.bracket(256,2,True)

    def test_actual_four_bracket_operands_and_context_checks(self):
        for case,forms in zip(tool.CASES,tool.FORMS):
            for va,raw in zip((case[3],case[4],case[5],case[6],case[8],case[12]),forms):
                changed=bytearray.fromhex(raw);changed[-1]^=1
                with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/store'):
                    tool.observe(self.changed(va,changed))
            with self.assertRaisesRegex(ValueError,'context pointer test'):
                tool.observe(self.changed(case[9]+5,b'\x90'))

    def test_actual_failure_routes_and_context_callee(self):
        for case in tool.CASES:
            with self.assertRaisesRegex(ValueError,'prior-state branch'):
                tool.observe(self.changed(case[7],b'\x0f\x85'))
            raw=bytearray(self.img.read(case[9],5));raw[-1]^=1
            with self.assertRaisesRegex(ValueError,'context helper'):
                tool.observe(self.changed(case[9],raw))
        for loc in (0x56b7c30,0x57556e8):
            with self.assertRaisesRegex(ValueError,'source context'):
                tool.observe(self.changed(loc+16,struct.pack('<I',999)))

    def test_actual_owner_extents_and_identity(self):
        for owner in self.record['owners']:
            fde=int(owner['fde'],16);size=int(owner['end_exclusive'],16)-int(owner['start'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                tool.observe(self.changed(fde+12,struct.pack('<i',size-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.CASES[0][0],b'\x90'))


if __name__=='__main__':unittest.main()
