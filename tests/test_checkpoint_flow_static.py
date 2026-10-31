"""Static checkpoint branch predicates and actual-capture corruption controls."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import checkpoint_flow_static as tool


class CheckpointFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_real_packet_and_engine_bindings(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['prune_count'],100)
        self.assertEqual([(m['line'],m['column']) for m in self.record['messages']],[(279,25),(286,17)])
        self.assertTrue(all(m['source_path'].endswith('/l1/src/abci/engine.rs') for m in self.record['messages']))

    def test_overflow_extremes_and_independent_sign_bit_form(self):
        words=[0,1,tool.MIN-2,tool.MIN-1,tool.MIN,tool.MIN+1,tool.MIN+2,(1<<64)-1]
        # CMP computes 0-word; signed overflow iff operand/result signs differ
        # and result differs in sign from the zero left operand.
        for word in words:
            result=(-word)&((1<<64)-1)
            bit_form=bool(((0^word)&(0^result))>>63)
            self.assertEqual(tool.zero_minus_overflows(word),bit_form)
            self.assertEqual(bit_form,word==tool.MIN)
        for value in (-1,1<<64,True):
            with self.assertRaisesRegex(ValueError,'u64'):
                tool.zero_minus_overflows(value)

    def test_conditional_normal_return_paths(self):
        words=[0,1,2,tool.MIN-1,tool.MIN,tool.MIN+1,(1<<64)-1]
        for mode in (0,1,0x100,0xffffffff):
            for tar in words:
                for prune in words:
                    trace=tool.selected_trace(mode,tar,prune)
                    if mode:
                        expected=['tar']+(['critical_tar'] if tar==tool.MIN else [])+['followup','cleanup']
                    else:
                        expected=['prune_100']+(['critical_prune'] if prune else [])+['cleanup']
                    self.assertEqual(trace,expected)
        with self.assertRaisesRegex(ValueError,'mode'):
            tool.selected_trace(-1,0,0)

    def test_actual_dispatch_result_and_join_corruptions(self):
        for va in (0x432f330,0x432f35b,0x432f380,0x432f385,0x432f3eb,
                   0x432f3f0,0x432f401,0x432f462,0x432f506):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))

    def test_actual_callee_slots_and_relocations(self):
        for va,(slot,target) in tool.CALLS.items():
            raw=bytearray(self.img.read(va,6));raw[-1]^=1
            with self.subTest(call=hex(va)),self.assertRaisesRegex(ValueError,'call slot'):
                tool.observe(self.changed(va,raw))
        for slot,target in (tool.CALLS[0x432f378],tool.CALLS[0x432f4ed]):
            data=bytearray(self.data);needle=struct.pack('<QQq',slot,8,target);off=data.find(needle)
            self.assertGreaterEqual(off,0);self.assertEqual(data.find(needle,off+1),-1)
            data[off+16]^=1
            with self.assertRaisesRegex(ValueError,'call relocation'):
                tool.observe(data)

    def test_actual_message_source_fde_and_identity(self):
        for va in (0x1fd66f+1,0x1e78e4+1,0x571c948+16):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',732)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))


if __name__=='__main__':unittest.main()
