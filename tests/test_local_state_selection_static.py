"""Message-bound u64 decisions and actual-capture negative controls."""
import itertools
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import local_state_selection_static as tool


class LocalStateSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_real_record_and_selected_join(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['stale_join']['copy_size'],0x3ae8)
        self.assertEqual(self.record['owner_source_context']['line'],111)

    def test_all_low_and_overflow_boundary_word_population(self):
        words=list(range(20001))+list(range(tool.MAX-20000,tool.MAX+1))
        self.assertEqual(len(words),40002)
        for word in words:
            self.assertEqual(tool.saturated_limit(word),min(word+20000,tool.MAX))
        for value in [-1,1<<64,True]:
            with self.assertRaisesRegex(ValueError,'u64'):
                tool.saturated_limit(value)

    def test_priority_equality_and_wrap_selection(self):
        words=[0,1,19999,20000,20001,tool.MAX-20001,tool.MAX-20000,
               tool.MAX-19999,tool.MAX-1,tool.MAX]
        for a,b,c in itertools.product(words,repeat=3):
            limit=min(a+20000,tool.MAX)
            expected='too_far_behind_message' if limit<=b else 'stale_hardfork_message' if a<c else 'continue_selected_window'
            self.assertEqual(tool.select(a,b,c),expected)
        self.assertEqual(tool.select(1,20000,0),'continue_selected_window')
        self.assertEqual(tool.select(1,20001,tool.MAX),'too_far_behind_message')
        self.assertEqual(tool.select(tool.MAX,tool.MAX,0),'too_far_behind_message')
        self.assertEqual(tool.select(100,100,101),'stale_hardfork_message')
        self.assertEqual(tool.select(100,100,100),'continue_selected_window')

    def test_actual_arithmetic_condition_and_priority_corruptions(self):
        for va in (0x226ab12,0x226ab18,0x226ab1d,0x226ab2b,0x226ab3e,
                   0x226ab52,0x226ab68,0x226ab72,0x226ab88):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.subTest(va=hex(va)),self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))

    def test_actual_input_and_message_bindings(self):
        for va in (0x226a974,0x226a97c,0x226a984,0x226aba2):
            raw=bytearray.fromhex(tool.ANCHORS[va]);raw[-1]^=1
            with self.assertRaisesRegex(ValueError,'operand/control'):
                tool.observe(self.changed(va,raw))
        for va in (0x3d79b2,0x3d798f):
            with self.assertRaisesRegex(ValueError,'reason bytes'):
                tool.observe(self.changed(va,b'X'))

    def test_actual_source_fde_and_identity(self):
        with self.assertRaisesRegex(ValueError,'source context'):
            tool.observe(self.changed(0x569e5d0+16,struct.pack('<I',112)))
        fde=int(self.record['owner']['fde'],16)
        with self.assertRaisesRegex(ValueError,'FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<i',11026)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.START,b'\x90'))


if __name__=='__main__':unittest.main()
