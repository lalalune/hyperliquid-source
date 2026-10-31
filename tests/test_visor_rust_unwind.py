"""Real visor metadata/code controls, no captured execution or invented behavior."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import visor_rust_unwind as subject


class VisorRustUnwindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = subject.ROOT/'artifacts/visor/captured/hl-visor'
        cls.data = cls.binary.read_bytes()
        subject.authenticate(cls.data)
        cls.instructions, cls.exports, cls.versions = subject.decode(cls.data)
        cls.facts = subject.analyse(cls.data, cls.instructions)

    def relocation_offset(self, slot):
        matches = []
        for section in subject.sections(self.data):
            if section['type'] == 4:
                for offset in range(section['offset'], section['offset']+section['size'], 24):
                    if struct.unpack_from('<Q', self.data, offset)[0] == slot:
                        matches.append(offset)
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_five_exact_native_windows_and_independent_frame_records(self):
        f = self.facts
        self.assertEqual(f['target_sha256'], subject.SHA256)
        self.assertEqual(f['denominator'], {'fdes':5,'bytes':527,'instructions':123,
                         'calls':12,'owner_calls':8,'owner_calls_with_cleanup':4,
                         'call_site_intervals':3,'cleanup_pads':1})
        self.assertEqual(len(self.exports), 11)
        self.assertEqual(self.exports['frames.txt'].count('FDE cie='), 5)
        for name, window in f['windows'].items():
            first, last = subject.RANGES[name]
            self.assertEqual((int(window['fde']['start'],16),int(window['fde']['end'],16)),(first,last))
            self.assertEqual(hashlib.sha256(subject.read_va(self.data, first,last-first)[1]).hexdigest(),window['sha256'])

    def test_rust_source_error_edges_and_cleanup_are_distinguished_from_runtime(self):
        f = self.facts
        self.assertEqual([(x['source'],x['line'],x['column']) for x in f['locations']],
                         [('base/src/liner.rs',17,84),('base/src/liner.rs',17,74)])
        self.assertEqual(f['option_diagnostic']['text'],'called `Option::unwrap()` on a `None` value')
        self.assertEqual(f['resume']['symbol'],'_Unwind_Resume')
        self.assertEqual(f['opaque_personality_binding']['addend'],'0x696f30')
        calls = {x['site_va']:x for x in f['calls']}
        self.assertEqual(calls['0x3c8000']['lsda_row'],1)
        self.assertEqual(calls['0x3c8030']['lsda_row'],1)
        self.assertEqual(calls['0x3c8051']['lsda_row'],2)
        self.assertIsNone(f['lsda']['rows'][2]['landing_pad_va'])

    def test_wrong_identity_rejected_separately_from_below_identity_controls(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError,'pinned captured visor'):
            subject.authenticate(changed)

    def test_actual_cleanup_table_corruptions_fail_below_identity(self):
        table = self.facts['lsda']
        offset = int(table['file_offset'],16)
        rows = table['rows']
        cases = [('header',offset+1,0x9b),('table length',offset+3,16),
                 ('inside-instruction interval',offset+rows[0]['field_offsets'][1],108),
                 ('inside-instruction pad',offset+rows[1]['field_offsets'][2],0xc9),
                 ('unsupported action',offset+rows[1]['field_offsets'][3],1)]
        for name, position, value in cases:
            with self.subTest(name=name):
                changed = bytearray(self.data);changed[position]=value
                with self.assertRaises(ValueError):subject.analyse(changed,self.instructions)

    def test_upper_bound_padding_is_not_claimed_as_lsda_object_data(self):
        table = self.facts['lsda']
        end = int(table['declared_table_end_va'],16)
        self.assertLess(end,int(table['upper_bound_va'],16))
        changed = bytearray(self.data)
        changed[subject.read_va(changed,end,1)[0]]=0xa5
        result = subject.analyse(changed,self.instructions)
        self.assertEqual(result['lsda']['rows'],table['rows'])
        self.assertEqual(result['calls'],self.facts['calls'])
        self.assertNotEqual(result['target_sha256'],self.facts['target_sha256'])

    def test_actual_source_and_personality_retarget_controls(self):
        for slot in (0x7af278,0x7e9468,0x7e4de0):
            with self.subTest(slot=hex(slot)):
                changed = bytearray(self.data)
                offset = self.relocation_offset(slot)+16
                addend = struct.unpack_from('<q',changed,offset)[0]
                struct.pack_into('<q',changed,offset,addend+1 if slot==0x7af278 else 0x49abb0)
                with self.assertRaises(ValueError):subject.analyse(changed,self.instructions)
        changed = bytearray(self.data)
        offset = subject.read_va(changed,0x7af278+16,4)[0]
        struct.pack_into('<I',changed,offset,18)
        with self.assertRaisesRegex(ValueError,'Location contents'):subject.analyse(changed,self.instructions)

    def test_actual_resume_dynamic_symbol_and_plt_controls(self):
        changed = bytearray(self.data)
        strings = next(s for s in subject.sections(changed) if s['name']=='.dynstr')
        offset = changed.find(b'_Unwind_Resume\0',strings['offset'],strings['offset']+strings['size'])
        self.assertGreaterEqual(offset,0)
        changed[offset]=ord('X')
        with self.assertRaisesRegex(ValueError,'Resume import'):subject.analyse(changed,self.instructions)
        changed = bytearray(self.data)
        plt = int(self.facts['resume']['plt_va'],16)
        changed[subject.read_va(changed,plt+2,1)[0]] ^= 1
        with self.assertRaises(ValueError):subject.analyse(changed,self.instructions)

    def test_instruction_controls_are_redecoded_by_both_native_tools(self):
        # Native byte/boundary validation succeeds first, so rejection below is
        # from the source/cleanup/call obligations, not a stale decode or SHA gate.
        for name, va in [('exception argument',0x3c8050),('Option literal',0x49ab9a),
                         ('source reference',0x3c7ffc),('panic call edge',0x3c8002)]:
            with self.subTest(name=name):
                changed = bytearray(self.data)
                offset = subject.read_va(changed,va,1)[0]
                changed[offset] ^= 1
                decoded, _, _ = subject.decode(changed)
                with self.assertRaises(ValueError):subject.analyse(changed,decoded)

    def test_two_authenticated_collections_reproduce_all_exports(self):
        first, exports, versions = subject.collect(self.binary)
        second, other, again = subject.collect(self.binary)
        self.assertEqual(first,second)
        self.assertEqual(exports,other)
        self.assertEqual(versions,again)
        self.assertEqual(exports,self.exports)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'wrong-visor'
            path.write_bytes(b'not a captured binary')
            with self.assertRaisesRegex(ValueError,'pinned captured visor'):subject.collect(path)


if __name__ == '__main__':
    unittest.main()
