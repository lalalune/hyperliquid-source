"""Real pinned-ELF binding and targeted corruption controls, no captured execution."""
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('node115_info_proof', ROOT/'research/work-items/RE-001-info-diagnostic-115/proof.py')
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)

class InfoCoordinatesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT/p.TARGET).read_bytes()
        cls.image = p.Image(cls.data)
        cls.record = cls.image.offset(p.LOCATION, 24)
        cls.reloc, cls.row = cls.image.relocations(p.LOCATION)

    def changed(self, offset, fmt, value):
        data = bytearray(self.data)
        struct.pack_into(fmt, data, offset, value)
        return data

    def test_authentic_target(self):
        p.authenticate(self.data)
        self.assertEqual(p.binding(self.data)['line'], 664)

    def test_real_native_fde_and_alignment(self):
        result = p.prove()
        self.assertEqual(result['extent'], [hex(n) for n in p.EXTENT])
        self.assertEqual(result['location_va'], hex(p.LOCATION))
        self.assertEqual([r['va'] for r in result['xrefs']],
                         [hex(va) for va, _ in p.SITES])

    def test_wrong_digest_and_truncation(self):
        with self.assertRaises(ValueError):
            p.authenticate(self.changed(self.record, '<B', 1))
        with self.assertRaises(ValueError):
            p.authenticate(self.data[:-1])

    def test_location_fields_corrupted_below_digest(self):
        for delta, fmt, value in [(0,'<Q',1),(8,'<Q',len(p.SOURCE)-1),(16,'<I',665),(20,'<I',121)]:
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                p.binding(self.changed(self.record+delta, fmt, value))

    def test_path_corruption_below_digest(self):
        offset = self.image.offset(self.row[2], len(p.SOURCE))
        with self.assertRaises(ValueError):
            p.binding(self.changed(offset, '<B', 0))

    def test_relocation_missing_wrong_type_symbol_and_addend(self):
        for delta, value in [(0,p.LOCATION+1),(8,1),(8,(1<<32)|8),(16,0)]:
            with self.subTest(delta=delta, value=value), self.assertRaises(ValueError):
                p.binding(self.changed(self.reloc+delta, '<Q', value))

    def test_duplicate_relocation(self):
        with self.assertRaises(ValueError):
            p.binding(self.changed(self.reloc+24, '<Q', p.LOCATION))

    def test_each_lea_opcode_and_displacement(self):
        for va, expected in p.SITES:
            offset = self.image.offset(va, 7)
            for delta in [0,3]:
                with self.subTest(va=va, delta=delta), self.assertRaises(ValueError):
                    p.binding(self.changed(offset+delta, '<B', expected[delta]^1))

    def test_invalid_and_ambiguous_file_mapping(self):
        with self.assertRaises(ValueError):
            self.image.offset(1<<63, 24)
        image = p.Image(self.data)
        owner = next(x for x in image.ph if x[0]==1 and x[3]<=p.LOCATION<x[3]+x[5])
        image.ph.append(owner)
        with self.assertRaises(ValueError):
            image.offset(p.LOCATION, 24)

    def test_missing_changed_duplicate_and_overlapping_fde(self):
        valid = '0000 FDE cie=0010 pc=029691a0..02969331\n'
        p.frame_binding(valid)
        for text in ['', valid.replace('02969331','02969330'), valid*2,
                     valid+'0001 FDE cie=0010 pc=029692a8..029692bc\n']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                p.frame_binding(text)

    def test_native_alignment_and_byte_controls(self):
        valid = ''.join(f' {va:x}: '+raw.hex(' ')+'  lea  0x0(%rip),%rdi\n' for va,raw in p.SITES)
        p.instruction_binding(valid)
        for text in ['',valid.replace('lea','mov'),valid.replace('48 8d','49 8d'),valid+valid,
                     valid.replace('29692a8:','29692a9:')]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                p.instruction_binding(text)

if __name__ == '__main__':
    unittest.main()
