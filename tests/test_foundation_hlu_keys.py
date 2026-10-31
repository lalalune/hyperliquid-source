"""Target-grounded controls for the static HLU validator-key packet (no node execution)."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_hlu_keys as hlu
from elf_index import sections

PACKET = hlu.ROOT / 'research/work-items/foundation-hlu-validator-keys-94'


class HluKeyEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not hlu.TARGET.is_file() or hlu.TARGET.stat().st_size != hlu.SIZE:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = hlu.inspect(hlu.TARGET)
        cls.data = hlu.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return data

    def flipped(self, va):
        return self.mutated(va, bytes([self.data[self.offset(va)] ^ 1]))

    def rela_entry(self, address):
        rel = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rel['offset']:rel['offset'] + rel['size']]
        for off in range(0, len(raw), 24):
            if struct.unpack_from('<Q', raw, off)[0] == address:
                return rel['address'] + off
        self.fail(f'Expected relocation at {address:#x} missing')

    def test_retained_record_matches_authenticated_target(self):
        self.assertEqual(self.result, json.loads((PACKET / 'evidence.json').read_text()))

    def test_decoded_facts(self):
        loader = self.result['loader']
        self.assertEqual(loader['assertion']['minimum_len'], 2)
        self.assertEqual(loader['key_stride_bytes'], 32)
        self.assertEqual(loader['collector']['input_stride_bytes'], 32)
        self.assertEqual(loader['collector']['output_stride_bytes'], 152)
        self.assertEqual(int(loader['collector']['capacity_guard'], 16), ((1 << 63) - 1) // 152 * 32)
        self.assertEqual(loader['path_format']['literal'], '/hyperliquid_data/main_validator_keys.json')
        self.assertEqual(loader['path_format']['argument_contents'], 'not established')
        lines = [(loc['line'], loc['column']) for loc in self.result['source_locations'][:3]]
        self.assertEqual(lines, [(57, 13), (58, 18), (61, 13)])

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                hlu.inspect(path)
            path.write_bytes(self.flipped(hlu.LOADER[0]))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                hlu.inspect(path)

    def test_window_mutations_rejected(self):
        for name, va in [('loader', hlu.LOADER[0] + 1), ('loader', hlu.LOADER[1] - 1),
                         ('collector', hlu.COLLECTOR[0] + 1), ('shim', hlu.SHIM[0] + 1)]:
            with self.subTest(name=name, va=hex(va)):
                with self.assertRaisesRegex(ValueError, f'{name} instruction window'):
                    hlu.analyze(self.flipped(va))

    def test_operand_mutations_rejected(self):
        # Each locked operand carries a claimed fact: threshold, strides, guard, flag.
        for va in [0x13d26ba, 0x13d26c4, 0x13e0766, 0x13e076a, 0x13e0744, 0x13d271e]:
            with self.subTest(va=hex(va)):
                with self.assertRaises(ValueError):
                    hlu.analyze(self.flipped(va))

    def test_fde_extent_mutation_rejected(self):
        fde_va = hlu.FDES['loader'][0]
        with self.assertRaisesRegex(ValueError, 'loader FDE PC/range'):
            hlu.analyze(self.mutated(fde_va + 12, struct.pack('<I', 419)))

    def test_location_line_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Location layout'):
            hlu.analyze(self.mutated(0x5666d18 + 16, struct.pack('<I', 62)))

    def test_template_and_message_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Format template'):
            hlu.analyze(self.mutated(hlu.TEMPLATE_VA + 2, b'X'))
        with self.assertRaisesRegex(ValueError, 'Format template'):
            hlu.analyze(self.mutated(hlu.TEMPLATE_VA + 1, b'\x2b'))
        with self.assertRaisesRegex(ValueError, 'Error message'):
            hlu.analyze(self.mutated(0x216e5d + 50, b'3'))

    def test_relocation_target_mutations_rejected(self):
        for slot in [0x577ab08, 0x576ea08, 0x576e928, 0x576e848]:
            with self.subTest(slot=hex(slot)):
                entry = self.rela_entry(slot)
                addend = struct.unpack_from('<q', self.data, self.offset(entry + 16))[0]
                with self.assertRaisesRegex(ValueError, 'Relative relocation'):
                    hlu.analyze(self.mutated(entry + 16, struct.pack('<q', addend + 1)))

    def test_additional_loader_reference_rejected(self):
        # Retarget an unrelated relocation addend to the loader start.
        entry = self.rela_entry(0x5666d00)
        with self.assertRaisesRegex(ValueError, 'Location path relocation|Relative references to the loader'):
            hlu.analyze(self.mutated(entry + 16, struct.pack('<q', hlu.LOADER[0])))

    def test_additional_call_and_slot_load_candidates_rejected(self):
        # Insert only into retained int3 padding after the shim, outside every claimed window.
        va = hlu.SHIM[1]
        call = b'\xe8' + struct.pack('<i', hlu.LOADER[0] - (va + 5))
        with self.assertRaisesRegex(ValueError, 'Direct call candidates'):
            hlu.analyze(self.mutated(va, call))
        load = b'\x48\x8b\x05' + struct.pack('<i', 0x576ea08 - (va + 7))
        with self.assertRaisesRegex(ValueError, 'slot load candidates'):
            hlu.analyze(self.mutated(va, load))

    def test_independent_disassembly_and_corruption_controls(self):
        spec = importlib.util.spec_from_file_location('hlu_crosscheck', PACKET / 'crosscheck.py')
        crosscheck = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(crosscheck)
        self.assertEqual(crosscheck.check(), json.loads((PACKET / 'boundaries.json').read_text()))
        raw = (PACKET / 'loader.objdump.txt').read_text()
        start, end = hlu.LOADER
        off = self.offset(start)
        expected = self.data[off:off + end - start]
        for corrupted in [raw.replace(' 13d26b7:', ' 13d26b8:'),
                          raw.replace('49 83 fd 01', '49 83 fd 02'),
                          raw.rsplit('\n', 2)[0]]:
            with self.assertRaises(ValueError):
                crosscheck.instructions(corrupted, start, end, expected)


if __name__ == '__main__':
    unittest.main()
