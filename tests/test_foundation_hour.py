"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_hour as hour
from elf_index import sections


class HourEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not hour.TARGET.is_file() or hour.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = hour.inspect(hour.TARGET)
        cls.data = hour.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return data

    def test_retained_record_matches_authenticated_target(self):
        record = hour.ROOT / 'research/work-items/foundation-hour-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_arithmetic_edges_from_decoded_operands(self):
        arithmetic = self.result['arithmetic']
        multiplier = int(arithmetic['multiplier'], 16)
        shift = arithmetic['shift']
        # Target-derived instruction operands, compared with independent division.
        for n, expected in [(0,0), (3599,0), (3600,1), (86399,23), (86400,24), (89999,24)]:
            self.assertEqual((n * multiplier) >> shift, expected)
        self.assertEqual(arithmetic['exhaustive_quotient_cases'], 90000)
        self.assertEqual(arithmetic['inner_error_domain'], [90000, 921599])
        self.assertEqual(arithmetic['outer_error_domain'], [921600, 0xffffffff])

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                hour.inspect(path)
            path.write_bytes(self.mutated(hour.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                hour.inspect(path)

    def test_instruction_mutations_rejected(self):
        for va in [hour.START+3, hour.START+5, hour.START+9,
                   hour.START+12, hour.START+21, hour.START+32]:
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, 'instruction window'):
                    hour.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_fde_extent_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        with self.assertRaisesRegex(ValueError, 'FDE record'):
            hour.analyze(self.mutated(eh['address']+0xad08+12, struct.pack('<I', 98)))

    def test_location_line_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Location layout'):
            hour.analyze(self.mutated(0x566aac8+16, struct.pack('<I', 63)))

    def test_relocation_target_mutation_rejected(self):
        rel = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rel['offset']:rel['offset']+rel['size']]
        for off in range(0, len(raw), 24):
            if struct.unpack_from('<Q', raw, off)[0] == 0x576efc0:
                with self.assertRaisesRegex(ValueError, 'Relative relocation'):
                    hour.analyze(self.mutated(rel['address']+off+16, struct.pack('<q', hour.START+1)))
                return
        self.fail('Expected GOT relocation missing')

    def test_caller_displacement_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Caller argument/call'):
            hour.analyze(self.mutated(0x1403816, b'\x00'))

    def test_independent_disassembly_and_corruption_controls(self):
        import importlib.util
        packet = hour.ROOT / 'research/work-items/foundation-hour-94'
        spec = importlib.util.spec_from_file_location('hour_crosscheck', packet / 'crosscheck.py')
        crosscheck = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(crosscheck)
        self.assertEqual(crosscheck.check(), json.loads((packet / 'boundaries.json').read_text()))
        raw = (packet / 'caller.objdump.txt').read_text()
        start, end = 0x14027b0, 0x1403c29
        off = self.offset(start)
        expected = self.data[off:off+end-start]
        for corrupted in [raw.replace('1403814:', '1403815:'),
                          raw.replace('ff 15 a6 b7 36 04', 'ff 15 a7 b7 36 04'),
                          raw.rsplit('\n', 2)[0]]:
            with self.assertRaises(ValueError):
                crosscheck.instructions(corrupted, start, end, expected)

    def test_additional_call_candidate_rejected(self):
        # Insert only into retained alignment padding, outside the claimed body.
        va = hour.END
        call = b'\xe8' + struct.pack('<i', hour.START - (va + 5))
        with self.assertRaisesRegex(ValueError, 'candidate set'):
            hour.analyze(self.mutated(va, call))


def synthetic_elf(rows, contents):
    """Minimal ELF64 carrying the given (name, address, size) section rows;
    contents maps a row index to the bytes placed at that row's offset."""
    shstr_row = len(rows)
    rows = list(rows) + [('.shstrtab', 0, 0)]
    names = b'\0'
    name_off = {}
    for name, _addr, _size in rows:
        if name not in name_off:
            name_off[name] = len(names)
            names += name.encode() + b'\0'
    rows[shstr_row] = ('.shstrtab', 0, len(names))
    shoff = 0x1000
    data = bytearray(shoff + len(rows) * 64)
    data[0:6] = b'\x7fELF\x02\x01'
    off = 0x200
    offsets = []
    for i, (_name, _addr, size) in enumerate(rows):
        offsets.append(off)
        blob = contents.get(i, b'')
        data[off:off + len(blob)] = blob
        off += max(size, len(blob)) + 0x10
    data[offsets[shstr_row]:offsets[shstr_row] + len(names)] = names
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, len(rows), shstr_row)
    for i, (name, addr, size) in enumerate(rows):
        struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                         name_off[name], 1, 0, addr, offsets[i], size, 0, 0, 1, 0)
    return bytes(data)


class DuplicateSectionNameTests(unittest.TestCase):
    """analyze() reads .eh_frame/.rela.dyn/.text through a name->section
    dict that keeps only the last same-named section. A duplicate name must
    be refused: with the valid .eh_frame first the pinned CIE gate failed at
    once, with it last the same bytes passed and ran much further, so the
    verdict flipped on section order alone."""
    EH_GOOD, EH_BAD = 0x3000000, 0x4000000

    def hour_elf(self, eh_order):
        rows = [('.text', hour.START, hour.END - hour.START),
                ('.eh_frame', self.EH_GOOD, 0x100),
                ('.eh_frame', self.EH_BAD, 0x100),
                ('.rela.dyn', 0x5000000, 0)]
        blobs = {0: hour.BODY,
                 1: hour.CIE + b'\0' * (0x100 - len(hour.CIE)),
                 2: b'\0' * 0x100}
        if eh_order == 'bad-first':
            rows = [rows[0], rows[2], rows[1], rows[3]]
            blobs = {0: hour.BODY, 1: b'\0' * 0x100,
                     2: hour.CIE + b'\0' * (0x100 - len(hour.CIE))}
        return synthetic_elf(rows, blobs)

    def test_duplicate_eh_frame_rejected_in_either_order(self):
        for order in ('good-first', 'bad-first'):
            with self.subTest(order=order):
                with self.assertRaisesRegex(ValueError, 'Duplicate section: .eh_frame'):
                    hour.analyze(self.hour_elf(order))

    def test_duplicate_rela_dyn_and_text_rejected(self):
        base = [('.text', hour.START, hour.END - hour.START),
                ('.eh_frame', self.EH_GOOD, 0x100),
                ('.rela.dyn', 0x5000000, 0)]
        blobs = {0: hour.BODY,
                 1: hour.CIE + b'\0' * (0x100 - len(hour.CIE))}
        for name, addr in [('.rela.dyn', 0x6000000), ('.text', 0x7000000)]:
            with self.subTest(name=name):
                data = synthetic_elf(base + [(name, addr, 0)], blobs)
                with self.assertRaisesRegex(ValueError, 'Duplicate section: ' + name):
                    hour.analyze(data)

    def test_unconsumed_duplicate_names_still_tolerated(self):
        # The guard is scoped to the names analyze() reads; duplicates of a
        # section it never looks up must not be rejected.
        rows = [('.text', hour.START, hour.END - hour.START),
                ('.eh_frame', self.EH_GOOD, 0x100),
                ('.rela.dyn', 0x5000000, 0),
                ('.debug_info', 0x6000000, 0),
                ('.debug_info', 0x7000000, 0)]
        blobs = {0: hour.BODY,
                 1: hour.CIE + b'\0' * (0x100 - len(hour.CIE))}
        with self.assertRaises(ValueError) as caught:
            hour.analyze(synthetic_elf(rows, blobs))
        self.assertNotIn('Duplicate section', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
