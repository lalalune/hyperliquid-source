"""Real node #94 byte bindings and static-evaluator corruption controls."""
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import u128_division as u

PACKET = ROOT / 'research/work-items/RE-004-u128-division-94'
BINARY = ROOT / 'artifacts/node/94/hl-node'


class DivisionEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file() or BINARY.stat().st_size == 133:
            raise unittest.SkipTest('materialize authenticated node #94 LFS input')
        cls.data = BINARY.read_bytes()
        u.check_digest(cls.data)
        cls.image = u.Image(cls.data)
        cls.listing = (PACKET / 'helper.llvm-objdump.txt').read_text()
        cls.rows = u.decode(cls.listing, cls.image)

    def test_full_packet_reproduces_from_authenticated_bytes(self):
        expected = json.loads((PACKET / 'evidence.json').read_text())
        actual = u.produce(BINARY, self.listing)
        self.assertEqual(actual, expected)
        self.assertEqual(actual['visited_instructions'], actual['instructions'])
        self.assertEqual(len(actual['return_counts']), 4)
        self.assertEqual(len(actual['decisions']), 10)

    def test_both_retained_decoders_agree(self):
        gnu = u.decode((PACKET / 'helper.gnu-objdump.txt').read_text(), self.image)
        self.assertEqual(self.rows, gnu)

    def test_incoming_call_is_a_decoded_start_with_the_bound_slot(self):
        extent = u.Fdes(self.image).range_of(0x333e310)
        self.assertEqual((extent['start'], extent['end']), (0x333e310, 0x333e441))
        rows = u.decode((PACKET / 'caller.gnu-objdump.txt').read_text(), self.image,
                        start=extent['start'], end=extent['end'])
        call = next(row for row in rows if row[0] == 0x333e361)
        self.assertEqual(call[2], 'call')
        self.assertEqual(call[1][:2], b'\xff\x15')
        slot = call[0] + 6 + struct.unpack('<i', call[1][2:])[0]
        self.assertEqual(slot, u.SLOT)
        self.assertEqual(self.image.relative_relocs()[slot], u.ENTRY)

    def test_high_quotient_and_remainder_edges(self):
        machine = u.Machine(self.rows)
        for n, d in [(2**128-1, 1), (2**128-1, 2**64-1),
                     (2**65, 2**64+1), (2**127, 2**127),
                     (2**127-1, 2**127), (2**128-1, 2**127+1)]:
            with self.subTest(n=n, d=d):
                self.assertEqual(machine.run(n, d)[0], n // d)

    def test_zero_divisor_traps_on_both_hardware_widths(self):
        for n, width in [(0, 32), (2**64, 32), (2**96, 64)]:
            with self.subTest(n=n):
                with self.assertRaises(u.DivideError) as caught:
                    u.Machine(self.rows).run(n, 0)
                self.assertEqual(caught.exception.width, width)
                self.assertEqual(caught.exception.reason, 'zero divisor')

    def test_listing_holes_wrong_bytes_and_interior_targets_are_rejected(self):
        for listing in [self.listing.replace('49 89 d0', '49 89 f0', 1),
                        self.listing.replace('0x565f61e <', '0x565f61f <', 1),
                        '\n'.join(x for x in self.listing.splitlines()
                                  if not x.lstrip().startswith('565f5a0:'))]:
            with self.assertRaises(u.EvidenceError):
                u.decode(listing, self.image)

    def test_undefined_registers_flags_and_unknown_instructions_stop(self):
        for pc, op, args in [(u.ENTRY, 'mov', ('r8', 'rbx')),
                             (u.ENTRY, 'jae', ('0x565f61e',)),
                             (u.ENTRY, 'call', ('0x565f5a0',))]:
            rows = [(row[0], row[1], op, args) if row[0] == pc else row
                    for row in self.rows]
            with self.assertRaises(u.EvidenceError):
                u.Machine(rows).run(1, 1)

    def test_real_instruction_byte_mutations_below_identity_gate(self):
        tool = os.environ.get('LLVM_OBJDUMP') or shutil.which('objdump')
        if not tool:
            self.skipTest('GNU or LLVM objdump needed for fresh mutation decoding')
        controls = json.loads((PACKET / 'corruption-controls.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'mutant.elf'
            for control in controls:
                with self.subTest(control=control['name']):
                    original = bytes.fromhex(control['original'])
                    altered = bytes.fromhex(control['mutated'])
                    offset = self.image.off(int(control['va'], 0), len(original))
                    self.assertEqual(self.data[offset:offset+len(original)], original)
                    data = bytearray(self.data)
                    data[offset:offset+len(original)] = altered
                    with self.assertRaises(u.EvidenceError):
                        u.check_digest(data)
                    # Deliberately bypass only the global hash to exercise semantic
                    # controls, freshly decoding actual changed instruction bytes.
                    path.write_bytes(data)
                    rows = u.decode(u.disassemble(path, tool), u.Image(data))
                    n, d = int(control['numerator'], 0), int(control['denominator'], 0)
                    expected = n // d
                    if 'error' in control:
                        with self.assertRaises(u.DivideError) as caught:
                            u.Machine(rows).run(n, d)
                        self.assertEqual(str(caught.exception), control['error'])
                    else:
                        observed = u.Machine(rows).run(n, d)[0]
                        self.assertEqual(observed, int(control['observed'], 0))
                        self.assertNotEqual(observed, expected)


if __name__ == '__main__':
    unittest.main()
