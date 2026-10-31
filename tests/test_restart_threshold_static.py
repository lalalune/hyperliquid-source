"""Target-bound controls for the restart wrapper; never read runtime files."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import restart_threshold_static as subject
from elf_index import sections


class RestartThresholdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('requires materialized node94 capture')
        cls.data = subject.TARGET.read_bytes()
        cls.report = subject.analyze(cls.data)
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def test_retained_evidence_and_native_regeneration(self):
        self.assertEqual(self.report, json.loads((subject.PACKET / 'records.json').read_text()))
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            subject.generate(subject.TARGET, out)
            for f in out.iterdir():
                self.assertEqual(f.read_bytes(), (subject.PACKET / f.name).read_bytes(), f.name)

    def test_floor_covers_complete_u64_partition(self):
        # For n=0 CF=1, result1. For every n in [1,2**64-1], CF=0
        # and addition0 preserves n without overflow. Boundary samples verify
        # the implementation; the two disjoint intervals give the proof.
        samples = [0, 1, 2, 255, 256, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
        samples += [x for k in range(1, 64) for x in [(1 << k) - 1, 1 << k, (1 << k) + 1]]
        for n in samples:
            self.assertEqual(subject.return_floor(n), max(1, n))
        for bad in [-1, 1 << 64, True, 1.0, None]:
            with self.assertRaises(ValueError):
                subject.return_floor(bad)

    def test_real_operand_and_control_corruptions(self):
        # Bypass identity only here, so actual downstream controls see changed
        # global offsets, argument/callback setup, template/reader call,
        # compare/ADC operand, reader entry clobber, error callback and zero.
        mutations = [0x13ca00a, 0x13ca010, 0x13ca018, 0x13ca020,
                     0x13ca02c, 0x13ca03a, 0x13ca045, 0x13ca053,
                     0x13ca075, 0x13ca079, 0x13ca0ac,
                     0x144b910, 0x144bce1, 0x144bcec,
                     0x144bdbb, 0x144bdbd, 0x144be10, 0x144be1c,
                     0x144be38, 0x1de68f, 0x1de690, 0x1de691]
        for va in mutations:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                changed[self.offset(va)] ^= 1
                with self.assertRaisesRegex(ValueError, 'instruction|template'):
                    subject.analyze(changed)

    def test_actual_relocations_and_locations(self):
        sec = next(s for s in self.sections if s['name'] == '.rela.dyn')
        offsets = {struct.unpack_from('<Q', self.data, p)[0]: p for p in range(sec['offset'], sec['offset'] + sec['size'], 24)}
        for slot in subject.RELATIVE:
            changed = bytearray(self.data)
            changed[offsets[slot] + 16] ^= 1
            with self.assertRaisesRegex(ValueError, 'relocation'):
                subject.analyze(changed)
        for va in [0x5666b80 + 16, 0x1ef2de, 0x5666a68 + 20]:
            changed = bytearray(self.data)
            changed[self.offset(va)] ^= 1
            with self.assertRaisesRegex(ValueError, 'Location'):
                subject.analyze(changed)
        for f in self.report['frame_records']:
            changed = bytearray(self.data)
            changed[self.offset(int(f['fde']['va'], 16)) + 12] ^= 1
            with self.assertRaisesRegex(ValueError, 'FDE'):
                subject.analyze(changed)

    def test_public_identity_gate_rejects_changed_or_other_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            changed = bytearray(self.data)
            changed[self.offset(0x13ca079)] ^= 1
            binary = root / 'changed'
            binary.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, 'pinned node94'):
                subject.generate(binary, root / 'out')
            self.assertFalse((root / 'out').exists())
            binary.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'pinned node94'):
                subject.generate(binary, root / 'out')
            with self.assertRaisesRegex(ValueError, 'pinned node94'):
                subject.generate(subject.ROOT / 'artifacts/node/115/hl-node', root / 'out')
