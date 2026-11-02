"""Target-byte controls for the async frame stream's exact-I/O loop evidence."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-tcp-stream-94'
spec = importlib.util.spec_from_file_location('tcp_stream_evidence', PACKET / 'verify.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class StreamEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.TARGET.read_bytes()
        cls.sections = evidence.sections(cls.data)

    def offset(self, address):
        s = next(s for s in self.sections if s['type'] != 8 and
                 s['address'] <= address < s['address'] + s['size'])
        return s['offset'] + address - s['address']

    def test_full_target_identity_and_retained_record(self):
        import json
        expected = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(evidence.analyze(self.data), expected)
        self.assertEqual(len(expected['instructions']), 21)
        self.assertEqual([r['bytes'] for r in expected['functions'].values()], [702, 867])

    def test_claimed_addresses_are_instruction_starts_in_both_native_listings(self):
        import re
        for provider in ('gnu', 'llvm'):
            listing = '\n'.join((PACKET / f'{name}.{provider}.txt').read_text()
                                for name in ('read-exact', 'write-all'))
            starts = {int(m.group(1), 16) for m in
                      re.finditer(r'^\s*([0-9a-f]+):\s', listing, re.M)}
            for name, address, *_ in evidence.FACTS:
                self.assertIn(address, starts, (provider, name))

    def test_each_claimed_instruction_rejects_changed_bytes_below_identity(self):
        for name, address, *_ in evidence.FACTS:
            with self.subTest(name=name):
                changed = bytearray(self.data)
                changed[self.offset(address)] ^= 1
                with self.assertRaisesRegex(ValueError, 'changed instruction'):
                    evidence.inspect(changed)

    def test_eof_kind_text_and_call_target_are_not_interchangeable(self):
        changed = bytearray(self.data)
        changed[self.offset(0x7d0cd4)] ^= 1
        with self.assertRaisesRegex(ValueError, 'EOF text'):
            evidence.inspect(changed)
        changed = bytearray(self.data)
        # The selected RELA target is scanned structurally, independently of the opcode.
        import struct
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
            if struct.unpack_from('<Q', changed, off)[0] == 0x576ee60:
                struct.pack_into('<q', changed, off + 16, 0x4edac61)
                break
        with self.assertRaisesRegex(ValueError, 'constructor relocation'):
            evidence.inspect(changed)

    def test_unqualified_seam_does_not_claim_authentic_input(self):
        self.assertEqual(evidence.inspect(self.data)['origin'], 'unqualified structural inspection')
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            evidence.analyze(changed)


if __name__ == '__main__':
    unittest.main()
