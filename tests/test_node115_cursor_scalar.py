import json
import mmap
from pathlib import Path
import re
import tempfile
import unittest

from tools import node115_cursor_scalar as bind

PACKET = bind.ROOT / 'research/work-items/RE-001-node115-cursor-scalar'


class CursorScalarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = bind.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def test_target_record_regenerates(self):
        self.assertEqual(bind.render(bind.collect(self.data)), (PACKET / 'records.json').read_bytes())

    def test_readme_counts_match_records(self):
        doc = (PACKET / 'README.md').read_text()
        f = json.loads((PACKET / 'records.json').read_text())['function']
        for label, value in [('instructions', len(f['instructions'])), ('callees', len(f['callees'])),
                             ('rel32 caller candidates', len(f['rel32_caller_candidates']))]:
            self.assertRegex(doc, r'\*\*' + str(value) + ' ' + label + r'\*\*')
        self.assertIn('**%d bytes**' % f['size'], doc)
        self.assertIn(format(json.loads((PACKET / 'records.json').read_text())['target_size'], ','), doc)
        self.assertEqual(len(bytes.fromhex(f['padding_hex'])), 4)
        self.assertEqual(sum(x['opcode'] == 'jmp' for x in f['rel32_caller_candidates']), 0)
        self.assertEqual(sum(x['opcode'] == 'call' for x in f['rel32_caller_candidates']), 7)

    def test_empty_and_ascii(self):
        self.assertEqual(bind.model(b'', 0, 0), (0, None, 0))
        for x in (0, 0x41, 0x7f):
            self.assertEqual(bind.model(bytes([x]), 0, 1), (1, x, 1))

    def test_variable_width_values(self):
        for raw, value in ((b'\xc2\xa2', 0xa2), (b'\xe2\x82\xac', 0x20ac),
                           (b'\xf0\x9f\x92\xa9', 0x1f4a9)):
            self.assertEqual(bind.model(raw, 0, len(raw)), (1, value, len(raw)))

    def test_invalid_bytes_are_masked_not_rejected(self):
        for raw, value in ((b'\x80\xff', 63), (b'\xdf\x00', 0x7c0),
                           (b'\xe0\xff\xff', 0xfff), (b'\xff\xff\xff\xff', 0x1fffff)):
            self.assertEqual(bind.model(raw, 0, 1), (1, value, len(raw)))

    def test_missing_accessible_continuation(self):
        with self.assertRaises(ValueError):
            bind.model(b'\xf0\x80', 0, 2)

    def test_wrong_digest_fails_before_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bad = root / 'bad'
            with bad.open('wb') as stream:
                stream.truncate(bind.SIZE)
            from unittest.mock import patch
            with patch('sys.argv', ['producer', '--binary', str(bad), '--out', str(root / 'out')]):
                with self.assertRaises(ValueError):
                    bind.main()
            self.assertFalse((root / 'out').exists())

    def test_mutated_instruction_rejected(self):
        offset = bind.TEXT_FILE + bind.START - bind.TEXT_START
        body = bytearray(self.data[offset:offset + bind.END - bind.START])
        body[0x24] ^= 1
        with self.assertRaises(ValueError):
            bind.decode(body)

    def test_shifted_fde_rejected(self):
        fde = bytearray(bind.FDE_BYTES)
        fde[8] ^= 1
        with self.assertRaises(ValueError):
            bind.frame(fde, bind.CIE_BYTES)

    def test_changed_direct_target_rejected(self):
        addr = bind.CALLERS[0]
        offset = bind.TEXT_FILE + addr - bind.TEXT_START
        raw = bytearray(self.data[offset:offset + 5])
        bind.require_target(addr, raw)
        raw[1] ^= 1
        with self.assertRaises(ValueError):
            bind.require_target(addr, raw)


if __name__ == '__main__':
    unittest.main()
