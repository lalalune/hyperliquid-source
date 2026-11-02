import hashlib
import json
import mmap
from pathlib import Path
import re
import shutil
import struct
import tempfile
import unittest

from tools import word_complement_94 as bind

PACKET = bind.ROOT / 'research/work-items/RE-001-word-complement-94'


class WordComplementTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = bind.BINARY.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_READ)
        cls.sec = bind.sections(cls.data)
        cls.offset = cls.sec['.text']['offset'] + bind.START - cls.sec['.text']['va']
        cls.body = cls.data[cls.offset:cls.offset + bind.END - bind.START]
        cls.record, cls.walk = bind.collect(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def test_binary_and_generated_packet(self):
        self.assertEqual(json.loads((PACKET / 'records.json').read_text()), self.record)
        self.assertEqual((PACKET / 'walk.txt').read_text(), self.walk)
        self.assertEqual(hashlib.sha256(self.body).hexdigest(), bind.BODY_HASH)

    def test_readme_counts_derive_from_records(self):
        text = (PACKET / 'README.md').read_text()
        checks = {'bytes': self.record['window']['size_bytes'],
                  'padding bytes': self.record['window']['padding']['bytes'],
                  'instructions': self.record['instruction_count'],
                  'callees': len(self.record['callees']),
                  'direct-reference candidates': len(self.record['direct_reference_candidates']),
                  'exact body matches': len(self.record['exact_body_matches_in_text']),
                  'relative relocation slots': len(self.record['relative_relocation_slots'])}
        rule = self.record['rule']
        self.assertEqual((rule['low_budget_max'], rule['cost'], rule['element_bytes'], rule['chunk_bytes']), (2, 3, 32, 16))
        self.assertEqual(int(self.record['window']['start'], 16), 37997824)
        for name, expected in checks.items():
            match = re.search(r'\*\*(\d+) ' + re.escape(name) + r'\*\*', text)
            self.assertIsNotNone(match, name)
            self.assertEqual(int(match.group(1)), expected, name)

    def test_low_budget_precedes_empty_check(self):
        word = bytes(range(32))
        for budget in (0, 1, 2):
            for count in (0, 1):
                self.assertEqual(bind.model(budget, count, word), (budget, 0x50, word))

    def test_empty_charges_before_error(self):
        word = bytes(range(32))
        self.assertEqual(bind.model(3, 0, word), (0, 0x5b, word))
        self.assertEqual(bind.model(2**64 - 1, 0, word), (2**64 - 4, 0x5b, word))

    def test_complement_success(self):
        word = bytes(range(32))
        expected = bytes(range(255, 223, -1))
        self.assertEqual(bind.model(3, 1, word), (0, None, expected))
        self.assertEqual(bind.model(5, 2, bytes(32)), (2, None, b'\xff' * 32))
        self.assertEqual(bind.model(2**64 - 1, 1, b'\xff' * 32), (2**64 - 4, None, bytes(32)))

    def test_model_rejects_bad_input(self):
        for args in ((-1, 1, bytes(32)), (1, 2**64, bytes(32)), (1, 1, b'')):
            with self.assertRaises(ValueError): bind.model(*args)

    def test_wrong_digest_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            bind.collect(self.data, '0' * 64)

    def test_mutated_binary_fails_authentication(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'mutated'
            shutil.copyfile(bind.BINARY, path)
            with path.open('r+b') as f:
                f.seek(self.offset + 0x31)
                b = f.read(1)
                f.seek(self.offset + 0x31)
                f.write(bytes([b[0] ^ 1]))
            with path.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
                with self.assertRaisesRegex(ValueError, 'digest'):
                    bind.collect(data)

    def test_mutated_window_byte_fails_decoder(self):
        bad = bytearray(self.body)
        bad[0x31] ^= 1
        with self.assertRaises(ValueError): bind.decode(bad)

    def test_changed_branch_target_fails_decoder(self):
        bad = bytearray(self.body)
        bad[0x0c] ^= 1
        with self.assertRaises(ValueError): bind.decode(bad)

    def test_injected_call_and_wrong_callee_target_fail_decoder(self):
        for destination in (bind.START, bind.START + 0x10):
            bad = bytearray(self.body)
            bad[:5] = b'\xe8' + struct.pack('<i', destination - (bind.START + 5))
            with self.assertRaises(ValueError): bind.decode(bad)

    def test_shifted_fde_rejected(self):
        frame = self.sec['.eh_frame']
        p = frame['offset'] + bind.FDE_OFFSET
        record = bytearray(self.data[p:p + 20])
        self.assertEqual(bind.parse_fde(record, frame['va'])['start'], hex(bind.START))
        record[8] ^= 1
        with self.assertRaises(ValueError): bind.parse_fde(record, frame['va'])
        with self.assertRaises(ValueError): bind.parse_fde(self.data[p:p + 20], frame['va'], bind.FDE_OFFSET + 4)

    def test_relocation_type_and_slot_are_checked(self):
        data = struct.pack('<QQq', 0x1008, 8, bind.START)
        rela = {'type': 4, 'entry_size': 24, 'size': 24, 'offset': 0}
        section = {'va': 0x1000, 'size': 32}
        self.assertEqual(bind.relocation_slots(data, rela, section), ['0x1008'])
        for bad in (struct.pack('<QQq', 0x1008, 7, bind.START),
                    struct.pack('<QQq', 0x2000, 8, bind.START)):
            with self.assertRaises(ValueError): bind.relocation_slots(bad, rela, section)

    def test_direct_census_scans_both_encodings(self):
        start = bind.START - 0x100
        blob = bytearray(b'\x90' * 32)
        for p, op in ((1, 0xe8), (13, 0xe9)):
            blob[p] = op
            struct.pack_into('<i', blob, p + 1, bind.START - (start + p + 5))
        sec = {'offset': 0, 'va': start, 'size': len(blob)}
        self.assertEqual(bind.callers(bytes(blob), sec), [
            {'site': hex(start + 1), 'kind': 'call'}, {'site': hex(start + 13), 'kind': 'jump'}])
        blob[2] ^= 1
        self.assertEqual(bind.callers(bytes(blob), sec), [{'site': hex(start + 13), 'kind': 'jump'}])

    def test_regeneration_byte_identical(self):
        with tempfile.TemporaryDirectory() as d:
            import subprocess
            subprocess.run(['python3', str(bind.ROOT / 'tools/word_complement_94.py'), '--out', d], check=True)
            for name in ('records.json', 'walk.txt'):
                self.assertEqual((Path(d) / name).read_bytes(), (PACKET / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
