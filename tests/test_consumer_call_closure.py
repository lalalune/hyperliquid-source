"""RE-001 consumer-call closure: pinned output, tamper controls, determinism."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402
import consumer_call_closure as cc  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-001-consumer-call-closure-94'
OUTPUT_SHA256 = '5cbc9201e95866e46d605ad3dfc4a5a9730b3510c5f416ba797ba5cab4b3f3c8'
_DATA = None


def data():
    global _DATA
    if _DATA is None:
        _DATA = bv.TARGET.read_bytes()
    return _DATA


def mutate(va, new):
    buf = bytearray(data())
    offset = bv.va_to_off(bv.sections(data()), va)
    buf[offset:offset + len(new)] = new
    return bytes(buf)


def scan_mutated(buf):
    return cc.scan(buf, expected_sha256=hashlib.sha256(buf).hexdigest())


def relocation_offset(slot):
    """File offset of the .rela.dyn entry for `slot`."""
    secs = bv.sections(data())
    r = secs['.rela.dyn']
    for offset in range(r['offset'], r['offset'] + r['size'], 24):
        if struct.unpack_from('<Q', data(), offset)[0] == slot:
            return offset
    raise AssertionError(f'no relocation for {slot:#x}')


class Pinned(unittest.TestCase):
    def test_committed_record(self):
        self.assertEqual((PACKET / 'records.json').read_bytes(),
                         cc.render(cc.scan(data())).encode())

    def test_exact_values(self):
        r = cc.scan(data())
        self.assertEqual((r['function']['start_va'], r['function']['end_va'],
                          r['function']['size']), ('0x1455c00', '0x1455f8d', 909))
        self.assertEqual(r['direct_caller_count'], 6)
        self.assertEqual([row['site_va'] for row in r['direct_callers']],
                         ['0x1404e53', '0x144a916', '0x144c036', '0x144cbab',
                          '0x144d004', '0x37e3207'])
        self.assertEqual(r['direct_callers'][1]['fde_start_va'], '0x144a890')
        self.assertEqual(r['relative_pointer_slots_to_target'], [])
        self.assertEqual(r['indirect_operand_count'], 11)
        self.assertEqual([row['relocation'].get('symbol') for row in r['indirect_operands']
                          if row['relocation']['kind'] == 'glob_dat'], ['memcpy', 'memcpy'])
        self.assertEqual(r['location']['path'].rsplit('/', 1)[-1], 'accum.rs')
        self.assertEqual((r['location']['line'], r['location']['column']), (204, 1))
        self.assertEqual(r['separator_store'], {'site_va': '0x1455e47', 'bytes': '42c6043820',
                                                'immediate': '0x20', 'occurrences': 1})
        self.assertEqual(r['overflow_branch']['target_va'], '0x1455f31')

    def test_cli_check(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools/consumer_call_closure.py'),
                                 '--check', str(PACKET / 'records.json')],
                                check=True, capture_output=True)
        self.assertEqual(result.stdout, b'Consumer call closure reproduces exactly.\n')


class Negative(unittest.TestCase):
    def test_digest(self):
        buf = bytearray(data())
        buf[0x100] ^= 1
        with self.assertRaisesRegex(bv.EvidenceError, 'SHA-256'):
            cc.scan(bytes(buf))

    def test_caller_retarget(self):
        # Point the first caller at the adjacent function instead of 0x1455c00.
        offset = bv.va_to_off(bv.sections(data()), 0x1404e53)
        target = 0x1404d90
        rel = target - (0x1404e53 + 5)
        buf = bytearray(data())
        struct.pack_into('<i', buf, offset + 1, rel)
        r = scan_mutated(bytes(buf))
        self.assertNotIn('0x1404e53', [row['site_va'] for row in r['direct_callers']])
        self.assertEqual(r['direct_caller_count'], 5)

    def test_extra_e8_candidate(self):
        # Overwrite five bytes inside the body with an E8 to the target itself.
        offset = bv.va_to_off(bv.sections(data()), 0x1455c11)
        buf = bytearray(data())
        buf[offset:offset + 5] = b'\xe8' + struct.pack('<i', cc.TARGET - (0x1455c11 + 5))
        r = scan_mutated(bytes(buf))
        self.assertEqual(r['direct_caller_count'], 7)

    def test_indirect_operand_retarget(self):
        offset = bv.va_to_off(bv.sections(data()), 0x1455e10)
        buf = bytearray(data())
        struct.pack_into('<i', buf, offset + 2, 0x576e010 - (0x1455e10 + 6))
        with self.assertRaisesRegex(bv.EvidenceError, '0x1455e10'):
            scan_mutated(bytes(buf))

    def test_relative_relocation_retarget(self):
        offset = relocation_offset(0x576e010)
        buf = bytearray(data())
        struct.pack_into('<q', buf, offset + 16, 0x54c8cb1)
        with self.assertRaisesRegex(bv.EvidenceError, '0x576e010'):
            scan_mutated(bytes(buf))

    def test_memcpy_symbol_retarget(self):
        offset = relocation_offset(0x576dfe0)
        buf = bytearray(data())
        struct.pack_into('<Q', buf, offset + 8, (1 << 32) | 6)
        with self.assertRaisesRegex(bv.EvidenceError, 'GLOB_DAT'):
            scan_mutated(bytes(buf))

    def test_location_path_byte(self):
        secs = bv.sections(data())
        offset = bv.va_to_off(secs, 0x1eb86e)
        buf = bytearray(data())
        buf[offset] = ord('R')
        with self.assertRaisesRegex(bv.EvidenceError, 'Location record changed'):
            scan_mutated(bytes(buf))

    def test_separator_immediate(self):
        offset = bv.va_to_off(bv.sections(data()), cc.SEPARATOR_SITE)
        buf = bytearray(data())
        buf[offset + 4] = 0x2c
        with self.assertRaisesRegex(bv.EvidenceError, 'separator store changed'):
            scan_mutated(bytes(buf))

    def test_overflow_branch_target(self):
        offset = bv.va_to_off(bv.sections(data()), cc.OVERFLOW_SITE)
        buf = bytearray(data())
        struct.pack_into('<i', buf, offset + 2, 0x218 - 1)
        with self.assertRaisesRegex(bv.EvidenceError, 'overflow branch target changed'):
            scan_mutated(bytes(buf))


class Determinism(unittest.TestCase):
    def test_hashseed(self):
        outs = {subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/consumer_call_closure.py')],
                               env=dict(os.environ, PYTHONHASHSEED=seed), check=True,
                               capture_output=True).stdout for seed in ('0', '7', '4242')}
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), OUTPUT_SHA256)


if __name__ == '__main__':
    unittest.main()


