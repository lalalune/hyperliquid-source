"""RE-001 consumer-callee extents: pinned record, tamper controls, determinism."""
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
import consumer_callees as cc  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-001-consumer-callees-94'
OUTPUT_SHA256 = '5ecba323d4bad1cb3d61c113c51b5de89db2f7b41a3ff3c6ee649d38c570f406'
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
        self.assertEqual([f['start_va'] for f in r['functions']],
                         ['0x54c8cb0', '0x1346068', '0x54c06b0', '0x13460a0', '0x157b480'])
        by_start = {f['start_va']: f for f in r['functions']}
        self.assertEqual(by_start['0x54c8cb0']['size'], 165)
        self.assertEqual(by_start['0x1346068']['size'], 21)
        self.assertEqual(by_start['0x1346068']['e8_byte_candidates'], [])
        self.assertEqual([o.get('slot_va') for o in by_start['0x1346068']['operands']],
                         ['0x576e0c0', '0x576e020'])
        self.assertEqual([o.get('relocation', {}).get('target_va')
                          for o in by_start['0x1346068']['operands']],
                         ['0x1346080', '0x1345e2a'])
        self.assertEqual(by_start['0x13460a0']['operands'][0]['target_va'], '0x1346100')
        self.assertEqual(by_start['0x1346068']['operands'][0]['target_section']['name'], '.text')
        self.assertEqual(by_start['0x54c8cb0']['operands'][0]['target_section'],
                         {'name': '.bss', 'type': 8, 'file_backed': False})
        self.assertEqual(by_start['0x157b480']['operands'][0]['target_va'], '0x252cf8')
        self.assertEqual(by_start['0x157b480']['operands'][0]['target_section']['name'], '.rodata')
        self.assertEqual(by_start['0x157b480']['operands'][1]['slot_va'], '0x576e098')

    def test_cli_check(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools/consumer_callees.py'),
                                 '--check', str(PACKET / 'records.json')],
                                check=True, capture_output=True)
        self.assertEqual(result.stdout, b'Consumer callee extents reproduce exactly.\n')


class Negative(unittest.TestCase):
    def test_digest(self):
        buf = bytearray(data())
        buf[0x100] ^= 1
        with self.assertRaisesRegex(bv.EvidenceError, 'SHA-256'):
            cc.scan(bytes(buf))

    def test_size_threshold(self):
        with self.assertRaisesRegex(bv.EvidenceError, '0x54c8cb4'):
            scan_mutated(mutate(0x54C8CB4, bytes.fromhex('4881fe00200000')))

    def test_slot_addend(self):
        offset = relocation_offset(0x576E0C0)
        buf = bytearray(data())
        struct.pack_into('<q', buf, offset + 16, 0x1346081)
        with self.assertRaisesRegex(bv.EvidenceError, '0x576e0c0'):
            scan_mutated(bytes(buf))

    def test_direct_call_target(self):
        offset = bv.va_to_off(bv.sections(data()), 0x13460CE)
        buf = bytearray(data())
        struct.pack_into('<i', buf, offset + 1, 0x1346101 - (0x13460CE + 5))
        with self.assertRaisesRegex(bv.EvidenceError, '0x13460ce: call target'):
            scan_mutated(bytes(buf))

    def test_rip_lea_target(self):
        offset = bv.va_to_off(bv.sections(data()), 0x157B487)
        buf = bytearray(data())
        struct.pack_into('<i', buf, offset + 3, 0x252CF9 - 0x157B48E)
        with self.assertRaisesRegex(bv.EvidenceError, '0x157b487: rip target'):
            scan_mutated(bytes(buf))


class Determinism(unittest.TestCase):
    def test_hashseed(self):
        outs = {subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/consumer_callees.py')],
                               env=dict(os.environ, PYTHONHASHSEED=seed), check=True,
                               capture_output=True).stdout for seed in ('0', '7', '4242')}
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), OUTPUT_SHA256)


if __name__ == '__main__':
    unittest.main()


